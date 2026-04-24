use std::collections::HashMap;
use std::sync::Arc;

use bastion_vault::core::SealConfig;
use bastion_vault::logical::{Operation, Request};
use bastion_vault::storage::physical::file::FileBackend;
use bastion_vault::storage::{new_backend, Backend};
use bastion_vault::BastionVault;
use serde_json::{Map, Value};

use crate::error::CommandError;
use crate::preferences::{self, CloudStorageConfig};
use crate::secure_store;

// ── Storage selection ──────────────────────────────────────────────
//
// The embedded vault can run on either the plain file backend (simple,
// zero-config, one file per key) or hiqlite (embedded Raft SQLite, single
// node in dev). The backend is picked at process start from the
// `BASTION_EMBEDDED_STORAGE` env var:
//
//   unset / "file"     -> file backend (default, backward compatible)
//   "hiqlite"          -> hiqlite backend, single-node, TLS disabled
//
// Each backend gets its own data directory so switching via the env var
// does not mix file-style keys with hiqlite's SQLite files.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    File,
    Hiqlite,
}

pub fn storage_kind() -> StorageKind {
    match std::env::var("BASTION_EMBEDDED_STORAGE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .trim()
    {
        "hiqlite" => StorageKind::Hiqlite,
        _ => StorageKind::File,
    }
}

/// Base data directory for the embedded vault, picked from the env-
/// var `BASTION_EMBEDDED_STORAGE`. Each storage backend uses a
/// different subdirectory so the two layouts never mix on the same
/// machine.
pub fn data_dir() -> Result<std::path::PathBuf, CommandError> {
    data_dir_for(storage_kind())
}

/// Kind-parameterized variant used when the current vault profile
/// overrides `storage_kind` independently of the env var (the
/// Add Local Vault form's "Storage engine" select). Same layout as
/// `data_dir`, different discriminant.
pub fn data_dir_for(kind: StorageKind) -> Result<std::path::PathBuf, CommandError> {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("Cannot determine home directory")?;
    let root = base.join(".bastion_vault_gui");
    Ok(match kind {
        StorageKind::File => root.join("data"),
        StorageKind::Hiqlite => root.join("data-hiqlite"),
    })
}

/// Build a storage backend. If preferences hold a `cloud_storage`
/// config, the backend is a `FileBackend` wrapped around the named
/// cloud target (S3 / OneDrive / Google Drive / Dropbox); otherwise
/// the env-var-selected local / Hiqlite path is used, preserving
/// backward compatibility.
///
/// Async because the cloud-target path may need to bootstrap an
/// obfuscation salt against the underlying provider before the
/// backend is usable.
pub async fn build_backend() -> Result<Arc<dyn Backend>, CommandError> {
    // If the currently-default saved vault profile is a Cloud entry,
    // build an `ObfuscatingTarget`-capable cloud backend. Local
    // entries fall through to the env-var-selected filesystem path
    // below; Remote entries don't reach this code path at all (the
    // Tauri `connect_remote` command handles them out-of-band).
    //
    // Falls back gracefully when no default is set (fresh install,
    // or the user hit "Switch vault" to clear it) — we just build
    // the local default, same as the pre-multi-vault behavior.
    // Effective storage kind + data dir, starting from the env-var
    // fallback and then overlaying anything the currently-default
    // saved profile asks for. Cloud profiles short-circuit entirely
    // below; Local profiles pick up `storage_kind` + the optional
    // custom `data_dir` here.
    let mut effective_kind = storage_kind();
    let mut effective_dir: Option<std::path::PathBuf> = None;

    if let Ok(prefs) = preferences::load() {
        if let Some(profile) = prefs.default_profile() {
            match &profile.spec {
                preferences::VaultSpec::Cloud { config } => {
                    return build_cloud_backend(config.clone()).await;
                }
                preferences::VaultSpec::Local { data_dir, storage_kind: sk } => {
                    // Per-profile overrides. `storage_kind` strings
                    // we don't recognise fall back to `File` so we
                    // never hard-fail on a typo in the preferences
                    // file; other misconfigurations are louder.
                    effective_kind = match sk.as_str() {
                        "hiqlite" => StorageKind::Hiqlite,
                        _ => StorageKind::File,
                    };
                    if let Some(custom) = data_dir.as_ref().filter(|s| !s.is_empty()) {
                        effective_dir = Some(std::path::PathBuf::from(custom));
                    }
                }
                preferences::VaultSpec::Remote { .. } => {
                    // Remote profiles are handled by the Tauri
                    // `connect_remote` command, not here. If we see
                    // one set as the default we fall through to the
                    // local default — same as pre-multi-vault.
                }
            }
        }
    }

    // Use the profile's custom dir if set, otherwise the canonical
    // per-kind default under the user's data-local dir.
    let dir = match effective_dir {
        Some(p) => p,
        None => data_dir_for(effective_kind)?,
    };
    std::fs::create_dir_all(&dir)?;

    let mut conf: HashMap<String, Value> = HashMap::new();
    let dir_str = dir.to_string_lossy().into_owned();

    match effective_kind {
        StorageKind::File => {
            conf.insert("path".into(), Value::String(dir_str));
            new_backend("file", &conf).map_err(CommandError::from)
        }
        StorageKind::Hiqlite => {
            // Single-node dev config. NOT for production -- the secrets
            // below are public knowledge because they are in source.
            //
            // listen_addr is set to 127.0.0.1 so hiqlite's self-dial (which
            // uses the same address field as the listener) actually reaches
            // the local node. The default of "0.0.0.0" works as a listener
            // but is not a valid dial target on Windows and hangs here.
            conf.insert("data_dir".into(), Value::String(dir_str));
            conf.insert("node_id".into(), Value::from(1u64));
            conf.insert(
                "secret_raft".into(),
                Value::String("dev_raft_secret_1".into()),
            );
            conf.insert(
                "secret_api".into(),
                Value::String("dev_api_secret_01".into()),
            );
            conf.insert(
                "listen_addr_api".into(),
                Value::String("127.0.0.1".into()),
            );
            conf.insert(
                "listen_addr_raft".into(),
                Value::String("127.0.0.1".into()),
            );
            conf.insert("tls_raft_disable".into(), Value::Bool(true));
            conf.insert("tls_api_disable".into(), Value::Bool(true));
            // Default ports: 8210 raft, 8220 api. If either is already in
            // use, hiqlite will fail to bind and init_embedded will surface
            // a clear error.
            eprintln!(
                "embedded: starting hiqlite backend at {} (raft 127.0.0.1:8210, api 127.0.0.1:8220)",
                dir.display()
            );
            new_backend("hiqlite", &conf).map_err(CommandError::from)
        }
    }
}

/// Construct a cloud-backed `FileBackend` from a stored
/// `CloudStorageConfig`. Uses `FileBackend::new_maybe_obfuscated` so
/// the async salt bootstrap for `obfuscate_keys = true` runs before
/// the backend is handed to the vault.
async fn build_cloud_backend(cloud: CloudStorageConfig) -> Result<Arc<dyn Backend>, CommandError> {
    let mut conf: HashMap<String, Value> = cloud
        .config
        .into_iter()
        .collect();
    conf.insert("target".into(), Value::String(cloud.target.clone()));

    eprintln!(
        "embedded: starting cloud backend with target `{}`",
        cloud.target
    );

    let backend = FileBackend::new_maybe_obfuscated(&conf)
        .await
        .map_err(CommandError::from)?;
    Ok(Arc::new(backend))
}

/// Check if a vault has been previously initialized.
///
/// Checks for the file-backend barrier marker file first, then falls back
/// to checking whether the data directory contains any files at all. The
/// fallback is what catches hiqlite's SQLite files (hiqlite stores the
/// barrier as rows, not as a literal `_barrier` file).
pub fn is_initialized() -> Result<bool, CommandError> {
    // Cloud Vault: can't cheaply check without a network round-trip,
    // so we treat it as always-initialized once the config is saved.
    // The caller's subsequent `open_embedded` will surface a clear
    // error if the underlying bucket / folder doesn't actually have
    // a vault on it yet (unseal will fail on a missing barrier).
    // First-time-ever boot uses `init_vault` explicitly from the UI,
    // so this lives in the "open when possible" code path only.
    if let Ok(prefs) = preferences::load() {
        if let Some(profile) = prefs.default_profile() {
            if matches!(profile.spec, preferences::VaultSpec::Cloud { .. }) {
                return Ok(true);
            }
        }
    }

    let dir = data_dir()?;
    if !dir.exists() {
        return Ok(false);
    }
    // Primary check: file-backend barrier marker.
    if dir.join("_barrier").exists() {
        return Ok(true);
    }
    // Fallback: any files/subdirs present means some backend has written
    // to this tree before.
    let has_files = std::fs::read_dir(&dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    Ok(has_files)
}

/// Result of a fresh embedded-vault initialization. The caller receives
/// both the root token (to stash in app state / keychain already happened
/// internally) and the already-unsealed `BastionVault` so it can be
/// placed directly into Tauri state. Returning the live vault avoids a
/// close-then-reopen cycle which the hiqlite backend cannot tolerate --
/// its on-disk lockfile would still be held by the dropped instance and
/// reopening would deadlock or panic.
pub struct InitOutcome {
    pub root_token: String,
    pub vault: Arc<BastionVault>,
}

/// Create a new embedded vault, initialize it, and store keys in the OS
/// keychain. Returns the unsealed vault *and* the root token so the Tauri
/// command can put the vault into app state without a separate open.
pub async fn init_embedded() -> Result<InitOutcome, CommandError> {
    eprintln!("embedded: init_embedded starting (storage = {:?})", storage_kind());
    let backend = build_backend().await?;
    eprintln!("embedded: backend built, creating vault");
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    let seal_config = SealConfig {
        secret_shares: 1,
        secret_threshold: 1,
    };

    let init_result = vault.init(&seal_config).await.map_err(|e| CommandError::from(e))?;

    // Store the unseal key and root token in the local keystore,
    // indexed by the active vault profile's id. `local_keystore`
    // encrypts the whole set with a single OS-keychain-anchored
    // master key, so creating a second vault after this one does
    // NOT overwrite the first one's secrets (the bug this commit
    // exists to fix). See `local_keystore` module docstring.
    let unseal_key_hex = hex::encode(&init_result.secret_shares[0]);
    let root_token = init_result.root_token.clone();
    let vault_id = current_vault_id();
    crate::local_keystore::store_unseal_key(&vault_id, &unseal_key_hex)?;
    crate::local_keystore::store_root_token(&vault_id, &root_token)?;

    // Unseal immediately.
    let key_bytes = &init_result.secret_shares[0];
    vault.unseal(&[key_bytes.as_slice()]).await.map_err(|e| CommandError::from(e))?;

    // Create default policies and enable auth methods.
    create_default_policies(&vault, &root_token).await?;
    enable_default_auth_methods(&vault, &root_token).await?;

    Ok(InitOutcome {
        root_token,
        vault: Arc::new(vault),
    })
}

/// Create default policies on a freshly initialized vault.
async fn create_default_policies(vault: &BastionVault, root_token: &str) -> Result<(), CommandError> {
    let core = vault.core.load();

    // "admin" — full access to secrets, auth, policies, and system endpoints.
    let admin_policy = r#"
# Full access to all secret engines
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Full access to resources
path "resources/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage auth methods and users
path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Read and manage policies
path "sys/policies/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage secret engine mounts
path "sys/mounts/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage auth method mounts
path "sys/auth/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# System health and status
path "sys/health" {
  capabilities = ["read"]
}

path "sys/seal" {
  capabilities = ["update"]
}

path "sys/unseal" {
  capabilities = ["update"]
}
"#;

    let mut body = Map::new();
    body.insert("policy".to_string(), Value::String(admin_policy.trim().to_string()));

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = "sys/policies/acl/admin".to_string();
    req.client_token = root_token.to_string();
    req.body = Some(body);

    core.handle_request(&mut req).await.map_err(CommandError::from)?;

    // "default" — basic read-only access for regular users.
    let default_policy = r#"
# Read and list secrets
path "secret/*" {
  capabilities = ["read", "list"]
}

# Allow users to look up their own token
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
"#;

    let mut body = Map::new();
    body.insert("policy".to_string(), Value::String(default_policy.trim().to_string()));

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = "sys/policies/acl/default".to_string();
    req.client_token = root_token.to_string();
    req.body = Some(body);

    core.handle_request(&mut req).await.map_err(CommandError::from)?;

    Ok(())
}

/// Enable default auth methods on a freshly initialized vault.
/// FIDO2 is integrated into the userpass backend, so only userpass needs to be mounted.
async fn enable_default_auth_methods(vault: &BastionVault, root_token: &str) -> Result<(), CommandError> {
    let core = vault.core.load();

    // Mount userpass (includes integrated FIDO2 support)
    let mut body = Map::new();
    body.insert("type".to_string(), Value::String("userpass".to_string()));
    body.insert("description".to_string(), Value::String("Username & password authentication".to_string()));

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = "sys/auth/userpass/".to_string();
    req.client_token = root_token.to_string();
    req.body = Some(body);

    // Ignore errors if already mounted.
    let _ = core.handle_request(&mut req).await;

    // Auto-configure FIDO2 relying party with localhost defaults for embedded mode.
    let mut body = Map::new();
    body.insert("rp_id".to_string(), Value::String("localhost".to_string()));
    body.insert("rp_origin".to_string(), Value::String("https://localhost".to_string()));
    body.insert("rp_name".to_string(), Value::String("BastionVault".to_string()));

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = "auth/userpass/fido2/config".to_string();
    req.client_token = root_token.to_string();
    req.body = Some(body);

    let _ = core.handle_request(&mut req).await;

    Ok(())
}

/// Open and unseal an existing embedded vault using keys from the OS keychain.
pub async fn open_embedded() -> Result<Arc<BastionVault>, CommandError> {
    let backend = build_backend().await?;
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    // Look up the unseal key for the currently-selected vault
    // profile. Falls back to the legacy single-entry keychain slot
    // (via the migration path inside `local_keystore::get_unseal_key`)
    // so existing installs upgrade transparently.
    let vault_id = current_vault_id();
    let unseal_key_hex = crate::local_keystore::get_unseal_key(&vault_id)?
        .ok_or_else(|| CommandError::from(format!(
            "No unseal key found for vault `{vault_id}`. Was the vault initialized?"
        )))?;
    let unseal_key = hex::decode(&unseal_key_hex)
        .map_err(|_| CommandError::from("Invalid unseal key in local keystore"))?;

    vault.unseal(&[&unseal_key]).await.map_err(|e| CommandError::from(e))?;

    Ok(Arc::new(vault))
}

/// Seal the vault.
pub async fn seal_vault(vault: &BastionVault) -> Result<(), CommandError> {
    vault.core.load().seal().await.map_err(|e| CommandError::from(e))
}

/// Resolve the "active" vault id used to index the local keystore.
/// Falls back to `"default"` when no profile has been marked
/// last-used — typical of a fresh install's first init. This keeps
/// single-vault deployments working identically to the pre-keystore
/// behavior while still giving multi-vault installs their own
/// per-id slots.
pub fn current_vault_id() -> String {
    crate::preferences::load()
        .ok()
        .and_then(|p| p.last_used_id)
        .unwrap_or_else(|| "default".to_string())
}
