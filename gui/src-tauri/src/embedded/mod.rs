use std::collections::HashMap;
use std::sync::Arc;

use bastion_vault::core::SealConfig;
use bastion_vault::logical::{Operation, Request};
use bastion_vault::storage::new_backend;
use bastion_vault::BastionVault;
use serde_json::{Map, Value};

use crate::error::CommandError;
use crate::secure_store;

/// Returns the data directory for the embedded vault.
pub fn data_dir() -> Result<std::path::PathBuf, CommandError> {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("Cannot determine home directory")?;
    Ok(base.join(".bastion_vault_gui").join("data"))
}

/// Check if a vault has been previously initialized.
///
/// Checks for the barrier init marker file first, then falls back to
/// checking whether the data directory contains any files at all (the
/// vault may have been initialized via a different storage backend that
/// doesn't use `_barrier`).
pub fn is_initialized() -> Result<bool, CommandError> {
    let dir = data_dir()?;
    if !dir.exists() {
        return Ok(false);
    }
    // Primary check: barrier marker file.
    if dir.join("_barrier").exists() {
        return Ok(true);
    }
    // Fallback: if the directory has any contents, consider it initialized.
    let has_files = std::fs::read_dir(&dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    Ok(has_files)
}

/// Create a new embedded vault, initialize it, and store keys in the OS keychain.
/// Returns the root token.
pub async fn init_embedded() -> Result<String, CommandError> {
    let dir = data_dir()?;
    std::fs::create_dir_all(&dir)?;

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = new_backend("file", &conf).map_err(|e| CommandError::from(e))?;
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    let seal_config = SealConfig {
        secret_shares: 1,
        secret_threshold: 1,
    };

    let init_result = vault.init(&seal_config).await.map_err(|e| CommandError::from(e))?;

    // Store the unseal key and root token in the OS keychain.
    let unseal_key_hex = hex::encode(&init_result.secret_shares[0]);
    let root_token = init_result.root_token.clone();
    secure_store::store_unseal_key(&unseal_key_hex)?;
    secure_store::store_root_token(&root_token)?;

    // Unseal immediately.
    let key_bytes = &init_result.secret_shares[0];
    vault.unseal(&[key_bytes.as_slice()]).await.map_err(|e| CommandError::from(e))?;

    // Create default policies and enable auth methods.
    create_default_policies(&vault, &root_token).await?;
    enable_default_auth_methods(&vault, &root_token).await?;

    Ok(root_token)
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
    let dir = data_dir()?;

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = new_backend("file", &conf).map_err(|e| CommandError::from(e))?;
    let vault = BastionVault::new(backend, None).map_err(|e| CommandError::from(e))?;

    let unseal_key_hex = secure_store::get_unseal_key()?
        .ok_or("No unseal key found in keychain. Was the vault initialized?")?;
    let unseal_key = hex::decode(&unseal_key_hex)
        .map_err(|_| CommandError::from("Invalid unseal key in keychain"))?;

    vault.unseal(&[&unseal_key]).await.map_err(|e| CommandError::from(e))?;

    Ok(Arc::new(vault))
}

/// Seal the vault.
pub async fn seal_vault(vault: &BastionVault) -> Result<(), CommandError> {
    vault.core.load().seal().await.map_err(|e| CommandError::from(e))
}
