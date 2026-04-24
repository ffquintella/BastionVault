use bastion_vault::logical::{Operation, Request};
use serde::Serialize;
use serde_json::Value;
use tauri::State;

use crate::embedded;
use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

#[derive(Serialize)]
pub struct InitResponse {
    pub root_token: String,
}

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub sealed: bool,
    pub has_vault: bool,
}

#[tauri::command]
pub async fn init_vault(state: State<'_, AppState>) -> CmdResult<InitResponse> {
    // Hold the vault mutex for the entire init so concurrent invocations
    // -- e.g. React StrictMode in dev firing a click handler's effect
    // twice -- serialize and the loser sees an already-initialized vault
    // instead of trying to open a second hiqlite instance over the same
    // on-disk lockfile.
    let mut vault_guard = state.vault.lock().await;
    if vault_guard.is_some() {
        return Err("Vault already initialized in this session".into());
    }
    // init_embedded returns the already-unsealed vault. We stash it into
    // app state directly -- reopening the backend right after init would
    // collide with its still-held lockfile (hiqlite) or be wasteful (file).
    let outcome = embedded::init_embedded().await?;
    let root_token = outcome.root_token.clone();
    *vault_guard = Some(outcome.vault);
    drop(vault_guard);
    *state.token.lock().await = Some(root_token.clone());

    Ok(InitResponse { root_token })
}

#[tauri::command]
pub async fn open_vault(state: State<'_, AppState>) -> CmdResult<()> {
    // Idempotent: if something (e.g. a double-fired StrictMode effect)
    // already opened the vault, return success without touching storage.
    // Holding the mutex across open_embedded serializes concurrent calls.
    let mut vault_guard = state.vault.lock().await;
    if vault_guard.is_some() {
        return Ok(());
    }
    let vault = embedded::open_embedded().await?;
    *vault_guard = Some(vault);
    drop(vault_guard);

    // Restore the per-vault root token the init flow stashed under
    // this profile's id. Keeps the post-open session alive without
    // a re-login in the single-operator / local-install case.
    let vault_id = crate::embedded::current_vault_id();
    if let Some(token) = crate::local_keystore::get_root_token(&vault_id)? {
        *state.token.lock().await = Some(token);
    }

    Ok(())
}

/// Seal the vault. Backend-gated: the caller must hold a policy
/// granting `update` on `sys/seal`, which in the shipped policy set
/// is only the `root` token. Before this gate was added, any
/// authenticated user could seal the vault from the dashboard.
///
/// The authorization check routes through `PolicyStore::can_operate`,
/// which replays the same per-target resolution the request pipeline
/// uses in `post_auth`. It is not a UI-only hide: even a hand-crafted
/// Tauri call with a low-privilege token is rejected here.
#[tauri::command]
pub async fn seal_vault(state: State<'_, AppState>) -> CmdResult<()> {
    use bastion_vault::modules::{auth::AuthModule, policy::PolicyModule};

    let vault_guard = state.vault.lock().await;
    let Some(vault) = vault_guard.as_ref() else {
        return Ok(());
    };

    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();
    if token.is_empty() {
        return Err("Authentication required to seal the vault".into());
    }

    // Resolve the token → Auth, then probe `sys/seal` Write.
    let auth_module = core
        .module_manager
        .get_module::<AuthModule>("auth")
        .ok_or("auth module unavailable")?;
    let token_store = auth_module
        .token_store
        .load_full()
        .ok_or("token store unavailable")?;

    let auth = token_store
        .check_token("sys/seal", &token)
        .await
        .map_err(CommandError::from)?
        .ok_or("invalid or expired token")?;

    let policy_module = core
        .module_manager
        .get_module::<PolicyModule>("policy")
        .ok_or("policy module unavailable")?;
    let policy_store = policy_module.policy_store.load();

    if !policy_store
        .can_operate(&auth, "sys/seal", Operation::Write)
        .await
    {
        return Err("Permission denied: caller lacks `update` on sys/seal".into());
    }

    embedded::seal_vault(vault).await?;
    Ok(())
}

#[tauri::command]
pub async fn get_vault_status(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    let vault_guard = state.vault.lock().await;
    match vault_guard.as_ref() {
        Some(vault) => {
            let core = vault.core.load();
            let initialized = core.inited().await.unwrap_or(false);
            let sealed = core.sealed();
            Ok(VaultStatus {
                initialized,
                sealed,
                has_vault: true,
            })
        }
        None => Ok(VaultStatus {
            initialized: embedded::is_initialized().unwrap_or(false),
            sealed: true,
            has_vault: false,
        }),
    }
}

/// Close the active embedded-vault handle without touching the
/// on-disk data, keychain, or saved preferences. Used by the
/// Switch-vault flow so the AppState slot is free for a subsequent
/// `open_vault` to drop in a different profile (embedded's
/// `build_backend` reads `last_used_id` from preferences, so swapping
/// the profile is a `set_last_used_vault` + close + open sequence).
///
/// Intentionally does NOT clear `state.token` — the GUI caches
/// per-vault tokens in its auth store so it can restore the session
/// on the target vault without a full re-login if the stashed token
/// is still valid. The token IS cleared on the Rust side later by
/// the open path when the new vault comes up; or on explicit sign-out.
#[tauri::command]
pub async fn disconnect_vault(state: State<'_, AppState>) -> CmdResult<()> {
    *state.vault.lock().await = None;
    *state.token.lock().await = None;
    Ok(())
}

#[tauri::command]
pub async fn reset_vault(state: State<'_, AppState>) -> CmdResult<()> {
    use crate::preferences::{self, VaultSpec};

    // Drop the active vault + session first so we don't race with
    // ongoing reads during the wipe.
    *state.vault.lock().await = None;
    *state.token.lock().await = None;

    // Drop the per-vault entry for the currently-active profile
    // (the one whose data we're about to nuke) plus any legacy
    // single-slot keychain residue. Other vaults' entries stay
    // intact so this action is scoped to the one being reset.
    let vault_id = crate::embedded::current_vault_id();
    crate::local_keystore::remove_vault(&vault_id)?;
    crate::secure_store::delete_all_keys()?;

    // Branch on the active profile's spec. Cloud vaults live in a
    // bucket / drive and require a backend-level wipe — just
    // removing the local data dir (which is what earlier revisions
    // did) left the bucket intact, so the next open saw
    // "initialized" again and the user's Reset button appeared to
    // do nothing. Local profiles continue to delete their data dir.
    let profile = preferences::load().ok().and_then(|p| p.default_profile().cloned());
    match profile.as_ref().map(|p| &p.spec) {
        Some(VaultSpec::Cloud { .. }) => {
            // Build the cloud backend the same way `open_vault`
            // would, then enumerate every key and delete it. This
            // wipes barrier markers, keyring, and all logical paths
            // in one pass.
            wipe_cloud_backend().await?;
        }
        Some(VaultSpec::Remote { .. }) => {
            // Reset-vault against a remote server doesn't make
            // sense here — the operator does that server-side.
            // We've already cleared the local session state, which
            // is all this command can legitimately touch.
        }
        _ => {
            // Local (or no profile configured at all) — delete the
            // effective data directory. Honours per-profile custom
            // `data_dir` overrides that `build_backend` applies.
            let dir = active_local_data_dir()?;
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    crate::error::CommandError::from(format!("Failed to remove vault data: {e}"))
                })?;
            }
        }
    }

    Ok(())
}

/// Enumerate every object stored under the active cloud profile and
/// issue a backend-level `delete` for each. Run under a fresh
/// backend handle — the active vault is already closed by the
/// caller, so building one here doesn't race with an in-flight
/// session. Empty enumeration is a no-op, which is the expected
/// state after a successful reset.
async fn wipe_cloud_backend() -> Result<(), crate::error::CommandError> {
    // `backend` is `Arc<dyn Backend>`; trait methods resolve through
    // the trait object directly, no `use Backend` needed.
    let backend = crate::embedded::build_backend().await?;

    // BFS-style walk: start at "" (the provider's root) and recurse
    // into any directory-shaped entries (trailing "/"). Leaf entries
    // get deleted; directories get expanded. This handles Hiqlite's
    // flat-key layout and cloud targets' virtual-hierarchy view
    // identically.
    let mut queue: Vec<String> = vec![String::new()];
    let mut deleted = 0usize;
    while let Some(prefix) = queue.pop() {
        let entries = match backend.list(&prefix).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "reset: cloud list(`{prefix}`) failed: {e} — continuing best-effort"
                );
                continue;
            }
        };
        for entry in entries {
            let full = format!("{prefix}{entry}");
            if entry.ends_with('/') {
                queue.push(full);
            } else {
                match backend.delete(&full).await {
                    Ok(()) => {
                        deleted += 1;
                    }
                    Err(e) => {
                        // Best-effort: don't abort the whole wipe
                        // on one stubborn object. Operators who see
                        // repeated resets not fully clearing the
                        // bucket can check the log + use their
                        // provider's console to remove the rest.
                        eprintln!(
                            "reset: cloud delete(`{full}`) failed: {e} — continuing"
                        );
                    }
                }
            }
        }
    }
    eprintln!("reset: cloud backend wipe complete ({deleted} object(s) removed)");
    Ok(())
}

/// Resolve the data directory that would be used by the currently-
/// active local profile. Mirrors the effective-dir logic in
/// `embedded::build_backend`: honours the profile's custom
/// `data_dir` override, falls back to the canonical per-kind
/// default otherwise.
fn active_local_data_dir() -> Result<std::path::PathBuf, crate::error::CommandError> {
    use crate::embedded::{data_dir, data_dir_for, StorageKind};
    use crate::preferences::{self, VaultSpec};

    if let Ok(prefs) = preferences::load() {
        if let Some(profile) = prefs.default_profile() {
            if let VaultSpec::Local { data_dir: dir, storage_kind } = &profile.spec {
                if let Some(custom) = dir.as_ref().filter(|s| !s.is_empty()) {
                    return Ok(std::path::PathBuf::from(custom));
                }
                let kind = match storage_kind.as_str() {
                    "hiqlite" => StorageKind::Hiqlite,
                    _ => StorageKind::File,
                };
                return data_dir_for(kind);
            }
        }
    }
    data_dir()
}

#[derive(Serialize)]
pub struct MountInfo {
    pub path: String,
    pub mount_type: String,
    pub description: String,
}

/// List the secret-engine mounts the caller is authorized to see.
///
/// Routes through `sys/internal/ui/mounts`, which runs through the
/// full auth + policy pipeline on the backend: the ACL gates each
/// mount entry via `has_mount_access`. An earlier revision read the
/// router's mount table directly, which leaked every mount to every
/// authenticated caller regardless of their policies — felipe with
/// only `default` would still see `secret/`, `resources/`, etc. on
/// the dashboard. Don't reintroduce that: the backend filter is the
/// source of truth.
#[tauri::command]
pub async fn list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let map = read_ui_mounts(&state, "secret").await?;
    Ok(mount_map_to_info(&map))
}

/// Same as `list_mounts` but for auth-method mounts. Pulls the
/// `auth` half of the `sys/internal/ui/mounts` response.
#[tauri::command]
pub async fn list_auth_methods(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let map = read_ui_mounts(&state, "auth").await?;
    Ok(mount_map_to_info(&map))
}

/// Read `sys/internal/ui/mounts` through the full request pipeline
/// so the ACL filter applies, and return the map under the given
/// top-level field (`"secret"` or `"auth"`).
async fn read_ui_mounts(
    state: &State<'_, AppState>,
    field: &str,
) -> Result<serde_json::Map<String, Value>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = "sys/internal/ui/mounts".to_string();
    req.client_token = token;

    let resp = core
        .handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;

    let data = resp
        .and_then(|r| r.data)
        .ok_or("sys/internal/ui/mounts returned no data")?;
    let map = data
        .get(field)
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    Ok(map)
}

/// Convert the `{path -> {type, description, ...}}` payload used by
/// `sys/internal/ui/mounts` into the flat `Vec<MountInfo>` the
/// frontend expects.
/// One row of the unified audit trail. Mirrors the shape of the
/// server's `/v2/sys/audit/events` response so the frontend can
/// render it directly. `changed_fields` is empty for policies (where
/// only raw-HCL before/after is tracked) and populated for group
/// changes.
#[derive(Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub user: String,
    pub op: String,
    pub category: String,
    pub target: String,
    pub changed_fields: Vec<String>,
    pub summary: String,
}

#[tauri::command]
pub async fn list_audit_events(
    state: State<'_, AppState>,
    from: String,
    to: String,
    limit: Option<u32>,
) -> CmdResult<Vec<AuditEvent>> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = "sys/audit/events".to_string();
    req.client_token = token;

    // The handler parses these from `req.data` after field resolution;
    // for Read it populates from the body, so stuff them there.
    let mut body = serde_json::Map::new();
    if !from.is_empty() {
        body.insert("from".into(), Value::String(from));
    }
    if !to.is_empty() {
        body.insert("to".into(), Value::String(to));
    }
    if let Some(l) = limit {
        body.insert("limit".into(), Value::Number(l.into()));
    }
    if !body.is_empty() {
        req.body = Some(body);
    }

    let resp = core.handle_request(&mut req).await.map_err(CommandError::from)?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let arr = data.get("events").and_then(|v| v.as_array()).cloned();
    let out = arr
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(AuditEvent {
                ts: o.get("ts").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                user: o.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                op: o.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                category: o
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                target: o
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                changed_fields: o
                    .get("changed_fields")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                summary: o
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(out)
}

// ── SSO discovery + admin toggle ───────────────────────────────────
//
// `sys/sso/providers` is unauthenticated on the backend so the login
// page can fetch the list before the user has a token. `sys/sso/settings`
// is root-gated — only an operator with a sudo token flips the
// global enable bit.

#[derive(Serialize, Debug, Clone)]
pub struct SsoProvider {
    pub mount: String,
    pub name: String,
    pub kind: String,
}

#[derive(Serialize, Debug)]
pub struct SsoProvidersResult {
    pub enabled: bool,
    pub providers: Vec<SsoProvider>,
}

/// Read the unauth discovery endpoint. Used by the login page to
/// decide whether the SSO tab is shown at all.
#[tauri::command]
pub async fn list_sso_providers(state: State<'_, AppState>) -> CmdResult<SsoProvidersResult> {
    let data = read_sys_path(&state, "sys/sso/providers", /* authed = */ false).await?;
    let enabled = data
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let providers = data
        .get("providers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(SsoProvider {
                mount: o.get("mount")?.as_str()?.to_string(),
                name: o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                kind: o
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(SsoProvidersResult { enabled, providers })
}

#[tauri::command]
pub async fn get_sso_settings(state: State<'_, AppState>) -> CmdResult<bool> {
    let data = read_sys_path(&state, "sys/sso/settings", /* authed = */ true).await?;
    Ok(data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
}

#[tauri::command]
pub async fn set_sso_settings(
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<()> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = "sys/sso/settings".to_string();
    req.client_token = token;
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), Value::Bool(enabled));
    req.body = Some(body);

    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;
    Ok(())
}

async fn read_sys_path(
    state: &State<'_, AppState>,
    path: &str,
    authed: bool,
) -> Result<serde_json::Map<String, Value>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = path.to_string();
    if authed {
        req.client_token = state.token.lock().await.clone().unwrap_or_default();
    }

    let resp = core
        .handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

fn mount_map_to_info(map: &serde_json::Map<String, Value>) -> Vec<MountInfo> {
    let mut out: Vec<MountInfo> = map
        .iter()
        .map(|(path, v)| MountInfo {
            path: path.clone(),
            mount_type: v
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            description: v
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}
