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

    if let Some(token) = crate::secure_store::get_root_token()? {
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

#[tauri::command]
pub async fn reset_vault(state: State<'_, AppState>) -> CmdResult<()> {
    // Drop the vault instance first.
    *state.vault.lock().await = None;
    *state.token.lock().await = None;

    // Remove keychain entries.
    crate::secure_store::delete_all_keys()?;

    // Remove the data directory.
    let dir = embedded::data_dir()?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| {
            crate::error::CommandError::from(format!("Failed to remove vault data: {e}"))
        })?;
    }

    Ok(())
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
