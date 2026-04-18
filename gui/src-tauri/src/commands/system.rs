use serde::Serialize;
use tauri::State;

use crate::embedded;
use crate::error::CmdResult;
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

#[tauri::command]
pub async fn seal_vault(state: State<'_, AppState>) -> CmdResult<()> {
    let vault_guard = state.vault.lock().await;
    if let Some(vault) = vault_guard.as_ref() {
        embedded::seal_vault(vault).await?;
    }
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

#[tauri::command]
pub async fn list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let entries = core.mounts_router.mounts.entries.read().unwrap();
    let mut result = Vec::new();
    for (_path, entry_lock) in entries.iter() {
        let e = entry_lock.read().unwrap();
        result.push(MountInfo {
            path: e.path.clone(),
            mount_type: e.logical_type.clone(),
            description: e.description.clone(),
        });
    }
    Ok(result)
}

#[tauri::command]
pub async fn list_auth_methods(state: State<'_, AppState>) -> CmdResult<Vec<MountInfo>> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let module = core.module_manager.get_module::<bastion_vault::modules::auth::AuthModule>("auth");
    match module {
        Some(auth_module) => {
            let entries = auth_module.mounts_router.mounts.entries.read().unwrap();
            let mut result = Vec::new();
            for (_path, entry_lock) in entries.iter() {
                let e = entry_lock.read().unwrap();
                result.push(MountInfo {
                    path: e.path.clone(),
                    mount_type: e.logical_type.clone(),
                    description: e.description.clone(),
                });
            }
            Ok(result)
        }
        None => Ok(Vec::new()),
    }
}
