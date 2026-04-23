//! Vault-profile CRUD: list, add, update, remove, and set-default.
//!
//! The GUI's Get Started screen enumerates vaults via
//! `list_vault_profiles`, adds new ones via `add_vault_profile`, and
//! flips the current default via `set_last_used_vault`. Every entry
//! has a stable `id` the UI uses as a handle; display `name` is
//! separately editable.
//!
//! `remove_vault_profile` only edits the preferences file — it does
//! not destroy any data. Removing a Local profile leaves the data
//! directory untouched; removing a Remote profile just forgets the
//! address; removing a Cloud profile doesn't touch the bucket or
//! folder. The user is free to re-add the same profile later.
//!
//! On save, legacy preference fields (`mode`, `remote_profile`,
//! `cloud_storage`) are dropped via `skip_serializing_if` so a
//! migrated file only carries the new shape going forward.

use crate::error::{CmdResult, CommandError};
use crate::preferences::{self, short_id, VaultProfile, VaultSpec};

/// Return the saved vault list + the currently-default id.
///
/// The default is whichever vault the user most recently opened. On
/// a fresh install this is `None` and the UI shows the chooser with
/// only the "Add new" actions visible.
#[tauri::command]
pub async fn list_vault_profiles() -> CmdResult<VaultProfileList> {
    let prefs = preferences::load().unwrap_or_default();
    Ok(VaultProfileList {
        vaults: prefs.vaults,
        last_used_id: prefs.last_used_id,
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProfileList {
    pub vaults: Vec<VaultProfile>,
    pub last_used_id: Option<String>,
}

/// Append a new vault profile and, by default, set it as the new
/// last-used so the caller can immediately open it. The returned id
/// is the caller's handle for subsequent operations.
#[tauri::command]
pub async fn add_vault_profile(
    name: String,
    spec: VaultSpec,
    set_default: Option<bool>,
) -> CmdResult<String> {
    if name.trim().is_empty() {
        return Err("vault profile name cannot be empty".into());
    }
    let mut prefs = preferences::load().unwrap_or_default();
    let id = short_id();
    prefs.vaults.push(VaultProfile {
        id: id.clone(),
        name: name.trim().to_string(),
        spec,
    });
    if set_default.unwrap_or(true) {
        prefs.last_used_id = Some(id.clone());
    }
    preferences::save(&prefs)?;
    Ok(id)
}

/// Replace an existing vault profile in place (name + spec). Used by
/// the Settings "Edit vault" UI. `set_last_used_vault` is a separate
/// command so editing doesn't have a side-effect on which vault is
/// the default.
#[tauri::command]
pub async fn update_vault_profile(
    id: String,
    name: String,
    spec: VaultSpec,
) -> CmdResult<()> {
    if name.trim().is_empty() {
        return Err("vault profile name cannot be empty".into());
    }
    let mut prefs = preferences::load().unwrap_or_default();
    let entry = prefs
        .vaults
        .iter_mut()
        .find(|v| v.id == id)
        .ok_or_else(|| CommandError::from(format!("no vault profile with id `{id}`")))?;
    entry.name = name.trim().to_string();
    entry.spec = spec;
    preferences::save(&prefs)
}

/// Remove a vault profile from the saved list. If the removed entry
/// was the current default, `last_used_id` is cleared so the UI falls
/// back to the chooser on the next launch. Safe to call twice —
/// missing id is reported as an error the caller can swallow or
/// surface as a toast.
#[tauri::command]
pub async fn remove_vault_profile(id: String) -> CmdResult<()> {
    let mut prefs = preferences::load().unwrap_or_default();
    let before = prefs.vaults.len();
    prefs.vaults.retain(|v| v.id != id);
    if prefs.vaults.len() == before {
        return Err(format!("no vault profile with id `{id}`").into());
    }
    if prefs.last_used_id.as_deref() == Some(id.as_str()) {
        prefs.last_used_id = None;
    }
    preferences::save(&prefs)
}

/// Mark a saved vault profile as the new default. Called both after
/// successful open (so subsequent launches auto-resume it) and from
/// the Settings "Switch default" control.
#[tauri::command]
pub async fn set_last_used_vault(id: String) -> CmdResult<()> {
    let mut prefs = preferences::load().unwrap_or_default();
    if !prefs.vaults.iter().any(|v| v.id == id) {
        return Err(format!("no vault profile with id `{id}`").into());
    }
    prefs.last_used_id = Some(id);
    preferences::save(&prefs)
}

/// Clear `last_used_id` so the next launch shows the chooser. Used
/// by the "Switch vault" button in Settings.
#[tauri::command]
pub async fn clear_last_used_vault() -> CmdResult<()> {
    let mut prefs = preferences::load().unwrap_or_default();
    prefs.last_used_id = None;
    preferences::save(&prefs)
}

/// Look up a single profile by id. The ConnectPage open-flow calls
/// this just before invoking the right connect command, so the
/// frontend always works against a fresh copy of the saved config
/// (operators who hand-edit the JSON while the app is running see
/// their changes reflected immediately).
#[tauri::command]
pub async fn get_vault_profile(id: String) -> CmdResult<VaultProfile> {
    let prefs = preferences::load().unwrap_or_default();
    prefs
        .vaults
        .into_iter()
        .find(|v| v.id == id)
        .ok_or_else(|| format!("no vault profile with id `{id}`").into())
}

/// Return the canonical default data directory for a local vault of
/// the given storage engine. Used by the Add Local Vault modal to
/// pre-populate the path field and for the "Reset to default"
/// button. `kind` is `"file"` or `"hiqlite"`; anything else defaults
/// to `"file"` so a typo from the frontend doesn't hard-fail.
#[tauri::command]
pub async fn get_default_local_data_dir(kind: String) -> CmdResult<String> {
    use crate::embedded::{data_dir_for, StorageKind};
    let sk = match kind.as_str() {
        "hiqlite" => StorageKind::Hiqlite,
        _ => StorageKind::File,
    };
    let path = data_dir_for(sk)?;
    Ok(path.to_string_lossy().into_owned())
}
