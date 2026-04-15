use serde::{Deserialize, Serialize};

use crate::error::CommandError;
use crate::state::{RemoteProfile, VaultMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    pub mode: VaultMode,
    #[serde(default)]
    pub remote_profile: Option<RemoteProfile>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            mode: VaultMode::Embedded,
            remote_profile: None,
        }
    }
}

fn prefs_path() -> Result<std::path::PathBuf, CommandError> {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .ok_or("Cannot determine home directory")?;
    Ok(base.join(".bastion_vault_gui").join("preferences.json"))
}

pub fn load() -> Result<Preferences, CommandError> {
    let path = prefs_path()?;
    if !path.exists() {
        return Ok(Preferences::default());
    }
    let data = std::fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(|e| {
        CommandError::from(format!("Failed to parse preferences: {e}"))
    })
}

pub fn save(prefs: &Preferences) -> Result<(), CommandError> {
    let path = prefs_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(prefs).map_err(|e| {
        CommandError::from(format!("Failed to serialize preferences: {e}"))
    })?;
    std::fs::write(&path, data)?;
    Ok(())
}
