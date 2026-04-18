use serde::{Deserialize, Serialize};

use crate::error::CommandError;
use crate::state::{RemoteProfile, VaultMode};

/// Minimum-acceptable password composition for the built-in password
/// generator. Saved in the GUI's local preferences file (not in the vault)
/// because it is a UX policy, not an authorization one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 16,
            require_lowercase: true,
            require_uppercase: true,
            require_digits: true,
            require_symbols: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    pub mode: VaultMode,
    #[serde(default)]
    pub remote_profile: Option<RemoteProfile>,
    #[serde(default)]
    pub password_policy: PasswordPolicy,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            mode: VaultMode::Embedded,
            remote_profile: None,
            password_policy: PasswordPolicy::default(),
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
