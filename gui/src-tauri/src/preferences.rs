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

/// Configuration for a cloud-backed embedded vault. When present on
/// a `VaultProfile` of kind `Cloud`, `embedded::build_backend`
/// constructs storage as a `FileBackend` wrapped around the named
/// cloud target instead of the default local path.
///
/// `target` is one of `"s3"`, `"onedrive"`, `"gdrive"`, `"dropbox"`.
/// `config` is a free-form JSON object handed straight to the
/// target's `from_config` constructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorageConfig {
    pub target: String,
    #[serde(flatten)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// One saved vault entry. `id` is a stable short identifier (not the
/// display name, which can be edited). `spec` is kind-specific config.
///
/// The preferences file is user-editable JSON; adding or reordering
/// entries by hand is expected, so we keep every field explicit and
/// human-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultProfile {
    pub id: String,
    pub name: String,
    pub spec: VaultSpec,
}

/// Kind-specific configuration. Serialized with a `kind` tag so the
/// preferences file stays readable (`"kind": "local" | "remote" |
/// "cloud"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum VaultSpec {
    /// Embedded vault backed by local storage. `data_dir` defaults
    /// to the canonical per-profile path when absent (currently a
    /// single shared data dir — multi-data-dir support is a future
    /// sub-slice). `storage_kind` is `"file"` or `"hiqlite"`.
    Local {
        #[serde(default)]
        data_dir: Option<String>,
        #[serde(default = "default_local_storage_kind")]
        storage_kind: String,
    },
    /// Remote BastionVault server over HTTP(S).
    Remote { profile: RemoteProfile },
    /// Embedded vault backed by a cloud `FileTarget`.
    Cloud { config: CloudStorageConfig },
}

fn default_local_storage_kind() -> String {
    // Matches `embedded::storage_kind` default; picked up by
    // `build_backend` when the env var isn't set.
    "file".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    /// All saved vault profiles. Order is preserved from the on-disk
    /// file so operators who hand-edit the JSON control the UI's
    /// sort order.
    #[serde(default)]
    pub vaults: Vec<VaultProfile>,
    /// ID of the most recently opened vault; the UI treats it as
    /// the default on app launch. `None` means "show the chooser".
    #[serde(default)]
    pub last_used_id: Option<String>,
    #[serde(default)]
    pub password_policy: PasswordPolicy,

    // ── Legacy fields (pre-multi-vault preferences) ───────────────
    //
    // These three were the original single-vault config. We keep
    // them on the struct so an existing install still deserializes
    // cleanly; `migrate_legacy` folds them into `vaults` on load
    // and they're cleared from the next `save()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<VaultMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_profile: Option<RemoteProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_storage: Option<CloudStorageConfig>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            vaults: Vec::new(),
            last_used_id: None,
            password_policy: PasswordPolicy::default(),
            mode: None,
            remote_profile: None,
            cloud_storage: None,
        }
    }
}

impl Preferences {
    /// One-time in-memory migration: if the on-disk file was written
    /// by a pre-multi-vault build (legacy fields set, `vaults` empty)
    /// fold them into the new list. Called from `load()`, and the
    /// next `save()` will strip the legacy fields via
    /// `skip_serializing_if = Option::is_none`.
    ///
    /// Idempotent: re-running on an already-migrated file is a no-op.
    pub fn migrate_legacy(&mut self) {
        if !self.vaults.is_empty() {
            // Already migrated.
            self.mode = None;
            self.remote_profile = None;
            self.cloud_storage = None;
            return;
        }

        let mut entries: Vec<VaultProfile> = Vec::new();

        // Pull in the legacy local-embedded mode first so it ends up
        // as the default in single-vault upgrades.
        match self.mode {
            Some(VaultMode::Embedded) => {
                entries.push(VaultProfile {
                    id: short_id(),
                    name: "Local Vault".to_string(),
                    spec: VaultSpec::Local {
                        data_dir: None,
                        storage_kind: default_local_storage_kind(),
                    },
                });
            }
            Some(VaultMode::Remote) => {
                if let Some(profile) = self.remote_profile.clone() {
                    entries.push(VaultProfile {
                        id: short_id(),
                        name: if profile.name.is_empty() {
                            "Remote Vault".to_string()
                        } else {
                            profile.name.clone()
                        },
                        spec: VaultSpec::Remote { profile },
                    });
                }
            }
            None => {}
        }

        // If the legacy file had a cloud_storage but mode wasn't
        // Embedded (unusual), still preserve it.
        if let Some(cloud) = self.cloud_storage.clone() {
            if !entries.iter().any(|e| matches!(e.spec, VaultSpec::Cloud { .. })) {
                entries.push(VaultProfile {
                    id: short_id(),
                    name: format!("Cloud Vault ({})", cloud.target),
                    spec: VaultSpec::Cloud { config: cloud },
                });
            }
        }

        if !entries.is_empty() {
            self.last_used_id = Some(entries[0].id.clone());
            self.vaults = entries;
        }
        self.mode = None;
        self.remote_profile = None;
        self.cloud_storage = None;
    }

    /// Return the currently-default profile, if any. The UI uses
    /// this to auto-open on app launch.
    pub fn default_profile(&self) -> Option<&VaultProfile> {
        let id = self.last_used_id.as_deref()?;
        self.vaults.iter().find(|v| v.id == id)
    }
}

/// Short random-ish ID for a saved vault profile. Not cryptographic;
/// just needs to be unique within the file.
pub fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Stir in a pid to disambiguate two adds inside the same ns
    // clock tick (rare but possible on fast hardware).
    let pid = std::process::id() as u128;
    format!("v{:x}{:x}", nanos, pid)
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
    let mut prefs: Preferences = serde_json::from_str(&data)
        .map_err(|e| CommandError::from(format!("Failed to parse preferences: {e}")))?;
    prefs.migrate_legacy();
    Ok(prefs)
}

pub fn save(prefs: &Preferences) -> Result<(), CommandError> {
    let path = prefs_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(prefs)
        .map_err(|e| CommandError::from(format!("Failed to serialize preferences: {e}")))?;
    std::fs::write(&path, data)?;
    Ok(())
}
