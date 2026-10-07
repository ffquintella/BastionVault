use std::collections::BTreeMap;

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

/// Where Resource Connect sessions are rendered (features/session-workspace.md
/// §5). A UX preference kept in the local preferences file next to
/// `PasswordPolicy`; it never decides *whether* a session may open, only
/// where it is drawn.
///
/// Both fields are strings on disk, as in the spec, and are parsed strictly
/// where they are used (`session::workspace`): a value this build does not
/// know is an error naming it, never a guess. `set_session_workspace_prefs`
/// validates before it writes, so only a hand-edited file can carry one.
///
/// `#[serde(default)]` keeps files written by any phase readable by every
/// other, in both directions (a missing key takes its default, an unknown
/// one is ignored). Saved layouts (Phase 5) live in their own file, not
/// here — see `session::layouts` for why.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SessionWorkspacePrefs {
    /// `workspace` (default) or `windows`. `windows` keeps one
    /// `WebviewWindow` per session; on macOS those windows carry a shared
    /// tabbing identifier so they group as native window tabs.
    pub layout_mode: String,
    /// Placement used when an open request carries none: `workspace-tab`
    /// (default since T38 Phase 3) or `own-window`; the two split
    /// placements are accepted too.
    pub default_placement: String,
    /// Ask before a paste containing a line break reaches a terminal pane
    /// (T38 Phase 4). On by default.
    pub confirm_multiline_paste: bool,
    /// Workspace action id → chord, overriding the platform default in
    /// `gui/src/lib/reservedChords.ts`. A `BTreeMap` so the file is written
    /// in a stable order.
    pub chord_overrides: BTreeMap<String, String>,
    /// Keep the most recent 256 KiB of each SSH session's output in host
    /// memory after it is shown, so a session moved to another window
    /// redraws it (T38 Phase 6, `session::output`). Off by default: it is
    /// plaintext session output held for the life of the session. Read at
    /// open, so it applies to sessions opened after it changes.
    pub replay_buffer: bool,
}

impl Default for SessionWorkspacePrefs {
    fn default() -> Self {
        Self {
            layout_mode: "workspace".to_string(),
            default_placement: "workspace-tab".to_string(),
            confirm_multiline_paste: true,
            chord_overrides: BTreeMap::new(),
            replay_buffer: false,
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
#[derive(Default)]
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
    /// Session layout preferences (T38). Absent in files written before
    /// the Session Workspace; those load as the defaults.
    #[serde(default)]
    pub session_workspace: SessionWorkspacePrefs,

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
                    spec: VaultSpec::Local { data_dir: None, storage_kind: default_local_storage_kind() },
                });
            }
            Some(VaultMode::Remote) => {
                if let Some(profile) = self.remote_profile.clone() {
                    entries.push(VaultProfile {
                        id: short_id(),
                        name: if profile.name.is_empty() { "Remote Vault".to_string() } else { profile.name.clone() },
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
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    // Stir in a pid to disambiguate two adds inside the same ns
    // clock tick (rare but possible on fast hardware).
    let pid = std::process::id() as u128;
    format!("v{:x}{:x}", nanos, pid)
}

fn prefs_path() -> Result<std::path::PathBuf, CommandError> {
    let base = dirs::data_local_dir().or_else(dirs::home_dir).ok_or("Cannot determine home directory")?;
    Ok(base.join(".bastion_vault_gui").join("preferences.json"))
}

pub fn load() -> Result<Preferences, CommandError> {
    let path = prefs_path()?;
    if !path.exists() {
        return Ok(Preferences::default());
    }
    let data = std::fs::read_to_string(&path)?;
    let mut prefs: Preferences =
        serde_json::from_str(&data).map_err(|e| CommandError::from(format!("Failed to parse preferences: {e}")))?;
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

#[cfg(test)]
mod session_workspace_prefs_tests {
    use super::{Preferences, SessionWorkspacePrefs};

    /// A preferences file written before T38 has no `session_workspace`
    /// key; it must load, and load as the defaults (workspace tabs since
    /// Phase 3, paste confirmation on, no chord overrides).
    #[test]
    fn file_without_session_workspace_loads_the_defaults() {
        let prefs: Preferences = serde_json::from_str(r#"{ "vaults": [], "last_used_id": null }"#).unwrap();
        assert_eq!(prefs.session_workspace, SessionWorkspacePrefs::default());
        assert_eq!(prefs.session_workspace.layout_mode, "workspace");
        assert_eq!(prefs.session_workspace.default_placement, "workspace-tab");
        assert!(prefs.session_workspace.confirm_multiline_paste);
        assert!(prefs.session_workspace.chord_overrides.is_empty());
        // Phase 6: the output replay ring is opt-in.
        assert!(!prefs.session_workspace.replay_buffer);
    }

    /// A file written by Phases 0–4 has no `replay_buffer`; it loads off.
    #[test]
    fn a_phase_4_file_loads_with_the_replay_buffer_off() {
        let prefs: Preferences = serde_json::from_str(
            r#"{ "session_workspace": { "layout_mode": "workspace", "default_placement": "workspace-tab",
                 "confirm_multiline_paste": true, "chord_overrides": {} } }"#,
        )
        .unwrap();
        assert!(!prefs.session_workspace.replay_buffer);
    }

    /// A file written by Phases 0–2 carries only the first two keys, with
    /// the then-default `own-window` written out explicitly. It keeps that
    /// choice, and gains the Phase 4 defaults.
    #[test]
    fn a_phase_2_file_keeps_its_placement_and_gains_the_new_defaults() {
        let prefs: Preferences = serde_json::from_str(
            r#"{ "session_workspace": { "layout_mode": "workspace", "default_placement": "own-window" } }"#,
        )
        .unwrap();
        assert_eq!(prefs.session_workspace.default_placement, "own-window");
        assert!(prefs.session_workspace.confirm_multiline_paste);
        assert!(prefs.session_workspace.chord_overrides.is_empty());
    }

    /// A later phase may write only some of the keys (or more of them);
    /// the missing ones default and the unknown ones are ignored.
    #[test]
    fn partial_and_future_session_workspace_objects_load() {
        let prefs: Preferences = serde_json::from_str(
            r#"{ "session_workspace": { "layout_mode": "windows", "confirm_multiline_paste": false, "saved_layouts": {} } }"#,
        )
        .unwrap();
        assert_eq!(prefs.session_workspace.layout_mode, "windows");
        assert_eq!(prefs.session_workspace.default_placement, "workspace-tab");
        assert!(!prefs.session_workspace.confirm_multiline_paste);
    }

    #[test]
    fn round_trips() {
        let mut prefs = Preferences::default();
        prefs.session_workspace.layout_mode = "windows".into();
        prefs.session_workspace.confirm_multiline_paste = false;
        prefs.session_workspace.chord_overrides.insert("splitRight".into(), "Ctrl+Shift+R".into());
        let back: Preferences = serde_json::from_str(&serde_json::to_string(&prefs).unwrap()).unwrap();
        assert_eq!(back.session_workspace, prefs.session_workspace);
    }
}
