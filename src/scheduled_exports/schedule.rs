//! Schedule + RunRecord domain types.

use serde::{Deserialize, Serialize};

use crate::exchange::ScopeSpec;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ExportFormat {
    /// Argon2id + XChaCha20-Poly1305 password-encrypted envelope.
    #[default]
    Bvx,
    /// Plaintext canonical JSON. Refused unless `allow_plaintext` is set.
    Json,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationKind {
    /// Atomic tmp-then-rename write to a directory on the BastionVault host.
    LocalPath { path: String },
    // Future: CloudTarget { target, prefix }, HttpWebhook { url, ... }.
}

impl DestinationKind {
    /// Reject destinations that cannot round-trip a backup before a schedule
    /// is persisted.
    ///
    /// An empty or relative `LocalPath` is the dangerous case: the runner
    /// resolves it against the server process's current working directory
    /// (`Path::new("").join(name)` yields a bare relative name), so the write
    /// "succeeds" into an undefined location while the listing endpoint —
    /// which `read_dir`s the configured path — gets `NotFound` on an empty
    /// string and reports zero backups. The result is a silently unlistable
    /// backup. Requiring a non-empty absolute path closes that gap.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            DestinationKind::LocalPath { path } => {
                if path.trim().is_empty() {
                    return Err("destination path must not be empty".to_string());
                }
                if !std::path::Path::new(path).is_absolute() {
                    return Err(format!(
                        "destination path must be absolute, got {path:?}"
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PasswordRefKind {
    /// Literal password baked into the schedule. Stored barrier-encrypted
    /// (the schedule record itself is barrier-encrypted at rest like every
    /// other vault state). Practical for single-operator deployments;
    /// rotation requires editing the schedule.
    Literal { password: String },
    /// Read the password from a barrier-encrypted KV path at run time.
    /// The runner reads `<mount><path>` and uses the value's `password`
    /// field. Rotation = update the KV value; no schedule edit needed.
    StaticSecret { mount: String, path: String },
    // Future: Transit { key, param }, ExternalKms { ... }.
}

/// Persisted schedule record.
///
/// Storage shape matches the spec's JSON example except where noted. The
/// password lives via reference (`PasswordRefKind`) — never plaintext on
/// the schedule itself unless the operator explicitly picks `Literal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub cron: String,
    #[serde(default)]
    pub format: ExportFormat,
    pub scope: ScopeSpec,
    pub destination: DestinationKind,
    pub password_ref: Option<PasswordRefKind>,
    /// Required when `format = Json` so the engine produces an unencrypted
    /// file (matching the HTTP path's `allow_plaintext` discipline).
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Optional comment embedded in the `.bvx` envelope's `comment` field.
    #[serde(default)]
    pub comment: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Input shape for `POST /v1/sys/scheduled-exports` and PATCH. The id +
/// timestamps are server-controlled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleInput {
    pub name: String,
    pub cron: String,
    #[serde(default)]
    pub format: ExportFormat,
    pub scope: ScopeSpec,
    pub destination: DestinationKind,
    pub password_ref: Option<PasswordRefKind>,
    #[serde(default)]
    pub allow_plaintext: bool,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub schedule_id: String,
    pub run_at: String,
    pub status: RunStatus,
    pub bytes_written: u64,
    pub destination: DestinationKind,
    /// Set on `RunStatus::Failed`.
    #[serde(default)]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_path_validation_rejects_empty_and_relative() {
        // Empty / whitespace-only: the incident case — writes land in the
        // server CWD, listing reads "" and finds nothing.
        assert!(DestinationKind::LocalPath { path: String::new() }.validate().is_err());
        assert!(DestinationKind::LocalPath { path: "   ".into() }.validate().is_err());
        // Relative paths resolve against CWD too — equally unlistable.
        assert!(DestinationKind::LocalPath { path: "backups".into() }.validate().is_err());
        assert!(DestinationKind::LocalPath { path: "./backups".into() }.validate().is_err());
        // A leading space makes an otherwise-absolute path non-absolute.
        assert!(DestinationKind::LocalPath { path: " /backups".into() }.validate().is_err());
    }

    #[test]
    fn local_path_validation_accepts_absolute() {
        assert!(DestinationKind::LocalPath { path: "/backups".into() }.validate().is_ok());
        assert!(DestinationKind::LocalPath { path: "/var/lib/bvault/backups".into() }.validate().is_ok());
    }
}
