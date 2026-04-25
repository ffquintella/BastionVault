//! Schedule + RunRecord domain types.

use serde::{Deserialize, Serialize};

use crate::exchange::ScopeSpec;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Argon2id + XChaCha20-Poly1305 password-encrypted envelope.
    Bvx,
    /// Plaintext canonical JSON. Refused unless `allow_plaintext` is set.
    Json,
}

impl Default for ExportFormat {
    fn default() -> Self {
        Self::Bvx
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationKind {
    /// Atomic tmp-then-rename write to a directory on the BastionVault host.
    LocalPath { path: String },
    // Future: CloudTarget { target, prefix }, HttpWebhook { url, ... }.
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
