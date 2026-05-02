//! Storage types for the cert-lifecycle module — Phase L5.
//!
//! Storage keys (all live under the engine's mount inside the barrier):
//!
//! ```text
//! targets/<name>     # JSON Target
//! state/<name>       # JSON TargetState
//! ```
//!
//! Lookup is by operator-supplied name. Names follow the same lexical
//! rules as PKI role names — `\w[\w-]*\w` — so they survive being
//! embedded in URL paths without escaping.

use serde::{Deserialize, Serialize};

use crate::{errors::RvError, logical::Request};

pub fn target_storage_key(name: &str) -> String {
    format!("targets/{name}")
}

pub fn state_storage_key(name: &str) -> String {
    format!("state/{name}")
}

pub const KEY_SCHEDULER_CONFIG: &str = "scheduler/config";

/// Per-mount scheduler config. Phase L6.
///
/// The L6 scheduler is opt-in: a mount with `enabled = false` (the
/// default) is never visited. When enabled the operator must supply a
/// `client_token` — the scheduler uses this token to dispatch
/// `pki/issue/<role>` calls into the configured PKI mount, so the
/// PKI ACL / namespace / policy boundary is exactly the same one the
/// operator established when they minted the token. There is no
/// scheduler-side ACL bypass.
///
/// Backoff:
/// - On success, `next_attempt_unix` is set to
///   `current_not_after - renew_before`.
/// - On failure, `next_attempt_unix = now + min(max_backoff,
///   base_backoff * 2^(failure_count - 1))`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SchedulerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// How often the in-process tick fires for this mount. Clamped to
    /// at least 30 seconds at runtime.
    #[serde(default = "default_tick_interval_seconds")]
    pub tick_interval_seconds: u64,
    /// Token the scheduler dispatches PKI calls under. Empty token
    /// effectively disables the scheduler regardless of `enabled`.
    #[serde(default)]
    pub client_token: String,
    /// First backoff after a failure. Doubles per consecutive failure
    /// up to `max_backoff_seconds`.
    #[serde(default = "default_base_backoff_seconds")]
    pub base_backoff_seconds: u64,
    /// Cap on the doubled backoff.
    #[serde(default = "default_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_seconds: default_tick_interval_seconds(),
            client_token: String::new(),
            base_backoff_seconds: default_base_backoff_seconds(),
            max_backoff_seconds: default_max_backoff_seconds(),
        }
    }
}

fn default_tick_interval_seconds() -> u64 {
    30
}

fn default_base_backoff_seconds() -> u64 {
    60
}

fn default_max_backoff_seconds() -> u64 {
    3600
}

/// What kind of consumer this target represents.
///
/// Phase L5 shipped `File`; Phase L7 adds `HttpPush` (POST a JSON
/// envelope to a webhook URL). Additional kinds (e.g. `K8sSecret`,
/// `Plugin/<id>`) plug into the [`super::delivery::DelivererRegistry`]
/// without changing storage shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// Write the cert / key / chain into a directory at `address`.
    #[default]
    File,
    /// `POST` a JSON envelope to the URL at `address`.
    HttpPush,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::HttpPush => "http-push",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, RvError> {
        match s {
            "" | "file" => Ok(Self::File),
            "http-push" | "http_push" => Ok(Self::HttpPush),
            other => Err(RvError::ErrString(format!(
                "cert-lifecycle: unsupported target kind `{other}` (supported: `file`, `http-push`)"
            ))),
        }
    }
}

/// How the renewer treats the target's private key.
///
/// - `Rotate` — every renewal mints a fresh keypair (PKI default).
/// - `Reuse`  — the renewer pins `target.key_ref` on every issue call so
///   the leaf certs all share one private key. Requires the role's
///   `allow_key_reuse = true` (Phase L2 gate).
/// - `AgentGenerates` — declared here for forward compatibility but
///   intentionally not yet implemented (the consumer holding the key
///   would need to push a CSR to the engine; that transport lands in
///   L7).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPolicy {
    #[default]
    Rotate,
    Reuse,
    AgentGenerates,
}

impl KeyPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::Reuse => "reuse",
            Self::AgentGenerates => "agent-generates",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, RvError> {
        match s {
            "" | "rotate" => Ok(Self::Rotate),
            "reuse" => Ok(Self::Reuse),
            "agent-generates" | "agent_generates" => Ok(Self::AgentGenerates),
            other => Err(RvError::ErrString(format!(
                "cert-lifecycle: unsupported key_policy `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    #[serde(default)]
    pub kind: TargetKind,
    /// For `kind = File`, an absolute filesystem path that the renewer
    /// will treat as a *directory* and populate with `cert.pem`,
    /// `key.pem`, and `chain.pem`. The directory must already exist —
    /// the engine refuses to create or recursively chmod paths.
    pub address: String,
    /// PKI mount name to call (`pki/...`). Default `"pki"`.
    #[serde(default = "default_pki_mount")]
    pub pki_mount: String,
    pub role_ref: String,
    pub common_name: String,
    #[serde(default)]
    pub alt_names: Vec<String>,
    #[serde(default)]
    pub ip_sans: Vec<String>,
    /// Optional duration string (e.g. `"720h"`). Empty = role default.
    #[serde(default)]
    pub ttl: String,
    #[serde(default)]
    pub key_policy: KeyPolicy,
    /// Required when `key_policy == Reuse`. Otherwise empty.
    #[serde(default)]
    pub key_ref: String,
    /// How long before `NotAfter` the renewer should fire. The
    /// scheduler (L6) reads this; L5's manual renew endpoint ignores
    /// it and renews unconditionally.
    #[serde(default = "default_renew_before")]
    pub renew_before: String,
    pub created_at_unix: u64,
}

fn default_pki_mount() -> String {
    "pki".to_string()
}

fn default_renew_before() -> String {
    "168h".to_string() // 1 week
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetState {
    /// Hex-encoded serial of the most-recently-issued cert. Empty
    /// before the first successful renewal.
    #[serde(default)]
    pub current_serial: String,
    /// Unix timestamp of the current cert's `NotAfter`. 0 before the
    /// first successful renewal.
    #[serde(default)]
    pub current_not_after_unix: i64,
    /// Unix timestamp of the most-recent successful renewal.
    #[serde(default)]
    pub last_renewal_unix: u64,
    /// Unix timestamp of the most-recent renewal *attempt* (success
    /// or failure).
    #[serde(default)]
    pub last_attempt_unix: u64,
    /// Empty when the last attempt succeeded; otherwise carries the
    /// surfaced error message.
    #[serde(default)]
    pub last_error: String,
    /// Set by the scheduler (L6). Unused in L5.
    #[serde(default)]
    pub next_attempt_unix: u64,
    /// Consecutive-failure counter for the L6 backoff. Reset on
    /// success.
    #[serde(default)]
    pub failure_count: u32,
}

#[maybe_async::maybe_async]
pub async fn put_json<T: Serialize>(req: &Request, key: &str, value: &T) -> Result<(), RvError> {
    let bytes = serde_json::to_vec(value)?;
    let entry = crate::storage::StorageEntry { key: key.to_string(), value: bytes };
    req.storage_put(&entry).await
}

#[maybe_async::maybe_async]
pub async fn get_json<T: for<'de> Deserialize<'de>>(
    req: &Request,
    key: &str,
) -> Result<Option<T>, RvError> {
    match req.storage_get(key).await? {
        Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
        None => Ok(None),
    }
}
