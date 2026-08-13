//! Contracts between Tier 3 engines.
//!
//! Everything else in `kernel_api` is an engine talking *down* to the kernel.
//! This file is engines talking *sideways*, and it exists because the
//! decomposition roadmap's "Tier 3 — engines (each: Tier 0 + `bv-kernel-api`
//! only)" was not true: four engine pairs named each other's concrete types.
//!
//! | edge | what crossed it |
//! |---|---|
//! | `resource` → `ssh_broker` | `EffectiveLoginClass`, `LoginClass` |
//! | `rustion` → `resource` | `connect_mfa::enforce` |
//! | `credential` → `totp` | `mfa::verify_code`, `mfa::normalize_mount` |
//! | `plugins` → `notifications` | `NotificationService` |
//!
//! Each is now a trait registered by the providing engine and resolved through
//! [`VaultCtx`](super::VaultCtx), so neither side names the other. The types
//! that cross are narrowed to the answer the consumer actually uses — the
//! resource engine reads two fields of `EffectiveLoginClass` out of six, so
//! [`LoginClassVerdict`] carries two.
//!
//! **These are engine contracts, not kernel contracts.** They live beside
//! `VaultCtx` today because there is nowhere else yet; when the engine crates
//! land they belong in a `bv-engine-api` crate that depends on
//! `bv-kernel-api`, not in `bv-kernel-api` itself. Keeping them in their own
//! file is what makes that a file move.

use serde_json::Value;

use crate::{errors::RvError, logical::Request};

// ── resource → ssh_broker ──────────────────────────────────────────────

/// How a resource's SSH logins are minted.
///
/// The resource engine asks one question — "is this resource brokered?" — to
/// refuse attaching a static SSH credential to it. The full tier-resolution
/// result (`EffectiveLoginClass`: lock state, per-tier chain, violations)
/// stays inside the ssh-broker engine, which is the only place that can act
/// on it.
#[derive(Debug, Clone)]
pub struct LoginClassVerdict {
    /// True when every login must be minted per-connect from the SSH engine.
    pub brokered: bool,
    /// Which tier decided, for the operator-facing refusal message.
    pub source: String,
}

impl Default for LoginClassVerdict {
    /// A deployment that never configures brokering: shared credentials, by
    /// default, decided by nothing.
    fn default() -> Self {
        Self { brokered: false, source: "default".to_string() }
    }
}

/// Resolves the login class for a resource from the brokering policy tiers.
#[maybe_async::maybe_async]
pub trait LoginClassPolicy: Send + Sync {
    async fn resolve_for(
        &self,
        resource_type: &str,
        asset_group_ids: &[String],
        resource_id: &str,
    ) -> Result<LoginClassVerdict, RvError>;
}

// ── rustion → resource ─────────────────────────────────────────────────

/// A redeemed connect-MFA ticket, for the audit line the transport writes.
#[derive(Debug, Clone)]
pub struct ConnectMfaGrant {
    pub principal: String,
    pub method: String,
}

/// Whether a connection profile record carries the MFA gate flag.
///
/// A plain predicate over the stored profile JSON, not a trait method: both
/// engines read the same field off the same record, and a transport asking
/// "is anything on this resource gated" reads many profiles at once.
pub fn profile_gate_flag(profile: &Value) -> bool {
    profile.get("require_mfa").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// The connect-MFA gate, owned by the resource engine and enforced by every
/// transport that opens a session.
#[maybe_async::maybe_async]
pub trait ConnectMfaGate: Send + Sync {
    /// Enforce the gate for one connect.
    ///
    /// `Ok(None)` — the profile is not gated, nothing to check. `Ok(Some(_))` —
    /// the gate applied and the ticket was redeemed. `Err` — refused; the
    /// error carries the operator-facing reason and the correct status.
    ///
    /// A missing `ticket` on a gated profile is an error, never a pass.
    async fn enforce(
        &self,
        req: &Request,
        ns_prefix: &str,
        resource: &str,
        profile_id: &str,
        ticket: Option<&str>,
    ) -> Result<Option<ConnectMfaGrant>, RvError>;

    /// Whether *any* connection profile on `resource` is gated.
    ///
    /// A transport uses this to refuse an unattributed open — a caller that
    /// omits `profile_id` on a resource carrying a gated profile must not be
    /// routed around the gate.
    async fn resource_has_gated_profile(
        &self,
        ns_prefix: &str,
        resource: &str,
    ) -> Result<bool, RvError>;
}

// ── credential → totp ──────────────────────────────────────────────────

/// TOTP second-factor verification, owned by the TOTP engine.
///
/// The credential backends call this at login and at step-up. They must not
/// hold the key policy or the comparison itself: the skew walk is
/// constant-time and lives in one place on purpose.
#[maybe_async::maybe_async]
pub trait TotpMfa: Send + Sync {
    /// Canonical form of a TOTP engine mount path.
    fn normalize_mount(&self, mount: &str) -> String;

    /// `Ok(true)` = the code is valid right now. `Ok(false)` = it is not.
    /// `Err(_)` = the check could not run (no mount, no key, storage failure)
    /// — never treat that as a pass.
    async fn verify_code(
        &self,
        mount: &str,
        key_name: &str,
        code: &str,
        now_secs: u64,
    ) -> Result<bool, RvError>;
}

// ── plugins → notifications ────────────────────────────────────────────

/// A notification a plugin or engine wants delivered.
///
/// Mirrors the notification service's own request shape as raw JSON: the
/// service owns validation, targeting and channel selection, and re-declaring
/// its schema here would be a second place to keep in sync.
#[maybe_async::maybe_async]
pub trait NotificationSink: Send + Sync {
    /// Send a notification attributed to `author` (a plugin name, or empty for
    /// the server itself). `notification` is the request body; the service
    /// overwrites `source` so an author can never forge a system origin.
    ///
    /// Returns `{"id": ..., "recipient_count": ...}`.
    async fn send_from_plugin(
        &self,
        author: &str,
        notification: Value,
        ns_path: &str,
    ) -> Result<Value, RvError>;

    /// Notifications authored by `author`, newest first.
    async fn list_authored_by_plugin(
        &self,
        author: &str,
        ns_path: &str,
    ) -> Result<Vec<Value>, RvError>;

    /// One notification authored by `author`, or `None`.
    async fn get_authored_by_plugin(
        &self,
        author: &str,
        ns_path: &str,
        id: &str,
    ) -> Result<Option<Value>, RvError>;
}
