//! Data model for the Rustion target registry.
//!
//! A `RustionTarget` describes one enrolled Rustion bastion instance:
//! its control-plane endpoint, pinned hybrid public key, status flags,
//! tags, and a (deliberately lightweight) cached health record. The
//! registry is **multi-instance by design** — a real deployment runs
//! several Rustion instances (per region, primary + DR, PCI zone, …)
//! and the dispatcher (Phase 3) treats them as a pool.
//!
//! Persistence: one CBOR-serialized record per target under the
//! `rustion/targets/<id>` sub-view. Cached health lives next to the
//! record in `rustion/health/<id>` so a target's identity rotation
//! doesn't churn its health history and vice-versa.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Pinned hybrid public key for a Rustion control-plane endpoint.
/// Both halves are required: an Ed25519-only or ML-DSA-only enrolment
/// is rejected as a downgrade attack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HybridPubKey {
    /// Base64-encoded SPKI of the Ed25519 half.
    pub ed25519: String,
    /// Base64-encoded raw FIPS 204 ML-DSA-65 public key.
    pub mldsa65: String,
}

/// One enrolled Rustion bastion instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RustionTarget {
    /// Stable id. Generated on first write; never reused.
    pub id: String,
    /// Operator-visible name. Unique per-deployment (case-insensitive).
    pub name: String,
    /// Control-plane endpoint, `host:port`. TLS-only.
    pub endpoint: String,
    /// Pinned hybrid **signing** pubkey of the Rustion identity
    /// keypair. Rustion signs its outbound `recording.ready` webhook
    /// + signed-nonce health responses with the matching private
    /// key; BV verifies inbound payloads from Rustion with this.
    /// Operators rotate via `rustion control-plane identity rotate`
    /// on the Rustion side, then re-paste here.
    pub public_key: HybridPubKey,
    /// Pinned **KEM** pubkey of the Rustion identity keypair.
    /// Base64-encoded ML-KEM-768 public key (1184 bytes raw → 1580
    /// chars base64). Distinct from `public_key` because the
    /// signing + KEM halves are independent on the Rustion side —
    /// rotating one does not invalidate the other, and the wire
    /// formats are different (FIPS 204 vs FIPS 203). Empty on
    /// records created before this field landed; the session-open
    /// path refuses such records with a `kem_pubkey_missing` error
    /// pointing the operator at the enrolment wizard.
    #[serde(default)]
    pub kem_public_key: String,
    /// SHA-256 of the canonical concatenation `ed25519 || mldsa65`,
    /// rendered as `sha256:xx:xx…`. Computed at write time so the GUI
    /// can show it without re-parsing the keys.
    pub fingerprint: String,
    /// Free-form display description.
    #[serde(default)]
    pub description: String,
    /// Operator-set tags, used for fleet filtering and dispatcher
    /// affinity hints (e.g. `region=eu-west-1`, `zone=pci`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// When disabled, the dispatcher skips this target regardless of
    /// health. Soft toggle for staged drain.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional: relative directory under the Rustion recordings root
    /// where this instance writes. Surfaced in the GUI for diagnostics;
    /// the actual lookup at session-close happens via the sidecar
    /// JSON path Rustion returns.
    #[serde(default)]
    pub default_recording_dir: String,
    /// ISO-8601.
    pub created_at: DateTime<Utc>,
    /// ISO-8601. Bumped on every successful upsert.
    pub updated_at: DateTime<Utc>,
}

fn default_enabled() -> bool {
    true
}

/// Health verdict assigned by the background pinger. `Unknown` is the
/// at-rest value before the first probe completes; the dispatcher
/// treats `Unknown` as **not eligible** so a freshly-enrolled target
/// doesn't get traffic before its first health check confirms reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Up,
    Degraded,
    Down,
    Unknown,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl HealthStatus {
    /// True when the dispatcher is allowed to route traffic to this
    /// target. Only `Up` qualifies — `Degraded` is treated as `Down`
    /// for dispatching but distinguished in the GUI so operators see
    /// the warning before things actually fail.
    pub fn is_routable(self) -> bool {
        matches!(self, Self::Up)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

/// Cached per-target health record. The pinger writes one of these for
/// every probe round, regardless of whether the verdict changed —
/// downstream consumers want the freshness timestamp even when the
/// status is stable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RustionTargetHealth {
    pub status: HealthStatus,
    /// Last probe that returned 2xx, regardless of current status.
    /// `None` means "never seen healthy in this process lifetime".
    pub last_ok_at: Option<DateTime<Utc>>,
    /// Most recent probe error, populated when `status != Up`.
    #[serde(default)]
    pub last_error: String,
    /// Rolling p50 of the last 16 successful probes, in milliseconds.
    #[serde(default)]
    pub latency_ms_p50: u32,
    /// Consecutive failed probes. Resets to 0 on first success.
    /// Three-strikes flips status to `Down`; one success flips back
    /// to `Up`. `Degraded` covers the transient one-or-two-failures
    /// window so operators see the wobble.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Last reported Rustion version string (`rustion 0.4.2`).
    #[serde(default)]
    pub version: String,
    /// Last reported active session count.
    #[serde(default)]
    pub active_sessions: u64,
    /// Wallclock the health record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input payload for an upsert, as accepted by the HTTP / CLI surfaces.
/// The id is allocated by the registry on create; subsequent updates
/// address by id and may rotate any of the mutable fields.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RustionTargetInput {
    pub name: String,
    pub endpoint: String,
    pub public_key: HybridPubKey,
    /// Base64-encoded ML-KEM-768 public key.
    #[serde(default)]
    pub kem_public_key: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub default_recording_dir: String,
}
