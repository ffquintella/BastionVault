//! Audit-event taxonomy for the Rustion-integration module.
//!
//! Phase 1 ships the registry / health / master-cert events. Session
//! events (`session.open`, `session.renew`, `session.terminate`) and
//! policy events arrive in later phases — listed here for forward
//! compatibility so downstream consumers (log shippers, SIEM rules)
//! can match on the full set without future-proofing strings.
//!
//! Event payloads are produced by the handler that performs the
//! action; this file fixes the **names** so the spelling stays
//! consistent across the codebase.

/// A new Rustion target was registered.
pub const TARGET_ENROL: &str = "rustion.target.enrol";

/// An existing target's mutable fields were updated.
pub const TARGET_UPDATE: &str = "rustion.target.update";

/// Target pubkey rotated (separate from a generic update so
/// downstream filters can alert on key rotation specifically).
pub const TARGET_ROTATE: &str = "rustion.target.rotate";

/// Target deleted from the registry.
pub const TARGET_DELETE: &str = "rustion.target.delete";

/// Health verdict changed (`up` → `down` etc.). Emitted only on
/// transitions, not on every probe.
pub const TARGET_HEALTH_CHANGED: &str = "rustion.target.health.changed";

/// Master signing certificate freshly issued (first enrolment, or a
/// rotation). The `not_after` of the new cert is the deadline by
/// which every enrolled Rustion must accept the new pubkey.
pub const MASTER_ISSUE: &str = "rustion.master.issue";

/// Master cert rotated; the co-signed envelope payload was prepared
/// for delivery to every enrolled bastion.
pub const MASTER_ROTATE: &str = "rustion.master.rotate";

// ─── Phase 2+ (reserved here so the strings are stable) ─────────────

pub const BASTION_GROUP_UPDATE: &str = "rustion.bastion_group.update";
pub const POLICY_GLOBAL_UPDATE: &str = "rustion.policy.global.update";
pub const POLICY_TYPE_UPDATE: &str = "rustion.policy.type.update";
pub const POLICY_ASSET_GROUP_UPDATE: &str = "rustion.policy.asset_group.update";
pub const POLICY_RESOURCE_UPDATE: &str = "rustion.policy.resource.update";
pub const SESSION_OPEN: &str = "session.open";
pub const SESSION_RENEW: &str = "session.renew";
pub const SESSION_TERMINATE: &str = "session.terminate";
pub const RECORDING_LINKED: &str = "recording.linked";
pub const RECORDING_REPLAYED: &str = "recording.replayed";
pub const RUSTION_AUDIT_WITNESS: &str = "rustion.audit.witness";
