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
/// Phase 9.1 — fired by `rustion_enrol_submit` when the operator
/// submits a fresh enrolment request to a bastion.
pub const TARGET_ENROL_SUBMITTED: &str = "rustion.target.enrol.submitted";
/// Phase 9.1 — fired when an operator's enrolment-status check
/// shows the bastion has approved a pending submission.
pub const TARGET_ENROL_APPROVED: &str = "rustion.target.enrol.approved";
/// Phase 9.2 — fires on `rustion_target_deenrol` before the local
/// registry delete.
pub const TARGET_DEENROLLED: &str = "rustion.target.deenrolled";
/// Phase 9.2 — weekly re-attestation timer + on-demand
/// `rustion_authority_attest` Tauri command.
pub const MASTER_ATTEST: &str = "rustion.master.attest";

// ─── Phase 8.6 — keystroke transcripts ──────────────────────────────
//
// A `.rdp-rec` version-4 transcript is the highest-value artifact in a
// recording, so reading one is auditable **separately** from viewing
// the recording it came from: `recording.replayed` says an operator
// watched the screen, and these say an operator read what was typed.
// Every payload is counts and verdicts only — never a character of
// typed text, and never a search query.

/// A transcript was read out of a `.rdp-rec` and stored in the
/// keystroke index. Carries run/character counts, `text_decoding` and
/// the `rebuilt` flag.
pub const RECORDING_TRANSCRIPT_INDEXED: &str = "recording.transcript.indexed";

/// An operator read one recording's keystroke transcript. Distinct
/// from `recording.replayed` on purpose.
pub const RECORDING_TRANSCRIPT_ACCESSED: &str = "recording.transcript.accessed";

/// An operator ran a keystroke search. Records that a search happened
/// and how many recordings and hits it touched — **never the query**,
/// which is user-supplied text about a secret-bearing corpus and is
/// treated with the same care as the transcript itself.
pub const RECORDING_TRANSCRIPT_SEARCHED: &str = "recording.transcript.searched";
