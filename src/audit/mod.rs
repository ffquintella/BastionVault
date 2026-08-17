//! Audit logging — see the [`bv_audit`] crate for the entry format, the hash
//! chain, the file device and the broker. Everything there is re-exported
//! here, so `bastion_vault::audit::*` paths are unchanged.
//!
//! Two pieces stay in the root crate because they are not audit:
//!
//! * [`sys_emit`] — emitting an entry for a sys-level operation outside the
//!   `Core::handle_request` pipeline. It resolves the caller's token through
//!   the kernel's `TokenService` and fetches the broker off `VaultCtx`, which
//!   makes it kernel glue. Keeping it above `bv-audit` is what breaks the
//!   dependency loop: `VaultCtx::audit_broker` returns an `AuditBroker`, so if
//!   the audit crate also named `VaultCtx` neither could be extracted.
//! * the end-to-end tests, which stand up a whole vault through
//!   `crate::test_utils`.
//!
//! See roadmaps/workspace-decomposition.md § Phase 1.

pub use bv_audit::{
    broker, entry, file_device, hash_chain, AuditAuth, AuditBroker, AuditDevice,
    AuditDeviceConfig, AuditEntry, AuditRequest, AuditResponse, DeviceEntry, FileAuditDevice,
};

pub mod sys_emit;

pub use sys_emit::{emit_sys_audit, emit_sys_audit_with_response, outcome_for};

#[cfg(test)]
mod tests;
