//! Audit logging subsystem — Phase 1.
//!
//! Records every authenticated request and response through one or
//! more audit devices, with tamper-evident hash chaining across
//! entries. Devices register via the [`AuditDevice`] trait; the
//! [`AuditBroker`] fans out each entry to every enabled device.
//!
//! See `features/audit-logging.md` for the full design. Phase 1
//! implements: entry + HMAC redaction, hash chain, append-only file
//! device, broker fan-out, sys/audit enable/disable/list APIs,
//! fail-closed policy (if any device fails, the request is rejected).
//!
//! Deferred to later phases:
//!   - syslog, socket, HTTP webhook devices
//!   - per-mount HMAC level overrides (uses global hmac_accessor on
//!     the file device for now)
//!   - external chain-head witness for stronger tamper guarantees

pub mod broker;
pub mod entry;
pub mod file_device;
pub mod hash_chain;

#[cfg(test)]
mod tests;

pub use broker::{AuditBroker, AuditDeviceConfig};
pub use entry::{AuditAuth, AuditEntry, AuditRequest, AuditResponse};
pub use file_device::FileAuditDevice;

use std::sync::Arc;

use crate::errors::RvError;

/// One pluggable audit sink. Implementations serialize entries to
/// their own destination (file, syslog, HTTP) and signal success or
/// failure per entry. Broker treats a per-device failure as a hard
/// stop so unaudited operations cannot slip through.
#[maybe_async::maybe_async]
pub trait AuditDevice: Send + Sync {
    /// Identifier for the device type, e.g. `"file"`.
    fn device_type(&self) -> &str;

    /// Durably write a single audit entry. `entry` is already
    /// hash-chained + redacted by the broker. Must not return `Ok`
    /// until the entry is persisted far enough that a crash would
    /// not lose it (file device flushes after every write).
    async fn log_entry(&self, entry: &AuditEntry) -> Result<(), RvError>;

    /// Flush any device-level buffering. Called by the broker on
    /// operator-driven `flush` commands and during shutdown.
    async fn flush(&self) -> Result<(), RvError>;

    /// Reload device-internal resources (e.g., reopen file handles
    /// after logrotate).
    async fn reload(&self) -> Result<(), RvError>;
}

/// Opaque handle to a registered device. Just the broker-assigned
/// mount path keyed alongside the device instance; operators
/// address devices through this path at the HTTP layer.
pub struct DeviceEntry {
    pub path: String,
    pub device_type: String,
    pub description: String,
    pub device: Arc<dyn AuditDevice>,
}
