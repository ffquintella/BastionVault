//! Scheduled exports — cron-driven `.bvx` (or plaintext JSON) backups
//! that drive `crate::exchange` on a recurring cadence.
//!
//! Phase 1 deliverable per `features/scheduled-exports.md`:
//!
//! - Schedule CRUD persisted under the barrier (`core/scheduled_exports/`).
//! - Single-process tokio tick loop spawned at unseal.
//! - Local-path destination only.
//! - `static_secret` password-ref (password lives in a barrier-encrypted KV
//!   path the operator points the schedule at — no plaintext password in
//!   the schedule record itself).
//!
//! Out of scope for Phase 1 (tracked in the spec):
//! - Hiqlite leader gating (single-process is fine for the embedded /
//!   single-instance deployments we ship today).
//! - GFS retention, verification, cloud destinations, BVBK format.
//! - `transit` and `external_kms` password-ref modes.

pub mod catalog;
pub mod runner;
pub mod schedule;
pub mod store;

pub use catalog::{
    list_backups, BackupCatalog, BackupEntry, BackupRecord, NodeRef,
};
pub use runner::start_scheduler;
pub use schedule::{
    DestinationKind, ExportFormat, PasswordRefKind, RunRecord, RunStatus, Schedule, ScheduleInput,
};
pub use store::{ScheduleStore, STORE_PREFIX};

/// Identity of the node this process is: Raft node id (when the storage
/// backend is a Hiqlite cluster), host name, and the advertised API address
/// peers can dial.
///
/// Used to stamp catalog records at write time and to decide, at read time,
/// whether a recorded backup lives on *this* node's filesystem.
pub fn local_node(core: &crate::core::Core) -> NodeRef {
    #[allow(unused_mut)]
    let mut node_id = None;
    #[cfg(feature = "storage_hiqlite")]
    {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite) = backend_any.downcast_ref::<HiqliteBackend>() {
            node_id = Some(hiqlite.node_id());
        }
    }
    #[cfg(not(feature = "storage_hiqlite"))]
    let _ = core;

    NodeRef {
        node_id,
        node_name: hostname(),
        api_addr: crate::server_info::api_addr().map(|s| s.to_string()),
    }
}

/// Best-effort host name, used as the human-readable half of [`NodeRef`].
///
/// `HOSTNAME` covers containers that set it (podman/docker do, from
/// `--hostname` or the container name); `/etc/hostname` covers the rest of
/// Linux; an empty string is an acceptable fallback because node identity
/// falls back to the Raft node id.
fn hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
