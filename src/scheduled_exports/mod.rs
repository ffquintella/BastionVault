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

pub mod runner;
pub mod schedule;
pub mod store;

pub use runner::start_scheduler;
pub use schedule::{
    DestinationKind, ExportFormat, PasswordRefKind, RunRecord, RunStatus, Schedule, ScheduleInput,
};
pub use store::{ScheduleStore, STORE_PREFIX};
