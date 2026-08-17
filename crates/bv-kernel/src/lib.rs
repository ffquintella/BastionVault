//! The kernel tier: token and lease management, identity, policy evaluation,
//! namespaces, resource groups and the `sys/` backend.
//!
//! # Where it sits
//!
//! Tier 2b of the workspace decomposition, **above** [`bv_core`]. That
//! direction is the whole trick. Phase 2 measured this boundary and left it
//! alone, calling the remaining `core.rs` ↔ `modules` edges "the `bv-core` ↔
//! `bv-kernel` entanglement the target graph already predicts" — but it is
//! only a cycle if you insist `Core` sits above the modules. It does not.
//! `Core` is the substrate these six modules are built on, so they name it
//! freely (93 `get_module` sites and 38 distinct `core.<member>` accessors,
//! none of which had to change), and the eight places `Core` named *them* went
//! through contracts in [`bv_kernel_api::pipeline`] and
//! [`bv_kernel_api::auth`] first.
//!
//! # Why one crate and not six
//!
//! Because they are mutually entangled and the roadmap said so from the
//! start: 93 `get_module::<T>()` lookups run between them — a login resolves
//! an entity, which expands group policies, which are scoped by namespace,
//! which enforces a quota, which the system backend reports. Splitting that
//! into six crates would mean six more trait boundaries across a graph with no
//! natural cut, for no compile-time win: they change together.
//!
//! # Tests
//!
//! Roughly 5,000 lines of `#[cfg(test)]` here drive
//! `test_utils::new_unseal_test_bastion_vault`, which stands up a whole vault
//! from the assembly layer. Rather than relocate them, this crate keeps a
//! **dev-dependency** on `bastion_vault` — a dependency cycle, which cargo
//! permits for dev-dependencies — and re-exports its fixtures below under the
//! name they already use. Not one of those test blocks changed. Same
//! arrangement `bastion_vault` itself uses to reach `bv-server`'s HTTP
//! harness, established in Phase 4.

// The substrate and the kernel, under the names this code has always spelled
// them. Private: none of it leaks into the public API.
use bv_audit as audit;
use bv_context as context;
use bv_core::core;
use bv_core::mount;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_kernel_api::dos;
use bv_kernel_api::router;
// The policy store records its cache hit/miss counters; the families are Tier
// 0, and the actix middleware that scrapes them is in `bv-server`.
use bv_metrics as metrics;
use bv_logical as logical;
use bv_logical::handler;
use bv_storage as storage;
use bv_storage::cache;
use bv_utils as utils;

// The `#[macro_export]`ed constructors sit at their defining crate's root; the
// call sites here reach them as `crate::<name>`.
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};

pub mod modules;

/// The assembly layer's fixtures, under the name the test blocks already use.
///
/// Reached through a dev-dependency cycle back onto `bastion_vault`; see the
/// crate docs. `cfg(test)` only — nothing here is part of the shipped crate.
#[cfg(test)]
mod test_utils {
    pub use bastion_vault::test_utils::*;

    /// The in-process HTTP harness, which lives in `bv-server` — two policy
    /// and system tests drive the vault over the wire rather than through
    /// `Core`. `bastion_vault::test_utils` re-exports it only under its own
    /// `cfg(test)`, which does not reach here, so it is named at its source.
    pub use bv_server::test_support::TestHttpServer;
}
