//! The kernel tier: the six modules that *are* the vault's tenancy and
//! identity machinery, plus the handful of engine re-exports they read.
//!
//! This file used to be `bastion_vault::modules` and carried the full engine
//! list. The engines it kept are only the four whose audit stores the kernel
//! reads — `system` builds the Audit page out of them, and `token_store`
//! records logins and logouts. Everything else `bastion_vault::modules`
//! offers is re-exported by the facade, which is where the mount list lives.
//!
//! See roadmaps/workspace-decomposition.md § Phase 4.5.

/// The `Module` trait lives in [`bv_kernel_api::module`] — an engine crate
/// cannot implement a trait defined in the crate above it, and every engine
/// implements this one. See Phase 3.
pub use bv_kernel_api::Module;

pub mod auth;
pub mod credential;
pub mod crypto;
pub mod identity;
pub mod namespace;
pub mod policy;
pub mod resource_group;
pub mod system;

/// The encrypted file-resource engine. Read for `FileAuditStore`, which the
/// system backend folds into the Audit page.
pub use bv_engine_files as files;

/// The SSH secret engine. Read for `SshCaAuditStore` and `SshSignAuditStore`,
/// same reason.
pub use bv_engine_ssh as ssh;
