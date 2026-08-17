//! Tests for engines that now live in their own crates.
//!
//! Each of these was a `#[cfg(test)] mod` inside its engine, and each stands
//! up a whole vault through [`crate::test_utils`] — so it could not travel
//! into the engine crate, which sits below the root in the dependency graph.
//! They are here rather than in `tests/` because `test_utils` is a
//! `#[cfg(test)]` module of this crate, not part of its public API.
//!
//! Same pattern as `src/storage_backend_tests.rs` and
//! `src/dos/store_tests.rs`. See roadmaps/workspace-decomposition.md § Phase 3.

mod approle;
mod ferrogate;
mod files;
mod notifications;
mod resource;
mod oidc;
mod rustion;
mod saml;
mod userpass;

// ── Kernel-tier tests lifted in Phase 4.5 ────────────────────────────
//
// These construct a vault and then look modules and stores back up by type.
// `bv-kernel`'s own test binary is a separate compilation of that crate from
// the rlib `bastion_vault` links, so the two disagree on `TypeId` and every
// `get_module::<T>()` returns `None`. They have to live where the vault is
// built. See roadmaps/workspace-decomposition.md § Phase 4.5.
mod kernel_identity;
mod kernel_identity_link;
mod kernel_migrate;
mod kernel_namespace;
mod kernel_ns_assignment;
mod kernel_resource_group;
mod kernel_token_binding;
