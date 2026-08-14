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
