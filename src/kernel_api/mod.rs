//! The kernel contract: what a module is allowed to know about the vault.
//!
//! This is Phase 2 of [the decomposition](../roadmaps/workspace-decomposition.md).
//! It has two halves, and they were landed in that order:
//!
//! 1. **[`VaultCtx`]** ([`ctx`]) cut the `Core` ↔ `modules` cycle. Modules
//!    depend on a trait; `Core` implements it; the concrete kernel type left
//!    every engine's compile unit.
//! 2. **The service registry** ([`services`]) cuts the *sibling* cycle. An
//!    engine no longer names `IdentityModule`, `AuthModule`, `PolicyModule`,
//!    `NamespaceModule` or `ResourceGroupModule` to reach them — it asks
//!    [`VaultCtx`] for the capability. That was 175 `get_module::<T>()` call
//!    sites, and it was the remaining blocker for Phase 3, not `Core`.
//!
//! ## The shape
//!
//! ```text
//!   engine ──asks──▶ VaultCtx ──reads──▶ KernelServices ──holds──▶ dyn IdentityService
//!                                                ▲
//!                            kernel module ──registers itself
//! ```
//!
//! Providers register at module installation; consumers resolve per call. The
//! direction of the dependency edge is what changed: nobody names anybody.
//!
//! ## What lives where
//!
//! | file | contract |
//! |---|---|
//! | [`ctx`] | [`VaultCtx`] — the kernel itself: dispatch, barrier, router, mounts |
//! | [`services`] | [`KernelServices`] — the registry and its slots |
//! | [`identity`] | entities, group policy expansion, ownership, user audit |
//! | [`auth`] | token lookup/revocation, auth-mount registration |
//! | [`policy`] | the three authorization questions an engine may ask |
//! | [`namespace`] | namespace resolution, login binding, per-namespace routers |
//! | [`resource_group`] | the asset-group reverse index |
//! | [`engines`] | Tier 3 ↔ Tier 3 contracts (**not** kernel contracts — see the file) |
//!
//! ## Why this is still in the monolith
//!
//! The roadmap has Phase 2 opening with "define `bv-kernel-api`". It cannot,
//! yet: these signatures name types that have not been extracted —
//! `BarrierView` and `SecurityBarrier` are `src/storage` (Tier 0, not done),
//! `Router` is `src/router` and `MountsRouter` is `src/mount` (both Tier 2).
//! A crate holding these traits would need all of them as dependencies.
//!
//! That is a sequencing problem, not a design problem, because **the crate is
//! not what breaks the cycle — the abstraction is.** The traits start here, the
//! modules move onto them, and the directory becomes `bv-kernel-api` later,
//! once `bv-storage` exists and `router`/`mount` have moved into `bv-core`.

pub mod auth;
pub mod ctx;
pub mod engines;
pub mod identity;
pub mod namespace;
pub mod policy;
pub mod resource_group;
pub mod services;

pub use ctx::VaultCtx;
pub use services::KernelServices;
