//! The kernel contract: what a module is allowed to know about the vault.
//!
//! Phases 2 and 3 of [the decomposition](../roadmaps/workspace-decomposition.md).
//! Phase 2 defined the traits inside the monolith and moved every engine onto
//! them; Phase 3 is this crate, which is what lets an engine become a crate of
//! its own — a Tier 3 engine depends on `bv-kernel-api` and the Tier 0
//! substrate, and on nothing else.
//!
//! The contract has two halves, landed in that order:
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
//! | [`module`] | [`Module`] — the lifecycle hooks every engine implements |
//! | [`identity`] | entities, group policy expansion, ownership, user audit |
//! | [`auth`] | token lookup/revocation, auth-mount registration |
//! | [`policy`] | the three authorization questions an engine may ask |
//! | [`namespace`] | namespace resolution, login binding, per-namespace routers |
//! | [`resource_group`] | the asset-group reverse index |
//! | [`engines`] | Tier 3 ↔ Tier 3 contracts (**not** kernel contracts — see the file) |
//!
//! ## Why the routing and mount tables are in here
//!
//! [`router`], [`mount`], [`stats`] and [`dos`] are Tier 2 in the roadmap's
//! target graph, sitting in `bv-core`. They are here instead because
//! [`VaultCtx`] *names* them — `router()`, `mounts_router()`,
//! `mounts_monitor()`, `stats()`, `dos_guard()` and
//! `mount_entry_hmac_level()` are all real methods with real engine callers
//! (`pki`, `ldap`, `files` and `cert_lifecycle` schedulers resolve their own
//! mount through `mounts_router()`; `totp`, `resource`, `rustion` and
//! `credential` dispatch sub-requests through `router()`).
//!
//! A crate holding only the traits would therefore need all four as
//! dependencies anyway. The alternative — a further trait layer between the
//! kernel contract and the mount table — buys nothing: the mount table is
//! already the narrow, engine-facing view of the routing tier, and `Core`'s
//! own mount management (`mount`, `unmount`, `remount`) stayed behind in the
//! root crate precisely because it is *not* part of that view.

pub mod auth;
pub mod ctx;
pub mod dos;
pub mod engines;
pub mod identity;
pub mod module;
pub mod mount;
pub mod namespace;
pub mod policy;
pub mod resource_group;
pub mod router;
pub mod services;
pub mod stats;

pub use ctx::{LogicalBackendNewFunc, MountEntryHMACLevel, VaultCtx};
pub use module::Module;
pub use services::KernelServices;
