//! The vault kernel: `Core`, the mount table, the module registry, the seal
//! path and the server configuration model.
//!
//! # Where it sits
//!
//! Tier 2 of the workspace decomposition — the crate the target graph has
//! predicted since the beginning and that no numbered phase ever created.
//! Phase 3 extracted the engines above it, Phase 4 extracted the assembly
//! layer above *those*, and this is what was left in the middle.
//!
//! It sits **below** the kernel tier (`bv-kernel`: auth, identity, policy,
//! namespace, resource groups, system), which is the direction that makes the
//! split work. `Core` does not name a module; modules name `Core`. Everything
//! `Core::handle_request` and `Core::post_unseal` used to call by path — the
//! namespace request pipeline, the token-binding check, the two quota gates,
//! the denial-audit sink, the two boot migrations, the root-token mint and the
//! auth-handler push — now goes through a contract in
//! [`bv_kernel_api::pipeline`] or [`bv_kernel_api::auth`], published by
//! whichever module provides it. See
//! roadmaps/workspace-decomposition.md § Phase 4.5.
//!
//! # What is deliberately not here
//!
//! - **`dos` and `metrics`.** Both were pure re-export shims over
//!   `bv-kernel-api` and `bv-metrics`; this crate names those directly rather
//!   than through a facade that sits above it.
//! - **`audit::sys_emit`.** Kernel glue for the HTTP surface, and its only
//!   callers are the plugin runtime, the scheduled-export runner and
//!   `bv-server` — all above. The audit *types* come from `bv-audit`.
//! - **`Core`'s own tests.** They stand up a whole vault through the assembly
//!   layer's `test_utils`, and one reaches `modules::auth::AuthModule` — the
//!   tier above. They live in `bastion_vault::core_tests`, the fourth instance
//!   of a pattern this decomposition keeps hitting.

// The substrate, under the names this code has always spelled them. Private:
// none of it leaks into the public API, and every one of these resolves the
// `crate::<name>::` paths the moved files still use. Same alias preamble the
// Phase 3 engine crates carry.
use bv_audit as audit;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_logical::handler;
use bv_shamir as shamir;
use bv_storage as storage;
use bv_storage::cache;
use bv_utils as utils;

// `dos` was a re-export shim in the root crate; the guard, its config and its
// store are all `bv-kernel-api`'s, and naming them through a module that sits
// above this crate would have been a cycle.
use bv_kernel_api::dos;
// `router` and `stats` moved into `bv-kernel-api` in Phase 3 (`VaultCtx`
// returns both), and the root crate re-exported them. Aliased here under the
// same names so the moved files' `crate::router::Router` paths resolve.
use bv_kernel_api::router;
use bv_kernel_api::stats;

// The `#[macro_export]`ed constructors live at `bv-errors`' crate root; the
// call sites here reach them as `crate::bv_error_*`.
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

pub mod config;
pub mod core;
pub mod hsm;
mod kernel_impl;
pub mod logging;
pub mod module_manager;
pub mod mount;
pub mod seal;
pub mod server_info;
