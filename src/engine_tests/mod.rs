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
mod approle_reserved_meta;
mod audit_events_window;
mod bulk_info_endpoints;
mod cache_version;
mod ferrogate;
mod files;
mod kv_version_read;
mod mcp_access;
mod mcp_sessions_ssh;
mod mcp_sessions_web;
mod mcp_transcripts;
mod notifications;
mod oidc;
mod pki_certs_info;
mod pki_export;
mod pki_issuer_renew;
mod pki_key_ref_policy;
mod pki_managed_role_key;
mod pki_tidy_key_refs;
mod connect_session_open;
mod rdp_clipboard;
mod resource;
mod resource_connect_web;
mod rustion;
mod saml;
mod self_accounts_connect;
mod self_accounts_host;
mod userpass;

// ── Kernel-tier tests lifted in Phase 4.5 ────────────────────────────
//
// These construct a vault and then look modules and stores back up by type.
// `bv-kernel`'s own test binary is a separate compilation of that crate from
// the rlib `bastion_vault` links, so the two disagree on `TypeId` and every
// `get_module::<T>()` returns `None`. They have to live where the vault is
// built. See roadmaps/workspace-decomposition.md § Phase 4.5.
mod audit_retention;
mod dashboard_stats;
mod kernel_identity;
mod kernel_identity_link;
mod kernel_migrate;
mod kernel_namespace;
mod kernel_ns_assignment;
mod kernel_policy_deny;
mod kernel_policy_segment_glob;
mod kernel_policy_sql;
mod kernel_resource_group;
mod kernel_token_binding;
