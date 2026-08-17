//! The slice of `bastion_vault::modules::credential` the kernel tier reads.
//!
//! The full list of eight backends is the facade's — this is not a narrowing
//! of what a server mounts, it is a narrowing of what the *kernel* has to
//! compile against. Two entries, both for the same reason: `system` builds the
//! Audit page from the login-audit store, and `self_profile` validates an
//! e-mail change against the userpass user record.
//!
//! See roadmaps/workspace-decomposition.md § Phase 4.5.

/// The shared login-audit store, the Tier 3 `bv-auth-audit` crate. Five
/// backends write to it and the kernel tier reads it, so it belongs to none of
/// them.
pub use bv_auth_audit as login_audit_store;

/// The username/password auth backend, the Tier 3 `bv-auth-userpass` crate.
pub use bv_auth_userpass as userpass;
