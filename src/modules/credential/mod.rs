//! This module provides several authentication methods, such as
//! username/password, certificate, etc.
//!
//! Every backend is its own Tier 3 crate and this file is the list of
//! re-exports that keeps `bastion_vault::modules::credential::*` resolving.
//! See roadmaps/workspace-decomposition.md § Phase 3.
//!
//! `token` is absent because it no longer exists: the module was one line,
//! `pub mod cli;`, and that CLI login handler moved to `bvault-cli` with the
//! other two. Token auth itself is the kernel's `auth` module, not a
//! credential backend.
//!
//! `bv_kernel::modules::credential` carries a two-entry subset of this list —
//! the login-audit store and userpass — because those are what the kernel tier
//! itself reads. This is the full list, and it is the one a mount table is
//! written against.

/// The shared login-audit store, the Tier 3 `bv-auth-audit` crate. Five
/// backends write to it and the kernel tier reads it, so it belongs to none of
/// them.
pub use bv_auth_audit as login_audit_store;

/// The AppRole auth backend, the Tier 3 `bv-auth-approle` crate.
pub use bv_auth_approle as approle;

/// The username/password auth backend, the Tier 3 `bv-auth-userpass` crate.
pub use bv_auth_userpass as userpass;

/// The FerroGate machine-identity auth backend, the Tier 3
/// `bv-auth-ferrogate` crate.
pub use bv_auth_ferrogate as ferrogate;

/// The SAML auth backend, the Tier 3 `bv-auth-saml` crate.
pub use bv_auth_saml as saml;

/// The OIDC auth backend, the Tier 3 `bv-auth-oidc` crate.
pub use bv_auth_oidc as oidc;

/// The FIDO2 / WebAuthn auth backend, the Tier 3 `bv-auth-fido2` crate.
pub use bv_auth_fido2 as fido2;

/// The (retired) certificate auth backend, the Tier 3 `bv-auth-cert` crate.
pub use bv_auth_cert as cert;
