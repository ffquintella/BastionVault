//! This module provides several authentication methods, such as username/password, certificate
//! , etc.
//!
//! Every backend is now its own Tier 3 crate and this file is the list of
//! re-exports that keeps `bastion_vault::modules::credential::*` resolving.
//! See roadmaps/workspace-decomposition.md § Phase 3.
//!
//! `token` is absent because it no longer exists: the module was one line,
//! `pub mod cli;`, and that CLI login handler moved to
//! `src/cli/command/login_handlers.rs` with the other two. Token auth itself
//! is the kernel's `auth` module, not a credential backend.

/// The shared login-audit store, now the Tier 3 `bv-auth-audit` crate. Five
/// backends write to it and the kernel tier reads it, so it belongs to none of
/// them. Re-exported here so
/// `bastion_vault::modules::credential::login_audit_store::*` is unchanged.
pub use bv_auth_audit as login_audit_store;

/// The AppRole auth backend, now the Tier 3 `bv-auth-approle` crate.
pub use bv_auth_approle as approle;

/// The username/password auth backend, now the Tier 3 `bv-auth-userpass` crate.
pub use bv_auth_userpass as userpass;

/// The FerroGate machine-identity auth backend, now the Tier 3 `bv-auth-ferrogate` crate.
pub use bv_auth_ferrogate as ferrogate;

/// The SAML auth backend, now the Tier 3 `bv-auth-saml` crate.
pub use bv_auth_saml as saml;

/// The OIDC auth backend, now the Tier 3 `bv-auth-oidc` crate.
pub use bv_auth_oidc as oidc;

/// The FIDO2 / WebAuthn auth backend, now the Tier 3 `bv-auth-fido2` crate.
pub use bv_auth_fido2 as fido2;

/// The (retired) certificate auth backend, now the Tier 3 `bv-auth-cert` crate.
pub use bv_auth_cert as cert;

