//! This module provides several authentication methods, such as username/password, certificate
//! , etc.
//!

pub mod approle;
pub mod cert;
pub mod ferrogate;
pub mod fido2;
pub mod login_audit_store;
pub mod oidc;
pub mod saml;
pub mod token;
pub mod userpass;
