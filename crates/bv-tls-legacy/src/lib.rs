//! An opt-in, client-only TLS 1.2 stack for servers that offer nothing but
//! ECDHE-RSA AES-CBC suites, and a minimal HTTP/1.1 client over it.
//!
//! It exists for one OIDC provider that cannot be upgraded (T551); it is
//! never a fallback for rustls. Spec, scope and threat model:
//! `features/legacy-tls-cbc.md`. Nothing here logs.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod handshake;
pub mod http;
mod prf;
mod record;
mod stream;
mod suite;
mod verify;

#[cfg(test)]
mod test_server;
#[cfg(test)]
mod tests;

pub use error::TlsError;
pub use handshake::{ClientConfig, ConnectionInfo};
pub use rustls_pki_types::ServerName;
pub use stream::{connect, LegacyTlsStream};
pub use suite::CipherSuite;
pub use verify::TrustAnchors;
