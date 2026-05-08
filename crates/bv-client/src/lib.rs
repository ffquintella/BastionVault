//! `bv-client` — client crate for BastionVault.
//!
//! Defines the [`Backend`] trait the GUI uses to dispatch logical
//! requests, plus a [`RemoteBackend`] implementation that talks to a
//! BastionVault server over HTTP. Has zero dependencies on the
//! `bastion_vault` server crate, so consumers (in particular the
//! Tauri host) can compile against this without pulling in storage,
//! crypto, PKI, or any other server-side machinery.
//!
//! The complementary `EmbeddedBackend` (which wraps an in-process
//! `bastion_vault::core::Core`) lives in the GUI itself behind a
//! Cargo feature gate, so the two implementations stay isolated.

pub mod backend;
pub mod error;
pub mod remote;
pub mod tls;
pub mod types;

pub use backend::Backend;
pub use error::ClientError;
pub use remote::RemoteBackend;
pub use tls::TLSConfigBuilder;
pub use types::{JsonResponse, Operation};
