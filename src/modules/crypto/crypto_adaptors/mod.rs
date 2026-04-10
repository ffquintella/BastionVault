//! This module contains the remaining legacy crypto adaptor implementations.
//! BastionVault is moving toward smaller PQ-first crates for new crypto work, while the legacy
//! OpenSSL adaptor still backs older runtime paths during the migration.

#[macro_use]
pub mod common;
#[cfg(feature = "crypto_adaptor_openssl")]
pub mod openssl_adaptor;
