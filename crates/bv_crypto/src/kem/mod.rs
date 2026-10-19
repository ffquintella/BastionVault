#[cfg(feature = "ml-kem-768")]
mod ml_kem_768;

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

pub const ML_KEM_768_SEED_LEN: usize = 64;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KemAlgorithm {
    MlKem768,
}

/// A KEM shared secret. Wiped on drop and left out of `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").field(&"<redacted>").finish()
    }
}

impl SharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KemCiphertext(Vec<u8>);

impl KemCiphertext {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A KEM public key and its secret key. The secret key is wiped on drop
/// and left out of `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct KemKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl fmt::Debug for KemKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemKeypair").field("public_key", &self.public_key).field("secret_key", &"<redacted>").finish()
    }
}

impl KemKeypair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self { public_key, secret_key }
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    pub fn secret_key(&self) -> &[u8] {
        self.secret_key.as_slice()
    }
}

pub trait KemProvider {
    fn algorithm(&self) -> KemAlgorithm;
    fn generate_keypair(&self) -> Result<KemKeypair, CryptoError>;
    fn encapsulate(&self, public_key: &[u8]) -> Result<(KemCiphertext, SharedSecret), CryptoError>;
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, CryptoError>;
}

#[cfg(feature = "ml-kem-768")]
pub use ml_kem_768::MlKem768Provider;

#[cfg(not(feature = "ml-kem-768"))]
#[derive(Default)]
pub struct MlKem768Provider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_keypair_debug_redacts_secret_key() {
        let keypair = KemKeypair::new(vec![0x11; 4], vec![0xa5; 8]);
        let rendered = format!("{keypair:?}");
        assert!(rendered.contains("public_key: [17, 17, 17, 17]"), "{rendered}");
        assert!(rendered.contains("secret_key: \"<redacted>\""), "{rendered}");
        assert!(!rendered.contains("165"), "secret key bytes leaked into Debug: {rendered}");
    }

    #[test]
    fn test_shared_secret_debug_redacts_bytes() {
        let secret = SharedSecret::new(vec![0xa5; 32]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SharedSecret(\"<redacted>\")");
        assert!(!format!("{secret:#?}").contains("165"), "shared secret bytes leaked into Debug");
    }
}
