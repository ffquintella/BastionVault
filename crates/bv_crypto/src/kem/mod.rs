#[cfg(feature = "ml-kem-768")]
mod ml_kem_768;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

pub const ML_KEM_768_SEED_LEN: usize = 64;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KemAlgorithm {
    MlKem768,
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

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

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct KemKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
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
