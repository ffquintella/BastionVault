pub mod aead;
pub mod envelope;
pub mod error;
pub mod kem;
pub mod signature;

pub use aead::{AeadCipher, Chacha20Poly1305Cipher, Nonce, SymmetricKey};
pub use envelope::{AeadAlgorithm, KemDemEnvelopeV1};
pub use error::CryptoError;
pub use kem::{
    KemAlgorithm, KemCiphertext, KemKeypair, KemProvider, MlKem768Provider, SharedSecret, ML_KEM_768_SEED_LEN,
};
#[cfg(feature = "ml-dsa-44")]
pub use signature::{
    MlDsa44Keypair, MlDsa44Provider, ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SEED_LEN, ML_DSA_44_SIGNATURE_LEN,
};
#[cfg(feature = "ml-dsa-65")]
pub use signature::{
    MlDsa65Keypair, MlDsa65Provider, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SEED_LEN, ML_DSA_65_SIGNATURE_LEN,
};
#[cfg(feature = "ml-dsa-87")]
pub use signature::{
    MlDsa87Keypair, MlDsa87Provider, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SEED_LEN, ML_DSA_87_SIGNATURE_LEN,
};
