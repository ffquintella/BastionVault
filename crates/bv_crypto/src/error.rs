use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid symmetric key length")]
    InvalidKeyLength,
    #[error("invalid nonce length")]
    InvalidNonceLength,
    #[error("invalid KEM seed length")]
    InvalidSeedLength,
    #[error("invalid KEM public key")]
    InvalidPublicKey,
    #[error("invalid KEM secret key")]
    InvalidSecretKey,
    #[error("invalid KEM ciphertext")]
    InvalidKemCiphertext,
    #[error("invalid envelope version")]
    InvalidEnvelopeVersion,
    #[error("unsupported envelope algorithm")]
    UnsupportedAlgorithm,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}
