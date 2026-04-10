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
    #[error("invalid signature seed length")]
    InvalidSignatureSeedLength,
    #[error("invalid signature public key")]
    InvalidSignaturePublicKey,
    #[error("invalid signature secret key")]
    InvalidSignatureSecretKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("invalid envelope version")]
    InvalidEnvelopeVersion,
    #[error("unsupported envelope algorithm")]
    UnsupportedAlgorithm,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("signing failed")]
    SignFailed,
    #[error("verification failed")]
    VerifyFailed,
}
