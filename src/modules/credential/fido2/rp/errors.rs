//! Errors raised by the WebAuthn RP layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpError {
    #[error("invalid RP configuration: {0}")]
    InvalidConfig(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("CBOR parse error: {0}")]
    Cbor(String),
    #[error("malformed authenticatorData: {0}")]
    BadAuthData(String),
    #[error("malformed clientDataJSON: {0}")]
    BadClientData(String),
    #[error("clientData type mismatch: expected `{expected}`, got `{actual}`")]
    ClientDataType { expected: String, actual: String },
    #[error("clientData origin mismatch: expected `{expected}`, got `{actual}`")]
    OriginMismatch { expected: String, actual: String },
    #[error("clientData challenge mismatch")]
    ChallengeMismatch,
    #[error("rpIdHash mismatch")]
    RpIdMismatch,
    #[error("user-presence flag (UP) was not set")]
    UserPresenceMissing,
    #[error("attestation contains no attested credential data")]
    MissingAttestedCredentialData,
    #[error("unsupported attestation format `{0}` (only `none` is accepted)")]
    UnsupportedAttestation(String),
    #[error("unsupported COSE algorithm: alg={0}")]
    UnsupportedAlg(i64),
    #[error("malformed COSE_Key: {0}")]
    BadCoseKey(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("no credentials registered")]
    NoCredentials,
    #[error("unknown credential")]
    UnknownCredential,
    #[error("sign-count regression (stored={stored}, presented={presented}) — possible cloned authenticator")]
    CounterRegression { stored: u32, presented: u32 },
}
