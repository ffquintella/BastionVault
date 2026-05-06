//! Signature verification for WebAuthn assertions.
//!
//! Per spec, the authenticator signs the concatenation
//! `authenticatorData ‖ SHA-256(clientDataJSON)`. ES256 signatures are
//! ASN.1-DER encoded over (r, s); Ed25519 signatures are raw 64-byte
//! `r ‖ s`. The two crates below give us those formats directly.

use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256};

use super::cose::PublicKey;
use super::errors::RpError;

pub fn verify_assertion(
    key: &PublicKey,
    auth_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<(), RpError> {
    let mut hasher = Sha256::new();
    hasher.update(client_data_json);
    let client_data_hash = hasher.finalize();

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(&client_data_hash);

    match key {
        PublicKey::Es256 { verifying_key } => {
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| RpError::BadSignature)?;
            verifying_key
                .verify(&signed, &sig)
                .map_err(|_| RpError::BadSignature)
        }
        PublicKey::Ed25519 { verifying_key } => {
            let bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| RpError::BadSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(&bytes);
            ed25519_dalek::Verifier::verify(verifying_key, &signed, &sig)
                .map_err(|_| RpError::BadSignature)
        }
    }
}
