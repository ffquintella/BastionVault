//! BV-side verifier for the Rustion `X-Rustion-Signature` header —
//! Phase 6.2 of `features/rustion-integration.md`.
//!
//! Mirror of `rustion-control-plane::webhook::WebhookVerifyingKey::verify_header`
//! kept in-tree so the BV main lib doesn't pull `rustion-control-plane`
//! as a dependency. Both implementations sign/verify `sha256(body)`
//! with hybrid Ed25519 + ML-DSA-65; both halves are required (a
//! classical-only signature is rejected as a downgrade).
//!
//! Wire format: `ed25519=<base64> mldsa65=<base64>`.

#![deny(unsafe_code)]

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier as PqcVerifier};
use sha2::{Digest, Sha256};

const MLDSA65_PK_LEN: usize = 1952;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("X-Rustion-Signature malformed — expected `ed25519=… mldsa65=…`")]
    HeaderMalformed,
    #[error("base64 decode failed: {0}")]
    Base64(String),
    #[error("pinned pubkey is not valid base64: {0}")]
    PinnedPubkey(String),
    #[error("Ed25519 signature half failed verification")]
    Ed25519Invalid,
    #[error("ML-DSA-65 signature half failed verification")]
    MlDsa65Invalid,
    #[error("pinned pubkey wrong length")]
    PubkeyLen,
}

/// Verify the signature header against `body` using the pinned
/// hybrid pubkey halves (`ed25519_b64` and `mldsa65_b64` come straight
/// off `RustionTarget.public_key`).
pub fn verify(
    ed25519_b64: &str,
    mldsa65_b64: &str,
    header_value: &str,
    body: &[u8],
) -> Result<(), VerifyError> {
    let (ed_sig_b64, ml_sig_b64) = parse_header(header_value)?;
    let ed_sig_bytes = B64
        .decode(ed_sig_b64.as_bytes())
        .map_err(|e| VerifyError::Base64(format!("ed25519: {e}")))?;
    let ml_sig_bytes = B64
        .decode(ml_sig_b64.as_bytes())
        .map_err(|e| VerifyError::Base64(format!("mldsa65: {e}")))?;

    let ed_pub_bytes = B64
        .decode(ed25519_b64.trim().as_bytes())
        .map_err(|e| VerifyError::PinnedPubkey(format!("ed25519: {e}")))?;
    let ml_pub_bytes = B64
        .decode(mldsa65_b64.trim().as_bytes())
        .map_err(|e| VerifyError::PinnedPubkey(format!("mldsa65: {e}")))?;

    if ml_pub_bytes.len() != MLDSA65_PK_LEN {
        return Err(VerifyError::PubkeyLen);
    }
    let ed_pub_arr: [u8; 32] = ed_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::PubkeyLen)?;
    let ed_pub =
        VerifyingKey::from_bytes(&ed_pub_arr).map_err(|_| VerifyError::Ed25519Invalid)?;

    if ed_sig_bytes.len() != 64 {
        return Err(VerifyError::Ed25519Invalid);
    }
    let ed_sig =
        Ed25519Signature::from_slice(&ed_sig_bytes).map_err(|_| VerifyError::Ed25519Invalid)?;

    let mut h = Sha256::new();
    h.update(body);
    let tbs: [u8; 32] = h.finalize().into();

    use ed25519_dalek::Verifier;
    ed_pub
        .verify(&tbs, &ed_sig)
        .map_err(|_| VerifyError::Ed25519Invalid)?;

    // ML-DSA-65 verify via fips204 — BV already uses fips204 for the
    // outbound BVRG-v1 signing path, so we keep a single PQC crate.
    let pk_arr: [u8; MLDSA65_PK_LEN] = ml_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::PubkeyLen)?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
        .map_err(|_| VerifyError::PubkeyLen)?;
    let ml_sig_arr: [u8; 3309] = ml_sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::MlDsa65Invalid)?;
    pk.verify(&tbs, &ml_sig_arr, &[])
        .then_some(())
        .ok_or(VerifyError::MlDsa65Invalid)
}

fn parse_header(s: &str) -> Result<(String, String), VerifyError> {
    let trimmed = s.trim();
    let mut ed: Option<&str> = None;
    let mut ml: Option<&str> = None;
    for tok in trimmed.split_whitespace() {
        if let Some(v) = tok.strip_prefix("ed25519=") {
            ed = Some(v);
        } else if let Some(v) = tok.strip_prefix("mldsa65=") {
            ml = Some(v);
        }
    }
    match (ed, ml) {
        (Some(e), Some(m)) => Ok((e.to_string(), m.to_string())),
        _ => Err(VerifyError::HeaderMalformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use fips204::traits::{KeyGen, Signer as PqcSigner};

    fn synth() -> (String, String, [u8; 32], fips204::ml_dsa_65::PrivateKey) {
        // Deterministic seed is fine here — these tests round-trip
        // sign/verify and don't care about cryptographic randomness.
        let sk_seed: [u8; 32] = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42,
        ];
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&sk_seed);
        let ed_pk = ed_sk.verifying_key();

        let (ml_pk, ml_sk) = ml_dsa_65::try_keygen().unwrap();
        let ed_pk_b64 = B64.encode(ed_pk.to_bytes());
        let ml_pk_b64 = B64.encode(ml_pk.into_bytes());
        (ed_pk_b64, ml_pk_b64, sk_seed, ml_sk)
    }

    fn sign(
        sk_seed: &[u8; 32],
        ml_sk: &ml_dsa_65::PrivateKey,
        body: &[u8],
    ) -> String {
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(sk_seed);
        let mut h = Sha256::new();
        h.update(body);
        let tbs: [u8; 32] = h.finalize().into();
        let ed_sig = ed_sk.sign(&tbs);
        let ml_sig = ml_sk.try_sign(&tbs, &[]).unwrap();
        format!(
            "ed25519={} mldsa65={}",
            B64.encode(ed_sig.to_bytes()),
            B64.encode(ml_sig.as_slice())
        )
    }

    #[test]
    fn round_trip() {
        let (ed_pk_b64, ml_pk_b64, sk_seed, ml_sk) = synth();
        let body = br#"{"x":1}"#;
        let header = sign(&sk_seed, &ml_sk, body);
        verify(&ed_pk_b64, &ml_pk_b64, &header, body).expect("ok");
    }

    #[test]
    fn tampered_body_rejected() {
        let (ed_pk_b64, ml_pk_b64, sk_seed, ml_sk) = synth();
        let header = sign(&sk_seed, &ml_sk, b"a");
        let err = verify(&ed_pk_b64, &ml_pk_b64, &header, b"b").expect_err("tamper");
        assert!(matches!(err, VerifyError::Ed25519Invalid));
    }

    #[test]
    fn malformed_header_rejected() {
        let (ed_pk_b64, ml_pk_b64, _, _) = synth();
        let err = verify(&ed_pk_b64, &ml_pk_b64, "broken", b"x").expect_err("malformed");
        assert!(matches!(err, VerifyError::HeaderMalformed));
    }

    #[test]
    fn classical_only_rejected() {
        let (ed_pk_b64, ml_pk_b64, sk_seed, ml_sk) = synth();
        let header_full = sign(&sk_seed, &ml_sk, b"x");
        let classical_only = header_full
            .split_whitespace()
            .find(|t| t.starts_with("ed25519="))
            .unwrap()
            .to_string();
        let err = verify(&ed_pk_b64, &ml_pk_b64, &classical_only, b"x")
            .expect_err("downgrade");
        assert!(matches!(err, VerifyError::HeaderMalformed));
    }
}
