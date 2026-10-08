//! Detached hybrid signature (`bvrg::sign_detached_hybrid` /
//! `bvrg::verify_detached_hybrid`) round-trip and tamper-rejection tests.
//!
//! The detached form is what Rustion's signed `GET /v1/health` probe
//! carries in `X-Rustion-Sig`, and the same framing the BVRG-v1
//! envelope's `sig` field uses:
//!
//! ```text
//! ed_len:u16 (=64) || ed25519_sig (64) || ml_len:u16 (=3309) || mldsa65_sig (3309)
//! ```
//!
//! Covered here: exact length and prefixes, round trip, a flipped bit in
//! the message / either half / either length prefix, the classical-only
//! downgrade, the wrong key, and that the message is signed as given
//! (no pre-hash).

use bv_crypto::bvrg::{sign_detached_hybrid, verify_detached_hybrid, HYBRID_SIG_LEN};
use bv_crypto::{BvrgError, BvrgMasterSigningKey};
use sha2::{Digest, Sha256};

const MESSAGE: &[u8] = b"0123456789abcdefbastion-vault";

/// Predicate over the error a tampered signature must produce.
type ExpectedError = fn(&BvrgError) -> bool;

#[test]
fn blob_has_the_wire_length_and_prefixes() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();

    assert_eq!(HYBRID_SIG_LEN, 3377);
    assert_eq!(sig.len(), HYBRID_SIG_LEN);
    assert_eq!(&sig[0..2], &[0x00, 0x40], "ed_len must be 64, big-endian");
    assert_eq!(&sig[66..68], &[0x0C, 0xED], "ml_len must be 3309, big-endian");
}

#[test]
fn round_trip_verifies() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();
    verify_detached_hybrid(MESSAGE, &sig, &master.public_key()).expect("round trip");
}

#[test]
fn a_flipped_message_bit_is_refused() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();
    for i in 0..MESSAGE.len() {
        let mut msg = MESSAGE.to_vec();
        msg[i] ^= 0x01;
        assert!(
            verify_detached_hybrid(&msg, &sig, &master.public_key()).is_err(),
            "flipped message byte {i} still verified"
        );
    }
}

#[test]
fn a_flipped_signature_bit_is_refused_in_each_region() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let pubkey = master.public_key();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();

    // (offset, expected error) — one byte in each of the four regions.
    let cases: &[(usize, ExpectedError)] = &[
        (1, |e| matches!(e, BvrgError::HybridSignatureMalformed)), // ed_len
        (2 + 10, |e| matches!(e, BvrgError::Ed25519SignatureInvalid)), // ed25519 sig
        (67, |e| matches!(e, BvrgError::HybridSignatureMalformed)), // ml_len
        (68 + 1000, |e| matches!(e, BvrgError::MlDsa65SignatureInvalid)), // ml-dsa-65 sig
    ];
    for (offset, expected) in cases {
        let mut forged = sig.clone();
        forged[*offset] ^= 0x01;
        let err = verify_detached_hybrid(MESSAGE, &forged, &pubkey).expect_err("tampered signature verified");
        assert!(expected(&err), "offset {offset}: unexpected error {err:?}");
    }
}

#[test]
fn an_ed25519_only_signature_is_refused() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();

    // Keep a valid Ed25519 half, drop the ML-DSA-65 half.
    let mut forged = sig[..2 + 64].to_vec();
    forged.extend_from_slice(&0u16.to_be_bytes());
    let err =
        verify_detached_hybrid(MESSAGE, &forged, &master.public_key()).expect_err("classical-only signature verified");
    assert!(matches!(err, BvrgError::HybridSignatureMalformed), "got {err:?}");

    // And with no ML-DSA-65 length prefix at all.
    let err = verify_detached_hybrid(MESSAGE, &sig[..2 + 64], &master.public_key())
        .expect_err("truncated signature verified");
    assert!(matches!(err, BvrgError::HybridSignatureMalformed), "got {err:?}");
}

#[test]
fn a_different_key_is_refused() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let other = BvrgMasterSigningKey::generate().unwrap();
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();
    assert!(verify_detached_hybrid(MESSAGE, &sig, &other.public_key()).is_err());
}

#[test]
fn the_message_is_signed_without_a_pre_hash() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let pubkey = master.public_key();

    // A signature over the raw message must not verify over its hash...
    let sig = sign_detached_hybrid(&master, MESSAGE).unwrap();
    let digest: [u8; 32] = Sha256::digest(MESSAGE).into();
    assert!(verify_detached_hybrid(&digest, &sig, &pubkey).is_err());

    // ...and a signature over the hash must not verify over the message.
    let sig_over_digest = sign_detached_hybrid(&master, &digest).unwrap();
    assert!(verify_detached_hybrid(MESSAGE, &sig_over_digest, &pubkey).is_err());
}
