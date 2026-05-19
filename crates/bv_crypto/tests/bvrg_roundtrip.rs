//! BVRG-v1 envelope round-trip and tamper-rejection tests.
//!
//! Covers the build → verify symmetry expected by Phase 2 of the
//! Rustion-integration spec, plus the fail-closed behaviour the
//! verify path promises for each tamper class:
//!
//!   - magic prefix mismatch         → MagicMismatch
//!   - truncated frame               → EnvelopeTooShort
//!   - Ed25519 half tampered         → Ed25519SignatureInvalid
//!   - ML-DSA-65 half tampered       → MlDsa65SignatureInvalid
//!   - hybrid half dropped (downgrade) → HybridSignatureMalformed
//!   - ciphertext byte flipped       → CiphertextInvalid
//!   - wrong recipient KEM key       → CiphertextInvalid
//!
//! Synthetic-only — no network, no live Rustion. The Rustion-side
//! verify path (in `crates/rustion-control-plane`) will be tested
//! independently with the same fixtures once that crate is in tree.

use bv_crypto::{
    bvrg_build, bvrg_fresh_nonce, bvrg_unix_now, bvrg_verify, BvrgCredential, BvrgError,
    BvrgMasterPublicKey, BvrgMasterSigningKey, BvrgOperator, BvrgPayload, BvrgSession, BvrgTarget,
    MlKem768Provider, BVRG_MAGIC,
};

fn sample_payload(op: &str) -> BvrgPayload {
    BvrgPayload {
        v: 1,
        op: op.to_string(),
        nonce: bvrg_fresh_nonce(),
        issued_at: bvrg_unix_now(),
        not_after: bvrg_unix_now() + 60,
        target: Some(BvrgTarget {
            host: "prod-web-01.internal".into(),
            port: 22,
            protocol: "ssh".into(),
            hostkey_pin: None,
        }),
        credential: Some(BvrgCredential {
            kind: "ssh-password".into(),
            username: "deploy".into(),
            material: b"hunter2".to_vec(),
            extra: None,
        }),
        session: Some(BvrgSession {
            ttl_secs: 3600,
            max_renewals: 3,
            recording: "always".into(),
        }),
        operator: BvrgOperator {
            vault_user_id: "uuid-operator".into(),
            vault_user_name: "alice".into(),
            vault_session_id: "uuid-session".into(),
            src_ip: "10.0.1.5".into(),
            deployment_id: "uuid-deployment".into(),
        },
        correlation_id: "uuid-corr".into(),
    }
}

fn rustion_keypair() -> (Vec<u8>, Vec<u8>) {
    use bv_crypto::KemProvider;
    let keypair = MlKem768Provider
        .generate_keypair()
        .expect("ml-kem keypair");
    (keypair.public_key().to_vec(), keypair.secret_key().to_vec())
}

#[test]
fn roundtrip_succeeds_on_well_formed_envelope() {
    let master = BvrgMasterSigningKey::generate().expect("master keypair");
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let payload = sample_payload("open");
    let envelope = bvrg_build(&payload, &master, &rustion_pub).expect("build");
    assert!(envelope.starts_with(BVRG_MAGIC), "magic prefix present");

    let verified = bvrg_verify(&envelope, &master_pub, &rustion_sec).expect("verify");
    assert_eq!(verified.payload.op, "open");
    assert_eq!(verified.payload.nonce, payload.nonce);
    assert_eq!(verified.payload.correlation_id, "uuid-corr");
    assert_eq!(verified.envelope_fingerprint.len(), 32);

    let credential = verified.payload.credential.expect("credential present");
    assert_eq!(credential.username, "deploy");
    assert_eq!(credential.material, b"hunter2");
}

#[test]
fn magic_mismatch_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let mut envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    envelope[0] = b'X';
    let err = bvrg_verify(&envelope, &master_pub, &rustion_sec).expect_err("magic tamper");
    assert!(
        matches!(err, BvrgError::MagicMismatch),
        "expected MagicMismatch, got {err:?}"
    );
}

#[test]
fn truncation_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    let truncated = &envelope[..4]; // less than even the magic header
    let err = bvrg_verify(truncated, &master_pub, &rustion_sec).expect_err("truncated");
    assert!(
        matches!(err, BvrgError::EnvelopeTooShort),
        "expected EnvelopeTooShort, got {err:?}"
    );
}

#[test]
fn ed25519_signature_tamper_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let mut envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    // Sig section starts right after the 5-byte magic + 2-byte
    // sig_len header. The first 2 bytes after that are the Ed25519
    // length prefix; the 64 sig bytes follow. Flip a byte deep
    // inside the Ed25519 sig.
    let offset = BVRG_MAGIC.len() + 2 + 2 + 16;
    envelope[offset] ^= 0xFF;
    let err = bvrg_verify(&envelope, &master_pub, &rustion_sec).expect_err("ed sig tamper");
    assert!(
        matches!(err, BvrgError::Ed25519SignatureInvalid),
        "expected Ed25519SignatureInvalid, got {err:?}"
    );
}

#[test]
fn mldsa65_signature_tamper_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let mut envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    // The ML-DSA-65 half starts after: magic(5) + sig_len(2) +
    // ed_len(2) + ed_sig(64) + ml_len(2). Flip a byte 32 into the
    // ML-DSA sig (well past anything Ed25519 cares about).
    let offset = BVRG_MAGIC.len() + 2 + 2 + 64 + 2 + 32;
    envelope[offset] ^= 0xFF;
    let err = bvrg_verify(&envelope, &master_pub, &rustion_sec).expect_err("ml sig tamper");
    assert!(
        matches!(err, BvrgError::MlDsa65SignatureInvalid),
        "expected MlDsa65SignatureInvalid, got {err:?}"
    );
}

#[test]
fn hybrid_downgrade_drops_mldsa_half_and_rejects() {
    // Synthesize a forged envelope where the hybrid sig contains
    // only the Ed25519 half (length-prefix says "no ML-DSA-65").
    // Even if the attacker presents a valid Ed25519 signature, the
    // hybrid construction must reject because the ML-DSA half is
    // missing.
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();

    // Carve out the sig section, replace the mldsa half with zero
    // length + zero bytes.
    let sig_start = BVRG_MAGIC.len() + 2;
    let original_sig_len = u16::from_be_bytes([
        envelope[BVRG_MAGIC.len()],
        envelope[BVRG_MAGIC.len() + 1],
    ]) as usize;
    let ct_start = sig_start + original_sig_len;
    let new_sig_len = 2 + 64 + 2; // ed25519 only, zero-length mldsa
    let mut forged = Vec::with_capacity(envelope.len());
    forged.extend_from_slice(BVRG_MAGIC);
    forged.extend_from_slice(&(new_sig_len as u16).to_be_bytes());
    forged.extend_from_slice(&envelope[sig_start..sig_start + 2 + 64]); // ed_len + ed_sig
    forged.extend_from_slice(&0u16.to_be_bytes()); // mldsa_len = 0
    forged.extend_from_slice(&envelope[ct_start..]); // ct_len + ct unchanged

    let err = bvrg_verify(&forged, &master_pub, &rustion_sec).expect_err("downgrade");
    assert!(
        matches!(err, BvrgError::HybridSignatureMalformed),
        "expected HybridSignatureMalformed, got {err:?}"
    );
}

#[test]
fn ciphertext_tamper_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let mut envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    // Flip a byte well inside the ciphertext. The tamper-detection
    // SHA-256 over (magic || ct_len || ct) means even a single bit
    // flip causes the hybrid signature to fail before AEAD ever sees
    // the bytes. Expected error: signature half fails first.
    let last_offset = envelope.len() - 1;
    envelope[last_offset] ^= 0xFF;
    let err = bvrg_verify(&envelope, &master_pub, &rustion_sec).expect_err("ct tamper");
    assert!(
        matches!(
            err,
            BvrgError::Ed25519SignatureInvalid | BvrgError::MlDsa65SignatureInvalid
        ),
        "expected signature failure (sig covers ct), got {err:?}"
    );
}

#[test]
fn wrong_recipient_kem_key_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let master_pub = master.public_key();
    let (rustion_pub, _correct_secret) = rustion_keypair();
    let (_other_pub, other_secret) = rustion_keypair();

    let envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    let err = bvrg_verify(&envelope, &master_pub, &other_secret).expect_err("wrong kem secret");
    assert!(
        matches!(err, BvrgError::CiphertextInvalid),
        "expected CiphertextInvalid, got {err:?}"
    );
}

#[test]
fn wrong_master_pub_rejects() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let stranger = BvrgMasterSigningKey::generate().unwrap();
    let stranger_pub = stranger.public_key();
    let (rustion_pub, rustion_sec) = rustion_keypair();

    let envelope = bvrg_build(&sample_payload("open"), &master, &rustion_pub).unwrap();
    // Stranger's pubkey can verify neither half.
    let err = bvrg_verify(&envelope, &stranger_pub, &rustion_sec).expect_err("wrong master");
    assert!(
        matches!(err, BvrgError::Ed25519SignatureInvalid),
        "expected Ed25519SignatureInvalid (checked first), got {err:?}"
    );
}

#[test]
fn payload_public_key_construction_rejects_classical_only() {
    let master = BvrgMasterSigningKey::generate().unwrap();
    let pk = master.public_key();
    // Hand-roll a half-only public key — Ed25519 ok, ML-DSA-65 empty.
    // Construction must refuse the downgrade.
    let err = BvrgMasterPublicKey::from_bytes(pk.ed25519.as_bytes(), &[]).expect_err("empty mldsa");
    assert!(
        matches!(err, BvrgError::PublicKeyLength),
        "expected PublicKeyLength, got {err:?}"
    );
}

#[test]
fn nonces_are_distinct_across_builds() {
    // Cheap smoke test on `fresh_nonce`: 8 nonces in a row should
    // not collide (collision odds are ~2^-122).
    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        assert!(seen.insert(bvrg_fresh_nonce()), "duplicate nonce minted");
    }
}
