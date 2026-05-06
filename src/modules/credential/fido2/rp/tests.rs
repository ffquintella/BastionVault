//! Smoke tests for the in-tree WebAuthn RP.
//!
//! Full end-to-end coverage requires real authenticator output (browser
//! or virtual authenticator). These tests focus on the deterministic
//! pieces: parsers, encoding helpers, and clientData verification.

use super::*;

#[test]
fn challenge_is_32_bytes_b64() {
    let c = Challenge::random();
    let raw = b64::decode(&c.b64).expect("decodes");
    assert_eq!(raw.len(), 32);
}

#[test]
fn rp_validates_origin_host_against_rp_id() {
    let rp = RelyingParty {
        rp_id: "example.com",
        rp_origin: "https://app.example.com",
        rp_name: "Example",
    };
    rp.validate().expect("subdomain origin is allowed");

    let bad = RelyingParty {
        rp_id: "example.com",
        rp_origin: "https://other.org",
        rp_name: "Example",
    };
    assert!(bad.validate().is_err());
}

#[test]
fn rp_validates_exact_host_match() {
    let rp = RelyingParty {
        rp_id: "example.com",
        rp_origin: "https://example.com",
        rp_name: "Example",
    };
    rp.validate().unwrap();
}

#[test]
fn client_data_rejects_wrong_type() {
    let challenge = Challenge::from_bytes(&[7u8; 32]);
    let cd = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge.b64,
        "origin": "https://example.com",
    });
    let raw = serde_json::to_vec(&cd).unwrap();
    let err = client_data::verify(&raw, "webauthn.create", "https://example.com", &challenge)
        .unwrap_err();
    matches!(err, RpError::ClientDataType { .. });
}

#[test]
fn client_data_rejects_wrong_origin() {
    let challenge = Challenge::from_bytes(&[7u8; 32]);
    let cd = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge.b64,
        "origin": "https://evil.example",
    });
    let raw = serde_json::to_vec(&cd).unwrap();
    let err = client_data::verify(&raw, "webauthn.create", "https://example.com", &challenge)
        .unwrap_err();
    matches!(err, RpError::OriginMismatch { .. });
}

#[test]
fn client_data_rejects_wrong_challenge() {
    let issued = Challenge::from_bytes(&[7u8; 32]);
    let other = Challenge::from_bytes(&[8u8; 32]);
    let cd = serde_json::json!({
        "type": "webauthn.create",
        "challenge": other.b64,
        "origin": "https://example.com",
    });
    let raw = serde_json::to_vec(&cd).unwrap();
    let err = client_data::verify(&raw, "webauthn.create", "https://example.com", &issued)
        .unwrap_err();
    matches!(err, RpError::ChallengeMismatch);
}

#[test]
fn client_data_accepts_valid() {
    let challenge = Challenge::from_bytes(&[1u8; 32]);
    let cd = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge.b64,
        "origin": "https://example.com",
        "crossOrigin": false,
    });
    let raw = serde_json::to_vec(&cd).unwrap();
    client_data::verify(&raw, "webauthn.create", "https://example.com", &challenge).unwrap();
}

#[test]
fn auth_data_parses_minimum_blob() {
    use sha2::{Digest, Sha256};
    let mut blob = Vec::with_capacity(37);
    let rp_hash: [u8; 32] = Sha256::digest(b"example.com").into();
    blob.extend_from_slice(&rp_hash);
    blob.push(0x01); // UP only
    blob.extend_from_slice(&5u32.to_be_bytes());
    let ad = auth_data::AuthenticatorData::parse(&blob).unwrap();
    assert!(ad.flags.user_present());
    assert!(!ad.flags.attested_credential_data());
    assert_eq!(ad.sign_count, 5);
    ad.expect_rp_id("example.com").unwrap();
    assert!(ad.expect_rp_id("other.com").is_err());
}

#[test]
fn auth_data_rejects_short_blob() {
    let blob = vec![0u8; 36];
    assert!(auth_data::AuthenticatorData::parse(&blob).is_err());
}

#[test]
fn passkey_round_trip_json() {
    let pk = Passkey {
        v: 1,
        cred_id: b64::encode(&[1, 2, 3, 4]),
        cose_pub_key: b64::encode(&[9, 9, 9]),
        sign_count: 42,
        user_handle: b64::encode(&[0xab; 16]),
        transports: vec!["usb".into()],
        created_at: 1_700_000_000,
    };
    let s = serde_json::to_string(&pk).unwrap();
    let back: Passkey = serde_json::from_str(&s).unwrap();
    assert_eq!(back.cred_id_bytes().unwrap(), vec![1, 2, 3, 4]);
    assert_eq!(back.sign_count, 42);
}
