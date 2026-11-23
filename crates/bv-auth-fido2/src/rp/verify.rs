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
            let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| RpError::BadSignature)?;
            verifying_key.verify(&signed, &sig).map_err(|_| RpError::BadSignature)
        }
        PublicKey::Ed25519 { verifying_key } => {
            let bytes: [u8; 64] = signature.try_into().map_err(|_| RpError::BadSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(&bytes);
            ed25519_dalek::Verifier::verify(verifying_key, &signed, &sig).map_err(|_| RpError::BadSignature)
        }
    }
}

/// Old-data KATs: assertions signed by commit 1ae9d7e1 (p256 0.13.2,
/// ed25519-dalek 2.2.0) must keep verifying. Never regenerate them.
#[cfg(test)]
mod compat_kat {
    use ciborium::value::Value as CborValue;

    use super::super::cose::parse_public_key;
    use super::verify_assertion;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn cose_key(entries: Vec<(i64, CborValue)>) -> Vec<u8> {
        let map = entries.into_iter().map(|(k, v)| (CborValue::Integer(k.into()), v)).collect();
        let mut out = Vec::new();
        ciborium::ser::into_writer(&CborValue::Map(map), &mut out).unwrap();
        out
    }

    const AUTH_DATA: &[u8] = b"fido2-kat-authenticator-data-0123456789";
    const CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"kat"}"#;

    fn es256_key() -> Vec<u8> {
        cose_key(vec![
            (1, CborValue::Integer(2.into())),
            (3, CborValue::Integer((-7).into())),
            (-1, CborValue::Integer(1.into())),
            (-2, CborValue::Bytes(from_hex("1e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e"))),
            (-3, CborValue::Bytes(from_hex("a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"))),
        ])
    }

    fn ed25519_key() -> Vec<u8> {
        cose_key(vec![
            (1, CborValue::Integer(1.into())),
            (3, CborValue::Integer((-8).into())),
            (-1, CborValue::Integer(6.into())),
            (-2, CborValue::Bytes(from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))),
        ])
    }

    #[test]
    fn es256_assertion_signed_by_the_old_build_verifies() {
        let key = parse_public_key(&es256_key()).unwrap();
        let der = from_hex(
            "3044022056340e2ed59a63cf0b31d7ba0dd695e8256f3c563db146e3a64eccfe9a5e8fb102207aadc50cd38ab5bfd2aca4cf5de6a5dd1aa65813b87378c161250704f1c08403",
        );
        verify_assertion(&key, AUTH_DATA, CLIENT_DATA, &der).unwrap();
        assert!(verify_assertion(&key, AUTH_DATA, b"{}", &der).is_err());
        // Malformed input: truncated DER and a raw r||s encoding are refused.
        assert!(verify_assertion(&key, AUTH_DATA, CLIENT_DATA, &der[..der.len() - 1]).is_err());
        assert!(verify_assertion(&key, AUTH_DATA, CLIENT_DATA, &[0u8; 64]).is_err());
    }

    #[test]
    fn ed25519_assertion_signed_by_the_old_build_verifies() {
        let key = parse_public_key(&ed25519_key()).unwrap();
        let sig = from_hex(
            "cd470e1b8a329050f268bef853c3ca8a1a952c1a14c7ccbe1d66a831199513ed6f959a245eed5a65fe29552ca92bf1e3bbad0fdf9b0a80cf22eb67688fcec607",
        );
        verify_assertion(&key, AUTH_DATA, CLIENT_DATA, &sig).unwrap();
        assert!(verify_assertion(&key, b"other", CLIENT_DATA, &sig).is_err());
        assert!(verify_assertion(&key, AUTH_DATA, CLIENT_DATA, &sig[..63]).is_err());
    }

    #[test]
    fn malformed_cose_points_are_refused() {
        // A coordinate off the curve (y flipped) must not parse.
        let bad = cose_key(vec![
            (1, CborValue::Integer(2.into())),
            (3, CborValue::Integer((-7).into())),
            (-1, CborValue::Integer(1.into())),
            (-2, CborValue::Bytes(from_hex("1e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e"))),
            (-3, CborValue::Bytes(from_hex("a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a2"))),
        ]);
        assert!(parse_public_key(&bad).is_err());
    }
}
