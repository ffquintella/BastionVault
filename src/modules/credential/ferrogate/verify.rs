//! Verification core (Phase 2): a thin wrapper over FerroGate's reference
//! verifier. No crypto is implemented here — `ferro-child-verify` performs the
//! composite (Ed25519 + ML-DSA-65) signature check and the DPoP sender-constraint
//! enforcement; this module only sources the trust anchor from config and applies
//! the relying-party checks BastionVault owns (audience + trust domain).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_child_verify::{normalize_htu, verify_bound, DpopExpectation, JwkSet, Verified};

use super::FerroGateConfig;

/// Maximum age (seconds) accepted on a DPoP proof (RFC 9449 §4.3).
const DPOP_MAX_AGE_SECS: i64 = 300;

/// The verified identity of a directly-presented host SVID.
pub struct VerifiedSvid {
    /// Host SPIFFE id (the SVID `sub`).
    pub spiffe_id: String,
    /// `SHA-384(ek_cert)` hex from the attestation block.
    pub ek_cert_sha384: String,
    /// RIM policy generation from the attestation block.
    pub policy_id: String,
}

/// Peek the JOSE `typ` of a compact JWS without verifying it. Used to route a
/// presented token to the child-token or SVID verifier.
#[must_use]
pub fn token_typ(jws: &str) -> Option<String> {
    let seg = jws.split('.').next()?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("typ")?.as_str().map(str::to_string)
}

/// Peek the JOSE `kid` of a compact JWS without verifying it. Feeds the CMIS
/// JWKS fetch's `kid_hint` and the miss check that busts the JWKS cache when
/// a token names a key the cached set does not carry.
#[must_use]
pub fn token_kid(jws: &str) -> Option<String> {
    let seg = jws.split('.').next()?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("kid")?.as_str().map(str::to_string)
}

/// Whether a JWKS JSON document carries a key with the given `kid`. A
/// malformed document reports `false` — the caller's subsequent parse/verify
/// surfaces the real error.
#[must_use]
pub fn jwks_has_kid(jwks_json: &str, kid: &str) -> bool {
    JwkSet::from_json(jwks_json).is_ok_and(|s| s.keys.iter().any(|k| k.kid == kid))
}

/// Verify a host SVID presented directly (the opt-in `accept_svid` mode). This
/// enforces the FerroGate CRL via `verify_unrevoked` (a revoked or stale-CRL
/// SVID is rejected) but provides **no** per-request DPoP sender-constraint —
/// it is the weaker path. Returns the host identity (the SVID `sub`).
pub fn verify_svid_token(
    config: &FerroGateConfig,
    jwks_json: &str,
    token: &str,
    now: i64,
) -> Result<VerifiedSvid, String> {
    if jwks_json.trim().is_empty() {
        return Err("ferrogate backend has no JWKS (trust anchor) configured".to_string());
    }
    let jwks = ferro_svid_verify::JwkSet::from_json(jwks_json).map_err(|e| format!("invalid JWKS: {e}"))?;
    let verified = ferro_svid_verify::verify_unrevoked(token, &jwks, now, config.clock_leeway_secs)
        .map_err(|e| format!("SVID verification failed: {e}"))?;

    if !config.trust_domain.is_empty() {
        let prefix = format!("spiffe://{}/", config.trust_domain);
        if !verified.claims.sub.starts_with(&prefix) {
            return Err(format!(
                "SVID subject '{}' is not in trust domain '{}'",
                verified.claims.sub, config.trust_domain
            ));
        }
    }

    Ok(VerifiedSvid {
        spiffe_id: verified.claims.sub,
        ek_cert_sha384: verified.claims.attest.ek_cert_sha384,
        policy_id: verified.claims.attest.policy_id,
    })
}

/// Verify a FerroGate child token presented at `auth/ferrogate/login`.
///
/// `jwks_json` is the trust anchor the caller resolved (from `static_jwks` or a
/// `cmis_grpc` fetch). Returns the validated [`Verified`] claims, or a
/// human-readable rejection reason (safe to surface — it names *why*
/// verification failed, never secret material). `now` is Unix seconds; `dpop`
/// is the RFC 9449 proof JWS.
pub fn verify_child_token(
    config: &FerroGateConfig,
    jwks_json: &str,
    token: &str,
    dpop: Option<&str>,
    now: i64,
) -> Result<Verified, String> {
    if jwks_json.trim().is_empty() {
        return Err("ferrogate backend has no JWKS (trust anchor) configured".to_string());
    }
    if config.expected_audience.is_empty() {
        return Err("ferrogate backend is not configured: expected_audience is empty".to_string());
    }

    let jwks = JwkSet::from_json(jwks_json).map_err(|e| format!("invalid JWKS: {e}"))?;

    // The DPoP proof binds to the HTTP method + target URI. Phase 2 uses the
    // configured audience as the expected `htu` (FerroGate's child tokens carry
    // `aud == htu`); a later phase can derive the real request URL from the
    // connection instead.
    let expect = DpopExpectation { htm: "POST", htu: &config.expected_audience, max_age_secs: DPOP_MAX_AGE_SECS };

    let verified = verify_bound(token, &jwks, dpop, &expect, now, config.clock_leeway_secs)
        .map_err(|e| format!("token verification failed: {e}"))?;

    // Compare on the normalized origin so a trailing slash or case/default-port
    // difference between the client-echoed audience and the configured
    // `expected_audience` is not a mismatch. This mirrors the `htu` check inside
    // `verify_bound` (both derive from the same address) and is a normalization,
    // not a loosening — scheme, host, port and path must still all be equal.
    if normalize_htu(&verified.claims.aud) != normalize_htu(&config.expected_audience) {
        return Err(format!(
            "token audience '{}' does not match expected '{}'",
            verified.claims.aud, config.expected_audience
        ));
    }

    if !config.trust_domain.is_empty() {
        let prefix = format!("spiffe://{}/", config.trust_domain);
        if !verified.claims.iss.starts_with(&prefix) {
            return Err(format!(
                "token issuer '{}' is not in trust domain '{}'",
                verified.claims.iss, config.trust_domain
            ));
        }
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use ferro_child_verify::{jwk_thumbprint_ed25519, CHILD_ALG, CHILD_SIGNING_CONTEXT, CHILD_TYP};
    use ferro_crypto::composite::CompositeSecretKey;
    use serde_json::json;

    use super::{verify_child_token, FerroGateConfig};

    const KID: &str = "host-test-1";
    const ISS: &str = "spiffe://ferrogate.test/host/abc";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn mint_child(sk: &CompositeSecretKey, aud: &str, jkt: &str, iat: i64, exp: i64) -> String {
        let header = json!({ "alg": CHILD_ALG, "typ": CHILD_TYP, "kid": KID });
        let claims = json!({
            "iss": ISS,
            "sub": format!("{ISS}#app:abababababababab"),
            "aud": aud,
            "exp": exp,
            "iat": iat,
            "jti": "0123456789abcdef0123456789abcdef",
            "cnf": { "jkt": jkt },
            "ferrogate": {
                "parent_svid": "33".repeat(48),
                "actor_pid": 1234u32,
                "actor_uid": 1001u32,
                "actor_bin": "ab".repeat(48),
            },
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(CHILD_SIGNING_CONTEXT, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64(&sig.to_concat_bytes()))
    }

    fn mint_dpop(ed_sk: &SigningKey, htu: &str, iat: i64) -> (String, String) {
        let x = b64(ed_sk.verifying_key().as_bytes());
        let jkt = jwk_thumbprint_ed25519(&x);
        let header = json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x } });
        let claims = json!({ "jti": "dpop-jti-0001", "htm": "POST", "htu": htu, "iat": iat });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = ed_sk.sign(signing_input.as_bytes());
        (format!("{signing_input}.{}", b64(&sig.to_bytes())), jkt)
    }

    fn jwks_json(pk: &ferro_crypto::composite::CompositePublicKey) -> String {
        json!({ "keys": [ { "kty": "FERROGATE-COMPOSITE", "kid": KID, "pub": b64(&pk.to_concat_bytes()) } ] })
            .to_string()
    }

    /// Mint a token+proof whose `aud`/`htu` is `client_addr` and verify it
    /// against a mount configured with `expected_audience = configured`.
    fn verify_with(client_addr: &str, configured: &str) -> Result<(), String> {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
        let now = 1000;
        let (proof, jkt) = mint_dpop(&ed_sk, client_addr, now);
        let jws = mint_child(&sk, client_addr, &jkt, now, now + 3600);
        let config = FerroGateConfig {
            trust_domain: "ferrogate.test".to_string(),
            expected_audience: configured.to_string(),
            clock_leeway_secs: 30,
            ..Default::default()
        };
        verify_child_token(&config, &jwks_json(&pk), &jws, Some(&proof), now + 10).map(|_| ())
    }

    #[test]
    fn trailing_slash_difference_is_accepted() {
        verify_with("https://vault.example.com:4200/", "https://vault.example.com:4200")
            .expect("client trailing slash must still verify");
        verify_with("https://vault.example.com:4200", "https://vault.example.com:4200/")
            .expect("configured trailing slash must still verify");
    }

    #[test]
    fn scheme_and_host_case_difference_is_accepted() {
        verify_with("HTTPS://Vault.Example.com:4200", "https://vault.example.com:4200")
            .expect("scheme/host case must not break verification");
    }

    #[test]
    fn default_port_difference_is_accepted() {
        verify_with("https://vault.example.com:443", "https://vault.example.com")
            .expect("explicit default https port must verify");
    }

    #[test]
    fn token_kid_peeks_the_header_without_verifying() {
        let (sk, _pk) = CompositeSecretKey::generate().unwrap();
        let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
        let (_proof, jkt) = mint_dpop(&ed_sk, "https://a", 1000);
        let jws = mint_child(&sk, "https://a", &jkt, 1000, 2000);
        assert_eq!(super::token_kid(&jws).as_deref(), Some(KID));
        assert_eq!(super::token_kid("not-a-jws"), None);
    }

    #[test]
    fn jwks_has_kid_reports_presence_and_tolerates_garbage() {
        let (_sk, pk) = CompositeSecretKey::generate().unwrap();
        let json = jwks_json(&pk);
        assert!(super::jwks_has_kid(&json, KID));
        assert!(!super::jwks_has_kid(&json, "host-absent"));
        assert!(!super::jwks_has_kid("{ not json", KID));
    }

    #[test]
    fn genuinely_different_audience_is_rejected() {
        // A different host must still fail — normalization is not a loosening.
        let err = verify_with("https://vault.example.com", "https://evil.example.com")
            .expect_err("a different origin must be rejected");
        // The DPoP htu binding trips first (htu == aud here), surfaced verbatim.
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }
}
