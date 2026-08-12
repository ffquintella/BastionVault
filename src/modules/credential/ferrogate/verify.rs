//! Verification core (Phase 2): a thin wrapper over FerroGate's reference
//! verifier. No crypto is implemented here — `ferro-child-verify` performs the
//! composite (Ed25519 + ML-DSA-65) signature check and the DPoP sender-constraint
//! enforcement; this module only sources the trust anchor from config and applies
//! the relying-party checks BastionVault owns (audience + trust domain).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_child_verify::{verify_bound, DpopExpectation, JwkSet, Verified};

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

/// Peek the `htu` claim of a DPoP proof's payload without verifying it.
///
/// Used only to pick the spelling of the expected `htu` handed to
/// `verify_bound`, and only when it is an RFC 3986 equivalent of the configured
/// audience — see [`verify_child_token`]. The value is never otherwise trusted:
/// the proof's signature, key-thumbprint binding, and freshness are still
/// checked by the verifier crate.
#[must_use]
fn dpop_htu(proof: &str) -> Option<String> {
    let seg = proof.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("htu")?.as_str().map(str::to_string)
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
    //
    // SDK 0.21.3 made `verify_bound`'s internal `htu` comparison BYTE-EXACT
    // (0.15.0 normalized both sides via the since-removed `normalize_htu`). To
    // keep accepting the same set of requests, we normalize here: if the proof's
    // own `htu` is an RFC 3986 equivalent of the configured audience, hand that
    // spelling to the verifier so its exact comparison succeeds; otherwise pass
    // the configured value and let `verify_bound` reject it.
    //
    // This does NOT trust the proof. The peeked `htu` is only ever used when it
    // normalizes equal to the operator's configured audience, so the accepted
    // set is exactly what it was on 0.15.0 — and `verify_bound` still performs
    // the full signature, thumbprint-binding, and freshness checks against
    // whichever spelling it is given. Whether a benign `htu` variation is
    // acceptable is a relying-party policy call, which this module owns.
    let want_origin = normalize_origin(&config.expected_audience);
    let proof_htu = dpop.and_then(dpop_htu).filter(|h| normalize_origin(h) == want_origin);
    let expect_htu = proof_htu.as_deref().unwrap_or(&config.expected_audience);

    let expect = DpopExpectation { htm: "POST", htu: expect_htu, max_age_secs: DPOP_MAX_AGE_SECS };

    let verified = verify_bound(token, &jwks, dpop, &expect, now, config.clock_leeway_secs)
        .map_err(|e| format!("token verification failed: {e}"))?;

    // Compare on the normalized origin so a trailing slash or case/default-port
    // difference between the client-echoed audience and the configured
    // `expected_audience` is not a mismatch. This is a normalization, not a
    // loosening — scheme, host, port and path must still all be equal.
    //
    // NOTE: this check used to call `ferro_child_verify::normalize_htu`, and the
    // `htu` comparison inside `verify_bound` used to normalize the same way. SDK
    // 0.21.3 removed that helper and made its own `htu` comparison BYTE-EXACT.
    // Keeping the audience comparison normalized therefore preserves
    // BastionVault's existing behaviour on the check we own, but the `htu`
    // binding inside `verify_bound` is now stricter than it was on 0.15.0 and we
    // cannot influence it from here. See `normalize_origin` below.
    if normalize_origin(&verified.claims.aud) != normalize_origin(&config.expected_audience) {
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

/// Normalize an origin-shaped URI for comparison, applying only well-defined
/// RFC 3986 equivalences:
///
/// * the scheme is lower-cased (schemes are case-insensitive),
/// * the authority's host is lower-cased (DNS names are case-insensitive),
/// * an explicit default port — `:80` for `http`, `:443` for `https` — is
///   dropped,
/// * trailing `/` are stripped from an otherwise clean path.
///
/// Userinfo, query, and fragment are preserved verbatim; the path stays
/// case-sensitive (only its trailing slash is trimmed). A value with no `://`
/// separator is only trailing-slash-trimmed, since no host can be safely
/// identified to case-fold.
///
/// This is a verbatim port of `ferro_child_verify::normalize_htu` as it stood in
/// FerroGate SDK 0.15.0 (Apache-2.0, same upstream project as the vendored SDK
/// under `third_party/ferrogate-sdk-rust/`). SDK 0.21.3 dropped the helper and
/// switched its internal `htu` check to a byte-exact comparison. The audience
/// check is a relying-party policy decision BastionVault owns — the module doc
/// says as much — so it lives here now rather than being borrowed from the
/// verifier crate, and it keeps working the way operators' configs expect.
#[must_use]
fn normalize_origin(uri: &str) -> String {
    let uri = uri.trim();

    // Without a scheme separator we cannot isolate a host to case-fold; limit
    // ourselves to the unambiguous trailing-slash trim.
    let Some((scheme, rest)) = uri.split_once("://") else {
        return uri.trim_end_matches('/').to_string();
    };
    let scheme = scheme.to_ascii_lowercase();

    // Split the authority from everything that follows it (path/query/fragment),
    // which is left untouched apart from the path's trailing slash.
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    // authority = [ userinfo "@" ] host [ ":" port ]. Userinfo is rare and kept
    // verbatim (it is case-sensitive).
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(u), hp),
        None => (None, authority),
    };

    // Separate host from port, honoring bracketed IPv6 literals (`[::1]:443`).
    let (host, port) = if let Some(after_bracket) = hostport.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((h, rest)) => (format!("[{}]", h.to_ascii_lowercase()), rest.strip_prefix(':')),
            None => (hostport.to_ascii_lowercase(), None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (hostport.to_ascii_lowercase(), None),
        }
    };

    // Drop an explicit default port; keep any other (including an empty one,
    // which is malformed but preserved so it cannot silently match a real port).
    let port = match port {
        Some("443") if scheme == "https" => None,
        Some("80") if scheme == "http" => None,
        other => other,
    };

    // Trim trailing slash(es) only on a clean path (no query/fragment), so a
    // bare `/` collapses to the empty path and `/a/` matches `/a`.
    let tail = if tail.starts_with('/') && !tail.contains(['?', '#']) {
        tail.trim_end_matches('/')
    } else {
        tail
    };

    let mut out = String::with_capacity(uri.len());
    out.push_str(&scheme);
    out.push_str("://");
    if let Some(u) = userinfo {
        out.push_str(u);
        out.push('@');
    }
    out.push_str(&host);
    if let Some(p) = port {
        out.push(':');
        out.push_str(p);
    }
    out.push_str(tail);
    out
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

    /// Since SDK 0.21.3 the `htu` expectation handed to `verify_bound` may come
    /// from the proof itself (see `verify_child_token`), gated on normalizing
    /// equal to the configured audience. These guard that gate: a non-equivalent
    /// `htu` must not be able to smuggle itself in as its own expectation.
    #[test]
    fn non_equivalent_htu_cannot_supply_its_own_expectation() {
        // A non-default port is significant — only :80/:443 are droppable.
        let err = verify_with("https://vault.example.com:4200", "https://vault.example.com:9999")
            .expect_err("a different port must be rejected");
        assert!(err.contains("does not match"), "unexpected error: {err}");

        // The path stays case- and content-sensitive; only a trailing slash goes.
        let err = verify_with("https://vault.example.com/a", "https://vault.example.com/b")
            .expect_err("a different path must be rejected");
        assert!(err.contains("does not match"), "unexpected error: {err}");

        // A default port on the *wrong* scheme is not droppable either.
        let err = verify_with("https://vault.example.com:80", "https://vault.example.com")
            .expect_err("http's default port must not be dropped for https");
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }

    #[test]
    fn normalize_origin_applies_only_rfc3986_equivalences() {
        let n = super::normalize_origin;

        // Scheme + host case-fold, default port drops, trailing slash trims.
        assert_eq!(n("HTTPS://Vault.Example.com:443/"), "https://vault.example.com");
        assert_eq!(n("http://Host:80/a/"), "http://host/a");
        assert_eq!(n("https://h:4200/"), "https://h:4200");

        // Non-default ports, mismatched scheme/port pairs, and paths survive.
        assert_eq!(n("https://h:9999"), "https://h:9999");
        assert_eq!(n("https://h:80"), "https://h:80");
        assert_eq!(n("https://h/A"), "https://h/A");

        // IPv6 literals keep their brackets; userinfo is left verbatim.
        assert_eq!(n("https://[::1]:443/x/"), "https://[::1]/x");
        assert_eq!(n("https://User@H/"), "https://User@h");

        // Query/fragment suppress the trailing-slash trim (it is no longer a
        // clean path), and are preserved byte-for-byte.
        assert_eq!(n("https://H/a/?q=1"), "https://h/a/?q=1");

        // No scheme separator: trailing-slash trim only, no case-folding.
        assert_eq!(n("Vault.Example.com/"), "Vault.Example.com");
    }
}
