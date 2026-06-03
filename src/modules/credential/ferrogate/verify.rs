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

    if verified.claims.aud != config.expected_audience {
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
