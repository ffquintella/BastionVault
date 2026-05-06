//! `clientDataJSON` parsing and verification.
//!
//! WebAuthn defines clientDataJSON as a JSON-encoded object containing at
//! least `type`, `challenge` (base64url) and `origin`. We only check the
//! fields that matter for security; any extra fields are tolerated.

use serde::Deserialize;

use super::challenge::Challenge;
use super::errors::RpError;

#[derive(Debug, Deserialize)]
struct CollectedClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
}

/// Parse the raw clientDataJSON bytes and check the four invariants
/// every WebAuthn ceremony requires:
///
/// * the JSON parses and contains the required keys,
/// * `type` matches the expected ceremony (`webauthn.create` or `webauthn.get`),
/// * `origin` matches the configured RP origin exactly,
/// * `challenge` matches the challenge we issued in `begin_*`.
pub fn verify(
    raw: &[u8],
    expected_type: &str,
    expected_origin: &str,
    expected_challenge: &Challenge,
) -> Result<(), RpError> {
    let cd: CollectedClientData = serde_json::from_slice(raw)
        .map_err(|e| RpError::BadClientData(format!("not valid JSON: {e}")))?;

    if cd.ty != expected_type {
        return Err(RpError::ClientDataType {
            expected: expected_type.to_string(),
            actual: cd.ty,
        });
    }
    if cd.origin != expected_origin {
        return Err(RpError::OriginMismatch {
            expected: expected_origin.to_string(),
            actual: cd.origin,
        });
    }
    // Both sides are base64url-no-pad strings — string compare is fine.
    // Browsers MUST emit base64url-no-pad per spec; if a future browser
    // emits a different encoding we'll see a mismatch and reject, which
    // is the safe failure mode.
    if cd.challenge != expected_challenge.b64 {
        return Err(RpError::ChallengeMismatch);
    }
    Ok(())
}
