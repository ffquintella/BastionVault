//! Non-cryptographic SAML Response validation.
//!
//! Signature verification lives in `verify.rs`; this module covers
//! the structural + semantic checks that apply even before the
//! signature is proved valid. Every check here produces a
//! `RvError::ErrString` with a stable message fragment that the
//! callback handler can log and the test suite can regex on.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::RvError;

use super::response::ParsedResponse;

/// Small clock-skew grace window applied to `NotBefore` /
/// `NotOnOrAfter` comparisons. Real IdPs run with NTP, but vault
/// nodes drift; 60 seconds is the value every SAML implementation
/// we've seen uses as the "acceptable" default.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 60;

pub struct ValidationInput<'a> {
    pub expected_destination: &'a str,
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_in_response_to: &'a str,
    pub now_unix: u64,
    pub clock_skew_secs: u64,
}

pub fn validate(
    parsed: &ParsedResponse,
    input: &ValidationInput<'_>,
) -> Result<(), RvError> {
    // Status must be Success — everything else is a hard failure and
    // the IdP's `StatusMessage` (when present) is surfaced so the
    // operator can diagnose (account locked, MFA required, etc.).
    if parsed.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        let msg = if parsed.status_message.is_empty() {
            String::from("(no StatusMessage)")
        } else {
            parsed.status_message.clone()
        };
        return Err(RvError::ErrString(format!(
            "saml: IdP returned non-Success status `{}`: {}",
            parsed.status_code, msg
        )));
    }

    if parsed.destination != input.expected_destination {
        return Err(RvError::ErrString(format!(
            "saml: Response Destination `{}` does not match expected ACS URL `{}`",
            parsed.destination, input.expected_destination
        )));
    }

    // InResponseTo protects against cross-session confusion + unsolicited
    // responses. Empty → IdP-initiated SSO, which we don't support here.
    if parsed.in_response_to.is_empty() {
        return Err(RvError::ErrString(
            "saml: Response has no InResponseTo — unsolicited responses not supported".into(),
        ));
    }
    if parsed.in_response_to != input.expected_in_response_to {
        return Err(RvError::ErrString(format!(
            "saml: Response InResponseTo `{}` does not match this session's AuthnRequest ID `{}`",
            parsed.in_response_to, input.expected_in_response_to
        )));
    }

    if parsed.issuer != input.expected_issuer {
        return Err(RvError::ErrString(format!(
            "saml: Response Issuer `{}` does not match configured IdP entity id `{}`",
            parsed.issuer, input.expected_issuer
        )));
    }

    let assertion = parsed
        .assertion
        .as_ref()
        .ok_or_else(|| RvError::ErrString("saml: Response carries no Assertion".into()))?;

    if assertion.issuer != input.expected_issuer {
        return Err(RvError::ErrString(format!(
            "saml: Assertion Issuer `{}` does not match configured IdP entity id `{}`",
            assertion.issuer, input.expected_issuer
        )));
    }

    if !assertion.audience_restrictions.is_empty()
        && !assertion
            .audience_restrictions
            .iter()
            .any(|a| a == input.expected_audience)
    {
        return Err(RvError::ErrString(format!(
            "saml: Assertion Audience `{:?}` does not include configured SP entity id `{}`",
            assertion.audience_restrictions, input.expected_audience
        )));
    }

    // Timestamp windows. SAML uses `NotBefore` (inclusive) and
    // `NotOnOrAfter` (exclusive). We apply `clock_skew_secs` at
    // both edges so a vault clock that's a minute ahead of the
    // IdP's doesn't spuriously reject a just-issued assertion.
    if !assertion.not_before.is_empty() {
        let nb = parse_iso8601_utc(&assertion.not_before)?;
        if input.now_unix + input.clock_skew_secs < nb {
            return Err(RvError::ErrString(format!(
                "saml: Assertion not yet valid — NotBefore `{}` is in the future",
                assertion.not_before
            )));
        }
    }
    if !assertion.not_on_or_after.is_empty() {
        let noa = parse_iso8601_utc(&assertion.not_on_or_after)?;
        if input.now_unix >= noa + input.clock_skew_secs {
            return Err(RvError::ErrString(format!(
                "saml: Assertion expired — NotOnOrAfter `{}` has passed",
                assertion.not_on_or_after
            )));
        }
    }

    if assertion.name_id.is_empty() {
        return Err(RvError::ErrString(
            "saml: Assertion has no NameID".into(),
        ));
    }

    Ok(())
}

/// Seconds-since-epoch for "now".
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an ISO-8601 UTC timestamp of the form `YYYY-MM-DDTHH:MM:SSZ`
/// or with fractional seconds `YYYY-MM-DDTHH:MM:SS.fffZ`. Produces
/// the corresponding seconds-since-epoch. Rejects offsets other
/// than `Z` — SAML spec requires UTC, IdPs comply in practice, and
/// parsing arbitrary offsets would bloat this module for no gain.
pub fn parse_iso8601_utc(s: &str) -> Result<u64, RvError> {
    // Strip any fractional-seconds section so the remainder is a
    // fixed-width 20-char timestamp.
    let trimmed = s.trim();
    let without_frac = match trimmed.find('.') {
        Some(dot) => {
            let end_z = trimmed
                .find('Z')
                .ok_or_else(|| RvError::ErrString(format!("saml: timestamp `{s}` missing Z")))?;
            let mut out = String::with_capacity(trimmed.len() - (end_z - dot));
            out.push_str(&trimmed[..dot]);
            out.push('Z');
            out
        }
        None => trimmed.to_string(),
    };

    if !without_frac.ends_with('Z') || without_frac.len() != 20 {
        return Err(RvError::ErrString(format!(
            "saml: timestamp `{s}` is not ISO-8601 UTC (want YYYY-MM-DDTHH:MM:SSZ)"
        )));
    }

    let bytes = without_frac.as_bytes();
    let year: u32 = std::str::from_utf8(&bytes[0..4])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;
    if bytes[4] != b'-' {
        return Err(bad(s));
    }
    let month: u32 = std::str::from_utf8(&bytes[5..7])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;
    if bytes[7] != b'-' {
        return Err(bad(s));
    }
    let day: u32 = std::str::from_utf8(&bytes[8..10])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;
    if bytes[10] != b'T' {
        return Err(bad(s));
    }
    let hour: u32 = std::str::from_utf8(&bytes[11..13])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;
    if bytes[13] != b':' {
        return Err(bad(s));
    }
    let min: u32 = std::str::from_utf8(&bytes[14..16])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;
    if bytes[16] != b':' {
        return Err(bad(s));
    }
    let sec: u32 = std::str::from_utf8(&bytes[17..19])
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad(s))?;

    if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 60 {
        return Err(bad(s));
    }

    Ok(days_from_civil(year as i64, month, day) * 86_400
        + (hour as u64) * 3600
        + (min as u64) * 60
        + (sec as u64))
}

/// Howard-Hinnant civil_from_days, adapted for UTC epoch. Returns
/// days since 1970-01-01 as `u64` for seconds-since-epoch
/// arithmetic — we assume every SAML timestamp is post-epoch.
fn days_from_civil(y: i64, m: u32, d: u32) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let d = d as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era as u64) * 146_097 + doe - 719_468
}

fn bad(s: &str) -> RvError {
    RvError::ErrString(format!(
        "saml: timestamp `{s}` is not a parseable ISO-8601 UTC datetime"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::credential::saml::response::{ParsedAssertion, ParsedResponse};

    fn good_response() -> ParsedResponse {
        ParsedResponse {
            response_id: "resp-1".into(),
            issuer: "https://idp.example.com".into(),
            destination: "https://sp.example.com/acs".into(),
            in_response_to: "id-abc".into(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
            assertion: Some(ParsedAssertion {
                id: "assert-1".into(),
                issuer: "https://idp.example.com".into(),
                name_id: "alice".into(),
                name_id_format: String::new(),
                not_before: "2026-04-24T12:00:00Z".into(),
                not_on_or_after: "2026-04-24T13:00:00Z".into(),
                audience_restrictions: vec!["https://sp.example.com".into()],
                attributes: Default::default(),
                xml_span: None,
            }),
            ..Default::default()
        }
    }

    fn good_input<'a>() -> ValidationInput<'a> {
        ValidationInput {
            expected_destination: "https://sp.example.com/acs",
            expected_issuer: "https://idp.example.com",
            expected_audience: "https://sp.example.com",
            expected_in_response_to: "id-abc",
            now_unix: parse_iso8601_utc("2026-04-24T12:30:00Z").unwrap(),
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        }
    }

    #[test]
    fn happy_path_passes() {
        validate(&good_response(), &good_input()).unwrap();
    }

    #[test]
    fn non_success_status_rejected() {
        let mut r = good_response();
        r.status_code = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".into();
        r.status_message = "invalid password".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("AuthnFailed"));
        assert!(format!("{err}").contains("invalid password"));
    }

    #[test]
    fn destination_mismatch_rejected() {
        let mut r = good_response();
        r.destination = "https://evil.example.com/acs".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("Destination"));
    }

    #[test]
    fn in_response_to_mismatch_rejected() {
        let mut r = good_response();
        r.in_response_to = "id-not-ours".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("InResponseTo"));
    }

    #[test]
    fn unsolicited_response_rejected() {
        let mut r = good_response();
        r.in_response_to = String::new();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("unsolicited"));
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let mut r = good_response();
        r.issuer = "https://wrong-idp.example.com".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("Issuer"));
    }

    #[test]
    fn audience_mismatch_rejected() {
        let mut r = good_response();
        r.assertion.as_mut().unwrap().audience_restrictions =
            vec!["https://someone-else.example.com".into()];
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("Audience"));
    }

    #[test]
    fn not_yet_valid_rejected() {
        let mut r = good_response();
        r.assertion.as_mut().unwrap().not_before = "2027-01-01T00:00:00Z".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("not yet valid"));
    }

    #[test]
    fn expired_rejected() {
        let mut r = good_response();
        r.assertion.as_mut().unwrap().not_on_or_after = "2020-01-01T00:00:00Z".into();
        let err = validate(&r, &good_input()).unwrap_err();
        assert!(format!("{err}").contains("expired"));
    }

    #[test]
    fn clock_skew_grace_applies() {
        // Input's "now" is T+30m within the validity window; push
        // NotBefore to "now + 30s" and confirm the 60s default
        // clock-skew grace accepts it.
        let mut r = good_response();
        let input = good_input();
        let now_plus_30 = input.now_unix + 30;
        // Rebuild ISO timestamp for now_plus_30.
        let nb = format_iso(now_plus_30);
        r.assertion.as_mut().unwrap().not_before = nb;
        validate(&r, &input).unwrap();
    }

    fn format_iso(secs: u64) -> String {
        let (y, m, d, hh, mm, ss) = break_down_utc(secs);
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }

    // Duplicate of `authn_request::break_down_utc` to keep this
    // test module self-contained; the SAML crate has one other
    // copy and a third here would be silly, but refactoring the
    // helper into a shared location is out of scope for this turn.
    fn break_down_utc(epoch_secs: u64) -> (u32, u32, u32, u32, u32, u32) {
        const SECS_PER_DAY: u64 = 86_400;
        let days = (epoch_secs / SECS_PER_DAY) as i64;
        let rem = epoch_secs % SECS_PER_DAY;
        let hh = (rem / 3600) as u32;
        let mm = ((rem % 3600) / 60) as u32;
        let ss = (rem % 60) as u32;
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = (y + if m <= 2 { 1 } else { 0 }) as u32;
        (year, m as u32, d as u32, hh, mm, ss)
    }

    #[test]
    fn parse_iso_accepts_fractional() {
        let a = parse_iso8601_utc("2026-04-24T12:00:00Z").unwrap();
        let b = parse_iso8601_utc("2026-04-24T12:00:00.123Z").unwrap();
        assert_eq!(a, b, "fractional seconds must be stripped, not rejected");
    }

    #[test]
    fn parse_iso_rejects_non_z() {
        let err = parse_iso8601_utc("2026-04-24T12:00:00+00:00").unwrap_err();
        assert!(format!("{err}").contains("ISO-8601 UTC"));
    }
}
