//! SAML 2.0 AuthnRequest generation.
//!
//! Builds the minimum-conformant `<samlp:AuthnRequest>` XML element
//! that an SP issues to kick off SP-initiated SSO, DEFLATE-compresses
//! it per the HTTP-Redirect binding (SAML Bindings § 3.4.4.1), and
//! base64-encodes the result. The caller tacks the output onto the
//! IdP SSO URL as a `SAMLRequest=...&RelayState=...` query string.
//!
//! We do NOT sign outbound AuthnRequests. Most production IdPs accept
//! unsigned requests when the SP is pre-registered with its metadata
//! and `entity_id` — enabling request signing is a follow-up that
//! needs a matching SP signing keypair, which BastionVault does not
//! currently mint. Incoming responses are still signature-verified
//! against the IdP cert either way, so this asymmetry only affects
//! authenticity of the request, not the assertion.

use std::io::Write;

use base64::{engine::general_purpose, Engine as _};
use flate2::{write::DeflateEncoder, Compression};

/// Minimum-conformant AuthnRequest. Most optional attributes are
/// omitted deliberately so we don't accidentally encode anything
/// the IdP will reject — per-IdP quirks around ProtocolBinding
/// values and NameIDPolicy Format show up when those are set without
/// careful per-IdP tuning.
///
/// `issue_instant` must be an ISO-8601 UTC timestamp with `Z` suffix
/// (SAML requires `xs:dateTime` format; practical IdPs reject
/// offsets other than `Z`).
pub struct AuthnRequestBuilder<'a> {
    pub id: &'a str,
    pub issue_instant: &'a str,
    pub destination: &'a str,
    pub assertion_consumer_service_url: &'a str,
    pub issuer: &'a str,
}

impl<'a> AuthnRequestBuilder<'a> {
    /// Serialize the AuthnRequest as raw UTF-8 XML bytes. The result
    /// is *not* compressed or base64-encoded — call `encode_redirect`
    /// to get the HTTP-Redirect-binding-ready query-string value.
    pub fn to_xml(&self) -> String {
        // Every `attribute="..."` value is built from `id` / URLs /
        // the issuer, all of which are controlled by the vault admin
        // (config + backend-generated UUID). XML-escaping is still
        // applied defensively — admins could legitimately configure
        // URLs that contain ampersands (`&entityID=…`) and we don't
        // want to silently corrupt them.
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}"><saml:Issuer>{issuer}</saml:Issuer></samlp:AuthnRequest>"#,
            id = xml_escape(self.id),
            issue_instant = xml_escape(self.issue_instant),
            destination = xml_escape(self.destination),
            acs = xml_escape(self.assertion_consumer_service_url),
            issuer = xml_escape(self.issuer),
        )
    }

    /// Encode the AuthnRequest for the HTTP-Redirect binding:
    /// DEFLATE (raw, no zlib header — SAML Bindings § 3.4.4.1), then
    /// base64. Caller URL-encodes this when appending to the SSO URL.
    pub fn encode_redirect(&self) -> Result<String, std::io::Error> {
        let xml = self.to_xml();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes())?;
        let deflated = encoder.finish()?;
        Ok(general_purpose::STANDARD.encode(deflated))
    }
}

/// Minimal XML attribute-context escape. The five characters that
/// break XML parsers inside attribute values are `& < > " '`. The
/// full spec also wants `\r` and `\n` encoded in attribute values
/// but no IdP we're targeting rejects them when left raw — we
/// escape the five that matter for safety, not the two that are
/// technically required.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Format an `Instant::now`-equivalent as the SAML-conformant UTC
/// ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn saml_now() -> String {
    // SystemTime → seconds since epoch → broken-down UTC. We avoid
    // pulling in `chrono` for this one use-case; the integer
    // arithmetic below is exact and well-tested in civil-date
    // literature.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d, hh, mm, ss) = break_down_utc(now);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Epoch-seconds → `(year, month, day, hour, minute, second)` in UTC.
/// Algorithm from Howard Hinnant's civil_from_days, in the public
/// domain — correct for all dates in the Gregorian calendar, no
/// leap-second skew (SAML timestamps don't care).
fn break_down_utc(epoch_secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    const SECS_PER_DAY: u64 = 86_400;
    let days = (epoch_secs / SECS_PER_DAY) as i64;
    let rem = epoch_secs % SECS_PER_DAY;
    let hh = (rem / 3600) as u32;
    let mm = ((rem % 3600) / 60) as u32;
    let ss = (rem % 60) as u32;

    // Shift so the civil epoch starts on 0000-03-01 to simplify the
    // leap-year math.
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

/// Short opaque id used as the AuthnRequest's `ID` attribute and the
/// storage key for the in-flight state record. SAML requires a
/// leading non-digit (XML `NCName`); prefixing with `id-` satisfies
/// that regardless of the underlying random source.
pub fn new_request_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("id-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authn_request_xml_has_required_attributes() {
        let req = AuthnRequestBuilder {
            id: "id-abc",
            issue_instant: "2026-04-24T12:00:00Z",
            destination: "https://idp.example.com/sso",
            assertion_consumer_service_url: "https://sp.example.com/acs",
            issuer: "https://sp.example.com/saml",
        };
        let xml = req.to_xml();
        assert!(xml.contains(r#"ID="id-abc""#));
        assert!(xml.contains(r#"Version="2.0""#));
        assert!(xml.contains(r#"IssueInstant="2026-04-24T12:00:00Z""#));
        assert!(xml.contains(r#"Destination="https://idp.example.com/sso""#));
        assert!(xml.contains(r#"AssertionConsumerServiceURL="https://sp.example.com/acs""#));
        assert!(xml.contains("<saml:Issuer>https://sp.example.com/saml</saml:Issuer>"));
    }

    #[test]
    fn xml_escape_handles_ampersand_and_quotes() {
        assert_eq!(
            xml_escape("a & b < c > d \" e ' f"),
            "a &amp; b &lt; c &gt; d &quot; e &apos; f"
        );
    }

    #[test]
    fn encode_redirect_roundtrips_through_deflate_and_base64() {
        let req = AuthnRequestBuilder {
            id: "id-xyz",
            issue_instant: "2026-04-24T12:00:00Z",
            destination: "https://idp.example.com/sso",
            assertion_consumer_service_url: "https://sp.example.com/acs",
            issuer: "https://sp.example.com",
        };
        let encoded = req.encode_redirect().unwrap();
        // base64-decodable.
        let deflated = general_purpose::STANDARD.decode(&encoded).unwrap();
        // inflate-decodable back to the original XML.
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let mut inflater = DeflateDecoder::new(deflated.as_slice());
        let mut xml = String::new();
        inflater.read_to_string(&mut xml).unwrap();
        assert_eq!(xml, req.to_xml());
    }

    #[test]
    fn saml_now_parses_as_iso_with_z() {
        let ts = saml_now();
        assert_eq!(ts.len(), 20, "want YYYY-MM-DDTHH:MM:SSZ, got `{ts}`");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn break_down_utc_known_dates() {
        // Unix epoch.
        assert_eq!(break_down_utc(0), (1970, 1, 1, 0, 0, 0));
        // 2020-01-01T00:00:00Z = 1577836800.
        assert_eq!(break_down_utc(1_577_836_800), (2020, 1, 1, 0, 0, 0));
        // 2026-04-24T12:00:00Z = 1777032000. (Derived by hand from
        // the day count since 1970-01-01 × 86400 + 12 × 3600.)
        assert_eq!(break_down_utc(1_777_032_000), (2026, 4, 24, 12, 0, 0));
        // Leap-day boundary: 2020-02-29T00:00:00Z = 1582934400.
        assert_eq!(break_down_utc(1_582_934_400), (2020, 2, 29, 0, 0, 0));
    }

    #[test]
    fn request_ids_are_unique_and_xml_ncname_safe() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
        assert!(a.starts_with("id-"));
        for c in a.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-',
                "request id `{a}` contains `{c}`, not NCName-safe"
            );
        }
    }
}
