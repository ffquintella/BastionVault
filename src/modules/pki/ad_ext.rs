//! Active Directory / Microsoft-specific X.509 extension encoders.
//!
//! Windows smart-card logon (and the Kerberos PKINIT exchange that backs
//! it) needs three things in a client certificate that RFC 5280 has no
//! opinion about:
//!
//! 1. **UPN in `subjectAltName` as an `otherName`** (OID
//!    `1.3.6.1.4.1.311.20.2.3`, value a UTF8String). This is how the KDC
//!    maps the certificate to an AD account when no explicit
//!    `altSecurityIdentities` mapping exists.
//! 2. **The Smart Card Logon EKU** (`1.3.6.1.4.1.311.20.2.2`). Windows
//!    refuses a logon certificate whose EKU set is present but omits it.
//! 3. **The `szOID_NTDS_CA_SECURITY_EXT` SID extension**
//!    (`1.3.6.1.4.1.311.25.2`), carrying the account's SID. Since
//!    KB5014754 moved domain controllers to Full Enforcement — and the
//!    September 9, 2025 update removed the `StrongCertificateBindingEnforcement`
//!    escape hatch entirely — a certificate without either this extension
//!    or a *strong* `altSecurityIdentities` mapping is refused outright.
//!
//! The third one is why this module exists at all rather than being a
//! two-line addition to the SAN builder. The strong `altSecurityIdentities`
//! mappings (`X509IssuerSerialNumber`, `X509SKI`, `X509SHA1PublicKey`) all
//! bind to one specific certificate, so they are unusable for short-lived,
//! minted-per-session credentials — the AD attribute would have to be
//! rewritten before every connect. Emitting the SID extension is the only
//! route that keeps per-session issuance viable.
//!
//! Everything here is opt-in per role and fails closed: a role that does
//! not set `allow_upn_sans` / `allow_ad_sid` produces exactly the
//! certificate profile it produced before this module landed.
//!
//! Both certificate paths use these encoders. The classical (`rcgen`)
//! builder consumes [`upn_san_arcs`] plus [`sid_extension_der`] wrapped in
//! an `rcgen::CustomExtension`; the ML-DSA / composite builders (which
//! assemble DER by hand via `x509-cert`) consume [`upn_general_name`] and
//! [`sid_extension`] directly. One encoder, so the two paths cannot drift.

use const_oid::ObjectIdentifier;
use x509_cert::{
    der::{
        asn1::{Any, OctetString},
        Encode, Tag,
    },
    ext::{
        pkix::name::{GeneralName, GeneralNames, OtherName},
        Extension,
    },
};

use super::path_roles::RoleEntry;
use crate::errors::RvError;

/// `szOID_NT_PRINCIPAL_NAME` — the UPN `otherName` type-id that goes in
/// `subjectAltName`.
pub const UPN_OID: &str = "1.3.6.1.4.1.311.20.2.3";

/// `szOID_NTDS_CA_SECURITY_EXT` — the certificate extension that carries
/// the subject's SID for KB5014754 strong mapping.
pub const SID_EXT_OID: &str = "1.3.6.1.4.1.311.25.2";

/// `szOID_NTDS_OBJECTSID` — the `otherName` type-id *inside* the SID
/// extension's `GeneralNames` value. Note this is a child of
/// [`SID_EXT_OID`], not the same OID.
pub const SID_OTHER_NAME_OID: &str = "1.3.6.1.4.1.311.25.2.1";

/// `szOID_KP_SMARTCARD_LOGON` — required EKU for Windows smart-card logon.
pub const SMARTCARD_LOGON_EKU_OID: &str = "1.3.6.1.4.1.311.20.2.2";

/// `id-pkinit-KPKdc` — the KDC Authentication EKU. Domain-controller
/// certificates need it; exposed here so an operator can mint DC certs off
/// a BastionVault issuer too.
pub const KDC_AUTH_EKU_OID: &str = "1.3.6.1.5.2.3.5";

/// Longest SID we will accept. A SID is `S-1-<authority>` plus up to 15
/// sub-authorities; the theoretical maximum is comfortably under this, and
/// the bound keeps a hostile `ad_sid` from bloating the certificate.
const MAX_SID_LEN: usize = 187;

/// Parse a dotted-decimal OID into a `const_oid::ObjectIdentifier`.
///
/// Stricter than `ObjectIdentifier::new` on purpose. `const_oid` accepts
/// an empty component — `1.3.6.1.4.1.311..2` parses as if the gap were a
/// `0` arc — which would turn a typo in a role's `ext_key_usage_oids`
/// into a valid-looking but wrong EKU on every certificate the role
/// issues. We reject empty components up front so the mistake surfaces at
/// role-write time with a readable message.
pub fn parse_oid(dotted: &str) -> Result<ObjectIdentifier, RvError> {
    let trimmed = dotted.trim();
    if trimmed.is_empty() {
        return Err(RvError::ErrString("oid: empty value".into()));
    }
    if trimmed.split('.').any(|component| component.is_empty()) {
        return Err(RvError::ErrString(format!(
            "oid `{trimmed}` has an empty component (check for a doubled or trailing `.`)"
        )));
    }
    ObjectIdentifier::new(trimmed).map_err(|e| {
        RvError::ErrString(format!("oid `{trimmed}` is not a valid object identifier ({e})"))
    })
}

/// Parse a dotted-decimal OID into the `&[u64]` arc form `rcgen` wants.
pub fn parse_oid_arcs(dotted: &str) -> Result<Vec<u64>, RvError> {
    Ok(parse_oid(dotted)?.arcs().map(u64::from).collect())
}

/// The UPN `otherName` type-id in arc form, for `rcgen::SanType::OtherName`.
pub fn upn_san_arcs() -> Vec<u64> {
    // UPN_OID is a compile-time constant we control, so this cannot fail.
    // Falling back to an empty vec on a hypothetical parse failure would
    // silently emit a malformed SAN, so we assert instead.
    parse_oid_arcs(UPN_OID).expect("UPN_OID is a valid OID")
}

/// Build the `otherName` `GeneralName` for a UPN, for the hand-rolled DER
/// paths (ML-DSA / composite).
///
/// The value is a UTF8String, per the Microsoft requirement that the UPN
/// `otherName` be "ASN1 / UTF-8" encoded — a raw-bytes encoding is the
/// classic cause of AD rejecting an otherwise well-formed certificate.
pub fn upn_general_name(upn: &str) -> Result<GeneralName, RvError> {
    let type_id = parse_oid(UPN_OID)?;
    let value = Any::new(Tag::Utf8String, upn.as_bytes())
        .map_err(|e| RvError::ErrString(format!("upn_sans: cannot encode `{upn}` as UTF8String ({e})")))?;
    Ok(GeneralName::OtherName(OtherName { type_id, value }))
}

/// DER-encode the *value* of the SID extension: a `GeneralNames`
/// containing a single `otherName` whose type-id is
/// [`SID_OTHER_NAME_OID`] and whose value is an OCTET STRING holding the
/// SID in its textual `S-1-5-21-…` form.
///
/// Returned as raw DER (not wrapped in an `Extension`) so the `rcgen`
/// path can hand it straight to `CustomExtension::from_oid_content`,
/// which does its own OCTET STRING wrapping.
pub fn sid_extension_der(sid: &str) -> Result<Vec<u8>, RvError> {
    let type_id = parse_oid(SID_OTHER_NAME_OID)?;
    // The SID travels as an OCTET STRING of the *ASCII text* form, not as
    // the binary SID structure. Windows reads it back with a plain string
    // compare against the account SID.
    let value = Any::new(Tag::OctetString, sid.as_bytes())
        .map_err(|e| RvError::ErrString(format!("ad_sid: cannot wrap `{sid}` in Any ({e})")))?;

    let names: GeneralNames = vec![GeneralName::OtherName(OtherName { type_id, value })];
    names
        .to_der()
        .map_err(|e| RvError::ErrString(format!("ad_sid: GeneralNames DER encode failed ({e})")))
}

/// The SID extension as an `x509-cert` `Extension`, for the hand-rolled
/// DER paths. Non-critical, matching what an Enterprise CA emits — a
/// critical unknown extension would make non-Windows verifiers reject
/// the chain.
pub fn sid_extension(sid: &str) -> Result<Extension, RvError> {
    let extn_id = parse_oid(SID_EXT_OID)?;
    let der = sid_extension_der(sid)?;
    Ok(Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(der)
            .map_err(|e| RvError::ErrString(format!("ad_sid: extension wrap failed ({e})")))?,
    })
}

/// Validate a UPN against the role's policy.
///
/// Structural rules: exactly one `@`, both halves non-empty, no embedded
/// whitespace or control characters. Policy rule: when the role sets
/// `allowed_upn_domains`, the realm must appear on that list
/// (case-insensitive). An empty list with `allow_upn_sans = true` accepts
/// any realm — the same "empty means unconstrained" convention
/// `allowed_key_refs` already uses.
pub fn validate_upn(role: &RoleEntry, upn: &str) -> Result<(), RvError> {
    if !role.allow_upn_sans {
        return Err(RvError::ErrString(
            "upn_sans: this role does not permit UPN SANs (set allow_upn_sans=true on the role)".into(),
        ));
    }
    if upn.is_empty() {
        return Err(RvError::ErrString("upn_sans: empty UPN".into()));
    }
    if upn.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RvError::ErrString(format!(
            "upn_sans: `{upn}` contains whitespace or control characters"
        )));
    }
    let mut parts = upn.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        return Err(RvError::ErrString(format!(
            "upn_sans: `{upn}` is not a valid UPN (expected exactly one `@`, e.g. user@example.com)"
        )));
    }

    if role.allowed_upn_domains.is_empty() {
        return Ok(());
    }
    let candidate = domain.to_ascii_lowercase();
    let permitted = role
        .allowed_upn_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .any(|d| !d.is_empty() && d == candidate);
    if permitted {
        Ok(())
    } else {
        Err(RvError::ErrString(format!(
            "upn_sans: realm `{domain}` is not in the role's allowed_upn_domains"
        )))
    }
}

/// Validate a security identifier in its textual form.
///
/// Accepts `S-1-<authority>[-<sub-authority>…]`: a leading `S`, revision
/// `1`, an identifier authority, and zero or more sub-authorities, each a
/// decimal number. Case-insensitive on the leading `S` since AD tooling
/// is inconsistent about it, but the emitted value is normalised to
/// upper-case `S-` because Windows compares the extension byte-for-byte
/// against the account SID.
pub fn validate_ad_sid(role: &RoleEntry, sid: &str) -> Result<(), RvError> {
    if !role.allow_ad_sid {
        return Err(RvError::ErrString(
            "ad_sid: this role does not permit the AD SID extension (set allow_ad_sid=true on the role)".into(),
        ));
    }
    if sid.len() > MAX_SID_LEN {
        return Err(RvError::ErrString(format!(
            "ad_sid: `{sid}` exceeds the maximum SID length of {MAX_SID_LEN} characters"
        )));
    }
    let mut parts = sid.split('-');
    match parts.next() {
        Some(p) if p.eq_ignore_ascii_case("S") => {}
        _ => {
            return Err(RvError::ErrString(format!(
                "ad_sid: `{sid}` must start with `S-` (e.g. S-1-5-21-1004336348-1177238915-682003330-512)"
            )))
        }
    }
    match parts.next() {
        Some("1") => {}
        _ => {
            return Err(RvError::ErrString(format!(
                "ad_sid: `{sid}` must use SID revision 1"
            )))
        }
    }
    let mut authority_count = 0usize;
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(RvError::ErrString(format!(
                "ad_sid: `{sid}` has a non-numeric or empty component"
            )));
        }
        if part.parse::<u64>().is_err() {
            return Err(RvError::ErrString(format!(
                "ad_sid: `{sid}` has a component that overflows a 64-bit integer"
            )));
        }
        authority_count += 1;
    }
    if authority_count == 0 {
        return Err(RvError::ErrString(format!(
            "ad_sid: `{sid}` is missing an identifier authority"
        )));
    }
    Ok(())
}

/// Normalise a validated SID for emission: upper-case the leading `S`
/// and trim. Everything after the `S` is already digits and dashes.
pub fn normalize_ad_sid(sid: &str) -> String {
    let trimmed = sid.trim();
    if let Some(rest) = trimmed.strip_prefix('s') {
        format!("S{rest}")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{Decode, Tagged};

    fn role(allow_upn: bool, allow_sid: bool) -> RoleEntry {
        RoleEntry { allow_upn_sans: allow_upn, allow_ad_sid: allow_sid, ..Default::default() }
    }

    #[test]
    fn oid_constants_parse() {
        for oid in [UPN_OID, SID_EXT_OID, SID_OTHER_NAME_OID, SMARTCARD_LOGON_EKU_OID, KDC_AUTH_EKU_OID] {
            assert!(parse_oid(oid).is_ok(), "{oid} should parse");
            assert!(!parse_oid_arcs(oid).unwrap().is_empty());
        }
        // The arc form and the dotted form must describe the same OID —
        // the rcgen path uses the former, the x509-cert path the latter.
        assert_eq!(upn_san_arcs(), vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3]);
    }

    #[test]
    fn rejects_bogus_oid() {
        assert!(parse_oid_arcs("").is_err());
        assert!(parse_oid_arcs("not-an-oid").is_err());
        // `const_oid` would happily read the doubled dot as a `0` arc,
        // producing a wrong-but-valid OID. We refuse it instead.
        assert!(parse_oid_arcs("1.3.6.1.4.1.311..2").is_err());
        assert!(parse_oid_arcs("1.3.6.1.4.1.311.20.2.2.").is_err(), "trailing dot");
        assert!(parse_oid_arcs(".1.3.6").is_err(), "leading dot");
    }

    #[test]
    fn upn_other_name_encodes_as_utf8_string() {
        let gn = upn_general_name("felipe@example.com").unwrap();
        let der = gn.to_der().unwrap();
        // Re-decode and confirm the type-id and the UTF8String tag survived.
        let decoded = GeneralName::from_der(&der).unwrap();
        match decoded {
            GeneralName::OtherName(other) => {
                assert_eq!(other.type_id, parse_oid(UPN_OID).unwrap());
                assert_eq!(other.value.tag(), Tag::Utf8String);
                assert_eq!(other.value.value(), b"felipe@example.com");
            }
            _ => panic!("expected an otherName GeneralName"),
        }
    }

    #[test]
    fn sid_extension_wraps_general_names_with_octet_string_value() {
        let sid = "S-1-5-21-1004336348-1177238915-682003330-512";
        let ext = sid_extension(sid).unwrap();
        assert_eq!(ext.extn_id, parse_oid(SID_EXT_OID).unwrap());
        assert!(!ext.critical, "the SID extension must be non-critical");

        // extn_value holds the DER of a GeneralNames; decode it back and
        // confirm the inner otherName carries the SID text as an OCTET
        // STRING under the szOID_NTDS_OBJECTSID type-id.
        let names = GeneralNames::from_der(ext.extn_value.as_bytes()).unwrap();
        assert_eq!(names.len(), 1);
        match &names[0] {
            GeneralName::OtherName(other) => {
                assert_eq!(other.type_id, parse_oid(SID_OTHER_NAME_OID).unwrap());
                assert_eq!(other.value.tag(), Tag::OctetString);
                assert_eq!(other.value.value(), sid.as_bytes());
            }
            _ => panic!("expected an otherName GeneralName"),
        }
    }

    #[test]
    fn upn_validation_is_closed_by_default() {
        let closed = role(false, false);
        assert!(validate_upn(&closed, "felipe@example.com").is_err());

        let open = role(true, false);
        assert!(validate_upn(&open, "felipe@example.com").is_ok());
        assert!(validate_upn(&open, "felipe").is_err(), "no @ should fail");
        assert!(validate_upn(&open, "@example.com").is_err(), "empty local part should fail");
        assert!(validate_upn(&open, "felipe@").is_err(), "empty realm should fail");
        assert!(validate_upn(&open, "a@b@c").is_err(), "two @ should fail");
        assert!(validate_upn(&open, "fe lipe@example.com").is_err(), "whitespace should fail");
        assert!(validate_upn(&open, "").is_err());
    }

    #[test]
    fn upn_realm_allow_list_is_enforced_case_insensitively() {
        let mut r = role(true, false);
        r.allowed_upn_domains = vec!["example.com".into(), " Corp.Example.NET ".into()];
        assert!(validate_upn(&r, "felipe@example.com").is_ok());
        assert!(validate_upn(&r, "felipe@EXAMPLE.COM").is_ok());
        assert!(validate_upn(&r, "felipe@corp.example.net").is_ok());
        assert!(validate_upn(&r, "felipe@evil.example.com").is_err(), "subdomains are not implied");
        assert!(validate_upn(&r, "felipe@other.com").is_err());
    }

    #[test]
    fn sid_validation_is_closed_by_default() {
        let closed = role(false, false);
        assert!(validate_ad_sid(&closed, "S-1-5-21-1-2-3-512").is_err());
    }

    #[test]
    fn sid_validation_accepts_well_formed_and_rejects_junk() {
        let r = role(false, true);
        assert!(validate_ad_sid(&r, "S-1-5-21-1004336348-1177238915-682003330-512").is_ok());
        assert!(validate_ad_sid(&r, "S-1-5-18").is_ok(), "well-known SIDs are valid");
        assert!(validate_ad_sid(&r, "s-1-5-18").is_ok(), "lower-case S is tolerated");

        assert!(validate_ad_sid(&r, "S-2-5-18").is_err(), "revision must be 1");
        assert!(validate_ad_sid(&r, "X-1-5-18").is_err(), "must start with S");
        assert!(validate_ad_sid(&r, "S-1").is_err(), "needs an authority");
        assert!(validate_ad_sid(&r, "S-1-5-").is_err(), "trailing dash leaves an empty component");
        assert!(validate_ad_sid(&r, "S-1-5-abc").is_err(), "components must be numeric");
        assert!(
            validate_ad_sid(&r, "S-1-5-99999999999999999999999").is_err(),
            "components must fit a u64"
        );
        let too_long = format!("S-1-5{}", "-1".repeat(MAX_SID_LEN));
        assert!(validate_ad_sid(&r, &too_long).is_err(), "over-long SIDs are refused");
    }

    #[test]
    fn sid_normalisation_upper_cases_the_prefix() {
        assert_eq!(normalize_ad_sid("s-1-5-18"), "S-1-5-18");
        assert_eq!(normalize_ad_sid(" S-1-5-18 "), "S-1-5-18");
    }
}
