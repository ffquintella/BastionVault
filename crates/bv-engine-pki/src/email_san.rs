//! `rfc822Name` subjectAltName entries — the identifier that binds a
//! certificate to a mailbox.
//!
//! RFC 8550 §3 requires an S/MIME certificate to carry the sender's email
//! address as an `rfc822Name` in `subjectAltName`. A CN holding the
//! address does not count, and neither does the deprecated `emailAddress`
//! DN attribute (RFC 5280 §4.1.2.6) — mail clients match the SAN or they
//! refuse to use the certificate.
//!
//! Before this module the engine had no email channel at all: `alt_names`
//! classified everything that was not an IP as a **dNSName**, so an
//! operator who typed `felipe@example.com` there got a `dNSName` with an
//! `@` in it — plausible-looking, and useless. An `rfc822Name` sitting in
//! a caller-supplied CSR was dropped on the floor without a word.
//!
//! Both are fixed here, and the policy is deliberately the same shape as
//! [`super::ad_ext`]'s UPN handling:
//!
//! - **Closed by default.** A role must set `allow_email_sans`. An
//!   organisation-trusted CA that will emit any `rfc822Name` on request
//!   lets anyone with issue rights mint a signing certificate for anyone
//!   else's mailbox.
//! - **Narrowable.** `allowed_email_domains` restricts the part after the
//!   `@`, matched case-insensitively and **exactly** — `example.com` does
//!   not admit `evil.example.com`, because mail routing does not treat a
//!   subdomain as its parent.
//! - **Refuse, never drop.** A requested address the role will not permit
//!   is an error, not an omission.
//!
//! One module holds both encoders — [`rcgen_rfc822_san`] for the classical
//! rcgen path and [`rfc822_general_name`] for the hand-rolled DER paths
//! (ML-DSA / composite) — so the two cannot drift apart.

use x509_cert::{der::asn1::Ia5String, ext::pkix::name::GeneralName};

use super::path_roles::RoleEntry;
use crate::errors::RvError;

/// Maximum accepted address length: RFC 5321 §4.5.3.1's maximum forward
/// path (256 octets including the enclosing `<>`), i.e. 254 characters of
/// address. Bounds how much a hostile `email_sans` can add to every
/// certificate a role issues.
const MAX_EMAIL_LEN: usize = 254;

/// Validate one address against the role's policy.
///
/// Structural rules: ASCII only, exactly one `@`, both halves non-empty,
/// no whitespace or control characters, within [`MAX_EMAIL_LEN`]. Policy
/// rule: when the role sets `allowed_email_domains`, the domain must
/// appear on that list. An empty list with `allow_email_sans = true`
/// accepts any domain — the "empty means unconstrained" convention
/// `allowed_upn_domains` and `allowed_key_refs` already use.
///
/// This is deliberately *not* a full RFC 5322 address grammar. A CA has no
/// business adjudicating quoted local parts; what it must guarantee is
/// that the value is encodable as an `IA5String`, unambiguous about which
/// domain it belongs to, and attributable to exactly one mailbox.
pub fn validate_email(role: &RoleEntry, addr: &str) -> Result<(), RvError> {
    if !role.allow_email_sans {
        return Err(RvError::ErrString(
            "email_sans: this role does not permit rfc822Name SANs (set allow_email_sans=true on the role)"
                .into(),
        ));
    }
    if addr.is_empty() {
        return Err(RvError::ErrString("email_sans: empty address".into()));
    }
    if addr.len() > MAX_EMAIL_LEN {
        return Err(RvError::ErrString(format!(
            "email_sans: address exceeds the maximum length of {MAX_EMAIL_LEN} characters"
        )));
    }
    // `rfc822Name` is an IA5String — there is no legal encoding for a
    // non-ASCII local part or a U-label domain. Say so rather than
    // emitting mojibake or a punycode guess the operator did not ask for.
    if !addr.is_ascii() {
        return Err(RvError::ErrString(format!(
            "email_sans: `{addr}` contains non-ASCII characters; rfc822Name is an IA5String, so an internationalised domain must be supplied in its A-label (xn--…) form"
        )));
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RvError::ErrString(format!(
            "email_sans: `{addr}` contains whitespace or control characters"
        )));
    }

    let mut parts = addr.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        return Err(RvError::ErrString(format!(
            "email_sans: `{addr}` is not a valid address (expected exactly one `@`, e.g. user@example.com)"
        )));
    }

    if role.allowed_email_domains.is_empty() {
        return Ok(());
    }
    let candidate = domain.to_ascii_lowercase();
    let permitted = role
        .allowed_email_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .any(|d| !d.is_empty() && d == candidate);
    if permitted {
        Ok(())
    } else {
        Err(RvError::ErrString(format!(
            "email_sans: domain `{domain}` is not in the role's allowed_email_domains"
        )))
    }
}

/// Split a comma-separated `email_sans` value, validate every entry
/// against the role, and de-duplicate.
///
/// De-duplication is case-*sensitive* on purpose: the local part of an
/// address is case-sensitive per RFC 5321 §2.3.11, so `Felipe@x` and
/// `felipe@x` are — formally — different mailboxes. We do not fold them
/// together, and we do not rewrite what the caller asked for.
pub fn resolve_email_sans(role: &RoleEntry, raw: &str) -> Result<Vec<String>, RvError> {
    let mut out: Vec<String> = Vec::new();
    for candidate in raw.split(',') {
        let addr = candidate.trim();
        if addr.is_empty() {
            continue;
        }
        validate_email(role, addr)?;
        if !out.iter().any(|existing| existing == addr) {
            out.push(addr.to_string());
        }
    }
    Ok(out)
}

/// Validate an already-split list (the CSR-supplied case, where the
/// addresses arrive as parsed `GeneralName`s rather than a comma string).
/// De-duplicates identically to [`resolve_email_sans`].
pub fn validate_email_list(role: &RoleEntry, addrs: &[String]) -> Result<Vec<String>, RvError> {
    let mut out: Vec<String> = Vec::new();
    for addr in addrs {
        let addr = addr.trim();
        if addr.is_empty() {
            continue;
        }
        validate_email(role, addr)?;
        if !out.iter().any(|existing| existing == addr) {
            out.push(addr.to_string());
        }
    }
    Ok(out)
}

/// The `rfc822Name` `GeneralName` for the hand-rolled DER paths (ML-DSA /
/// composite).
pub fn rfc822_general_name(addr: &str) -> Result<GeneralName, RvError> {
    let ia5 = Ia5String::new(addr).map_err(|e| {
        RvError::ErrString(format!("email_sans: cannot encode `{addr}` as an IA5String ({e})"))
    })?;
    Ok(GeneralName::Rfc822Name(ia5))
}

/// The `rfc822Name` SAN entry for the classical (rcgen) path.
pub fn rcgen_rfc822_san(addr: &str) -> Result<rcgen::SanType, RvError> {
    let ia5 = rcgen::string::Ia5String::try_from(addr).map_err(|e| {
        RvError::ErrString(format!("email_sans: cannot encode `{addr}` as an IA5String ({e})"))
    })?;
    Ok(rcgen::SanType::Rfc822Name(ia5))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{Decode, Encode};

    fn role(allow: bool) -> RoleEntry {
        RoleEntry { allow_email_sans: allow, ..Default::default() }
    }

    #[test]
    fn closed_by_default() {
        assert!(validate_email(&RoleEntry::default(), "felipe@example.com").is_err());
        assert!(validate_email(&role(false), "felipe@example.com").is_err());
        assert!(validate_email(&role(true), "felipe@example.com").is_ok());
    }

    #[test]
    fn rejects_structurally_bad_addresses() {
        let r = role(true);
        assert!(validate_email(&r, "").is_err(), "empty");
        assert!(validate_email(&r, "felipe").is_err(), "no @");
        assert!(validate_email(&r, "@example.com").is_err(), "empty local part");
        assert!(validate_email(&r, "felipe@").is_err(), "empty domain");
        assert!(validate_email(&r, "a@b@c").is_err(), "two @");
        assert!(validate_email(&r, "fe lipe@example.com").is_err(), "whitespace");
        assert!(validate_email(&r, "felipe\t@example.com").is_err(), "tab");
        assert!(validate_email(&r, "felipe\n@example.com").is_err(), "newline");
        assert!(validate_email(&r, "felipe\u{0}@example.com").is_err(), "NUL");
    }

    #[test]
    fn rejects_non_ascii_rather_than_mangling_it() {
        let r = role(true);
        // An IA5String cannot hold either of these. Emitting a
        // best-effort encoding would produce a certificate that does not
        // say what the operator asked for.
        assert!(validate_email(&r, "josé@example.com").is_err(), "non-ASCII local part");
        assert!(validate_email(&r, "felipe@exâmple.com").is_err(), "U-label domain");
        // The A-label form is accepted.
        assert!(validate_email(&r, "felipe@xn--exmple-cua.com").is_ok());
    }

    #[test]
    fn rejects_over_long_addresses() {
        let r = role(true);
        let long_local = "a".repeat(MAX_EMAIL_LEN);
        assert!(validate_email(&r, &format!("{long_local}@example.com")).is_err());
        let at_limit = format!("{}@example.com", "a".repeat(MAX_EMAIL_LEN - "@example.com".len()));
        assert_eq!(at_limit.len(), MAX_EMAIL_LEN);
        assert!(validate_email(&r, &at_limit).is_ok(), "exactly at the limit is fine");
    }

    #[test]
    fn domain_allow_list_is_case_insensitive_and_exact() {
        let mut r = role(true);
        r.allowed_email_domains = vec!["fgv.br".into(), " Example.COM ".into()];
        assert!(validate_email(&r, "felipe@fgv.br").is_ok());
        assert!(validate_email(&r, "felipe@FGV.BR").is_ok());
        assert!(validate_email(&r, "felipe@example.com").is_ok());
        assert!(
            validate_email(&r, "felipe@evil.fgv.br").is_err(),
            "subdomains are not implied by a parent domain on the allow-list"
        );
        assert!(validate_email(&r, "felipe@other.com").is_err());
        // An empty entry must not act as a wildcard.
        r.allowed_email_domains = vec!["".into(), "  ".into()];
        assert!(validate_email(&r, "felipe@fgv.br").is_err());
    }

    #[test]
    fn resolve_splits_trims_and_dedups() {
        let r = role(true);
        let out = resolve_email_sans(&r, " a@x.com , b@x.com ,, a@x.com ").unwrap();
        assert_eq!(out, vec!["a@x.com".to_string(), "b@x.com".to_string()]);
        assert!(resolve_email_sans(&r, "").unwrap().is_empty());
        assert!(resolve_email_sans(&r, " , ").unwrap().is_empty());
        // Case differences in the local part are distinct mailboxes and
        // must not be folded together.
        let cased = resolve_email_sans(&r, "A@x.com,a@x.com").unwrap();
        assert_eq!(cased.len(), 2);
    }

    #[test]
    fn resolve_refuses_the_whole_request_on_one_bad_entry() {
        let r = role(true);
        // Partial success would emit a certificate missing an address the
        // caller asked for — the silent-drop failure this feature exists
        // to remove.
        assert!(resolve_email_sans(&r, "good@x.com,bad").is_err());
    }

    #[test]
    fn validate_list_matches_resolve_semantics() {
        let r = role(true);
        let out =
            validate_email_list(&r, &["a@x.com".into(), " b@x.com ".into(), "a@x.com".into()])
                .unwrap();
        assert_eq!(out, vec!["a@x.com".to_string(), "b@x.com".to_string()]);
        assert!(validate_email_list(&role(false), &["a@x.com".into()]).is_err());
    }

    #[test]
    fn der_encoder_round_trips_as_rfc822_name() {
        let gn = rfc822_general_name("felipe@example.com").unwrap();
        let der = gn.to_der().unwrap();
        // Context tag [1] is rfc822Name in the GeneralName CHOICE. Assert
        // the tag byte directly: getting the tag wrong is exactly the bug
        // that would make a mail client ignore the entry.
        assert_eq!(der[0], 0x81, "rfc822Name must be context-specific tag 1");
        match GeneralName::from_der(&der).unwrap() {
            GeneralName::Rfc822Name(ia5) => assert_eq!(ia5.as_str(), "felipe@example.com"),
            other => panic!("expected an rfc822Name GeneralName, got {other:?}"),
        }
    }

    #[test]
    fn rcgen_encoder_accepts_the_same_input() {
        let san = rcgen_rfc822_san("felipe@example.com").unwrap();
        match san {
            rcgen::SanType::Rfc822Name(ia5) => assert_eq!(ia5.as_str(), "felipe@example.com"),
            other => panic!("expected an Rfc822Name SanType, got {other:?}"),
        }
        // Both encoders reject what validation would have rejected, so a
        // caller that skipped validation still cannot emit junk.
        assert!(rcgen_rfc822_san("josé@example.com").is_err());
        assert!(rfc822_general_name("josé@example.com").is_err());
    }
}
