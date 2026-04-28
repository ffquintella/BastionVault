//! `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…`
//!
//! Reference: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>.
//!
//! Build/parse round-trip lets the engine accept either a fully
//! constructed URL (provider-mode `url` field) or the discrete
//! fields, then re-emit the URL for QR rendering.

use base32::Alphabet;
use url::Url;

use super::super::policy::{Algorithm, KeyPolicy, DEFAULT_DIGITS, DEFAULT_PERIOD};

/// RFC 4648 Base32 alphabet **without** padding. Authenticator apps
/// expect the unpadded form; padding `=` characters break some
/// scanners.
pub const B32: Alphabet = Alphabet::Rfc4648 { padding: false };

pub fn encode_secret(key: &[u8]) -> String {
    base32::encode(B32, key)
}

/// Decode a base32 secret. Tolerates whitespace and lowercase, and
/// accepts both padded and unpadded forms.
pub fn decode_secret(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| *c != '=')
        .collect();
    base32::decode(B32, &cleaned).ok_or_else(|| {
        "key is not valid base32 (RFC 4648 alphabet, padding optional)".to_string()
    })
}

pub fn build_url(p: &KeyPolicy) -> String {
    // Manual escape — `url::Url::path_segments_mut` won't let us
    // build a path that contains `:` literally without surprise
    // re-encoding, and the otpauth label is `Issuer:Account`.
    let label = if p.issuer.is_empty() {
        urlencode(&p.account_name)
    } else {
        format!("{}:{}", urlencode(&p.issuer), urlencode(&p.account_name))
    };

    let mut q = Vec::<(String, String)>::new();
    q.push(("secret".into(), encode_secret(&p.key)));
    if !p.issuer.is_empty() {
        q.push(("issuer".into(), p.issuer.clone()));
    }
    q.push(("algorithm".into(), p.algorithm.as_str().into()));
    q.push(("digits".into(), p.digits.to_string()));
    q.push(("period".into(), p.period.to_string()));

    let qs = q
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("otpauth://totp/{label}?{qs}")
}

/// Parse a caller-supplied `otpauth://totp/...` URL into a (partial)
/// policy. Caller-supplied policy fields take precedence on conflict;
/// this helper only fills what was missing.
pub fn parse_url(input: &str) -> Result<ParsedOtpAuth, String> {
    let url = Url::parse(input).map_err(|e| format!("invalid otpauth url: {e}"))?;
    if url.scheme() != "otpauth" {
        return Err(format!(
            "otpauth url scheme must be `otpauth`, got `{}`",
            url.scheme()
        ));
    }
    if url.host_str() != Some("totp") {
        return Err(format!(
            "otpauth url type must be `totp`, got `{}`",
            url.host_str().unwrap_or("<none>")
        ));
    }

    // Path: leading `/` then `Issuer:Account`. `url` returns it
    // percent-encoded; otpauth labels routinely contain `@` and `:`
    // which the encoder escapes, so we decode here.
    let label = url.path().trim_start_matches('/');
    let label = pct_decode(label)?;
    let (issuer_label, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.to_string()), a.to_string()),
        None => (None, label),
    };

    let mut secret: Option<String> = None;
    let mut issuer: Option<String> = issuer_label;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_PERIOD;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret = Some(v.into_owned()),
            // Vault and Google Authenticator both prefer the
            // explicit `issuer` query parameter when present —
            // overrides the path-label issuer if both are set.
            "issuer" => issuer = Some(v.into_owned()),
            "algorithm" => algorithm = Algorithm::parse(&v)?,
            "digits" => {
                digits = v
                    .parse::<u32>()
                    .map_err(|e| format!("digits: {e}"))?;
            }
            "period" => {
                period = v
                    .parse::<u64>()
                    .map_err(|e| format!("period: {e}"))?;
            }
            _ => {} // forward-compat: ignore unknown params
        }
    }

    let secret = secret.ok_or_else(|| "otpauth url missing `secret` parameter".to_string())?;
    let key = decode_secret(&secret)?;

    Ok(ParsedOtpAuth {
        key,
        issuer: issuer.unwrap_or_default(),
        account_name: account,
        algorithm,
        digits,
        period,
    })
}

#[derive(Debug, Clone)]
pub struct ParsedOtpAuth {
    pub key: Vec<u8>,
    pub issuer: String,
    pub account_name: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

/// Minimal RFC 3986 `pchar` percent-encoder for the bits we put into
/// otpauth URLs (label + query values). We don't pull in the
/// `percent-encoding` crate just for this — the set of characters we
/// need to escape is small.
fn pct_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("truncated percent escape".into());
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid percent escape".to_string())?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid percent escape".to_string())?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| format!("non-utf8 in label: {e}"))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b;
        let safe = c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::totp::policy::KeyPolicy;

    fn sample_policy() -> KeyPolicy {
        KeyPolicy {
            generate: true,
            key: b"12345678901234567890".to_vec(),
            issuer: "ACME Co".into(),
            account_name: "alice@example.com".into(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            skew: 1,
            replay_check: true,
            exported: false,
        }
    }

    #[test]
    fn round_trip_url() {
        let p = sample_policy();
        let url = build_url(&p);
        assert!(url.starts_with("otpauth://totp/"), "url: {url}");
        let back = parse_url(&url).unwrap();
        assert_eq!(back.key, p.key);
        assert_eq!(back.issuer, p.issuer);
        assert_eq!(back.account_name, p.account_name);
        assert_eq!(back.algorithm, p.algorithm);
        assert_eq!(back.digits, p.digits);
        assert_eq!(back.period, p.period);
    }

    #[test]
    fn decode_tolerates_lowercase_and_whitespace() {
        let want = b"12345678901234567890";
        let b32 = encode_secret(want);
        let dirty = format!(" {} {}", &b32[..6].to_ascii_lowercase(), &b32[6..]);
        let back = decode_secret(&dirty).unwrap();
        assert_eq!(back, want);
    }

    #[test]
    fn missing_secret_rejected() {
        let r = parse_url("otpauth://totp/Foo:bar?digits=6");
        assert!(r.is_err());
    }

    #[test]
    fn wrong_scheme_rejected() {
        let r = parse_url("https://totp/Foo:bar?secret=AAAA");
        assert!(r.is_err());
    }
}
