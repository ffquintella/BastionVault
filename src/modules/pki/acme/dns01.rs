//! DNS-01 challenge validator (RFC 8555 §8.4).
//!
//! Resolve `_acme-challenge.<domain>` TXT records and look for an
//! entry equal to `base64url(SHA-256(keyAuthorization))`. The
//! validator is engine-side and runs against the operator-pinned
//! resolvers from `acme/config.dns_resolvers` — falling back to the
//! system resolver only when that list is empty. Pinning matters
//! because a misbehaving system resolver shouldn't be the path that
//! decides whether to issue a cert.
//!
//! Runs DNS lookups synchronously by spinning up a single-threaded
//! tokio runtime on a fresh OS thread per call. That keeps the
//! handler usable under both `sync_handler` (no ambient tokio
//! runtime) and the default async build (where re-entering
//! `Runtime::new` would panic), at the cost of one thread spawn per
//! validation attempt — which is fine for this code path.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use sha2::{Digest, Sha256};

/// Validator entry point — feeds the same `(domain, expected)` pair
/// the HTTP-01 path uses, where `expected` is the keyAuthorization
/// (`<token>.<thumbprint>`). RFC 8555 §8.4 says the TXT record holds
/// `base64url(SHA-256(keyAuthorization))`, so we compute that and
/// scan the answer set.
pub fn dns01_validate(domain: &str, expected_key_auth: &str, resolvers: &[String]) -> Result<(), String> {
    if domain.is_empty() {
        return Err("empty domain".into());
    }
    let qname = format!("_acme-challenge.{domain}");
    let want = {
        let mut h = Sha256::new();
        h.update(expected_key_auth.as_bytes());
        B64.encode(h.finalize())
    };

    let answers = txt_lookup(&qname, resolvers)?;
    if answers.iter().any(|t| t.trim() == want) {
        Ok(())
    } else {
        Err(format!(
            "no matching TXT at `{qname}` (got {} record(s); wanted SHA-256 of keyAuthorization)",
            answers.len()
        ))
    }
}

/// Run a TXT lookup for `qname` against the supplied resolvers
/// (empty = system resolver). Returns the joined string per record.
fn txt_lookup(qname: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    let qname = qname.to_string();
    let resolvers: Vec<String> = resolvers.to_vec();
    // Spawn a fresh OS thread → fresh tokio runtime so we don't
    // depend on (or collide with) any ambient async runtime.
    let handle = std::thread::spawn(move || -> Result<Vec<String>, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("dns: tokio runtime build: {e}"))?;
        rt.block_on(async move { txt_lookup_async(&qname, &resolvers).await })
    });
    handle
        .join()
        .map_err(|_| "dns: lookup thread panicked".to_string())?
}

async fn txt_lookup_async(qname: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    let (config, mut opts) = if resolvers.is_empty() {
        // RFC says the validator must be the deciding resolver; the
        // system resolver is a fallback for ergonomic local testing.
        // Production operators should pin `dns_resolvers`.
        match hickory_resolver::system_conf::read_system_conf() {
            Ok((c, o)) => (c, o),
            Err(_) => (ResolverConfig::default(), ResolverOpts::default()),
        }
    } else {
        let mut group = NameServerConfigGroup::new();
        for r in resolvers {
            let sa = parse_resolver(r)
                .ok_or_else(|| format!("dns: invalid resolver `{r}`"))?;
            group.merge(NameServerConfigGroup::from_ips_clear(
                &[sa.ip()],
                sa.port(),
                true,
            ));
        }
        (
            ResolverConfig::from_parts(None, Vec::new(), group),
            ResolverOpts::default(),
        )
    };
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    let resolver = TokioAsyncResolver::tokio(config, opts);
    let lookup = resolver
        .txt_lookup(qname)
        .await
        .map_err(|e| format!("dns: txt lookup `{qname}`: {e}"))?;
    let mut out = Vec::new();
    for record in lookup.iter() {
        // A TXT record can be split across multiple character
        // strings; concatenate them per RFC 1035 §3.3.14 before
        // matching.
        let joined: String = record
            .iter()
            .filter_map(|seg| std::str::from_utf8(seg).ok())
            .collect::<Vec<_>>()
            .join("");
        out.push(joined);
    }
    Ok(out)
}

/// Accept either `1.2.3.4` (default port 53) or `1.2.3.4:5353` /
/// `[2001:db8::1]:53`.
fn parse_resolver(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Some(sa);
    }
    let ip = std::net::IpAddr::from_str(s).ok()?;
    Some(SocketAddr::new(ip, 53))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns01_expected_value_is_b64_sha256_of_keyauth() {
        // RFC 8555 §8.4 worked example fragment: the TXT must hold the
        // base64url-encoded SHA-256 of the keyAuthorization. We don't
        // hit the wire here — just confirm the encoding shape, since
        // that's what `dns01_validate` compares against.
        let key_auth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.thumbprintXYZ";
        let mut h = Sha256::new();
        h.update(key_auth.as_bytes());
        let want = B64.encode(h.finalize());
        // Sanity: the encoded value is the standard 43-char b64url-no-pad.
        assert_eq!(want.len(), 43);
        assert!(want.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn parse_resolver_accepts_ip_or_socket() {
        assert_eq!(
            parse_resolver("8.8.8.8").unwrap().port(),
            53
        );
        assert_eq!(
            parse_resolver("8.8.8.8:5353").unwrap().port(),
            5353
        );
        assert!(parse_resolver("not-an-ip").is_none());
    }
}
