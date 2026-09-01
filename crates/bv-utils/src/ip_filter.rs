//! Source-IP filters that accept a *mixed* list of address forms.
//!
//! [`super::cidr`] is a replica of Vault's CIDR helper and understands CIDR
//! blocks only. Operators writing an allow-list for an application usually have
//! a mix on their hands — one jump host, one subnet, one DHCP range — so this
//! module accepts, per entry:
//!
//! | form | example |
//! |---|---|
//! | single address | `10.0.0.5`, `2001:db8::1` |
//! | CIDR block | `10.0.0.0/24`, `2001:db8::/64` |
//! | address + dotted netmask (IPv4) | `10.0.0.0/255.255.255.0` |
//! | inclusive range | `10.0.0.5-10.0.0.50`, `2001:db8::1-2001:db8::ff` |
//!
//! An entry is parsed once, on write, so a malformed rule is rejected at
//! configuration time rather than silently never matching at login time. The
//! match itself fails closed: an unparsable client address or rule is an error,
//! never a match.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use ipnetwork::IpNetwork;

use bv_errors::RvError;

/// One parsed entry of a source-IP filter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceIpRule {
    /// A single address, a CIDR block, or an address + dotted netmask. A bare
    /// address parses as a host network (`/32` or `/128`).
    Network(IpNetwork),

    /// An inclusive `start-end` range. Both ends are the same address family
    /// and `start <= end`.
    Range { start: IpAddr, end: IpAddr },
}

impl SourceIpRule {
    /// Parse a single filter entry. Surrounding whitespace is ignored.
    pub fn parse(entry: &str) -> Result<Self, RvError> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(RvError::ErrResponse("empty source IP filter entry".to_string()));
        }

        // A range is the only form containing '-' outside an IPv6 literal, and
        // IPv6 literals never contain '-'.
        if let Some((start_str, end_str)) = entry.split_once('-') {
            let start = IpAddr::from_str(start_str.trim()).map_err(|e| {
                RvError::ErrResponse(format!("invalid start address in source IP range {entry:?}: {e}"))
            })?;
            let end = IpAddr::from_str(end_str.trim())
                .map_err(|e| RvError::ErrResponse(format!("invalid end address in source IP range {entry:?}: {e}")))?;

            match (start, end) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
                _ => {
                    return Err(RvError::ErrResponse(format!(
                        "source IP range {entry:?} mixes IPv4 and IPv6 addresses"
                    )))
                }
            }

            if !addr_le(&start, &end) {
                return Err(RvError::ErrResponse(format!(
                    "source IP range {entry:?} is inverted: start address is above the end address"
                )));
            }

            return Ok(SourceIpRule::Range { start, end });
        }

        // `IpNetwork` covers the remaining three forms: a bare address becomes a
        // host network, and a `/`-suffix is read as either a prefix length or a
        // dotted IPv4 netmask.
        let network = IpNetwork::from_str(entry)
            .map_err(|e| RvError::ErrResponse(format!("invalid source IP filter entry {entry:?}: {e}")))?;

        Ok(SourceIpRule::Network(network))
    }

    /// Does this rule cover `ip`?
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            SourceIpRule::Network(net) => net.contains(*ip),
            SourceIpRule::Range { start, end } => addr_le(start, ip) && addr_le(ip, end),
        }
    }
}

/// Parse every entry, failing on the first malformed one.
pub fn parse_rules<S: AsRef<str>>(entries: &[S]) -> Result<Vec<SourceIpRule>, RvError> {
    entries.iter().map(|e| SourceIpRule::parse(e.as_ref())).collect()
}

/// Validate a filter list without keeping the parsed rules. Use on the write
/// path so an operator learns about a typo immediately.
pub fn validate_entries<S: AsRef<str>>(entries: &[S]) -> Result<(), RvError> {
    parse_rules(entries).map(|_| ())
}

/// Does `ip_addr` match at least one entry? An empty list matches nothing —
/// callers treat "no filter configured" as "no restriction" before calling.
pub fn ip_matches_any<S: AsRef<str>>(ip_addr: &str, entries: &[S]) -> Result<bool, RvError> {
    if ip_addr.is_empty() {
        return Err(RvError::ErrResponse("missing IP address".to_string()));
    }

    let ip = IpAddr::from_str(ip_addr.trim())
        .map_err(|e| RvError::ErrResponse(format!("invalid source IP address {ip_addr:?}: {e}")))?;

    for entry in entries.iter() {
        if SourceIpRule::parse(entry.as_ref())?.contains(&ip) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Family-aware `<=` on addresses. Mixed families never compare equal-or-less,
/// so a rule of one family can never match an address of the other.
fn addr_le(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(*a) <= u32::from(*b),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(*a) <= u128::from(*b),
        _ => false,
    }
}

/// The lowest address a rule covers, for display and ordering.
pub fn rule_start(rule: &SourceIpRule) -> IpAddr {
    match rule {
        SourceIpRule::Network(net) => match net {
            IpNetwork::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4.network()))),
            IpNetwork::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6.network()))),
        },
        SourceIpRule::Range { start, .. } => *start,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_single_address() {
        let rule = SourceIpRule::parse("10.0.0.5").unwrap();
        assert!(rule.contains(&"10.0.0.5".parse().unwrap()));
        assert!(!rule.contains(&"10.0.0.6".parse().unwrap()));

        let rule = SourceIpRule::parse("2001:db8::1").unwrap();
        assert!(rule.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!rule.contains(&"2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr_and_netmask() {
        let cidr = SourceIpRule::parse("10.0.0.0/24").unwrap();
        let netmask = SourceIpRule::parse("10.0.0.0/255.255.255.0").unwrap();
        assert_eq!(cidr, netmask, "dotted netmask is the same network as the prefix form");

        assert!(cidr.contains(&"10.0.0.200".parse().unwrap()));
        assert!(!cidr.contains(&"10.0.1.1".parse().unwrap()));

        let v6 = SourceIpRule::parse("2001:db8::/64").unwrap();
        assert!(v6.contains(&"2001:db8::dead:beef".parse().unwrap()));
        assert!(!v6.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_range() {
        let rule = SourceIpRule::parse("10.0.0.5-10.0.0.50").unwrap();
        assert!(rule.contains(&"10.0.0.5".parse().unwrap()), "start is inclusive");
        assert!(rule.contains(&"10.0.0.50".parse().unwrap()), "end is inclusive");
        assert!(rule.contains(&"10.0.0.20".parse().unwrap()));
        assert!(!rule.contains(&"10.0.0.4".parse().unwrap()));
        assert!(!rule.contains(&"10.0.0.51".parse().unwrap()));

        // Ranges may cross an octet boundary.
        let rule = SourceIpRule::parse("10.0.0.250 - 10.0.1.5").unwrap();
        assert!(rule.contains(&"10.0.1.0".parse().unwrap()));
        assert!(!rule.contains(&"10.0.1.6".parse().unwrap()));

        let rule = SourceIpRule::parse("2001:db8::1-2001:db8::ff").unwrap();
        assert!(rule.contains(&"2001:db8::80".parse().unwrap()));
        assert!(!rule.contains(&"2001:db8::100".parse().unwrap()));
    }

    #[test]
    fn test_rejects_malformed_entries() {
        for bad in [
            "",
            "   ",
            "not-an-ip",
            "10.0.0.999",
            "10.0.0.0/33",
            "10.0.0.50-10.0.0.5",     // inverted
            "10.0.0.1-2001:db8::1",   // mixed family
            "10.0.0.1-",              // missing end
            "10.0.0.0/24/8",          // two slashes
        ] {
            assert!(SourceIpRule::parse(bad).is_err(), "entry {bad:?} must be rejected");
        }
    }

    #[test]
    fn test_ip_matches_any_mixed_list() {
        let entries =
            vec!["10.0.0.5".to_string(), "192.168.1.0/24".to_string(), "172.16.4.10-172.16.4.20".to_string()];

        assert!(ip_matches_any("10.0.0.5", &entries).unwrap());
        assert!(ip_matches_any("192.168.1.77", &entries).unwrap());
        assert!(ip_matches_any("172.16.4.15", &entries).unwrap());

        assert!(!ip_matches_any("10.0.0.6", &entries).unwrap());
        assert!(!ip_matches_any("192.168.2.1", &entries).unwrap());
        assert!(!ip_matches_any("172.16.4.21", &entries).unwrap());

        // Fails closed rather than matching.
        assert!(ip_matches_any("", &entries).is_err());
        assert!(ip_matches_any("bogus", &entries).is_err());
        assert!(ip_matches_any("10.0.0.5", &["10.0.0.0/bogus".to_string()]).is_err());

        // An IPv4 client never matches an IPv6 rule and vice versa.
        assert!(!ip_matches_any("10.0.0.5", &["2001:db8::/32".to_string()]).unwrap());
        assert!(!ip_matches_any("2001:db8::1", &["10.0.0.0/8".to_string()]).unwrap());
    }

    #[test]
    fn test_validate_entries() {
        assert!(validate_entries(&["10.0.0.1".to_string(), "10.0.0.0/8".to_string()]).is_ok());
        assert!(validate_entries(&["10.0.0.1".to_string(), "oops".to_string()]).is_err());
    }
}
