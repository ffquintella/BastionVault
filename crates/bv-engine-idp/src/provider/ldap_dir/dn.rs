//! Distinguished names, restricted to what this directory serves: plain
//! `type=value` RDNs without escapes, quotes or multi-valued RDNs. Types and
//! values are compared case-insensitively, so both are kept lower-case.

use std::fmt;

pub const MAX_DN_LEN: usize = 512;
pub const MAX_RDNS: usize = 16;
const MAX_TYPE_LEN: usize = 32;
const MAX_VALUE_LEN: usize = 64;

/// Leaf RDN first. The empty DN is the root DSE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dn {
    rdns: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnError;

fn valid_type(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= MAX_TYPE_LEN
        && t.as_bytes()[0].is_ascii_alphabetic()
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_VALUE_LEN
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
}

impl Dn {
    pub fn root() -> Self {
        Self { rdns: Vec::new() }
    }

    pub fn parse(s: &str) -> Result<Self, DnError> {
        if s.len() > MAX_DN_LEN {
            return Err(DnError);
        }
        if s.trim().is_empty() {
            return Ok(Self::root());
        }
        let mut rdns = Vec::new();
        for rdn in s.split(',') {
            let (t, v) = rdn.split_once('=').ok_or(DnError)?;
            let (t, v) = (t.trim(), v.trim());
            if !valid_type(t) || !valid_value(v) || rdns.len() == MAX_RDNS {
                return Err(DnError);
            }
            rdns.push((t.to_ascii_lowercase(), v.to_ascii_lowercase()));
        }
        Ok(Self { rdns })
    }

    pub fn is_root(&self) -> bool {
        self.rdns.is_empty()
    }

    pub fn rdn_count(&self) -> usize {
        self.rdns.len()
    }

    /// `type=value,<self>`. The caller passes values it has validated.
    pub fn child(&self, t: &str, v: &str) -> Self {
        let mut rdns = Vec::with_capacity(self.rdns.len() + 1);
        rdns.push((t.to_ascii_lowercase(), v.to_ascii_lowercase()));
        rdns.extend(self.rdns.iter().cloned());
        Self { rdns }
    }

    pub fn parent(&self) -> Option<Self> {
        (!self.rdns.is_empty()).then(|| Self { rdns: self.rdns[1..].to_vec() })
    }

    /// The leaf RDN, `(type, value)`.
    pub fn leaf(&self) -> Option<(&str, &str)> {
        self.rdns.first().map(|(t, v)| (t.as_str(), v.as_str()))
    }

    /// Whether `self` is `ancestor` or lies below it.
    pub fn within(&self, ancestor: &Dn) -> bool {
        self.rdns.len() >= ancestor.rdns.len() && self.rdns[self.rdns.len() - ancestor.rdns.len()..] == ancestor.rdns
    }
}

impl fmt::Display for Dn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (t, v)) in self.rdns.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{t}={v}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalises_and_refuses_what_it_does_not_serve() {
        let dn = Dn::parse(" UID = Alice , ou=People,DC=Example,dc=com").unwrap();
        assert_eq!(dn.to_string(), "uid=alice,ou=people,dc=example,dc=com");
        assert_eq!(dn.leaf(), Some(("uid", "alice")));
        let base = Dn::parse("dc=example,dc=com").unwrap();
        assert!(dn.within(&base) && base.within(&base) && !base.within(&dn));
        assert!(dn.within(&Dn::root()));
        assert_eq!(dn.parent().unwrap().parent().unwrap(), base);
        assert!(Dn::parse("").unwrap().is_root());
        for bad in [
            "uid=a\\,b,dc=x",
            "uid=\"a\",dc=x",
            "uid=a+cn=b,dc=x",
            "uid=,dc=x",
            "=a,dc=x",
            "uid=a,,dc=x",
            "1uid=a",
            "uid=a;dc=x",
            "uid=#0401",
            "cn=é",
        ] {
            assert_eq!(Dn::parse(bad), Err(DnError), "{bad}");
        }
        assert!(Dn::parse(&vec!["dc=a"; 16].join(",")).is_ok());
        assert_eq!(Dn::parse(&vec!["dc=a"; 17].join(",")), Err(DnError));
        assert_eq!(Dn::parse(&format!("dc={}", "a".repeat(65))), Err(DnError));
    }
}
