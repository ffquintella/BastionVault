//! Search filters (RFC 4511 §4.5.1.7), decoded under a depth and node
//! budget and evaluated in three-valued logic against the entries this
//! directory builds. Strings match ASCII case-insensitively, uidNumber and
//! gidNumber numerically; there is no regular expression and no
//! client-chosen matching rule (extensible match is Undefined).

use super::{
    ber::{self, BerError, Reader},
    directory::{is_integer_attribute, is_known_attribute, Entry},
};

pub const MAX_FILTER_DEPTH: usize = 16;
pub const MAX_FILTER_NODES: usize = 128;
pub const MAX_SUBSTRING_PARTS: usize = 8;
pub const MAX_ASSERTION_LEN: usize = 256;
const MAX_ATTRIBUTE_LEN: usize = 64;

pub mod tag {
    pub const AND: u8 = 0xa0;
    pub const OR: u8 = 0xa1;
    pub const NOT: u8 = 0xa2;
    pub const EQUALITY: u8 = 0xa3;
    pub const SUBSTRINGS: u8 = 0xa4;
    pub const GREATER_OR_EQUAL: u8 = 0xa5;
    pub const LESS_OR_EQUAL: u8 = 0xa6;
    pub const PRESENT: u8 = 0x87;
    pub const APPROX: u8 = 0xa8;
    pub const EXTENSIBLE: u8 = 0xa9;
    pub const SUB_INITIAL: u8 = 0x80;
    pub const SUB_ANY: u8 = 0x81;
    pub const SUB_FINAL: u8 = 0x82;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Substrings {
    pub initial: Option<Vec<u8>>,
    pub any: Vec<Vec<u8>>,
    pub last: Option<Vec<u8>>,
}

/// Attribute names are kept lower-case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equality(String, Vec<u8>),
    Substrings(String, Substrings),
    GreaterOrEqual(String, Vec<u8>),
    LessOrEqual(String, Vec<u8>),
    Present(String),
    Approx(String, Vec<u8>),
    /// Recognised and bounded, never evaluated (Undefined).
    Extensible,
}

fn attribute(content: &[u8]) -> Result<String, BerError> {
    let s = ber::utf8(content, MAX_ATTRIBUTE_LEN)?;
    let ok = !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b';' | b'.'));
    if !ok {
        return Err(BerError::BadString);
    }
    Ok(s.to_ascii_lowercase())
}

fn assertion(content: &[u8]) -> Result<Vec<u8>, BerError> {
    if content.len() > MAX_ASSERTION_LEN {
        return Err(BerError::TooLarge);
    }
    Ok(content.to_vec())
}

fn ava(content: &[u8]) -> Result<(String, Vec<u8>), BerError> {
    let mut r = Reader::new(content);
    let attr = attribute(r.expect(0x04)?)?;
    let value = assertion(r.expect(0x04)?)?;
    r.finish()?;
    Ok((attr, value))
}

impl Filter {
    /// Decode the filter element `(tag, content)`.
    pub fn decode(tag: u8, content: &[u8]) -> Result<Self, BerError> {
        let mut budget = MAX_FILTER_NODES;
        Self::decode_at(tag, content, 1, &mut budget)
    }

    fn decode_at(tag: u8, content: &[u8], depth: usize, budget: &mut usize) -> Result<Self, BerError> {
        if depth > MAX_FILTER_DEPTH {
            return Err(BerError::TooDeep);
        }
        if *budget == 0 {
            return Err(BerError::TooMany);
        }
        *budget -= 1;
        match tag {
            tag::AND | tag::OR => {
                let mut r = Reader::new(content);
                let mut items = Vec::new();
                while !r.is_empty() {
                    let (t, c) = r.any()?;
                    items.push(Self::decode_at(t, c, depth + 1, budget)?);
                }
                Ok(if tag == tag::AND { Self::And(items) } else { Self::Or(items) })
            }
            tag::NOT => {
                let mut r = Reader::new(content);
                let (t, c) = r.any()?;
                r.finish()?;
                Ok(Self::Not(Box::new(Self::decode_at(t, c, depth + 1, budget)?)))
            }
            tag::EQUALITY => ava(content).map(|(a, v)| Self::Equality(a, v)),
            tag::GREATER_OR_EQUAL => ava(content).map(|(a, v)| Self::GreaterOrEqual(a, v)),
            tag::LESS_OR_EQUAL => ava(content).map(|(a, v)| Self::LessOrEqual(a, v)),
            tag::APPROX => ava(content).map(|(a, v)| Self::Approx(a, v)),
            tag::PRESENT => Ok(Self::Present(attribute(content)?)),
            tag::SUBSTRINGS => {
                let mut r = Reader::new(content);
                let attr = attribute(r.expect(0x04)?)?;
                let mut parts = Reader::new(r.expect(0x30)?);
                r.finish()?;
                let mut s = Substrings::default();
                let mut count = 0;
                while !parts.is_empty() {
                    count += 1;
                    if count > MAX_SUBSTRING_PARTS {
                        return Err(BerError::TooMany);
                    }
                    let (t, c) = parts.any()?;
                    let value = assertion(c)?;
                    match t {
                        tag::SUB_INITIAL if count == 1 => s.initial = Some(value),
                        tag::SUB_ANY if s.last.is_none() => s.any.push(value),
                        tag::SUB_FINAL if s.last.is_none() => s.last = Some(value),
                        _ => return Err(BerError::UnexpectedTag),
                    }
                }
                if count == 0 {
                    return Err(BerError::Truncated);
                }
                Ok(Self::Substrings(attr, s))
            }
            tag::EXTENSIBLE => {
                let mut r = Reader::new(content);
                while !r.is_empty() {
                    let (t, c) = r.any()?;
                    if !matches!(t, 0x81..=0x84) || c.len() > MAX_ASSERTION_LEN {
                        return Err(BerError::UnexpectedTag);
                    }
                }
                Ok(Self::Extensible)
            }
            _ => Err(BerError::UnexpectedTag),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let ava = |out: &mut Vec<u8>, t: u8, a: &str, v: &[u8]| {
            ber::nest(out, t, |o| {
                ber::put(o, 0x04, a.as_bytes());
                ber::put(o, 0x04, v);
            })
        };
        match self {
            Self::And(items) | Self::Or(items) => {
                let t = if matches!(self, Self::And(_)) { tag::AND } else { tag::OR };
                ber::nest(out, t, |o| items.iter().for_each(|f| f.encode(o)));
            }
            Self::Not(inner) => ber::nest(out, tag::NOT, |o| inner.encode(o)),
            Self::Equality(a, v) => ava(out, tag::EQUALITY, a, v),
            Self::GreaterOrEqual(a, v) => ava(out, tag::GREATER_OR_EQUAL, a, v),
            Self::LessOrEqual(a, v) => ava(out, tag::LESS_OR_EQUAL, a, v),
            Self::Approx(a, v) => ava(out, tag::APPROX, a, v),
            Self::Present(a) => ber::put(out, tag::PRESENT, a.as_bytes()),
            Self::Substrings(a, s) => ber::nest(out, tag::SUBSTRINGS, |o| {
                ber::put(o, 0x04, a.as_bytes());
                ber::nest(o, 0x30, |p| {
                    if let Some(i) = &s.initial {
                        ber::put(p, tag::SUB_INITIAL, i);
                    }
                    for any in &s.any {
                        ber::put(p, tag::SUB_ANY, any);
                    }
                    if let Some(f) = &s.last {
                        ber::put(p, tag::SUB_FINAL, f);
                    }
                });
            }),
            Self::Extensible => ber::nest(out, tag::EXTENSIBLE, |o| ber::put(o, 0x83, b"")),
        }
    }

    pub fn eq(attr: &str, value: &str) -> Self {
        Self::Equality(attr.to_ascii_lowercase(), value.as_bytes().to_vec())
    }

    pub fn present(attr: &str) -> Self {
        Self::Present(attr.to_ascii_lowercase())
    }

    /// The login every match must carry when the filter is, or is a
    /// conjunction containing, an equality on `uid`: only person entries
    /// have `uid`, so only that person can match.
    pub fn uid_hint(&self) -> Option<&[u8]> {
        fn uid(f: &Filter) -> Option<&[u8]> {
            match f {
                Filter::Equality(a, v) if a == "uid" => Some(v.as_slice()),
                _ => None,
            }
        }
        match self {
            Self::And(items) => items.iter().find_map(uid),
            other => uid(other),
        }
    }

    /// `Some(true)` matches; `Some(false)` and `None` (Undefined) do not.
    pub fn evaluate(&self, e: &Entry) -> Option<bool> {
        match self {
            Self::And(items) => {
                let mut undefined = false;
                for f in items {
                    match f.evaluate(e) {
                        Some(false) => return Some(false),
                        None => undefined = true,
                        Some(true) => {}
                    }
                }
                (!undefined).then_some(true)
            }
            Self::Or(items) => {
                let mut undefined = false;
                for f in items {
                    match f.evaluate(e) {
                        Some(true) => return Some(true),
                        None => undefined = true,
                        Some(false) => {}
                    }
                }
                (!undefined).then_some(false)
            }
            Self::Not(inner) => inner.evaluate(e).map(|b| !b),
            Self::Equality(a, v) | Self::Approx(a, v) => compare(e, a, v, |o| o == std::cmp::Ordering::Equal),
            Self::GreaterOrEqual(a, v) => ordered(e, a, v, |o| o != std::cmp::Ordering::Less),
            Self::LessOrEqual(a, v) => ordered(e, a, v, |o| o != std::cmp::Ordering::Greater),
            Self::Present(a) => Some(e.values(a).is_some_and(|v| !v.is_empty())),
            Self::Substrings(a, s) => {
                if !is_known_attribute(a) || is_integer_attribute(a) || a == "objectclass" {
                    return None;
                }
                let parts = lower_parts(s)?;
                let values = e.values(a).unwrap_or(&[]);
                Some(values.iter().any(|v| substring_match(&v.to_ascii_lowercase(), &parts)))
            }
            Self::Extensible => None,
        }
    }
}

/// Equality (and approximate match, treated as equality).
fn compare(e: &Entry, attr: &str, value: &[u8], ok: impl Fn(std::cmp::Ordering) -> bool) -> Option<bool> {
    if !is_known_attribute(attr) {
        return None;
    }
    let value = std::str::from_utf8(value).ok()?;
    let values = e.values(attr).unwrap_or(&[]);
    if is_integer_attribute(attr) {
        let n: i64 = value.trim().parse().ok()?;
        return Some(values.iter().filter_map(|v| v.parse::<i64>().ok()).any(|v| ok(v.cmp(&n))));
    }
    Some(values.iter().any(|v| ok(v.to_ascii_lowercase().cmp(&value.to_ascii_lowercase()))))
}

/// Ordering matches: numeric, or case-insensitive lexical; objectClass has
/// no ordering rule.
fn ordered(e: &Entry, attr: &str, value: &[u8], ok: impl Fn(std::cmp::Ordering) -> bool) -> Option<bool> {
    if attr == "objectclass" {
        return None;
    }
    compare(e, attr, value, ok)
}

struct LowerParts {
    initial: Option<String>,
    any: Vec<String>,
    last: Option<String>,
}

fn lower_parts(s: &Substrings) -> Option<LowerParts> {
    let lower = |b: &Vec<u8>| std::str::from_utf8(b).ok().map(|s| s.to_ascii_lowercase());
    let initial = match &s.initial {
        Some(b) => Some(lower(b)?),
        None => None,
    };
    let last = match &s.last {
        Some(b) => Some(lower(b)?),
        None => None,
    };
    Some(LowerParts { initial, any: s.any.iter().map(lower).collect::<Option<Vec<_>>>()?, last })
}

/// Linear in the value per part; parts do not overlap.
fn substring_match(value: &str, p: &LowerParts) -> bool {
    let mut rest = value;
    if let Some(i) = &p.initial {
        match rest.strip_prefix(i.as_str()) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    for a in &p.any {
        match rest.find(a.as_str()) {
            Some(at) => rest = &rest[at + a.len()..],
            None => return false,
        }
    }
    match &p.last {
        Some(f) => rest.ends_with(f.as_str()),
        None => true,
    }
}
