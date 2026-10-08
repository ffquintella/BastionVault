//! Segment-wildcard path matching.

/// One `/`-separated path segment. The host implements it for `&str`; the
/// proofs for an abstract alphabet. The matcher observes a segment only
/// through these four questions.
pub trait Segment {
    /// The segment is the single-segment wildcard `+`. Only meaningful in a
    /// rule path; in a request path `+` is an ordinary segment.
    fn is_wildcard(&self) -> bool;
    /// The segment is empty (a trailing `/`, or `//`).
    fn is_empty(&self) -> bool;
    /// The two segments are the same string.
    fn equals(&self, other: &Self) -> bool;
    /// This segment starts with `prefix`.
    fn starts_with(&self, prefix: &Self) -> bool;
}

impl Segment for &str {
    fn is_wildcard(&self) -> bool {
        *self == "+"
    }

    fn is_empty(&self) -> bool {
        str::is_empty(self)
    }

    fn equals(&self, other: &Self) -> bool {
        *self == *other
    }

    fn starts_with(&self, prefix: &Self) -> bool {
        str::starts_with(self, *prefix)
    }
}

/// Does a segment-wildcard rule match `path`? Returns the number of `+`
/// segments in the rule when it does.
///
/// `rule` and `path` are the `/`-split segments; `is_prefix` says the rule
/// ended in `*` (stripped by the caller). The rules:
///
/// - a non-prefix rule matches only a path with as many segments;
/// - a prefix rule matches a path with at least as many segments, and its
///   last segment only needs to be a string prefix of the path's segment;
/// - `+` matches exactly one *non-empty* segment, so a rule written for a
///   named child (`targets/+`) never matches the collection's LIST path
///   (`targets/`);
/// - every other segment must be equal.
pub fn segments_match<S: Segment>(rule: &[S], is_prefix: bool, path: &[S]) -> Option<usize> {
    if !is_prefix && rule.len() != path.len() {
        return None;
    }
    if is_prefix && path.len() < rule.len() {
        return None;
    }

    let mut wildcards = 0;
    for (i, r) in rule.iter().enumerate() {
        let p = &path[i];
        if r.is_wildcard() {
            if p.is_empty() {
                return None;
            }
            wildcards += 1;
            continue;
        }
        let matched = if is_prefix && i == rule.len() - 1 { p.starts_with(r) } else { r.equals(p) };
        if !matched {
            return None;
        }
    }
    Some(wildcards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rule: &str, is_prefix: bool, path: &str) -> Option<usize> {
        let r: [&str; 8] = split(rule);
        let p: [&str; 8] = split(path);
        let (rn, pn) = (rule.split('/').count(), path.split('/').count());
        segments_match(&r[..rn], is_prefix, &p[..pn])
    }

    fn split(s: &str) -> [&str; 8] {
        let mut out = [""; 8];
        for (i, seg) in s.split('/').enumerate() {
            out[i] = seg;
        }
        out
    }

    #[test]
    fn plus_matches_one_non_empty_segment() {
        assert_eq!(m("targets/+", false, "targets/a"), Some(1));
        assert_eq!(m("targets/+", false, "targets/"), None);
        assert_eq!(m("pki/+/pem", false, "pki//pem"), None);
        assert_eq!(m("a/+/+", false, "a/b/c"), Some(2));
    }

    #[test]
    fn prefix_rules_match_a_string_prefix_of_the_last_segment() {
        assert_eq!(m("a/+/fo", true, "a/x/foo/bar"), Some(1));
        assert_eq!(m("a/+/fo", true, "a/x/f"), None);
        assert_eq!(m("a/+/", true, "a/x/anything"), Some(1));
        assert_eq!(m("a/+/b", false, "a/x/b/c"), None);
    }
}
