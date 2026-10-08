//! Specificity: which prefix or segment-wildcard rule governs a path.

use core::cmp::Ordering;

/// The ranking facts of one non-exact candidate rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Specificity {
    /// Byte offset of the first wildcard: the first `+` of a segment-wildcard
    /// rule, or the length of a prefix rule's literal part (where its `*`
    /// stood). `-1` if there is none.
    pub first_wildcard: isize,
    /// The rule ends in `*`.
    pub is_prefix: bool,
    /// Number of `+` segments.
    pub wildcards: usize,
    /// Byte length of the rule path without its trailing `*`.
    pub len: usize,
}

/// A candidate that can be ranked: its [`Specificity`] plus a final
/// tie-break (the host uses the rule path itself, which no two candidates
/// share).
pub trait Ranked {
    /// The tie-break key.
    type Tiebreak: Ord + ?Sized;
    /// The candidate's ranking facts.
    fn specificity(&self) -> Specificity;
    /// The candidate's tie-break key.
    fn tiebreak(&self) -> &Self::Tiebreak;
}

/// The specificity order. `Greater` is more specific: a later first wildcard;
/// then, at the same position, a rule that does not end in `*`; then fewer
/// `+` segments; then a longer path; then the tie-break. Every component is
/// a total order, so this is one, and two candidates compare `Equal` only
/// when every component is equal.
pub fn compare<R: Ranked + ?Sized>(a: &R, b: &R) -> Ordering {
    let (sa, sb) = (a.specificity(), b.specificity());
    sa.first_wildcard
        .cmp(&sb.first_wildcard)
        .then_with(|| sb.is_prefix.cmp(&sa.is_prefix))
        .then_with(|| sb.wildcards.cmp(&sa.wildcards))
        .then_with(|| sa.len.cmp(&sb.len))
        .then_with(|| a.tiebreak().cmp(b.tiebreak()))
}

/// Selects the most specific of a stream of candidates — the maximum under
/// [`compare`]. Among candidates that compare `Equal` the last one offered
/// wins, which is exactly what sorting the candidates (stably) and taking the
/// last one did; with distinct tie-breaks there is no such tie, so the winner
/// does not depend on the order the candidates are offered in (the host's
/// segment-wildcard map iterates in no defined order).
#[derive(Debug)]
pub struct MostSpecific<R> {
    best: Option<R>,
}

impl<R> Default for MostSpecific<R> {
    fn default() -> Self {
        Self { best: None }
    }
}

impl<R: Ranked> MostSpecific<R> {
    /// No candidate yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consider one candidate.
    pub fn offer(&mut self, candidate: R) {
        let replace = match &self.best {
            None => true,
            Some(best) => compare(&candidate, best) != Ordering::Less,
        };
        if replace {
            self.best = Some(candidate);
        }
    }

    /// The most specific candidate offered, if any.
    pub fn into_winner(self) -> Option<R> {
        self.best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Key;

    fn key(first_wildcard: isize, is_prefix: bool, wildcards: usize, len: usize, tie: u8) -> Key {
        Key { spec: Specificity { first_wildcard, is_prefix, wildcards, len }, tie }
    }

    #[test]
    fn later_wildcards_win_then_literal_tails_then_fewer_plus() {
        assert_eq!(compare(&key(4, true, 0, 4, 0), &key(3, false, 1, 9, 0)), Ordering::Greater);
        assert_eq!(compare(&key(4, false, 1, 4, 0), &key(4, true, 0, 4, 0)), Ordering::Greater);
        assert_eq!(compare(&key(4, false, 1, 4, 0), &key(4, false, 2, 4, 0)), Ordering::Greater);
        assert_eq!(compare(&key(4, false, 1, 5, 0), &key(4, false, 1, 4, 9)), Ordering::Greater);
    }

    #[test]
    fn the_last_maximum_offered_wins() {
        let mut m = MostSpecific::new();
        m.offer(key(1, true, 0, 1, 7));
        m.offer(key(2, true, 0, 2, 1));
        m.offer(key(2, true, 0, 2, 1));
        m.offer(key(0, false, 0, 0, 9));
        assert_eq!(m.into_winner(), Some(key(2, true, 0, 2, 1)));
    }
}
