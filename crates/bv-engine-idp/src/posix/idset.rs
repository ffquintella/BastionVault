//! Run-length-encoded set of POSIX ids: the allocator's "used bitmap".
//!
//! Stored as sorted, disjoint, non-adjacent inclusive intervals, so a dense
//! block of sequential allocations costs one interval rather than one bit per
//! id of a 920 000-id range. Decoding rejects anything not in that canonical
//! form: a corrupted set fails closed instead of being silently repaired.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<[u32; 2]>", into = "Vec<[u32; 2]>")]
pub struct IdSet {
    ranges: Vec<(u32, u32)>,
}

impl TryFrom<Vec<[u32; 2]>> for IdSet {
    type Error = String;

    fn try_from(raw: Vec<[u32; 2]>) -> Result<Self, Self::Error> {
        let mut prev_end: Option<u32> = None;
        for [start, end] in &raw {
            if start > end {
                return Err(format!("malformed id set: interval [{start}, {end}] is inverted"));
            }
            if let Some(prev) = prev_end {
                // Canonical form leaves a gap of at least one id between intervals.
                if u64::from(*start) <= u64::from(prev) + 1 {
                    return Err(format!("malformed id set: interval starting at {start} is not canonical"));
                }
            }
            prev_end = Some(*end);
        }
        Ok(Self { ranges: raw.into_iter().map(|[s, e]| (s, e)).collect() })
    }
}

impl From<IdSet> for Vec<[u32; 2]> {
    fn from(set: IdSet) -> Self {
        set.ranges.into_iter().map(|(s, e)| [s, e]).collect()
    }
}

impl IdSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, id: u32) -> bool {
        let i = self.ranges.partition_point(|&(_, end)| end < id);
        matches!(self.ranges.get(i), Some(&(start, _)) if start <= id)
    }

    /// Add `id`; returns `false` when it was already present.
    pub fn insert(&mut self, id: u32) -> bool {
        if self.contains(id) {
            return false;
        }
        let i = self.ranges.partition_point(|&(start, _)| start < id);
        let merge_left = i > 0 && self.ranges[i - 1].1.checked_add(1) == Some(id);
        let merge_right = i < self.ranges.len() && id.checked_add(1) == Some(self.ranges[i].0);
        match (merge_left, merge_right) {
            (true, true) => {
                self.ranges[i - 1].1 = self.ranges[i].1;
                self.ranges.remove(i);
            }
            (true, false) => self.ranges[i - 1].1 = id,
            (false, true) => self.ranges[i].0 = id,
            (false, false) => self.ranges.insert(i, (id, id)),
        }
        true
    }

    /// Smallest id in `[from, to]` that is not in the set.
    pub fn next_absent(&self, from: u32, to: u32) -> Option<u32> {
        let mut x = from;
        loop {
            if x > to {
                return None;
            }
            let i = self.ranges.partition_point(|&(_, end)| end < x);
            match self.ranges.get(i) {
                Some(&(start, end)) if start <= x => x = end.checked_add(1)?,
                _ => return Some(x),
            }
        }
    }

    /// Number of ids in the set.
    pub fn count(&self) -> u64 {
        self.ranges.iter().map(|&(s, e)| u64::from(e - s) + 1).sum()
    }

    /// Number of stored intervals (the encoded size).
    pub fn interval_count(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_merges_and_stays_canonical() {
        let mut s = IdSet::new();
        assert!(s.insert(10));
        assert!(s.insert(12));
        assert_eq!(s.interval_count(), 2);
        assert!(s.insert(11));
        assert_eq!(s.interval_count(), 1);
        assert!(!s.insert(11));
        assert!(s.insert(9));
        assert!(s.insert(13));
        assert_eq!(s.interval_count(), 1);
        assert_eq!(s.count(), 5);
        assert!(s.contains(9) && s.contains(13) && !s.contains(8) && !s.contains(14));
        // Round-trips through its persisted form.
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "[[9,13]]");
        assert_eq!(serde_json::from_str::<IdSet>(&json).unwrap(), s);
    }

    #[test]
    fn extremes_do_not_overflow() {
        let mut s = IdSet::new();
        assert!(s.insert(u32::MAX));
        assert!(s.insert(0));
        assert!(s.contains(u32::MAX) && s.contains(0));
        assert_eq!(s.next_absent(u32::MAX, u32::MAX), None);
        assert_eq!(s.next_absent(0, 5), Some(1));
    }

    #[test]
    fn next_absent_skips_intervals() {
        let mut s = IdSet::new();
        for id in [100, 101, 102, 104] {
            s.insert(id);
        }
        assert_eq!(s.next_absent(100, 200), Some(103));
        assert_eq!(s.next_absent(104, 200), Some(105));
        assert_eq!(s.next_absent(100, 102), None);
        assert_eq!(s.next_absent(99, 200), Some(99));
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        for bad in ["[[5,4]]", "[[1,5],[3,8]]", "[[1,5],[6,8]]", "[[6,8],[1,2]]", "[[1]]", "{\"a\":1}"] {
            assert!(serde_json::from_str::<IdSet>(bad).is_err(), "accepted {bad}");
        }
        assert!(serde_json::from_str::<IdSet>("[[1,5],[7,8]]").is_ok());
        assert!(serde_json::from_str::<IdSet>("[]").is_ok());
    }
}
