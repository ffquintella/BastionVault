//! The uid/gid allocator state and its pure allocation rules.
//!
//! Three independent guards keep an id from ever being handed out twice:
//! `high_water` (vault-mode allocation only moves upward), `used` (every id
//! ever allocated, imported or referenced as a shared group; never shrinks)
//! and `retired` (tombstones of removed identities). The store adds a fourth,
//! the per-id index key, checked before an allocation is committed.

use serde::{Deserialize, Serialize};

use super::{
    idset::IdSet,
    model::{decode_versioned, IdKind, IdRange, PosixError, RECORD_VERSION, RESERVED_IDS},
};

/// `idp/posix/alloc/{uid,gid}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocatorState {
    pub version: u32,
    pub kind: IdKind,
    /// Highest id this allocator handed out. Allocation never returns an id
    /// at or below it, whatever the range is later changed to.
    pub high_water: Option<u32>,
    /// Never allocatable again. Never shrinks.
    pub used: IdSet,
    /// Ids of removed identities (a subset of `used`).
    pub retired: IdSet,
}

impl AllocatorState {
    pub fn new(kind: IdKind) -> Self {
        Self { version: RECORD_VERSION, kind, high_water: None, used: IdSet::new(), retired: IdSet::new() }
    }

    pub fn decode(kind: IdKind, bytes: &[u8]) -> Result<Self, PosixError> {
        let state: Self = decode_versioned(&format!("{} allocator", kind.as_str()), bytes)?;
        if state.kind != kind {
            return Err(PosixError::Corrupt(format!(
                "allocator record for {} holds {} state",
                kind.as_str(),
                state.kind.as_str()
            )));
        }
        Ok(state)
    }

    /// Whether `id` may not be allocated or imported.
    pub fn is_taken(&self, id: u32) -> bool {
        self.used.contains(id) || self.retired.contains(id) || RESERVED_IDS.contains(&id)
    }

    /// The next id vault-mode allocation would hand out. Does not mutate.
    pub fn next_free(&self, range: &IdRange) -> Result<u32, PosixError> {
        let floor = match self.high_water {
            Some(h) => h.checked_add(1),
            None => Some(range.min),
        };
        let mut cursor = floor.map(|f| f.max(range.min));
        while let Some(start) = cursor {
            if start > range.max {
                break;
            }
            let Some(candidate) = self.used.next_absent(start, range.max) else {
                break;
            };
            if self.retired.contains(candidate) || RESERVED_IDS.contains(&candidate) {
                cursor = candidate.checked_add(1);
                continue;
            }
            return Ok(candidate);
        }
        let hw = self.high_water.map_or_else(|| "none".to_string(), |h| h.to_string());
        Err(PosixError::Conflict(format!(
            "{} range [{}, {}] is exhausted (high-water mark {hw}); configure a range above it",
            self.kind.as_str(),
            range.min,
            range.max
        )))
    }

    /// Record a vault-mode allocation: marks it used and raises the high-water mark.
    pub fn commit_allocation(&mut self, id: u32) {
        self.used.insert(id);
        self.high_water = Some(self.high_water.map_or(id, |h| h.max(id)));
    }

    /// Record an id taken outside vault-mode allocation (import, shared group,
    /// or a claim discovered in the index). Leaves the high-water mark alone.
    pub fn mark_used(&mut self, id: u32) {
        self.used.insert(id);
    }

    /// Tombstone the id of a removed identity.
    pub fn retire(&mut self, id: u32) {
        self.used.insert(id);
        self.retired.insert(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: u32, max: u32) -> IdRange {
        IdRange { min, max }
    }

    #[test]
    fn allocates_upward_from_the_range_floor() {
        let mut a = AllocatorState::new(IdKind::Uid);
        let r = range(80_000, 80_002);
        for expected in [80_000, 80_001, 80_002] {
            let id = a.next_free(&r).unwrap();
            assert_eq!(id, expected);
            a.commit_allocation(id);
        }
        assert_eq!(a.high_water, Some(80_002));
        // Range exhaustion is an explicit refusal, not a wrap-around.
        assert!(matches!(a.next_free(&r), Err(PosixError::Conflict(m)) if m.contains("exhausted")));
    }

    #[test]
    fn never_reissues_below_high_water_even_if_used_is_lost() {
        let mut a = AllocatorState::new(IdKind::Uid);
        let r = range(80_000, 90_000);
        for _ in 0..5 {
            let id = a.next_free(&r).unwrap();
            a.commit_allocation(id);
        }
        // Simulate a damaged `used` set: high-water alone still prevents reuse.
        a.used = IdSet::new();
        assert_eq!(a.next_free(&r).unwrap(), 80_005);
    }

    #[test]
    fn retired_and_reserved_ids_are_skipped() {
        let mut a = AllocatorState::new(IdKind::Gid);
        a.retired.insert(70_000);
        let r = range(65_533, 70_001);
        a.commit_allocation(65_533);
        // 65534/65535 are reserved, 70000 is a tombstone (not even in `used`).
        a.high_water = Some(65_533);
        a.used.insert(65_536);
        for id in 65_537..70_000 {
            a.used.insert(id);
        }
        assert_eq!(a.next_free(&r).unwrap(), 70_001);
    }

    #[test]
    fn imports_above_high_water_are_skipped_without_moving_it() {
        let mut a = AllocatorState::new(IdKind::Uid);
        let r = range(80_000, 80_010);
        a.mark_used(80_000);
        a.mark_used(80_001);
        assert_eq!(a.high_water, None);
        assert_eq!(a.next_free(&r).unwrap(), 80_002);
    }

    #[test]
    fn range_changes_never_go_back_below_high_water() {
        let mut a = AllocatorState::new(IdKind::Uid);
        a.commit_allocation(85_000);
        // Moved above: allocation starts at the new floor.
        assert_eq!(a.next_free(&range(200_000, 300_000)).unwrap(), 200_000);
        // Moved below the high-water mark: refused rather than reusing space.
        assert!(a.next_free(&range(80_000, 84_999)).is_err());
        // Overlapping: continues above the high-water mark.
        assert_eq!(a.next_free(&range(80_000, 90_000)).unwrap(), 85_001);
    }

    #[test]
    fn state_survives_a_reload() {
        let mut a = AllocatorState::new(IdKind::Uid);
        a.commit_allocation(80_000);
        a.commit_allocation(80_001);
        a.mark_used(81_000);
        a.retire(80_000);
        let bytes = serde_json::to_vec(&a).unwrap();
        let back = AllocatorState::decode(IdKind::Uid, &bytes).unwrap();
        assert_eq!(back, a);
        assert!(back.is_taken(80_000) && back.is_taken(81_000) && back.is_taken(65_534));
        assert_eq!(back.next_free(&range(80_000, 90_000)).unwrap(), 80_002);
        // A uid record cannot be read as gid state.
        assert!(matches!(AllocatorState::decode(IdKind::Gid, &bytes), Err(PosixError::Corrupt(_))));
    }
}
