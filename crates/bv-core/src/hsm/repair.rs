//! The repair job's plan, pacing and report (T454 phase 4).
//!
//! Repair runs in the leader under the `hsm-repair` lock. For every blob set
//! (the KEK and each custody set) it adds a copy for each active or joining
//! member that lacks one, by a `Rewrap` authorization on a member that holds
//! one, and drops copies on retired members once another copy exists. The
//! flow itself is `HsmSealProvider::repair`. Spec: § Degraded operation and repair.

use std::{collections::BTreeSet, time::Duration};

use serde::Serialize;

use crate::hsm::{blob::HsmId, blobset::BvHsmBlobSet};

/// The cluster lock that keeps two repair runs apart.
pub const HSM_REPAIR_LOCK: &str = "hsm-repair";
/// Sets re-wrapped per second when `repair_rate` is not set.
pub const DEFAULT_REPAIR_RATE: u32 = 2;
/// Upper bound on `repair_rate`; above it repair could starve live traffic.
pub const MAX_REPAIR_RATE_U64: u64 = 100;
/// How often the background repair tick runs.
pub const REPAIR_INTERVAL: Duration = Duration::from_secs(300);

/// What one set needs: copies to add, and retired copies it may drop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetPlan {
    pub add: Vec<HsmId>,
    pub remove: Vec<HsmId>,
}

impl SetPlan {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

/// Plan one set against the members that must hold a copy (`targets`:
/// active and joining) and the retired ones whose copies go.
pub fn plan(set: &BvHsmBlobSet, targets: &BTreeSet<HsmId>, retired: &BTreeSet<HsmId>) -> SetPlan {
    SetPlan {
        add: targets.iter().filter(|id| set.copy_for(id).is_none()).cloned().collect(),
        remove: set.copies.keys().filter(|id| retired.contains(*id)).cloned().collect(),
    }
}

/// Drop the retired copies from `set`, never the last copy that is not on a
/// retired member: a set is never left without a usable copy.
pub fn drop_retired(set: &mut BvHsmBlobSet, remove: &[HsmId]) -> usize {
    let usable = set.copies.keys().filter(|id| !remove.contains(id)).count();
    if usable == 0 {
        return 0;
    }
    remove.iter().filter(|id| set.copies.remove(*id).is_some()).count()
}

/// Spaces set writes `1 / rate` seconds apart.
pub struct Pacer {
    interval: Duration,
}

impl Pacer {
    pub fn new(rate: u32) -> Self {
        Self { interval: Duration::from_secs(1) / rate.max(1) }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    #[maybe_async::maybe_async]
    pub async fn pause(&self) {
        #[cfg(not(feature = "sync_handler"))]
        tokio::time::sleep(self.interval).await;
        #[cfg(feature = "sync_handler")]
        std::thread::sleep(self.interval);
    }
}

/// One run's outcome; also what `v2/sys/hsm/repair` reports. No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RepairReport {
    pub started_at: u64,
    pub finished_at: u64,
    pub sets_scanned: usize,
    pub copies_added: usize,
    pub copies_removed: usize,
    /// Recovery copies sealed for sets that had none (T454 phase 5).
    pub recovery_copies_added: usize,
    /// Sets still missing a copy for an active or joining member.
    pub under_replicated: usize,
    pub failures: Vec<String>,
    pub invalid_custody_entries: Vec<String>,
    /// Joining members holding every set, waiting for an admin-credentialed run.
    pub ready_to_promote: Vec<String>,
    pub promoted: Vec<String>,
    pub revocations_applied: Vec<String>,
    pub revocations_pending: Vec<String>,
    /// False when the barrier was not available (custody sets not scanned).
    pub custody_scanned: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::blob::{AuthzAlg, BlobAad, BvHsmBlob, Context, DeviceBinding, Purpose};

    fn id(s: &str) -> HsmId {
        HsmId::from_parts("mock", s).unwrap()
    }

    fn copy(serial: &str) -> BvHsmBlob {
        let ctx = Context::new("c", Purpose::BarrierKek, 0, "n");
        let device = DeviceBinding { hsm_id: id(serial), authz_alg: AuthzAlg::Ed25519, authz_fp: "fp".into() };
        BvHsmBlob {
            backend_type: "mock".into(),
            wrap_key: 2,
            aad: BlobAad::v2_from_context(&ctx, &device),
            wrapped: vec![1],
        }
    }

    fn set(serials: &[&str]) -> BvHsmBlobSet {
        let mut s = BvHsmBlobSet::new(Purpose::BarrierKek, 0, copy(serials[0]), "n", 1).unwrap();
        for serial in &serials[1..] {
            s.insert_copy(copy(serial)).unwrap();
        }
        s
    }

    #[test]
    fn plans_add_missing_copies_and_drop_retired_ones_but_never_the_last() {
        let targets: BTreeSet<HsmId> = [id("A"), id("C")].into();
        let retired: BTreeSet<HsmId> = [id("B")].into();
        let p = plan(&set(&["A", "B"]), &targets, &retired);
        assert_eq!(p, SetPlan { add: vec![id("C")], remove: vec![id("B")] });

        let mut only_retired = set(&["B"]);
        assert_eq!(drop_retired(&mut only_retired, &[id("B")]), 0, "the last copy stays until another exists");
        assert_eq!(only_retired.copies.len(), 1);
        let mut both = set(&["A", "B"]);
        assert_eq!(drop_retired(&mut both, &[id("B")]), 1);
        assert_eq!(both.copies.keys().cloned().collect::<Vec<_>>(), vec![id("A")]);
        assert!(plan(&set(&["A", "C"]), &targets, &retired).is_empty());
    }

    #[test]
    fn pacing_follows_the_rate() {
        assert_eq!(Pacer::new(2).interval(), Duration::from_millis(500));
        assert_eq!(Pacer::new(100).interval(), Duration::from_millis(10));
        assert_eq!(Pacer::new(0).interval(), Duration::from_secs(1), "a zero rate never divides by zero");
    }
}
