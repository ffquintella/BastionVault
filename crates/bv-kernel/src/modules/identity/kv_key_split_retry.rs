//! Bounded background retry of the T499 KV key-split datafix (T511) and the
//! T507 asset-group key switch, which run together in `Core::post_unseal`.
//! When either fails there its marker stays unset and the node keeps the old
//! keys, so one task per node retries both with backoff. Scheduling never
//! blocks unseal, a seal aborts the task, and both markers set end it.

use std::{
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use super::kv_key_split_migrate;
use crate::{core::Core, modules::resource_group::secret_name_migrate};

/// Background attempts after a failed unseal pass, at 5, 10, 20, 40 and 80 s.
pub const MAX_RETRIES: u32 = 5;
/// The wait before the first background attempt; each later one doubles it.
const FIRST_DELAY: Duration = Duration::from_secs(5);

/// The node's retry task: at most one runs at a time (single-flight).
#[derive(Default)]
pub struct KvSplitRetry {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The first wait in milliseconds; 0 is [`FIRST_DELAY`]. Tests shorten it.
    first_delay_ms: AtomicU64,
    /// Failed background attempts of the current task.
    failures: Arc<AtomicU32>,
    /// Waits the current task has finished, whatever it then did.
    wakes: Arc<AtomicU32>,
}

impl KvSplitRetry {
    /// Start the retry task unless one is already running. Without a tokio
    /// runtime nothing is spawned and the next unseal runs the pass, as before.
    pub fn schedule(&self, core: Weak<Core>) {
        let mut task = self.task.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            log::warn!(
                target: "migration",
                "kv key split datafix: no runtime for a background retry; it runs again at the next unseal"
            );
            return;
        };
        let first = match self.first_delay_ms.load(Ordering::Relaxed) {
            0 => FIRST_DELAY,
            ms => Duration::from_millis(ms),
        };
        self.failures.store(0, Ordering::Relaxed);
        self.wakes.store(0, Ordering::Relaxed);
        log::warn!(
            target: "migration",
            "kv key datafixes (T499 key split, T507 asset-group keys) failed at unseal; retrying them in the \
             background up to {MAX_RETRIES} times, first in {first:?}"
        );
        let counters = (self.failures.clone(), self.wakes.clone());
        *task = Some(runtime.spawn(retry(core, first, counters)));
    }

    /// Abort the task, on seal. A pass cut short resumes from its saved plan.
    pub fn cancel(&self) {
        let task = self.task.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        if let Some(task) = task {
            task.abort();
        }
    }

    /// Whether a retry task is scheduled and has not ended.
    pub fn running(&self) -> bool {
        let task = self.task.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        task.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Test support: the first wait, instead of five seconds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_first_delay_for_test(&self, delay: Duration) {
        self.first_delay_ms.store(delay.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    /// Test support: failed background attempts of the current task.
    #[cfg(any(test, feature = "test-support"))]
    pub fn failures_for_test(&self) -> u32 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Test support: waits the current task has finished (0 if it was
    /// aborted before its first wait ended).
    #[cfg(any(test, feature = "test-support"))]
    pub fn wakes_for_test(&self) -> u32 {
        self.wakes.load(Ordering::Relaxed)
    }
}

/// Up to [`MAX_RETRIES`] attempts, each after a doubling wait. Stops when the
/// vault is gone or sealed, or when both passes complete or find their marker.
async fn retry(core: Weak<Core>, first: Duration, (failures, wakes): (Arc<AtomicU32>, Arc<AtomicU32>)) {
    let mut delay = first;
    let mut last_error = String::new();
    for attempt in 1..=MAX_RETRIES {
        tokio::time::sleep(delay).await;
        wakes.fetch_add(1, Ordering::Relaxed);
        delay = delay.saturating_mul(2);
        let Some(core) = core.upgrade() else {
            return;
        };
        if core.sealed() {
            return;
        }
        let split = kv_key_split_migrate::run_if_needed(&core).await;
        let names = secret_name_migrate::run_if_needed(&core).await;
        match (split, names) {
            (Ok(split), Ok(names)) if split.skipped && names.skipped => {
                log::info!(target: "migration", "kv key datafixes: both markers are set; background retry stopped");
                return;
            }
            (Ok(_), Ok(_)) => {
                log::info!(target: "migration", "kv key datafixes completed on background retry {attempt}");
                return;
            }
            (split, names) => {
                failures.fetch_add(1, Ordering::Relaxed);
                for e in [split.err(), names.err()].into_iter().flatten() {
                    log::warn!(target: "migration", "kv key datafix retry {attempt} of {MAX_RETRIES} failed: {e}");
                    last_error = e.to_string();
                }
            }
        }
    }
    log::error!(
        target: "security",
        "kv key datafixes gave up after {MAX_RETRIES} background retries: until the T499 pass completes, writes, \
         deletes, owner changes and shares on KV secrets whose key moves at the switch answer 503 on every node, \
         and the pre-T499 keys stay in use (a secret named data/x shares x's record); until the T507 pass \
         completes, asset-group KV-secret membership changes answer 503 and lookups use the pre-T507 keys; find \
         the cause in the migration warnings above, fix it, then seal and unseal a node to run the passes again \
         (docs/api.md, \"KV key-split datafix pending\" and \"Asset-group key switch pending\"): {last_error}"
    );
}
