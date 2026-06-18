//! In-memory, time-bucketed counters for request-level operational
//! statistics surfaced on the GUI Dashboard (`sys/dashboard/summary`).
//!
//! BastionVault's tamper-evident audit *trail* is a change-history
//! aggregation — it records who created/updated/deleted policies,
//! groups, shares, etc., but not the outcome of every individual
//! request. The dashboard, however, wants live operational signals:
//! how many requests were *denied*, how many *logins failed*, and
//! whether any *audit-device write failed* (which should always read
//! zero). Those are properties of the request hot path, so we count
//! them there, cheaply, as they happen.
//!
//! Each metric is a ring of hourly buckets. A bucket holds the epoch
//! hour it represents plus a count; recording into a stale bucket
//! resets it first, so the ring always covers the trailing 24h with no
//! background sweeper. Counters are atomic and lock-free — a lost
//! increment at an hour boundary under heavy contention is acceptable
//! for a dashboard gauge.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Number of hourly buckets — one full day.
const BUCKETS: usize = 24;

struct Bucket {
    /// Epoch hour this bucket currently represents, or -1 when unused.
    hour: AtomicI64,
    count: AtomicU64,
}

impl Default for Bucket {
    fn default() -> Self {
        Self { hour: AtomicI64::new(-1), count: AtomicU64::new(0) }
    }
}

struct Metric {
    buckets: Vec<Bucket>,
}

impl Default for Metric {
    fn default() -> Self {
        Self { buckets: (0..BUCKETS).map(|_| Bucket::default()).collect() }
    }
}

impl Metric {
    fn record(&self, now_secs: i64) {
        let hour = now_secs.div_euclid(3600);
        let idx = hour.rem_euclid(BUCKETS as i64) as usize;
        let b = &self.buckets[idx];
        // If this slot is holding a different (older) hour, claim it for
        // the current hour and zero the count before adding.
        if b.hour.load(Ordering::Relaxed) != hour {
            b.hour.store(hour, Ordering::Relaxed);
            b.count.store(0, Ordering::Relaxed);
        }
        b.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Sum counts across the trailing `hours` window ending at `now_secs`.
    fn sum_window(&self, now_secs: i64, hours: i64) -> u64 {
        let cur_hour = now_secs.div_euclid(3600);
        let min_hour = cur_hour - (hours - 1);
        let mut total = 0u64;
        for b in &self.buckets {
            let h = b.hour.load(Ordering::Relaxed);
            if h >= min_hour && h <= cur_hour {
                total += b.count.load(Ordering::Relaxed);
            }
        }
        total
    }
}

/// Process-wide request-outcome counters. Held on `Core` (always
/// present, cheap) and incremented from the request hot path.
#[derive(Default)]
pub struct DashboardStats {
    requests: Metric,
    denied: Metric,
    auth_failures: Metric,
    audit_write_failures: Metric,
}

impl DashboardStats {
    pub fn record_request(&self, now_secs: i64) {
        self.requests.record(now_secs);
    }
    pub fn record_denied(&self, now_secs: i64) {
        self.denied.record(now_secs);
    }
    pub fn record_auth_failure(&self, now_secs: i64) {
        self.auth_failures.record(now_secs);
    }
    pub fn record_audit_write_failure(&self, now_secs: i64) {
        self.audit_write_failures.record(now_secs);
    }

    pub fn requests_24h(&self, now_secs: i64) -> u64 {
        self.requests.sum_window(now_secs, 24)
    }
    pub fn denied_24h(&self, now_secs: i64) -> u64 {
        self.denied.sum_window(now_secs, 24)
    }
    pub fn audit_write_failures_24h(&self, now_secs: i64) -> u64 {
        self.audit_write_failures.sum_window(now_secs, 24)
    }
    /// Failed logins over the trailing hour — the freshest "is someone
    /// hammering us" signal for the attention panel.
    pub fn failed_logins_1h(&self, now_secs: i64) -> u64 {
        self.auth_failures.sum_window(now_secs, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;

    #[test]
    fn counts_within_window() {
        let s = DashboardStats::default();
        let now = 1_000_000 * HOUR; // arbitrary fixed epoch hour
        s.record_denied(now);
        s.record_denied(now);
        s.record_denied(now);
        assert_eq!(s.denied_24h(now), 3);
        assert_eq!(s.requests_24h(now), 0, "metrics are independent");
    }

    #[test]
    fn failed_logins_1h_only_sees_current_hour() {
        let s = DashboardStats::default();
        let now = 500 * HOUR;
        s.record_auth_failure(now);
        s.record_auth_failure(now - HOUR); // previous hour
        assert_eq!(s.failed_logins_1h(now), 1, "only the trailing hour");
        // both fall inside the 24h window though (auth_failures metric)
    }

    #[test]
    fn events_older_than_window_drop_off() {
        let s = DashboardStats::default();
        let base = 2_000 * HOUR;
        s.record_denied(base);
        // 24 hours later the original bucket has been reclaimed/rotated,
        // so the old count no longer contributes.
        let later = base + 24 * HOUR;
        s.record_denied(later);
        assert_eq!(s.denied_24h(later), 1, "the 24h-old event aged out");
    }

    #[test]
    fn bucket_reset_on_reuse() {
        let s = DashboardStats::default();
        let h = 10_000 * HOUR;
        s.record_request(h);
        // Same ring slot, exactly 24h later → must reset, not accumulate.
        s.record_request(h + 24 * HOUR);
        assert_eq!(s.requests_24h(h + 24 * HOUR), 1);
    }
}
