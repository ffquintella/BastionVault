//! Precomputed audit statistics for the GUI Dashboard.
//!
//! `sys/dashboard/summary` used to aggregate every audit source over a 24-hour
//! window on every request, and the Dashboard additionally pulled the 200
//! newest events through an unwindowed `sys/audit/events`. On a store with
//! hundreds of thousands of rows that is seconds of work and tens of megabytes
//! per page view, on every node. Now one record, `sys/dashboard-stats/record`,
//! holds exactly what the Dashboard shows, and [`super::housekeeping`]
//! recomputes it every [`REFRESH_INTERVAL`] on the single elected runner. The
//! summary handler only reads it; when it is missing it says so
//! ([`SummaryAuditView::Pending`]) and never falls back to scanning.
//!
//! The record is derived data with a `version` field. A reader that does not
//! recognise the version reports the statistics as not computed; the runner
//! rewrites the record in its own version on its next refresh, which loses
//! nothing because everything in it can be recomputed.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{AuditEventBuilder, SystemBackend};
use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Current version of [`DashboardStatsRecord`].
pub const DASHBOARD_STATS_VERSION: u64 = 1;
/// How often the runner recomputes the record.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Age at which the summary flags the record as stale: three missed refreshes.
pub const STALE_AFTER: Duration = Duration::from_secs(30 * 60);
/// Number of events kept for the "Recent activity" panel.
pub const RECENT_LIMIT: usize = 20;
/// How far back "Recent activity" looks when the last 24 hours hold fewer than
/// [`RECENT_LIMIT`] events. Bounded so an idle deployment never scans its whole
/// history to fill the panel.
pub const RECENT_LOOKBACK_DAYS: i64 = 7;
/// Hourly buckets in the activity histogram.
pub const HISTOGRAM_BUCKETS: usize = 24;
const HISTOGRAM_BUCKET_SECS: i64 = 3600;

const STATS_SUB_PATH: &str = "dashboard-stats/";
const STATS_KEY: &str = "record";

/// One "Recent activity" row: the `sys/audit/events` row shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentAuditEvent {
    pub ts: String,
    pub user: String,
    /// SPIFFE id of an attesting machine; omitted when empty, as on
    /// `sys/audit/events`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine: String,
    pub op: String,
    pub category: String,
    pub target: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

impl RecentAuditEvent {
    fn from_builder(e: &AuditEventBuilder) -> Self {
        Self {
            ts: e.ts.clone(),
            user: e.user.clone(),
            machine: e.machine.clone(),
            op: e.op.clone(),
            category: e.category.clone(),
            target: e.target.clone(),
            changed_fields: e.changed_fields.clone(),
            summary: e.summary.clone(),
        }
    }
}

/// The persisted statistics, version [`DASHBOARD_STATS_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardStatsRecord {
    pub version: u64,
    /// RFC3339 UTC instant the record describes.
    pub computed_at: String,
    /// `computed_at - 24h`; start of the histogram and of the counters.
    pub window_start: String,
    /// Wall-clock cost of the computation, for operators.
    pub compute_ms: u64,
    /// Events across every audit source in the 24-hour window.
    pub audit_24h_total: u64,
    /// Permission-denied requests in the window.
    pub audit_24h_denied: u64,
    /// Failed logins in the hour before `computed_at`.
    pub failed_logins_1h: u64,
    /// [`HISTOGRAM_BUCKETS`] hourly counts, oldest first. Bucket `i` covers
    /// `[window_start + i h, window_start + (i + 1) h)`.
    pub histogram_24h: Vec<u64>,
    /// Newest [`RECENT_LIMIT`] events, newest first.
    pub recent: Vec<RecentAuditEvent>,
    /// At least one source could not be read, so the numbers under-count.
    /// Additive in version 1: a record written before the field reads back
    /// as complete, which is what it claimed to be.
    #[serde(default)]
    pub partial: bool,
    /// The sources that could not be read (`policy`, `access`, …).
    #[serde(default)]
    pub failed_sources: Vec<String>,
}

/// What the stats record looks like in storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredStats {
    Ready(DashboardStatsRecord),
    Missing,
    /// Written by a build with another record version.
    UnsupportedVersion(u64),
    /// Present but not decodable.
    Unreadable(String),
}

/// Decode a stored record; never panics, never guesses.
pub fn decode_record(bytes: &[u8]) -> StoredStats {
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => return StoredStats::Unreadable(format!("not JSON: {e}")),
    };
    match value.get("version").and_then(Value::as_u64) {
        Some(DASHBOARD_STATS_VERSION) => match serde_json::from_value::<DashboardStatsRecord>(value) {
            Ok(record) if record.histogram_24h.len() == HISTOGRAM_BUCKETS => StoredStats::Ready(record),
            Ok(record) => StoredStats::Unreadable(format!(
                "histogram has {} buckets, expected {HISTOGRAM_BUCKETS}",
                record.histogram_24h.len()
            )),
            Err(e) => StoredStats::Unreadable(e.to_string()),
        },
        Some(other) => StoredStats::UnsupportedVersion(other),
        None => StoredStats::Unreadable("no version field".to_string()),
    }
}

fn stats_view(core: &Core) -> Result<BarrierView, RvError> {
    let system_view = core.system_view().ok_or(RvError::ErrBarrierSealed)?;
    Ok(system_view.new_sub_view(STATS_SUB_PATH))
}

/// Read the stored record. Storage errors propagate; decoding problems are a
/// [`StoredStats`] variant.
pub async fn load(core: &Core) -> Result<StoredStats, RvError> {
    Ok(match stats_view(core)?.get(STATS_KEY).await? {
        None => StoredStats::Missing,
        Some(entry) => decode_record(&entry.value),
    })
}

pub async fn save(core: &Core, record: &DashboardStatsRecord) -> Result<(), RvError> {
    stats_view(core)?.put(&StorageEntry { key: STATS_KEY.to_string(), value: serde_json::to_vec(record)? }).await
}

/// Write raw bytes as the record. Test fixtures use it to plant records of
/// another version; production writes go through [`save`].
pub async fn save_raw(core: &Core, bytes: Vec<u8>) -> Result<(), RvError> {
    stats_view(core)?.put(&StorageEntry { key: STATS_KEY.to_string(), value: bytes }).await
}

pub async fn delete(core: &Core) -> Result<(), RvError> {
    stats_view(core)?.delete(STATS_KEY).await
}

fn parse_utc(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts).ok().map(|t| t.with_timezone(&Utc))
}

/// Seconds since the record was computed; negative when another node's clock
/// is ahead of ours. `None` when `computed_at` does not parse.
fn age_secs(record: &DashboardStatsRecord, now: DateTime<Utc>) -> Option<i64> {
    parse_utc(&record.computed_at).map(|t| (now - t).num_seconds())
}

/// Whether the runner should recompute: no usable record, or one at least
/// [`REFRESH_INTERVAL`] old.
pub fn needs_refresh(stored: &StoredStats, now: DateTime<Utc>) -> bool {
    match stored {
        StoredStats::Ready(record) => match age_secs(record, now) {
            Some(age) => age >= REFRESH_INTERVAL.as_secs() as i64,
            None => true,
        },
        StoredStats::Missing | StoredStats::UnsupportedVersion(_) | StoredStats::Unreadable(_) => true,
    }
}

/// Build the record from the 24-hour event groups (as returned by
/// `collect_audit_event_groups_since(now - 24h)`) and the pool to draw the
/// recent rows from. Pure, so the arithmetic is testable without a vault.
///
/// The counters are the ones the summary computed on the fly: the total is
/// every collected event, denials are the denial group, failed logins are the
/// login group's `login-failed` rows at or after `now - 1h`. Histogram buckets
/// are relative to `now`; an event stamped just outside the window (clock skew,
/// or written during the scan) lands in the nearest edge bucket so the
/// histogram accounts for the total, and only an unparseable timestamp is left
/// out of it.
pub(super) fn build_record(
    groups: &[Vec<AuditEventBuilder>],
    denials_group: usize,
    logins_group: usize,
    recent_pool: &[&AuditEventBuilder],
    failed_sources: &[&str],
    now: DateTime<Utc>,
    compute_ms: u64,
) -> DashboardStatsRecord {
    let window_start = now - chrono::Duration::hours(HISTOGRAM_BUCKETS as i64);
    let hour_cutoff = (now - chrono::Duration::hours(1)).to_rfc3339();

    let audit_24h_total = groups.iter().map(|g| g.len() as u64).sum();
    let audit_24h_denied = groups.get(denials_group).map(|g| g.len() as u64).unwrap_or(0);
    let failed_logins_1h = groups
        .get(logins_group)
        .map(|g| g.iter().filter(|e| e.op == "login-failed" && e.ts.as_str() >= hour_cutoff.as_str()).count() as u64)
        .unwrap_or(0);

    let mut histogram_24h = vec![0u64; HISTOGRAM_BUCKETS];
    for event in groups.iter().flatten() {
        let Some(t) = parse_utc(&event.ts) else { continue };
        let offset = (t - window_start).num_seconds().div_euclid(HISTOGRAM_BUCKET_SECS);
        let idx = offset.clamp(0, HISTOGRAM_BUCKETS as i64 - 1) as usize;
        histogram_24h[idx] += 1;
    }

    let mut pool: Vec<&AuditEventBuilder> = recent_pool.to_vec();
    // Newest first by RFC3339 string, the order `sys/audit/events` uses.
    pool.sort_by(|a, b| b.ts.cmp(&a.ts));
    let recent = pool.into_iter().take(RECENT_LIMIT).map(RecentAuditEvent::from_builder).collect();

    DashboardStatsRecord {
        version: DASHBOARD_STATS_VERSION,
        computed_at: now.to_rfc3339(),
        window_start: window_start.to_rfc3339(),
        compute_ms,
        audit_24h_total,
        audit_24h_denied,
        failed_logins_1h,
        histogram_24h,
        recent,
        partial: !failed_sources.is_empty(),
        failed_sources: failed_sources.iter().map(|s| s.to_string()).collect(),
    }
}

/// What `sys/dashboard/summary` tells an audit-capable caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryAuditView {
    Ready {
        record: DashboardStatsRecord,
        age_secs: i64,
        stale: bool,
    },
    /// No usable record. `reason` is one of `not_computed`,
    /// `unsupported_version`, `unreadable`, `storage_error`.
    Pending {
        reason: &'static str,
    },
}

impl SummaryAuditView {
    pub fn from_stored(stored: Result<StoredStats, RvError>, now: DateTime<Utc>) -> Self {
        match stored {
            Ok(StoredStats::Ready(record)) => match age_secs(&record, now) {
                Some(age) => {
                    let stale = age >= STALE_AFTER.as_secs() as i64;
                    SummaryAuditView::Ready { record, age_secs: age.max(0), stale }
                }
                None => SummaryAuditView::Pending { reason: "unreadable" },
            },
            Ok(StoredStats::Missing) => SummaryAuditView::Pending { reason: "not_computed" },
            Ok(StoredStats::UnsupportedVersion(_)) => SummaryAuditView::Pending { reason: "unsupported_version" },
            Ok(StoredStats::Unreadable(_)) => SummaryAuditView::Pending { reason: "unreadable" },
            Err(_) => SummaryAuditView::Pending { reason: "storage_error" },
        }
    }

    /// The `audit_stats` block of the summary response.
    ///
    /// `detail` adds the per-hour histogram and the recent rows. Those carry
    /// what `sys/audit/events` itself serves (who did what, where, when), so
    /// the caller decides it with the same gate as that endpoint — `read`
    /// plus `sudo`, or root. Without it the block still says whether the
    /// counters are fresh and complete.
    pub fn to_json(&self, detail: bool) -> Value {
        match self {
            SummaryAuditView::Ready { record, age_secs, stale } => {
                let mut block = json!({
                    "state": "ready",
                    "version": record.version,
                    "computed_at": record.computed_at,
                    "age_secs": age_secs,
                    "stale": stale,
                    "window_start": record.window_start,
                    "partial": record.partial,
                    "failed_sources": record.failed_sources,
                    "refresh_interval_secs": REFRESH_INTERVAL.as_secs(),
                });
                if detail {
                    if let Some(obj) = block.as_object_mut() {
                        obj.insert("histogram_24h".into(), json!(record.histogram_24h));
                        obj.insert("histogram_bucket_secs".into(), json!(HISTOGRAM_BUCKET_SECS));
                        obj.insert("recent".into(), json!(record.recent));
                    }
                }
                block
            }
            SummaryAuditView::Pending { reason } => json!({
                "state": "pending",
                "reason": reason,
                "refresh_interval_secs": REFRESH_INTERVAL.as_secs(),
            }),
        }
    }
}

impl SystemBackend {
    /// Compute the statistics as of `now` with bounded range scans: the
    /// 24-hour window, and — only when that window holds fewer than
    /// [`RECENT_LIMIT`] events — a [`RECENT_LOOKBACK_DAYS`] window for the
    /// recent rows.
    pub async fn compute_dashboard_stats(&self, now: DateTime<Utc>) -> DashboardStatsRecord {
        let started = Instant::now();
        let day = self.collect_audit_event_groups_since(now - chrono::Duration::hours(24)).await;
        let in_window: usize = day.groups.iter().map(Vec::len).sum();
        let mut failed: Vec<&str> = day.failed.clone();

        let wider;
        let recent_pool: Vec<&AuditEventBuilder> = if in_window >= RECENT_LIMIT {
            day.groups.iter().flatten().collect()
        } else {
            wider = self.collect_audit_event_groups_since(now - chrono::Duration::days(RECENT_LOOKBACK_DAYS)).await;
            // A source that failed only on the wider read makes the recent
            // rows, not the counters, incomplete — still partial.
            for name in &wider.failed {
                if !failed.contains(name) {
                    failed.push(name);
                }
            }
            wider.groups.iter().flatten().collect()
        };

        let record = build_record(
            &day.groups,
            Self::AUDIT_GROUP_DENIALS,
            Self::AUDIT_GROUP_LOGINS,
            &recent_pool,
            &failed,
            now,
            started.elapsed().as_millis() as u64,
        );
        if record.partial {
            log::warn!(
                "dashboard-stats: computed without the {} source(s); the record is marked partial",
                record.failed_sources.join(", ")
            );
        }
        record
    }

    /// Recompute and persist the record now. Called by the housekeeping job on
    /// the elected runner; exposed for tests.
    pub async fn refresh_dashboard_stats(&self) -> Result<DashboardStatsRecord, RvError> {
        let record = self.compute_dashboard_stats(Utc::now()).await;
        save(&self.core, &record).await?;
        log::info!(
            "dashboard-stats: refreshed in {} ms (24h events={}, denied={}, failed logins 1h={})",
            record.compute_ms,
            record.audit_24h_total,
            record.audit_24h_denied,
            record.failed_logins_1h
        );
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn ev(ts: &str, op: &str, category: &str) -> AuditEventBuilder {
        AuditEventBuilder {
            ts: ts.to_string(),
            user: "alice".into(),
            machine: String::new(),
            op: op.into(),
            category: category.into(),
            target: format!("{category}/{ts}"),
            changed_fields: Vec::new(),
            summary: String::new(),
        }
    }

    fn sample_record(computed_at: &str) -> DashboardStatsRecord {
        DashboardStatsRecord {
            version: DASHBOARD_STATS_VERSION,
            computed_at: computed_at.into(),
            window_start: String::new(),
            compute_ms: 3,
            audit_24h_total: 5,
            audit_24h_denied: 1,
            failed_logins_1h: 2,
            histogram_24h: vec![0; HISTOGRAM_BUCKETS],
            recent: vec![RecentAuditEvent { ts: computed_at.into(), op: "read".into(), ..Default::default() }],
            partial: false,
            failed_sources: Vec::new(),
        }
    }

    #[test]
    fn build_record_counts_like_the_old_summary_and_buckets_by_hour() {
        let now = at("2026-10-14T12:00:00Z");
        // Group layout mirrors `collect_audit_event_groups_since`: index 1 is
        // logins and index 2 denials in this fixture.
        let groups = vec![
            vec![
                ev("2026-10-14T11:30:00+00:00", "update", "policy"),
                ev("2026-10-13T12:10:00+00:00", "create", "policy"),
            ],
            vec![
                ev("2026-10-14T11:20:00+00:00", "login-failed", "login"),
                ev("2026-10-14T10:20:00+00:00", "login-failed", "login"), // > 1h ago
                ev("2026-10-14T11:50:00+00:00", "login", "login"),
            ],
            vec![ev("2026-10-14T00:30:00+00:00", "denied", "request")],
            vec![ev("not-a-time", "read", "access")],
        ];
        let pool: Vec<&AuditEventBuilder> = groups.iter().flatten().collect();
        let r = build_record(&groups, 2, 1, &pool, &[], now, 7);

        assert_eq!(r.version, DASHBOARD_STATS_VERSION);
        assert_eq!(r.audit_24h_total, 7);
        assert_eq!(r.audit_24h_denied, 1);
        assert_eq!(r.failed_logins_1h, 1, "only the failure inside the last hour");
        assert_eq!(r.histogram_24h.len(), HISTOGRAM_BUCKETS);
        assert_eq!(r.histogram_24h.iter().sum::<u64>(), 6, "every parseable event is bucketed");
        assert_eq!(r.histogram_24h[23], 3, "11:20, 11:30, 11:50 are in the last hour");
        assert_eq!(r.histogram_24h[22], 1, "10:20");
        assert_eq!(r.histogram_24h[12], 1, "00:30 is 11.5h after the window start");
        assert_eq!(r.histogram_24h[0], 1, "12:10 yesterday is in the first bucket");
        assert_eq!(r.computed_at, now.to_rfc3339());
        assert_eq!(r.window_start, (now - chrono::Duration::hours(24)).to_rfc3339());
        assert_eq!(r.compute_ms, 7);
        assert_eq!(r.recent.first().map(|e| e.ts.as_str()), Some("not-a-time"), "string order, as sys/audit/events");
        assert_eq!(r.recent[1].ts, "2026-10-14T11:50:00+00:00");
    }

    #[test]
    fn events_just_outside_the_window_land_in_the_edge_buckets() {
        let now = at("2026-10-14T12:00:00Z");
        let groups = vec![vec![
            ev("2026-10-14T12:00:05+00:00", "read", "access"),
            ev("2026-10-13T11:59:59+00:00", "read", "access"),
        ]];
        let r = build_record(&groups, 9, 6, &[], &[], now, 0);
        assert_eq!(r.histogram_24h[23], 1);
        assert_eq!(r.histogram_24h[0], 1);
        assert_eq!(r.audit_24h_denied, 0, "a missing group index counts as zero");
        assert!(r.recent.is_empty());
    }

    #[test]
    fn recent_is_capped_and_newest_first() {
        let now = at("2026-10-14T12:00:00Z");
        let events: Vec<AuditEventBuilder> =
            (0..30).map(|i| ev(&format!("2026-10-14T10:{i:02}:00+00:00"), "read", "access")).collect();
        let groups = vec![events];
        let pool: Vec<&AuditEventBuilder> = groups.iter().flatten().collect();
        let r = build_record(&groups, 9, 6, &pool, &[], now, 0);
        assert_eq!(r.recent.len(), RECENT_LIMIT);
        assert_eq!(r.recent[0].ts, "2026-10-14T10:29:00+00:00");
        assert_eq!(r.recent[RECENT_LIMIT - 1].ts, "2026-10-14T10:10:00+00:00");
    }

    #[test]
    fn decode_handles_missing_old_new_and_corrupt_records() {
        let record = sample_record("2026-10-14T12:00:00+00:00");
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(decode_record(&bytes), StoredStats::Ready(record));
        assert_eq!(decode_record(br#"{"version": 99, "whatever": true}"#), StoredStats::UnsupportedVersion(99));
        assert!(matches!(decode_record(br#"{"computed_at": "x"}"#), StoredStats::Unreadable(_)));
        assert!(matches!(decode_record(b"\x00garbage"), StoredStats::Unreadable(_)));
        let mut short = serde_json::to_value(sample_record("2026-10-14T12:00:00+00:00")).unwrap();
        short["histogram_24h"] = serde_json::json!([1, 2, 3]);
        assert!(matches!(decode_record(&serde_json::to_vec(&short).unwrap()), StoredStats::Unreadable(_)));
    }

    #[test]
    fn refresh_cadence_and_staleness() {
        let now = at("2026-10-14T12:00:00Z");
        let fresh = StoredStats::Ready(sample_record("2026-10-14T11:55:00+00:00"));
        let due = StoredStats::Ready(sample_record("2026-10-14T11:50:00+00:00"));
        assert!(!needs_refresh(&fresh, now));
        assert!(needs_refresh(&due, now), "10 minutes old is due");
        assert!(needs_refresh(&StoredStats::Missing, now));
        assert!(needs_refresh(&StoredStats::UnsupportedVersion(2), now));
        assert!(needs_refresh(&StoredStats::Unreadable("x".into()), now));
        assert!(needs_refresh(&StoredStats::Ready(sample_record("garbage")), now));

        match SummaryAuditView::from_stored(Ok(due), now) {
            SummaryAuditView::Ready { age_secs, stale, .. } => {
                assert_eq!(age_secs, 600);
                assert!(!stale);
            }
            other => panic!("expected ready, got {other:?}"),
        }
        let old = StoredStats::Ready(sample_record("2026-10-14T11:30:00+00:00"));
        assert!(matches!(SummaryAuditView::from_stored(Ok(old), now), SummaryAuditView::Ready { stale: true, .. }));
    }

    #[test]
    fn pending_states_name_their_reason_and_carry_no_counts() {
        let now = at("2026-10-14T12:00:00Z");
        let cases = [
            (Ok(StoredStats::Missing), "not_computed"),
            (Ok(StoredStats::UnsupportedVersion(7)), "unsupported_version"),
            (Ok(StoredStats::Unreadable("x".into())), "unreadable"),
            (Err(RvError::ErrBarrierSealed), "storage_error"),
        ];
        for (stored, reason) in cases {
            let view = SummaryAuditView::from_stored(stored, now);
            assert_eq!(view, SummaryAuditView::Pending { reason });
            let j = view.to_json(true);
            assert_eq!(j["state"], "pending");
            assert_eq!(j["reason"], reason);
            assert!(j.get("histogram_24h").is_none() && j.get("recent").is_none());
        }
    }

    #[test]
    fn ready_json_carries_the_dashboard_fields() {
        let now = at("2026-10-14T12:00:00Z");
        let view =
            SummaryAuditView::from_stored(Ok(StoredStats::Ready(sample_record("2026-10-14T11:58:00+00:00"))), now);
        let j = view.to_json(true);
        assert_eq!(j["state"], "ready");
        assert_eq!(j["age_secs"], 120);
        assert_eq!(j["stale"], false);
        assert_eq!(j["partial"], false);
        assert_eq!(j["failed_sources"], serde_json::json!([]));
        assert_eq!(j["histogram_24h"].as_array().map(Vec::len), Some(HISTOGRAM_BUCKETS));
        assert_eq!(j["histogram_bucket_secs"], 3600);
        assert_eq!(j["refresh_interval_secs"], 600);
        let row = &j["recent"][0];
        assert_eq!(row["op"], "read");
        assert!(row.get("machine").is_none(), "an empty machine is omitted, as on sys/audit/events");
    }

    #[test]
    fn without_detail_the_block_carries_no_rows_and_no_histogram() {
        let now = at("2026-10-14T12:00:00Z");
        let view =
            SummaryAuditView::from_stored(Ok(StoredStats::Ready(sample_record("2026-10-14T11:58:00+00:00"))), now);
        let j = view.to_json(false);
        assert_eq!(j["state"], "ready");
        assert_eq!(j["computed_at"], "2026-10-14T11:58:00+00:00");
        for withheld in ["recent", "histogram_24h", "histogram_bucket_secs"] {
            assert!(j.get(withheld).is_none(), "{withheld} must need the sys/audit/events gate: {j}");
        }
    }

    #[test]
    fn a_failed_source_marks_the_record_partial() {
        let now = at("2026-10-14T12:00:00Z");
        let groups = vec![vec![ev("2026-10-14T11:30:00+00:00", "read", "access")], Vec::new()];
        let pool: Vec<&AuditEventBuilder> = groups.iter().flatten().collect();
        let r = build_record(&groups, 9, 6, &pool, &["denial", "login"], now, 0);
        assert!(r.partial);
        assert_eq!(r.failed_sources, vec!["denial".to_string(), "login".to_string()]);
        let complete = build_record(&groups, 9, 6, &pool, &[], now, 0);
        assert!(!complete.partial && complete.failed_sources.is_empty());

        let j = SummaryAuditView::Ready { record: r, age_secs: 0, stale: false }.to_json(false);
        assert_eq!(j["partial"], true, "partial is visible at every detail level");
        assert_eq!(j["failed_sources"], serde_json::json!(["denial", "login"]));
    }

    #[test]
    fn a_version_1_record_written_before_partial_existed_reads_as_complete() {
        let mut old = serde_json::to_value(sample_record("2026-10-14T12:00:00+00:00")).unwrap();
        let obj = old.as_object_mut().unwrap();
        obj.remove("partial");
        obj.remove("failed_sources");
        match decode_record(&serde_json::to_vec(&old).unwrap()) {
            StoredStats::Ready(r) => assert!(!r.partial && r.failed_sources.is_empty()),
            other => panic!("an additive field must not break version 1: {other:?}"),
        }
    }
}
