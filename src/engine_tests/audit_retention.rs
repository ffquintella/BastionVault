//! Audit retention and the daily housekeeping run
//! (features/audit-retention-and-dashboard-stats.md, T132).
//!
//! Here rather than in `bv-kernel` because the scheduler tests drive
//! `housekeeping::tick` with the vault's own `SystemBackend`, looked up by type
//! — see the `TypeId` note in `mod.rs`.

use std::{
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Map, Value};

use crate::{
    kernel_api::VaultCtx,
    modules::system::{
        audit_retention::{self, AuditRetentionConfig, PruneParams, RunOutcome, StoredStatus, RETENTION_STORES},
        dashboard_stats::{self, StoredStats},
        housekeeping::{self, RunnerRole},
        SystemBackend, SystemModule,
    },
    storage::{Storage, StorageEntry},
    test_utils::TestHttpServer,
};

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

fn system_backend(server: &TestHttpServer) -> Arc<SystemBackend> {
    server.core.module_manager.get_module::<SystemModule>("system").expect("system module").backend.clone()
}

/// Let the housekeeping task's first tick (spawned on this test's runtime by
/// the unseal) finish, so it cannot interleave with what a test drives by hand.
/// The next tick is a minute away.
async fn wait_for_startup_tick(server: &TestHttpServer) {
    let deadline = Instant::now() + StdDuration::from_secs(30);
    loop {
        let stats_ready = matches!(dashboard_stats::load(&server.core).await, Ok(StoredStats::Ready(_)));
        let armed = matches!(audit_retention::load_status(&server.core).await, Ok(StoredStatus::Present(_)));
        if stats_ready && armed {
            return;
        }
        assert!(Instant::now() < deadline, "the housekeeping task never completed its startup tick");
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
}

async fn boot(name: &str) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, true).await;
    server.token = server.root_token.clone();
    wait_for_startup_tick(&server).await;
    server
}

fn fast(batch_size: usize) -> PruneParams {
    PruneParams { batch_size, pause: StdDuration::ZERO }
}

fn nanos_key(t: DateTime<Utc>) -> String {
    format!("{:020}", t.timestamp_nanos_opt().unwrap())
}

/// The key a store would give a record stamped `t`: access-audit appends a
/// digest suffix, a transcript head its session id, every other store uses
/// the bare nanoseconds.
fn store_key(store: &str, t: DateTime<Utc>, salt: u8) -> String {
    match store {
        "access-audit" => format!("{}-{:016x}", nanos_key(t), salt),
        "mcp-session-transcripts" => format!("{}-as_{:02x}", nanos_key(t), salt),
        _ => nanos_key(t),
    }
}

/// The retention a store is pruned under while the operator's configuration
/// is `configured_days` and enabled.
fn store_days(store: &audit_retention::RetentionStore, configured_days: u32) -> i64 {
    store.rule.days(Some(configured_days)).expect("every rule prunes while retention is enabled") as i64
}

fn view(server: &TestHttpServer, sub_path: &str) -> crate::storage::barrier_view::BarrierView {
    server.core.system_view().unwrap().new_sub_view(sub_path)
}

async fn put(server: &TestHttpServer, sub_path: &str, key: &str, t: DateTime<Utc>) {
    let value = serde_json::to_vec(&json!({ "ts": t.to_rfc3339() })).unwrap();
    view(server, sub_path).put(&StorageEntry { key: key.to_string(), value }).await.unwrap();
}

async fn exists(server: &TestHttpServer, sub_path: &str, key: &str) -> bool {
    view(server, sub_path).get(key).await.unwrap().is_some()
}

/// A live deployment writes audit records all the time; the runner's clock
/// check (`audit_retention::clock_check`) refuses to delete without one
/// recent enough. This stands in for that traffic at `t`.
async fn activity_at(server: &TestHttpServer, t: DateTime<Utc>) {
    put(server, "access-audit/", &format!("{}-00000000000000ac", nanos_key(t)), t).await;
}

async fn set_config(server: &TestHttpServer, retention_days: u32, enabled: bool) {
    let cfg = AuditRetentionConfig { retention_days, enabled, ..Default::default() };
    audit_retention::save_config(&server.core, &cfg).await.unwrap();
}

/// `v2/sys/audit-retention` reads the default, persists a change, keeps the
/// other field on a partial write, refuses every invalid value without
/// touching the stored record, is v2-only, and is sudo-gated.
#[tokio::test]
async fn retention_config_round_trips_and_is_validated_over_http() {
    let mut server = boot("audit_retention_config_http").await;
    let root = server.root_token.clone();
    server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

    let (status, ret) = server.read("v2/sys/audit-retention", Some(&root)).unwrap();
    assert_eq!(status, 200, "{ret:?}");
    assert_eq!(ret["retention_days"], 365);
    assert_eq!(ret["enabled"], true);
    assert_eq!(ret["source"], "default");
    assert_eq!(ret["schedule"], "daily at 00:00 UTC");
    assert_eq!(ret["min_retention_days"], 1);
    assert_eq!(ret["max_retention_days"], 36500);
    assert!(ret["armed_at"].as_str().is_some(), "the startup tick armed the schedule: {ret:?}");
    assert!(ret["last_run"].is_null(), "an armed schedule waits for midnight: {ret:?}");
    assert!(ret["next_run_at"].as_str().is_some_and(|s| s.contains("T00:00:00")), "{ret:?}");
    let stores: Vec<&str> = ret["stores"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert_eq!(stores, RETENTION_STORES.iter().map(|s| s.name).collect::<Vec<_>>());

    let (status, ret) =
        server.write("v2/sys/audit-retention", obj(json!({ "retention_days": 30 })), Some(&root)).unwrap();
    assert_eq!(status, 200, "{ret:?}");
    assert_eq!(ret["retention_days"], 30);
    assert_eq!(ret["enabled"], true);
    assert_eq!(ret["source"], "stored");
    assert!(ret["updated_by"].as_str().is_some_and(|s| !s.is_empty()), "{ret:?}");

    // Partial write keeps the other field.
    let (status, ret) = server.write("v2/sys/audit-retention", obj(json!({ "enabled": false })), Some(&root)).unwrap();
    assert_eq!(status, 200, "{ret:?}");
    assert_eq!(ret["retention_days"], 30);
    assert_eq!(ret["enabled"], false);

    for bad in [
        json!({ "retention_days": 0 }),
        json!({ "retention_days": -1 }),
        json!({ "retention_days": 36501 }),
        json!({ "retention_days": 1.5 }),
        json!({ "retention_days": "abc" }),
        json!({ "enabled": "yes" }),
        json!({}),
    ] {
        let (status, ret) = server.write("v2/sys/audit-retention", obj(bad.clone()), Some(&root)).unwrap();
        assert_eq!(status, 400, "{bad} must be refused: {ret:?}");
    }

    let (cfg, source) = audit_retention::load_config(&server.core).await.unwrap();
    assert_eq!((cfg.retention_days, cfg.enabled, source), (30, false, audit_retention::ConfigSource::Stored));

    // v2 only: the frozen v1 sys scope has no such route.
    // (A raw request: the scope's 404 has no JSON body for the harness to parse.)
    let agent = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
    let v1 = agent
        .get(format!("{}/v1/sys/audit-retention", server.url_prefix))
        .header("X-BastionVault-Token", root.as_str())
        .call()
        .unwrap();
    assert_eq!(v1.status().as_u16(), 404, "the retention route must not exist under v1");

    // Sudo-gated: a `default`-policy principal is refused both ways.
    server.write("v1/sys/auth/pass", obj(json!({ "type": "userpass" })), Some(&root)).unwrap();
    server
        .write(
            "v1/auth/pass/users/plain",
            obj(json!({ "password": "retention-pw-1", "token_policies": "default", "ttl": 0 })),
            Some(&root),
        )
        .unwrap();
    let token = server.write("v1/auth/pass/login/plain", obj(json!({ "password": "retention-pw-1" })), None).unwrap().1
        ["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_string();
    // The refusal is the sudo (root-path) gate's. It currently surfaces as the
    // policy store's generic error status rather than a 403 — the same for
    // every sudo-gated `sys/` path — so the test pins the gate, not the code.
    let refused_by_sudo_gate = |(status, ret): (u16, Value)| {
        assert!(!(200..300).contains(&status), "a non-sudo caller must be refused: {status} {ret:?}");
        assert!(
            status == 403 || ret["error"].as_str().is_some_and(|e| e.contains("root path")),
            "refused by the sudo gate: {status} {ret:?}"
        );
    };
    refused_by_sudo_gate(server.read("v2/sys/audit-retention", Some(&token)).unwrap());
    refused_by_sudo_gate(
        server.write("v2/sys/audit-retention", obj(json!({ "retention_days": 1 })), Some(&token)).unwrap(),
    );
    assert_eq!(audit_retention::load_config(&server.core).await.unwrap().0.retention_days, 30);
}

/// One run deletes, in every store, exactly the records older than the cutoff:
/// the record stamped at the cutoff is kept, the one a nanosecond older is not,
/// fresh records and keys without a timestamp prefix are untouched.
#[tokio::test]
async fn a_run_prunes_only_expired_records_in_every_store() {
    let server = boot("audit_retention_prunes_every_store").await;
    let now = Utc::now();
    let configured = audit_retention::DEFAULT_RETENTION_DAYS;
    let cutoff_of = |store: &audit_retention::RetentionStore| now - Duration::days(store_days(store, configured));

    for (i, store) in RETENTION_STORES.iter().enumerate() {
        let salt = i as u8;
        let cutoff = cutoff_of(store);
        put(&server, store.sub_path, &store_key(store.name, now - Duration::days(400), salt), now).await;
        put(&server, store.sub_path, &store_key(store.name, cutoff - Duration::nanoseconds(1), salt), now).await;
        put(&server, store.sub_path, &store_key(store.name, cutoff, salt), now).await;
        put(&server, store.sub_path, &store_key(store.name, now - Duration::days(1), salt), now).await;
    }
    put(&server, "denial-audit/", "not-a-timestamp", now).await;

    let report = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(report.outcome, RunOutcome::Completed, "{report:?}");
    assert_eq!(report.retention_days, 365);
    assert_eq!(report.cutoff, (now - Duration::days(365)).to_rfc3339());
    assert_eq!(report.stores.len(), RETENTION_STORES.len());

    for (i, store) in RETENTION_STORES.iter().enumerate() {
        let salt = i as u8;
        let cutoff = cutoff_of(store);
        let r = report.stores.iter().find(|r| r.store == store.name).expect("a report per store");
        assert_eq!(r.rule, store.rule.as_str());
        assert_eq!(r.retention_days as i64, store_days(store, configured));
        assert_eq!(r.cutoff, cutoff.to_rfc3339());
        assert_eq!(r.deleted, 2, "{r:?}");
        assert!(r.remaining >= 2, "{r:?}");
        assert!(r.error.is_none(), "{r:?}");
        assert!(!exists(&server, store.sub_path, &store_key(store.name, now - Duration::days(400), salt)).await);
        assert!(
            !exists(&server, store.sub_path, &store_key(store.name, cutoff - Duration::nanoseconds(1), salt)).await,
            "{}: a nanosecond before the cutoff is expired",
            store.name
        );
        assert!(
            exists(&server, store.sub_path, &store_key(store.name, cutoff, salt)).await,
            "{}: the record at the cutoff is kept",
            store.name
        );
        assert!(exists(&server, store.sub_path, &store_key(store.name, now - Duration::days(1), salt)).await);
    }
    let denial = report.stores.iter().find(|r| r.store == "denial-audit").unwrap();
    assert_eq!(denial.unrecognised, 1);
    assert!(exists(&server, "denial-audit/", "not-a-timestamp").await, "unrecognised keys are never deleted");
}

/// Deletes go out in batches of the configured size, and a second run with
/// the same cutoff deletes nothing (idempotent).
#[tokio::test]
async fn deletes_are_batched_and_a_rerun_deletes_nothing() {
    let server = boot("audit_retention_batches").await;
    let now = Utc::now();
    for d in 0..5 {
        put(&server, "login-audit/", &nanos_key(now - Duration::days(500 + d)), now).await;
    }
    activity_at(&server, now - Duration::minutes(5)).await;

    let first = audit_retention::run_retention(&server.core, now, fast(2)).await;
    let login = first.stores.iter().find(|r| r.store == "login-audit").unwrap();
    assert_eq!((login.deleted, login.batches), (5, 3), "5 expired in batches of 2: {login:?}");

    let second = audit_retention::run_retention(&server.core, now, fast(2)).await;
    assert_eq!(second.outcome, RunOutcome::Completed);
    assert!(second.stores.iter().all(|r| r.deleted == 0 && r.batches == 0), "{second:?}");
}

/// Each run reads the configuration it runs under: shortening the retention
/// deletes more at the next run, disabling it deletes nothing, and an
/// unreadable configuration deletes nothing rather than falling back to the
/// 365-day default.
#[tokio::test]
async fn runs_follow_configuration_changes_and_refuse_an_unreadable_one() {
    let server = boot("audit_retention_config_changes").await;
    let now = Utc::now();
    let forty = nanos_key(now - Duration::days(40));
    let twenty = nanos_key(now - Duration::days(20));
    let ancient = nanos_key(now - Duration::days(4000));
    for key in [&forty, &twenty, &ancient] {
        put(&server, "denial-audit/", key, now).await;
    }
    activity_at(&server, now - Duration::minutes(5)).await;

    set_config(&server, 30, true).await;
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!((run.outcome, run.retention_days), (RunOutcome::Completed, 30));
    assert!(!exists(&server, "denial-audit/", &forty).await && !exists(&server, "denial-audit/", &ancient).await);
    assert!(exists(&server, "denial-audit/", &twenty).await);

    set_config(&server, 10, false).await;
    put(&server, "denial-audit/", &ancient, now).await;
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Disabled);
    // Only the stores with a fixed rule are pruned while retention is off.
    assert!(!run.stores.is_empty() && run.stores.iter().all(|r| r.rule == "fixed"), "{run:?}");
    assert!(exists(&server, "denial-audit/", &twenty).await && exists(&server, "denial-audit/", &ancient).await);

    set_config(&server, 10, true).await;
    audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert!(!exists(&server, "denial-audit/", &twenty).await, "10 days now applies");

    // Unreadable configuration: refuse, delete nothing.
    put(&server, "denial-audit/", &ancient, now).await;
    view(&server, "audit-retention/")
        .put(&StorageEntry { key: "config".into(), value: b"{garbage".to_vec() })
        .await
        .unwrap();
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Failed, "{run:?}");
    assert!(run.error.as_deref().is_some_and(|e| e.contains("could not be read")), "{run:?}");
    assert!(exists(&server, "denial-audit/", &ancient).await, "nothing is deleted under an unreadable config");
}

/// A follower does nothing: it neither refreshes statistics, nor arms the
/// schedule, nor deletes — only the elected runner does.
#[tokio::test]
async fn a_follower_tick_does_nothing() {
    let server = boot("audit_retention_follower").await;
    let backend = system_backend(&server);
    let now = Utc::now();
    let expired = nanos_key(now - Duration::days(1000));
    put(&server, "access-audit/", &format!("{expired}-00000000000000aa"), now).await;
    dashboard_stats::delete(&server.core).await.unwrap();
    view(&server, "audit-retention/").delete("status").await.unwrap();

    let report = housekeeping::tick(&backend, now, RunnerRole::Follower, fast(500)).await;
    assert!(report.skipped_follower, "{report:?}");
    assert!(!report.stats_refreshed && !report.retention_armed && report.retention_ran.is_none());
    assert!(matches!(dashboard_stats::load(&server.core).await, Ok(StoredStats::Missing)));
    assert!(matches!(audit_retention::load_status(&server.core).await, Ok(StoredStatus::Missing)));
    assert!(exists(&server, "access-audit/", &format!("{expired}-00000000000000aa")).await);

    // The same tick as the runner does all three.
    let report = housekeeping::tick(&backend, now, RunnerRole::Leader, fast(500)).await;
    assert!(report.stats_refreshed && report.retention_armed, "{report:?}");
}

/// The schedule: arming waits for the first 00:00 UTC at least a day later,
/// the run happens once that day, and a node that was down across midnights catches up exactly
/// once. Each run is recorded and readable.
#[tokio::test]
async fn the_daily_run_waits_for_midnight_and_catches_up_once() {
    let mut server = boot("audit_retention_schedule").await;
    let root = server.root_token.clone();
    let backend = system_backend(&server);
    view(&server, "audit-retention/").delete("status").await.unwrap();

    let day = audit_retention::last_scheduled_run(Utc::now());
    let at = |offset: Duration| day + offset;
    let tick = |now: DateTime<Utc>| {
        let backend = backend.clone();
        async move { housekeeping::tick(&backend, now, RunnerRole::Single, fast(500)).await }
    };

    // Armed at 13:00 (an install or upgrade). The first run is the first
    // 00:00 UTC at least 24 hours later — not tonight's — so an operator has a
    // day to configure retention before anything is deleted.
    let armed = tick(at(Duration::hours(13))).await;
    assert!(armed.retention_armed && armed.retention_ran.is_none(), "{armed:?}");
    let expired = nanos_key(day - Duration::days(400));
    put(&server, "ssh-sign-audit/", &expired, day).await;
    // (Each would-be run below is preceded by the audit traffic a live
    // deployment has; without it the clock check refuses.)
    let tonight = at(Duration::days(1) + Duration::seconds(30));
    activity_at(&server, tonight - Duration::minutes(1)).await;
    assert!(tick(at(Duration::hours(23) + Duration::minutes(59))).await.retention_ran.is_none());
    assert!(tick(tonight).await.retention_ran.is_none(), "the first midnight is inside the grace day");
    assert!(exists(&server, "ssh-sign-audit/", &expired).await);

    // The next midnight runs it, once.
    let first = at(Duration::days(2) + Duration::seconds(30));
    activity_at(&server, first - Duration::minutes(1)).await;
    assert_eq!(tick(first).await.retention_ran, Some(RunOutcome::Completed));
    assert!(!exists(&server, "ssh-sign-audit/", &expired).await);
    assert!(tick(at(Duration::days(2) + Duration::minutes(5))).await.retention_ran.is_none());

    // Down across two midnights, back at 04:00: one catch-up run.
    let back = at(Duration::days(4) + Duration::hours(4));
    activity_at(&server, back - Duration::minutes(1)).await;
    assert_eq!(tick(back).await.retention_ran, Some(RunOutcome::Completed));
    assert!(tick(back + Duration::minutes(1)).await.retention_ran.is_none());

    // The run is recorded and readable over the API.
    match audit_retention::load_status(&server.core).await.unwrap() {
        StoredStatus::Present(status) => {
            let last = status.last_run.expect("last run recorded");
            assert_eq!(last.started_at, back.to_rfc3339());
            assert_eq!(last.outcome, RunOutcome::Completed);
            assert_eq!(last.stores.len(), RETENTION_STORES.len());
        }
        other => panic!("expected a status record, got {other:?}"),
    }
    server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();
    let ret = server.read("v2/sys/audit-retention", Some(&root)).unwrap().1;
    assert_eq!(ret["last_run"]["outcome"], "completed", "{ret:?}");
    assert_eq!(ret["last_run"]["started_at"], back.to_rfc3339());
    assert!(ret["last_run"]["stores"].as_array().is_some_and(|s| s.len() == RETENTION_STORES.len()));

    // A damaged status record does not stop retention: the next tick runs
    // and replaces it.
    view(&server, "audit-retention/")
        .put(&StorageEntry { key: "status".into(), value: b"{garbage".to_vec() })
        .await
        .unwrap();
    assert_eq!(tick(back + Duration::minutes(2)).await.retention_ran, Some(RunOutcome::Completed));
    assert!(matches!(audit_retention::load_status(&server.core).await, Ok(StoredStatus::Present(_))));
}

/// A runner whose clock is far ahead of every audit record in the deployment
/// refuses to delete — its cutoff would be wrong — records why, and deletes
/// normally once records as recent as its clock exist.
#[tokio::test]
async fn a_runner_clock_far_ahead_of_the_newest_record_deletes_nothing() {
    let server = boot("audit_retention_clock_guard").await;
    let backend = system_backend(&server);
    // This node's clock reads 30 days ahead of every record the vault holds.
    let ahead = Utc::now() + Duration::days(30);
    let expired = nanos_key(ahead - Duration::days(400));
    let barely_retained = nanos_key(ahead - Duration::days(364));
    put(&server, "denial-audit/", &expired, ahead).await;
    put(&server, "denial-audit/", &barely_retained, ahead).await;

    let run = audit_retention::run_retention(&server.core, ahead, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Refused, "{run:?}");
    assert!(run.error.as_deref().is_some_and(|e| e.contains("clock")), "{run:?}");
    assert!(run.stores.iter().all(|r| r.deleted == 0), "{run:?}");
    let denial = run.stores.iter().find(|r| r.store == "denial-audit").unwrap();
    assert!(denial.error.as_deref().is_some_and(|e| e.contains("clock check")), "{denial:?}");
    assert!(exists(&server, "denial-audit/", &expired).await, "nothing is deleted on a suspect clock");

    // Through the scheduler the refusal is recorded in the status record.
    view(&server, "audit-retention/").delete("status").await.unwrap();
    housekeeping::tick(&backend, ahead - Duration::days(2), RunnerRole::Single, fast(500)).await; // arms
    let report = housekeeping::tick(&backend, ahead, RunnerRole::Single, fast(500)).await;
    assert_eq!(report.retention_ran, Some(RunOutcome::Refused));
    match audit_retention::load_status(&server.core).await.unwrap() {
        StoredStatus::Present(st) => assert_eq!(st.last_run.map(|r| r.outcome), Some(RunOutcome::Refused)),
        other => panic!("{other:?}"),
    }

    // Once the deployment has records as recent as this clock, it runs.
    activity_at(&server, ahead - Duration::hours(1)).await;
    let run = audit_retention::run_retention(&server.core, ahead, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Completed, "{run:?}");
    assert!(!exists(&server, "denial-audit/", &expired).await);
    assert!(exists(&server, "denial-audit/", &barely_retained).await);
}

// ── MCP session transcripts: the fixed 30-day rule ──────────────────────
// (features/mcp-brokered-sessions.md §10, T136)

const TRANSCRIPTS: &str = "mcp-session-transcripts/";

/// A transcript head and its body chunks, as the store writes them, stamped
/// `t`. Values are opaque here: pruning never reads them.
async fn put_transcript(server: &TestHttpServer, t: DateTime<Utc>, session: &str, chunks: usize) -> Vec<String> {
    let head = format!("{}-{session}", nanos_key(t));
    let mut keys: Vec<String> = (1..=chunks).map(|n| format!("{head}.{n}")).collect();
    keys.push(head);
    for key in &keys {
        put(server, TRANSCRIPTS, key, t).await;
    }
    keys
}

async fn all_exist(server: &TestHttpServer, keys: &[String]) -> bool {
    for key in keys {
        if !exists(server, TRANSCRIPTS, key).await {
            return false;
        }
    }
    true
}

async fn none_exist(server: &TestHttpServer, keys: &[String]) -> bool {
    for key in keys {
        if exists(server, TRANSCRIPTS, key).await {
            return false;
        }
    }
    true
}

/// Transcripts keep 30 days whatever the operator configured: a 31-day-old
/// transcript is pruned with its chunks and a 29-day-old one kept, under a
/// 3650-day retention (which keeps a 40-day-old audit record), with
/// retention disabled, and with an unreadable configuration (which deletes
/// no audit record).
#[tokio::test]
async fn transcripts_are_pruned_at_30_days_whatever_audit_retention_says() {
    let server = boot("audit_retention_transcripts_fixed_rule").await;
    let now = Utc::now();
    activity_at(&server, now - Duration::minutes(5)).await;
    let audit_40 = nanos_key(now - Duration::days(40));
    put(&server, "denial-audit/", &audit_40, now).await;

    // A decade of audit retention does not lengthen the transcripts' 30 days.
    set_config(&server, 3650, true).await;
    let expired = put_transcript(&server, now - Duration::days(31), "as_old", 3).await;
    let kept = put_transcript(&server, now - Duration::days(29), "as_new", 2).await;
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Completed, "{run:?}");
    let r = run.stores.iter().find(|r| r.store == "mcp-session-transcripts").unwrap();
    assert_eq!((r.deleted, r.rule.as_str(), r.retention_days), (4, "fixed", 30), "{r:?}");
    assert!(none_exist(&server, &expired).await, "the head and every chunk are pruned together");
    assert!(all_exist(&server, &kept).await);
    assert!(exists(&server, "denial-audit/", &audit_40).await, "3650 days keeps the audit record");

    // Retention disabled: no audit record goes, the old transcript does.
    set_config(&server, 10, false).await;
    let expired = put_transcript(&server, now - Duration::days(31), "as_off", 1).await;
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Disabled, "{run:?}");
    assert_eq!(run.stores.len(), 1, "{run:?}");
    assert_eq!(run.stores[0].store, "mcp-session-transcripts");
    assert!(none_exist(&server, &expired).await, "transcripts are pruned while audit retention is off");
    assert!(all_exist(&server, &kept).await);
    assert!(exists(&server, "denial-audit/", &audit_40).await);

    // An unreadable configuration fails the run for the audit stores only.
    view(&server, "audit-retention/")
        .put(&StorageEntry { key: "config".into(), value: b"{garbage".to_vec() })
        .await
        .unwrap();
    let expired = put_transcript(&server, now - Duration::days(45), "as_bad_cfg", 1).await;
    let run = audit_retention::run_retention(&server.core, now, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Failed, "{run:?}");
    assert!(run.error.as_deref().is_some_and(|e| e.contains("could not be read")), "{run:?}");
    assert!(none_exist(&server, &expired).await, "the fixed rule does not depend on the configuration");
    assert!(exists(&server, "denial-audit/", &audit_40).await, "no audit record under an unreadable config");

    // The status endpoint reports each store's rule.
    set_config(&server, 90, true).await;
    let mut server = server;
    server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();
    let root = server.root_token.clone();
    let ret = server.read("v2/sys/audit-retention", Some(&root)).unwrap().1;
    let rules = ret["store_rules"].as_array().expect("store_rules");
    let transcripts = rules.iter().find(|r| r["store"] == "mcp-session-transcripts").unwrap();
    assert_eq!((transcripts["rule"].as_str(), transcripts["retention_days"].as_u64()), (Some("fixed"), Some(30)));
    let access = rules.iter().find(|r| r["store"] == "access-audit").unwrap();
    assert_eq!((access["rule"].as_str(), access["retention_days"].as_u64()), (Some("configured"), Some(90)));
}

/// The clock check covers the transcripts too: a runner far ahead of every
/// record in the deployment deletes no transcript, even with retention
/// disabled, until records as recent as its clock exist.
#[tokio::test]
async fn the_clock_check_defers_transcript_pruning() {
    let server = boot("audit_retention_transcripts_clock").await;
    let ahead = Utc::now() + Duration::days(30);
    set_config(&server, 365, false).await;
    let expired = put_transcript(&server, ahead - Duration::days(40), "as_clock", 2).await;

    let run = audit_retention::run_retention(&server.core, ahead, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Refused, "{run:?}");
    let r = run.stores.iter().find(|r| r.store == "mcp-session-transcripts").unwrap();
    assert!(r.error.as_deref().is_some_and(|e| e.contains("clock check")), "{r:?}");
    assert!(all_exist(&server, &expired).await, "nothing is deleted on a suspect clock");

    activity_at(&server, ahead - Duration::hours(1)).await;
    let run = audit_retention::run_retention(&server.core, ahead, fast(500)).await;
    assert_eq!(run.outcome, RunOutcome::Disabled, "{run:?}");
    assert!(none_exist(&server, &expired).await);
}
