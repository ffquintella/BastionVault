//! Precomputed dashboard statistics and the bounded `sys/audit/events`
//! (features/audit-retention-and-dashboard-stats.md, T133, T134).
//!
//! Here rather than in `bv-kernel` because these tests reach the system module
//! by type (`get_module::<SystemModule>`) to force a statistics refresh, which
//! only resolves where the vault is constructed — see the `TypeId` note in
//! `mod.rs`. Three of them are the dashboard-counter tests that used to live in
//! `bv-kernel`'s system module: the summary no longer computes anything per
//! request, so each now refreshes the record before it reads.

use std::{
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Map, Value};

use crate::{
    kernel_api::VaultCtx,
    modules::{
        credential::login_audit_store::{LoginAuditEntry, LoginAuditStore},
        system::{
            audit_retention,
            dashboard_stats::{self, DashboardStatsRecord, RecentAuditEvent, StoredStats},
            denial_audit_store::{DenialAuditEntry, DenialAuditStore},
            housekeeping, SystemBackend, SystemModule,
        },
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
/// the unseal) finish, so it cannot write over what a test plants afterwards.
/// The next tick is a minute away.
async fn wait_for_startup_tick(server: &TestHttpServer) {
    let deadline = Instant::now() + StdDuration::from_secs(30);
    loop {
        let stats_ready = matches!(dashboard_stats::load(&server.core).await, Ok(StoredStats::Ready(_)));
        let armed =
            matches!(audit_retention::load_status(&server.core).await, Ok(audit_retention::StoredStatus::Present(_)));
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

fn summary(server: &TestHttpServer, token: &str) -> Value {
    let (status, ret) = server.read("sys/dashboard/summary", Some(token)).unwrap();
    assert_eq!(status, 200, "summary read failed: {ret:?}");
    ret
}

/// Percent-encode the `+` of an RFC3339 offset for a query string.
fn q(ts: &str) -> String {
    ts.replace('+', "%2B")
}

fn nanos_key(t: DateTime<Utc>) -> String {
    format!("{:020}", t.timestamp_nanos_opt().unwrap())
}

/// Append a denial stamped at `t` straight into the replicated store, keyed the
/// way the store keys its own appends — what a record written `t` ago looks like.
async fn put_denial_at(server: &TestHttpServer, t: DateTime<Utc>, path: &str) {
    let view = server.core.system_view().unwrap().new_sub_view("denial-audit/");
    let entry = DenialAuditEntry {
        ts: t.to_rfc3339(),
        user: "seeded".into(),
        machine: String::new(),
        path: path.into(),
        operation: "read".into(),
        authenticated: true,
        remote_addr: String::new(),
        reason: "policy".into(),
    };
    view.put(&StorageEntry { key: nanos_key(t), value: serde_json::to_vec(&entry).unwrap() }).await.unwrap();
}

async fn put_failed_login_at(server: &TestHttpServer, t: DateTime<Utc>, username: &str) {
    let view = server.core.system_view().unwrap().new_sub_view("login-audit/");
    let entry = LoginAuditEntry {
        ts: t.to_rfc3339(),
        username: username.into(),
        mount: "auth/pass/".into(),
        success: false,
        action: "login".into(),
        remote_addr: String::new(),
        details: "bad password".into(),
    };
    view.put(&StorageEntry { key: nanos_key(t), value: serde_json::to_vec(&entry).unwrap() }).await.unwrap();
}

fn events_of(ret: &Value) -> Vec<Value> {
    ret.get("events").and_then(|v| v.as_array()).cloned().unwrap_or_else(|| panic!("no events: {ret:?}"))
}

/// `sys/dashboard/summary` returns the operational snapshot: an
/// unsealed/initialized seal block, non-zero secret-engine and policy counts,
/// and — once the statistics are refreshed — a 24h audit total that includes a
/// policy's create event, with the histogram and recent rows alongside.
#[tokio::test]
async fn summary_basic_after_a_refresh() {
    let server = boot("dash_stats_summary_basic").await;
    let root = server.root_token.clone();

    let (status, _) = server
        .write(
            "sys/policies/acl/dash-test-pol",
            obj(json!({ "policy": r#"path "secret/*" { capabilities = ["read"] }"# })),
            None,
        )
        .unwrap();
    assert!(status == 200 || status == 204);

    system_backend(&server).refresh_dashboard_stats().await.expect("refresh");
    let ret = summary(&server, &root);

    let seal = ret.get("seal").and_then(|v| v.as_object()).expect("seal block");
    assert_eq!(seal.get("sealed").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(seal.get("initialized").and_then(|v| v.as_bool()), Some(true));
    let counts = ret.get("counts").and_then(|v| v.as_object()).expect("counts block");
    assert!(counts.get("secret_mounts").and_then(|v| v.as_u64()).unwrap_or(0) >= 1, "{ret:?}");
    assert!(counts.get("policies").and_then(|v| v.as_u64()).unwrap_or(0) >= 1, "{ret:?}");

    let total = ret["audit_24h"]["total"].as_u64().unwrap_or(0);
    assert!(total >= 1, "the policy create should be in the 24h total: {ret:?}");

    let stats = &ret["audit_stats"];
    assert_eq!(stats["state"], "ready", "{ret:?}");
    assert_eq!(stats["version"], 1);
    assert!(stats["computed_at"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(stats["stale"], false);
    let histogram = stats["histogram_24h"].as_array().expect("histogram");
    assert_eq!(histogram.len(), 24);
    assert_eq!(histogram.iter().filter_map(Value::as_u64).sum::<u64>(), total, "every event is bucketed");
    let recent = stats["recent"].as_array().expect("recent");
    assert!(
        recent.iter().any(|e| e["category"] == "policy" && e["target"] == "dash-test-pol"),
        "the policy create is in the recent rows: {recent:?}"
    );
}

/// A permission-denied request and a failed login flowing through the request
/// path show up in the summary as `audit_24h.denied` and
/// `attention.failed_logins_1h` after the next refresh.
#[tokio::test]
async fn summary_counts_denials_and_failed_logins() {
    let server = boot("dash_stats_denials_and_failed_logins").await;
    let root = server.root_token.clone();

    server.write("sys/auth/pass", obj(json!({ "type": "userpass" })), None).unwrap();
    server
        .write(
            "auth/pass/users/lowpriv",
            obj(json!({ "password": "hunter22XX!", "token_policies": "default", "ttl": 0 })),
            None,
        )
        .unwrap();
    let _ = server.write("auth/pass/login/lowpriv", obj(json!({ "password": "WRONG" })), None);
    let token = server.write("auth/pass/login/lowpriv", obj(json!({ "password": "hunter22XX!" })), None).unwrap().1
        ["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_string();
    let denied = server
        .write(
            "sys/policies/acl/should-be-denied",
            obj(json!({ "policy": r#"path "x" { capabilities = ["read"] }"# })),
            Some(&token),
        )
        .unwrap();
    assert_eq!(denied.0, 403, "low-priv policy write must be forbidden");

    system_backend(&server).refresh_dashboard_stats().await.expect("refresh");
    let ret = summary(&server, &root);
    assert!(ret["audit_24h"]["denied"].as_u64().unwrap_or(0) >= 1, "{ret:?}");
    assert!(ret["attention"]["failed_logins_1h"].as_u64().unwrap_or(0) >= 1, "{ret:?}");
}

/// HA regression: `denied` and `failed_logins_1h` come from the replicated
/// stores, not the per-node in-memory ring. Events are appended straight to
/// the stores, as a peer node's request handling would, bypassing this node's
/// ring.
#[tokio::test]
async fn summary_counters_come_from_storage_not_the_ring() {
    let server = boot("dash_stats_counters_from_storage").await;
    let root = server.root_token.clone();

    let now_secs = Utc::now().timestamp();
    assert_eq!(server.core.stats.denied_24h(now_secs), 0, "ring denials start at zero");
    assert_eq!(server.core.stats.failed_logins_1h(now_secs), 0, "ring failed-logins start at zero");

    let denial_store = DenialAuditStore::from_core(server.core.as_ref()).expect("denial store");
    for path in ["secret/data/a", "secret/data/b"] {
        denial_store
            .append(DenialAuditEntry {
                ts: String::new(),
                user: "peer-node-caller".into(),
                machine: String::new(),
                path: path.into(),
                operation: "read".into(),
                authenticated: true,
                remote_addr: String::new(),
                reason: "policy".into(),
            })
            .await
            .expect("append denial");
    }
    let login_store = LoginAuditStore::from_core(server.core.as_ref()).expect("login store");
    for action in ["login", "logout"] {
        // The logout carries success=false on purpose: the `!success` filter
        // alone would count it, so this proves the `action` guard excludes it.
        login_store
            .append(LoginAuditEntry {
                ts: String::new(),
                username: "peer-node-user".into(),
                mount: "auth/pass/".into(),
                success: false,
                action: action.into(),
                remote_addr: String::new(),
                details: String::new(),
            })
            .await
            .expect("append login event");
    }
    assert_eq!(server.core.stats.denied_24h(now_secs), 0, "ring stays empty");

    system_backend(&server).refresh_dashboard_stats().await.expect("refresh");
    let ret = summary(&server, &root);
    assert_eq!(ret["audit_24h"]["denied"].as_u64(), Some(2), "{ret:?}");
    assert_eq!(ret["attention"]["failed_logins_1h"].as_u64(), Some(1), "the logout is not a failure: {ret:?}");
}

/// The summary serves the stored record as it is: planted values that no
/// computation could produce come back verbatim, so the handler is not
/// recomputing per request.
#[tokio::test]
async fn summary_serves_the_stored_record() {
    let server = boot("dash_stats_serves_stored").await;
    let root = server.root_token.clone();
    let now = Utc::now();

    let planted = DashboardStatsRecord {
        version: dashboard_stats::DASHBOARD_STATS_VERSION,
        computed_at: now.to_rfc3339(),
        window_start: (now - Duration::hours(24)).to_rfc3339(),
        compute_ms: 1,
        audit_24h_total: 4242,
        audit_24h_denied: 17,
        failed_logins_1h: 3,
        histogram_24h: (1..=24).collect(),
        recent: vec![RecentAuditEvent {
            ts: now.to_rfc3339(),
            user: "planted-user".into(),
            machine: String::new(),
            op: "read".into(),
            category: "access".into(),
            target: "planted/target".into(),
            changed_fields: vec!["op=read".into()],
            summary: String::new(),
        }],
        partial: true,
        failed_sources: vec!["ssh-ca".into()],
    };
    dashboard_stats::save(&server.core, &planted).await.unwrap();

    let ret = summary(&server, &root);
    assert_eq!(ret["audit_24h"]["total"], 4242, "{ret:?}");
    assert_eq!(ret["audit_24h"]["denied"], 17);
    assert_eq!(ret["attention"]["failed_logins_1h"], 3);
    let stats = &ret["audit_stats"];
    assert_eq!(stats["state"], "ready");
    assert_eq!(stats["computed_at"], planted.computed_at);
    assert_eq!(stats["histogram_24h"], json!((1..=24).collect::<Vec<u64>>()));
    assert_eq!(stats["recent"][0]["target"], "planted/target");
    assert_eq!(stats["recent"][0]["user"], "planted-user");
    assert!(stats["recent"][0].get("machine").is_none(), "empty machine is omitted");
    assert_eq!(stats["partial"], true, "a partial record says so");
    assert_eq!(stats["failed_sources"], json!(["ssh-ca"]));
}

/// No record ⇒ an explicit "not computed" state, and no counters. The summary
/// does not fall back to scanning the audit stores.
#[tokio::test]
async fn summary_reports_pending_when_no_record_exists() {
    let server = boot("dash_stats_pending_missing").await;
    let root = server.root_token.clone();

    dashboard_stats::delete(&server.core).await.unwrap();
    let ret = summary(&server, &root);
    assert_eq!(ret["audit_stats"]["state"], "pending", "{ret:?}");
    assert_eq!(ret["audit_stats"]["reason"], "not_computed");
    assert!(ret.get("audit_24h").is_none() && ret.get("attention").is_none(), "{ret:?}");
    // The request did not compute one either.
    assert!(matches!(dashboard_stats::load(&server.core).await, Ok(StoredStats::Missing)));
    // The counts that are cheap stay live.
    assert!(ret["counts"]["secret_mounts"].as_u64().unwrap_or(0) >= 1);
}

/// A record of another version is reported as not computed — never decoded by
/// guesswork — and the next housekeeping tick replaces it with a current one.
#[tokio::test]
async fn an_unknown_record_version_is_pending_until_the_runner_rewrites_it() {
    let server = boot("dash_stats_unknown_version").await;
    let root = server.root_token.clone();

    let future = json!({ "version": 99, "computed_at": Utc::now().to_rfc3339(), "audit_24h_total": 1 });
    dashboard_stats::save_raw(&server.core, serde_json::to_vec(&future).unwrap()).await.unwrap();
    let ret = summary(&server, &root);
    assert_eq!(ret["audit_stats"]["state"], "pending", "{ret:?}");
    assert_eq!(ret["audit_stats"]["reason"], "unsupported_version");
    assert!(ret.get("audit_24h").is_none());

    // A corrupt record is reported the same way, with its own reason.
    dashboard_stats::save_raw(&server.core, b"{not json".to_vec()).await.unwrap();
    assert_eq!(summary(&server, &root)["audit_stats"]["reason"], "unreadable");

    let report = housekeeping::tick(
        &system_backend(&server),
        Utc::now(),
        housekeeping::RunnerRole::Single,
        audit_retention::PruneParams { batch_size: 10, pause: StdDuration::ZERO },
    )
    .await;
    assert!(report.stats_refreshed, "{report:?}");
    let ret = summary(&server, &root);
    assert_eq!(ret["audit_stats"]["state"], "ready", "{ret:?}");
    assert_eq!(ret["audit_stats"]["version"], 1);
}

/// The record holds what the old on-the-fly summary computed from the same
/// sources over the same window: total, denials, failed logins in the last
/// hour — checked against `sys/audit/events` over `[now - 24h, now]` on a
/// seeded dataset with events inside and outside both windows.
#[tokio::test]
async fn computed_record_equals_the_on_the_fly_aggregation() {
    let server = boot("dash_stats_equals_on_the_fly").await;
    let root = server.root_token.clone();

    for i in 1..=2 {
        let (status, _) = server
            .write(
                &format!("sys/policies/acl/eq-pol-{i}"),
                obj(json!({ "policy": r#"path "secret/*" { capabilities = ["read"] }"# })),
                None,
            )
            .unwrap();
        assert!(status == 200 || status == 204);
    }
    let base = Utc::now();
    put_denial_at(&server, base - Duration::minutes(5), "secret/data/recent-1").await;
    put_denial_at(&server, base - Duration::minutes(4), "secret/data/recent-2").await;
    put_denial_at(&server, base - Duration::hours(36), "secret/data/old").await; // outside 24h, inside 7d
    put_failed_login_at(&server, base - Duration::minutes(10), "fresh-failure").await;
    put_failed_login_at(&server, base - Duration::hours(2), "older-failure").await; // in 24h, not in 1h

    let now = Utc::now();
    let record = system_backend(&server).compute_dashboard_stats(now).await;

    let window = server
        .read(
            &format!(
                "sys/audit/events?from={}&to={}&limit=100000",
                q(&(now - Duration::hours(24)).to_rfc3339()),
                q(&now.to_rfc3339())
            ),
            Some(&root),
        )
        .unwrap()
        .1;
    let events = events_of(&window);
    let hour_cutoff = (now - Duration::hours(1)).to_rfc3339();
    let expected_denied = events.iter().filter(|e| e["op"] == "denied").count() as u64;
    let expected_failed_1h = events
        .iter()
        .filter(|e| e["op"] == "login-failed" && e["ts"].as_str().unwrap_or("") >= hour_cutoff.as_str())
        .count() as u64;

    assert_eq!(record.audit_24h_total, events.len() as u64, "total: {events:?}");
    assert_eq!(record.audit_24h_denied, expected_denied);
    assert_eq!(record.failed_logins_1h, expected_failed_1h);
    assert_eq!(expected_denied, 2, "the 36h-old denial is outside the window");
    assert_eq!(expected_failed_1h, 1, "the 2h-old failure is outside the hour");
    assert_eq!(record.histogram_24h.iter().sum::<u64>(), record.audit_24h_total);
    assert_eq!(record.computed_at, now.to_rfc3339());

    // Fewer than 20 events in the day, so the recent rows look back 7 days —
    // the 36h-old denial is in them although it is not in the 24h counts.
    let week = server
        .read(
            &format!(
                "sys/audit/events?from={}&to={}&limit={}",
                q(&(now - Duration::days(7)).to_rfc3339()),
                q(&now.to_rfc3339()),
                dashboard_stats::RECENT_LIMIT
            ),
            Some(&root),
        )
        .unwrap()
        .1;
    let expected_recent: Vec<(String, String)> = events_of(&week)
        .iter()
        .map(|e| (e["ts"].as_str().unwrap().to_string(), e["target"].as_str().unwrap().to_string()))
        .collect();
    let got_recent: Vec<(String, String)> = record.recent.iter().map(|e| (e.ts.clone(), e.target.clone())).collect();
    assert_eq!(got_recent, expected_recent);
    assert!(got_recent.iter().any(|(_, target)| target == "secret/data/old"), "{got_recent:?}");
}

/// Without `from`, `sys/audit/events` reads the 24 hours before `to` (or now)
/// instead of every record ever written, and says which bound it applied.
#[tokio::test]
async fn audit_events_without_from_reads_a_bounded_window() {
    let server = boot("audit_events_default_window").await;
    let root = server.root_token.clone();
    let now = Utc::now();
    put_denial_at(&server, now - Duration::minutes(1), "secret/data/fresh").await;
    put_denial_at(&server, now - Duration::hours(36), "secret/data/day-and-a-half").await;

    let targets = |ret: &Value| -> Vec<String> {
        events_of(ret).iter().filter_map(|e| e["target"].as_str().map(str::to_string)).collect()
    };

    let ret = server.read("sys/audit/events", Some(&root)).unwrap().1;
    let got = targets(&ret);
    assert!(got.contains(&"secret/data/fresh".to_string()), "{got:?}");
    assert!(!got.contains(&"secret/data/day-and-a-half".to_string()), "older than 24h must not be read: {got:?}");
    let applied = ret["from"].as_str().expect("the applied lower bound is reported");
    let applied = DateTime::parse_from_rfc3339(applied).unwrap().with_timezone(&Utc);
    let drift = (now - Duration::hours(24) - applied).num_seconds().abs();
    assert!(drift < 120, "default window is 24h back from now, got {applied}");

    // `to` without `from`: the 24h before `to`.
    let ret = server
        .read(&format!("sys/audit/events?to={}", q(&(now - Duration::hours(24)).to_rfc3339())), Some(&root))
        .unwrap()
        .1;
    let got = targets(&ret);
    assert!(got.contains(&"secret/data/day-and-a-half".to_string()), "{got:?}");
    assert!(!got.contains(&"secret/data/fresh".to_string()), "{got:?}");

    // An explicit `from` is honoured as before.
    let ret = server
        .read(&format!("sys/audit/events?from={}", q(&(now - Duration::days(3)).to_rfc3339())), Some(&root))
        .unwrap()
        .1;
    let got = targets(&ret);
    assert!(got.contains(&"secret/data/fresh".to_string()) && got.contains(&"secret/data/day-and-a-half".to_string()));
}

/// Regression (security review): the summary's audit rows and per-hour
/// histogram must need what `sys/audit/events` itself needs — `read` *and*
/// `sudo`, or root. A caller with `read` alone is refused by that endpoint
/// and must not get its 20 newest rows through the summary; it keeps the
/// aggregate counters it could always see.
#[tokio::test]
async fn audit_rows_in_the_summary_need_what_sys_audit_events_needs() {
    let server = boot("dash_stats_detail_gate").await;
    let root = server.root_token.clone();

    for (name, caps) in [("audit-reader", r#"["read"]"#), ("audit-admin", r#"["read", "sudo"]"#)] {
        let (status, ret) = server
            .write(
                &format!("sys/policies/acl/{name}"),
                obj(json!({ "policy": format!("path \"sys/audit/events\" {{ capabilities = {caps} }}") })),
                Some(&root),
            )
            .unwrap();
        assert!(status == 200 || status == 204, "policy {name}: {ret:?}");
    }
    server.write("sys/auth/pass", obj(json!({ "type": "userpass" })), Some(&root)).unwrap();
    let mut tokens = Vec::new();
    for (user, policy) in [("reader", "audit-reader"), ("auditor", "audit-admin")] {
        server
            .write(
                &format!("auth/pass/users/{user}"),
                obj(json!({ "password": "gate-pw-1234", "token_policies": format!("default,{policy}"), "ttl": 0 })),
                Some(&root),
            )
            .unwrap();
        let token = server
            .write(&format!("auth/pass/login/{user}"), obj(json!({ "password": "gate-pw-1234" })), None)
            .unwrap()
            .1["auth"]["client_token"]
            .as_str()
            .expect("client_token")
            .to_string();
        tokens.push(token);
    }
    let (reader, auditor) = (&tokens[0], &tokens[1]);
    // A row the reader must not see.
    put_denial_at(&server, Utc::now() - Duration::minutes(1), "secret/data/sensitive-target").await;
    system_backend(&server).refresh_dashboard_stats().await.expect("refresh");

    // `read` alone: the real endpoint refuses ...
    let (status, ret) = server.read("sys/audit/events", Some(reader)).unwrap();
    assert!(!(200..300).contains(&status), "read without sudo is refused by sys/audit/events: {ret:?}");
    // ... and the summary withholds the rows and the histogram, keeping the
    // counters this caller could see before.
    let ret = summary(&server, reader);
    assert!(ret["audit_24h"]["total"].as_u64().is_some(), "counters keep their prior visibility: {ret:?}");
    assert!(ret["attention"]["failed_logins_1h"].as_u64().is_some(), "{ret:?}");
    let stats = &ret["audit_stats"];
    assert_eq!(stats["state"], "ready", "{ret:?}");
    assert!(stats.get("recent").is_none(), "no audit rows without sudo: {ret:?}");
    assert!(stats.get("histogram_24h").is_none(), "no per-hour histogram without sudo: {ret:?}");
    assert!(!ret.to_string().contains("sensitive-target"), "{ret:?}");

    // `read` + `sudo`: both the endpoint and the summary detail.
    let (status, _) = server.read("sys/audit/events", Some(auditor)).unwrap();
    assert_eq!(status, 200);
    let ret = summary(&server, auditor);
    let recent = ret["audit_stats"]["recent"].as_array().expect("rows with read + sudo");
    assert!(recent.iter().any(|e| e["target"] == "secret/data/sensitive-target"), "{recent:?}");
    assert_eq!(ret["audit_stats"]["histogram_24h"].as_array().map(Vec::len), Some(24));
}
