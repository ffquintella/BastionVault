//! Tests for the `sql_*` write gate: the pure decision, the persisted
//! records, and the store paths against a real test vault with the cluster
//! topology replaced through the `cfg(test)` seam.

use std::{str::FromStr, sync::Arc};

use super::*;
use crate::{
    modules::policy::{
        policy_store::{PolicyEntry, DEFAULT_POLICY, NAMESPACE_SHARED_POLICY, SHARED_ACCESS_POLICY},
        PolicyStore, PolicyType,
    },
    test_utils::new_unseal_test_bastion_vault,
};

const NOW: u64 = 1_800_000_000;

fn ok(node: &str, at: u64) -> Result<NodeSchemaRecord, String> {
    Ok(NodeSchemaRecord::this_build(node, at))
}

fn raft(ids: &[u64]) -> Result<Membership, String> {
    Ok(Membership::Raft(ids.iter().copied().collect()))
}

fn records(entries: Vec<(&str, Result<NodeSchemaRecord, String>)>) -> Result<NodeRecords, String> {
    Ok(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

// ---- the decision --------------------------------------------------------

#[test]
fn a_standalone_node_opens_on_its_own() {
    let e = evaluate(STANDALONE_NODE, Ok(Membership::Standalone), records(vec![]), NOW);
    assert!(e.ready(), "{e:?}");
    assert_eq!(e.members, vec![STANDALONE_NODE]);
}

#[test]
fn every_raft_member_must_report_and_this_node_counts_from_its_constants() {
    let e = evaluate("1", raft(&[1, 2, 3]), records(vec![("2", ok("2", NOW - 10)), ("3", ok("3", NOW))]), NOW);
    assert!(e.ready(), "{e:?}");
    assert_eq!(e.members, vec!["1", "2", "3"]);
}

/// Membership, not the set of records, decides: a pre-T124 node writes no
/// record, so "every record qualifies" would hold with one still running.
#[test]
fn a_member_without_a_record_keeps_the_gate_closed() {
    let e = evaluate("1", raft(&[1, 2, 3]), records(vec![("2", ok("2", NOW))]), NOW);
    let blocker = e.blocker.expect("closed");
    assert!(blocker.starts_with("node 3: no version record"), "{blocker}");
    let three = e.nodes.iter().find(|n| n.node == "3").unwrap();
    assert!(three.member && three.problem.is_some() && three.record.is_none());
}

#[test]
fn old_schema_old_abi_stale_future_and_misnamed_records_keep_it_closed() {
    let mut old_schema = NodeSchemaRecord::this_build("2", NOW);
    old_schema.policy_schema = 1;
    let mut old_abi = NodeSchemaRecord::this_build("2", NOW);
    old_abi.host_abi_minor = 3;
    let stale = NodeSchemaRecord::this_build("2", NOW - RECORD_TTL_SECS - 1);
    let future = NodeSchemaRecord::this_build("2", NOW + MAX_FUTURE_SKEW_SECS + 1);
    let misnamed = NodeSchemaRecord::this_build("7", NOW);
    for (record, needle) in [
        (old_schema, "policy schema 1"),
        (old_abi, "ABI 1.3"),
        (stale, "old (limit"),
        (future, "in the future"),
        (misnamed, "names node \"7\""),
    ] {
        let e = evaluate("1", raft(&[1, 2]), records(vec![("2", Ok(record))]), NOW);
        let blocker = e.blocker.expect("closed");
        assert!(blocker.contains(needle), "{needle:?} not in {blocker}");
    }
    // The edges themselves still qualify.
    for record in [
        NodeSchemaRecord::this_build("2", NOW - RECORD_TTL_SECS),
        NodeSchemaRecord::this_build("2", NOW + MAX_FUTURE_SKEW_SECS),
    ] {
        assert!(evaluate("1", raft(&[1, 2]), records(vec![("2", Ok(record))]), NOW).ready());
    }
}

#[test]
fn unreadable_state_fails_closed() {
    let e = evaluate("1", Err("metrics timed out".into()), records(vec![("2", ok("2", NOW))]), NOW);
    assert!(e.blocker.unwrap().contains("membership could not be read: metrics timed out"));

    let e = evaluate("1", raft(&[1, 2]), Err("barrier sealed".into()), NOW);
    assert!(e.blocker.unwrap().contains("version records could not be read: barrier sealed"));

    let e = evaluate("1", raft(&[1, 2]), records(vec![("2", Err("its version record is malformed".into()))]), NOW);
    assert!(e.blocker.unwrap().contains("node 2: its version record is malformed"));

    let e = evaluate("1", raft(&[]), records(vec![]), NOW);
    assert!(e.blocker.unwrap().contains("membership is empty"));
}

/// A former member's record is listed, neither required nor able to open it.
#[test]
fn records_of_non_members_are_listed_not_required() {
    let mut ancient = NodeSchemaRecord::this_build("9", NOW - 10_000);
    ancient.policy_schema = 1;
    let e = evaluate("1", raft(&[1]), records(vec![("9", Ok(ancient))]), NOW);
    assert!(e.ready(), "{e:?}");
    let nine = e.nodes.iter().find(|n| n.node == "9").unwrap();
    assert!(!nine.member && nine.problem.is_none());
}

#[test]
fn several_blockers_are_counted() {
    let e = evaluate("1", raft(&[1, 2, 3, 4]), records(vec![]), NOW);
    let blocker = e.blocker.unwrap();
    assert!(blocker.starts_with("node 2:") && blocker.ends_with("(and 2 more)"), "{blocker}");
}

// ---- persisted records -----------------------------------------------------

/// A v1 record, as this build writes it, reads back unchanged.
#[test]
fn a_v1_node_record_reads_back() {
    let stored = br#"{"v":1,"node":"2","policy_schema":2,"host_abi_minor":4,"updated_at":1800000000}"#;
    let record = NodeSchemaRecord::parse(stored).expect("v1 record");
    assert_eq!(record, NodeSchemaRecord::this_build("2", 1_800_000_000));
    let written = serde_json::to_vec(&record).unwrap();
    assert_eq!(NodeSchemaRecord::parse(&written).unwrap(), record);
}

#[test]
fn malformed_node_records_are_refused() {
    for (bytes, needle) in [
        (&b""[..], "malformed"),
        (b"not json", "malformed"),
        (b"[]", "malformed"),
        (br#"{"v":1,"node":"2","policy_schema":"2","host_abi_minor":4,"updated_at":1}"#, "malformed"),
        (br#"{"v":1,"node":"2","host_abi_minor":4,"updated_at":1}"#, "malformed"),
        (br#"{"v":1,"node":"2","policy_schema":-1,"host_abi_minor":4,"updated_at":1}"#, "malformed"),
        (br#"{"v":2,"node":"2","policy_schema":2,"host_abi_minor":4,"updated_at":1}"#, "version 2"),
        (br#"{"v":1,"node":"","policy_schema":2,"host_abi_minor":4,"updated_at":1}"#, "names no node"),
    ] {
        let err = NodeSchemaRecord::parse(bytes).unwrap_err();
        assert!(err.contains(needle), "{needle:?} not in {err}");
    }
}

#[test]
fn a_v1_latch_reads_back_and_malformed_ones_are_refused() {
    let stored = br#"{"v":1,"opened_at":1800000000,"opened_by":"1","members":["1","2"]}"#;
    assert_eq!(SqlGateLatch::parse(stored).expect("v1 latch").members, vec!["1", "2"]);
    for bytes in [
        &b"{}"[..],
        b"garbage",
        br#"{"v":2,"opened_at":1,"opened_by":"1","members":["1"]}"#,
        br#"{"v":1,"opened_at":1,"opened_by":"","members":["1"]}"#,
        br#"{"v":1,"opened_at":1,"opened_by":"1","members":[]}"#,
        br#"{"v":1,"opened_at":"x","opened_by":"1","members":["1"]}"#,
    ] {
        assert!(SqlGateLatch::parse(bytes).is_err(), "{}", String::from_utf8_lossy(bytes));
    }
}

// ---- Raft membership -------------------------------------------------------

/// The shape openraft 0.9 serializes `RaftMetrics::membership_config` to: a
/// joint configuration, plus a learner (4) known only to `nodes`.
#[test]
fn raft_members_are_voters_and_learners() {
    let metrics = json!({
        "id": 1,
        "membership_config": {
            "log_id": null,
            "membership": {
                "configs": [[1, 2], [1, 2, 3]],
                "nodes": { "1": {}, "2": {}, "3": {}, "4": {} }
            }
        }
    });
    assert_eq!(raft_member_ids(&metrics).unwrap(), [1, 2, 3, 4].into_iter().collect());
}

#[test]
fn malformed_raft_membership_is_an_error() {
    for metrics in [
        json!({}),
        json!({ "membership_config": {} }),
        json!({ "membership_config": { "membership": { "configs": [[1]] } } }),
        json!({ "membership_config": { "membership": { "nodes": { "1": {} } } } }),
        json!({ "membership_config": { "membership": { "configs": [[1]], "nodes": { "x": {} } } } }),
        json!({ "membership_config": { "membership": { "configs": [["1"]], "nodes": { "1": {} } } } }),
        json!({ "membership_config": { "membership": { "configs": [1], "nodes": { "1": {} } } } }),
        json!({ "membership_config": { "membership": { "configs": [], "nodes": {} } } }),
    ] {
        assert!(raft_member_ids(&metrics).is_err(), "{metrics}");
    }
}

// ---- gated baselines -------------------------------------------------------

/// The text a closed gate writes parses, names no `sql_*` capability, and
/// differs from the full text by exactly the marked rule.
#[test]
fn gated_baselines_strip_to_a_parsable_text_without_sql() {
    for (name, full) in [("default", DEFAULT_POLICY), ("shared-access", SHARED_ACCESS_POLICY)] {
        let full_policy = Policy::from_str(full).unwrap();
        assert!(policy_names_sql_capabilities(&full_policy), "{name}: the full text carries the SQL rule");

        let compat = without_gated_sql_rules(full).unwrap();
        let compat_policy = Policy::from_str(&compat).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!policy_names_sql_capabilities(&compat_policy), "{name}");
        assert!(!compat.contains("\"sql_"), "{name}: no sql_ capability name survives");
        assert_eq!(compat_policy.paths.len() + 1, full_policy.paths.len(), "{name}: exactly one rule removed");
        assert!(compat.starts_with('\n') && compat.ends_with('\n'), "{name}: framing kept");
    }
    // `namespace-shared` is parsed in process only and carries no markers.
    assert!(without_gated_sql_rules(NAMESPACE_SHARED_POLICY).is_err());
}

#[test]
fn misplaced_markers_are_refused() {
    let rule = "path \"a\" { capabilities = [\"sql_select\"] }";
    for text in [
        "path \"a\" { capabilities = [\"read\"] }".to_string(),
        format!("{SQL_RULE_BEGIN}\n{rule}\n"),
        format!("{rule}\n{SQL_RULE_END}\n"),
        format!("{SQL_RULE_BEGIN}\n{SQL_RULE_BEGIN}\n{rule}\n{SQL_RULE_END}\n"),
        format!("{SQL_RULE_BEGIN}\n{rule}\n{SQL_RULE_END}\n{SQL_RULE_BEGIN}\n{rule}\n{SQL_RULE_END}\n"),
    ] {
        assert!(without_gated_sql_rules(&text).is_err(), "{text}");
    }
}

#[test]
fn only_sql_capabilities_count_as_sql() {
    let plain = Policy::from_str(r#"path "resources/*" { capabilities = ["read", "connect", "deny"] }"#).unwrap();
    assert!(!policy_names_sql_capabilities(&plain));
    for cap in ["sql_select", "sql_script", "sql_admin"] {
        let p = Policy::from_str(&format!(r#"path "r/*" {{ capabilities = ["read", "{cap}"] }}"#)).unwrap();
        assert!(policy_names_sql_capabilities(&p), "{cap}");
    }
}

// ---- against a test vault --------------------------------------------------

/// A pre-T124 `default`, as an older node stores it: no SQL rule, no markers.
const PRE_T124_DEFAULT: &str = r#"
path "auth/token/lookup-self" {
    capabilities = ["read"]
}
"#;

/// A pre-T124 `shared-access`, likewise.
const PRE_T124_SHARED_ACCESS: &str = r#"
path "{{request.namespace}}/secret/*" {
    capabilities = ["read"]
    scopes       = ["shared"]
}
"#;

fn set_topology(store: &PolicyStore, node: &str, membership: Result<Membership, String>) {
    *store.sql_gate_test_topology.lock().unwrap() = Some((node.to_string(), membership));
}

/// A store over a vault whose gate has not opened yet: the unseal of the
/// test vault (one standalone node) latched it, so the latch is removed.
async fn unlatched_store(core: &crate::core::Core) -> Arc<PolicyStore> {
    let store = PolicyStore::new(core).await.unwrap();
    store.sql_gate_view().unwrap().delete(LATCH_KEY).await.unwrap();
    store
}

async fn put_record(store: &PolicyStore, key: &str, value: Vec<u8>) {
    let view = store.sql_gate_view().unwrap();
    view.put(&StorageEntry { key: format!("{NODES_PREFIX}{key}"), value }).await.unwrap();
}

async fn put_fresh_record(store: &PolicyStore, node: &str) {
    put_record(store, node, serde_json::to_vec(&NodeSchemaRecord::this_build(node, unix_now())).unwrap()).await;
}

/// Store `raw` under `name` exactly as an older node writes a policy.
async fn store_as_old_node(store: &PolicyStore, name: &str, raw: &str) {
    let entry = PolicyEntry {
        version: 2,
        raw: raw.to_string(),
        templated: raw.contains("{{"),
        policy_type: PolicyType::Acl,
        sentinal_policy: Default::default(),
    };
    store.get_acl_view().unwrap().put(&StorageEntry::new(name, &entry).unwrap()).await.unwrap();
}

async fn stored_raw(store: &PolicyStore, name: &str) -> String {
    let entry = store.get_acl_view().unwrap().get(name).await.unwrap().expect("stored");
    serde_json::from_slice::<PolicyEntry>(&entry.value).unwrap().raw
}

fn sql_policy(name: &str) -> Policy {
    let mut p =
        Policy::from_str(r#"path "resources/resources/netrisk-db/sql/*" { capabilities = ["sql_select"] }"#).unwrap();
    p.name = name.to_string();
    p
}

fn plain_policy(name: &str) -> Policy {
    let mut p = Policy::from_str(r#"path "secret/data/x" { capabilities = ["read"] }"#).unwrap();
    p.name = name.to_string();
    p
}

fn assert_gate_refusal(err: RvError, needle: &str) {
    match err {
        RvError::ErrResponseStatus(409, msg) => {
            assert!(msg.contains("names sql_* capabilities"), "{msg}");
            assert!(msg.contains(needle), "{needle:?} not in {msg}");
            assert!(msg.contains("v2/sys/policy-schema"), "{msg}");
        }
        other => panic!("expected a 409 gate refusal, got {other:?}"),
    }
}

/// Gate closed (node 2 has never reported): every `sql_*` write is refused
/// with a 409 that names the node, in the root and in a namespace, for a
/// share as for a policy; everything else is written.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_closed_gate_refuses_sql_policy_and_share_writes() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("sql_gate_closed_refuses").await;
    let store = unlatched_store(&core).await;
    set_topology(&store, "1", raft(&[1, 2]));

    let err = store.set_policy(sql_policy("analysts")).await.unwrap_err();
    assert_gate_refusal(err, "node 2: no version record");
    let err = store.set_policy_ns(sql_policy("analysts"), "tenant-a").await.unwrap_err();
    assert_gate_refusal(err, "node 2: no version record");
    assert!(store.get_policy("analysts", PolicyType::Acl).await.unwrap().is_none(), "nothing was written");

    store.set_policy(plain_policy("readers")).await.expect("a policy without sql_* is not gated");
    store.set_policy_ns(plain_policy("readers"), "tenant-a").await.unwrap();

    let caps = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let err = require_sql_share_writable(Some(&store), &caps(&["read", " SQL_SELECT "])).await.unwrap_err();
    assert_gate_refusal(err, "node 2");
    require_sql_share_writable(Some(&store), &caps(&["read", "connect"])).await.unwrap();
    // No policy module to ask: an unknown gate is a closed gate.
    let err = require_sql_share_writable(None, &caps(&["sql_select"])).await.unwrap_err();
    assert_gate_refusal(err, "unavailable");
    require_sql_share_writable(None, &caps(&["read"])).await.unwrap();

    assert!(store.read_sql_gate_latch().await.unwrap().is_none(), "a refusal never latches");
}

/// Once node 2 reports, the next `sql_*` write opens the gate, latches it,
/// and upgrades the baselines; the latch then outlives the evidence.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_gate_opens_once_every_member_reports_and_stays_latched() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("sql_gate_opens").await;
    let store = unlatched_store(&core).await;
    set_topology(&store, "1", raft(&[1, 2]));
    store.load_default_acl_policy().await.unwrap();
    // The stored copies already carried sql_* (the vault unsealed latched),
    // so the closed load left them as they were (never stripped).
    assert_eq!(stored_raw(&store, "default").await, DEFAULT_POLICY);

    put_fresh_record(&store, "2").await;
    store.set_policy(sql_policy("analysts")).await.expect("gate open");
    let latch = store.read_sql_gate_latch().await.unwrap().expect("latched");
    assert_eq!((latch.v, latch.opened_by.as_str(), latch.members.clone()), (1, "1", vec!["1".into(), "2".into()]));
    assert!(store.get_policy("analysts", PolicyType::Acl).await.unwrap().is_some());

    // A later unseal (a new store) with node 2 silent again: still open.
    store.sql_gate_view().unwrap().delete("nodes/2").await.unwrap();
    let restarted = PolicyStore::new(&core).await.unwrap();
    set_topology(&restarted, "1", raft(&[1, 2]));
    restarted.set_policy(sql_policy("analysts-2")).await.expect("the latch outlives the heartbeat");
    assert_eq!(restarted.sql_gate_status().await["sql_capabilities_writable"], json!(true));
}

/// The force-load both ways: with the gate closed an older `default` /
/// `shared-access` is replaced by the text without the SQL rule (which any
/// node parses); the heartbeat then opens the gate and upgrades both.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn baselines_load_without_sql_while_closed_and_upgrade_when_open() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("sql_gate_baselines").await;
    let store = unlatched_store(&core).await;
    store_as_old_node(&store, "default", PRE_T124_DEFAULT).await;
    store_as_old_node(&store, "shared-access", PRE_T124_SHARED_ACCESS).await;
    // The pre-T124 record reads back through this build.
    assert_eq!(store.get_policy("default", PolicyType::Acl).await.unwrap().unwrap().raw, PRE_T124_DEFAULT);

    set_topology(&store, "1", raft(&[1, 2]));
    store.load_default_acl_policy().await.unwrap();
    for (name, full) in [("default", DEFAULT_POLICY), ("shared-access", SHARED_ACCESS_POLICY)] {
        let raw = stored_raw(&store, name).await;
        assert_eq!(raw, without_gated_sql_rules(full).unwrap(), "{name}");
        assert!(!policy_names_sql_capabilities(&Policy::from_str(&raw).unwrap()), "{name}");
    }
    let status = store.sql_gate_status().await;
    assert_eq!(status["baselines"], json!({ "default": "without-sql", "shared-access": "without-sql" }));
    assert_eq!(status["sql_capabilities_writable"], json!(false));

    // A heartbeat while node 2 is silent records node 1 and changes nothing.
    store.sql_gate_heartbeat().await;
    let one = NodeSchemaRecord::parse(&store.sql_gate_view().unwrap().get("nodes/1").await.unwrap().unwrap().value);
    assert_eq!(one.unwrap().policy_schema, NODE_POLICY_SCHEMA);
    assert_eq!(stored_raw(&store, "default").await, without_gated_sql_rules(DEFAULT_POLICY).unwrap());

    put_fresh_record(&store, "2").await;
    store.sql_gate_heartbeat().await;
    assert!(store.read_sql_gate_latch().await.unwrap().is_some());
    assert_eq!(stored_raw(&store, "default").await, DEFAULT_POLICY);
    assert_eq!(stored_raw(&store, "shared-access").await, SHARED_ACCESS_POLICY);
    let status = store.sql_gate_status().await;
    assert_eq!(status["baselines"], json!({ "default": "with-sql", "shared-access": "with-sql" }));
}

/// Unreadable membership, a malformed member record, a stale one, or a
/// malformed latch: the gate stays closed and says why.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn unreadable_or_malformed_state_fails_closed() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("sql_gate_fails_closed").await;
    let store = unlatched_store(&core).await;

    set_topology(&store, "1", Err("the Raft engine did not return its metrics".into()));
    let err = store.set_policy(sql_policy("a")).await.unwrap_err();
    assert_gate_refusal(err, "membership could not be read");

    set_topology(&store, "1", raft(&[1, 2]));
    put_record(&store, "2", b"{\"v\":1,\"node\":\"2\",\"policy_schema\":\"two\"}".to_vec()).await;
    let err = store.set_policy(sql_policy("a")).await.unwrap_err();
    assert_gate_refusal(err, "node 2: its version record is malformed");

    let stale = NodeSchemaRecord::this_build("2", unix_now() - RECORD_TTL_SECS - 60);
    put_record(&store, "2", serde_json::to_vec(&stale).unwrap()).await;
    assert_gate_refusal(store.set_policy(sql_policy("a")).await.unwrap_err(), "stopped reporting");

    // A malformed latch is not trusted: the evidence decides (closed here).
    let garbage = StorageEntry { key: LATCH_KEY.into(), value: b"opened".to_vec() };
    store.sql_gate_view().unwrap().put(&garbage).await.unwrap();
    assert_gate_refusal(store.set_policy(sql_policy("a")).await.unwrap_err(), "node 2");
    let status = store.sql_gate_status().await;
    assert_eq!(status["sql_capabilities_writable"], json!(false));
    assert!(status["latch_error"].as_str().unwrap().contains("malformed"), "{status:?}");
    assert_eq!(status["membership"], json!("raft"));
    let two = status["nodes"].as_array().unwrap().iter().find(|n| n["node"] == "2").unwrap().clone();
    assert_eq!((two["member"].clone(), two["qualifies"].clone()), (json!(true), json!(false)));

    // ...and when the evidence holds, a valid latch replaces it.
    set_topology(&store, STANDALONE_NODE, Ok(Membership::Standalone));
    store.set_policy(sql_policy("a")).await.expect("standalone opens");
    assert_eq!(store.read_sql_gate_latch().await.unwrap().unwrap().members, vec![STANDALONE_NODE]);
}

/// A bare store (no core, no storage) cannot evaluate the gate and refuses.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_bare_store_refuses_sql_writes() {
    let store = PolicyStore::default();
    let check = store.sql_gate_check().await;
    assert!(!check.is_open());
    assert!(store.record_this_node().await.is_err());
}
