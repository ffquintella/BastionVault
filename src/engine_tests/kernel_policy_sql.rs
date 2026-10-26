//! `PolicyGate::sql_privileges` end to end (T124, features/sql-browser.md §3).
//!
//! Drives the gate the way the SQL browser host calls will, with owner, share
//! and asset-group qualifiers resolved from storage and refusals read back
//! from the denial store. Here because it looks the policy module up by type.

use std::sync::Arc;

use serde_json::json;

use super::kernel_policy_deny::{user, write, write_policy};
use crate::{
    core::Core,
    kernel_api::policy::{PolicyGate, SqlCapability, SqlCheck, SqlPurpose, SqlTarget, SqlVerdict},
    logical::{Auth, Request},
    modules::{
        identity::{EntityStore, SecretShare, ShareStore},
        policy::PolicyModule,
        system::denial_audit_store::{DenialAuditStore, SQL_PRIVILEGE_REASON},
    },
    test_utils::new_unseal_test_bastion_vault,
};

const PLUGIN: &str = "dbms-management";

fn gate(core: &Arc<Core>) -> Arc<PolicyModule> {
    core.module_manager().get_module::<PolicyModule>("policy").expect("policy module")
}

/// The caller as a plugin invocation carries it: its policies and entity.
fn caller(policies: &[&str], entity_id: &str) -> Request {
    let mut auth = Auth { policies: policies.iter().map(|p| p.to_string()).collect(), ..Default::default() };
    auth.display_name = "userpass-ana".into();
    auth.metadata.insert("entity_id".into(), entity_id.into());
    let mut req = Request::new("dbms/v2/sessions/s1/execute");
    req.auth = Some(auth);
    req
}

fn checks(caps: &[(SqlCapability, SqlTarget)]) -> Vec<SqlCheck> {
    caps.iter().map(|(c, t)| SqlCheck { capability: *c, target: t.clone() }).collect()
}

fn users_table() -> SqlTarget {
    SqlTarget::Object { catalog: "netrisk".into(), schema: "public".into(), object: "users".into() }
}

fn allowed(verdicts: &[SqlVerdict]) -> Vec<bool> {
    verdicts.iter().map(|v| v.allowed).collect()
}

async fn entity_of(core: &Arc<Core>, name: &str) -> String {
    let entities = EntityStore::new(core).await.unwrap();
    entities.get_by_alias_ns("userpass/", name, "").await.unwrap().expect("entity after login").id
}

async fn share(core: &Arc<Core>, kind: &str, target: &str, grantee: &str, caps: &[&str]) -> Result<(), String> {
    let shares = ShareStore::new(core).await.unwrap();
    shares
        .set_share(SecretShare {
            target_kind: kind.into(),
            target_path: target.into(),
            grantee_kind: String::new(),
            grantee_entity_id: grantee.into(),
            granted_by_entity_id: "root".into(),
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            granted_at: String::new(),
            expires_at: String::new(),
        })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn sql_denials(core: &Arc<Core>) -> Vec<crate::modules::system::denial_audit_store::DenialAuditEntry> {
    let store = DenialAuditStore::from_core(core.as_ref()).unwrap();
    store.list_all().await.unwrap().into_iter().filter(|e| e.reason == SQL_PRIVILEGE_REASON).collect()
}

/// A share on the resource conveys exactly the `sql_*` entries it names,
/// through the shipped `default` baseline, resource-wide; every refusal of
/// an enforcing batch lands in the denial store with actor, namespace, path,
/// capability and plugin; a display batch records nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_privileges_follow_the_share_and_record_refusals() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sql_privileges_follow_the_share").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let _ = user(&core, &root, "ana", "default").await;
    let ana = entity_of(&core, "ana").await;

    let batch = checks(&[
        (SqlCapability::Select, SqlTarget::Server),
        (SqlCapability::Select, users_table()),
        (SqlCapability::Update, users_table()),
    ]);
    let req = caller(&["default"], &ana);

    let none = gate(&core).sql_privileges(&req, SqlPurpose::Display, "netrisk-db", &batch).await.unwrap();
    assert_eq!(allowed(&none), [false, false, false], "no share, no privilege");
    assert!(sql_denials(&core).await.is_empty(), "a display batch recorded a refusal");

    // `read` and `connect` on the share convey no SQL privilege.
    share(&core, "resource", "netrisk-db", &ana, &["read", "connect"]).await.unwrap();
    let v = gate(&core).sql_privileges(&req, SqlPurpose::Display, "netrisk-db", &batch).await.unwrap();
    assert_eq!(allowed(&v), [false, false, false]);

    share(&core, "resource", "netrisk-db", &ana, &["sql_select"]).await.unwrap();
    let v =
        gate(&core).sql_privileges(&req, SqlPurpose::Enforce { plugin: PLUGIN }, "NetRisk-DB", &batch).await.unwrap();
    assert_eq!(allowed(&v), [true, true, false]);
    assert_eq!(v[2].path, "resources/resources/netrisk-db/sql/objects/netrisk/public/users");
    assert!(!v[2].denied_by_deny);

    let denials = sql_denials(&core).await;
    assert_eq!(denials.len(), 1, "{denials:?}");
    let d = &denials[0];
    assert_eq!(d.capability, "sql_update");
    assert_eq!(d.plugin, PLUGIN);
    assert_eq!(d.path, v[2].path);
    assert_eq!(d.namespace, "");
    assert_eq!(d.operation, "sql");
    assert_eq!(d.user, "userpass-ana");
    assert!(d.authenticated);
}

/// An asset-group share reaches every member resource; a deny on one
/// resource revokes it there, and the verdict says the deny decided.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_privileges_through_an_asset_group_and_deny_wins() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sql_privileges_asset_group_deny").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write(&core, &root, "resource-group/groups/prod-dbs", json!({ "members": "netrisk-db,pci-db" })).await;
    write_policy(
        &core,
        &root,
        "pci-deny",
        "path \"resources/resources/pci-db/sql/*\" {\n  capabilities = [\"deny\"]\n}\n",
    )
    .await;
    let _ = user(&core, &root, "bob", "default").await;
    let bo = entity_of(&core, "bob").await;
    share(&core, "asset-group", "prod-dbs", &bo, &["sql_select", "sql_drop"]).await.unwrap();

    let batch = checks(&[(SqlCapability::Drop, users_table()), (SqlCapability::Select, SqlTarget::Server)]);
    let g = gate(&core);
    let ok = g.sql_privileges(&caller(&["default"], &bo), SqlPurpose::Display, "netrisk-db", &batch).await.unwrap();
    assert_eq!(allowed(&ok), [true, true], "the asset-group share reaches its member");

    let pci =
        g.sql_privileges(&caller(&["default", "pci-deny"], &bo), SqlPurpose::Display, "pci-db", &batch).await.unwrap();
    assert_eq!(allowed(&pci), [false, false], "a deny was overridden by a share");
    assert!(pci.iter().all(|v| v.denied_by_deny));

    let outside = g.sql_privileges(&caller(&["default"], &bo), SqlPurpose::Display, "other-db", &batch).await.unwrap();
    assert_eq!(allowed(&outside), [false, false], "the share reached a resource outside the group");
}

/// SQL capabilities are refused, not dropped, on targets other than
/// resources and asset groups.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_share_vocabulary_is_refused_on_other_targets() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_sql_share_vocabulary_refused").await;
    for (kind, target) in [("kv-secret", "secret/team/x"), ("file", "0b6c4f9e-0000-4000-8000-000000000001")] {
        let err = share(&core, kind, target, "some-entity", &["read", "sql_select"]).await.unwrap_err();
        assert!(err.contains("can only be granted on resource and asset-group targets"), "{kind}: {err}");
        let shares = ShareStore::new(&core).await.unwrap();
        assert!(
            shares.list_shares_for_grantee("some-entity").await.unwrap().is_empty(),
            "{kind}: a refused share was written"
        );
    }
}

/// Fail closed: every malformed batch is an error, never a verdict.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_privileges_fail_closed() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_sql_privileges_fail_closed").await;
    let g = gate(&core);
    let batch = checks(&[(SqlCapability::Select, SqlTarget::Server)]);
    let req = caller(&["default"], "e1");

    let mut anonymous = req.clone();
    anonymous.auth = None;
    assert!(g.sql_privileges(&anonymous, SqlPurpose::Display, "db", &batch).await.is_err(), "no caller");
    for bad in ["", "a/b", "*", "+", ".."] {
        assert!(g.sql_privileges(&req, SqlPurpose::Display, bad, &batch).await.is_err(), "resource {bad:?}");
    }
    assert!(
        g.sql_privileges(&req, SqlPurpose::Enforce { plugin: " " }, "db", &batch).await.is_err(),
        "an enforcing batch must name its plugin"
    );
    let mut lost = req.clone();
    lost.namespace_path = Some("no-such-namespace".into());
    assert!(g.sql_privileges(&lost, SqlPurpose::Display, "db", &batch).await.is_err(), "unknown namespace");
    let huge = vec![batch[0].clone(); crate::kernel_api::policy::SQL_MAX_CHECKS + 1];
    assert!(g.sql_privileges(&req, SqlPurpose::Display, "db", &huge).await.is_err(), "oversized batch");

    // The root token passes everything; an empty batch is an empty answer.
    let root_req = caller(&["root"], "");
    let v = g.sql_privileges(&root_req, SqlPurpose::Display, "db", &batch).await.unwrap();
    assert_eq!(allowed(&v), [true]);
    assert!(g.sql_privileges(&req, SqlPurpose::Display, "db", &[]).await.unwrap().is_empty());
}

/// Inside a namespace the synthetic path carries the namespace, and the
/// refusal records it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_privileges_inside_a_namespace() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sql_privileges_inside_a_namespace").await;
    write(&core, &root, "sys/namespaces/tenant", json!({})).await;
    let mut req = caller(&["default"], "e1");
    req.namespace_path = Some("tenant".into());
    let batch = checks(&[(SqlCapability::Script, SqlTarget::Server)]);
    let v = gate(&core).sql_privileges(&req, SqlPurpose::Enforce { plugin: PLUGIN }, "db", &batch).await.unwrap();
    assert_eq!(allowed(&v), [false]);
    assert_eq!(v[0].path, "tenant/resources/resources/db/sql/server");
    let denials = sql_denials(&core).await;
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].namespace, "tenant");
    assert_eq!(denials[0].capability, "sql_script");
}
