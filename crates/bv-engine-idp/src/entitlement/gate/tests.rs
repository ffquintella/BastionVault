//! Issue-gate tests: the allow path, every deny path (table-driven), the
//! lifecycle taking effect at the next evaluation, and the audit record of
//! each decision.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use chrono::Duration;

use super::*;
use crate::{
    entitlement::{
        model::EntitlementSource,
        store::{BoundNamespace, EntitlementWrite, EnvironmentWrite},
    },
    posix::store::IdentityWrite,
    storage::Storage,
    test_support::MemStorage,
};

#[derive(Default)]
struct FakeNamespaces {
    map: Mutex<HashMap<String, NamespaceRef>>,
    fail: AtomicBool,
}

#[maybe_async::maybe_async]
impl NamespaceLookup for FakeNamespaces {
    async fn resolve(&self, path: &str) -> Result<Option<NamespaceRef>, RvError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(RvError::ErrString("injected registry failure".into()));
        }
        Ok(self.map.lock().unwrap().get(path).cloned())
    }
}

impl FakeNamespaces {
    fn set(&self, path: &str, uuid: Option<&str>) {
        let mut map = self.map.lock().unwrap();
        match uuid {
            Some(u) => map.insert(path.into(), NamespaceRef { uuid: u.into(), path: path.into() }),
            None => map.remove(path),
        };
    }
}

#[derive(Default)]
struct RecordingAudit {
    events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
    refuse_allow: AtomicBool,
}

#[maybe_async::maybe_async]
impl IssueAuditSink for RecordingAudit {
    async fn record(&self, name: &'static str, event: &IssueEvent, _req: Option<&Request>) -> Result<(), RvError> {
        if name == events::ISSUE && self.refuse_allow.load(Ordering::SeqCst) {
            return Err(RvError::ErrString("injected audit device failure".into()));
        }
        self.events.lock().unwrap().push((name, event.fields()?));
        Ok(())
    }
}

impl RecordingAudit {
    fn take(&self) -> Vec<(&'static str, Map<String, Value>)> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

struct Fixture {
    posix_mem: Arc<MemStorage>,
    posix: Arc<PosixStore>,
    authz_mem: Arc<MemStorage>,
    authz: Arc<EntitlementStore>,
    namespaces: Arc<FakeNamespaces>,
    audit: Arc<RecordingAudit>,
}

impl Fixture {
    fn gate(&self) -> IssueGate {
        IssueGate::new(Some(self.posix.clone()), Some(self.authz.clone()), self.namespaces.clone(), self.audit.clone())
    }
}

fn grant(entity_id: &str, env: &str, roles: &[&str]) -> EntitlementWrite {
    EntitlementWrite {
        entity_id: entity_id.into(),
        environment: env.into(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        not_after: None,
        source: EntitlementSource::Manual,
        granted_by: "root".into(),
    }
}

fn environment(name: &str, ns: &str, roles: &[(&str, &[&str])]) -> EnvironmentWrite {
    EnvironmentWrite {
        name: name.into(),
        namespace: Some(BoundNamespace { path: ns.into(), uuid: format!("u-{ns}") }),
        roles: Some(roles.iter().map(|(r, ps)| (r.to_string(), ps.iter().map(|p| p.to_string()).collect())).collect()),
        description: None,
    }
}

/// alice: active, entitled to prod as sysadmin+dba. dora: disabled, entitled.
/// remy: removed, was entitled. nora: active, no entitlement.
async fn fixture() -> Fixture {
    let posix_mem = MemStorage::new_arc();
    let posix = Arc::new(PosixStore::new(posix_mem.clone() as Arc<dyn Storage>));
    let authz_mem = MemStorage::new_arc();
    let authz = Arc::new(EntitlementStore::new(authz_mem.clone() as Arc<dyn Storage>));
    let namespaces = Arc::new(FakeNamespaces::default());
    namespaces.set("prod", Some("u-prod"));
    namespaces.set("dev", Some("u-dev"));
    let prod_roles: &[(&str, &[&str])] = &[("sysadmin", &["prod-admin", "prod-ro"]), ("dba", &["prod-dba", "prod-ro"])];
    authz.put_environment(environment("prod", "prod", prod_roles)).await.unwrap();
    authz.put_environment(environment("dev", "dev", &[("sysadmin", &["dev-admin"])])).await.unwrap();
    let now = Utc::now();
    for (id, login) in [("e-alice", "alice"), ("e-dora", "dora"), ("e-remy", "remy"), ("e-nora", "nora")] {
        let w = IdentityWrite { entity_id: id.into(), login: Some(login.into()), ..Default::default() };
        posix.create_or_update(w).await.unwrap();
    }
    authz.put_entitlement(&posix, grant("e-alice", "prod", &["sysadmin", "dba"]), now).await.unwrap();
    authz.put_entitlement(&posix, grant("e-dora", "prod", &["dba"]), now).await.unwrap();
    authz.put_entitlement(&posix, grant("e-remy", "prod", &["dba"]), now).await.unwrap();
    posix.transition("e-dora", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Removed, None).await.unwrap();
    Fixture { posix_mem, posix, authz_mem, authz, namespaces, audit: Arc::new(RecordingAudit::default()) }
}

fn ask(entity_id: &str, environment: &str) -> IssueRequest {
    IssueRequest {
        entity_id: entity_id.into(),
        environment: environment.into(),
        roles: None,
        caller_namespace: String::new(),
        provider: "test".into(),
    }
}

/// Exactly one event was recorded, `idp.issue-denied` with this reason.
fn assert_one_denial(fx: &Fixture, reason: DenyReason, label: &str) -> Map<String, Value> {
    let events = fx.audit.take();
    assert_eq!(events.len(), 1, "{label}: {events:?}");
    let (name, fields) = events.into_iter().next().unwrap();
    assert_eq!(name, events::ISSUE_DENIED, "{label}");
    assert_eq!(fields["decision"], "deny", "{label}");
    assert_eq!(fields["reason"], reason.as_str(), "{label}");
    fields
}

#[tokio::test]
async fn allows_an_active_entitled_identity_and_records_it() {
    let fx = fixture().await;
    let gate = fx.gate();
    let grant = gate.authorize(&ask("e-alice", "prod"), None).await.unwrap();
    assert_eq!((grant.login.as_str(), grant.uid, grant.primary_gid), ("alice", 80_000, 80_000));
    assert_eq!((grant.namespace.as_str(), grant.namespace_uuid.as_str()), ("prod", "u-prod"));
    assert_eq!(grant.roles, vec!["dba", "sysadmin"]);
    assert_eq!(grant.policies, vec!["prod-admin", "prod-dba", "prod-ro"]);

    let events = fx.audit.take();
    assert_eq!(events.len(), 1);
    let (name, f) = &events[0];
    assert_eq!(*name, "idp.issue");
    assert_eq!((f["decision"].as_str(), f["reason"].clone()), (Some("allow"), Value::Null));
    assert_eq!(
        (f["entity_id"].as_str(), f["login"].as_str(), f["uid"].as_u64()),
        (Some("e-alice"), Some("alice"), Some(80_000))
    );
    assert_eq!((f["environment"].as_str(), f["namespace"].as_str()), (Some("prod"), Some("prod")));
    assert_eq!((f["provider"].as_str(), f["caller_namespace"].as_str()), (Some("test"), Some("")));
    assert_eq!(f["roles"], serde_json::json!(["dba", "sysadmin"]));
    assert_eq!(f["policies"], serde_json::json!(["prod-admin", "prod-dba", "prod-ro"]));

    // A requested subset narrows the policies; the environment's own
    // namespace may ask as well as root.
    let narrow =
        IssueRequest { roles: Some(vec!["dba".into()]), caller_namespace: "prod".into(), ..ask("e-alice", "prod") };
    let grant = gate.authorize(&narrow, None).await.unwrap();
    assert_eq!(
        (grant.roles, grant.policies),
        (vec!["dba".to_string()], vec!["prod-dba".to_string(), "prod-ro".to_string()])
    );
    let events = fx.audit.take();
    assert_eq!(events[0].1["requested_roles"], serde_json::json!(["dba"]));
}

/// Deny paths that need no change to the fixture.
#[tokio::test]
async fn every_unproven_precondition_is_a_deny() {
    let fx = fixture().await;
    let gate = fx.gate();
    let roles = |r: &[&str]| Some(r.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let cases: Vec<(&str, IssueRequest, DenyReason)> = vec![
        ("malformed entity id", ask("../e-alice", "prod"), DenyReason::InvalidRequest),
        ("upper-case environment", ask("e-alice", "Prod"), DenyReason::InvalidRequest),
        ("no provider", IssueRequest { provider: String::new(), ..ask("e-alice", "prod") }, DenyReason::InvalidRequest),
        (
            "bad caller namespace",
            IssueRequest { caller_namespace: "a//b c".into(), ..ask("e-alice", "prod") },
            DenyReason::InvalidRequest,
        ),
        (
            "empty role request",
            IssueRequest { roles: roles(&[]), ..ask("e-alice", "prod") },
            DenyReason::InvalidRequest,
        ),
        ("no workforce identity", ask("e-ghost", "prod"), DenyReason::NoIdentity),
        ("disabled identity", ask("e-dora", "prod"), DenyReason::IdentityDisabled),
        ("removed identity", ask("e-remy", "prod"), DenyReason::IdentityRemoved),
        ("unknown environment", ask("e-alice", "qa"), DenyReason::UnknownEnvironment),
        ("no entitlement at all", ask("e-nora", "prod"), DenyReason::NotEntitled),
        ("entitled elsewhere only", ask("e-alice", "dev"), DenyReason::NotEntitled),
        (
            "another namespace asks",
            IssueRequest { caller_namespace: "dev".into(), ..ask("e-alice", "prod") },
            DenyReason::NamespaceMismatch,
        ),
        (
            "an unknown namespace asks",
            IssueRequest { caller_namespace: "tenant".into(), ..ask("e-alice", "prod") },
            DenyReason::NamespaceMismatch,
        ),
        (
            "role not entitled",
            IssueRequest { roles: roles(&["dba", "ops"]), ..ask("e-alice", "prod") },
            DenyReason::RoleNotEntitled,
        ),
    ];
    for (label, req, reason) in cases {
        let denied = gate.authorize(&req, None).await.expect_err(label);
        assert_eq!(denied.reason, reason, "{label}");
        assert_one_denial(&fx, reason, label);
    }
}

/// Deny paths that need the stored state, the registry or the audit sink
/// changed first. Each runs on a fresh fixture.
#[derive(Debug, Clone, Copy)]
enum Breakage {
    RetireEnvironment,
    NamespaceDeleted,
    NamespaceRecreated,
    RegistryFails,
    RoleDroppedFromEnvironment,
    IdentityRecordUnknownVersion,
    EnvironmentRecordUnknownField,
    EntitlementRecordGarbage,
    IdentityStoreUnreadable,
    EntitlementStoreUnreadable,
    AuditRefusesAllow,
}

async fn break_it(fx: &Fixture, how: Breakage) {
    match how {
        Breakage::RetireEnvironment => {
            fx.authz.retire_environment("prod").await.unwrap();
        }
        Breakage::NamespaceDeleted => fx.namespaces.set("prod", None),
        Breakage::NamespaceRecreated => fx.namespaces.set("prod", Some("u-prod-2")),
        Breakage::RegistryFails => fx.namespaces.fail.store(true, Ordering::SeqCst),
        Breakage::RoleDroppedFromEnvironment => {
            fx.authz.put_environment(environment("prod", "prod", &[("dba", &["prod-dba"])])).await.unwrap();
        }
        Breakage::IdentityRecordUnknownVersion => {
            let raw = String::from_utf8(fx.posix_mem.raw_get("identities/e-alice").unwrap()).unwrap();
            fx.posix_mem.raw_put("identities/e-alice", raw.replacen("\"version\":1", "\"version\":9", 1).as_bytes());
        }
        Breakage::EnvironmentRecordUnknownField => {
            let raw = String::from_utf8(fx.authz_mem.raw_get("environments/prod").unwrap()).unwrap();
            let raw = raw.replacen("\"version\":1", "\"version\":1,\"allow_all\":true", 1);
            fx.authz_mem.raw_put("environments/prod", raw.as_bytes());
        }
        Breakage::EntitlementRecordGarbage => fx.authz_mem.raw_put("entitlements/e-alice/prod", b"\x00garbage"),
        Breakage::IdentityStoreUnreadable => fx.posix_mem.fail_gets_under(Some("identities/")),
        Breakage::EntitlementStoreUnreadable => fx.authz_mem.fail_gets_under(Some("entitlements/")),
        Breakage::AuditRefusesAllow => fx.audit.refuse_allow.store(true, Ordering::SeqCst),
    }
}

#[tokio::test]
async fn broken_state_is_a_deny_never_a_default_allow() {
    use Breakage::*;
    let cases = [
        (RetireEnvironment, DenyReason::EnvironmentRetired),
        (NamespaceDeleted, DenyReason::NamespaceMissing),
        (NamespaceRecreated, DenyReason::NamespaceReplaced),
        (RegistryFails, DenyReason::NamespaceUnavailable),
        (RoleDroppedFromEnvironment, DenyReason::UnknownRole),
        (IdentityRecordUnknownVersion, DenyReason::StoreError),
        (EnvironmentRecordUnknownField, DenyReason::StoreError),
        (EntitlementRecordGarbage, DenyReason::StoreError),
        (IdentityStoreUnreadable, DenyReason::StoreError),
        (EntitlementStoreUnreadable, DenyReason::StoreError),
        (AuditRefusesAllow, DenyReason::AuditFailed),
    ];
    for (how, reason) in cases {
        let fx = fixture().await;
        let label = format!("{how:?}");
        // The unbroken fixture allows, so the deny below is the breakage's.
        fx.gate().authorize(&ask("e-alice", "prod"), None).await.expect(&label);
        fx.audit.take();
        break_it(&fx, how).await;
        let denied = fx.gate().authorize(&ask("e-alice", "prod"), None).await.expect_err(&label);
        assert_eq!(denied.reason, reason, "{label}");
        assert_one_denial(&fx, reason, &label);
    }

    // Sealed (no stores): denied before anything is read.
    let fx = fixture().await;
    let sealed = IssueGate::new(None, Some(fx.authz.clone()), fx.namespaces.clone(), fx.audit.clone());
    let denied = sealed.authorize(&ask("e-alice", "prod"), None).await.unwrap_err();
    assert_eq!(denied.reason, DenyReason::StoreUnavailable);
    assert_one_denial(&fx, DenyReason::StoreUnavailable, "sealed");
}

#[tokio::test]
async fn lifecycle_and_revocation_apply_at_the_next_evaluation() {
    let fx = fixture().await;
    let gate = fx.gate();
    let alice = ask("e-alice", "prod");
    gate.authorize(&alice, None).await.unwrap();

    fx.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(gate.authorize(&alice, None).await.unwrap_err().reason, DenyReason::IdentityDisabled);
    fx.posix.transition("e-alice", IdentityState::Active, None).await.unwrap();
    gate.authorize(&alice, None).await.unwrap();

    // Revoked mid-way: the very next evaluation is denied.
    fx.authz.delete_entitlement("e-alice", "prod").await.unwrap();
    assert_eq!(gate.authorize(&alice, None).await.unwrap_err().reason, DenyReason::NotEntitled);

    // Time-boxed: allowed before not_after, denied at and after it.
    let now = Utc::now();
    let not_after = now + Duration::hours(1);
    let boxed = EntitlementWrite { not_after: Some(not_after), ..grant("e-alice", "prod", &["dba"]) };
    fx.authz.put_entitlement(&fx.posix, boxed, now).await.unwrap();
    gate.authorize_at(&alice, None, now).await.unwrap();
    for at in [not_after, not_after + Duration::seconds(1)] {
        assert_eq!(gate.authorize_at(&alice, None, at).await.unwrap_err().reason, DenyReason::EntitlementExpired);
    }

    let events = fx.audit.take();
    let names: Vec<&str> = events.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "idp.issue",
            "idp.issue-denied",
            "idp.issue",
            "idp.issue-denied",
            "idp.issue",
            "idp.issue-denied",
            "idp.issue-denied"
        ]
    );
    assert_eq!(events[6].1["not_after"].as_str(), Some(not_after.to_rfc3339().as_str()));
}

#[tokio::test]
async fn denials_bound_caller_input_and_map_to_statuses() {
    let fx = fixture().await;
    let long = "e".repeat(400);
    let denied = fx.gate().authorize(&ask(&long, "prod"), None).await.unwrap_err();
    let fields = assert_one_denial(&fx, DenyReason::InvalidRequest, "long id");
    let recorded = fields["entity_id"].as_str().unwrap();
    assert_eq!(recorded.chars().count(), MAX_EVENT_ARG_LEN + 1);
    assert!(recorded.ends_with('…'));
    assert_eq!(fields["login"], Value::Null);

    for (reason, code) in [
        (denied.reason, 400),
        (DenyReason::NotEntitled, 403),
        (DenyReason::NamespaceMismatch, 403),
        (DenyReason::StoreUnavailable, 503),
        (DenyReason::StoreError, 500),
        (DenyReason::AuditFailed, 500),
    ] {
        match RvError::from(IssueDenied { reason }) {
            RvError::ErrResponseStatus(s, msg) => {
                assert_eq!(s, code, "{reason:?}");
                assert_eq!(msg, format!("identity issuance denied: {}", reason.as_str()));
            }
            other => panic!("{other:?}"),
        }
    }
}
