//! SSH provider tests: the allowed path read back from the certificate,
//! every gate deny producing no certificate, the TTL cap, malformed input,
//! an SSH engine that returns the wrong certificate, and a mutation check
//! showing these tests depend on the gate being called.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};

use chrono::Duration;
use ssh_key::{certificate::Builder, rand_core::OsRng, Algorithm, PrivateKey};

use super::{store::SshConfigUpdate, *};
use crate::{
    entitlement::{
        gate::{DenyReason, IssueAuditSink, IssueEvent, NamespaceLookup},
        model::{Entitlement, EntitlementSource},
        store::{BoundNamespace, EntitlementStore, EntitlementWrite, EnvironmentWrite},
    },
    kernel_api::namespace::NamespaceRef,
    posix::{
        model::IdentityState,
        store::{IdentityWrite, PosixStore},
    },
    storage::Storage,
    test_support::MemStorage,
};

#[derive(Default)]
struct FakeNamespaces {
    map: Mutex<HashMap<String, NamespaceRef>>,
}

#[maybe_async::maybe_async]
impl NamespaceLookup for FakeNamespaces {
    async fn resolve(&self, path: &str) -> Result<Option<NamespaceRef>, RvError> {
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
        if name == "idp.issue" && self.refuse_allow.load(Ordering::SeqCst) {
            return Err(RvError::ErrString("injected audit failure".into()));
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

/// How the stand-in SSH engine misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Honest,
    Refuse,
    DropUidExtension,
    WrongPrincipal,
    LongerTtl,
    OtherKey,
    HostCert,
    SerialZero,
}

/// Signs like the SSH engine's CA path, with an in-memory Ed25519 CA.
struct FakeSigner {
    ca: PrivateKey,
    mode: Mutex<Mode>,
    calls: AtomicUsize,
    next_serial: AtomicU64,
    targets: Mutex<Vec<String>>,
}

impl FakeSigner {
    fn new() -> Self {
        Self {
            ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
            mode: Mutex::new(Mode::Honest),
            calls: AtomicUsize::new(0),
            next_serial: AtomicU64::new(0x1000),
            targets: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn ca_line(&self) -> String {
        self.ca.public_key().to_openssh().unwrap()
    }
}

#[maybe_async::maybe_async]
impl SshSigner for FakeSigner {
    async fn sign(&self, target: &SignTarget<'_>, body: Map<String, Value>) -> Result<String, RvError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets
            .lock()
            .unwrap()
            .push(format!("{}|{}|{}|{}", target.namespace, target.namespace_uuid, target.mount, target.role));
        let mode = *self.mode.lock().unwrap();
        if mode == Mode::Refuse {
            return Err(RvError::ErrString("role `idp` has empty allowed_users; sign refused".into()));
        }
        let text = |k: &str| body[k].as_str().unwrap().to_string();
        let mut key = PublicKey::from_openssh(&text("public_key")).unwrap();
        if mode == Mode::OtherKey {
            key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap().public_key().clone();
        }
        let mut ttl: u64 = text("ttl").trim_end_matches('s').parse().unwrap();
        if mode == Mode::LongerTtl {
            ttl += 3600;
        }
        let now = unix_secs(Utc::now());
        let mut b = Builder::new_with_random_nonce(&mut OsRng, key.key_data().clone(), now - 30, now + ttl).unwrap();
        let serial = if mode == Mode::SerialZero { 0 } else { self.next_serial.fetch_add(1, Ordering::SeqCst) };
        b.serial(serial).unwrap();
        b.key_id(text("key_id")).unwrap();
        b.cert_type(if mode == Mode::HostCert { CertType::Host } else { CertType::User }).unwrap();
        b.valid_principal(if mode == Mode::WrongPrincipal { "root".to_string() } else { text("valid_principals") })
            .unwrap();
        b.extension("permit-pty", "").unwrap();
        for (k, v) in body["extensions"].as_object().unwrap() {
            if mode == Mode::DropUidExtension && k == EXT_UID {
                continue;
            }
            b.extension(k.clone(), v.as_str().unwrap().to_string()).unwrap();
        }
        Ok(b.sign(&self.ca).unwrap().to_openssh().unwrap())
    }
}

struct Fx {
    posix: Arc<PosixStore>,
    authz: Arc<EntitlementStore>,
    authz_mem: Arc<MemStorage>,
    ssh: SshStore,
    namespaces: Arc<FakeNamespaces>,
    audit: Arc<RecordingAudit>,
    signer: FakeSigner,
    cfg: SshProviderConfig,
}

impl Fx {
    fn gate(&self) -> IssueGate {
        IssueGate::new(Some(self.posix.clone()), Some(self.authz.clone()), self.namespaces.clone(), self.audit.clone())
    }

    async fn sign(&self, req: &SignRequest) -> Result<IssuedCert, RvError> {
        issue(&self.gate(), &self.signer, &self.ssh, &self.cfg, req, None).await
    }

    async fn recorded(&self) -> usize {
        self.ssh.list_certs().await.unwrap().len()
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

/// alice 80000 (prod sysadmin+dba, dev sysadmin, stage ops), bob 80001
/// (prod dba), dora 80002 (disabled), remy 80003 (removed), nora 80004
/// (no entitlement), exp 80005 (prod, expired).
async fn fixture() -> Fx {
    let posix = Arc::new(PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
    let authz_mem = MemStorage::new_arc();
    let authz = Arc::new(EntitlementStore::new(authz_mem.clone() as Arc<dyn Storage>));
    let namespaces = Arc::new(FakeNamespaces::default());
    for ns in ["prod", "dev", "stage", "old"] {
        namespaces.set(ns, Some(&format!("u-{ns}")));
    }
    authz
        .put_environment(environment("prod", "prod", &[("sysadmin", &["prod-admin"]), ("dba", &["prod-dba"])]))
        .await
        .unwrap();
    authz.put_environment(environment("dev", "dev", &[("sysadmin", &["dev-admin"])])).await.unwrap();
    authz.put_environment(environment("stage", "stage", &[("ops", &["stage-ops"])])).await.unwrap();
    authz.put_environment(environment("old", "old", &[("ops", &["old-ops"])])).await.unwrap();
    let now = Utc::now();
    for (id, login) in [
        ("e-alice", "alice"),
        ("e-bob", "bob"),
        ("e-dora", "dora"),
        ("e-remy", "remy"),
        ("e-nora", "nora"),
        ("e-exp", "exp"),
    ] {
        let w = IdentityWrite { entity_id: id.into(), login: Some(login.into()), ..Default::default() };
        posix.create_or_update(w).await.unwrap();
    }
    for (id, env, roles) in [
        ("e-alice", "prod", &["sysadmin", "dba"][..]),
        ("e-alice", "dev", &["sysadmin"][..]),
        ("e-alice", "stage", &["ops"][..]),
        ("e-alice", "old", &["ops"][..]),
        ("e-bob", "prod", &["dba"][..]),
        ("e-dora", "prod", &["dba"][..]),
        ("e-remy", "prod", &["dba"][..]),
    ] {
        authz.put_entitlement(&posix, grant(id, env, roles), now).await.unwrap();
    }
    // An entitlement that has since expired, written as stored.
    let expired = Entitlement {
        version: 1,
        entity_id: "e-exp".into(),
        environment: "prod".into(),
        roles: vec!["dba".into()],
        not_after: Some(now - Duration::hours(1)),
        source: EntitlementSource::Manual,
        granted_by: "root".into(),
        granted_at: now - Duration::days(1),
    };
    authz_mem.raw_put("entitlements/e-exp/prod", &serde_json::to_vec(&expired).unwrap());
    authz.retire_environment("old").await.unwrap();
    posix.transition("e-dora", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Removed, None).await.unwrap();

    let ssh = SshStore::new(MemStorage::new_arc() as Arc<dyn Storage>);
    let cfg = ssh.put_config(SshConfigUpdate::default(), now).await.unwrap();
    Fx {
        posix,
        authz,
        authz_mem,
        ssh,
        namespaces,
        audit: Arc::new(RecordingAudit::default()),
        signer: FakeSigner::new(),
        cfg,
    }
}

fn client_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap().public_key().to_openssh().unwrap()
}

fn ask(entity_id: &str, environment: &str, public_key: &str) -> SignRequest {
    SignRequest {
        entity_id: entity_id.into(),
        environment: environment.into(),
        public_key: public_key.into(),
        ttl_secs: None,
        roles: None,
        caller_namespace: String::new(),
    }
}

fn status(e: RvError) -> u16 {
    match e {
        RvError::ErrResponseStatus(s, _) => s,
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test]
async fn allowed_sign_carries_the_identity_in_the_certificate() {
    let fx = fixture().await;
    let key = client_key();
    let issued = fx.sign(&ask("e-alice", "prod", &key)).await.unwrap();

    let cert = Certificate::from_openssh(&issued.signed_key).unwrap();
    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.valid_principals(), ["alice".to_string()]);
    assert_eq!(cert.key_id(), "bv:e-alice:alice:uid=80000:env=prod");
    let ext = |k: &str| cert.extensions().get(k).cloned();
    assert_eq!(ext(EXT_UID).as_deref(), Some("80000"));
    assert_eq!(ext(EXT_GID).as_deref(), Some("80000"));
    assert_eq!(ext(EXT_ENV).as_deref(), Some("prod"));
    assert_eq!(ext(EXT_ROLES).as_deref(), Some("dba,sysadmin"));
    assert_eq!(cert.public_key(), PublicKey::from_openssh(&key).unwrap().key_data());
    assert_eq!((issued.serial, issued.login.as_str(), issued.uid), (cert.serial(), "alice", 80000));
    let lifetime = cert.valid_before() - unix_secs(Utc::now());
    assert!(lifetime <= fx.cfg.default_ttl_secs && lifetime + 60 > fx.cfg.default_ttl_secs, "{lifetime}");

    // Signed in the environment's own namespace, by the configured role.
    assert_eq!(fx.signer.targets.lock().unwrap().as_slice(), ["prod|u-prod|ssh|idp".to_string()]);
    // Recorded before it was returned, against the CA that signed it.
    let recorded = fx.ssh.certs_of("e-alice").await.unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        (recorded[0].serial_u64().unwrap(), recorded[0].ca_public_key.as_str()),
        (cert.serial(), fx.signer.ca_line().as_str())
    );
    assert_eq!(recorded[0].revoked_at, None);
    // The gate's event is the issuance record.
    let events = fx.audit.take();
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].0, events[0].1["provider"].as_str()), ("idp.issue", Some("ssh")));

    // A requested role subset narrows the roles extension.
    let narrow = SignRequest { roles: Some(vec!["dba".into()]), ..ask("e-alice", "prod", &key) };
    let issued = fx.sign(&narrow).await.unwrap();
    let cert = Certificate::from_openssh(&issued.signed_key).unwrap();
    assert_eq!(cert.extensions().get(EXT_ROLES).map(String::as_str), Some("dba"));
}

#[tokio::test]
async fn uid_and_login_are_identical_across_environments() {
    let fx = fixture().await;
    let key = client_key();
    let prod = Certificate::from_openssh(&fx.sign(&ask("e-alice", "prod", &key)).await.unwrap().signed_key).unwrap();
    let dev = Certificate::from_openssh(&fx.sign(&ask("e-alice", "dev", &key)).await.unwrap().signed_key).unwrap();
    assert_eq!(prod.valid_principals(), dev.valid_principals());
    assert_eq!(prod.extensions().get(EXT_UID), dev.extensions().get(EXT_UID));
    assert_eq!(prod.extensions().get(EXT_GID), dev.extensions().get(EXT_GID));
    assert_eq!(dev.key_id(), "bv:e-alice:alice:uid=80000:env=dev");
    let targets = fx.signer.targets.lock().unwrap().clone();
    assert_eq!(targets, ["prod|u-prod|ssh|idp", "dev|u-dev|ssh|idp"]);
}

/// Every deny the gate can return ends with no signature and no record.
#[tokio::test]
async fn every_gate_deny_issues_nothing() {
    let fx = fixture().await;
    let key = client_key();
    let with = |f: fn(&mut SignRequest)| {
        let mut r = ask("e-alice", "prod", &key);
        f(&mut r);
        r
    };
    let cases: Vec<(&str, SignRequest, DenyReason)> = vec![
        ("malformed entity", ask("../x", "prod", &key), DenyReason::InvalidRequest),
        ("no identity", ask("e-ghost", "prod", &key), DenyReason::NoIdentity),
        ("disabled identity", ask("e-dora", "prod", &key), DenyReason::IdentityDisabled),
        ("removed identity", ask("e-remy", "prod", &key), DenyReason::IdentityRemoved),
        ("not entitled", ask("e-nora", "prod", &key), DenyReason::NotEntitled),
        ("entitled elsewhere", ask("e-bob", "dev", &key), DenyReason::NotEntitled),
        ("expired entitlement", ask("e-exp", "prod", &key), DenyReason::EntitlementExpired),
        ("unknown environment", ask("e-alice", "qa", &key), DenyReason::UnknownEnvironment),
        ("retired environment", ask("e-alice", "old", &key), DenyReason::EnvironmentRetired),
        ("role not entitled", with(|r| r.roles = Some(vec!["ops".into()])), DenyReason::RoleNotEntitled),
        ("other namespace", with(|r| r.caller_namespace = "dev".into()), DenyReason::NamespaceMismatch),
    ];
    for (label, req, reason) in cases {
        let err = fx.sign(&req).await.expect_err(label);
        assert!(matches!(err, RvError::ErrResponseStatus(_, ref m) if m.contains(reason.as_str())), "{label}: {err:?}");
        let events = fx.audit.take();
        assert_eq!(events.len(), 1, "{label}");
        assert_eq!(
            (events[0].0, events[0].1["reason"].as_str()),
            ("idp.issue-denied", Some(reason.as_str())),
            "{label}"
        );
    }

    // Namespace gone, then recreated under the same path.
    fx.namespaces.set("stage", None);
    fx.sign(&ask("e-alice", "stage", &key)).await.unwrap_err();
    fx.namespaces.set("stage", Some("u-stage-2"));
    fx.sign(&ask("e-alice", "stage", &key)).await.unwrap_err();
    // An audit device refusing the allow event.
    fx.audit.refuse_allow.store(true, Ordering::SeqCst);
    assert_eq!(status(fx.sign(&ask("e-alice", "prod", &key)).await.unwrap_err()), 500);
    fx.audit.refuse_allow.store(false, Ordering::SeqCst);
    // Sealed: no stores behind the gate.
    let sealed = IssueGate::new(None, None, fx.namespaces.clone(), fx.audit.clone());
    let err = issue(&sealed, &fx.signer, &fx.ssh, &fx.cfg, &ask("e-alice", "prod", &key), None).await.unwrap_err();
    assert_eq!(status(err), 503);
    // A store read failure.
    fx.authz_mem.fail_gets_under(Some("entitlements/"));
    assert_eq!(status(fx.sign(&ask("e-alice", "prod", &key)).await.unwrap_err()), 500);
    fx.authz_mem.fail_gets_under(None);

    assert_eq!(fx.signer.calls(), 0, "the SSH engine was asked to sign after a deny");
    assert_eq!(fx.recorded().await, 0);
}

/// Disabling takes effect at the next sign; reinstating restores it.
#[tokio::test]
async fn a_disabled_or_removed_identity_never_receives_a_certificate() {
    let fx = fixture().await;
    let key = client_key();
    fx.sign(&ask("e-bob", "prod", &key)).await.unwrap();
    fx.posix.transition("e-bob", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(status(fx.sign(&ask("e-bob", "prod", &key)).await.unwrap_err()), 403);
    fx.posix.transition("e-bob", IdentityState::Removed, None).await.unwrap();
    assert_eq!(status(fx.sign(&ask("e-bob", "prod", &key)).await.unwrap_err()), 403);
    assert_eq!((fx.signer.calls(), fx.recorded().await), (1, 1));
}

#[tokio::test]
async fn ttl_is_capped_and_checked_on_the_certificate() {
    let mut fx = fixture().await;
    let key = client_key();
    let long = SignRequest { ttl_secs: Some(fx.cfg.max_ttl_secs + 1), ..ask("e-alice", "prod", &key) };
    assert_eq!(status(fx.sign(&long).await.unwrap_err()), 400);
    let short = SignRequest { ttl_secs: Some(10), ..ask("e-alice", "prod", &key) };
    assert_eq!(status(fx.sign(&short).await.unwrap_err()), 400);
    assert!(fx.audit.take().is_empty(), "refused before the gate");

    let exact = SignRequest { ttl_secs: Some(fx.cfg.max_ttl_secs), ..ask("e-alice", "prod", &key) };
    let issued = fx.sign(&exact).await.unwrap();
    assert!(issued.valid_before <= unix_secs(Utc::now()) + fx.cfg.max_ttl_secs);

    // An engine that signs for longer than asked is not trusted.
    fx.signer.set(Mode::LongerTtl);
    assert_eq!(status(fx.sign(&ask("e-alice", "prod", &key)).await.unwrap_err()), 502);
    assert_eq!(fx.recorded().await, 1);

    // The configuration itself is bounded.
    let over = SshConfigUpdate { max_ttl_secs: Some(store::TTL_CEILING_SECS + 1), ..Default::default() };
    assert!(fx.ssh.put_config(over, Utc::now()).await.is_err());
    let inverted = SshConfigUpdate { default_ttl_secs: Some(7200), max_ttl_secs: Some(3600), ..Default::default() };
    assert!(fx.ssh.put_config(inverted, Utc::now()).await.is_err());
    let ok = SshConfigUpdate { default_ttl_secs: Some(300), max_ttl_secs: Some(600), ..Default::default() };
    fx.cfg = fx.ssh.put_config(ok, Utc::now()).await.unwrap();
    assert_eq!((fx.cfg.default_ttl_secs, fx.cfg.max_ttl_secs, fx.cfg.mount.as_str()), (300, 600, "ssh"));
}

#[tokio::test]
async fn malformed_input_is_refused_before_the_gate() {
    let fx = fixture().await;
    let key = client_key();
    let host_key_cert = {
        fx.signer.set(Mode::Honest);
        fx.sign(&ask("e-alice", "prod", &key)).await.unwrap().signed_key
    };
    fx.audit.take();
    let bad_keys: Vec<String> = vec![
        String::new(),
        "not a key".into(),
        "ssh-ed25519 AAAA".into(),
        format!("{key}\n{key}"),
        host_key_cert,
        "A".repeat(20_000),
    ];
    for bad in &bad_keys {
        let err = fx.sign(&ask("e-alice", "prod", bad)).await.unwrap_err();
        assert_eq!(status(err), 400, "{bad:.40}");
    }
    assert!(fx.audit.take().is_empty());

    for (name, mount, role) in
        [("mount", "../ssh", "idp"), ("mount", "a//b", "idp"), ("role", "ssh", "-x"), ("role", "ssh", "a b")]
    {
        let update = SshConfigUpdate { mount: Some(mount.into()), role: Some(role.into()), ..Default::default() };
        assert!(fx.ssh.put_config(update, Utc::now()).await.is_err(), "{name} {mount} {role}");
    }
}

/// The certificate is read back; an engine role that drops or alters an
/// identity field gets nothing issued, and nothing recorded.
#[tokio::test]
async fn a_certificate_that_does_not_match_is_discarded() {
    let fx = fixture().await;
    let key = client_key();
    for mode in
        [Mode::Refuse, Mode::DropUidExtension, Mode::WrongPrincipal, Mode::OtherKey, Mode::HostCert, Mode::SerialZero]
    {
        fx.signer.set(mode);
        let err = fx.sign(&ask("e-alice", "prod", &key)).await.unwrap_err();
        assert_eq!(status(err), 502, "{mode:?}");
    }
    assert_eq!(fx.recorded().await, 0);
}

/// Stand-in for a provider that reads the stores instead of asking the gate.
struct SkipGate {
    posix: Arc<PosixStore>,
    authz: Arc<EntitlementStore>,
}

#[maybe_async::maybe_async]
impl Authorizer for SkipGate {
    async fn check(&self, req: &IssueRequest, _http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
        let denied = IssueDenied { reason: DenyReason::StoreError };
        let id = self.posix.get_identity(&req.entity_id).await.ok().flatten().ok_or(denied)?;
        let env = self.authz.get_environment(&req.environment).await.ok().flatten().ok_or(denied)?;
        Ok(IssueGrant {
            entity_id: id.entity_id,
            login: id.login,
            uid: id.uid,
            primary_gid: id.primary_gid,
            gids: id.gids,
            display_name: id.display_name,
            environment: env.name,
            namespace: env.namespace,
            namespace_uuid: env.namespace_uuid,
            roles: vec!["dba".into()],
            policies: Vec::new(),
            not_after: None,
        })
    }
}

/// Mutation check: run the deny cases with the gate skipped. Each would
/// then get a certificate, so the "no certificate" assertions above fail
/// unless the gate is called.
#[tokio::test]
async fn deny_tests_fail_if_the_gate_is_skipped() {
    let fx = fixture().await;
    let key = client_key();
    let skip = SkipGate { posix: fx.posix.clone(), authz: fx.authz.clone() };
    for entity in ["e-dora", "e-remy", "e-nora", "e-exp"] {
        let req = ask(entity, "prod", &key);
        assert!(fx.sign(&req).await.is_err(), "{entity}: the gate denies");
        let mutated = issue(&skip, &fx.signer, &fx.ssh, &fx.cfg, &req, None).await;
        assert!(mutated.is_ok(), "{entity}: without the gate a certificate is issued: {mutated:?}");
    }
    assert_eq!(fx.signer.calls(), 4);
}

#[test]
fn stored_records_are_versioned() {
    use crate::posix::model::decode_versioned;
    let cert = r#"{"version":1,"serial":"0000000000001000","entity_id":"e-a","login":"a","uid":80000,
        "environment":"prod","namespace":"prod","key_id":"bv:e-a:a:uid=80000:env=prod",
        "ca_public_key":"ssh-ed25519 AAAA","valid_after":1,"valid_before":2,
        "issued_at":"2026-01-01T00:00:00Z","revoked_at":null,"revoke_reason":null}"#;
    let rec: CertRecord = decode_versioned("certificate", cert.as_bytes()).unwrap();
    assert_eq!(rec.serial_u64().unwrap(), 0x1000);
    assert!(decode_versioned::<CertRecord>("certificate", cert.replace("\"version\":1", "\"version\":2").as_bytes())
        .is_err());
    assert!(decode_versioned::<CertRecord>("certificate", cert.replace("\"uid\"", "\"extra\":1,\"uid\"").as_bytes())
        .is_err());
    let cfg = r#"{"version":1,"mount":"ssh","role":"idp","default_ttl_secs":1800,"max_ttl_secs":3600,
        "updated_at":"2026-01-01T00:00:00Z"}"#;
    let cfg: SshProviderConfig = decode_versioned("ssh provider config", cfg.as_bytes()).unwrap();
    assert_eq!(cfg.role, "idp");
    for bad in ["", "1000", "000000000000100G", "000000000000100A"] {
        assert!(store::parse_serial(bad).is_err(), "{bad}");
    }
}
