//! RADIUS provider tests: codec round trips, the malformed-packet table,
//! the accept path, every reject and discard path with its audit event,
//! lifecycle taking effect at once, the store's validation, the limiter
//! and duplicate cache, UDP and RadSec listeners over real sockets, and a
//! mutation check showing the reject tests depend on the gate.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration as StdDuration, Instant},
};

use chrono::Duration;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    packet::*,
    server::{DuplicateCache, DuplicateCheck, Opened, RadiusSource, RateLimiter, RATE_WINDOW},
    store::*,
    vendor::{parse_attribute, FORTINET_VENDOR_ID},
    *,
};
use crate::{
    entitlement::{
        gate::{IssueAuditSink, IssueDenied, IssueEvent, IssueGate, IssueGrant, NamespaceLookup},
        model::{Entitlement, EntitlementSource},
        store::{BoundNamespace, EntitlementStore, EntitlementWrite, EnvironmentWrite},
    },
    kernel_api::namespace::NamespaceRef,
    logical::Request,
    posix::{model::IdentityState, store::IdentityWrite},
    provider::ssh::store::SshStore,
    revoke::store::FeedStore,
    storage::Storage,
    test_support::MemStorage,
    IssuanceStores,
};

const SECRET: &str = "nas-shared-secret-0001";
const NAS_IP: &str = "192.0.2.10";

// ─── Fakes ──────────────────────────────────────────────────────────

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

#[derive(Default)]
struct IssueEvents {
    events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
}

#[maybe_async::maybe_async]
impl IssueAuditSink for IssueEvents {
    async fn record(&self, name: &'static str, event: &IssueEvent, _req: Option<&Request>) -> Result<(), RvError> {
        self.events.lock().unwrap().push((name, event.fields()?));
        Ok(())
    }
}

#[derive(Default)]
struct RadiusEvents {
    events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
    refuse_accept: AtomicBool,
}

#[maybe_async::maybe_async]
impl RadiusAudit for RadiusEvents {
    async fn record(&self, name: &'static str, fields: Map<String, Value>) -> Result<(), RvError> {
        if name == events::ACCEPT && self.refuse_accept.load(Ordering::SeqCst) {
            return Err(RvError::ErrString("injected audit failure".into()));
        }
        self.events.lock().unwrap().push((name, fields));
        Ok(())
    }
}

impl RadiusEvents {
    fn take(&self) -> Vec<(&'static str, Map<String, Value>)> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

/// A provider that reads the stores instead of asking the gate.
struct SkipGate {
    posix: Arc<PosixStore>,
}

#[maybe_async::maybe_async]
impl Authorizer for SkipGate {
    async fn check(&self, req: &IssueRequest, _http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
        let denied = IssueDenied { reason: DenyReason::StoreError };
        let id = self.posix.get_identity(&req.entity_id).await.ok().flatten().ok_or(denied)?;
        Ok(IssueGrant {
            entity_id: id.entity_id,
            login: id.login,
            uid: id.uid,
            primary_gid: id.primary_gid,
            gids: id.gids,
            display_name: id.display_name,
            environment: req.environment.clone(),
            namespace: req.environment.clone(),
            namespace_uuid: String::new(),
            roles: vec!["netadmin".into()],
            policies: Vec::new(),
            not_after: None,
        })
    }
}

// ─── Fixture ────────────────────────────────────────────────────────

struct Fx {
    posix: Arc<PosixStore>,
    authz: Arc<EntitlementStore>,
    stores: Arc<IssuanceStores>,
    namespaces: Arc<FakeNamespaces>,
    issue_events: Arc<IssueEvents>,
    radius_events: Arc<RadiusEvents>,
}

impl Fx {
    fn radius(&self) -> &RadiusStore {
        &self.stores.radius
    }

    fn gate(&self) -> IssueGate {
        IssueGate::new(
            Some(self.posix.clone()),
            Some(self.authz.clone()),
            self.namespaces.clone(),
            self.issue_events.clone(),
        )
    }

    async fn answer_with(
        &self,
        authorizer: &dyn Authorizer,
        client: &str,
        packet: &[u8],
        now: DateTime<Utc>,
    ) -> Answer {
        let client = self.radius().get_client(client).await.unwrap().unwrap();
        let deps =
            RadiusDeps { authorizer, posix: &self.posix, radius: self.radius(), audit: self.radius_events.as_ref() };
        answer(&deps, &Exchange { client: &client, peer: NAS_IP.parse().unwrap(), packet }, now).await
    }

    async fn answer(&self, client: &str, packet: &[u8]) -> Answer {
        self.answer_with(&self.gate(), client, packet, Utc::now()).await
    }

    async fn passcode(&self, entity_id: &str, login: &str, env: &str, roles: Option<&[&str]>) -> String {
        let roles = roles.map(|r| r.iter().map(|s| s.to_string()).collect());
        let (code, _) = self.radius().mint_passcode(entity_id, login, env, roles, 120, Utc::now()).await.unwrap();
        code.to_string()
    }

    fn issue_reasons(&self) -> Vec<String> {
        let mut events = self.issue_events.events.lock().unwrap();
        let out = events.iter().map(|(n, f)| format!("{n}:{}", f["reason"].as_str().unwrap_or("allow"))).collect();
        events.clear();
        out
    }
}

fn environment(name: &str, roles: &[(&str, &str)]) -> EnvironmentWrite {
    EnvironmentWrite {
        name: name.into(),
        namespace: Some(BoundNamespace { path: name.into(), uuid: format!("u-{name}") }),
        roles: Some(roles.iter().map(|(r, p)| (r.to_string(), vec![p.to_string()])).collect()),
        description: None,
    }
}

fn attrs(json: Value) -> BTreeMap<String, Vec<vendor::VendorAttribute>> {
    json.as_object()
        .unwrap()
        .iter()
        .map(|(r, list)| (r.clone(), list.as_array().unwrap().iter().map(|a| parse_attribute(a).unwrap()).collect()))
        .collect()
}

/// alice 80000 (prod netadmin+readonly, dev netadmin), dora (disabled),
/// remy (removed), nora (no entitlement), exp (expired). NAS `fgt1` (UDP,
/// prod), `fgt-dev` (UDP, dev), `fgt-tls` (RadSec, prod).
async fn fixture() -> Fx {
    let posix = Arc::new(PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
    let authz_mem = MemStorage::new_arc();
    let authz = Arc::new(EntitlementStore::new(authz_mem.clone() as Arc<dyn Storage>));
    let namespaces = Arc::new(FakeNamespaces::default());
    for ns in ["prod", "dev", "old"] {
        let r = NamespaceRef { uuid: format!("u-{ns}"), path: ns.into() };
        namespaces.map.lock().unwrap().insert(ns.into(), r);
    }
    authz.put_environment(environment("prod", &[("netadmin", "p-net"), ("readonly", "p-ro")])).await.unwrap();
    authz.put_environment(environment("dev", &[("netadmin", "d-net")])).await.unwrap();
    authz.put_environment(environment("old", &[("netadmin", "o-net")])).await.unwrap();
    let now = Utc::now();
    for (id, login) in
        [("e-alice", "alice"), ("e-dora", "dora"), ("e-remy", "remy"), ("e-nora", "nora"), ("e-exp", "exp")]
    {
        let w = IdentityWrite { entity_id: id.into(), login: Some(login.into()), ..Default::default() };
        posix.create_or_update(w).await.unwrap();
    }
    for (id, env, roles) in [
        ("e-alice", "prod", &["netadmin", "readonly"][..]),
        ("e-alice", "dev", &["netadmin"][..]),
        ("e-alice", "old", &["netadmin"][..]),
        ("e-dora", "prod", &["netadmin"][..]),
        ("e-remy", "prod", &["netadmin"][..]),
    ] {
        let grant = EntitlementWrite {
            entity_id: id.into(),
            environment: env.into(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            not_after: None,
            source: EntitlementSource::Manual,
            granted_by: "root".into(),
        };
        authz.put_entitlement(&posix, grant, now).await.unwrap();
    }
    let expired = Entitlement {
        version: 1,
        entity_id: "e-exp".into(),
        environment: "prod".into(),
        roles: vec!["netadmin".into()],
        not_after: Some(now - Duration::hours(1)),
        source: EntitlementSource::Manual,
        granted_by: "root".into(),
        granted_at: now - Duration::days(1),
    };
    authz_mem.raw_put("entitlements/e-exp/prod", &serde_json::to_vec(&expired).unwrap());
    posix.transition("e-dora", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Removed, None).await.unwrap();

    let stores = Arc::new(IssuanceStores {
        ssh: SshStore::new(MemStorage::new_arc() as Arc<dyn Storage>),
        feed: FeedStore::new(MemStorage::new_arc() as Arc<dyn Storage>),
        radius: RadiusStore::new(MemStorage::new_arc() as Arc<dyn Storage>),
    });
    let radius = &stores.radius;
    let prod_roles = attrs(json!({
        "netadmin": [{"attribute": "fortinet-group-name", "value": "bv-super"}],
        "readonly": [{"attribute": "fortinet-group-name", "value": "bv-read"},
                     {"attribute": "vsa", "vendor_id": 9, "vendor_type": 1, "value": "shell:priv-lvl=1"}]
    }));
    for (name, env, roles) in [
        ("fgt-prod", "prod", prod_roles),
        ("fgt-dev", "dev", attrs(json!({"netadmin": [{"attribute": "fortinet-group-name", "value": "dev-adm"}]}))),
        ("fgt-old", "old", attrs(json!({"netadmin": [{"attribute": "fortinet-group-name", "value": "old-adm"}]}))),
        ("ro-only", "prod", attrs(json!({"readonly": [{"attribute": "fortinet-group-name", "value": "bv-read"}]}))),
    ] {
        let w =
            ProfileWrite { name: name.into(), environment: Some(env.into()), roles: Some(roles), description: None };
        radius.put_profile(&authz, w, now).await.unwrap();
    }
    for (name, env, profile, address) in [
        ("fgt1", "prod", "fgt-prod", "192.0.2.10"),
        ("fgt-dev", "dev", "fgt-dev", "192.0.2.20"),
        ("fgt-old", "old", "fgt-old", "192.0.2.30"),
        ("fgt-ro", "prod", "ro-only", "192.0.2.40"),
    ] {
        radius.put_client(&authz, udp_client(name, env, profile, address), now).await.unwrap();
    }
    let tls = ClientWrite {
        name: "fgt-tls".into(),
        transport: Some(Transport::Radsec),
        environment: Some("prod".into()),
        profile: Some("fgt-prod".into()),
        cert_sha256: Some("ab".repeat(32)),
        ..Default::default()
    };
    radius.put_client(&authz, tls, now).await.unwrap();
    Fx {
        posix,
        authz,
        stores,
        namespaces,
        issue_events: Arc::new(IssueEvents::default()),
        radius_events: Arc::new(RadiusEvents::default()),
    }
}

fn udp_client(name: &str, env: &str, profile: &str, address: &str) -> ClientWrite {
    ClientWrite {
        name: name.into(),
        transport: Some(Transport::Udp),
        environment: Some(env.into()),
        profile: Some(profile.into()),
        address: Some(address.into()),
        secret: Some(Zeroizing::new(SECRET.into())),
        ..Default::default()
    }
}

fn authenticator(id: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, b) in a.iter_mut().enumerate() {
        *b = id.wrapping_mul(37).wrapping_add(i as u8).wrapping_mul(11);
    }
    a
}

/// A NAS's Access-Request with User-Name, hidden User-Password, `extra`.
fn request(id: u8, user: &str, password: &str, secret: &str, extra: Vec<(u8, Vec<u8>)>) -> (Vec<u8>, [u8; 16]) {
    let auth = authenticator(id);
    let hidden = hide_password(password.as_bytes(), secret.as_bytes(), &auth).unwrap();
    let mut attributes = vec![(attr::USER_NAME, user.as_bytes().to_vec()), (attr::USER_PASSWORD, hidden)];
    attributes.extend(extra);
    (encode_request(id, &auth, &attributes, secret.as_bytes()).unwrap(), auth)
}

/// A packet with exactly these attribute octets and a matching Length.
fn raw(code: u8, id: u8, attributes: &[u8]) -> Vec<u8> {
    let mut out = vec![code, id, 0, 0];
    out.extend_from_slice(&authenticator(id));
    out.extend_from_slice(attributes);
    let len = out.len() as u16;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    out
}

/// Vendor-specific string attributes of a reply: (vendor, type, value).
fn vsas(reply: &[u8]) -> Vec<(u32, u8, String)> {
    let p = parse(reply).unwrap();
    p.attributes
        .iter()
        .filter(|a| a.kind == attr::VENDOR_SPECIFIC)
        .map(|a| {
            let vendor = u32::from_be_bytes([a.value[0], a.value[1], a.value[2], a.value[3]]);
            assert_eq!(usize::from(a.value[5]), a.value.len() - 4, "sub-attribute length");
            (vendor, a.value[4], String::from_utf8(a.value[6..].to_vec()).unwrap())
        })
        .collect()
}

fn reply_code(reply: &[u8]) -> u8 {
    reply[0]
}

// ─── Codec ──────────────────────────────────────────────────────────

#[test]
fn codec_round_trips() {
    let secret = SECRET.as_bytes();
    for len in [0usize, 1, 15, 16, 17, 31, 32, 100, 128] {
        let password: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
        let auth = authenticator(len as u8);
        let hidden = hide_password(&password, secret, &auth).unwrap();
        assert_eq!(hidden.len(), len.div_ceil(16).max(1) * 16);
        assert_eq!(unhide_password(&hidden, secret, &auth).unwrap().as_slice(), password.as_slice(), "{len}");
        assert_ne!(unhide_password(&hidden, b"another-secret", &auth).unwrap().as_slice(), password.as_slice());
    }
    assert_eq!(hide_password(&[b'x'; 129], secret, &authenticator(1)), Err(PacketError::Oversize));

    let (pkt, auth) = request(7, "alice", "pw", SECRET, vec![]);
    let p = parse(&pkt).unwrap();
    assert_eq!((p.code, p.identifier, p.authenticator), (code::ACCESS_REQUEST, 7, auth));
    assert_eq!(p.attributes[0].kind, attr::MESSAGE_AUTHENTICATOR, "Message-Authenticator first");
    assert_eq!(p.single(attr::USER_NAME).unwrap(), Some(&b"alice"[..]));
    assert_eq!(check_message_authenticator(&p, secret), MessageAuthCheck::Valid);
    assert_eq!(check_message_authenticator(&p, b"other-secret-0000"), MessageAuthCheck::Invalid);
    // Trailing padding is ignored.
    let mut padded = pkt.clone();
    padded.extend_from_slice(&[0u8; 7]);
    assert_eq!(parse(&padded).unwrap().raw, &pkt[..]);

    let vsa = vendor_specific(FORTINET_VENDOR_ID, 1, b"bv-super").unwrap();
    assert_eq!(vsa, [&[0, 0, 0x30, 0x44, 1, 10][..], b"bv-super"].concat());
    let reply = encode_response(code::ACCESS_ACCEPT, 7, &auth, &[(attr::VENDOR_SPECIFIC, vsa)], secret).unwrap();
    assert!(verify_response(&reply, &auth, secret));
    assert!(!verify_response(&reply, &auth, b"other-secret-0000"));
    assert!(!verify_response(&reply, &authenticator(8), secret));
    let mut tampered = reply.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(!verify_response(&tampered, &auth, secret));
    assert_eq!(vsas(&reply), [(FORTINET_VENDOR_ID, 1, "bv-super".to_string())]);
    assert_eq!(vendor_specific(FORTINET_VENDOR_ID, 1, &[b'a'; 248]), Err(PacketError::Oversize));
    let big = vec![(attr::VENDOR_SPECIFIC, vec![b'a'; 250]); 17];
    assert_eq!(encode_response(code::ACCESS_ACCEPT, 1, &auth, &big, secret), Err(PacketError::Oversize));
}

#[test]
fn malformed_packets_do_not_parse() {
    let (pkt, _) = request(1, "alice", "pw", SECRET, vec![]);
    let with_len = |len: u16| {
        let mut p = pkt.clone();
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    };
    let mut oversized = vec![0u8; MAX_PACKET_LEN + 1];
    oversized[..20].copy_from_slice(&raw(1, 1, &[])[..20]);
    let too_many: Vec<u8> = std::iter::repeat_n([33u8, 2], MAX_ATTRIBUTES + 1).flatten().collect();
    let cases: Vec<(&str, Vec<u8>, PacketError)> = vec![
        ("empty", vec![], PacketError::TooShort),
        ("truncated header", pkt[..19].to_vec(), PacketError::TooShort),
        ("truncated body", pkt[..pkt.len() - 1].to_vec(), PacketError::BadLength),
        ("length below header", with_len(19), PacketError::BadLength),
        ("length above buffer", with_len(pkt.len() as u16 + 4), PacketError::BadLength),
        ("length above 4096", with_len(4097), PacketError::TooLong),
        ("oversized datagram", oversized, PacketError::TooLong),
        ("attribute length 1", raw(1, 1, &[1, 1]), PacketError::BadAttribute),
        ("attribute length 0", raw(1, 1, &[1, 0, 0]), PacketError::BadAttribute),
        ("attribute overruns", raw(1, 1, &[1, 10, b'a']), PacketError::BadAttribute),
        ("lone type octet", raw(1, 1, &[1]), PacketError::BadAttribute),
        ("attribute type 0", raw(1, 1, &[0, 2]), PacketError::BadAttribute),
        ("too many attributes", raw(1, 1, &too_many), PacketError::TooManyAttributes),
    ];
    for (name, bytes, want) in cases {
        assert_eq!(parse(&bytes).err(), Some(want), "{name}");
    }
    assert_eq!(frame_len(&[1, 1, 0x10, 0x01]), Err(PacketError::TooLong));
    assert_eq!(frame_len(&[1, 1, 0, 19]), Err(PacketError::BadLength));
    assert_eq!(frame_len(&[1, 1, 0, 20]), Ok(20));
}

// ─── Decisions ──────────────────────────────────────────────────────

#[tokio::test]
async fn accept_carries_the_profile_attributes_and_goes_through_the_gate() {
    let fx = fixture().await;
    let code = fx.passcode("e-alice", "alice", "prod", None).await;
    let (pkt, auth) = request(3, "alice", &code, SECRET, vec![]);
    let ans = fx.answer("fgt1", &pkt).await;
    let accepted = ans.outcome.clone().unwrap();
    assert_eq!((accepted.login.as_str(), accepted.uid, accepted.environment.as_str()), ("alice", 80000, "prod"));
    assert_eq!(accepted.roles, ["netadmin", "readonly"]);
    let reply = ans.reply.unwrap();
    assert_eq!(reply_code(&reply), code::ACCESS_ACCEPT);
    assert!(verify_response(&reply, &auth, SECRET.as_bytes()));
    assert_eq!(parse(&reply).unwrap().attributes[0].kind, attr::MESSAGE_AUTHENTICATOR);
    assert_eq!(
        vsas(&reply),
        [
            (FORTINET_VENDOR_ID, 1, "bv-super".to_string()),
            (FORTINET_VENDOR_ID, 1, "bv-read".to_string()),
            (9, 1, "shell:priv-lvl=1".to_string()),
        ]
    );
    // The gate decided, as provider `radius`, and the accept is audited.
    let issued = fx.issue_events.events.lock().unwrap().clone();
    assert_eq!(issued.len(), 1);
    assert_eq!((issued[0].0, issued[0].1["provider"].as_str()), ("idp.issue", Some("radius")));
    assert_eq!(issued[0].1["entity_id"], "e-alice");
    let events = fx.radius_events.take();
    assert_eq!(events.len(), 1);
    let (name, f) = &events[0];
    assert_eq!((*name, f["decision"].as_str(), f["client"].as_str()), (events::ACCEPT, Some("accept"), Some("fgt1")));
    assert_eq!(
        (f["user_name"].as_str(), f["uid"].as_u64(), f["peer"].as_str()),
        (Some("alice"), Some(80000), Some(NAS_IP))
    );
    assert_eq!(f["attributes"], json!(["fortinet-group-name", "fortinet-group-name", "vsa"]));
    let text = serde_json::to_string(&events).unwrap();
    assert!(!text.contains(&code) && !text.contains(SECRET), "no passcode or secret in the audit event");

    // Single use: the same passcode again is refused.
    let (pkt, _) = request(4, "alice", &code, SECRET, vec![]);
    assert_eq!(fx.answer("fgt1", &pkt).await.outcome, Err(Refusal::BadPasscode));

    // A passcode for a subset of roles gets only those attributes.
    let code = fx.passcode("e-alice", "alice", "prod", Some(&["readonly"])).await;
    let (pkt, _) = request(5, "alice", &code, SECRET, vec![]);
    let reply = fx.answer("fgt1", &pkt).await.reply.unwrap();
    assert_eq!(vsas(&reply).len(), 2);
    assert!(vsas(&reply).iter().all(|(_, _, v)| v != "bv-super"));
}

#[tokio::test]
async fn every_gate_deny_is_an_access_reject_and_audited() {
    let fx = fixture().await;
    let mut cases = Vec::new();
    for (entity, login, env, client) in [
        ("e-dora", "dora", "prod", "fgt1"),
        ("e-remy", "remy", "prod", "fgt1"),
        ("e-nora", "nora", "prod", "fgt1"),
        ("e-exp", "exp", "prod", "fgt1"),
        ("e-alice", "alice", "old", "fgt-old"),
    ] {
        cases.push((login, client, fx.passcode(entity, login, env, None).await));
    }
    fx.authz.retire_environment("old").await.unwrap();
    let expected = [
        DenyReason::IdentityDisabled,
        DenyReason::IdentityRemoved,
        DenyReason::NotEntitled,
        DenyReason::EntitlementExpired,
        DenyReason::EnvironmentRetired,
    ];
    for ((login, client, code), want) in cases.into_iter().zip(expected) {
        let (pkt, auth) = request(9, login, &code, SECRET, vec![]);
        let ans = fx.answer(client, &pkt).await;
        assert_eq!(ans.outcome, Err(Refusal::Denied(want)), "{login}");
        let reply = ans.reply.expect("an Access-Reject");
        assert_eq!(reply_code(&reply), code::ACCESS_REJECT, "{login}");
        assert!(verify_response(&reply, &auth, SECRET.as_bytes()));
        assert_eq!(parse(&reply).unwrap().attributes.len(), 1, "a reject carries only the Message-Authenticator");
        let events = fx.radius_events.take();
        assert_eq!(events.len(), 1);
        assert_eq!((events[0].0, events[0].1["reason"].as_str()), (events::REJECT, Some("issue_denied")));
        assert_eq!(events[0].1["gate_reason"].as_str(), Some(want.as_str()));
        assert_eq!(fx.issue_reasons(), [format!("idp.issue-denied:{}", want.as_str())]);
    }
}

#[tokio::test]
async fn disabling_an_identity_rejects_its_next_request() {
    let fx = fixture().await;
    let first = fx.passcode("e-alice", "alice", "prod", None).await;
    let second = fx.passcode("e-alice", "alice", "prod", None).await;
    fx.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    let (pkt, _) = request(1, "alice", &first, SECRET, vec![]);
    assert_eq!(fx.answer("fgt1", &pkt).await.outcome, Err(Refusal::Denied(DenyReason::IdentityDisabled)));
    // Reinstated: a passcode minted before the disable still passes the
    // gate, which judges the identity's state now.
    fx.posix.transition("e-alice", IdentityState::Active, None).await.unwrap();
    let (pkt, _) = request(2, "alice", &second, SECRET, vec![]);
    assert!(fx.answer("fgt1", &pkt).await.outcome.is_ok());
    let third = fx.passcode("e-alice", "alice", "prod", None).await;
    fx.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    fx.posix.transition("e-alice", IdentityState::Removed, None).await.unwrap();
    let (pkt, _) = request(3, "alice", &third, SECRET, vec![]);
    assert_eq!(fx.answer("fgt1", &pkt).await.outcome, Err(Refusal::Denied(DenyReason::IdentityRemoved)));
}

#[tokio::test]
async fn every_other_refusal_is_audited_with_the_right_reply() {
    let fx = fixture().await;
    let good = fx.passcode("e-alice", "alice", "prod", None).await;
    let dev = fx.passcode("e-alice", "alice", "dev", None).await;
    let expiring = fx.passcode("e-alice", "alice", "prod", None).await;
    let netadmin_only = fx.passcode("e-alice", "alice", "prod", Some(&["netadmin"])).await;
    let hidden = |id: u8| hide_password(good.as_bytes(), SECRET.as_bytes(), &authenticator(id)).unwrap();
    let signed = |id: u8, attributes: Vec<(u8, Vec<u8>)>| {
        encode_request(id, &authenticator(id), &attributes, SECRET.as_bytes()).unwrap()
    };
    let user = |name: &str| (attr::USER_NAME, name.as_bytes().to_vec());
    let mut bad_ma = request(20, "alice", &good, SECRET, vec![]).0;
    *bad_ma.last_mut().unwrap() ^= 1;
    let mut two_ma = request(21, "alice", &good, SECRET, vec![]).0;
    two_ma.extend_from_slice(&[attr::MESSAGE_AUTHENTICATOR, 18]);
    two_ma.extend_from_slice(&[0u8; 16]);
    let len = two_ma.len() as u16;
    two_ma[2..4].copy_from_slice(&len.to_be_bytes());
    let mut accounting = raw(4, 22, &[attr::MESSAGE_AUTHENTICATOR, 18]);
    accounting.extend_from_slice(&[0u8; 16]);
    let len = accounting.len() as u16;
    accounting[2..4].copy_from_slice(&len.to_be_bytes());
    let later = Utc::now() + Duration::hours(1);

    // (name, client, packet, expected refusal, reply expected, now)
    let cases: Vec<(&str, &str, Vec<u8>, Refusal, bool, DateTime<Utc>)> = vec![
        ("truncated", "fgt1", vec![1, 2, 3], Refusal::Malformed(PacketError::TooShort), false, Utc::now()),
        (
            "bad attribute",
            "fgt1",
            raw(1, 23, &[1, 1]),
            Refusal::Malformed(PacketError::BadAttribute),
            false,
            Utc::now(),
        ),
        ("not access-request", "fgt1", accounting, Refusal::NotAccessRequest, false, Utc::now()),
        (
            "no message-authenticator",
            "fgt1",
            raw(1, 24, &[1, 7, b'a', b'l', b'i', b'c', b'e']),
            Refusal::NoMessageAuthenticator,
            false,
            Utc::now(),
        ),
        ("bad message-authenticator", "fgt1", bad_ma, Refusal::BadMessageAuthenticator, false, Utc::now()),
        (
            "duplicate message-authenticator",
            "fgt1",
            two_ma,
            Refusal::Malformed(PacketError::BadAttribute),
            false,
            Utc::now(),
        ),
        (
            "wrong secret",
            "fgt1",
            request(25, "alice", &good, "a-different-secret-01", vec![]).0,
            Refusal::BadMessageAuthenticator,
            false,
            Utc::now(),
        ),
        (
            "duplicate user-name",
            "fgt1",
            signed(26, vec![user("alice"), user("alice"), (attr::USER_PASSWORD, hidden(26))]),
            Refusal::BadRequest,
            true,
            Utc::now(),
        ),
        (
            "duplicate user-password",
            "fgt1",
            signed(27, vec![user("alice"), (attr::USER_PASSWORD, hidden(27)), (attr::USER_PASSWORD, hidden(27))]),
            Refusal::BadRequest,
            true,
            Utc::now(),
        ),
        ("no user-password", "fgt1", signed(28, vec![user("alice")]), Refusal::BadRequest, true, Utc::now()),
        (
            "user-password not 16n",
            "fgt1",
            signed(29, vec![user("alice"), (attr::USER_PASSWORD, vec![1; 17])]),
            Refusal::BadRequest,
            true,
            Utc::now(),
        ),
        (
            "chap",
            "fgt1",
            request(30, "alice", &good, SECRET, vec![(attr::CHAP_PASSWORD, vec![1; 17])]).0,
            Refusal::UnsupportedAuthentication,
            true,
            Utc::now(),
        ),
        (
            "eap",
            "fgt1",
            request(31, "alice", &good, SECRET, vec![(attr::EAP_MESSAGE, vec![2, 0, 0, 5, 1])]).0,
            Refusal::UnsupportedAuthentication,
            true,
            Utc::now(),
        ),
        (
            "unknown login",
            "fgt1",
            request(32, "mallory", &good, SECRET, vec![]).0,
            Refusal::UnknownLogin,
            true,
            Utc::now(),
        ),
        (
            "invalid login",
            "fgt1",
            request(33, "Root!", &good, SECRET, vec![]).0,
            Refusal::UnknownLogin,
            true,
            Utc::now(),
        ),
        (
            "not a passcode",
            "fgt1",
            request(34, "alice", "hunter2", SECRET, vec![]).0,
            Refusal::BadPasscode,
            true,
            Utc::now(),
        ),
        (
            "wrong passcode",
            "fgt1",
            request(35, "alice", &"0".repeat(32), SECRET, vec![]).0,
            Refusal::BadPasscode,
            true,
            Utc::now(),
        ),
        (
            "another user's passcode",
            "fgt1",
            request(36, "dora", &good, SECRET, vec![]).0,
            Refusal::BadPasscode,
            true,
            Utc::now(),
        ),
        (
            "expired passcode",
            "fgt1",
            request(37, "alice", &expiring, SECRET, vec![]).0,
            Refusal::PasscodeExpired,
            true,
            later,
        ),
        (
            "passcode for another environment",
            "fgt1",
            request(38, "alice", &dev, SECRET, vec![]).0,
            Refusal::EnvironmentMismatch,
            true,
            Utc::now(),
        ),
        (
            "no attributes for the roles",
            "fgt-ro",
            request(39, "alice", &netadmin_only, SECRET, vec![]).0,
            Refusal::NoAttributes,
            true,
            Utc::now(),
        ),
    ];
    for (name, client, pkt, want, replies, now) in cases {
        let ans = fx.answer_with(&fx.gate(), client, &pkt, now).await;
        assert_eq!(ans.outcome, Err(want), "{name}");
        assert_eq!(want.is_discard(), !replies, "{name}");
        match ans.reply {
            Some(reply) => {
                assert!(replies, "{name}: a discard sends nothing");
                assert_eq!(reply_code(&reply), code::ACCESS_REJECT, "{name}");
                assert!(verify_response(&reply, &authenticator(pkt[1]), SECRET.as_bytes()), "{name}");
            }
            None => assert!(!replies, "{name}: expected an Access-Reject"),
        }
        let events = fx.radius_events.take();
        assert_eq!(events.len(), 1, "{name}");
        let (event, f) = &events[0];
        assert_eq!(*event, events::REJECT, "{name}");
        assert_eq!(f["decision"].as_str(), Some(if replies { "reject" } else { "discard" }), "{name}");
        assert_eq!(f["reason"].as_str(), Some(want.as_str()), "{name}");
        assert_eq!(f["client"].as_str(), Some(client), "{name}");
    }
    // Every request above that carried `good` for alice was refused before
    // the passcode check, so it was never consumed.
    let (pkt, _) = request(40, "alice", &good, SECRET, vec![]);
    assert!(fx.answer("fgt1", &pkt).await.outcome.is_ok(), "rejects before the passcode check do not burn it");
}

#[tokio::test]
async fn an_accept_whose_event_cannot_be_recorded_is_a_reject() {
    let fx = fixture().await;
    fx.radius_events.refuse_accept.store(true, Ordering::SeqCst);
    let code = fx.passcode("e-alice", "alice", "prod", None).await;
    let (pkt, _) = request(1, "alice", &code, SECRET, vec![]);
    let ans = fx.answer("fgt1", &pkt).await;
    assert_eq!(ans.outcome, Err(Refusal::Internal));
    assert_eq!(reply_code(&ans.reply.unwrap()), code::ACCESS_REJECT);
}

#[tokio::test]
async fn a_store_read_failure_is_a_reject() {
    let posix_mem = MemStorage::new_arc();
    let mut fx = fixture().await;
    let code = fx.passcode("e-alice", "alice", "prod", None).await;
    // The same identity, on a store whose index reads now fail.
    let w = IdentityWrite { entity_id: "e-alice".into(), login: Some("alice".into()), ..Default::default() };
    PosixStore::new(posix_mem.clone() as Arc<dyn Storage>).create_or_update(w).await.unwrap();
    posix_mem.fail_gets_under(Some("index/"));
    fx.posix = Arc::new(PosixStore::new(posix_mem as Arc<dyn Storage>));
    let (pkt, _) = request(1, "alice", &code, SECRET, vec![]);
    let ans = fx.answer("fgt1", &pkt).await;
    assert_eq!(ans.outcome, Err(Refusal::Internal));
    assert_eq!(reply_code(&ans.reply.unwrap()), code::ACCESS_REJECT);
}

/// Mutation check: with the gate skipped, every deny case above would be
/// accepted, so the reject assertions fail unless the gate is called.
#[tokio::test]
async fn reject_tests_fail_if_the_gate_is_skipped() {
    let fx = fixture().await;
    let skip = SkipGate { posix: fx.posix.clone() };
    for (entity, login) in [("e-dora", "dora"), ("e-remy", "remy"), ("e-nora", "nora"), ("e-exp", "exp")] {
        let gated = fx.passcode(entity, login, "prod", None).await;
        let (pkt, _) = request(1, login, &gated, SECRET, vec![]);
        assert!(fx.answer("fgt1", &pkt).await.outcome.is_err(), "{login}: the gate denies");
        let skipped = fx.passcode(entity, login, "prod", None).await;
        let (pkt, _) = request(2, login, &skipped, SECRET, vec![]);
        let mutated = fx.answer_with(&skip, "fgt1", &pkt, Utc::now()).await;
        assert!(mutated.outcome.is_ok(), "{login}: without the gate it is accepted: {:?}", mutated.outcome);
        assert_eq!(reply_code(&mutated.reply.unwrap()), code::ACCESS_ACCEPT);
    }
}

// ─── Store ──────────────────────────────────────────────────────────

#[tokio::test]
async fn config_defaults_off_and_refuses_unsafe_settings() {
    let fx = fixture().await;
    let radius = fx.radius();
    assert!(radius.config().await.unwrap().is_none());
    let cfg = radius.put_config(ConfigUpdate::default(), Utc::now()).await.unwrap();
    assert!(!cfg.enabled && !cfg.udp_enabled && cfg.udp_addr().is_none() && cfg.radsec_addr().is_none());
    assert_eq!((cfg.passcode_default_ttl_secs, cfg.passcode_max_ttl_secs), (120, 300));
    let bad = |u: ConfigUpdate| async move { radius.put_config(u, Utc::now()).await.unwrap_err() };
    let status = |e: RvError| match e {
        RvError::ErrResponseStatus(s, m) => (s, m),
        other => panic!("{other:?}"),
    };
    let (s, m) = status(bad(ConfigUpdate { udp_listen: Some("127.0.0.1:1812".into()), ..Default::default() }).await);
    assert!(s == 400 && m.contains("udp_enabled"), "{m}");
    let (s, _) = status(bad(ConfigUpdate { udp_enabled: Some(true), ..Default::default() }).await);
    assert_eq!(s, 400);
    let any = ConfigUpdate { udp_enabled: Some(true), udp_listen: Some("0.0.0.0:1812".into()), ..Default::default() };
    let (s, m) = status(bad(any).await);
    assert!(s == 400 && m.contains("allow_unspecified_bind"), "{m}");
    let (s, _) = status(bad(ConfigUpdate { enabled: Some(true), ..Default::default() }).await);
    assert_eq!(s, 400, "enabled with no listener");
    let radsec = ConfigUpdate { radsec_listen: Some("127.0.0.1:2083".into()), ..Default::default() };
    let (s, m) = status(bad(radsec).await);
    assert!(s == 400 && m.contains("RadSec needs"), "{m}");
    let ttl = ConfigUpdate { passcode_default_ttl_secs: Some(600), ..Default::default() };
    assert_eq!(status(bad(ttl).await).0, 400);
    let rate = ConfigUpdate { rate_limit_per_minute: Some(0), ..Default::default() };
    assert_eq!(status(bad(rate).await).0, 400);
    let ok = ConfigUpdate {
        enabled: Some(true),
        udp_enabled: Some(true),
        udp_listen: Some("127.0.0.1:1812".into()),
        ..Default::default()
    };
    let cfg = radius.put_config(ok, Utc::now()).await.unwrap();
    assert_eq!(cfg.udp_addr(), Some("127.0.0.1:1812".parse().unwrap()));
    // Clearing the listener with an empty string, while enabled, is refused.
    let clear = ConfigUpdate { udp_listen: Some(String::new()), ..Default::default() };
    assert_eq!(status(bad(clear).await).0, 400);
}

#[tokio::test]
async fn clients_and_profiles_are_validated_and_never_return_secrets() {
    let fx = fixture().await;
    let (radius, authz, now) = (fx.radius(), fx.authz.as_ref(), Utc::now());
    let client = radius.get_client("fgt1").await.unwrap().unwrap();
    let shown = serde_json::to_string(&client.to_map()).unwrap();
    assert!(!shown.contains(SECRET) && shown.contains("\"secret_set\":true"));
    assert!(!format!("{client:?}").contains(SECRET));
    assert_eq!(radius.client_for_udp("192.0.2.10".parse().unwrap()).await.unwrap().unwrap().name, "fgt1");
    let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().unwrap();
    assert_eq!(radius.client_for_udp(mapped).await.unwrap().unwrap().name, "fgt1");
    assert!(radius.client_for_udp("192.0.2.99".parse().unwrap()).await.unwrap().is_none());
    assert_eq!(radius.client_for_cert(&"ab".repeat(32)).await.unwrap().unwrap().name, "fgt-tls");

    let refused = |w: ClientWrite| async move { radius.put_client(authz, w, now).await.unwrap_err() };
    let code = |e: RvError| match e {
        RvError::ErrResponseStatus(s, _) => s,
        other => panic!("{other:?}"),
    };
    assert_eq!(code(refused(udp_client("dup", "prod", "fgt-prod", "192.0.2.10")).await), 409, "address taken");
    assert_eq!(code(refused(udp_client("x", "prod", "fgt-dev", "192.0.2.11")).await), 400, "profile env");
    assert_eq!(code(refused(udp_client("x", "nope", "fgt-prod", "192.0.2.11")).await), 404, "environment");
    assert_eq!(code(refused(udp_client("x", "prod", "fgt-prod", "0.0.0.0")).await), 400, "unspecified");
    assert_eq!(code(refused(udp_client("X", "prod", "fgt-prod", "192.0.2.11")).await), 400, "name");
    let mut short = udp_client("x", "prod", "fgt-prod", "192.0.2.11");
    short.secret = Some(Zeroizing::new("too-short".into()));
    assert_eq!(code(refused(short).await), 400, "short secret");
    let mut moved = udp_client("fgt1", "dev", "fgt-dev", "192.0.2.10");
    moved.secret = None;
    assert_eq!(code(refused(moved).await), 400, "environment is fixed");
    let mixed = ClientWrite {
        name: "x".into(),
        transport: Some(Transport::Radsec),
        environment: Some("prod".into()),
        profile: Some("fgt-prod".into()),
        cert_sha256: Some("ab".repeat(32)),
        address: Some("192.0.2.11".into()),
        ..Default::default()
    };
    assert_eq!(code(refused(mixed).await), 400, "radsec takes no address");

    // A re-addressed client moves its index entry.
    let readdress = ClientWrite { name: "fgt1".into(), address: Some("192.0.2.11".into()), ..Default::default() };
    radius.put_client(authz, readdress, now).await.unwrap();
    assert!(radius.client_for_udp("192.0.2.10".parse().unwrap()).await.unwrap().is_none());
    assert_eq!(
        radius.client_for_udp("192.0.2.11".parse().unwrap()).await.unwrap().unwrap().secret.as_deref(),
        Some(SECRET)
    );

    let profile = |roles: Value| ProfileWrite {
        name: "p2".into(),
        environment: Some("prod".into()),
        roles: Some(attrs(roles)),
        description: None,
    };
    let unknown_role = profile(json!({"dba": [{"attribute": "fortinet-group-name", "value": "x"}]}));
    assert_eq!(code(radius.put_profile(authz, unknown_role, now).await.unwrap_err()), 400);
    let empty = profile(json!({"netadmin": []}));
    assert_eq!(code(radius.put_profile(authz, empty, now).await.unwrap_err()), 400);
    for bad in [
        json!({"attribute": "fortinet-group-name", "value": ""}),
        json!({"attribute": "fortinet-group-name", "value": "a".repeat(248)}),
        json!({"attribute": "fortinet-group-name", "value": "a\nb"}),
        json!({"attribute": "fortinet-group-name", "value": "x", "vendor_id": 9}),
        json!({"attribute": "vsa", "value": "x", "vendor_id": 9}),
        json!({"attribute": "vsa", "value": "x", "vendor_id": 16777216, "vendor_type": 1}),
        json!({"attribute": "vsa", "value": "x", "vendor_id": 9, "vendor_type": 0}),
        json!({"attribute": "no-such-kind", "value": "x"}),
        json!({"attribute": "vsa", "value": "x", "vendor_id": 9, "vendor_type": 1, "extra": 1}),
        json!("fortinet-group-name"),
    ] {
        assert!(parse_attribute(&bad).is_err(), "{bad}");
    }
    assert_eq!(code(radius.delete_profile("fgt-prod").await.unwrap_err()), 409, "still used by a client");
    assert!(radius.delete_client("fgt1").await.unwrap().is_some());
    assert!(radius.client_for_udp("192.0.2.11".parse().unwrap()).await.unwrap().is_none());
}

#[tokio::test]
async fn passcodes_are_hashed_bounded_and_single_use() {
    let fx = fixture().await;
    let radius = fx.radius();
    let now = Utc::now();
    let mut codes = Vec::new();
    for _ in 0..MAX_OUTSTANDING_PASSCODES {
        let (code, rec) = radius.mint_passcode("e-alice", "alice", "prod", None, 60, now).await.unwrap();
        assert!(is_passcode_format(code.as_bytes()));
        assert_eq!(rec.expires_at, now + Duration::seconds(60));
        codes.push(code.to_string());
    }
    let err = radius.mint_passcode("e-alice", "alice", "prod", None, 60, now).await.unwrap_err();
    assert!(matches!(err, RvError::ErrResponseStatus(429, _)));
    // Expired ones are pruned at the next mint.
    radius.mint_passcode("e-alice", "alice", "prod", None, 60, now + Duration::minutes(5)).await.unwrap();
    let rec = radius.consume_passcode("e-alice", codes[0].as_bytes()).await.unwrap();
    assert!(rec.is_none(), "pruned");
    let mut fresh = radius.mint_passcode("e-alice", "alice", "prod", None, 60, now).await.unwrap().0.to_string();
    assert!(radius.consume_passcode("e-bob", fresh.as_bytes()).await.unwrap().is_none(), "bound to the identity");
    assert!(radius.consume_passcode("e-alice", fresh.as_bytes()).await.unwrap().is_some());
    assert!(radius.consume_passcode("e-alice", fresh.as_bytes()).await.unwrap().is_none(), "single use");
    fresh.make_ascii_uppercase();
    assert!(!is_passcode_format(fresh.as_bytes()));
}

#[test]
fn stored_records_are_versioned() {
    use crate::posix::model::decode_versioned;
    let passcode = r#"{"version":1,"entity_id":"e-a","login":"a","environment":"prod","roles":null,
        "created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:02:00Z"}"#;
    assert!(decode_versioned::<PasscodeRecord>("p", passcode.as_bytes()).is_ok());
    assert!(
        decode_versioned::<PasscodeRecord>("p", passcode.replace("\"version\":1", "\"version\":2").as_bytes()).is_err()
    );
    assert!(
        decode_versioned::<PasscodeRecord>("p", passcode.replace("\"login\"", "\"x\":1,\"login\"").as_bytes()).is_err()
    );
    let client = r#"{"version":1,"name":"n","transport":"udp","environment":"prod","profile":"p",
        "address":"192.0.2.1","secret":"0123456789abcdef","cert_sha256":null,"description":null,
        "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
    assert!(decode_versioned::<RadiusClient>("c", client.as_bytes()).is_ok());
    assert!(decode_versioned::<RadiusClient>("c", client.replace("\"version\":1", "\"version\":0").as_bytes()).is_err());
    assert!(decode_versioned::<RadiusClient>("c", client.replace("udp", "tcp").as_bytes()).is_err());
}

// ─── Limiter and duplicate cache ────────────────────────────────────

#[test]
fn rate_limiter_counts_per_source_and_is_bounded() {
    let mut l = RateLimiter::new(2);
    let (a, b, c) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap(), "192.0.2.3".parse().unwrap());
    let t0 = Instant::now();
    assert!(l.allow(a, 2, t0) && l.allow(a, 2, t0));
    assert!(!l.allow(a, 2, t0), "third in the window");
    assert!(l.allow(b, 2, t0), "another source has its own window");
    assert!(!l.allow(c, 2, t0), "table full: a new source is refused");
    assert!(l.allow(a, 2, t0 + RATE_WINDOW), "a new window");
    assert!(l.allow(c, 2, t0 + RATE_WINDOW), "expired windows are reclaimed");
}

#[test]
fn duplicate_cache_replays_and_forgets_discards() {
    let mut d = DuplicateCache::new(2);
    let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
    let k = ("fgt1".to_string(), peer, 7u8, [1u8; 16]);
    let t0 = Instant::now();
    assert_eq!(d.begin(&k, t0), DuplicateCheck::New);
    assert_eq!(d.begin(&k, t0), DuplicateCheck::InFlight);
    d.finish(&k, Some(vec![2, 7]), t0);
    assert_eq!(d.begin(&k, t0), DuplicateCheck::Replay(vec![2, 7]));
    let other = ("fgt1".to_string(), peer, 7u8, [2u8; 16]);
    assert_eq!(d.begin(&other, t0), DuplicateCheck::New, "a new authenticator is a new request");
    d.finish(&other, None, t0);
    assert_eq!(d.begin(&other, t0), DuplicateCheck::New, "a discard is not remembered");
    let third = ("fgt1".to_string(), peer, 8u8, [3u8; 16]);
    assert_eq!(d.begin(&third, t0), DuplicateCheck::Full);
    assert_eq!(d.begin(&k, t0 + server::DUPLICATE_WINDOW), DuplicateCheck::New, "expired");
}

// ─── Listeners ──────────────────────────────────────────────────────

struct TestSource {
    fx: Fx,
    sealed: AtomicBool,
}

impl RadiusSource for TestSource {
    fn open(&self) -> Option<Opened> {
        if self.sealed.load(Ordering::SeqCst) {
            return None;
        }
        Some(Opened {
            posix: self.fx.posix.clone(),
            stores: self.fx.stores.clone(),
            gate: Box::new(self.fx.gate()),
            audit: self.fx.radius_events.clone(),
        })
    }

    fn alive(&self) -> bool {
        true
    }
}

async fn wait_for(runtime: &RadiusRuntime, f: impl Fn(&ListenerStatus) -> bool) -> ListenerStatus {
    let deadline = Instant::now() + StdDuration::from_secs(10);
    loop {
        let s = runtime.status();
        if f(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "listener status never matched: {s:?}");
        tokio::time::sleep(StdDuration::from_millis(20)).await;
    }
}

async fn exchange(sock: &tokio::net::UdpSocket, to: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    sock.send_to(pkt, to).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(StdDuration::from_millis(700), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_listener_answers_known_nas_dedups_and_rate_limits() {
    let fx = fixture().await;
    let now = Utc::now();
    fx.radius().put_client(&fx.authz, udp_client("local", "prod", "fgt-prod", "127.0.0.1"), now).await.unwrap();
    let source = Arc::new(TestSource { fx, sealed: AtomicBool::new(false) });
    let runtime = Arc::new(RadiusRuntime::default());
    runtime.start(source.clone());
    // Off by default: no config, nothing listens.
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    assert_eq!(runtime.status(), ListenerStatus::default());

    let limit = ConfigUpdate { rate_limit_per_minute: Some(3), ..Default::default() };
    source.fx.radius().put_config(limit, now).await.unwrap();
    let on = ConfigUpdate {
        enabled: Some(true),
        udp_enabled: Some(true),
        udp_listen: Some("127.0.0.1:0".into()),
        ..Default::default()
    };
    source.fx.radius().put_config(on, now).await.unwrap();
    runtime.reconcile_soon();
    let addr = wait_for(&runtime, |s| s.udp.is_some()).await.udp.unwrap();

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let code = source.fx.passcode("e-alice", "alice", "prod", None).await;
    let (pkt, auth) = request(1, "alice", &code, SECRET, vec![]);
    let reply = exchange(&sock, addr, &pkt).await.expect("an answer");
    assert_eq!(reply_code(&reply), code::ACCESS_ACCEPT);
    assert!(verify_response(&reply, &auth, SECRET.as_bytes()));
    // A retransmission is answered from the cache: the same Accept, even
    // though the passcode is gone.
    assert_eq!(exchange(&sock, addr, &pkt).await.as_deref(), Some(&reply[..]));
    // Third packet in the window (limit 3, the retransmission counted): a Reject.
    let (bad, _) = request(2, "alice", &"0".repeat(32), SECRET, vec![]);
    assert_eq!(exchange(&sock, addr, &bad).await.map(|r| r[0]), Some(code::ACCESS_REJECT));
    // Fourth: over the limit, silently dropped.
    let (bad, _) = request(3, "alice", &"0".repeat(32), SECRET, vec![]);
    assert_eq!(exchange(&sock, addr, &bad).await, None, "rate limited");
    let reasons: Vec<String> = source
        .fx
        .radius_events
        .take()
        .iter()
        .map(|(_, f)| f["reason"].as_str().unwrap_or("accept").to_string())
        .collect();
    assert_eq!(reasons, ["accept", "bad_passcode", "rate_limited"], "a retransmission is not re-audited");

    // Sealed: the listener stops.
    source.sealed.store(true, Ordering::SeqCst);
    runtime.reconcile_soon();
    wait_for(&runtime, |s| s.udp.is_none()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_from_an_unknown_source_gets_nothing() {
    let fx = fixture().await;
    let source = Arc::new(TestSource { fx, sealed: AtomicBool::new(false) });
    let on = ConfigUpdate {
        enabled: Some(true),
        udp_enabled: Some(true),
        udp_listen: Some("127.0.0.1:0".into()),
        ..Default::default()
    };
    source.fx.radius().put_config(on, Utc::now()).await.unwrap();
    let runtime = Arc::new(RadiusRuntime::default());
    runtime.start(source.clone());
    let addr = wait_for(&runtime, |s| s.udp.is_some()).await.udp.unwrap();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let code = source.fx.passcode("e-alice", "alice", "prod", None).await;
    let (pkt, _) = request(1, "alice", &code, SECRET, vec![]);
    assert_eq!(exchange(&sock, addr, &pkt).await, None);
    let events = source.fx.radius_events.take();
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].1["reason"].as_str(), events[0].1["client"].clone()), (Some("unknown_client"), Value::Null));
}

struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Self { issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap() }
    }

    /// (certificate PEM, key PEM, certificate DER).
    fn leaf(&self, san: &str) -> (String, String, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        (cert.pem(), key.serialize_pem(), cert.der().to_vec())
    }
}

async fn radsec_connect(
    addr: SocketAddr,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()],
            PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap(),
        )
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap()
}

async fn radsec_exchange(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    pkt: &[u8],
) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tls.write_all(pkt).await.ok()?;
    tls.flush().await.ok()?;
    let mut header = [0u8; 4];
    let read = tokio::time::timeout(StdDuration::from_secs(5), tls.read_exact(&mut header)).await;
    if !matches!(read, Ok(Ok(_))) {
        return None;
    }
    let len = frame_len(&header).ok()?;
    let mut reply = vec![0u8; len];
    reply[..4].copy_from_slice(&header);
    tls.read_exact(&mut reply[4..]).await.ok()?;
    Some(reply)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn radsec_listener_accepts_a_pinned_nas_and_refuses_others() {
    let fx = fixture().await;
    let pki = Pki::new();
    let (server_cert, server_key, _) = pki.leaf("localhost");
    let (nas_cert, nas_key, nas_der) = pki.leaf("fgt-tls.example");
    let (rogue_cert, rogue_key, _) = pki.leaf("rogue.example");
    let ca_pem = pki.issuer.pem();
    let pinned = ClientWrite {
        name: "fgt-pinned".into(),
        transport: Some(Transport::Radsec),
        environment: Some("prod".into()),
        profile: Some("fgt-prod".into()),
        cert_sha256: Some(tls::cert_fingerprint(&nas_der)),
        ..Default::default()
    };
    fx.radius().put_client(&fx.authz, pinned, Utc::now()).await.unwrap();
    let on = ConfigUpdate {
        enabled: Some(true),
        radsec_listen: Some("127.0.0.1:0".into()),
        tls_cert_pem: Some(server_cert),
        tls_key_pem: Some(Zeroizing::new(server_key)),
        client_ca_pem: Some(ca_pem.clone()),
        ..Default::default()
    };
    let cfg = fx.radius().put_config(on, Utc::now()).await.unwrap();
    assert!(!format!("{cfg:?}").contains("PRIVATE KEY"));
    assert!(!serde_json::to_string(&cfg.to_map()).unwrap().contains("PRIVATE KEY"));
    let source = Arc::new(TestSource { fx, sealed: AtomicBool::new(false) });
    let runtime = Arc::new(RadiusRuntime::default());
    runtime.start(source.clone());
    let status = wait_for(&runtime, |s| s.radsec.is_some()).await;
    assert!(status.udp.is_none(), "UDP stays off unless enabled");
    let addr = status.radsec.unwrap();

    let code = source.fx.passcode("e-alice", "alice", "prod", None).await;
    let secret = std::str::from_utf8(RADSEC_SECRET).unwrap();
    let (pkt, auth) = request(1, "alice", &code, secret, vec![]);
    let mut tls = radsec_connect(addr, &ca_pem, &nas_cert, &nas_key).await;
    let reply = radsec_exchange(&mut tls, &pkt).await.expect("an answer over RadSec");
    assert_eq!(reply_code(&reply), code::ACCESS_ACCEPT);
    assert!(verify_response(&reply, &auth, RADSEC_SECRET));
    assert_eq!(vsas(&reply)[0], (FORTINET_VENDOR_ID, 1, "bv-super".to_string()));
    // A second request on the same session is answered too (here: a Reject).
    let (again, _) = request(2, "alice", &code, secret, vec![]);
    assert_eq!(radsec_exchange(&mut tls, &again).await.map(|r| r[0]), Some(code::ACCESS_REJECT));

    // A certificate from the same CA that no client pins: closed, no answer.
    let mut rogue = radsec_connect(addr, &ca_pem, &rogue_cert, &rogue_key).await;
    let code = source.fx.passcode("e-alice", "alice", "prod", None).await;
    let (pkt, _) = request(3, "alice", &code, secret, vec![]);
    assert_eq!(radsec_exchange(&mut rogue, &pkt).await, None);
    let reasons: Vec<String> = source
        .fx
        .radius_events
        .take()
        .iter()
        .map(|(_, f)| f["reason"].as_str().unwrap_or("accept").to_string())
        .collect();
    assert_eq!(reasons, ["accept", "bad_passcode", "unknown_client"]);
}
