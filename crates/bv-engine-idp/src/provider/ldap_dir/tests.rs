//! LDAP directory tests: codec round trips, a malformed-PDU table and a
//! seeded mutation run; filter semantics; binds, searches, refused writes,
//! limits and their audit events; the store's validation; listeners over
//! real sockets driven by the independent ldap3 client; and a mutation
//! check showing the bind and search tests depend on the gate.

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use chrono::{Duration, Utc};
use serde_json::{Map, Value};

use super::{
    ber::{self, BerError},
    filter::{Filter, Substrings},
    proto::{client, client::Reply, tag, ResultCode, Scope, WriteOp},
    store::*,
    *,
};
use crate::{
    entitlement::{
        gate::{IssueGate, IssueGrant},
        model::{Entitlement, EntitlementSource},
        store::{BoundNamespace, EntitlementStore, EntitlementWrite, EnvironmentWrite},
    },
    kernel_api::namespace::NamespaceRef,
    posix::store::IdentityWrite,
    provider::{
        oidc_op::store::OidcStore, radius::store::RadiusStore, saml_idp::store::SamlStore, ssh::store::SshStore,
    },
    revoke::store::FeedStore,
    storage::Storage,
    test_support::{FakeNamespaces, IssueEvents, MemStorage, SkipGate},
    IssuanceStores,
};

const BASE: &str = "dc=example,dc=com";
const LEGACY_IP: &str = "192.0.2.50";

fn fp(c: char) -> String {
    c.to_string().repeat(64)
}

fn dn(login: &str) -> String {
    format!("uid={login},ou=people,{BASE}")
}

// ─── Fakes ──────────────────────────────────────────────────────────

#[derive(Default)]
struct LdapEvents {
    events: Mutex<Vec<(&'static str, Map<String, Value>)>>,
    refuse: Mutex<Option<&'static str>>,
}

#[maybe_async::maybe_async]
impl DirectoryAudit for LdapEvents {
    async fn record(&self, name: &'static str, fields: Map<String, Value>) -> Result<(), RvError> {
        if *self.refuse.lock().unwrap() == Some(name) {
            return Err(RvError::ErrString("injected audit failure".into()));
        }
        self.events.lock().unwrap().push((name, fields));
        Ok(())
    }
}

impl LdapEvents {
    fn take(&self) -> Vec<(&'static str, Map<String, Value>)> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    /// `name:decision:reason` of every event so far, then cleared.
    fn summary(&self) -> Vec<String> {
        self.take()
            .iter()
            .map(|(n, f)| {
                let d = f.get("decision").and_then(Value::as_str).unwrap_or("");
                format!("{n}:{d}:{}", f.get("reason").and_then(Value::as_str).unwrap_or("-"))
            })
            .collect()
    }
}

/// The mutation: a view that reads the identity and skips the gate.
#[maybe_async::maybe_async]
impl DirectoryView for SkipGate {
    async fn view(&self, req: &IssueRequest) -> Result<IssueGrant, IssueDenied> {
        Authorizer::check(self, req, None).await
    }
}

// ─── Fixture ────────────────────────────────────────────────────────

struct Fx {
    posix: Arc<PosixStore>,
    authz: Arc<EntitlementStore>,
    stores: Arc<IssuanceStores>,
    namespaces: Arc<FakeNamespaces>,
    issue_events: Arc<IssueEvents>,
    events: Arc<LdapEvents>,
}

/// Environments prod (ops, readonly), dev (ops), old (ops). alice
/// ("Alice Souza", gid 4000) holds prod, dev and old; bob dev only; carol
/// (gid 4000) prod readonly; dora (gid 4000, disabled) and remy (removed)
/// held prod; nora holds nothing; exp's prod grant has expired. Clients:
/// host-prod, host-dev, host-old (tls) and legacy (plain, prod).
async fn fixture() -> Fx {
    let posix = Arc::new(PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
    let authz_mem = MemStorage::new_arc();
    let authz = Arc::new(EntitlementStore::new(authz_mem.clone() as Arc<dyn Storage>));
    let namespaces = Arc::new(FakeNamespaces::default());
    for ns in ["prod", "dev", "old"] {
        let r = NamespaceRef { uuid: format!("u-{ns}"), path: ns.into() };
        namespaces.map.lock().unwrap().insert(ns.into(), r);
    }
    for (name, roles) in [("prod", &["ops", "readonly"][..]), ("dev", &["ops"][..]), ("old", &["ops"][..])] {
        let w = EnvironmentWrite {
            name: name.into(),
            namespace: Some(BoundNamespace { path: name.into(), uuid: format!("u-{name}") }),
            roles: Some(roles.iter().map(|r| (r.to_string(), vec![format!("{name}-{r}")])).collect()),
            description: None,
        };
        authz.put_environment(w).await.unwrap();
    }
    for (id, login, display, gids) in [
        ("e-alice", "alice", Some("Alice Souza"), vec![4000]),
        ("e-bob", "bob", None, vec![]),
        ("e-carol", "carol", None, vec![4000]),
        ("e-dora", "dora", None, vec![4000]),
        ("e-remy", "remy", None, vec![]),
        ("e-nora", "nora", None, vec![]),
        ("e-exp", "exp", None, vec![]),
    ] {
        let w = IdentityWrite {
            entity_id: id.into(),
            login: Some(login.into()),
            display_name: display.map(str::to_string),
            gids: Some(gids),
            ..Default::default()
        };
        posix.create_or_update(w).await.unwrap();
    }
    let now = Utc::now();
    for (id, env, roles) in [
        ("e-alice", "prod", &["ops", "readonly"][..]),
        ("e-alice", "dev", &["ops"][..]),
        ("e-alice", "old", &["ops"][..]),
        ("e-bob", "dev", &["ops"][..]),
        ("e-carol", "prod", &["readonly"][..]),
        ("e-dora", "prod", &["ops"][..]),
        ("e-remy", "prod", &["ops"][..]),
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
        roles: vec!["ops".into()],
        not_after: Some(now - Duration::hours(1)),
        source: EntitlementSource::Manual,
        granted_by: "root".into(),
        granted_at: now - Duration::days(1),
    };
    authz_mem.raw_put("entitlements/e-exp/prod", &serde_json::to_vec(&expired).unwrap());
    posix.transition("e-dora", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Disabled, None).await.unwrap();
    posix.transition("e-remy", IdentityState::Removed, None).await.unwrap();

    let mem = || MemStorage::new_arc() as Arc<dyn Storage>;
    let stores = Arc::new(IssuanceStores {
        ssh: SshStore::new(mem()),
        feed: FeedStore::new(mem()),
        radius: RadiusStore::new(mem()),
        oidc: OidcStore::new(mem()),
        saml: SamlStore::new(mem()),
        ldap: LdapStore::new(mem()),
    });
    let on = ConfigUpdate {
        enabled: Some(true),
        ldap_listen: Some("127.0.0.1:0".into()),
        plaintext_enabled: Some(true),
        base_dn: Some("DC=Example, dc=com".into()),
        ..Default::default()
    };
    stores.ldap.put_config(on, now).await.unwrap();
    for (name, env, c) in [("host-prod", "prod", 'a'), ("host-dev", "dev", 'b'), ("host-old", "old", 'c')] {
        let w = ClientWrite {
            name: name.into(),
            transport: Some(Transport::Tls),
            environment: Some(env.into()),
            cert_sha256: Some(fp(c)),
            ..Default::default()
        };
        stores.ldap.put_client(&authz, w, now).await.unwrap();
    }
    let legacy = ClientWrite {
        name: "legacy".into(),
        transport: Some(Transport::Plain),
        environment: Some("prod".into()),
        address: Some(LEGACY_IP.into()),
        ..Default::default()
    };
    stores.ldap.put_client(&authz, legacy, now).await.unwrap();
    Fx {
        posix,
        authz,
        stores,
        namespaces,
        issue_events: Arc::new(IssueEvents::default()),
        events: Arc::new(LdapEvents::default()),
    }
}

impl Fx {
    fn ldap(&self) -> &LdapStore {
        &self.stores.ldap
    }

    fn gate(&self) -> IssueGate {
        IssueGate::new(
            Some(self.posix.clone()),
            Some(self.authz.clone()),
            self.namespaces.clone(),
            self.issue_events.clone(),
        )
    }

    fn session(&self, client: &str) -> Session {
        let (recognised, channel) = match client {
            "legacy" => (Recognised::Address(LEGACY_IP.parse().unwrap()), Channel::Plain),
            "host-prod" => (Recognised::Certificate(fp('a')), Channel::Ldaps),
            "host-dev" => (Recognised::Certificate(fp('b')), Channel::Ldaps),
            "host-old" => (Recognised::Certificate(fp('c')), Channel::Ldaps),
            _ => (Recognised::Certificate(fp('f')), Channel::Ldaps),
        };
        Session {
            client: client.into(),
            recognised,
            channel,
            peer: "192.0.2.1".parse().unwrap(),
            bound: Bound::Anonymous,
        }
    }

    async fn send_with(
        &self,
        authorizer: &dyn Authorizer,
        view: &dyn DirectoryView,
        s: &mut Session,
        pdu: &[u8],
        now: chrono::DateTime<Utc>,
    ) -> (Vec<Reply>, After) {
        let msg = proto::decode_message(pdu).expect("the test PDU decodes");
        let deps = LdapDeps { authorizer, view, posix: &self.posix, ldap: self.ldap(), audit: self.events.as_ref() };
        let served = serve(&deps, s, msg, now).await;
        (served.pdus.iter().map(|p| client::read_reply(p).expect("a reply decodes")).collect(), served.after)
    }

    async fn send(&self, s: &mut Session, pdu: &[u8]) -> Vec<Reply> {
        let gate = self.gate();
        self.send_with(&gate, &gate, s, pdu, Utc::now()).await.0
    }

    async fn passcode(&self, entity_id: &str, login: &str, env: &str) -> String {
        let (code, _) = self.ldap().mint_passcode(entity_id, login, env, 120, Utc::now()).await.unwrap();
        code.to_string()
    }

    async fn bind(&self, s: &mut Session, name: &str, password: &str) -> i64 {
        let replies = self.send(s, &client::bind_simple(1, name, password)).await;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].tag, tag::BIND_RESPONSE);
        replies[0].code.unwrap()
    }

    /// (entries, the done code).
    async fn search(
        &self,
        client_name: &str,
        base: &str,
        scope: Scope,
        f: &Filter,
        attrs: &[&str],
    ) -> (Vec<Reply>, i64) {
        self.search_limited(client_name, base, scope, 0, f, attrs).await
    }

    async fn search_limited(
        &self,
        client_name: &str,
        base: &str,
        scope: Scope,
        size_limit: i32,
        f: &Filter,
        attrs: &[&str],
    ) -> (Vec<Reply>, i64) {
        let mut s = self.session(client_name);
        let mut replies = self.send(&mut s, &client::search(7, base, scope, size_limit, f, attrs)).await;
        let done = replies.pop().expect("a done");
        assert_eq!(done.tag, tag::SEARCH_RESULT_DONE);
        assert!(replies.iter().all(|r| r.tag == tag::SEARCH_RESULT_ENTRY && r.id == 7));
        (replies, done.code.unwrap())
    }

    async fn uid(&self, entity_id: &str) -> u32 {
        self.posix.get_identity(entity_id).await.unwrap().unwrap().uid
    }
}

fn dns(entries: &[Reply]) -> Vec<String> {
    entries.iter().map(|e| e.dn.clone()).collect()
}

fn and(items: Vec<Filter>) -> Filter {
    Filter::And(items)
}

// ─── Codec ──────────────────────────────────────────────────────────

fn sample_filter() -> Filter {
    and(vec![
        Filter::eq("objectClass", "posixAccount"),
        Filter::Or(vec![
            Filter::eq("uid", "alice"),
            Filter::Substrings(
                "cn".into(),
                Substrings { initial: Some(b"al".to_vec()), any: vec![b"ic".to_vec()], last: Some(b"e".to_vec()) },
            ),
        ]),
        Filter::Not(Box::new(Filter::eq("uidNumber", "0"))),
        Filter::GreaterOrEqual("uidnumber".into(), b"1000".to_vec()),
        Filter::LessOrEqual("gidnumber".into(), b"99999999".to_vec()),
        Filter::Approx("uid".into(), b"alice".to_vec()),
        Filter::present("uid"),
        Filter::Extensible,
    ])
}

#[test]
fn codec_round_trips() {
    // Bind (simple and SASL), search, unbind, StartTLS, the write operations.
    let msg = proto::decode_message(&client::bind_simple(5, &dn("alice"), "secret-passcode")).unwrap();
    assert_eq!(msg.id, 5);
    let Op::Bind(b) = msg.op else { panic!("not a bind") };
    assert_eq!((b.version, b.name.as_str()), (3, dn("alice").as_str()));
    assert!(matches!(&b.auth, BindAuth::Simple(p) if p.as_slice() == b"secret-passcode"));
    assert!(!format!("{:?}", b.auth).contains("secret"), "Debug never prints the password");
    let msg = proto::decode_message(&client::bind_sasl(6, "EXTERNAL", None)).unwrap();
    assert!(matches!(msg.op, Op::Bind(BindRequest { auth: BindAuth::Sasl { ref mechanism, credentials: None }, .. })
        if mechanism == "EXTERNAL"));

    let f = sample_filter();
    let msg = proto::decode_message(&client::search(9, BASE, Scope::Sub, 5, &f, &["uid", "1.1"])).unwrap();
    let Op::Search(s) = msg.op else { panic!("not a search") };
    assert_eq!((s.base.as_str(), s.scope, s.size_limit, s.time_limit), (BASE, Scope::Sub, 5, 0));
    assert_eq!(s.filter, f, "every filter variant round-trips");
    assert_eq!(s.attributes, ["uid", "1.1"]);

    assert!(matches!(proto::decode_message(&client::unbind(3)).unwrap().op, Op::Unbind));
    let msg = proto::decode_message(&client::start_tls(4)).unwrap();
    assert!(matches!(msg.op, Op::Extended { ref oid } if oid == proto::OID_STARTTLS));
    for w in [WriteOp::Modify, WriteOp::Add, WriteOp::Delete, WriteOp::ModifyDn, WriteOp::Compare] {
        let msg = proto::decode_message(&client::write(2, w, &dn("alice"))).unwrap();
        assert!(matches!(msg.op, Op::Write(op) if op == w), "{w:?}");
    }

    // Responses read back.
    let values = vec!["a".to_string(), "b".to_string()];
    let entry = proto::search_entry(9, &dn("alice"), &[("memberUid", values.as_slice())], false);
    let r = client::read_reply(&entry).unwrap();
    assert_eq!(
        (r.tag, r.dn.as_str(), r.values("memberuid")),
        (tag::SEARCH_RESULT_ENTRY, dn("alice").as_str(), vec!["a", "b"])
    );
    let typed = client::read_reply(&proto::search_entry(9, "", &[("cn", values.as_slice())], true)).unwrap();
    assert_eq!(typed.attrs, [("cn".to_string(), Vec::<String>::new())], "typesOnly sends no values");
    let done =
        client::read_reply(&proto::result(9, tag::SEARCH_RESULT_DONE, ResultCode::NoSuchObject, "", "x")).unwrap();
    assert_eq!((done.code, done.message.as_str()), (Some(32), "x"));
    let notice = client::read_reply(&proto::notice_of_disconnection(ResultCode::ProtocolError, "m")).unwrap();
    assert_eq!(
        (notice.id, notice.code, notice.response_name.as_deref()),
        (0, Some(2), Some(proto::OID_NOTICE_OF_DISCONNECTION))
    );
}

/// A search PDU whose filter element is `filter` (already encoded).
fn raw_search(filter: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ber::nest(&mut out, tag::SEQUENCE, |m| {
        ber::put_int(m, tag::INTEGER, 2);
        ber::nest(m, tag::SEARCH_REQUEST, |s| {
            ber::put(s, tag::OCTET_STRING, BASE.as_bytes());
            ber::put_int(s, tag::ENUMERATED, 2);
            ber::put_int(s, tag::ENUMERATED, 0);
            ber::put_int(s, tag::INTEGER, 0);
            ber::put_int(s, tag::INTEGER, 0);
            ber::put_bool(s, tag::BOOLEAN, false);
            s.extend_from_slice(filter);
            ber::nest(s, tag::SEQUENCE, |_| {});
        });
    });
    out
}

/// An LDAPMessage around an arbitrary protocol-op element.
fn raw_message(id: i64, op: &[u8], trailer: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ber::nest(&mut out, tag::SEQUENCE, |m| {
        ber::put_int(m, tag::INTEGER, id);
        m.extend_from_slice(op);
        m.extend_from_slice(trailer);
    });
    out
}

fn nested_not(depth: usize) -> Vec<u8> {
    let mut f = Vec::new();
    Filter::present("uid").encode(&mut f);
    for _ in 0..depth {
        let mut outer = Vec::new();
        ber::put(&mut outer, 0xa2, &f);
        f = outer;
    }
    f
}

#[test]
fn malformed_pdus_are_refused() {
    let good = client::search(2, BASE, Scope::Sub, 0, &Filter::present("uid"), &[]);
    assert!(proto::decode_message(&good).is_ok());
    let wide = Filter::Or((0..200).map(|i| Filter::eq("uid", &format!("u{i}"))).collect());
    let mut wide_bytes = Vec::new();
    wide.encode(&mut wide_bytes);
    let mut sub_bad_order = Vec::new();
    ber::nest(&mut sub_bad_order, 0xa4, |s| {
        ber::put(s, 0x04, b"cn");
        ber::nest(s, 0x30, |p| {
            ber::put(p, 0x82, b"z");
            ber::put(p, 0x80, b"a");
        });
    });
    let mut long_value = Vec::new();
    Filter::Equality("uid".into(), vec![b'a'; 300]).encode(&mut long_value);
    let names: Vec<String> = (0..65).map(|i| format!("a{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let too_many_attrs = client::search(2, BASE, Scope::Sub, 0, &Filter::present("uid"), &refs);
    let mut controls = Vec::new();
    ber::nest(&mut controls, tag::CONTROLS, |c| {
        for _ in 0..17 {
            ber::nest(c, tag::SEQUENCE, |x| ber::put(x, tag::OCTET_STRING, b"1.2.3"));
        }
    });
    let mut bad_bool = Vec::new();
    ber::nest(&mut bad_bool, tag::SEARCH_REQUEST, |s| {
        ber::put(s, tag::OCTET_STRING, BASE.as_bytes());
        ber::put_int(s, tag::ENUMERATED, 2);
        ber::put_int(s, tag::ENUMERATED, 0);
        ber::put_int(s, tag::INTEGER, 0);
        ber::put_int(s, tag::INTEGER, 0);
        ber::put(s, tag::BOOLEAN, &[0, 0]);
    });
    let mut constructed_dn = Vec::new();
    ber::nest(&mut constructed_dn, tag::BIND_REQUEST, |b| {
        ber::put_int(b, tag::INTEGER, 3);
        ber::nest(b, 0x24, |s| ber::put(s, tag::OCTET_STRING, b"uid=a"));
        ber::put(b, tag::AUTH_SIMPLE, b"x");
    });
    let mut non_utf8_dn = Vec::new();
    ber::nest(&mut non_utf8_dn, tag::BIND_REQUEST, |b| {
        ber::put_int(b, tag::INTEGER, 3);
        ber::put(b, tag::OCTET_STRING, &[0xff, 0xfe]);
        ber::put(b, tag::AUTH_SIMPLE, b"x");
    });
    let mut five_octet_id = vec![0x30, 0x09, 0x02, 0x05, 0, 0, 0, 0, 1];
    five_octet_id.extend_from_slice(&[0x42, 0x00]);

    let cases: Vec<(&str, Vec<u8>, BerError)> = vec![
        ("truncated", good[..good.len() - 3].to_vec(), BerError::Truncated),
        ("empty", vec![], BerError::Truncated),
        ("oversized length", vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02], BerError::TooLarge),
        ("indefinite length", vec![0x30, 0x80, 0x02, 0x01, 0x01, 0x42, 0x00, 0x00, 0x00], BerError::IndefiniteLength),
        ("length of five octets", vec![0x30, 0x85, 0, 0, 0, 0, 5], BerError::LengthTooLong),
        ("high tag number", raw_message(1, &[0x7f, 0x01, 0x00], &[]), BerError::HighTagNumber),
        ("wrong outer tag", vec![0x31, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00], BerError::UnexpectedTag),
        ("message id not an integer", vec![0x30, 0x05, 0x04, 0x01, 0x01, 0x42, 0x00], BerError::UnexpectedTag),
        ("message id zero", vec![0x30, 0x05, 0x02, 0x01, 0x00, 0x42, 0x00], BerError::BadInteger),
        ("negative message id", vec![0x30, 0x05, 0x02, 0x01, 0xff, 0x42, 0x00], BerError::BadInteger),
        ("integer of five octets", five_octet_id, BerError::BadInteger),
        ("unknown operation", raw_message(1, &[0x7a, 0x00], &[]), BerError::UnexpectedTag),
        ("unbind with content", raw_message(1, &[0x42, 0x01, 0x00], &[]), BerError::TrailingData),
        ("trailing data after the message", [good.clone(), vec![0x00]].concat(), BerError::TrailingData),
        ("trailing element in the message", raw_message(1, &[0x42, 0x00], &[0x04, 0x00]), BerError::TrailingData),
        ("deep nesting", raw_search(&nested_not(40)), BerError::TooDeep),
        ("huge filter", raw_search(&wide_bytes), BerError::TooMany),
        ("filter with a bad tag", raw_search(&[0x8a, 0x01, b'x']), BerError::UnexpectedTag),
        ("substrings out of order", raw_search(&sub_bad_order), BerError::UnexpectedTag),
        ("assertion too long", raw_search(&long_value), BerError::TooLarge),
        ("attribute with a bad character", raw_search(&[0x87, 0x03, b'u', b'(', b'd']), BerError::BadString),
        ("too many requested attributes", too_many_attrs, BerError::TooMany),
        ("too many controls", raw_message(1, &[0x42, 0x00], &controls), BerError::TooMany),
        ("boolean of two octets", raw_message(1, &bad_bool, &[]), BerError::BadBoolean),
        ("constructed OCTET STRING", raw_message(1, &constructed_dn, &[]), BerError::UnexpectedTag),
        ("DN not UTF-8", raw_message(1, &non_utf8_dn, &[]), BerError::BadString),
    ];
    for (what, pdu, want) in cases {
        let got = proto::decode_message(&pdu).map(|_| ()).map_err(|e| e.error);
        assert_eq!(got, Err(want), "{what}");
    }
    // Nesting just inside the bound decodes.
    assert!(proto::decode_message(&raw_search(&nested_not(filter::MAX_FILTER_DEPTH - 1))).is_ok());
}

/// A seeded xorshift so the run is deterministic.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn decoder_survives_mutated_and_random_input() {
    let seeds: Vec<Vec<u8>> = vec![
        client::bind_simple(1, &dn("alice"), "0123456789abcdef0123456789abcdef"),
        client::bind_sasl(2, "EXTERNAL", Some(b"dn:x")),
        client::search(3, BASE, Scope::Sub, 10, &sample_filter(), &["uid", "cn"]),
        client::unbind(4),
        client::start_tls(5),
        client::write(6, WriteOp::Modify, &dn("alice")),
        raw_search(&nested_not(12)),
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut decoded = 0usize;
    for _ in 0..30_000 {
        let mut pdu = seeds[rng.below(seeds.len())].clone();
        for _ in 0..=rng.below(4) {
            match rng.below(4) {
                0 if !pdu.is_empty() => {
                    let i = rng.below(pdu.len());
                    pdu[i] = rng.next() as u8;
                }
                1 if !pdu.is_empty() => pdu.truncate(rng.below(pdu.len())),
                2 => {
                    let i = rng.below(pdu.len() + 1);
                    pdu.insert(i, rng.next() as u8);
                }
                _ if !pdu.is_empty() => {
                    let i = rng.below(pdu.len());
                    pdu[i] ^= 0x80;
                }
                _ => {}
            }
        }
        if proto::decode_message(&pdu).is_ok() {
            decoded += 1;
        }
        let _ = ber::pdu_len(&pdu[..pdu.len().min(6)]);
    }
    for _ in 0..30_000 {
        let len = rng.below(96);
        let pdu: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = proto::decode_message(&pdu);
        let mut framed = vec![0x30];
        ber::put_len(&mut framed, pdu.len());
        framed.extend_from_slice(&pdu);
        let _ = proto::decode_message(&framed);
    }
    assert!(decoded > 0, "some mutations stay valid, so the run reaches the deeper decoders");
}

// ─── Filters ────────────────────────────────────────────────────────

#[test]
fn filters_evaluate_in_three_valued_logic() {
    let layout = Layout { base: dn::Dn::parse(BASE).unwrap(), home_base: "/home".into(), shell: "/bin/sh".into() };
    let p = directory::Person {
        entity_id: "e".into(),
        login: "alice".into(),
        uid: 80017,
        gid: 80017,
        gids: vec![],
        display_name: "Alice Souza".into(),
    };
    let e = layout.person(&p);
    let t = |f: Filter| f.evaluate(&e);
    assert_eq!(t(Filter::eq("objectClass", "POSIXACCOUNT")), Some(true), "case-insensitive");
    assert_eq!(t(Filter::eq("uid", "bob")), Some(false));
    assert_eq!(t(Filter::eq("uidNumber", "80017")), Some(true), "numeric");
    assert_eq!(t(Filter::eq("uidNumber", "080017")), Some(true), "numeric, not textual");
    assert_eq!(t(Filter::eq("uidNumber", "x")), None, "not a number: Undefined");
    assert_eq!(t(Filter::GreaterOrEqual("uidnumber".into(), b"80000".to_vec())), Some(true));
    assert_eq!(t(Filter::LessOrEqual("uidnumber".into(), b"80000".to_vec())), Some(false));
    assert_eq!(t(Filter::GreaterOrEqual("objectclass".into(), b"a".to_vec())), None, "no ordering rule");
    assert_eq!(t(Filter::eq("memberUid", "alice")), Some(false), "known but absent: FALSE");
    assert_eq!(t(Filter::eq("userPassword", "x")), None, "unknown attribute: Undefined");
    assert_eq!(t(Filter::Not(Box::new(Filter::eq("userPassword", "x")))), None, "NOT Undefined is Undefined");
    assert_eq!(t(Filter::present("userPassword")), Some(false));
    assert_eq!(t(Filter::present("objectclass")), Some(true));
    let sub = |i: Option<&str>, any: &[&str], f: Option<&str>| {
        Filter::Substrings(
            "cn".into(),
            Substrings {
                initial: i.map(|s| s.as_bytes().to_vec()),
                any: any.iter().map(|s| s.as_bytes().to_vec()).collect(),
                last: f.map(|s| s.as_bytes().to_vec()),
            },
        )
    };
    assert_eq!(t(sub(Some("ALI"), &["sou"], Some("za"))), Some(true));
    assert_eq!(t(sub(Some("alice souza"), &[], Some("za"))), Some(false), "parts do not overlap");
    assert_eq!(t(sub(None, &["za", "sou"], None)), Some(false), "order matters");
    assert_eq!(t(Filter::Substrings("uidnumber".into(), Substrings::default())), None);
    assert_eq!(t(Filter::Extensible), None);
    assert_eq!(t(Filter::And(vec![])), Some(true), "(&) is TRUE");
    assert_eq!(t(Filter::Or(vec![])), Some(false), "(|) is FALSE");
    assert_eq!(t(and(vec![Filter::eq("uid", "alice"), Filter::eq("userPassword", "x")])), None);
    assert_eq!(t(and(vec![Filter::eq("uid", "bob"), Filter::eq("userPassword", "x")])), Some(false));
    assert_eq!(t(Filter::Or(vec![Filter::eq("uid", "alice"), Filter::Extensible])), Some(true));
    assert_eq!(and(vec![Filter::eq("objectClass", "x"), Filter::eq("UID", "Bob")]).uid_hint(), Some(&b"Bob"[..]));
    assert_eq!(Filter::Or(vec![Filter::eq("uid", "bob")]).uid_hint(), None, "only a conjunct narrows");
}

// ─── Binds ──────────────────────────────────────────────────────────

#[tokio::test]
async fn bind_succeeds_only_with_a_live_gate_allow_and_a_one_time_passcode() {
    let fx = fixture().await;
    let code = fx.passcode("e-alice", "alice", "prod").await;
    let mut s = fx.session("host-prod");
    assert_eq!(fx.bind(&mut s, &dn("alice"), &code).await, 0);
    assert_eq!(s.bound, Bound::User("alice".into()));
    assert_eq!(fx.issue_events.take(), ["idp.issue:ldap:allow"]);
    let events = fx.events.take();
    assert_eq!(events.len(), 1);
    let (name, f) = &events[0];
    assert_eq!((*name, f["decision"].as_str(), f["login"].as_str()), (events::BIND, Some("success"), Some("alice")));
    assert_eq!((f["client"].as_str(), f["environment"].as_str()), (Some("host-prod"), Some("prod")));
    assert_eq!(f["uid"].as_u64(), Some(u64::from(fx.uid("e-alice").await)));
    // Single use: the same passcode again is refused, and the session is
    // anonymous again after the refused bind.
    assert_eq!(fx.bind(&mut s, &dn("alice"), &code).await, 49);
    assert_eq!(s.bound, Bound::Anonymous);
    assert_eq!(fx.events.summary(), ["idp.ldap.bind:refused:bad_passcode"]);
    // The DN is matched case-insensitively and the base is the stored one.
    let code = fx.passcode("e-alice", "alice", "prod").await;
    assert_eq!(fx.bind(&mut s, " UID=Alice,OU=People,DC=example,DC=com", &code).await, 0);
}

#[tokio::test]
async fn every_bind_refusal_is_audited_and_no_event_holds_a_passcode() {
    let fx = fixture().await;
    let mut minted = Vec::new();
    let mut mint = |code: String| {
        minted.push(code.clone());
        code
    };
    let alice_dev = mint(fx.passcode("e-alice", "alice", "dev").await);
    let alice_late = mint(fx.passcode("e-alice", "alice", "prod").await);
    let dora = mint(fx.passcode("e-dora", "dora", "prod").await);
    let remy = mint(fx.passcode("e-remy", "remy", "prod").await);
    let nora = mint(fx.passcode("e-nora", "nora", "prod").await);
    let exp = mint(fx.passcode("e-exp", "exp", "prod").await);
    let bob = mint(fx.passcode("e-bob", "bob", "prod").await);
    let wrong = "0".repeat(32);
    let cases: Vec<(&str, String, String, i64, &str)> = vec![
        ("anonymous", String::new(), String::new(), 48, "anonymous_bind"),
        ("unauthenticated", dn("alice"), String::new(), 53, "unauthenticated_bind"),
        ("password without a DN", String::new(), wrong.clone(), 49, "bad_dn"),
        ("DN outside the people branch", format!("uid=alice,ou=groups,{BASE}"), wrong.clone(), 49, "bad_dn"),
        ("DN under another base", "uid=alice,ou=people,dc=other".into(), wrong.clone(), 49, "bad_dn"),
        ("reserved login", dn("root"), wrong.clone(), 49, "bad_dn"),
        ("not a passcode", dn("alice"), "hunter2".into(), 49, "bad_passcode"),
        ("unknown login", dn("zed"), wrong.clone(), 49, "unknown_login"),
        ("wrong passcode", dn("alice"), wrong.clone(), 49, "bad_passcode"),
        ("passcode for another environment", dn("alice"), alice_dev.clone(), 49, "environment_mismatch"),
        ("disabled identity", dn("dora"), dora.clone(), 49, "issue_denied"),
        ("removed identity", dn("remy"), remy.clone(), 49, "issue_denied"),
        ("not entitled", dn("nora"), nora.clone(), 49, "issue_denied"),
        ("entitlement expired", dn("exp"), exp.clone(), 49, "issue_denied"),
        ("entitled elsewhere only", dn("bob"), bob.clone(), 49, "issue_denied"),
    ];
    for (what, name, password, code, reason) in &cases {
        let mut s = fx.session("host-prod");
        assert_eq!(fx.bind(&mut s, name, password).await, *code, "{what}");
        assert_eq!(s.bound, Bound::Anonymous, "{what}");
        assert_eq!(fx.events.summary(), [format!("idp.ldap.bind:refused:{reason}")], "{what}");
    }
    let gate: Vec<String> = fx.issue_events.take();
    assert_eq!(
        gate,
        [
            "idp.issue-denied:ldap:identity_disabled",
            "idp.issue-denied:ldap:identity_removed",
            "idp.issue-denied:ldap:not_entitled",
            "idp.issue-denied:ldap:entitlement_expired",
            "idp.issue-denied:ldap:not_entitled",
        ]
    );

    // Expired: the bind is judged at a later instant.
    let gate_ = fx.gate();
    let mut s = fx.session("host-prod");
    let later = Utc::now() + Duration::minutes(10);
    let (r, _) = fx.send_with(&gate_, &gate_, &mut s, &client::bind_simple(1, &dn("alice"), &alice_late), later).await;
    assert_eq!(r[0].code, Some(49));
    assert_eq!(fx.events.summary(), ["idp.ldap.bind:refused:passcode_expired"]);

    // SASL: EXTERNAL over TLS only, with no authorisation identity.
    let mut s = fx.session("host-prod");
    let sasl = |mech: &str, creds: Option<&[u8]>| client::bind_sasl(3, mech, creds);
    assert_eq!(fx.send(&mut s, &sasl("EXTERNAL", None)).await[0].code, Some(0));
    assert_eq!(s.bound, Bound::External);
    assert_eq!(fx.send(&mut s, &sasl("EXTERNAL", Some(b"dn:uid=root"))).await[0].code, Some(49));
    assert_eq!(fx.send(&mut s, &sasl("PLAIN", Some(b"\0alice\0x"))).await[0].code, Some(7));
    let mut plain = fx.session("legacy");
    assert_eq!(fx.send(&mut plain, &sasl("EXTERNAL", None)).await[0].code, Some(48));
    let mut v2 = client::bind_simple(4, &dn("alice"), &wrong);
    let at = v2.iter().position(|b| *b == 0x60).unwrap();
    v2[at + 4] = 2; // version INTEGER content
    assert_eq!(fx.send(&mut s, &v2).await[0].code, Some(2));
    assert_eq!(
        fx.events.summary(),
        [
            "idp.ldap.bind:success:-",
            "idp.ldap.bind:refused:authzid_refused",
            "idp.ldap.bind:refused:unsupported_mechanism",
            "idp.ldap.bind:refused:external_without_tls",
            "idp.ldap.bind:refused:unsupported_version",
        ]
    );

    // Run everything again and check no event, gate event or log field
    // holds a passcode or password.
    for (_, name, password, _, _) in &cases {
        let mut s = fx.session("host-prod");
        let _ = fx.bind(&mut s, name, password).await;
    }
    let all = format!("{:?}{:?}", fx.events.take(), fx.issue_events.events.lock().unwrap());
    for secret in minted.iter().chain([&wrong, &"hunter2".to_string()]) {
        assert!(!all.contains(secret.as_str()), "an audit event holds a credential");
    }
}

#[tokio::test]
async fn disabling_an_identity_refuses_its_next_bind_and_hides_it_at_once() {
    let fx = fixture().await;
    let first = fx.passcode("e-alice", "alice", "prod").await;
    let second = fx.passcode("e-alice", "alice", "prod").await;
    let mut s = fx.session("host-prod");
    assert_eq!(fx.bind(&mut s, &dn("alice"), &first).await, 0);
    let people = Filter::eq("objectClass", "posixAccount");
    let (entries, _) = fx.search("host-prod", BASE, Scope::Sub, &people, &["uid"]).await;
    assert!(dns(&entries).contains(&dn("alice")));

    fx.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(fx.bind(&mut s, &dn("alice"), &second).await, 49);
    let (entries, code) = fx.search("host-prod", BASE, Scope::Sub, &people, &["uid"]).await;
    assert_eq!((code, dns(&entries)), (0, vec![dn("carol")]));
    let (entries, _) = fx.search("host-prod", &dn("alice"), Scope::Base, &Filter::present("objectClass"), &[]).await;
    assert!(entries.is_empty());
    fx.posix.transition("e-alice", IdentityState::Active, None).await.unwrap();
    let third = fx.passcode("e-alice", "alice", "prod").await;
    assert_eq!(fx.bind(&mut s, &dn("alice"), &third).await, 0, "reinstated");
}

// ─── Clients ────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unknown_deleted_or_repinned_client_is_refused_and_closed() {
    let fx = fixture().await;
    let gate = fx.gate();
    let search = client::search(2, BASE, Scope::Sub, 0, &Filter::present("objectClass"), &[]);
    let refused = |r: &[Reply], after: After| {
        assert_eq!((r.len(), r[0].code, r[1].id, after), (2, Some(52), 0, After::Close));
        assert_eq!(r[1].response_name.as_deref(), Some(proto::OID_NOTICE_OF_DISCONNECTION));
    };
    let mut ghost = fx.session("ghost");
    let (r, after) = fx.send_with(&gate, &gate, &mut ghost, &search, Utc::now()).await;
    refused(&r, after);
    assert_eq!(fx.events.summary(), ["idp.ldap.refused:refused:unknown_client"]);

    let mut s = fx.session("host-prod");
    assert_eq!(fx.send(&mut s, &search).await.last().unwrap().code, Some(0));
    let repin = ClientWrite { name: "host-prod".into(), cert_sha256: Some(fp('d')), ..Default::default() };
    fx.ldap().put_client(&fx.authz, repin, Utc::now()).await.unwrap();
    let (r, after) = fx.send_with(&gate, &gate, &mut s, &search, Utc::now()).await;
    refused(&r, after);

    let mut legacy = fx.session("legacy");
    assert_eq!(fx.send(&mut legacy, &search).await.last().unwrap().code, Some(0));
    fx.ldap().delete_client("legacy").await.unwrap();
    let (r, after) = fx.send_with(&gate, &gate, &mut legacy, &search, Utc::now()).await;
    refused(&r, after);
    let off = ConfigUpdate { enabled: Some(false), ..Default::default() };
    fx.ldap().put_config(off, Utc::now()).await.unwrap();
    let mut dev = fx.session("host-dev");
    let (r, after) = fx.send_with(&gate, &gate, &mut dev, &search, Utc::now()).await;
    refused(&r, after);
    let summary = fx.events.summary();
    assert_eq!(
        summary,
        [
            "idp.ldap.search:allow:-",
            "idp.ldap.refused:refused:unknown_client",
            "idp.ldap.search:allow:-",
            "idp.ldap.refused:refused:unknown_client",
            "idp.ldap.refused:refused:directory_disabled",
        ]
    );
}

// ─── Searches ───────────────────────────────────────────────────────

#[tokio::test]
async fn searches_serve_posix_entries_of_the_clients_environment_only() {
    let fx = fixture().await;
    let (alice_uid, carol_uid, bob_uid) = (fx.uid("e-alice").await, fx.uid("e-carol").await, fx.uid("e-bob").await);
    let people = Filter::eq("objectClass", "posixAccount");
    let (entries, code) = fx.search("host-prod", BASE, Scope::Sub, &people, &[]).await;
    assert_eq!((code, dns(&entries)), (0, vec![dn("alice"), dn("carol")]), "not bob (dev), dora, remy, nora, exp");
    let alice = &entries[0];
    assert_eq!(alice.values("objectClass"), ["top", "account", "posixAccount"]);
    assert_eq!(alice.values("uid"), ["alice"]);
    assert_eq!(alice.values("cn"), ["Alice Souza"]);
    assert_eq!(alice.values("gecos"), ["Alice Souza"]);
    assert_eq!(alice.values("uidNumber"), [alice_uid.to_string()]);
    assert_eq!(alice.values("gidNumber"), [alice_uid.to_string()], "user-private group");
    assert_eq!(alice.values("homeDirectory"), ["/home/alice"]);
    assert_eq!(alice.values("loginShell"), ["/bin/bash"]);
    let carol = &entries[1];
    assert_eq!((carol.values("cn"), carol.values("gecos")), (vec!["carol"], vec![]));
    for e in &entries {
        let names: Vec<String> = e.attrs.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        assert!(!names.iter().any(|n| n.contains("password") || n.contains("shadow")), "{names:?}");
    }
    let search_event = fx.events.take().pop().unwrap().1;
    assert_eq!((search_event["entries"].as_u64(), search_event["hidden"].as_u64()), (Some(2), Some(3)));
    assert!(fx.issue_events.take().is_empty(), "visibility is not an issuance");

    // Groups: private groups without members, gid.4000 with visible members.
    let groups = Filter::eq("objectClass", "posixGroup");
    let (entries, _) = fx.search("host-prod", BASE, Scope::Sub, &groups, &[]).await;
    let g = |c: &str| format!("cn={c},ou=groups,{BASE}");
    assert_eq!(dns(&entries), [g("alice"), g("carol"), g("gid.4000")]);
    assert_eq!(entries[0].values("gidNumber"), [alice_uid.to_string()]);
    assert!(entries[0].values("memberUid").is_empty(), "a private group lists no members");
    assert_eq!(entries[1].values("gidNumber"), [carol_uid.to_string()]);
    assert_eq!(entries[2].values("memberUid"), ["alice", "carol"], "not dora (disabled)");
    let (entries, _) = fx.search("host-prod", BASE, Scope::Sub, &Filter::eq("memberUid", "alice"), &["cn"]).await;
    assert_eq!(dns(&entries), [g("gid.4000")]);
    assert_eq!(entries[0].attrs, [("cn".to_string(), vec!["gid.4000".to_string()])], "only the asked attribute");

    // The dev client sees dev's identities only.
    let (entries, _) =
        fx.search("host-dev", BASE, Scope::Sub, &Filter::Or(vec![people.clone(), groups]), &["1.1"]).await;
    assert_eq!(dns(&entries), [dn("alice"), dn("bob"), g("alice"), g("bob"), g("gid.4000")]);
    assert!(entries.iter().all(|e| e.attrs.is_empty()), "1.1 asks for no attribute");
    let (entries, _) = fx.search("host-dev", &g("gid.4000"), Scope::Base, &Filter::present("cn"), &["memberUid"]).await;
    assert_eq!(entries[0].values("memberUid"), ["alice"]);
    let (entries, _) =
        fx.search("host-dev", &dn("bob"), Scope::Base, &Filter::present("objectClass"), &["uidNumber"]).await;
    assert_eq!(entries[0].values("uidNumber"), [bob_uid.to_string()]);

    // An identity another environment holds, or an inactive one, does not exist here.
    for who in ["bob", "dora", "remy", "nora", "exp", "nobody"] {
        let (entries, code) = fx.search("host-prod", &dn(who), Scope::Base, &Filter::present("objectClass"), &[]).await;
        assert_eq!((entries.len(), code), (0, 32), "{who}");
    }
    let (entries, code) = fx.search("host-prod", BASE, Scope::Sub, &Filter::eq("uid", "bob"), &[]).await;
    assert_eq!((entries.len(), code), (0, 0));
    let (entries, _) =
        fx.search("host-prod", BASE, Scope::Sub, &and(vec![people.clone(), Filter::eq("UID", "Alice")]), &[]).await;
    assert_eq!(dns(&entries), [dn("alice")]);

    // Structure, scopes and the root DSE.
    let any = Filter::present("objectClass");
    let (entries, _) = fx.search("host-prod", BASE, Scope::One, &any, &[]).await;
    assert_eq!(dns(&entries), [format!("ou=people,{BASE}"), format!("ou=groups,{BASE}")]);
    let (entries, _) = fx.search("host-prod", &format!("ou=people,{BASE}"), Scope::One, &any, &[]).await;
    assert_eq!(dns(&entries), [dn("alice"), dn("carol")]);
    let (entries, _) = fx.search("host-prod", BASE, Scope::Base, &any, &[]).await;
    assert_eq!((dns(&entries), entries[0].values("dc")), (vec![BASE.to_string()], vec!["example"]));
    let (entries, _) = fx.search("host-prod", "", Scope::Base, &any, &[]).await;
    assert_eq!((entries[0].dn.as_str(), entries[0].values("namingContexts")), ("", vec![BASE]));
    assert_eq!(entries[0].values("supportedSASLMechanisms"), ["EXTERNAL"]);
    let (entries, _) = fx.search("host-prod", "", Scope::Sub, &people, &[]).await;
    assert_eq!(entries.len(), 2, "an empty base with a subtree scope searches the naming context");
    assert_eq!(fx.search("host-prod", "dc=other", Scope::Sub, &any, &[]).await.1, 32);
    assert_eq!(fx.search("host-prod", "uid=a\\,b", Scope::Sub, &any, &[]).await.1, 34);
    assert_eq!(fx.search("host-prod", &format!("ou=other,{BASE}"), Scope::Sub, &any, &[]).await.1, 32);

    // A retired environment serves nothing at all.
    fx.authz.retire_environment("old").await.unwrap();
    let (entries, code) = fx.search("host-old", BASE, Scope::Sub, &people, &[]).await;
    assert_eq!((entries.len(), code), (0, 50));
}

#[tokio::test]
async fn search_limits_hold() {
    let fx = fixture().await;
    let people = Filter::eq("objectClass", "posixAccount");
    let (entries, code) = fx.search_limited("host-prod", BASE, Scope::Sub, 1, &people, &[]).await;
    assert_eq!((dns(&entries), code), (vec![dn("alice")], 4), "the client's size limit");
    let cap = ConfigUpdate { size_limit: Some(1), ..Default::default() };
    fx.ldap().put_config(cap, Utc::now()).await.unwrap();
    let (entries, code) = fx.search_limited("host-prod", BASE, Scope::Sub, 100, &people, &[]).await;
    assert_eq!((entries.len(), code), (1, 4), "the server's size limit wins");

    // Time: a deadline already past stops at the first gate evaluation.
    let cfg = fx.ldap().config().await.unwrap().unwrap();
    let req = SearchRequest {
        base: BASE.into(),
        scope: Scope::Sub,
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: people,
        attributes: vec![],
    };
    let gate = fx.gate();
    let out = run_search(&fx.posix, &gate, "prod", &cfg, &req, true, Instant::now()).await;
    assert_eq!((out.entries.len(), out.code), (0, ResultCode::TimeLimitExceeded));
}

#[tokio::test]
async fn search_entries_are_withheld_when_their_event_cannot_be_recorded() {
    let fx = fixture().await;
    *fx.events.refuse.lock().unwrap() = Some(events::SEARCH);
    let (entries, code) = fx.search("host-prod", BASE, Scope::Sub, &Filter::present("uid"), &[]).await;
    assert_eq!((entries.len(), code), (0, 52));
    *fx.events.refuse.lock().unwrap() = Some(events::BIND);
    let code = fx.passcode("e-alice", "alice", "prod").await;
    let mut s = fx.session("host-prod");
    assert_eq!(fx.bind(&mut s, &dn("alice"), &code).await, 49);
    assert_eq!(s.bound, Bound::Anonymous);
}

// ─── Writes and the rest of the protocol ────────────────────────────

#[tokio::test]
async fn every_write_operation_is_refused() {
    let fx = fixture().await;
    let mut s = fx.session("host-prod");
    for (op, response) in [
        (WriteOp::Modify, tag::MODIFY_RESPONSE),
        (WriteOp::Add, tag::ADD_RESPONSE),
        (WriteOp::Delete, tag::DEL_RESPONSE),
        (WriteOp::ModifyDn, tag::MODDN_RESPONSE),
        (WriteOp::Compare, tag::COMPARE_RESPONSE),
    ] {
        let r = fx.send(&mut s, &client::write(11, op, &dn("alice"))).await;
        assert_eq!((r.len(), r[0].tag, r[0].id, r[0].code), (1, response, 11, Some(53)), "{op:?}");
    }
    assert_eq!(fx.events.summary(), vec!["idp.ldap.refused:refused:write_refused"; 5]);

    // StartTLS on TLS, an unknown extended operation, a critical control.
    let r = fx.send(&mut s, &client::start_tls(12)).await;
    assert_eq!((r[0].tag, r[0].code), (tag::EXTENDED_RESPONSE, Some(1)));
    let mut whoami = Vec::new();
    ber::nest(&mut whoami, tag::EXTENDED_REQUEST, |x| ber::put(x, 0x80, b"1.3.6.1.4.1.4203.1.11.3"));
    let r = fx.send(&mut s, &raw_message(13, &whoami, &[])).await;
    assert_eq!(r[0].code, Some(2));
    let mut critical = Vec::new();
    ber::nest(&mut critical, tag::CONTROLS, |c| {
        ber::nest(c, tag::SEQUENCE, |x| {
            ber::put(x, tag::OCTET_STRING, b"1.2.840.113556.1.4.319");
            ber::put_bool(x, tag::BOOLEAN, true);
        })
    });
    let search = client::search(14, BASE, Scope::Sub, 0, &Filter::present("uid"), &[]);
    let body = &search[2..];
    let mut with_control = Vec::new();
    ber::put(&mut with_control, tag::SEQUENCE, &[body, &critical].concat());
    let r = fx.send(&mut s, &with_control).await;
    assert_eq!((r.len(), r[0].tag, r[0].code), (1, tag::SEARCH_RESULT_DONE, Some(12)), "no entry, refused");
    let mut lax = Vec::new();
    ber::nest(&mut lax, tag::CONTROLS, |c| {
        ber::nest(c, tag::SEQUENCE, |x| ber::put(x, tag::OCTET_STRING, b"1.2.840.113556.1.4.319"))
    });
    let mut with_lax = Vec::new();
    ber::put(&mut with_lax, tag::SEQUENCE, &[body, &lax].concat());
    assert_eq!(fx.send(&mut s, &with_lax).await.last().unwrap().code, Some(0), "non-critical controls are ignored");
    assert_eq!(
        fx.events.summary(),
        [
            "idp.ldap.refused:refused:starttls_refused",
            "idp.ldap.refused:refused:unsupported_extended_operation",
            "idp.ldap.refused:refused:unsupported_critical_control",
            "idp.ldap.search:allow:-",
        ]
    );
    // Unbind closes; abandon has no response.
    let gate = fx.gate();
    let (r, after) = fx.send_with(&gate, &gate, &mut s, &client::unbind(15), Utc::now()).await;
    assert_eq!((r.len(), after), (0, After::Close));
    let mut abandon = Vec::new();
    ber::put_int(&mut abandon, 0x50, 14);
    let (r, after) = fx.send_with(&gate, &gate, &mut s, &raw_message(16, &abandon, &[]), Utc::now()).await;
    assert_eq!((r.len(), after), (0, After::Continue));
}

// ─── The gate ───────────────────────────────────────────────────────

/// Mutation check: with the gate replaced by a stand-in that only reads the
/// identity, the refusals above turn into successes, so those tests fail
/// unless the gate is consulted.
#[tokio::test]
async fn bind_and_search_tests_fail_if_the_gate_is_skipped() {
    let fx = fixture().await;
    let skip = SkipGate { posix: fx.posix.clone() };
    let gate = fx.gate();
    for (entity, login) in
        [("e-dora", "dora"), ("e-remy", "remy"), ("e-nora", "nora"), ("e-exp", "exp"), ("e-bob", "bob")]
    {
        let mut s = fx.session("host-prod");
        let gated = fx.passcode(entity, login, "prod").await;
        let (r, _) = fx.send_with(&gate, &gate, &mut s, &client::bind_simple(1, &dn(login), &gated), Utc::now()).await;
        assert_eq!(r[0].code, Some(49), "{login}: the gate refuses");
        let skipped = fx.passcode(entity, login, "prod").await;
        let (r, _) =
            fx.send_with(&skip, &gate, &mut s, &client::bind_simple(2, &dn(login), &skipped), Utc::now()).await;
        assert_eq!(r[0].code, Some(0), "{login}: without the gate the bind succeeds");
    }
    let mut s = fx.session("host-prod");
    let people = client::search(3, BASE, Scope::Sub, 0, &Filter::eq("objectClass", "posixAccount"), &["uid"]);
    let (r, _) = fx.send_with(&gate, &skip, &mut s, &people, Utc::now()).await;
    let seen: Vec<String> = r.iter().filter(|e| e.tag == tag::SEARCH_RESULT_ENTRY).map(|e| e.dn.clone()).collect();
    assert_eq!(seen, [dn("alice"), dn("bob"), dn("carol"), dn("exp"), dn("nora")], "the view decides what is seen");
}

#[tokio::test]
async fn the_unrecorded_evaluation_is_the_gate_decision_and_records_nothing() {
    let fx = fixture().await;
    let gate = fx.gate();
    for id in ["e-alice", "e-bob", "e-carol", "e-dora", "e-remy", "e-nora", "e-exp", "e-none"] {
        for env in ["prod", "dev", "nope"] {
            let ask = IssueRequest {
                entity_id: id.into(),
                environment: env.into(),
                roles: None,
                caller_namespace: String::new(),
                provider: PROVIDER.into(),
            };
            let quiet = gate.evaluate_unrecorded(&ask).await;
            assert!(fx.issue_events.take().is_empty());
            assert_eq!(quiet, gate.authorize(&ask, None).await, "{id}/{env}");
            assert_eq!(fx.issue_events.take().len(), 1);
        }
    }
}

// ─── Store ──────────────────────────────────────────────────────────

#[tokio::test]
async fn config_is_off_by_default_and_refuses_unsafe_settings() {
    let fx = fixture().await;
    let store = LdapStore::new(MemStorage::new_arc() as Arc<dyn Storage>);
    assert!(store.config().await.unwrap().is_none());
    let cfg = store.put_config(ConfigUpdate::default(), Utc::now()).await.unwrap();
    assert!(!cfg.enabled && !cfg.plaintext_enabled && cfg.ldaps_listen.is_none() && cfg.ldap_listen.is_none());
    assert_eq!(
        (cfg.base_dn.as_str(), cfg.home_directory_base.as_str(), cfg.login_shell.as_str()),
        ("dc=bastionvault", "/home", "/bin/bash")
    );
    assert_eq!((cfg.size_limit, cfg.time_limit_secs, cfg.rate_limit_per_minute), (1000, 10, 600));
    let store_ref = &store;
    let bad = |u: ConfigUpdate| async move { store_ref.put_config(u, Utc::now()).await.unwrap_err().to_string() };
    let listen = |a: &str| Some(a.to_string());
    assert!(bad(ConfigUpdate { ldaps_listen: listen("127.0.0.1:636"), ..Default::default() }).await.contains("tls"));
    assert!(bad(ConfigUpdate { ldap_listen: listen("127.0.0.1:389"), ..Default::default() })
        .await
        .contains("plaintext"));
    assert!(bad(ConfigUpdate { plaintext_enabled: Some(true), ..Default::default() }).await.contains("ldap_listen"));
    let open = ConfigUpdate { ldap_listen: listen("0.0.0.0:389"), plaintext_enabled: Some(true), ..Default::default() };
    assert!(bad(open).await.contains("every interface"));
    assert!(bad(ConfigUpdate { enabled: Some(true), ..Default::default() }).await.contains("needs"));
    for base in ["dc=a\\,b", "", "uid=a+cn=b", "dc=a,dc=b,dc=c,dc=d,dc=e,dc=f,dc=g,dc=h,dc=i"] {
        let r = store.put_config(ConfigUpdate { base_dn: Some(base.into()), ..Default::default() }, Utc::now()).await;
        assert_eq!(r.is_err(), !base.is_empty(), "{base:?}");
    }
    for path in ["home", "/", "/home/../etc", "/home//x", "/home/a b", "/home/$USER"] {
        let u = ConfigUpdate { home_directory_base: Some(path.into()), ..Default::default() };
        assert!(store.put_config(u, Utc::now()).await.is_err(), "{path}");
    }
    assert!(store
        .put_config(ConfigUpdate { login_shell: Some("/bin/../sh".into()), ..Default::default() }, Utc::now())
        .await
        .is_err());
    for u in [
        ConfigUpdate { size_limit: Some(0), ..Default::default() },
        ConfigUpdate { size_limit: Some(MAX_SIZE_LIMIT + 1), ..Default::default() },
        ConfigUpdate { time_limit_secs: Some(MAX_TIME_LIMIT_SECS + 1), ..Default::default() },
        ConfigUpdate { rate_limit_per_minute: Some(0), ..Default::default() },
        ConfigUpdate { passcode_max_ttl_secs: Some(3600), ..Default::default() },
    ] {
        assert!(store.put_config(u, Utc::now()).await.is_err());
    }
    // The fixture's stored base is normalised.
    assert_eq!(fx.ldap().config().await.unwrap().unwrap().base_dn, BASE);
}

#[tokio::test]
async fn clients_are_validated_and_bound_to_one_environment() {
    let fx = fixture().await;
    let ldap = fx.ldap();
    let now = Utc::now();
    let w =
        |name: &str, t: Option<Transport>, env: Option<&str>, cert: Option<String>, addr: Option<&str>| ClientWrite {
            name: name.into(),
            transport: t,
            environment: env.map(str::to_string),
            cert_sha256: cert,
            address: addr.map(str::to_string),
            description: None,
        };
    let status = |r: Result<(LdapClient, bool), RvError>| match r {
        Err(RvError::ErrResponseStatus(s, _)) => s,
        other => panic!("expected a refusal, got {other:?}"),
    };
    let tls = Some(Transport::Tls);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("nope"), Some(fp('e')), None), now).await), 404);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", None, Some("prod"), Some(fp('e')), None), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("prod"), None, None), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("prod"), Some("AB".into()), None), now).await), 400);
    let addr = Some("10.0.0.1");
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("prod"), Some(fp('e')), addr), now).await), 400);
    let plain = Some(Transport::Plain);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", plain, Some("prod"), Some(fp('e')), addr), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", plain, Some("prod"), None, Some("0.0.0.0")), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("prod"), Some(fp('a')), None), now).await), 409);
    assert_eq!(status(ldap.put_client(&fx.authz, w("host-prod", None, Some("dev"), None, None), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("host-prod", plain, None, None, addr), now).await), 400);
    assert_eq!(status(ldap.put_client(&fx.authz, w("BAD", tls, Some("prod"), Some(fp('e')), None), now).await), 400);
    fx.authz.retire_environment("old").await.unwrap();
    assert_eq!(status(ldap.put_client(&fx.authz, w("x", tls, Some("old"), Some(fp('e')), None), now).await), 409);
    // Upper-case hex is folded; the index follows a re-pin and a delete.
    let (c, created) = ldap.put_client(&fx.authz, w("x", tls, Some("prod"), Some(fp('E')), None), now).await.unwrap();
    assert_eq!((c.cert_sha256.as_deref(), created), (Some(fp('e').as_str()), true));
    assert_eq!(ldap.client_for_cert(&fp('e')).await.unwrap().unwrap().name, "x");
    assert!(ldap.client_for_cert(&fp('a')).await.unwrap().is_some());
    assert!(ldap.client_for_addr(LEGACY_IP.parse().unwrap()).await.unwrap().is_some());
    assert!(ldap.client_for_addr("::ffff:192.0.2.50".parse().unwrap()).await.unwrap().is_some(), "v4-mapped folds");
    ldap.delete_client("x").await.unwrap();
    assert!(ldap.client_for_cert(&fp('e')).await.unwrap().is_none());
}

#[tokio::test]
async fn stored_records_are_versioned_and_passcodes_hashed_bounded_single_use() {
    let mem = MemStorage::new_arc();
    let ldap = LdapStore::new(mem.clone() as Arc<dyn Storage>);
    ldap.put_config(ConfigUpdate::default(), Utc::now()).await.unwrap();
    let mut raw: Value = serde_json::from_slice(&mem.raw_get("config").unwrap()).unwrap();
    raw["version"] = 2.into();
    mem.raw_put("config", &serde_json::to_vec(&raw).unwrap());
    assert!(ldap.config().await.unwrap_err().to_string().contains("version 2"));
    raw["version"] = 1.into();
    raw["surprise"] = true.into();
    mem.raw_put("config", &serde_json::to_vec(&raw).unwrap());
    assert!(ldap.config().await.is_err(), "unknown fields are refused");

    let now = Utc::now();
    let (code, rec) = ldap.mint_passcode("e-alice", "alice", "prod", 60, now).await.unwrap();
    assert!(store_passcode_shape(&code));
    assert_eq!((rec.environment.as_str(), rec.roles.clone()), ("prod", None));
    let keys = ldap_keys(&mem, "passcodes/e-alice/").await;
    assert!(keys.iter().all(|k| !k.contains(code.as_str())), "only the hash is a key");
    assert!(keys.iter().all(|k| !String::from_utf8_lossy(&mem.raw_get(k).unwrap()).contains(code.as_str())));
    assert!(ldap.consume_passcode("e-bob", code.as_bytes()).await.unwrap().is_none(), "another identity's");
    assert!(ldap.consume_passcode("e-alice", code.as_bytes()).await.unwrap().is_some());
    assert!(ldap.consume_passcode("e-alice", code.as_bytes()).await.unwrap().is_none(), "single use");
    for _ in 0..8 {
        ldap.mint_passcode("e-alice", "alice", "prod", 60, now).await.unwrap();
    }
    let ninth = ldap.mint_passcode("e-alice", "alice", "prod", 60, now).await.unwrap_err();
    assert!(matches!(ninth, RvError::ErrResponseStatus(429, _)));
    let later = now + Duration::minutes(5);
    assert!(ldap.mint_passcode("e-alice", "alice", "prod", 60, later).await.is_ok(), "expired ones are pruned");
}

fn store_passcode_shape(code: &str) -> bool {
    code.len() == 32 && code.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn ldap_keys(mem: &MemStorage, prefix: &str) -> Vec<String> {
    mem.list(prefix).await.unwrap().into_iter().map(|k| format!("{prefix}{k}")).collect()
}

// ─── Listeners ──────────────────────────────────────────────────────

#[cfg(not(feature = "sync_handler"))]
mod listeners {
    use std::{
        collections::HashSet,
        net::SocketAddr,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration as StdDuration,
    };

    use ldap3::{LdapConnAsync, LdapConnSettings, Scope as L3Scope, SearchEntry, SearchResult};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::provider::{
        ldap_dir::server::{LdapSource, Opened},
        radius::tls::cert_fingerprint,
    };

    struct TestSource {
        fx: Fx,
        sealed: AtomicBool,
    }

    impl LdapSource for TestSource {
        fn open(&self) -> Option<Opened> {
            if self.sealed.load(Ordering::SeqCst) {
                return None;
            }
            Some(Opened {
                posix: self.fx.posix.clone(),
                stores: self.fx.stores.clone(),
                gate: Box::new(self.fx.gate()),
                view: Box::new(self.fx.gate()),
                audit: self.fx.events.clone(),
            })
        }

        fn alive(&self) -> bool {
            true
        }
    }

    async fn wait_for(runtime: &LdapRuntime, f: impl Fn(&ListenerStatus) -> bool) -> ListenerStatus {
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

    async fn wait_event(fx: &Fx, wanted: &str) {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        loop {
            let seen = fx
                .events
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|(_, f)| f.get("reason").and_then(Value::as_str) == Some(wanted));
            if seen {
                return;
            }
            assert!(Instant::now() < deadline, "no `{wanted}` event");
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
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

        /// (certificate PEM, key PEM, certificate DER). Two years at most
        /// and both TLS usages, which stricter TLS stacks (macOS) require.
        fn leaf(&self, san: &str) -> (String, String, Vec<u8>) {
            use chrono::Datelike;
            use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
            let year = Utc::now().year();
            params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
            params.not_after = rcgen::date_time_ymd(year + 1, 1, 1);
            params.extended_key_usages = vec![ServerAuth, ClientAuth];
            let cert = params.signed_by(&key, &*self.issuer).unwrap();
            (cert.pem(), key.serialize_pem(), cert.der().to_vec())
        }
    }

    fn tls_client(ca: &str, cert: &str, key: &str) -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
            )
            .unwrap();
        Arc::new(config)
    }

    async fn connect(url: &str, tls: Option<Arc<rustls::ClientConfig>>, starttls: bool) -> ldap3::Ldap {
        let mut settings = LdapConnSettings::new().set_conn_timeout(StdDuration::from_secs(5)).set_starttls(starttls);
        if let Some(cfg) = tls {
            settings = settings.set_config(cfg);
        }
        let (conn, ldap) = LdapConnAsync::with_settings(settings, url).await.expect("connects");
        ldap3::drive!(conn);
        ldap
    }

    async fn search(ldap: &mut ldap3::Ldap, filter: &str, attrs: Vec<&str>) -> (Vec<SearchEntry>, u32) {
        let SearchResult(rs, res) = ldap.search(BASE, L3Scope::Subtree, filter, attrs).await.unwrap();
        (rs.into_iter().map(SearchEntry::construct).collect(), res.rc)
    }

    async fn start(fx: Fx) -> (Arc<TestSource>, Arc<LdapRuntime>) {
        let source = Arc::new(TestSource { fx, sealed: AtomicBool::new(false) });
        let runtime = Arc::new(LdapRuntime::default());
        runtime.start(source.clone());
        (source, runtime)
    }

    struct Tls {
        ca: String,
        server_cert: String,
        server_key: String,
        host_cert: String,
        host_key: String,
        rogue_cert: String,
        rogue_key: String,
    }

    /// The server and client certificates; the host one is pinned on host-prod.
    async fn tls_material(fx: &Fx) -> Tls {
        let pki = Pki::new();
        let (server_cert, server_key, _) = pki.leaf("localhost");
        let (host_cert, host_key, host_der) = pki.leaf("host.example");
        let (rogue_cert, rogue_key, _) = pki.leaf("rogue.example");
        let pin = ClientWrite {
            name: "host-prod".into(),
            cert_sha256: Some(cert_fingerprint(&host_der)),
            ..Default::default()
        };
        fx.ldap().put_client(&fx.authz, pin, Utc::now()).await.unwrap();
        Tls { ca: pki.issuer.pem(), server_cert, server_key, host_cert, host_key, rogue_cert, rogue_key }
    }

    fn with_tls(t: &Tls, u: ConfigUpdate) -> ConfigUpdate {
        ConfigUpdate {
            tls_cert_pem: Some(t.server_cert.clone()),
            tls_key_pem: Some(Zeroizing::new(t.server_key.clone())),
            client_ca_pem: Some(t.ca.clone()),
            ..u
        }
    }

    async fn local_plain_client(fx: &Fx) {
        let w = ClientWrite {
            name: "local".into(),
            transport: Some(Transport::Plain),
            environment: Some("prod".into()),
            address: Some("127.0.0.1".into()),
            ..Default::default()
        };
        fx.ldap().put_client(&fx.authz, w, Utc::now()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ldaps_serves_a_pinned_client_and_refuses_others() {
        let fx = fixture().await;
        let t = tls_material(&fx).await;
        let on = ConfigUpdate {
            ldaps_listen: Some("127.0.0.1:0".into()),
            ldap_listen: Some(String::new()),
            plaintext_enabled: Some(false),
            ..Default::default()
        };
        let cfg = fx.ldap().put_config(with_tls(&t, on), Utc::now()).await.unwrap();
        assert!(!format!("{cfg:?}").contains("PRIVATE KEY"));
        assert!(!serde_json::to_string(&cfg.to_map()).unwrap().contains("PRIVATE KEY"));
        let (source, runtime) = start(fx).await;
        let status = wait_for(&runtime, |s| s.ldaps.is_some()).await;
        assert!(status.ldap.is_none(), "no cleartext listener unless configured");
        let url = format!("ldaps://localhost:{}", status.ldaps.unwrap().port());

        let mut ldap = connect(&url, Some(tls_client(&t.ca, &t.host_cert, &t.host_key)), false).await;
        assert_eq!(ldap.sasl_external_bind().await.unwrap().rc, 0);
        let code = source.fx.passcode("e-alice", "alice", "prod").await;
        assert_eq!(ldap.simple_bind(&dn("alice"), &code).await.unwrap().rc, 0);
        assert_eq!(ldap.simple_bind(&dn("alice"), &code).await.unwrap().rc, 49, "single use");
        assert_eq!(ldap.simple_bind("", "").await.unwrap().rc, 48, "anonymous");
        let (entries, rc) = search(&mut ldap, "(&(objectClass=posixAccount)(uid=*))", vec!["uid", "uidNumber"]).await;
        assert_eq!(rc, 0);
        let found: Vec<&str> = entries.iter().map(|e| e.dn.as_str()).collect();
        assert_eq!(found, [dn("alice"), dn("carol")]);
        let uid = source.fx.uid("e-alice").await.to_string();
        assert_eq!(entries[0].attrs["uidNumber"], [uid]);
        let (groups, _) =
            search(&mut ldap, "(&(objectClass=posixGroup)(memberUid=alice))", vec!["cn", "memberUid"]).await;
        assert_eq!(groups[0].attrs["memberUid"], ["alice", "carol"]);
        let add = ldap.add(&dn("zed"), vec![("objectClass", HashSet::from(["top"]))]).await.unwrap();
        assert_eq!(add.rc, 53);
        assert_eq!(ldap.delete(&dn("alice")).await.unwrap().rc, 53);
        let replace = vec![ldap3::Mod::Replace("cn", HashSet::from(["x"]))];
        assert_eq!(ldap.modify(&dn("alice"), replace).await.unwrap().rc, 53);
        ldap.unbind().await.unwrap();

        // A certificate from the same CA that no client pins: closed unanswered.
        let rogue = tls_client(&t.ca, &t.rogue_cert, &t.rogue_key);
        let settings = LdapConnSettings::new().set_conn_timeout(StdDuration::from_secs(5)).set_config(rogue);
        if let Ok((conn, mut ldap)) = LdapConnAsync::with_settings(settings, &url).await {
            ldap3::drive!(conn);
            let r = ldap.simple_bind(&dn("alice"), &"0".repeat(32)).await;
            assert!(r.map(|r| r.rc != 0).unwrap_or(true), "an unpinned client gets nothing");
        }
        wait_event(&source.fx, "unknown_client").await;
        // Sealed: the listener stops.
        source.sealed.store(true, Ordering::SeqCst);
        runtime.reconcile_soon();
        wait_for(&runtime, |s| s.ldaps.is_none()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleartext_needs_starttls_unless_opted_in() {
        let fx = fixture().await;
        let t = tls_material(&fx).await;
        let on = ConfigUpdate { plaintext_enabled: Some(false), ..Default::default() };
        fx.ldap().put_config(with_tls(&t, on), Utc::now()).await.unwrap();
        local_plain_client(&fx).await;
        let (source, runtime) = start(fx).await;
        let port = wait_for(&runtime, |s| s.ldap.is_some()).await.ldap.unwrap().port();

        // No opt-in: cleartext operations are refused, even from a plain client's address.
        let mut plain = connect(&format!("ldap://127.0.0.1:{port}"), None, false).await;
        assert_eq!(plain.simple_bind(&dn("alice"), &"0".repeat(32)).await.unwrap().rc, 13);
        let (entries, rc) = search(&mut plain, "(uid=alice)", vec!["uid"]).await;
        assert_eq!((entries.len(), rc), (0, 13));

        // StartTLS with the pinned certificate.
        let tls = Some(tls_client(&t.ca, &t.host_cert, &t.host_key));
        let mut upgraded = connect(&format!("ldap://localhost:{port}"), tls, true).await;
        let (entries, rc) = search(&mut upgraded, "(uid=alice)", vec!["uid"]).await;
        assert_eq!((entries.len(), rc), (1, 0));
        let code = source.fx.passcode("e-alice", "alice", "prod").await;
        assert_eq!(upgraded.simple_bind(&dn("alice"), &code).await.unwrap().rc, 0);

        // Opted in: the plain client is served in cleartext.
        let opt_in = ConfigUpdate { plaintext_enabled: Some(true), ..Default::default() };
        source.fx.ldap().put_config(opt_in, Utc::now()).await.unwrap();
        runtime.reconcile_soon();
        tokio::time::sleep(StdDuration::from_millis(200)).await;
        let mut plain = connect(&format!("ldap://127.0.0.1:{port}"), None, false).await;
        let (entries, rc) = search(&mut plain, "(uid=alice)", vec!["uid"]).await;
        assert_eq!((entries.len(), rc), (1, 0));
        wait_event(&source.fx, "tls_required").await;
    }

    async fn read_one(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match ber::pdu_len(&head) {
                Ok(Some(n)) => {
                    let mut pdu = vec![0u8; n];
                    pdu[..head.len()].copy_from_slice(&head);
                    tokio::time::timeout(StdDuration::from_secs(5), s.read_exact(&mut pdu[head.len()..]))
                        .await
                        .ok()?
                        .ok()?;
                    return Some(pdu);
                }
                Ok(None) => {
                    tokio::time::timeout(StdDuration::from_secs(5), s.read_exact(&mut b)).await.ok()?.ok()?;
                    head.push(b[0]);
                }
                Err(_) => return None,
            }
        }
    }

    /// Every reply up to and including the search's done.
    async fn exchange(s: &mut TcpStream, pdu: &[u8]) -> Vec<Reply> {
        s.write_all(pdu).await.unwrap();
        let mut out = Vec::new();
        while let Some(p) = read_one(s).await {
            let r = client::read_reply(&p).unwrap();
            let last = r.tag != tag::SEARCH_RESULT_ENTRY;
            out.push(r);
            if last {
                break;
            }
        }
        out
    }

    async fn cleartext_listener(rate_limit: Option<u32>) -> (Arc<TestSource>, Arc<LdapRuntime>, SocketAddr) {
        let fx = fixture().await;
        local_plain_client(&fx).await;
        if let Some(limit) = rate_limit {
            let u = ConfigUpdate { rate_limit_per_minute: Some(limit), ..Default::default() };
            fx.ldap().put_config(u, Utc::now()).await.unwrap();
        }
        let (source, runtime) = start(fx).await;
        let addr = wait_for(&runtime, |s| s.ldap.is_some()).await.ldap.unwrap();
        (source, runtime, addr)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_and_oversized_pdus_get_a_notice_and_a_close() {
        let (source, _runtime, addr) = cleartext_listener(None).await;
        let mut ok = TcpStream::connect(addr).await.unwrap();
        let good = client::search(1, BASE, Scope::Sub, 0, &Filter::eq("uid", "alice"), &["uid"]);
        let replies = exchange(&mut ok, &good).await;
        assert_eq!((replies.len(), replies[1].code), (2, Some(0)));
        for bad in [
            vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff],
            vec![0x30, 0x80, 0x02, 0x01, 0x01],
            vec![0x31, 0x03, 0x02, 0x01, 0x01],
            raw_search(&nested_not(40)),
            raw_message(1, &[0x7a, 0x00], &[]),
        ] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&bad).await.unwrap();
            let notice = client::read_reply(&read_one(&mut s).await.expect("a notice")).unwrap();
            assert_eq!((notice.id, notice.code), (0, Some(2)), "{bad:02x?}");
            assert_eq!(notice.response_name.as_deref(), Some(proto::OID_NOTICE_OF_DISCONNECTION));
            let mut rest = [0u8; 1];
            let closed = tokio::time::timeout(StdDuration::from_secs(5), s.read(&mut rest)).await;
            assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "the connection is closed");
        }
        wait_event(&source.fx, "malformed_pdu:too_large").await;
        wait_event(&source.fx, "malformed_pdu:indefinite_length").await;
        wait_event(&source.fx, "malformed_pdu:too_deep").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operations_over_the_rate_limit_are_busy() {
        let (source, _runtime, addr) = cleartext_listener(Some(3)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let q = |id| client::search(id, BASE, Scope::Sub, 0, &Filter::eq("uid", "alice"), &["uid"]);
        // The connection counted once, two searches, then the limit.
        assert_eq!(exchange(&mut s, &q(1)).await.last().unwrap().code, Some(0));
        assert_eq!(exchange(&mut s, &q(2)).await.last().unwrap().code, Some(0));
        let busy = exchange(&mut s, &q(3)).await;
        assert_eq!((busy.len(), busy[0].code), (1, Some(51)));
        wait_event(&source.fx, "rate_limited").await;
    }

    /// One interop run against the system's OpenLDAP `ldapsearch`, when
    /// `BV_IDP_LDAPSEARCH` names it (it is not part of the default run).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn system_ldapsearch_interop_when_asked() {
        let Some(bin) = std::env::var_os("BV_IDP_LDAPSEARCH") else { return };
        let fx = fixture().await;
        let t = tls_material(&fx).await;
        local_plain_client(&fx).await;
        let on = ConfigUpdate { ldaps_listen: Some("127.0.0.1:0".into()), ..Default::default() };
        fx.ldap().put_config(with_tls(&t, on), Utc::now()).await.unwrap();
        let (source, runtime) = start(fx).await;
        let status = wait_for(&runtime, |s| s.ldap.is_some() && s.ldaps.is_some()).await;
        let dir = std::env::temp_dir().join(format!("bv-idp-ldapsearch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, pem) in [("ca.pem", &t.ca), ("cert.pem", &t.host_cert), ("key.pem", &t.host_key)] {
            std::fs::write(dir.join(name), pem).unwrap();
        }
        let run = |args: Vec<String>, tls: bool| {
            let (bin, dir) = (bin.clone(), dir.clone());
            tokio::task::spawn_blocking(move || {
                let mut cmd = std::process::Command::new(bin);
                cmd.args(args).env("LDAPTLS_REQCERT", "demand");
                if tls {
                    cmd.env("LDAPTLS_CACERT", dir.join("ca.pem"))
                        .env("LDAPTLS_CERT", dir.join("cert.pem"))
                        .env("LDAPTLS_KEY", dir.join("key.pem"));
                }
                let out = cmd.output().expect("ldapsearch runs");
                (
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    String::from_utf8_lossy(&out.stderr).to_string(),
                )
            })
        };
        let code = source.fx.passcode("e-alice", "alice", "prod").await;
        let plain = format!("ldap://127.0.0.1:{}", status.ldap.unwrap().port());
        let args = |uri: &str, extra: &[&str]| {
            let mut a: Vec<String> = vec!["-LLL".into(), "-H".into(), uri.into(), "-b".into(), BASE.into()];
            a.extend(extra.iter().map(|s| s.to_string()));
            a
        };
        let (rc, out, err) =
            run(args(&plain, &["-x", "-D", &dn("alice"), "-w", &code, "(uid=alice)", "uidNumber"]), false)
                .await
                .unwrap();
        eprintln!("ldapsearch cleartext bind+search: rc={rc:?}\n{out}{err}");
        assert_eq!(rc, Some(0));
        assert!(out.contains(&format!("dn: {}", dn("alice"))) && out.contains("uidNumber:"));
        let (rc, out, _) =
            run(args(&plain, &["-x", "-D", &dn("alice"), "-w", &code, "(uid=alice)"]), false).await.unwrap();
        assert_eq!(rc, Some(49), "the passcode was used: {out}");
        let ldaps = format!("ldaps://localhost:{}", status.ldaps.unwrap().port());
        let (rc, out, err) =
            run(args(&ldaps, &["-Y", "EXTERNAL", "(objectClass=posixGroup)", "cn", "memberUid"]), true).await.unwrap();
        eprintln!("ldapsearch LDAPS + SASL EXTERNAL: rc={rc:?}\n{out}{err}");
        if std::env::var_os("BV_IDP_LDAPSEARCH_TLS").is_some() {
            assert_eq!(rc, Some(0));
            assert!(out.contains("memberUid: alice"));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
