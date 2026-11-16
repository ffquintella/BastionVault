//! Revocation tests: the KRL holds exactly the revoked, unexpired serials
//! and follows revocation; the feed version moves only up and only on a
//! change; a tampered, rolled-back, stale or foreign feed is refused; the
//! feed key persists and an unreadable key is never silently replaced.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{Duration, Utc};
use serde_json::Value;
use ssh_key::{rand_core::OsRng, Algorithm, PrivateKey, PublicKey};

use super::{
    feed::{check_fresh, verify_feed, DenyFeed, FeedError, FeedPublicKey, FeedSigner, FEED_FORMAT},
    krl::{build_krl, parse_krl},
    refresh,
    store::FeedStore,
    RevocationView,
};
use crate::{
    posix::{
        model::IdentityState,
        store::{IdentityWrite, PosixStore},
    },
    provider::ssh::store::{format_serial, CertRecord, SshStore},
    storage::Storage,
    test_support::MemStorage,
};

struct Fx {
    posix: Arc<PosixStore>,
    ssh: SshStore,
    feed: FeedStore,
    feed_mem: Arc<MemStorage>,
    ca: String,
    ca2: String,
}

fn ca_line() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap().public_key().to_openssh().unwrap()
}

fn now_secs() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

async fn fixture() -> Fx {
    let posix = Arc::new(PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>));
    for (id, login) in [("e-alice", "alice"), ("e-bob", "bob")] {
        let w = IdentityWrite { entity_id: id.into(), login: Some(login.into()), ..Default::default() };
        posix.create_or_update(w).await.unwrap();
    }
    let feed_mem = MemStorage::new_arc();
    Fx {
        posix,
        ssh: SshStore::new(MemStorage::new_arc() as Arc<dyn Storage>),
        feed: FeedStore::new(feed_mem.clone() as Arc<dyn Storage>),
        feed_mem,
        ca: ca_line(),
        ca2: ca_line(),
    }
}

impl Fx {
    async fn record(&self, entity: &str, serial: u64, ca: &str, valid_before: u64) {
        let rec = CertRecord {
            version: 1,
            serial: format_serial(serial),
            entity_id: entity.into(),
            login: entity.trim_start_matches("e-").into(),
            uid: 80_000,
            environment: "prod".into(),
            namespace: "prod".into(),
            key_id: format!("bv:{entity}"),
            ca_public_key: ca.into(),
            valid_after: 1,
            valid_before,
            issued_at: Utc::now(),
            revoked_at: None,
            revoke_reason: None,
        };
        self.ssh.record_issued(&rec, now_secs()).await.unwrap();
    }

    async fn view(&self) -> RevocationView {
        RevocationView::build(&self.posix, &self.ssh, now_secs()).await.unwrap()
    }
}

fn wire(ca: &str) -> Vec<u8> {
    PublicKey::from_openssh(ca).unwrap().to_bytes().unwrap()
}

#[tokio::test]
async fn krl_lists_exactly_the_revoked_serials_and_follows_revocation() {
    let fx = fixture().await;
    let later = now_secs() + 3600;
    fx.record("e-alice", 0x11, &fx.ca, later).await;
    fx.record("e-alice", 0x12, &fx.ca2, later).await;
    fx.record("e-alice", 0x13, &fx.ca, now_secs() - 10).await; // expired
    fx.record("e-bob", 0x21, &fx.ca, later).await;
    assert_eq!(fx.view().await, RevocationView::default());

    assert_eq!(fx.ssh.revoke_entity("e-alice", "identity disabled", Utc::now()).await.unwrap(), 2);
    assert_eq!(fx.ssh.revoke_entity("e-alice", "identity disabled", Utc::now()).await.unwrap(), 0, "idempotent");
    let view = fx.view().await;
    assert_eq!(view.serials(), [format_serial(0x11), format_serial(0x12)]);
    let krl = parse_krl(&build_krl(7, 1_700_000_000, "test", &view.certificates).unwrap()).unwrap();
    assert_eq!((krl.krl_version, krl.generated_at), (7, 1_700_000_000));
    let expected: BTreeMap<Vec<u8>, BTreeSet<u64>> =
        [(wire(&fx.ca), [0x11u64].into()), (wire(&fx.ca2), [0x12u64].into())].into_iter().collect();
    assert_eq!(krl.serials, expected);

    // An owner that is not active revokes its certificates even unmarked.
    fx.posix.transition("e-bob", IdentityState::Disabled, None).await.unwrap();
    assert!(fx.view().await.serials().contains(&format_serial(0x21)));
    assert_eq!(fx.view().await.identities.iter().map(|d| d.login.as_str()).collect::<Vec<_>>(), ["bob"]);
    // Marked before reinstating (as the backend does), it stays revoked.
    fx.ssh.revoke_entity("e-bob", "issued before the identity was disabled", Utc::now()).await.unwrap();
    fx.posix.transition("e-bob", IdentityState::Active, None).await.unwrap();
    let view = fx.view().await;
    assert!(view.serials().contains(&format_serial(0x21)));
    assert!(view.identities.is_empty());
}

#[test]
fn krl_encoding_edges() {
    type Map = BTreeMap<String, BTreeSet<u64>>;
    let ca = ca_line();
    let zero: Map = [(ca.clone(), [0u64].into())].into_iter().collect();
    assert!(build_krl(1, 0, "", &zero).is_err(), "serial 0 cannot be expressed");
    let empty_set: Map = [(ca, BTreeSet::new())].into_iter().collect();
    let krl = parse_krl(&build_krl(1, 0, "", &empty_set).unwrap()).unwrap();
    assert!(krl.serials.is_empty());
    let bad_ca: Map = [("not a key".to_string(), [5u64].into())].into_iter().collect();
    assert!(build_krl(1, 0, "", &bad_ca).is_err());
    let good = build_krl(1, 0, "c", &Default::default()).unwrap();
    assert!(parse_krl(&good[..good.len() - 1]).is_err());
    assert!(parse_krl(b"SSHKRL\n\0garbage").is_err());
}

#[tokio::test]
async fn feed_version_moves_up_only_when_the_content_changes() {
    let fx = fixture().await;
    let later = now_secs() + 3600;
    fx.record("e-alice", 0x11, &fx.ca, later).await;
    let version = |r: Result<(RevocationView, u64), _>| r.unwrap().1;
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 1);
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 1);
    fx.ssh.revoke_entity("e-alice", "identity disabled", Utc::now()).await.unwrap();
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 2);
    fx.posix.transition("e-bob", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 3);
    fx.posix.transition("e-bob", IdentityState::Active, None).await.unwrap();
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 4, "a reinstate is a change too");

    // The next version is always above the stored one.
    let mut state: Value = serde_json::from_slice(&fx.feed_mem.raw_get("feed/state").unwrap()).unwrap();
    state["feed_version"] = 40.into();
    fx.feed_mem.raw_put("feed/state", &serde_json::to_vec(&state).unwrap());
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 40);
    fx.posix.transition("e-bob", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(version(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await), 41);

    // A state record this build cannot read stops the feed; it is not reset.
    state["version"] = 2.into();
    fx.feed_mem.raw_put("feed/state", &serde_json::to_vec(&state).unwrap());
    assert!(refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await.is_err());
}

fn resign(signer: &FeedSigner, mutate: impl FnOnce(&mut Value)) -> (String, String) {
    let feed = DenyFeed {
        format: FEED_FORMAT.into(),
        format_version: 1,
        feed_version: 5,
        generated_at: Utc::now().timestamp(),
        identities: vec![],
        revoked_serials: vec![format_serial(1), format_serial(2)],
    };
    let mut value = serde_json::to_value(&feed).unwrap();
    mutate(&mut value);
    let signed = signer.sign_payload(serde_json::to_vec(&value).unwrap(), 5).unwrap();
    (B64.encode(&signed.payload), B64.encode(&signed.signature))
}

#[tokio::test]
async fn feed_signature_verifies_and_anything_else_is_refused() {
    let fx = fixture().await;
    fx.record("e-alice", 0x11, &fx.ca, now_secs() + 3600).await;
    fx.ssh.revoke_entity("e-alice", "identity disabled", Utc::now()).await.unwrap();
    fx.posix.transition("e-bob", IdentityState::Disabled, None).await.unwrap();
    let signer = fx.feed.signer(Utc::now()).await.unwrap();
    let key = signer.public_key();
    let (view, v) = refresh(&fx.posix, &fx.ssh, &fx.feed, Utc::now()).await.unwrap();
    let served = signer.sign(&view.into_feed(v, Utc::now().timestamp())).unwrap().to_map(&key);
    let (feed_b64, sig_b64) = (served["feed"].as_str().unwrap(), served["signature"].as_str().unwrap());

    let feed = verify_feed(feed_b64, sig_b64, &key, 0).unwrap();
    assert_eq!(feed.feed_version, v);
    assert_eq!(feed.revoked_serials, [format_serial(0x11)]);
    assert_eq!(feed.identities.len(), 1);
    assert!(feed.denies("e-bob", "x", 1) && feed.revokes_serial(0x11) && !feed.revokes_serial(0x12));
    assert_eq!(verify_feed(feed_b64, sig_b64, &key, v).unwrap().feed_version, v, "the same version is accepted");

    // Rollback: a version below the accepted one.
    assert_eq!(
        verify_feed(feed_b64, sig_b64, &key, v + 1).unwrap_err(),
        FeedError::Rollback { accepted: v + 1, offered: v }
    );
    // Tampered payload, either signature half, a dropped half, another key.
    let mut payload = B64.decode(feed_b64).unwrap();
    let at = payload.len() - 5;
    payload[at] ^= 0x01;
    assert_eq!(verify_feed(&B64.encode(&payload), sig_b64, &key, 0).unwrap_err(), FeedError::BadSignature);
    let sig = B64.decode(sig_b64).unwrap();
    for flip in [10, sig.len() - 10] {
        let mut s = sig.clone();
        s[flip] ^= 0x01;
        assert_eq!(verify_feed(feed_b64, &B64.encode(&s), &key, 0).unwrap_err(), FeedError::BadSignature);
    }
    assert_eq!(verify_feed(feed_b64, &B64.encode(&sig[..66]), &key, 0).unwrap_err(), FeedError::BadSignature);
    let stranger = FeedSigner::generate().unwrap().public_key();
    assert_eq!(verify_feed(feed_b64, sig_b64, &stranger, 0).unwrap_err(), FeedError::BadSignature);
    // Malformed input.
    assert!(matches!(verify_feed("%%%", sig_b64, &key, 0), Err(FeedError::Malformed(_))));
    assert!(matches!(verify_feed(&"A".repeat(12 * 1024 * 1024), sig_b64, &key, 0), Err(FeedError::Malformed(_))));

    // Validly signed, but not a feed this verifier reads.
    let (f, s) = resign(&signer, |v| v["format_version"] = 2.into());
    assert_eq!(verify_feed(&f, &s, &key, 0).unwrap_err(), FeedError::UnsupportedFormat);
    let (f, s) = resign(&signer, |v| v["format"] = "other".into());
    assert_eq!(verify_feed(&f, &s, &key, 0).unwrap_err(), FeedError::UnsupportedFormat);
    let (f, s) = resign(&signer, |v| v["extra"] = 1.into());
    assert!(matches!(verify_feed(&f, &s, &key, 0), Err(FeedError::Malformed(_))));
    let (f, s) = resign(&signer, |v| v["revoked_serials"] = serde_json::json!([format_serial(2), format_serial(1)]));
    assert!(matches!(verify_feed(&f, &s, &key, 0), Err(FeedError::Malformed(_))));

    // Freshness.
    let old = DenyFeed { generated_at: Utc::now().timestamp() - 100, ..feed.clone() };
    assert!(matches!(check_fresh(&old, Utc::now().timestamp(), 50), Err(FeedError::Stale { .. })));
    check_fresh(&old, Utc::now().timestamp(), 500).unwrap();

    // The published key round-trips; a different algorithm is refused.
    assert_eq!(FeedPublicKey::from_value(&Value::Object(key.to_map())).unwrap(), key);
    let mut wrong = key.to_map();
    wrong.insert("algorithm".into(), "ed25519".into());
    assert_eq!(FeedPublicKey::from_value(&Value::Object(wrong)).unwrap_err(), FeedError::UnsupportedFormat);
    let mut short = key.to_map();
    short.insert("ed25519".into(), B64.encode([0u8; 16]).into());
    assert!(FeedPublicKey::from_value(&Value::Object(short)).is_err());
}

#[tokio::test]
async fn feed_key_persists_and_an_unreadable_key_is_not_replaced() {
    let fx = fixture().await;
    let first = fx.feed.signer(Utc::now()).await.unwrap().public_key();
    let second = fx.feed.signer(Utc::now() + Duration::hours(1)).await.unwrap().public_key();
    assert_eq!(first, second);

    let raw = fx.feed_mem.raw_get("feed/key").unwrap();
    let mut record: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!((record["version"].as_u64(), record["algorithm"].as_str()), (Some(1), Some("ed25519+ml-dsa-65")));

    record["version"] = 2.into();
    fx.feed_mem.raw_put("feed/key", &serde_json::to_vec(&record).unwrap());
    assert!(fx.feed.signer(Utc::now()).await.is_err());
    record["version"] = 1.into();
    record["mldsa65_seed"] = B64.encode([0u8; 8]).into();
    fx.feed_mem.raw_put("feed/key", &serde_json::to_vec(&record).unwrap());
    assert!(fx.feed.signer(Utc::now()).await.is_err());
    // Still the same bytes: nothing regenerated behind the operator's back.
    assert_eq!(serde_json::from_slice::<Value>(&fx.feed_mem.raw_get("feed/key").unwrap()).unwrap(), record);
}
