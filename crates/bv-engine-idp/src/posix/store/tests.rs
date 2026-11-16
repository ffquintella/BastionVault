//! Store tests over an in-memory `Storage`: allocation, no-reuse, import
//! collisions, immutability, the lifecycle, crash ordering and concurrency.

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

use super::*;

#[derive(Default)]
struct MemStorage {
    map: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Fail every `put` whose key starts with this prefix (crash injection).
    fail_puts_under: Mutex<Option<String>>,
}

#[maybe_async::maybe_async]
impl Storage for MemStorage {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        let map = self.map.lock().unwrap();
        let mut out: Vec<String> = Vec::new();
        for key in map.keys().filter(|k| k.starts_with(prefix)) {
            let rest = &key[prefix.len()..];
            let child = match rest.find('/') {
                Some(i) => rest[..=i].to_string(),
                None => rest.to_string(),
            };
            if !out.contains(&child) {
                out.push(child);
            }
        }
        Ok(out)
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        // Yield like a real backend so concurrent writers really interleave.
        tokio::task::yield_now().await;
        let map = self.map.lock().unwrap();
        Ok(map.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
    }

    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        tokio::task::yield_now().await;
        if let Some(prefix) = self.fail_puts_under.lock().unwrap().as_deref() {
            if entry.key.starts_with(prefix) {
                return Err(RvError::ErrString("injected storage failure".into()));
            }
        }
        self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

impl MemStorage {
    fn raw_put(&self, key: &str, value: &[u8]) {
        self.map.lock().unwrap().insert(key.to_string(), value.to_vec());
    }

    fn has(&self, key: &str) -> bool {
        self.map.lock().unwrap().contains_key(key)
    }
}

fn new_store() -> (Arc<MemStorage>, PosixStore) {
    let mem = Arc::new(MemStorage::default());
    let store = PosixStore::new(mem.clone() as Arc<dyn Storage>);
    (mem, store)
}

fn alloc(entity_id: &str, login: &str) -> IdentityWrite {
    IdentityWrite { entity_id: entity_id.into(), login: Some(login.into()), ..Default::default() }
}

fn import(entity_id: &str, login: &str, uid: u32, gid: Option<u32>) -> IdentityWrite {
    IdentityWrite {
        entity_id: entity_id.into(),
        login: Some(login.into()),
        uid: Some(uid),
        primary_gid: gid,
        uid_source: Some(UidSource::Imported),
        ..Default::default()
    }
}

fn status(err: RvError) -> u16 {
    match err {
        RvError::ErrResponseStatus(s, _) => s,
        other => panic!("expected a status error, got {other:?}"),
    }
}

#[tokio::test]
async fn allocates_sequential_user_private_groups_and_pins_defaults() {
    let (_mem, store) = new_store();
    assert!(store.stored_config().await.unwrap().is_none());
    let (a, created) = store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    assert!(created);
    assert_eq!(
        (a.uid, a.primary_gid, a.state, a.uid_source),
        (80_000, 80_000, IdentityState::Active, UidSource::Vault)
    );
    assert_eq!(store.stored_config().await.unwrap(), Some(PosixConfig::default()));
    let (b, _) = store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    assert_eq!((b.uid, b.primary_gid), (80_001, 80_001));
    assert_eq!(store.list_identity_ids().await.unwrap(), vec!["e-a".to_string(), "e-b".to_string()]);
    assert_eq!(store.list_identities().await.unwrap().len(), 2);
}

#[tokio::test]
async fn removed_uid_and_login_are_never_reissued() {
    let (_mem, store) = new_store();
    let (a, _) = store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    // Removal requires disabling first.
    assert_eq!(status(store.transition("e-a", IdentityState::Removed, None).await.unwrap_err()), 409);
    store.transition("e-a", IdentityState::Disabled, Some("left".into())).await.unwrap();
    let removed = store.transition("e-a", IdentityState::Removed, None).await.unwrap();
    assert_eq!(removed.state, IdentityState::Removed);

    let (b, _) = store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    assert_ne!(b.uid, a.uid);
    assert_ne!(b.primary_gid, a.primary_gid);
    let uid_state = store.allocator(IdKind::Uid).await.unwrap();
    assert!(uid_state.retired.contains(a.uid));
    assert!(store.allocator(IdKind::Gid).await.unwrap().retired.contains(a.primary_gid));

    // Neither the uid, the gid nor the login can be taken over by a new hire.
    let err = store.create_or_update(import("e-c", "carol", a.uid, Some(90_000))).await.unwrap_err();
    assert_eq!(status(err), 409);
    let err = store.create_or_update(import("e-c", "carol", 90_000, Some(a.primary_gid))).await.unwrap_err();
    assert_eq!(status(err), 409);
    assert_eq!(status(store.create_or_update(alloc("e-c", "alice")).await.unwrap_err()), 409);
    // Removal is terminal and the record is frozen.
    assert_eq!(status(store.transition("e-a", IdentityState::Active, None).await.unwrap_err()), 409);
    let freeze = IdentityWrite { entity_id: "e-a".into(), display_name: Some("x".into()), ..Default::default() };
    assert_eq!(status(store.create_or_update(freeze).await.unwrap_err()), 409);
}

#[tokio::test]
async fn high_water_and_used_set_survive_a_reload() {
    let mem = Arc::new(MemStorage::default());
    {
        let store = PosixStore::new(mem.clone() as Arc<dyn Storage>);
        for i in 0..3 {
            store.create_or_update(alloc(&format!("e-{i}"), &format!("user{i}"))).await.unwrap();
        }
    }
    let reloaded = PosixStore::new(mem.clone() as Arc<dyn Storage>);
    let state = reloaded.allocator(IdKind::Uid).await.unwrap();
    assert_eq!(state.high_water, Some(80_002));
    assert_eq!(state.used.count(), 3);
    let (next, _) = reloaded.create_or_update(alloc("e-3", "user3")).await.unwrap();
    assert_eq!(next.uid, 80_003);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_allocation_never_collides() {
    let mem = Arc::new(MemStorage::default());
    // Two store instances over one storage stand in for two request paths.
    let stores = [
        Arc::new(PosixStore::new(mem.clone() as Arc<dyn Storage>)),
        Arc::new(PosixStore::new(mem.clone() as Arc<dyn Storage>)),
    ];
    let mut tasks = Vec::new();
    for i in 0..64 {
        let store = stores[i % 2].clone();
        tasks.push(tokio::spawn(async move {
            store.create_or_update(alloc(&format!("e-{i}"), &format!("user{i}"))).await.unwrap().0
        }));
    }
    let mut uids = HashSet::new();
    let mut gids = HashSet::new();
    for t in tasks {
        let rec = t.await.unwrap();
        assert!(uids.insert(rec.uid), "uid {} handed out twice", rec.uid);
        assert!(gids.insert(rec.primary_gid), "gid {} handed out twice", rec.primary_gid);
    }
    assert_eq!(uids, (80_000..80_064).collect::<HashSet<u32>>());
    assert_eq!(stores[0].allocator(IdKind::Uid).await.unwrap().high_water, Some(80_063));
}

#[tokio::test]
async fn stale_allocator_record_cannot_reissue_an_indexed_id() {
    let (mem, store) = new_store();
    let (a, _) = store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    // Another node's allocation that this node's allocator record never saw.
    let blank = |kind| serde_json::to_vec(&AllocatorState::new(kind)).unwrap();
    mem.raw_put("alloc/uid", &blank(IdKind::Uid));
    mem.raw_put("alloc/gid", &blank(IdKind::Gid));
    let (b, _) = store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    assert_ne!(b.uid, a.uid);
    assert_ne!(b.primary_gid, a.primary_gid);
    assert!(store.allocator(IdKind::Uid).await.unwrap().used.contains(a.uid));
}

#[tokio::test]
async fn crash_after_burning_ids_never_reuses_them() {
    let (mem, store) = new_store();
    *mem.fail_puts_under.lock().unwrap() = Some(IDENTITY_PREFIX.to_string());
    assert!(store.create_or_update(alloc("e-a", "alice")).await.is_err());
    *mem.fail_puts_under.lock().unwrap() = None;
    assert!(store.get_identity("e-a").await.unwrap().is_none());

    let (b, _) = store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    assert_eq!(b.uid, 80_001, "the uid burned by the interrupted allocation must stay burned");
    // The interrupted entity can finish with its own login, on a fresh uid.
    let (a, created) = store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    assert!(created);
    assert_eq!(a.uid, 80_002);
    // ...but nobody else can claim that login.
    assert_eq!(status(store.create_or_update(alloc("e-x", "alice")).await.unwrap_err()), 409);
}

#[tokio::test]
async fn import_mode_rejects_colliding_seeds() {
    let (_mem, store) = new_store();
    let (x, _) = store.create_or_update(import("e-x", "xavier", 5000, None)).await.unwrap();
    assert_eq!((x.uid, x.primary_gid, x.uid_source), (5000, 5000, UidSource::Imported));
    let uid_state = store.allocator(IdKind::Uid).await.unwrap();
    assert_eq!(uid_state.high_water, None, "imports do not move the high-water mark");

    assert_eq!(status(store.create_or_update(import("e-y", "yara", 5000, Some(7000))).await.unwrap_err()), 409);
    assert_eq!(status(store.create_or_update(import("e-y", "yara", 5001, Some(5000))).await.unwrap_err()), 409);
    // An in-range import is skipped by vault-mode allocation.
    store.create_or_update(import("e-y", "yara", 80_000, Some(80_000))).await.unwrap();
    let (z, _) = store.create_or_update(alloc("e-z", "zoe")).await.unwrap();
    assert_eq!((z.uid, z.primary_gid), (80_001, 80_001));
    // ...and a vault-allocated id cannot be imported.
    assert_eq!(status(store.create_or_update(import("e-w", "walt", 80_001, Some(91_000))).await.unwrap_err()), 409);

    // Malformed seeds.
    for (uid, gid) in [(999, None), (65_534, None), (MAX_ID_PLUS_ONE, None), (6000, Some(0))] {
        let err = store.create_or_update(import("e-w", "walt", uid, gid)).await.unwrap_err();
        assert_eq!(status(err), 400, "uid {uid} gid {gid:?}");
    }
    let mut no_uid = import("e-w", "walt", 6000, None);
    no_uid.uid = None;
    assert_eq!(status(store.create_or_update(no_uid).await.unwrap_err()), 400);
    let mut vault_with_uid = alloc("e-w", "walt");
    vault_with_uid.uid = Some(6000);
    assert_eq!(status(store.create_or_update(vault_with_uid).await.unwrap_err()), 400);
    // A failed import left nothing behind: the login is still free.
    store.create_or_update(import("e-w", "walt", 6000, None)).await.unwrap();
}

const MAX_ID_PLUS_ONE: u32 = crate::posix::model::MAX_ID + 1;

#[tokio::test]
async fn shared_groups_are_reserved_and_private_groups_are_not_shareable() {
    let (_mem, store) = new_store();
    let (a, _) = store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    let set = |gids: Vec<u32>| IdentityWrite { entity_id: "e-b".into(), gids: Some(gids), ..Default::default() };

    // Alice's private group cannot be granted to Bob.
    assert_eq!(status(store.create_or_update(set(vec![4, a.primary_gid])).await.unwrap_err()), 409);
    // Duplicates and Bob's own primary group are dropped.
    let (b, created) = store.create_or_update(set(vec![90_000, 4, 4, 80_001])).await.unwrap();
    assert!(!created);
    assert_eq!(b.gids, vec![4, 90_000]);
    assert_eq!(status(store.create_or_update(set(vec![0])).await.unwrap_err()), 400);
    assert_eq!(status(store.create_or_update(set((10_000..10_065).collect())).await.unwrap_err()), 400);

    // 90000 is now a shared group: never allocated as somebody's private group
    // nor importable as one.
    store
        .put_config(ConfigUpdate {
            uid_min: Some(90_000),
            uid_max: Some(90_010),
            gid_min: Some(90_000),
            gid_max: Some(90_010),
        })
        .await
        .unwrap();
    let (c, _) = store.create_or_update(alloc("e-c", "carol")).await.unwrap();
    assert_eq!(c.uid, 90_000);
    assert_eq!(c.primary_gid, 90_001);
    assert_eq!(status(store.create_or_update(import("e-d", "dave", 7000, Some(90_000))).await.unwrap_err()), 409);
}

#[tokio::test]
async fn immutable_fields_cannot_change() {
    let (_mem, store) = new_store();
    store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    let patch = |f: &dyn Fn(&mut IdentityWrite)| {
        let mut w = IdentityWrite { entity_id: "e-a".into(), ..Default::default() };
        f(&mut w);
        w
    };
    for w in [
        patch(&|w| w.login = Some("alice2".into())),
        patch(&|w| w.uid = Some(80_500)),
        patch(&|w| w.primary_gid = Some(80_500)),
        patch(&|w| w.uid_source = Some(UidSource::Imported)),
    ] {
        assert_eq!(status(store.create_or_update(w).await.unwrap_err()), 400);
    }
    // Restating the immutable values is an idempotent update.
    let (same, created) = store
        .create_or_update(patch(&|w| {
            w.login = Some("alice".into());
            w.uid = Some(80_000);
            w.display_name = Some("Alice Souza".into());
        }))
        .await
        .unwrap();
    assert!(!created);
    assert_eq!((same.login.as_str(), same.uid, same.display_name.as_str()), ("alice", 80_000, "Alice Souza"));
    assert_eq!(status(store.create_or_update(patch(&|w| w.display_name = Some("a:b".into()))).await.unwrap_err()), 400);
}

#[tokio::test]
async fn lifecycle_transitions() {
    let (_mem, store) = new_store();
    store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    let d = store.transition("e-a", IdentityState::Disabled, Some("on leave".into())).await.unwrap();
    assert_eq!((d.state, d.state_reason.as_deref()), (IdentityState::Disabled, Some("on leave")));
    let changed_at = d.state_changed_at;
    // A no-op transition leaves the record untouched.
    let again = store.transition("e-a", IdentityState::Disabled, None).await.unwrap();
    assert_eq!(again.state_changed_at, changed_at);
    let r = store.transition("e-a", IdentityState::Active, None).await.unwrap();
    assert_eq!((r.state, r.state_reason), (IdentityState::Active, None));
    assert_eq!(status(store.transition("e-missing", IdentityState::Disabled, None).await.unwrap_err()), 404);
    assert_eq!(status(store.transition("e-a", IdentityState::Disabled, Some("x\u{7}".into())).await.unwrap_err()), 400);
    assert_eq!(status(store.transition("../e-a", IdentityState::Disabled, None).await.unwrap_err()), 400);
    // A disabled identity can still be updated (supplementary groups).
    store.transition("e-a", IdentityState::Disabled, None).await.unwrap();
    let w = IdentityWrite { entity_id: "e-a".into(), gids: Some(vec![4]), ..Default::default() };
    assert_eq!(store.create_or_update(w).await.unwrap().0.gids, vec![4]);
}

#[tokio::test]
async fn range_exhaustion_is_explicit_and_burns_nothing() {
    let (mem, store) = new_store();
    store.put_config(ConfigUpdate { uid_max: Some(80_001), ..Default::default() }).await.unwrap();
    store.create_or_update(alloc("e-a", "alice")).await.unwrap();
    store.create_or_update(alloc("e-b", "bob")).await.unwrap();
    let err = store.create_or_update(alloc("e-c", "carol")).await.unwrap_err();
    assert!(matches!(&err, RvError::ErrResponseStatus(409, m) if m.contains("exhausted")), "{err:?}");
    assert!(!mem.has("index/login/carol"));
    // Moving the range up resumes allocation at its new floor.
    store
        .put_config(ConfigUpdate { uid_min: Some(100_000), uid_max: Some(200_000), ..Default::default() })
        .await
        .unwrap();
    let (c, _) = store.create_or_update(alloc("e-c", "carol")).await.unwrap();
    assert_eq!(c.uid, 100_000);
}

#[tokio::test]
async fn config_validation() {
    let (_mem, store) = new_store();
    for update in [
        ConfigUpdate { uid_min: Some(500), ..Default::default() },
        ConfigUpdate { gid_min: Some(5000), gid_max: Some(4000), ..Default::default() },
        ConfigUpdate { uid_max: Some(u32::MAX), ..Default::default() },
    ] {
        assert_eq!(status(store.put_config(update).await.unwrap_err()), 400);
    }
    assert!(store.stored_config().await.unwrap().is_none(), "a refused update writes nothing");
    let cfg = store
        .put_config(ConfigUpdate { gid_min: Some(2000), gid_max: Some(3000), ..Default::default() })
        .await
        .unwrap();
    assert_eq!((cfg.uid_range, cfg.gid_range), (IdRange::DEFAULT, IdRange { min: 2000, max: 3000 }));
    assert!(cfg.updated_at.is_some());
}

#[tokio::test]
async fn malformed_stored_records_fail_closed() {
    let (mem, store) = new_store();
    mem.raw_put("identities/e-a", b"{not json");
    assert_eq!(status(store.get_identity("e-a").await.unwrap_err()), 500);
    mem.raw_put("alloc/uid", br#"{"version":2,"kind":"uid","high_water":null,"used":[],"retired":[]}"#);
    assert_eq!(status(store.allocator(IdKind::Uid).await.unwrap_err()), 500);
    mem.raw_put("alloc/uid", br#"{"version":1,"kind":"uid","high_water":null,"used":[[5,9],[3,4]],"retired":[]}"#);
    assert_eq!(status(store.allocator(IdKind::Uid).await.unwrap_err()), 500);
    // An allocation refuses to run on a corrupt allocator record.
    assert_eq!(status(store.create_or_update(alloc("e-b", "bob")).await.unwrap_err()), 500);
    // A record filed under the wrong key is refused too.
    let (_m2, other) = new_store();
    let (rec, _) = other.create_or_update(alloc("e-z", "zoe")).await.unwrap();
    mem.raw_put("identities/e-q", &serde_json::to_vec(&rec).unwrap());
    assert_eq!(status(store.get_identity("e-q").await.unwrap_err()), 500);
}
