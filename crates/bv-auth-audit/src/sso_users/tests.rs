use std::{
    any::Any,
    collections::BTreeMap,
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    task::{Context, Poll, Waker},
};

use super::*;

/// In-memory `Storage`; `fail_puts` makes every write fail.
#[derive(Default)]
struct MemStorage {
    map: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_puts: AtomicBool,
}

#[async_trait::async_trait]
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
        Ok(self.map.lock().unwrap().get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
    }
    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        if self.fail_puts.load(Ordering::SeqCst) {
            return Err(RvError::ErrString("injected storage failure".into()));
        }
        self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }
    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        Ok(Box::new(true))
    }
}

/// The in-memory storage never pends, so a no-op waker suffices.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn store() -> (Arc<MemStorage>, SsoUserStore) {
    let mem = Arc::new(MemStorage::default());
    (mem.clone(), SsoUserStore::from_storage(mem))
}

fn login(username: &str, email: Option<&str>) -> SsoLogin {
    SsoLogin::new("oidc/", "oidc", username, "default", "sub-123", email).unwrap()
}

#[test]
fn first_login_creates_the_record() {
    let (_, store) = store();
    let rec = block_on(store.record_login(&login("felipe.quintella@fgv.br", Some("felipe.quintella@fgv.br")))).unwrap();
    assert_eq!(rec.version, SSO_USER_RECORD_VERSION);
    assert_eq!(rec.username, "felipe.quintella@fgv.br");
    assert_eq!(rec.mount, "oidc/");
    assert_eq!(rec.auth_method, "oidc");
    assert_eq!(rec.role, "default");
    assert_eq!(rec.subject, "sub-123");
    assert_eq!(rec.email, "felipe.quintella@fgv.br");
    assert_eq!(rec.email_source, EmailSource::Idp);
    assert_eq!(rec.login_count, 1);
    assert_eq!(rec.first_login, rec.last_login);
    let read = block_on(store.get("oidc", "felipe.quintella@fgv.br")).unwrap().unwrap();
    assert_eq!(read, rec);
}

#[test]
fn a_second_login_updates_last_login_and_count_and_keeps_first_login() {
    let (_, store) = store();
    let first = block_on(store.record_login(&login("alice", None))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let again = SsoLogin::new("oidc/", "oidc", "alice", "admins", "sub-123", Some("alice@example.com")).unwrap();
    let second = block_on(store.record_login(&again)).unwrap();
    assert_eq!(second.first_login, first.first_login);
    assert!(second.last_login > first.last_login, "{} !> {}", second.last_login, first.last_login);
    assert_eq!(second.login_count, 2);
    assert_eq!(second.role, "admins");
    assert_eq!(second.email, "alice@example.com");
}

#[test]
fn an_admin_set_email_survives_later_logins_and_clearing_hands_it_back_to_the_idp() {
    let (_, store) = store();
    block_on(store.record_login(&login("bob", Some("bob@idp.example")))).unwrap();
    let set = block_on(store.set_email("oidc/", "bob", "bob@corp.example")).unwrap().unwrap();
    assert_eq!((set.email.as_str(), set.email_source), ("bob@corp.example", EmailSource::Admin));

    let after = block_on(store.record_login(&login("bob", Some("bob@idp.example")))).unwrap();
    assert_eq!((after.email.as_str(), after.email_source), ("bob@corp.example", EmailSource::Admin));

    block_on(store.set_email("oidc", "bob", "")).unwrap().unwrap();
    let refreshed = block_on(store.record_login(&login("bob", Some("bob@idp.example")))).unwrap();
    assert_eq!((refreshed.email.as_str(), refreshed.email_source), ("bob@idp.example", EmailSource::Idp));
}

#[test]
fn set_email_refuses_garbage_and_unknown_principals() {
    let (_, store) = store();
    block_on(store.record_login(&login("carol", None))).unwrap();
    assert!(block_on(store.set_email("oidc/", "carol", "not-an-address")).is_err());
    assert!(block_on(store.set_email("oidc/", "nobody", "n@example.com")).unwrap().is_none());
}

#[test]
fn listing_is_sorted_and_spans_mounts() {
    let (_, store) = store();
    block_on(store.record_login(&login("zed", None))).unwrap();
    block_on(store.record_login(&login("amy", None))).unwrap();
    let saml = SsoLogin::new("saml", "saml", "amy", "r", "nameid", None).unwrap();
    block_on(store.record_login(&saml)).unwrap();
    let all = block_on(store.list()).unwrap();
    let keys: Vec<(&str, &str)> = all.iter().map(|r| (r.mount.as_str(), r.username.as_str())).collect();
    assert_eq!(keys, vec![("oidc/", "amy"), ("oidc/", "zed"), ("saml/", "amy")]);
}

#[test]
fn delete_removes_only_the_named_record() {
    let (_, store) = store();
    block_on(store.record_login(&login("dave", None))).unwrap();
    block_on(store.record_login(&login("erin", None))).unwrap();
    assert!(block_on(store.delete("oidc/", "dave")).unwrap());
    assert!(!block_on(store.delete("oidc/", "dave")).unwrap(), "second delete reports absence");
    let names: Vec<String> = block_on(store.list()).unwrap().into_iter().map(|r| r.username).collect();
    assert_eq!(names, vec!["erin".to_string()]);
}

#[test]
fn an_empty_or_placeholder_principal_never_becomes_a_record() {
    assert!(SsoLogin::new("oidc/", "oidc", "", "r", "s", None).is_none());
    assert!(SsoLogin::new("oidc/", "oidc", "(unknown)", "r", "s", None).is_none());
    assert!(SsoLogin::new("oidc/", "oidc", " padded ", "r", "s", None).is_none());
    assert!(SsoLogin::new("oidc/", "oidc", "a\nb", "r", "s", None).is_none());
    assert!(SsoLogin::new("oidc/", "oidc", &"x".repeat(MAX_SSO_USERNAME_LEN + 1), "r", "s", None).is_none());
    assert!(SsoLogin::new("", "oidc", "alice", "r", "s", None).is_none());
    assert!(SsoLogin::new("a/b", "oidc", "alice", "r", "s", None).is_none());
    let (mem, store) = store();
    assert!(block_on(store.get("oidc/", "")).unwrap().is_none());
    assert!(!block_on(store.delete("oidc/", "")).unwrap());
    assert!(mem.map.lock().unwrap().is_empty());
}

#[test]
fn an_unusable_email_is_dropped_not_fatal() {
    let l = SsoLogin::new("oidc", "oidc", "alice", "r", "s", Some("nope")).unwrap();
    assert_eq!(l.email(), None);
    assert_eq!(l.mount(), "oidc/");
    assert_eq!(l.username(), "alice");
}

#[test]
fn names_that_are_not_path_safe_get_distinct_flat_keys() {
    let (mem, store) = store();
    block_on(store.record_login(&login("a/b", None))).unwrap();
    block_on(store.record_login(&login("a", None))).unwrap();
    block_on(store.record_login(&login("../etc", None))).unwrap();
    let keys: Vec<String> = mem.map.lock().unwrap().keys().cloned().collect();
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k.chars().all(|c| c.is_ascii_hexdigit() || c == '-')), "{keys:?}");
    assert_eq!(block_on(store.list()).unwrap().len(), 3);
}

#[test]
fn a_storage_failure_is_reported_not_swallowed() {
    let (mem, store) = store();
    mem.fail_puts.store(true, Ordering::SeqCst);
    assert!(block_on(store.record_login(&login("frank", None))).is_err());
    assert!(!block_on(store.record_login_best_effort(&login("frank", None))));
    mem.fail_puts.store(false, Ordering::SeqCst);
    assert!(block_on(store.record_login_best_effort(&login("frank", None))));
}

#[test]
fn a_record_from_a_newer_version_is_not_overwritten() {
    let (mem, store) = store();
    let future = SsoUserRecord {
        version: SSO_USER_RECORD_VERSION + 1,
        username: "gina".into(),
        mount: "oidc/".into(),
        login_count: 7,
        ..Default::default()
    };
    let key = record_key("oidc/", "gina");
    mem.map.lock().unwrap().insert(key.clone(), serde_json::to_vec(&future).unwrap());
    assert!(block_on(store.record_login(&login("gina", None))).is_err());
    assert!(block_on(store.set_email("oidc/", "gina", "g@example.com")).is_err());
    let stored: SsoUserRecord = serde_json::from_slice(&mem.map.lock().unwrap()[&key]).unwrap();
    assert_eq!(stored.login_count, 7, "untouched");
}

#[test]
fn a_minimal_record_deserializes_with_defaults() {
    // Every field after `username`/`mount` is `#[serde(default)]`.
    let rec: SsoUserRecord = serde_json::from_str(r#"{"username":"h","mount":"saml/"}"#).unwrap();
    assert_eq!(rec.version, 0);
    assert_eq!(rec.email_source, EmailSource::None);
    assert_eq!(rec.login_count, 0);
}

#[test]
fn an_undecodable_record_is_skipped_by_the_listing() {
    let (mem, store) = store();
    block_on(store.record_login(&login("ivan", None))).unwrap();
    mem.map.lock().unwrap().insert("ff-ff".into(), b"not json".to_vec());
    let names: Vec<String> = block_on(store.list()).unwrap().into_iter().map(|r| r.username).collect();
    assert_eq!(names, vec!["ivan".to_string()]);
}

#[test]
fn email_normalization() {
    assert_eq!(normalize_email(" a@b.c ").as_deref(), Some("a@b.c"));
    assert_eq!(normalize_email("a@b@c"), None);
    assert_eq!(normalize_email("@b.c"), None);
    assert_eq!(normalize_email("a b@c.d"), None);
    assert_eq!(normalize_email(""), None);
}
