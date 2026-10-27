//! T62 slice 1: the `revoke_failed` state, the reaper, renew with its
//! max_ttl clamp, the per-lease guard, owner revocation and old rows.
//!
//! Deterministic: the sweeper thread is not started (except in the one test
//! about the sweeper itself), and the reaper's step is driven by hand.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, SystemTime},
};

use serde_json::json;

use super::{ExpirationManager, LeaseEntry, RevokeOutcome, LEASE_ENTRY_VERSION};
use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    kernel_api::{
        leases::{LeaseRevocation, OwnedLeaseRevoker},
        VaultCtx,
    },
    logical::{Lease, Operation, Request, Response, SecretData},
    modules::auth::{
        lease_state::{RevokeOrigin, RevokeRetryPolicy},
        token_store::TokenEntry,
        TokenStore,
    },
    mount::MountEntry,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    test_utils::{new_unseal_test_bastion_vault, NoopBackend},
};

const OWNER_TOKEN: &str = "owner-token";
const PASSWORD: &str = "never-logged-password";

type RenewFn = dyn Fn(&mut Request) -> Result<Option<Response>, RvError> + Send + Sync;

/// A target system behind a mount. Revokes fail while `fail_revoke` is set;
/// revokes and renews that reach it are counted; `held` records, for each
/// call, whether the lease named by `probe` was guarded while it ran.
struct Target {
    fail_revoke: Arc<AtomicBool>,
    revokes: Arc<AtomicU32>,
    renews: Arc<AtomicU32>,
    held: Arc<Mutex<Vec<bool>>>,
    probe: Arc<Mutex<Option<String>>>,
}

impl Target {
    fn revokes(&self) -> u32 {
        self.revokes.load(Ordering::SeqCst)
    }

    fn renews(&self) -> u32 {
        self.renews.load(Ordering::SeqCst)
    }

    fn fail(&self, fail: bool) {
        self.fail_revoke.store(fail, Ordering::SeqCst);
    }
}

fn mount_target(core: &Arc<Core>, expiration: &ExpirationManager, prefix: &str, renew: Arc<RenewFn>) -> Target {
    let target = Target {
        fail_revoke: Arc::new(AtomicBool::new(false)),
        revokes: Arc::new(AtomicU32::new(0)),
        renews: Arc::new(AtomicU32::new(0)),
        held: Arc::new(Mutex::new(Vec::new())),
        probe: Arc::new(Mutex::new(None)),
    };
    let (fail, revokes, renews) = (target.fail_revoke.clone(), target.revokes.clone(), target.renews.clone());
    let (held, probe, locks) = (target.held.clone(), target.probe.clone(), expiration.lease_locks.clone());
    let handler = move |req: &mut Request| -> Result<Option<Response>, RvError> {
        if let Some(id) = probe.lock().unwrap().clone() {
            held.lock().unwrap().push(locks.try_acquire(&id).is_err());
        }
        match req.operation {
            Operation::Revoke => {
                revokes.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) {
                    return Err(bv_error_string!("target unreachable: connection refused"));
                }
                Ok(None)
            }
            Operation::Renew => {
                renews.fetch_add(1, Ordering::SeqCst);
                renew(req)
            }
            _ => Ok(None),
        }
    };
    let backend = Arc::new(NoopBackend { request_handler: Some(Arc::new(handler)), ..Default::default() });
    let view = BarrierView::new(core.barrier().clone(), "logical/");
    let entry = MountEntry { path: prefix.into(), logical_type: "noop".into(), ..Default::default() };
    expiration.router.mount(backend, prefix, Arc::new(RwLock::new(entry)), view).unwrap();
    target
}

/// A backend renew that answers with the lease it was handed, at its role's
/// TTL of `ttl` seconds.
fn renews_with(ttl: u64) -> Arc<RenewFn> {
    Arc::new(move |req: &mut Request| {
        let mut secret = req.secret.clone().expect("a renew request carries the lease's secret");
        secret.lease_id.clear();
        secret.ttl = Duration::from_secs(ttl);
        Ok(Some(Response { secret: Some(secret), ..Default::default() }))
    })
}

fn renews_as_issued() -> Arc<RenewFn> {
    renews_with(60)
}

/// A backend with no real renew: it answers, but with nothing.
fn renews_nothing() -> Arc<RenewFn> {
    Arc::new(|_req: &mut Request| Ok(None))
}

/// An unsealed vault and an expiration manager on its router whose sweeper
/// is not running. The token store is returned to keep it alive.
async fn manager(name: &str, policy: RevokeRetryPolicy) -> (Arc<Core>, Arc<ExpirationManager>, Arc<TokenStore>) {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault(name).await;
    let mut expiration = ExpirationManager::new(&core).unwrap();
    expiration.revoke_policy = policy;
    let expiration = expiration.wrap();
    let token_store = TokenStore::new(&core, expiration.clone()).await.unwrap().wrap();
    expiration.set_token_store(&token_store).unwrap();
    (core, expiration, token_store)
}

fn immediate_retries(max_attempts: u32) -> RevokeRetryPolicy {
    RevokeRetryPolicy { max_attempts, base_delay: Duration::ZERO, ..Default::default() }
}

fn lease(ttl: u64, max_ttl: u64, renewable: bool) -> Lease {
    Lease { ttl: Duration::from_secs(ttl), max_ttl: Duration::from_secs(max_ttl), renewable, ..Default::default() }
}

async fn issue(expiration: &ExpirationManager, path: &str, lease: Lease) -> String {
    let mut req = Request::new(path);
    req.client_token = OWNER_TOKEN.into();
    let mut resp = Response {
        secret: Some(SecretData { lease, ..Default::default() }),
        data: json!({ "username": "v-app-1", "password": PASSWORD }).as_object().cloned(),
        ..Default::default()
    };
    expiration.register_secret(&mut req, &mut resp).await.expect("register the lease")
}

async fn row(expiration: &ExpirationManager, lease_id: &str) -> Option<LeaseEntry> {
    expiration.load_lease_entry(lease_id).await.expect("read the lease row")
}

fn status(result: &Result<impl std::fmt::Debug, RvError>) -> Option<u16> {
    match result {
        Err(RvError::ErrResponseStatus(status, _)) => Some(*status),
        _ => None,
    }
}

#[tokio::test]
async fn failed_revoke_keeps_the_row_and_marks_it_revoke_failed() {
    let (core, expiration, _ts) = manager("t62_failed_revoke_keeps_row", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;
    target.fail(true);

    let result = expiration.revoke_named_lease(&id).await;
    assert_eq!(status(&result), Some(502), "a failed backend revoke must be reported: {result:?}");

    let le = row(&expiration, &id).await.expect("the row must be kept, not deleted");
    let failure = le.revoke_failure.clone().expect("marked revoke_failed");
    assert_eq!((failure.attempts, failure.origin), (1, RevokeOrigin::Operator));
    assert!(failure.last_error.contains("connection refused"), "{failure:?}");
    assert_eq!(le.data["username"], "v-app-1", "the data the retry revokes with is kept");
    assert!(expiration.lookup_by_token(OWNER_TOKEN).await.unwrap().contains(&id), "token index kept");

    let listed = expiration.list_revoke_failed().await.unwrap();
    assert_eq!(listed.iter().map(|l| l.lease_id.as_str()).collect::<Vec<_>>(), vec![id.as_str()]);
    assert!(!listed[0].exhausted);

    // Not due for 10 s under the default policy: the reaper leaves it alone.
    expiration.revoke_swept_lease_entry(&id).await.unwrap();
    assert_eq!(target.revokes(), 1, "no retry before the backoff elapses");

    // Revoking the owning token does not fail on this lease's account.
    let te = TokenEntry { id: OWNER_TOKEN.into(), ..Default::default() };
    expiration.revoke_by_token(&te).await.expect("token revocation goes on");
    let failure = row(&expiration, &id).await.unwrap().revoke_failure.unwrap();
    assert_eq!((failure.attempts, failure.origin), (2, RevokeOrigin::Operator), "the first origin is kept");

    let debug = format!("{le:?}");
    assert!(!debug.contains(PASSWORD) && !debug.contains(OWNER_TOKEN), "Debug leaks: {debug}");
}

#[tokio::test]
async fn a_successful_retry_clears_revoke_failed() {
    let (core, expiration, _ts) = manager("t62_retry_clears", immediate_retries(6)).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;

    target.fail(true);
    assert_eq!(status(&expiration.revoke_named_lease(&id).await), Some(502));
    target.fail(false);

    expiration.revoke_swept_lease_entry(&id).await.expect("the reaper's retry");
    assert_eq!(target.revokes(), 2);
    assert!(row(&expiration, &id).await.is_none(), "revoked on retry: the row is gone");
    assert!(expiration.list_revoke_failed().await.unwrap().is_empty());
    assert!(!expiration.lookup_by_token(OWNER_TOKEN).await.unwrap().contains(&id), "token index removed");
}

#[tokio::test]
async fn the_reaper_stops_at_max_attempts_and_an_operator_force_clears() {
    let policy = immediate_retries(3);
    let (core, expiration, _ts) = manager("t62_reaper_cap", policy).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;
    let healthy = issue(&expiration, "dyn/creds/other", lease(3600, 0, true)).await;
    target.fail(true);

    assert_eq!(status(&expiration.revoke_named_lease(&id).await), Some(502));
    for _ in 0..2 {
        expiration.revoke_swept_lease_entry(&id).await.unwrap();
    }
    let le = row(&expiration, &id).await.unwrap();
    assert_eq!(le.revoke_failure.as_ref().unwrap().attempts, 3);
    assert_eq!(le.queue_priority(&policy).unwrap(), u128::MAX, "parked: never due again");

    expiration.revoke_swept_lease_entry(&id).await.unwrap();
    assert_eq!(target.revokes(), 3, "an exhausted lease is not retried");
    let listed = expiration.list_revoke_failed().await.unwrap();
    assert!(listed.len() == 1 && listed[0].exhausted, "still listed for the operator: {listed:?}");

    let refused = expiration.force_clear_revoke_failed(&healthy, None).await;
    assert_eq!(status(&refused), Some(400), "a healthy lease is revoked, not cleared");
    assert!(row(&expiration, &healthy).await.is_some());

    expiration.force_clear_revoke_failed(&id, None).await.expect("force-clear");
    assert!(row(&expiration, &id).await.is_none());
    assert!(expiration.list_revoke_failed().await.unwrap().is_empty());
    assert_eq!(target.revokes(), 3, "force-clear does not call the backend");
    let again = expiration.force_clear_revoke_failed(&id, None).await;
    assert_eq!(again.err(), Some(RvError::ErrLeaseNotFound));
}

/// A row as every version before T62 wrote it: no `version`, no
/// `max_ttl_secs`, no `revoke_failure`.
const PRE_T62_ROW: &str = r#"{
    "lease_id": "dyn/creds/app/0b7f",
    "client_token": "owner-token",
    "path": "dyn/creds/app",
    "data": { "username": "v-app-1" },
    "secret": { "lease": { "secs": 3600, "nanos": 0 }, "renewable": true,
                "lease_id": "dyn/creds/app/0b7f", "internal_data": {} },
    "auth": null,
    "issue_time": "2026-10-01T12:00:00Z",
    "expire_time": "2099-10-01T13:00:00Z",
    "revoke_err": ""
}"#;

#[tokio::test]
async fn pre_t62_rows_load_and_are_written_back_as_the_current_version() {
    let parsed: LeaseEntry = serde_json::from_str(PRE_T62_ROW).expect("an old row deserializes");
    assert_eq!((parsed.version, parsed.max_ttl_secs), (0, 0));
    assert!(parsed.revoke_failure.is_none());

    let (_core, expiration, _ts) = manager("t62_old_rows", RevokeRetryPolicy::default()).await;
    let key = "dyn/creds/app/0b7f";
    let old = StorageEntry { key: key.into(), value: PRE_T62_ROW.as_bytes().to_vec() };
    expiration.id_view.put(&old).await.unwrap();

    let le = row(&expiration, key).await.expect("loads");
    assert_eq!(le.version, LEASE_ENTRY_VERSION, "upgraded in memory");
    assert_eq!(le.max_ttl(), super::MAX_LEASE_DURATION_SECS, "no max_ttl means the global ceiling");
    assert_eq!(le.data["username"], "v-app-1");
    let raw = expiration.id_view.get(key).await.unwrap().unwrap();
    assert_eq!(raw.value, PRE_T62_ROW.as_bytes(), "reading does not rewrite the row");

    expiration.restore().await.unwrap();
    assert_eq!(expiration.get_lease_count(), 1);
    assert!(expiration.list_revoke_failed().await.unwrap().is_empty());

    expiration.persist_lease_entry(&le).await.unwrap();
    let written: serde_json::Value =
        serde_json::from_slice(&expiration.id_view.get(key).await.unwrap().unwrap().value).unwrap();
    assert_eq!(written["version"], LEASE_ENTRY_VERSION);
    assert!(written.get("revoke_failure").is_none(), "absent while not revoke_failed");
}

#[tokio::test]
async fn renew_extends_the_lease_and_clamps_it_to_max_ttl() {
    let (core, expiration, _ts) = manager("t62_renew_clamp", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_with(30));
    let id = issue(&expiration, "dyn/creds/app", lease(60, 120, true)).await;
    let issued = row(&expiration, &id).await.unwrap();
    assert_eq!(issued.max_ttl_secs, 120, "the backend's max_ttl is kept on the row");

    let renewal = expiration.renew(&id, Duration::from_secs(3600)).await.expect("renew");
    assert!(renewal.clamped, "{renewal:?}");
    assert!((118..=120).contains(&renewal.ttl.as_secs()), "clamped to max_ttl: {renewal:?}");
    let renewed = row(&expiration, &id).await.unwrap();
    assert!(renewed.expire_time <= issued.issue_time + Duration::from_secs(121), "never past issue + max_ttl");
    assert!(renewed.expire_time > issued.expire_time, "the expiry really moved");

    let plain = expiration.renew(&id, Duration::ZERO).await.expect("renew at the backend's TTL");
    assert_eq!((plain.ttl, plain.clamped), (Duration::from_secs(30), false));
    assert_eq!(target.renews(), 2);
}

#[tokio::test]
async fn renew_refuses_what_it_cannot_really_renew() {
    let (core, expiration, _ts) = manager("t62_renew_refusals", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let silent = mount_target(&core, &expiration, "quiet/", renews_nothing());

    let fixed = issue(&expiration, "dyn/creds/fixed", lease(60, 0, false)).await;
    assert_eq!(expiration.renew(&fixed, Duration::ZERO).await.err(), Some(RvError::ErrLeaseNotRenewable));

    let unhooked = issue(&expiration, "quiet/creds/app", lease(60, 0, true)).await;
    let before = row(&expiration, &unhooked).await.unwrap().expire_time;
    assert_eq!(status(&expiration.renew(&unhooked, Duration::ZERO).await), Some(501));
    assert_eq!(row(&expiration, &unhooked).await.unwrap().expire_time, before, "nothing renewed");
    assert_eq!(silent.renews(), 1);

    let now = SystemTime::now();
    let aged = LeaseEntry {
        lease_id: "dyn/creds/aged/1".into(),
        client_token: OWNER_TOKEN.into(),
        path: "dyn/creds/aged".into(),
        secret: Some(SecretData { lease: lease(60, 0, true), ..Default::default() }),
        issue_time: now - Duration::from_secs(300),
        expire_time: now + Duration::from_secs(60),
        max_ttl_secs: 120,
        ..Default::default()
    };
    expiration.persist_lease_entry(&aged).await.unwrap();
    assert_eq!(status(&expiration.renew(&aged.lease_id, Duration::ZERO).await), Some(400), "past max_ttl");

    let failing = issue(&expiration, "dyn/creds/failing", lease(3600, 0, true)).await;
    target.fail(true);
    assert_eq!(status(&expiration.revoke_named_lease(&failing).await), Some(502));
    assert_eq!(status(&expiration.renew(&failing, Duration::ZERO).await), Some(409), "revocation pending");

    assert_eq!(expiration.renew("dyn/creds/none/1", Duration::ZERO).await.err(), Some(RvError::ErrLeaseNotFound));
    assert_eq!(target.renews(), 0, "no refused renewal reached the target");
}

#[tokio::test]
async fn concurrent_revoke_and_renew_get_a_deterministic_error() {
    let (core, expiration, _ts) = manager("t62_revoke_renew_race", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(60, 0, true)).await;
    *target.probe.lock().unwrap() = Some(id.clone());

    expiration.renew(&id, Duration::ZERO).await.expect("renew");
    assert_eq!(*target.held.lock().unwrap(), vec![true], "the renew holds the lease during its backend call");

    // Another operation in flight on the same lease: both lose, nothing moves.
    let in_flight = expiration.lease_locks.try_acquire(&id).unwrap();
    let before = row(&expiration, &id).await.unwrap().expire_time;
    assert_eq!(status(&expiration.revoke_named_lease(&id).await), Some(409));
    assert_eq!(status(&expiration.renew(&id, Duration::ZERO).await), Some(409));
    assert_eq!(row(&expiration, &id).await.unwrap().expire_time, before);
    drop(in_flight);

    expiration.revoke_named_lease(&id).await.expect("revoke");
    assert_eq!(*target.held.lock().unwrap(), vec![true, true], "the revoke holds it too");
    assert_eq!(expiration.renew(&id, Duration::ZERO).await.err(), Some(RvError::ErrLeaseNotFound));
    assert!(row(&expiration, &id).await.is_none(), "a renew after a revoke cannot resurrect the row");
}

#[tokio::test]
async fn a_mount_can_revoke_only_its_own_leases_early() {
    let (core, expiration, _ts) = manager("t62_owner_revoke", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let _other = mount_target(&core, &expiration, "other/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;

    let wrong = expiration.revoke_owned_lease("other/", &id).await;
    assert_eq!(wrong.err(), Some(RvError::ErrPermissionDenied));
    assert!(row(&expiration, &id).await.is_some(), "a refused revoke changes nothing");
    assert_eq!(status(&expiration.revoke_owned_lease("dyn/", "../core/x").await), Some(400));

    assert_eq!(expiration.revoke_owned_lease("dyn", &id).await, Ok(LeaseRevocation::Revoked));
    assert!(row(&expiration, &id).await.is_none());
    assert_eq!(expiration.revoke_owned_lease("dyn/", &id).await.err(), Some(RvError::ErrLeaseNotFound));

    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;
    target.fail(true);
    assert_eq!(expiration.revoke_owned_lease("dyn/", &id).await, Ok(LeaseRevocation::Deferred { attempts: 1 }));
    assert_eq!(row(&expiration, &id).await.unwrap().revoke_failure.unwrap().origin, RevokeOrigin::Owner);
}

#[tokio::test]
async fn revoke_lease_id_reports_what_happened() {
    let (core, expiration, _ts) = manager("t62_revoke_outcome", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let id = issue(&expiration, "dyn/creds/app", lease(3600, 0, true)).await;

    assert_eq!(expiration.revoke_lease_id("dyn/creds/none/1", true).await, Ok(RevokeOutcome::Missing));
    target.fail(true);
    let failed = expiration.revoke_lease_id(&id, true).await;
    assert_eq!(failed, Ok(RevokeOutcome::Failed { attempts: 1, exhausted: false }));
    target.fail(false);
    assert_eq!(expiration.revoke_lease_id(&id, true).await, Ok(RevokeOutcome::Revoked { failed_attempts: 1 }));
}

/// The sweeper itself: an expired lease whose revoke fails stays on record.
#[tokio::test]
async fn the_sweeper_keeps_an_expired_lease_whose_revoke_fails() {
    let (core, expiration, _ts) = manager("t62_sweeper_keeps", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    target.fail(true);
    let id = issue(&expiration, "dyn/creds/app", lease(1, 0, true)).await;
    expiration.start_check_expired_lease_entries();

    std::thread::sleep(Duration::from_millis(1800));

    assert_eq!(target.revokes(), 1, "swept once, then backing off");
    let failure = row(&expiration, &id).await.expect("kept").revoke_failure.expect("revoke_failed");
    assert_eq!((failure.attempts, failure.origin), (1, RevokeOrigin::Expiry));
    assert_eq!(expiration.get_lease_count(), 1, "still tracked");
}

// ── Host-managed (dynamic-secrets) leases ─────────────────────────────────

fn host_managed_response(lease: Lease) -> Response {
    let mut internal_data = serde_json::Map::new();
    internal_data.insert("secret_type".into(), json!(super::HOST_MANAGED_SECRET_TYPE));
    internal_data.insert("bv_dynamic".into(), json!({ "username": "v-app-1" }));
    Response {
        secret: Some(SecretData { lease, internal_data, ..Default::default() }),
        data: json!({ "username": "v-app-1", "password": PASSWORD, "port": 5432 }).as_object().cloned(),
        ..Default::default()
    }
}

async fn raw_row(expiration: &ExpirationManager, lease_id: &str) -> String {
    let entry = expiration.id_view.get(lease_id).await.unwrap().expect("a stored row");
    String::from_utf8(entry.value).unwrap()
}

#[tokio::test]
async fn a_host_managed_lease_row_never_stores_the_password() {
    let (core, expiration, _ts) = manager("t62_host_managed_no_password", RevokeRetryPolicy::default()).await;
    let _target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let mut req = Request::new("dyn/creds/app");
    req.client_token = OWNER_TOKEN.into();
    let mut resp = host_managed_response(lease(3600, 0, true));
    let id = expiration.register_secret(&mut req, &mut resp).await.unwrap();

    assert!(!raw_row(&expiration, &id).await.contains(PASSWORD), "the stored row carries the credential");
    let le = row(&expiration, &id).await.unwrap();
    assert_eq!((le.data["username"].clone(), le.data["port"].clone()), (json!("v-app-1"), json!(5432)));
    assert_eq!(resp.data.unwrap()["password"], PASSWORD, "the caller still gets it");

    // Any other secret's row is as before.
    let plain = issue(&expiration, "dyn/creds/plain", lease(3600, 0, true)).await;
    assert_eq!(row(&expiration, &plain).await.unwrap().data["password"], PASSWORD);
}

#[tokio::test]
async fn an_old_host_managed_row_with_a_password_still_loads_and_loses_it_when_rewritten() {
    let (core, expiration, _ts) = manager("t62_host_managed_old_row", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let mut resp = host_managed_response(lease(3600, 0, true));
    let mut secret = resp.secret.take().unwrap();
    let id = "dyn/creds/app/old-row".to_string();
    secret.lease_id.clone_from(&id);
    let now = SystemTime::now();
    let old = LeaseEntry {
        lease_id: id.clone(),
        client_token: OWNER_TOKEN.into(),
        path: "dyn/creds/app".into(),
        data: resp.data.clone().unwrap(),
        secret: Some(secret),
        issue_time: now,
        expire_time: now + Duration::from_secs(3600),
        ..Default::default()
    };
    // Written as a slice-2 build did: the password inside the row.
    let bytes = serde_json::to_vec(&old).unwrap();
    expiration.id_view.put(&StorageEntry { key: id.clone(), value: bytes }).await.unwrap();
    assert!(raw_row(&expiration, &id).await.contains(PASSWORD));
    assert_eq!(row(&expiration, &id).await.expect("an old row still reads").data["password"], PASSWORD);

    expiration.renew(&id, Duration::ZERO).await.expect("renew");
    assert_eq!(target.renews(), 1);
    assert!(!raw_row(&expiration, &id).await.contains(PASSWORD), "rewritten without the credential");
}

#[tokio::test]
async fn a_host_managed_secret_whose_lease_cannot_be_registered_is_taken_back() {
    let (core, expiration, ts) = manager("t62_host_managed_take_back", RevokeRetryPolicy::default()).await;
    let target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    // Without its token store, registration fails after the row is written.
    drop(ts);
    let mut req = Request::new("dyn/creds/app");
    req.client_token = OWNER_TOKEN.into();
    let mut resp = host_managed_response(lease(3600, 0, true));
    assert!(expiration.register_host_managed_secret(&mut req, &mut resp).await.is_err());
    assert_eq!(target.revokes(), 1, "the credential was revoked through its backend");
    assert!(expiration.id_view.list("dyn/creds/app/").await.unwrap().is_empty(), "no half-written row is left");
    assert!(expiration.list_revoke_failed().await.unwrap().is_empty());

    // The revoke fails too: kept as revoke_failed, listed, retried.
    target.fail(true);
    let mut resp = host_managed_response(lease(3600, 0, true));
    assert!(expiration.register_host_managed_secret(&mut req, &mut resp).await.is_err());
    assert_eq!(target.revokes(), 2);
    let listed = expiration.list_revoke_failed().await.unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].failure.origin, RevokeOrigin::Registration);
    assert!(!raw_row(&expiration, &listed[0].lease_id).await.contains(PASSWORD));
    assert_eq!(expiration.get_lease_count(), 1, "tracked by the reaper");
}

#[tokio::test]
async fn a_registered_host_managed_lease_id_reaches_the_slot_the_backend_left() {
    let (core, expiration, _ts) = manager("t62_host_managed_slot", RevokeRetryPolicy::default()).await;
    let _target = mount_target(&core, &expiration, "dyn/", renews_as_issued());
    let mut req = Request::new("dyn/creds/app");
    req.client_token = OWNER_TOKEN.into();
    let slot: Arc<RwLock<dyn std::any::Any + Send + Sync>> = Arc::new(RwLock::new(None::<String>));
    req.ctx.set_mut(super::HOST_MANAGED_LEASE_SLOT, slot.clone());
    let mut resp = host_managed_response(lease(3600, 0, true));
    let id = expiration.register_host_managed_secret(&mut req, &mut resp).await.unwrap();
    let seen = slot.read().unwrap().downcast_ref::<Option<String>>().cloned().flatten();
    assert_eq!(seen.as_deref(), Some(id.as_str()));
}
