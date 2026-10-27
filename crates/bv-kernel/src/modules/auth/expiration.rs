//! This file contains the implementation of the ExpirationManager, which is responsible
//! for managing lease entries and their expiration. It includes functionalities to register,
//! renew, and revoke leases, as well as to check for expired leases and handle them accordingly.

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap},
    fmt,
    hash::{Hash, Hasher},
    sync::{Arc, RwLock, Weak},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use better_default::Default;
use crossbeam_channel::{select, tick};
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    lease_state::{
        emit_lease_event, rfc3339, LeaseLocks, LeaseOpGuard, LeaseRevokeFailedClearedEvent, LeaseRevokeFailedEvent,
        LeaseRevokedEvent, RevokeFailure, RevokeOrigin, RevokeRetryPolicy,
    },
    token_store::TokenEntry,
    TokenStore,
};
use crate::{
    bv_error_response_status, bv_error_string,
    errors::RvError,
    kernel_api::{
        leases::{LeaseRevocation, OwnedLeaseRevoker},
        mcp_events::McpAuditEvent,
    },
    logical::{lease::calculate_ttl, Auth, Request, Response, SecretData},
    router::Router,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::{
        deserialize_system_time, generate_uuid, serialize_system_time,
        token_util::{DEFAULT_LEASE_TTL, MAX_LEASE_TTL},
    },
};

use crate::kernel_api::VaultCtx;

pub const EXPIRATION_SUB_PATH: &str = "expire/";
pub const LEASE_VIEW_PREFIX: &str = "id/";
pub const TOKEN_VIEW_PREFIX: &str = "token/";
/// Failed backend revokes after which the reaper stops retrying a lease
/// (`max_revoke_attempts`, spec default). The lease stays listed for the operator.
pub const MAX_REVOKE_ATTEMPTS: u32 = 6;
/// Wait after a lease's first failed revoke; doubled after each further one.
pub const REVOKE_RETRY_SECS: Duration = Duration::from_secs(10);
pub const MIN_REVOKE_DELAY_SECS: Duration = Duration::from_secs(5);
pub use crate::kernel_api::auth::{DEFAULT_LEASE_DURATION_SECS, MAX_LEASE_DURATION_SECS};

/// `internal_data["secret_type"]` of a secret issued by the dynamic-secrets
/// plugin host (T62). Such a secret is always registered as a lease, whatever
/// the mount's `leased_passthrough` option says: the credential lives in an
/// external system and only its lease ever revokes it.
pub const HOST_MANAGED_SECRET_TYPE: &str = "bv_dynamic";

/// Whether `secret` was issued by the dynamic-secrets plugin host.
pub fn is_host_managed_secret(secret: &SecretData) -> bool {
    secret.internal_data.get("secret_type").and_then(Value::as_str) == Some(HOST_MANAGED_SECRET_TYPE)
}

/// `Request::ctx` key of a `RwLock<Option<String>>` slot the dynamic-secrets
/// host may leave there; the kernel writes the id of the lease it registered
/// for the host's answer into it.
pub const HOST_MANAGED_LEASE_SLOT: &str = "bv_dynamic.lease_id";

/// Response data never kept on a host-managed secret's lease row: its renew
/// and revoke do not read the credential, so the row (and every backup of it)
/// does not carry it.
const HOST_MANAGED_UNSTORED_KEYS: [&str; 1] = ["password"];

/// `data` as a lease row of `secret` stores it.
fn lease_row_data(secret: &SecretData, data: Option<&Map<String, Value>>) -> Map<String, Value> {
    let mut data = data.cloned().unwrap_or_default();
    if is_host_managed_secret(secret) {
        HOST_MANAGED_UNSTORED_KEYS.iter().for_each(|k| {
            data.remove(*k);
        });
    }
    data
}

/// Hand `lease_id` to the slot a host-managed backend left in `req.ctx`.
fn publish_host_managed_lease_id(req: &Request, lease_id: &str) {
    let Some(slot) = req.ctx.get_mut(HOST_MANAGED_LEASE_SLOT) else {
        return;
    };
    if let Ok(mut guard) = slot.write() {
        if let Some(value) = guard.downcast_mut::<Option<String>>() {
            *value = Some(lease_id.to_string());
        }
    };
}

/// Format of a lease row. 0 is every row written before T62 (the field is
/// absent there); 1 added `max_ttl_secs` and `revoke_failure`, both of which
/// default to "none" for a version-0 row, so reading one needs no rewrite.
pub const LEASE_ENTRY_VERSION: u32 = 1;

/// Represents an old lease entry that may need to be converted to the new format.
#[derive(Eq, Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
struct OldLeaseEntry {
    #[serde(default)]
    pub lease_id: String,
    pub client_token: String,
    pub path: String,
    pub data: Option<HashMap<String, Value>>,
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub issue_time: SystemTime,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub expire_time: SystemTime,
}

/// Represents a lease entry with all the necessary information.
///
/// `Debug` is written by hand: `data` holds the issued secret and
/// `client_token` the owning token, and neither may reach a log line.
#[derive(Default, Clone, Serialize, Deserialize)]
struct LeaseEntry {
    #[serde(default)]
    pub lease_id: String,
    pub client_token: String,
    pub path: String,
    pub data: Map<String, Value>,
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub issue_time: SystemTime,
    #[default(SystemTime::UNIX_EPOCH)]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub expire_time: SystemTime,
    /// Pre-T62 field, never written non-empty by any version; kept so old
    /// rows round-trip. The revoke error now lives in `revoke_failure`.
    #[serde(default)]
    pub revoke_err: String,
    /// [`LEASE_ENTRY_VERSION`] of the row; 0 (absent) before T62.
    #[default(LEASE_ENTRY_VERSION)]
    #[serde(default)]
    pub version: u32,
    /// Host-side ceiling on the lease's life from `issue_time`, in seconds;
    /// 0 means [`MAX_LEASE_DURATION_SECS`]. Needed because `SecretData`'s own
    /// `max_ttl` is not serialized, so it is gone by the time a renew comes.
    #[serde(default)]
    pub max_ttl_secs: u64,
    /// Present while the issuing backend has failed to revoke this lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_failure: Option<RevokeFailure>,
}

impl fmt::Debug for LeaseEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseEntry")
            .field("lease_id", &self.lease_id)
            .field("path", &self.path)
            .field("data_keys", &self.data.len())
            .field("secret", &self.secret.as_ref().map(|s| (s.ttl, s.renewable)))
            .field("auth", &self.auth.is_some())
            .field("issue_time", &self.issue_time)
            .field("expire_time", &self.expire_time)
            .field("version", &self.version)
            .field("max_ttl_secs", &self.max_ttl_secs)
            .field("revoke_failure", &self.revoke_failure)
            .finish_non_exhaustive()
    }
}

/// The ExpirationManager is responsible for managing lease entries and their expiration.
pub struct ExpirationManager {
    pub self_ptr: Weak<Self>,
    pub router: Arc<Router>,
    pub id_view: Arc<BarrierView>,
    pub token_view: Arc<BarrierView>,
    pub token_store: RwLock<Weak<TokenStore>>,
    queue: Arc<RwLock<PriorityQueue<Arc<LeaseEntry>, Reverse<u128>>>>,
    /// Back-reference to Core for resolving per-namespace lease quotas at
    /// registration time. Weak to avoid a cycle; tolerated absent in tests.
    core: Weak<dyn VaultCtx>,
    /// The leases a renew or revoke is running on (see [`LeaseLocks`]).
    lease_locks: Arc<LeaseLocks>,
    /// Retry schedule for leases whose backend revoke failed.
    revoke_policy: RevokeRetryPolicy,
    /// Ids of the rows in `revoke_failed`, rebuilt from storage by `restore`,
    /// so listing them does not read every lease row.
    revoke_failed_ids: RwLock<BTreeSet<String>>,
}

/// What a revoke did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Revoked and deleted; `failed_attempts` earlier tries had failed.
    Revoked { failed_attempts: u32 },
    /// No lease has that id.
    Missing,
    /// The backend failed; the row is kept as `revoke_failed`.
    Failed { attempts: u32, exhausted: bool },
}

/// What a renewal did. Only returned when the lease really was extended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRenewal {
    pub lease_id: String,
    /// The lease's new TTL, from now.
    pub ttl: Duration,
    /// Whether the backend allows a further renewal.
    pub renewable: bool,
    /// The TTL was cut short by the lease's max_ttl.
    pub clamped: bool,
}

/// One `revoke_failed` lease, as `LIST v2/sys/leases/revoke-failed` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevokeFailedLease {
    pub lease_id: String,
    pub path: String,
    pub issue_time: SystemTime,
    pub expire_time: SystemTime,
    pub failure: RevokeFailure,
    pub max_attempts: u32,
    pub exhausted: bool,
}

impl Hash for LeaseEntry {
    /// Implements hash function for lease entries based on unique attributes.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lease_id.hash(state);
        self.client_token.hash(state);
        self.path.hash(state);
    }
}

impl PartialEq for LeaseEntry {
    /// Implements partial equality checking for lease entries.
    fn eq(&self, other: &Self) -> bool {
        self.lease_id == other.lease_id && self.client_token == other.client_token && self.path == other.path
    }
}

impl Eq for LeaseEntry {}

impl LeaseEntry {
    /// Checks if the lease entry is renewable.
    fn renewable(&self) -> bool {
        self.expire_time >= SystemTime::now()
            && self.secret.as_ref().map_or(true, |s| s.renewable())
            && self.auth.as_ref().map_or(true, |a| a.renewable())
    }

    #[allow(dead_code)]
    fn is_non_expiring(&self) -> bool {
        self.auth.as_ref().map_or(false, |a| a.enabled() && a.policies.len() == 1 && a.policies[0] == "root")
    }

    /// The issuing backend has failed to revoke this lease and it is still owed one.
    fn is_revoke_failed(&self) -> bool {
        self.revoke_failure.is_some()
    }

    #[allow(dead_code)]
    fn is_incorrectly_non_expiring(&self) -> bool {
        self.expire_time == SystemTime::UNIX_EPOCH && !self.is_non_expiring()
    }

    /// The longest this lease may live, counted from `issue_time`.
    fn max_ttl(&self) -> Duration {
        match self.max_ttl_secs {
            0 => MAX_LEASE_DURATION_SECS,
            secs => Duration::from_secs(secs).min(MAX_LEASE_DURATION_SECS),
        }
    }

    /// When the sweeper must next look at this lease, in Unix milliseconds:
    /// its expiry, or for a `revoke_failed` lease its next retry. An exhausted
    /// one is parked at `u128::MAX`, never due, so it stays tracked (and
    /// counted against its namespace's quota) without being retried.
    fn queue_priority(&self, policy: &RevokeRetryPolicy) -> Result<u128, RvError> {
        match &self.revoke_failure {
            Some(failure) if policy.exhausted(failure) => Ok(u128::MAX),
            Some(failure) => Ok(failure.next_attempt_at.duration_since(UNIX_EPOCH)?.as_millis()),
            None => Ok(self.expire_time.duration_since(UNIX_EPOCH)?.as_millis()),
        }
    }
}

impl ExpirationManager {
    /// Creates a new ExpirationManager instance.
    pub fn new(core: &dyn VaultCtx) -> Result<ExpirationManager, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let id_view = system_view.new_sub_view(LEASE_VIEW_PREFIX);
        let token_view = system_view.new_sub_view(TOKEN_VIEW_PREFIX);

        let expiration = ExpirationManager {
            self_ptr: Weak::new(),
            router: core.router().clone(),
            id_view: Arc::new(id_view),
            token_view: Arc::new(token_view),
            token_store: RwLock::new(Weak::new()),
            queue: Arc::new(RwLock::new(PriorityQueue::new())),
            core: core.weak_ctx(),
            lease_locks: Arc::new(LeaseLocks::default()),
            revoke_policy: RevokeRetryPolicy::default(),
            revoke_failed_ids: RwLock::new(BTreeSet::new()),
        };

        Ok(expiration)
    }

    /// Wraps the ExpirationManager in an Arc and sets the weak pointer.
    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    /// Sets the token store for the ExpirationManager.
    pub fn set_token_store(&self, ts: &Arc<TokenStore>) -> Result<(), RvError> {
        let mut token_store = self.token_store.write()?;
        *token_store = Arc::downgrade(ts);
        Ok(())
    }

    /// Restores the lease entries from the storage.
    #[maybe_async::maybe_async]
    pub async fn restore(&self) -> Result<(), RvError> {
        let existing = self.id_view.get_keys().await?;

        for lease_id in existing {
            let le = self.load_lease_entry(&lease_id).await?;
            if le.is_none() {
                continue;
            }

            let le = le.unwrap();
            if le.is_revoke_failed() {
                self.remember_revoke_failed(&le.lease_id)?;
            }
            self.register_lease_entry(Arc::new(le))?;
        }

        Ok(())
    }

    /// Renews a secret lease by `increment` (0: the backend's own TTL).
    ///
    /// Returns only when the lease really was extended. Refused, with nothing
    /// changed: an unknown id ([`RvError::ErrLeaseNotFound`]); an expired or
    /// non-renewable lease ([`RvError::ErrLeaseNotRenewable`]); one past its
    /// max_ttl or whose revocation is pending (`400`/`409`); a token's lease,
    /// or a backend that does not renew this lease or answers without a lease
    /// (`501`). The new TTL is clamped to the lease's max_ttl.
    #[maybe_async::maybe_async]
    pub async fn renew(&self, lease_id: &str, increment: Duration) -> Result<LeaseRenewal, RvError> {
        let _guard = self.lease_locks.try_acquire(lease_id)?;
        let Some(mut le) = self.load_lease_entry(lease_id).await? else {
            return Err(RvError::ErrLeaseNotFound);
        };

        if le.auth.is_some() {
            return Err(renew_unsupported(
                "this is a token's lease: renew the token with auth/token/renew-self or auth/token/renew",
            ));
        }
        if le.is_revoke_failed() {
            return Err(bv_error_response_status!(
                409,
                "this lease is revoke_failed: its revocation is pending, so it cannot be renewed"
            ));
        }
        if le.secret.is_none() {
            return Err(renew_unsupported("this lease carries no secret to renew"));
        }
        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }
        // Checked before the backend is asked, so a lease the host will not
        // extend is not extended on the target system either.
        let max_ttl = le.max_ttl();
        if le.issue_time + max_ttl <= SystemTime::now() {
            return Err(past_max_ttl());
        }

        let resp = match self.renew_secret_lease_entry(&le, increment).await {
            Err(RvError::ErrLogicalOperationUnsupported) => {
                return Err(renew_unsupported("the backend that issued this lease does not renew it"));
            }
            result => result?,
        };
        let Some(resp) = resp else {
            return Err(renew_unsupported("the backend that issued this lease did not renew it"));
        };
        let Some(mut secret) = resp.secret else {
            return Err(renew_unsupported("the backend answered the renewal without a lease"));
        };
        if secret.ttl.is_zero() {
            return Err(renew_unsupported("the backend answered the renewal with a zero TTL"));
        }

        let requested = if increment.is_zero() { secret.ttl } else { increment };
        let ttl = calculate_ttl(
            MAX_LEASE_TTL,
            DEFAULT_LEASE_TTL,
            increment,
            Duration::ZERO,
            secret.ttl,
            secret.max_ttl,
            max_ttl,
            le.issue_time,
        )
        .map_err(|_| past_max_ttl())?;

        // The backend may update the internal data it revokes with, but an
        // answer that drops `secret_type` would make the next revoke a silent
        // no-op, so the stored keys are kept under the backend's.
        let previous = le.secret.take().map(|s| s.internal_data).unwrap_or_default();
        let mut internal_data = previous;
        internal_data.extend(std::mem::take(&mut secret.internal_data));
        secret.internal_data = internal_data;
        secret.ttl = ttl;
        secret.lease_id = lease_id.to_string();
        let renewable = secret.renewable;

        if let Some(data) = resp.data {
            le.data = data;
        }
        le.expire_time = SystemTime::now() + ttl;
        le.secret = Some(secret);

        self.persist_lease_entry(&le).await?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(LeaseRenewal { lease_id: lease_id.to_string(), ttl, renewable, clamped: ttl < requested })
    }

    /// Renews a token by the given increment.
    #[maybe_async::maybe_async]
    pub async fn renew_token(
        &self,
        req: &mut Request,
        te: &TokenEntry,
        increment: Duration,
    ) -> Result<Option<Response>, RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let lease_id = format!("{}/{}", te.path, token_store.salt_id(&te.id));

        let le = self.load_lease_entry(&lease_id).await?;
        if le.is_none() {
            return Err(RvError::ErrLeaseNotFound);
        }

        let mut le = le.unwrap();

        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }

        let resp = self.renew_auth_lease_entry(req, &le, increment).await?;
        if resp.is_none() {
            return Ok(None);
        }

        let resp = resp.unwrap();
        if resp.auth.is_none() {
            return Ok(None);
        }

        let mut auth = resp.auth.unwrap();

        auth.ttl = calculate_ttl(
            MAX_LEASE_TTL,
            DEFAULT_LEASE_TTL,
            increment,
            auth.period,
            auth.ttl,
            auth.max_ttl,
            auth.explicit_max_ttl,
            le.issue_time,
        )?;
        auth.client_token.clone_from(&te.id);

        le.expire_time = auth.expiration_time();
        le.auth = Some(auth.clone());

        self.persist_lease_entry(&le).await?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }

    /// Registers a secret from a response for lease management.
    #[maybe_async::maybe_async]
    /// Count live leases whose path falls under `ns_path` (a non-root
    /// namespace). Used for `max_leases` quota enforcement. Root (`""`) returns
    /// 0 since the root namespace is never lease-capped.
    pub fn count_leases_for_namespace(&self, ns_path: &str) -> usize {
        if ns_path.is_empty() {
            return 0;
        }
        let prefix = format!("{ns_path}/");
        self.queue
            .read()
            .map(|q| q.iter().filter(|(le, _)| le.path.starts_with(&prefix)).count())
            .unwrap_or(0)
    }

    /// Enforce the target namespace's `max_leases` quota before a new secret
    /// lease is registered. Resolves the namespace from the (already
    /// namespace-normalised) request path. A no-op for root / unlimited / when
    /// the namespace module is unavailable.
    #[maybe_async::maybe_async]
    async fn enforce_lease_quota(&self, req: &Request) -> Result<(), RvError> {
        self.enforce_lease_quota_for_path(&req.path).await
    }

    #[maybe_async::maybe_async]
    async fn enforce_lease_quota_for_path(&self, path: &str) -> Result<(), RvError> {
        let Some(core) = self.core.upgrade() else {
            return Ok(());
        };
        let Some(namespaces) = core.namespaces() else {
            return Ok(());
        };
        let Some((ns_path, limit)) = namespaces.lease_quota_for_path(path).await? else {
            return Ok(());
        };
        let current = self.count_leases_for_namespace(&ns_path) as u64;
        crate::modules::namespace::quota::check_lease_quota(&ns_path, current, limit)
    }

    /// [`OwnedLeaseRevoker::check_lease_quota`]: the check registration makes,
    /// for the namespace `ns_path` (empty: root, never capped).
    #[maybe_async::maybe_async]
    pub async fn check_namespace_lease_quota(&self, ns_path: &str) -> Result<(), RvError> {
        let ns_path = ns_path.trim_matches('/');
        if ns_path.is_empty() {
            return Ok(());
        }
        // The resolver never reads a path's last segment as a namespace.
        self.enforce_lease_quota_for_path(&format!("{ns_path}/_")).await
    }

    /// Register a host-managed secret's lease, on every mount. When that
    /// fails the credential already exists in its external system and nothing
    /// else would revoke it, so it is revoked now ([`Self::take_back`]).
    #[maybe_async::maybe_async]
    pub async fn register_host_managed_secret(
        &self,
        req: &mut Request,
        resp: &mut Response,
    ) -> Result<String, RvError> {
        match self.register_secret(req, resp).await {
            Ok(lease_id) => {
                publish_host_managed_lease_id(req, &lease_id);
                Ok(lease_id)
            }
            Err(e) => {
                self.take_back(req, resp, &e).await;
                Err(e)
            }
        }
    }

    /// Revoke the credential of an answer whose lease could not be registered,
    /// through its own backend. A failed revoke is kept as `revoke_failed`
    /// (origin `registration`) so the reaper retries it and operators see it.
    #[maybe_async::maybe_async]
    async fn take_back(&self, req: &Request, resp: &Response, error: &RvError) {
        let Some(mut secret) = resp.secret.clone() else {
            return;
        };
        // Set when registration failed after the row was written: undo it.
        let partial = std::mem::take(&mut secret.lease_id);
        if !partial.is_empty() {
            let _ = self.delete_lease_entry(&partial).await;
            let _ = self.remove_index_by_token(&req.client_token, &partial).await;
        }
        // The answer's data rides along only so the backend can redact the
        // credential from its error; it is not stored.
        let mut revoke = Request::new_revoke_request(&req.path, Some(secret.clone()), resp.data.clone());
        let Err(revoke_error) = self.router.handle_request(&mut revoke).await else {
            log::warn!("lease registration under {} failed ({error}); the credential it was for was revoked", req.path);
            return;
        };
        let lease_id = if partial.is_empty() { format!("{}/{}", req.path, generate_uuid()) } else { partial };
        let now = SystemTime::now();
        secret.lease_id.clone_from(&lease_id);
        secret.issue_time = Some(now);
        let le = LeaseEntry {
            lease_id: lease_id.clone(),
            client_token: req.client_token.clone(),
            path: req.path.clone(),
            data: lease_row_data(&secret, resp.data.as_ref()),
            secret: Some(secret),
            issue_time: now,
            expire_time: now,
            ..Default::default()
        };
        if let Err(e) = self.create_index_by_token(&le.client_token, &lease_id).await {
            log::warn!("revoke_failed lease {lease_id} is not indexed under its token: {e}");
        }
        if let Err(e) = self.record_revoke_failure(le, RevokeOrigin::Registration, &revoke_error).await {
            log::error!(
                "lease registration under {} failed and revoking its credential failed too ({revoke_error}); \
                 it could not be kept as revoke_failed ({e}): remove the credential by hand",
                req.path
            );
        }
    }

    pub async fn register_secret(&self, req: &mut Request, resp: &mut Response) -> Result<String, RvError> {
        if let Some(secret) = resp.secret.as_mut() {
            // Quota: refuse a new lease beyond the namespace's max_leases cap.
            self.enforce_lease_quota(req).await?;
            if secret.ttl.as_secs() == 0 {
                secret.ttl = DEFAULT_LEASE_DURATION_SECS;
            }

            if secret.ttl > MAX_LEASE_DURATION_SECS {
                secret.ttl = MAX_LEASE_DURATION_SECS;
            }

            // The backend's max_ttl, if it set one, bounds every renewal; it is
            // kept on the row because `SecretData` does not serialize it.
            let max_ttl = match secret.max_ttl {
                max if max.is_zero() => MAX_LEASE_DURATION_SECS,
                max => max.min(MAX_LEASE_DURATION_SECS),
            };
            if secret.ttl > max_ttl {
                secret.ttl = max_ttl;
            }

            let now = SystemTime::now();
            secret.issue_time = Some(now);

            let lease_id = format!("{}/{}", req.path, generate_uuid());

            secret.lease_id.clone_from(&lease_id);

            let le = LeaseEntry {
                lease_id: lease_id.clone(),
                client_token: req.client_token.clone(),
                path: req.path.clone(),
                data: lease_row_data(secret, resp.data.as_ref()),
                secret: Some(secret.clone()),
                issue_time: now,
                expire_time: secret.expiration_time(),
                // At least 1 s: a sub-second max_ttl must not read back as 0 ("none").
                max_ttl_secs: if secret.max_ttl.is_zero() { 0 } else { max_ttl.as_secs().max(1) },
                ..Default::default()
            };

            self.persist_lease_entry(&le).await?;
            self.create_index_by_token(&le.client_token, &le.lease_id).await?;

            secret.ttl = le.expire_time.duration_since(now)?;

            self.register_lease_entry(Arc::new(le))?;

            return Ok(lease_id);
        }

        Ok("".into())
    }

    /// Registers an authentication entry for lease management.
    #[maybe_async::maybe_async]
    pub async fn register_auth(&self, te: &TokenEntry, auth: &mut Auth) -> Result<(), RvError> {
        if te.ttl == 0
            && auth.expiration_time() == SystemTime::UNIX_EPOCH
            && (te.policies.len() != 1 || te.policies[0] != "root")
        {
            return Err(bv_error_string!("refusing to register a lease for a non-root token with no TTL"));
        }

        if auth.client_token.is_empty() {
            return Err(bv_error_string!("cannot register an auth lease with an empty token"));
        }

        if te.path.contains("..") {
            return Err(bv_error_string!(
                "cannot register an auth lease with n token entry whose path contains parent references"
            ));
        }

        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let lease_id = format!("{}/{}", te.path, token_store.salt_id(&auth.client_token));

        let now = SystemTime::now();
        auth.issue_time = Some(now);

        let le = LeaseEntry {
            lease_id,
            client_token: auth.client_token.clone(),
            path: te.path.clone(),
            auth: Some(auth.clone()),
            issue_time: now,
            expire_time: auth.expiration_time(),
            ..Default::default()
        };

        self.persist_lease_entry(&le).await?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(())
    }

    /// Revokes a lease entry by its lease ID.
    ///
    /// An unknown lease is [`RevokeOutcome::Missing`], not an error. A secret
    /// backend's failed revoke is [`RevokeOutcome::Failed`]: the row is kept
    /// as `revoke_failed` for the reaper and the operator, never deleted. A
    /// token lease's revoke error is returned as before.
    #[maybe_async::maybe_async]
    pub async fn revoke_lease_id(&self, lease_id: &str, register_lease_entry: bool) -> Result<RevokeOutcome, RvError> {
        let guard = self.lease_locks.try_acquire(lease_id)?;
        self.revoke_lease_locked(&guard, lease_id, register_lease_entry, RevokeOrigin::Operator).await
    }

    /// The revoke itself; the caller holds the lease's guard.
    #[maybe_async::maybe_async]
    async fn revoke_lease_locked(
        &self,
        _guard: &LeaseOpGuard,
        lease_id: &str,
        register_lease_entry: bool,
        origin: RevokeOrigin,
    ) -> Result<RevokeOutcome, RvError> {
        let Some(mut le) = self.load_lease_entry(lease_id).await? else {
            return Ok(RevokeOutcome::Missing);
        };

        log::debug!("revoke lease_id: {}", le.lease_id);

        if let Err(e) = self.revoke_lease_entry(&le).await {
            if le.auth.is_some() {
                return Err(e);
            }
            return self.record_revoke_failure(le, origin, &e).await;
        }

        let failed_attempts = le.revoke_failure.as_ref().map_or(0, |f| f.attempts);
        self.delete_lease_entry(lease_id).await?;

        if le.secret.is_some() {
            self.remove_index_by_token(&le.client_token, &le.lease_id).await?;
        }
        self.forget_revoke_failed(lease_id)?;

        if register_lease_entry {
            le.expire_time = SystemTime::UNIX_EPOCH;
            le.revoke_failure = None;
            self.register_lease_entry(Arc::new(le))?;
        }

        Ok(RevokeOutcome::Revoked { failed_attempts })
    }

    /// Keep a lease whose backend revoke failed, as `revoke_failed`, and
    /// schedule its next attempt (or park it, once the attempts are spent).
    #[maybe_async::maybe_async]
    async fn record_revoke_failure(
        &self,
        mut le: LeaseEntry,
        origin: RevokeOrigin,
        error: &RvError,
    ) -> Result<RevokeOutcome, RvError> {
        let policy = self.revoke_policy;
        let failure = policy.record(le.revoke_failure.as_ref(), origin, SystemTime::now(), error);
        let attempts = failure.attempts;
        let exhausted = policy.exhausted(&failure);
        log::warn!(
            "backend revoke of lease {} failed (attempt {attempts} of {}); kept as revoke_failed{}: {}",
            le.lease_id,
            policy.max_attempts,
            if exhausted { ", retries exhausted: an operator must clear it" } else { "" },
            failure.last_error
        );
        let event = LeaseRevokeFailedEvent {
            lease_id: le.lease_id.clone(),
            origin,
            attempts,
            max_attempts: policy.max_attempts,
            exhausted,
            next_attempt_at: (!exhausted).then(|| rfc3339(failure.next_attempt_at)),
            error: failure.last_error.clone(),
        };

        le.revoke_failure = Some(failure);
        self.persist_lease_entry(&le).await?;
        self.remember_revoke_failed(&le.lease_id)?;
        self.register_lease_entry(Arc::new(le))?;
        self.emit_best_effort(&event).await;

        Ok(RevokeOutcome::Failed { attempts, exhausted })
    }

    /// Revokes the lease an operator named (`sys/revoke/<lease_id>`).
    ///
    /// [`Self::revoke_lease_id`] treats an unknown lease as already revoked,
    /// which the sweeper and token-tree revocation rely on when they reach the
    /// same lease. An operator naming a lease that does not exist has a mistyped
    /// or stale id, and answering "revoked" would report an effect that never
    /// happened, so this returns [`RvError::ErrLeaseNotFound`] instead. A
    /// failed backend revoke is a `502`; the lease is kept as `revoke_failed`.
    #[maybe_async::maybe_async]
    pub async fn revoke_named_lease(&self, lease_id: &str) -> Result<(), RvError> {
        let guard = self.lease_locks.try_acquire(lease_id)?;
        match self.revoke_lease_locked(&guard, lease_id, true, RevokeOrigin::Operator).await? {
            RevokeOutcome::Missing => Err(RvError::ErrLeaseNotFound),
            RevokeOutcome::Revoked { failed_attempts } => {
                if failed_attempts > 0 {
                    self.emit_revoked(lease_id, RevokeOrigin::Operator, failed_attempts).await;
                }
                Ok(())
            }
            RevokeOutcome::Failed { attempts, exhausted } => {
                Err(revoke_failed_error(attempts, self.revoke_policy.max_attempts, exhausted))
            }
        }
    }

    /// Revokes all lease entries with a given prefix.
    ///
    /// Every lease under the prefix is attempted. If any was busy (`409`) or
    /// its backend failed (`502`, kept as `revoke_failed`), the call reports
    /// how many after the others have been revoked.
    #[maybe_async::maybe_async]
    pub async fn revoke_prefix(&self, prefix: &str) -> Result<(), RvError> {
        let mut prefix = prefix.to_string();
        if !prefix.ends_with('/') {
            prefix += "/";
        }

        let sub = self.id_view.new_sub_view(&prefix);
        let existing = sub.get_keys().await?;
        let (mut busy, mut failed) = (0usize, 0usize);
        for suffix in existing.iter() {
            let lease_id = format!("{prefix}{suffix}");
            let Ok(guard) = self.lease_locks.try_acquire(&lease_id) else {
                busy += 1;
                continue;
            };
            match self.revoke_lease_locked(&guard, &lease_id, true, RevokeOrigin::Prefix).await? {
                RevokeOutcome::Failed { .. } => failed += 1,
                RevokeOutcome::Revoked { failed_attempts } if failed_attempts > 0 => {
                    self.emit_revoked(&lease_id, RevokeOrigin::Prefix, failed_attempts).await;
                }
                _ => {}
            }
        }

        let total = existing.len();
        if busy > 0 {
            return Err(bv_error_response_status!(
                409,
                "{} of {} leases under this prefix were being renewed or revoked by another request and were left \
                 in place ({} more failed in their backend and are kept as revoke_failed); retry",
                busy,
                total,
                failed
            ));
        }
        if failed > 0 {
            return Err(bv_error_response_status!(
                502,
                "{} of {} leases under this prefix could not be revoked by their secret backend; they are kept as \
                 revoke_failed and retried, see v2/sys/leases/revoke-failed",
                failed,
                total
            ));
        }
        Ok(())
    }

    /// Revokes all lease entries associated with a given token.
    ///
    /// Never fails on one lease's account, because the token tree's
    /// revocation stops at the first error: a failed backend revoke is kept
    /// as `revoke_failed` (and retried), and a lease another request is
    /// renewing or revoking is left to it, with a warning. Storage errors are
    /// still returned.
    #[maybe_async::maybe_async]
    pub async fn revoke_by_token(&self, te: &TokenEntry) -> Result<(), RvError> {
        let existing = self.lookup_by_token(&te.id).await?;
        for lease_id in existing.iter() {
            let Ok(guard) = self.lease_locks.try_acquire(lease_id) else {
                log::warn!(
                    "lease {lease_id} of a revoked token is being renewed or revoked by another request; left to \
                     it, and revoked at its own expiry if that was a renewal"
                );
                continue;
            };
            if let RevokeOutcome::Revoked { failed_attempts } =
                self.revoke_lease_locked(&guard, lease_id, true, RevokeOrigin::Token).await?
            {
                if failed_attempts > 0 {
                    self.emit_revoked(lease_id, RevokeOrigin::Token, failed_attempts).await;
                }
            }
        }

        Ok(())
    }

    /// Drop a `revoke_failed` lease without its backend revoking it — for an
    /// operator who has cleaned the target system up by hand. The
    /// `lease.revoke_failed_cleared` event is written first and its failure
    /// refuses the clear. Refused for a lease that is not `revoke_failed`.
    #[maybe_async::maybe_async]
    pub async fn force_clear_revoke_failed(&self, lease_id: &str, req: Option<&Request>) -> Result<(), RvError> {
        let _guard = self.lease_locks.try_acquire(lease_id)?;
        let Some(mut le) = self.load_lease_entry(lease_id).await? else {
            return Err(RvError::ErrLeaseNotFound);
        };
        let Some(failure) = le.revoke_failure.take() else {
            return Err(bv_error_response_status!(
                400,
                "this lease is not revoke_failed, so there is nothing to clear: revoke it with sys/revoke/<lease_id>"
            ));
        };

        let event = LeaseRevokeFailedClearedEvent {
            lease_id: lease_id.to_string(),
            attempts: failure.attempts,
            last_error: failure.last_error,
        };
        let core = self.core.upgrade();
        emit_lease_event(core.as_deref(), &event, req).await?;

        self.delete_lease_entry(lease_id).await?;
        if le.secret.is_some() {
            self.remove_index_by_token(&le.client_token, &le.lease_id).await?;
        }
        self.forget_revoke_failed(lease_id)?;
        le.expire_time = SystemTime::UNIX_EPOCH;
        self.register_lease_entry(Arc::new(le))
    }

    /// Every lease in `revoke_failed`, by lease id.
    #[maybe_async::maybe_async]
    pub(crate) async fn list_revoke_failed(&self) -> Result<Vec<RevokeFailedLease>, RvError> {
        let ids: Vec<String> = self.revoke_failed_ids.read()?.iter().cloned().collect();
        let mut leases = Vec::with_capacity(ids.len());
        for lease_id in ids {
            let Some(le) = self.load_lease_entry(&lease_id).await? else {
                self.forget_revoke_failed(&lease_id)?;
                continue;
            };
            let Some(failure) = le.revoke_failure else {
                self.forget_revoke_failed(&lease_id)?;
                continue;
            };
            leases.push(RevokeFailedLease {
                lease_id: le.lease_id,
                path: le.path,
                issue_time: le.issue_time,
                expire_time: le.expire_time,
                max_attempts: self.revoke_policy.max_attempts,
                exhausted: self.revoke_policy.exhausted(&failure),
                failure,
            });
        }
        Ok(leases)
    }

    fn remember_revoke_failed(&self, lease_id: &str) -> Result<(), RvError> {
        self.revoke_failed_ids.write()?.insert(lease_id.to_string());
        Ok(())
    }

    fn forget_revoke_failed(&self, lease_id: &str) -> Result<(), RvError> {
        self.revoke_failed_ids.write()?.remove(lease_id);
        Ok(())
    }

    /// `lease.revoked`, for a lease leaving `revoke_failed` or ended early by its mount.
    #[maybe_async::maybe_async]
    async fn emit_revoked(&self, lease_id: &str, origin: RevokeOrigin, failed_attempts: u32) {
        let event = LeaseRevokedEvent { lease_id: lease_id.to_string(), origin, failed_attempts };
        self.emit_best_effort(&event).await;
    }

    /// Emit a lease event for a state change no request is waiting on: the
    /// broker's failure is logged, and the lease state is not rolled back.
    #[maybe_async::maybe_async]
    async fn emit_best_effort<E: McpAuditEvent + Sync>(&self, event: &E) {
        let core = self.core.upgrade();
        if let Err(e) = emit_lease_event(core.as_deref(), event, None).await {
            log::warn!("lease audit event {} was not written to the audit broker: {e}", E::NAME);
        }
    }

    /// Get the value of lease_count.
    pub fn get_lease_count(&self) -> usize {
        self.queue.read().map(|queue| queue.len()).unwrap_or(0)
    }

    /// Revokes one lease that the expiration sweeper has already removed from
    /// the queue.
    ///
    /// The sweeper drops its queue guard before calling this, so the lease may
    /// have been renewed in the window between being drained and being revoked.
    /// Storage is the source of truth for that: the renew paths persist the new
    /// `expire_time` *before* they re-register the queue entry, so a lease whose
    /// persisted expiry has moved into the future has been renewed and must be
    /// put back on the queue instead of revoked. Revoking it here would kill a
    /// live lease.
    ///
    /// A `revoke_failed` lease is queued at its next retry instead of its
    /// expiry; this is the reaper's step for it. The guard is taken before the
    /// row is read, so a renewal cannot land between the check and the revoke.
    #[maybe_async::maybe_async]
    async fn revoke_swept_lease_entry(&self, lease_id: &str) -> Result<(), RvError> {
        let guard = self.lease_locks.try_acquire(lease_id)?;
        let Some(current) = self.load_lease_entry(lease_id).await? else {
            // Already gone from storage — nothing left to revoke.
            return Ok(());
        };

        let now = SystemTime::now();
        let origin = match current.revoke_failure.as_ref() {
            // Parked: tracked and listed, never retried by the reaper again.
            Some(failure) if self.revoke_policy.exhausted(failure) => {
                return self.register_lease_entry(Arc::new(current));
            }
            Some(failure) if failure.next_attempt_at > now => return self.register_lease_entry(Arc::new(current)),
            Some(_) => RevokeOrigin::Retry,
            None if current.expire_time > now => return self.register_lease_entry(Arc::new(current)),
            None => RevokeOrigin::Expiry,
        };

        if let RevokeOutcome::Revoked { failed_attempts } =
            self.revoke_lease_locked(&guard, lease_id, false, origin).await?
        {
            if failed_attempts > 0 {
                self.emit_revoked(lease_id, RevokeOrigin::Retry, failed_attempts).await;
            }
        }
        Ok(())
    }

    /// Starts a background task to check for and handle expired lease entries.
    pub fn start_check_expired_lease_entries(&self) {
        let queue = self.queue.clone();
        let expiration = self.self_ptr.upgrade().unwrap().clone();

        let ticker = tick(Duration::from_millis(200));
        thread::spawn(move || {
            let rt = actix_rt::Runtime::new().unwrap();
            let queue_cloned = queue;
            let expiration_cloned = expiration;
            rt.block_on(async move {
                loop {
                    select! {
                        recv(ticker) -> _ => {
                            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_millis()).unwrap_or(0);
                            let expired = {
                                let queue_locked = queue_cloned.read().unwrap();
                                queue_locked.peek().map(|(_le, Reverse(priority))| *priority < now).unwrap_or(false)
                            };

                            if !expired {
                                continue;
                            }

                            // Drain every due lease under the guard, then release it
                            // before revoking anything. Revocation re-enters this same
                            // `RwLock` (`revoke_lease_id` -> `revoke_lease_entry` -> the
                            // revoke request path), and a `std::sync` guard is neither
                            // re-entrant nor releasable by the task awaiting it — so
                            // awaiting a revoke while holding this write guard wedges the
                            // sweeper permanently, and with it every lease still queued.
                            // This runtime is current-thread, so nothing else on it
                            // progresses either.
                            let mut due: Vec<Arc<LeaseEntry>> = Vec::new();
                            {
                                let mut queue_write_locked = queue_cloned.write().unwrap();
                                loop {
                                    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_millis()).unwrap_or(0);
                                    let Some((_le, Reverse(priority))) = queue_write_locked.peek() else {
                                        break;
                                    };

                                    if *priority > now {
                                        break;
                                    }

                                    // Priority 0 marks an entry that was already revoked
                                    // and re-registered as a tombstone: drop it without
                                    // revoking it a second time.
                                    let needs_revoke = *priority != 0;

                                    let Some((le, _)) = queue_write_locked.pop() else {
                                        break;
                                    };

                                    if needs_revoke {
                                        due.push(le);
                                    }
                                }
                            }

                            for le in due {
                                #[cfg(not(feature = "sync_handler"))]
                                let result = expiration_cloned.revoke_swept_lease_entry(&le.lease_id).await;
                                #[cfg(feature = "sync_handler")]
                                let result = expiration_cloned.revoke_swept_lease_entry(&le.lease_id);

                                if let Err(e) = result {
                                    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_millis()).unwrap_or(0);
                                    log::warn!(
                                        "check_expired_lease_entries call revoke_lease_id err: {:?}, lease_id: {}, now: \
                                        {}, expire_time: {:?}",
                                        e,
                                        le.lease_id,
                                        now,
                                        le.expire_time
                                    );

                                    // The entry was popped before the guard was released,
                                    // so put it back: leaving a lease live and untracked
                                    // is worse than retrying it on a later tick, which is
                                    // what the pre-drain code did by not popping on error.
                                    if let Err(err) = expiration_cloned.register_lease_entry(le.clone()) {
                                        log::warn!(
                                            "check_expired_lease_entries failed to requeue lease after revoke err: \
                                            {:?}, lease_id: {}",
                                            err,
                                            le.lease_id
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            });
        });
    }

    /// Stops the background task that checks for expired lease entries.
    pub fn stop_check_expired_lease_entries(&self) -> Result<(), RvError> {
        let mut queue_write_locked = self.queue.write()?;
        queue_write_locked.clear();
        Ok(())
    }

    /// Registers a lease entry in the priority queue for expiration tracking.
    fn register_lease_entry(&self, le: Arc<LeaseEntry>) -> Result<(), RvError> {
        let priority = le.queue_priority(&self.revoke_policy)?;
        let mut queue_locked = self.queue.write()?;
        queue_locked.push(le, Reverse(priority));
        Ok(())
    }

    /// Loads a lease entry from storage by lease ID, updating if necessary from old to new format.
    #[maybe_async::maybe_async]
    async fn load_lease_entry(&self, lease_id: &str) -> Result<Option<LeaseEntry>, RvError> {
        let raw = self.id_view.get(lease_id).await?;
        if raw.is_none() {
            return Ok(None);
        }

        if let Ok(mut le) = serde_json::from_slice::<LeaseEntry>(raw.clone().unwrap().value.as_slice()) {
            // Version 0 needs no transformation: its absent fields default to
            // "no max_ttl", "not revoke_failed". The next write stores the
            // current version (read-old, write-new).
            le.version = LEASE_ENTRY_VERSION;
            return Ok(Some(le));
        }

        // Because the data field type of LeaseEntry has changed, it is necessary to convert OldLeaseEntry to LeaseEntry
        // and update the data in its storage.
        if let Ok(ole) = serde_json::from_slice::<OldLeaseEntry>(raw.unwrap().value.as_slice()) {
            let le = LeaseEntry {
                lease_id: ole.lease_id.clone(),
                client_token: ole.client_token.clone(),
                path: ole.path.clone(),
                data: ole.data.clone().map(|serde_map| serde_map.into_iter().collect()).unwrap_or(Map::new()),
                secret: ole.secret.clone(),
                auth: ole.auth.clone(),
                issue_time: ole.issue_time,
                expire_time: ole.expire_time,
                ..Default::default()
            };
            self.persist_lease_entry(&le).await?;
            return Ok(Some(le));
        }

        Ok(None)
    }

    /// Persists a lease entry to storage.
    #[maybe_async::maybe_async]
    async fn persist_lease_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        // Read-old, write-new: a host-managed row written before the
        // credential was left out loses it on its next write.
        let value = match le.secret.as_ref() {
            Some(secret) if is_host_managed_secret(secret) => {
                let row = LeaseEntry { data: lease_row_data(secret, Some(&le.data)), ..le.clone() };
                serde_json::to_string(&row)?
            }
            _ => serde_json::to_string(&le)?,
        };

        let entry = StorageEntry { key: le.lease_id.clone(), value: value.as_bytes().to_vec() };

        self.id_view.put(&entry).await
    }

    /// Deletes a lease entry from storage.
    #[maybe_async::maybe_async]
    async fn delete_lease_entry(&self, lease_id: &str) -> Result<(), RvError> {
        self.id_view.delete(lease_id).await
    }

    /// Creates an index in the token view using the provided token and lease ID.
    #[maybe_async::maybe_async]
    async fn create_index_by_token(&self, token: &str, lease_id: &str) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));
        let entry = StorageEntry { key, value: lease_id.as_bytes().to_owned() };
        self.token_view.put(&entry).await
    }

    /// Removes an index from the token view based on the provided token and lease ID.
    #[maybe_async::maybe_async]
    async fn remove_index_by_token(&self, token: &str, lease_id: &str) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));
        self.token_view.delete(&key).await
    }

    /// Retrieves an index from the token view based on the provided token and lease ID.
    #[allow(dead_code)]
    #[maybe_async::maybe_async]
    async fn index_by_token(&self, token: &str, lease_id: &str) -> Result<Option<StorageEntry>, RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));
        self.token_view.get(&key).await
    }

    /// Looks up lease entries associated with a specific token.
    #[maybe_async::maybe_async]
    async fn lookup_by_token(&self, token: &str) -> Result<Vec<String>, RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let prefix = format!("{}/", token_store.salt_id(token));
        let sub_keys = self.token_view.list(&prefix).await?;

        let mut ret: Vec<String> = Vec::new();

        for sub in sub_keys.iter() {
            let key = format!("{prefix}{sub}");
            let raw = self.token_view.get(&key).await?;
            if raw.is_none() {
                continue;
            }

            let lease_id = String::from_utf8_lossy(&raw.unwrap().value).to_string();
            ret.push(lease_id);
        }

        Ok(ret)
    }

    /// Revokes a lease entry and handles secret or token revocation.
    ///
    /// A secret backend's error is returned, not swallowed: the caller keeps
    /// the row as `revoke_failed` rather than orphan the credential.
    #[maybe_async::maybe_async]
    async fn revoke_lease_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;

        if le.auth.is_some() {
            return token_store.revoke_tree(&le.auth.as_ref().unwrap().client_token).await;
        }

        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            secret = Some(le.secret.as_ref().unwrap().clone());
        }

        let mut data: Option<Map<String, Value>> = None;
        if !le.data.is_empty() {
            data = Some(le.data.clone());
        }

        let mut req = Request::new_revoke_request(&le.path, secret, data);
        self.router.handle_request(&mut req).await.map(|_| ())
    }

    /// Renews a secret lease entry with a specified increment duration.
    #[maybe_async::maybe_async]
    async fn renew_secret_lease_entry(
        &self,
        le: &LeaseEntry,
        increment: Duration,
    ) -> Result<Option<Response>, RvError> {
        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            let mut s = le.secret.as_ref().unwrap().clone();
            s.lease_id = "".to_string();
            s.increment = increment;
            s.issue_time = Some(le.issue_time);
            secret = Some(s);
        }

        let mut data: Option<Map<String, Value>> = None;
        if !le.data.is_empty() {
            data = Some(le.data.clone());
        }

        let mut req = Request::new_renew_request(&le.path, secret, data);
        let ret = self.router.handle_request(&mut req).await;
        if ret.is_err() {
            log::error!("failed to renew entry: {}", ret.as_ref().unwrap_err());
        }

        ret
    }

    /// Renews an authentication lease entry with a specified increment duration.
    #[maybe_async::maybe_async]
    async fn renew_auth_lease_entry(
        &self,
        _req: &mut Request,
        le: &LeaseEntry,
        increment: Duration,
    ) -> Result<Option<Response>, RvError> {
        let mut auth: Option<Auth> = None;
        if le.auth.is_some() {
            let mut au = le.auth.as_ref().unwrap().clone();
            if le.path.starts_with("auth/token/") {
                au.client_token.clone_from(&le.client_token);
            } else {
                au.client_token = "".to_string();
            }
            au.increment = increment;
            au.issue_time = Some(le.issue_time);
            auth = Some(au);
        }

        let mut req = Request::new_renew_auth_request(&le.path, auth, None);
        let ret = self.router.handle_request(&mut req).await;
        if ret.is_err() {
            log::error!("failed to renew_auth entry: {}", ret.as_ref().unwrap_err());
        }

        ret
    }
}

#[maybe_async::maybe_async]
impl OwnedLeaseRevoker for ExpirationManager {
    async fn revoke_owned_lease(&self, owner_mount: &str, lease_id: &str) -> Result<LeaseRevocation, RvError> {
        if lease_id.is_empty() || lease_id.starts_with('/') || lease_id.contains("..") {
            return Err(bv_error_response_status!(400, "invalid lease_id: must be a relative lease path without '..'"));
        }
        let mut owner = owner_mount.to_string();
        if !owner.ends_with('/') {
            owner.push('/');
        }
        if owner == "/" || owner.contains("..") {
            return Err(RvError::ErrPermissionDenied);
        }

        let guard = self.lease_locks.try_acquire(lease_id)?;
        let Some(le) = self.load_lease_entry(lease_id).await? else {
            return Err(RvError::ErrLeaseNotFound);
        };
        // A token's lease is the token store's to end, and a lease is the
        // mount's only if its path routes to that very mount, not a parent.
        if le.auth.is_some() || self.router.matching_mount(&le.path)? != owner {
            return Err(RvError::ErrPermissionDenied);
        }

        match self.revoke_lease_locked(&guard, lease_id, true, RevokeOrigin::Owner).await? {
            RevokeOutcome::Revoked { failed_attempts } => {
                self.emit_revoked(lease_id, RevokeOrigin::Owner, failed_attempts).await;
                Ok(LeaseRevocation::Revoked)
            }
            RevokeOutcome::Failed { attempts, .. } => Ok(LeaseRevocation::Deferred { attempts }),
            // The guard is held from the load above, so this means storage
            // lost the row underneath us: say so rather than claim a revoke.
            RevokeOutcome::Missing => Err(RvError::ErrLeaseNotFound),
        }
    }

    async fn check_lease_quota(&self, namespace_path: &str) -> Result<(), RvError> {
        self.check_namespace_lease_quota(namespace_path).await
    }
}

/// A renewal refused because nothing renews this kind of lease here.
fn renew_unsupported(why: &str) -> RvError {
    bv_error_response_status!(501, "lease not renewed: {}; nothing was changed", why)
}

fn past_max_ttl() -> RvError {
    bv_error_response_status!(400, "lease not renewed: it has reached its max_ttl and cannot be extended further")
}

/// An operator's revoke whose backend failed; the lease was kept.
fn revoke_failed_error(attempts: u32, max_attempts: u32, exhausted: bool) -> RvError {
    let next = if exhausted { "is no longer retried: clear it once the target is cleaned up" } else { "is retried" };
    bv_error_response_status!(
        502,
        "the secret backend failed to revoke this lease (attempt {} of {}); the lease is kept as revoke_failed and {}, \
         see v2/sys/leases/revoke-failed",
        attempts,
        max_attempts,
        next
    )
}

// The T62 lease lifecycle: revoke_failed, the reaper, renew and its clamp,
// the per-lease guard, owner revocation and the old row format. A child
// module, so it reaches the private row type and storage helpers.
#[cfg(all(test, not(feature = "sync_handler")))]
#[path = "expiration_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
mod mod_expiration_tests {
    use std::{sync::Mutex, thread::sleep};

    use serde_json::json;

    use super::*;
    use crate::kernel_api::VaultCtx;
    use crate::{
        context::Context,
        logical::{Backend, Field, FieldType, Lease, LogicalBackend, Operation, Path, PathOperation, Secret},
        mount::{MountEntry, MOUNT_TABLE_TYPE},
        new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
        new_path_internal, new_secret, new_secret_internal,
        test_utils::{new_unseal_test_bastion_vault, NoopBackend},
    };

    macro_rules! mock_expiration_manager {
        () => {{
            let name = format!("{}_{}", file!(), line!()).replace("/", "_").replace("\\", "_").replace(".", "_");
            println!("init_test_bastion_vault, name: {}", name);
            #[cfg(not(feature = "sync_handler"))]
            let (_, core, _) = new_unseal_test_bastion_vault(&name).await;
            #[cfg(feature = "sync_handler")]
            let (_, core, _) = new_unseal_test_bastion_vault(&name);

            let expiration = ExpirationManager::new(&core).unwrap().wrap();
            #[cfg(not(feature = "sync_handler"))]
            let token_store = TokenStore::new(&core, expiration.clone()).await.unwrap().wrap();
            #[cfg(feature = "sync_handler")]
            let token_store = TokenStore::new(&core, expiration.clone()).unwrap().wrap();

            expiration.set_token_store(&token_store).unwrap();
            #[cfg(not(feature = "sync_handler"))]
            expiration.restore().await.unwrap();
            #[cfg(feature = "sync_handler")]
            expiration.restore().unwrap();
            expiration.start_check_expired_lease_entries();
            (core, expiration, token_store)
        }};
    }

    #[maybe_async::maybe_async]
    pub async fn renew_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    #[maybe_async::maybe_async]
    pub async fn revoke_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    #[actix_rt::test]
    async fn test_secret_expiration() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let new_now: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let new_now_cloned = new_now.clone();
        let renew_flag = Arc::new(Mutex::new(false));
        let renew_flag_cloned = renew_flag.clone();

        let secret = Arc::new(Secret {
            secret_type: "test".into(),
            default_duration: Duration::from_secs(5),
            renew_handler: Some(Arc::new(
                #[cfg(not(feature = "sync_handler"))]
                move |_backend: &dyn Backend, req: &mut Request| {
                    let renew_flag_cloned = renew_flag_cloned.clone();
                    Box::pin(async move {
                        //let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                        let mut renew_flag_cloned_locked = renew_flag_cloned.lock().unwrap();
                        *renew_flag_cloned_locked = true;

                        let mut resp = Response::default();
                        resp.data = req.data.clone();
                        resp.secret = req.secret.clone();
                        Ok(Some(resp))
                    })
                },
                #[cfg(feature = "sync_handler")]
                move |_backend: &dyn Backend, req: &mut Request| -> Result<Option<Response>, RvError> {
                    //let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                    let mut renew_flag_cloned_locked = renew_flag_cloned.lock().unwrap();
                    *renew_flag_cloned_locked = true;

                    let mut resp = Response::default();
                    resp.data = req.data.clone();
                    resp.secret = req.secret.clone();
                    Ok(Some(resp))
                },
            )),
            revoke_handler: Some(Arc::new(
                #[cfg(not(feature = "sync_handler"))]
                move |_backend: &dyn Backend, _req: &mut Request| {
                    let new_now_cloned = new_now_cloned.clone();
                    Box::pin(async move {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                        let mut new_now_cloned_locked = new_now_cloned.lock().unwrap();
                        *new_now_cloned_locked = now;
                        Ok(None)
                    })
                },
                #[cfg(feature = "sync_handler")]
                move |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                    let mut new_now_cloned_locked = new_now_cloned.lock().unwrap();
                    *new_now_cloned_locked = now;
                    Ok(None)
                },
            )),
        });
        let secret_cloned = secret.clone();

        #[cfg(not(feature = "sync_handler"))]
        let new_backend_fn = move || -> LogicalBackend {
            let mut mock_logical_backend = new_logical_backend!({
                paths: [
                    {
                        pattern: "/(?P<bar>.+?)",
                        fields: {
                            "mytype": {
                                field_type: FieldType::Int,
                                description: "haha"
                            },
                            "mypath": {
                                field_type: FieldType::Str,
                                description: "hehe"
                            },
                            "mypassword": {
                                field_type: FieldType::SecretStr,
                                description: "password"
                            }
                        },
                        operations: [
                            {op: Operation::Read, raw_handler: async move |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError>
                                {
                                    Ok(None)
                                }
                            },
                            {op: Operation::Write, raw_handler: async move |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                    Ok(Some(Response::new()))
                                }
                            },
                            {op: Operation::Delete, raw_handler: async move |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                    Err(RvError::ErrUnknown)
                                }
                            }
                        ]
                    }
                ],
                secrets: [{
                    secret_type: "kv",
                    default_duration: 60,
                    renew_handler: renew_noop_handler,
                    revoke_handler: revoke_noop_handler,
                }],
                unauth_paths: ["/login"],
                root_paths: ["/"],
                help: "help content",
            });

            mock_logical_backend.secrets.push(secret.clone());

            mock_logical_backend
        };
        #[cfg(feature = "sync_handler")]
        let new_backend_fn = move || -> LogicalBackend {
            let mut mock_logical_backend = new_logical_backend!({
                paths: [
                    {
                        pattern: "/(?P<bar>.+?)",
                        fields: {
                            "mytype": {
                                field_type: FieldType::Int,
                                description: "haha"
                            },
                            "mypath": {
                                field_type: FieldType::Str,
                                description: "hehe"
                            },
                            "mypassword": {
                                field_type: FieldType::SecretStr,
                                description: "password"
                            }
                        },
                        operations: [
                            {op: Operation::Read, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError>
                                {
                                    Ok(None)
                                }
                            },
                            {op: Operation::Write, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                    Ok(Some(Response::new()))
                                }
                            },
                            {op: Operation::Delete, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                    Err(RvError::ErrUnknown)
                                }
                            }
                        ]
                    }
                ],
                secrets: [{
                    secret_type: "kv",
                    default_duration: 60,
                    renew_handler: renew_noop_handler,
                    revoke_handler: revoke_noop_handler,
                }],
                unauth_paths: ["/login"],
                root_paths: ["/"],
                help: "help content",
            });

            mock_logical_backend.secrets.push(secret.clone());

            mock_logical_backend
        };

        core.add_logical_backend(
            "test",
            Arc::new(move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
                let mut test_backend = new_backend_fn();
                test_backend.init()?;
                Ok(Arc::new(test_backend))
            }),
        )
        .unwrap();

        let me = MountEntry::new(MOUNT_TABLE_TYPE, "mytest/", "test", "test description");
        #[cfg(not(feature = "sync_handler"))]
        core.mount(&me).await.unwrap();
        #[cfg(feature = "sync_handler")]
        core.mount(&me).unwrap();

        let mut request = Request::new("mytest/tt");
        request.client_token = "mytest".into();

        let mut response = secret_cloned.response(json!({"key": "test"}).as_object().cloned(), None);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);

        // register secret
        #[cfg(not(feature = "sync_handler"))]
        let result = expiration.register_secret(&mut request, &mut response).await;
        #[cfg(feature = "sync_handler")]
        let result = expiration.register_secret(&mut request, &mut response);
        assert!(result.is_ok());

        println!("sleep 10s");
        sleep(Duration::from_secs(10));

        {
            // Check if the `revoke_handler` callback is called when `secret` expires. In `revoke_handler`,
            // we set external variable `new_now` to the current time. `new_now` minus the current time gives the `secret`'s TTL.
            let new_now_locked = new_now.lock().unwrap();
            assert_ne!(*new_now_locked, 0);
            assert!(*new_now_locked - now >= 5);
            assert!(*new_now_locked - now <= 6);
        }

        // register secret again
        //let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
        #[cfg(not(feature = "sync_handler"))]
        let result = expiration.register_secret(&mut request, &mut response).await;
        #[cfg(feature = "sync_handler")]
        let result = expiration.register_secret(&mut request, &mut response);
        assert!(result.is_ok());

        // test renew
        let lease_id = response.secret.as_ref().unwrap().lease_id.clone();
        #[cfg(not(feature = "sync_handler"))]
        let result = expiration.renew(&lease_id, Duration::from_secs(3)).await;
        #[cfg(feature = "sync_handler")]
        let result = expiration.renew(&lease_id, Duration::from_secs(3));
        assert!(result.is_ok());
        let renew_flag_locked = renew_flag.lock().unwrap();
        assert!(*renew_flag_locked);

        println!("sleep 10s");
        sleep(Duration::from_secs(10));
        {
            // TODO: The secret's initial TTL is 5s. After a 3s increase during renewal, the TTL should be 8s.
            let new_now_locked = new_now.lock().unwrap();
            assert_ne!(*new_now_locked, 0);
        }
    }

    #[test]
    fn test_auth_expiration() {
        // TODO
        println!("TODO");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_persist_and_load_lease_entry() {
        let (_core, expiration, _token_store) = mock_expiration_manager!();

        let le = LeaseEntry {
            lease_id: generate_uuid(),
            client_token: generate_uuid(),
            path: "test/kk".into(),
            expire_time: SystemTime::now() + Duration::from_secs(3600), // 1 hour from now
            ..Default::default()
        };

        expiration.persist_lease_entry(&le).await.unwrap();
        let loaded = expiration.load_lease_entry(&le.lease_id).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded, Some(le));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_total_lease_count() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        // The leases below must revoke for the counts to drop: since T62 a
        // lease whose path no mount serves is kept as revoke_failed, not
        // deleted, so give both prefixes a backend.
        for prefix in ["foo/", "new/"] {
            let view = BarrierView::new(core.barrier().clone(), "logical/");
            let entry = MountEntry { path: prefix.into(), logical_type: "noop".into(), ..Default::default() };
            let noop = Arc::new(NoopBackend::default());
            expiration.router.mount(noop, prefix, Arc::new(RwLock::new(entry)), view).unwrap();
        }

        let n: usize = 100;
        for i in 0..n {
            let le = LeaseEntry {
                lease_id: format!("lease-{}", i),
                client_token: format!("client_token-{}", i),
                path: format!("foo/bar/{}", i),
                expire_time: SystemTime::now() + Duration::from_secs(3600), // 1 hour from now
                ..Default::default()
            };

            let result = expiration.persist_lease_entry(&le).await;
            assert!(result.is_ok());
            let result = expiration.register_lease_entry(Arc::new(le));
            assert!(result.is_ok());
        }

        let lease_count = expiration.get_lease_count();
        assert_eq!(n, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), n);

        let m: usize = 20;
        for i in 0..m {
            let le = LeaseEntry {
                lease_id: format!("new-lease-{}", i),
                client_token: format!("new-client_token-{}", i),
                path: format!("new/foo/bar/{}", i),
                expire_time: SystemTime::now() + Duration::from_secs(5), // 5s from now
                ..Default::default()
            };

            let result = expiration.persist_lease_entry(&le).await;
            assert!(result.is_ok());
            assert!(expiration.register_lease_entry(Arc::new(le)).is_ok());
        }

        let lease_count = expiration.get_lease_count();
        assert_eq!(m + n, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), m + n);

        println!("sleep 7s");
        sleep(Duration::from_secs(7));

        let lease_count = expiration.get_lease_count();
        assert_eq!(n, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), n);

        let m: usize = 30;
        for i in 0..m {
            let le = LeaseEntry {
                lease_id: format!("lease-{}", i),
                client_token: format!("client_token-{}", i),
                path: format!("foo/bar/{}", i),
                expire_time: SystemTime::now() + Duration::from_secs(5), // Marked as expiring in 5 seconds.
                ..Default::default()
            };

            let result = expiration.persist_lease_entry(&le).await;
            assert!(result.is_ok());
            assert!(expiration.register_lease_entry(Arc::new(le)).is_ok());
        }

        println!("sleep 6s");
        sleep(Duration::from_secs(6));

        let lease_count = expiration.get_lease_count();
        assert_eq!(n - m, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), n - m);

        let k: usize = 30;
        for i in 50..(50 + k) {
            let lease_id = format!("lease-{}", i);

            let result = expiration.revoke_lease_id(&lease_id, true).await;
            assert!(result.is_ok());
        }

        println!("sleep 1s");
        sleep(Duration::from_secs(1));

        let lease_count = expiration.get_lease_count();
        assert_eq!(n - m - k, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), n - m - k);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_register_and_restore_benchmark() {
        let (_core, expiration, _token_store) = mock_expiration_manager!();

        let n = 10000;
        for i in 0..n {
            let mut secret = SecretData::default();
            // The TTL must outlive the whole registration loop, or leases
            // expire before the count below. Under a full-suite run on
            // Windows the loop has been measured at ~960s, well past the
            // former 400s, leaving 4399 of 10000 leases.
            secret.ttl = Duration::from_secs(24 * 60 * 60);
            let mut request = Request::new(format!("secret/{}", i));
            request.client_token = "root".into();

            let mut response = Response {
                secret: Some(secret),
                data: json!({"access_key": "xyz", "secret_key": "abc"}).as_object().cloned(),
                ..Default::default()
            };

            // register secret
            let result = expiration.register_secret(&mut request, &mut response).await;
            assert!(result.is_ok());
        }

        println!("sleep 5s");
        sleep(Duration::from_secs(5));

        assert!(expiration.stop_check_expired_lease_entries().is_ok());

        let result = expiration.restore().await;
        assert!(result.is_ok());

        let lease_count = expiration.get_lease_count();
        assert_eq!(n, lease_count);

        let keys = expiration.id_view.get_keys().await;
        assert!(keys.is_ok());
        let lease_id_vec = keys.unwrap();
        assert_eq!(lease_id_vec.len(), n);
        let mut lease_id_prefix_vec: Vec<String> = Vec::with_capacity(n);
        for i in 0..lease_id_vec.len() {
            lease_id_prefix_vec.push(format!("secret/{}/", i));
        }
        lease_id_prefix_vec.sort();
        for i in 0..lease_id_vec.len() {
            assert!(lease_id_vec[i].starts_with(&lease_id_prefix_vec[i]));
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_register_auth() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let mut auth = Auth { client_token: root.id.clone(), ..Default::default() };
        auth.ttl = Duration::from_secs(60 * 60);

        let te = TokenEntry { path: "auth/github/login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());

        let te = TokenEntry { path: "auth/github/../login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_register_auth_no_lease() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let mut auth = Auth { client_token: root.id.clone(), ..Default::default() };

        let mut te = TokenEntry {
            id: root.id.clone(),
            path: "auth/github/login".into(),
            policies: vec!["root".into()],
            ..Default::default()
        };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());

        let mut request = Request::new("");

        // Should not be able to renew, no expiration
        let resp = expiration.renew_token(&mut request, &te, Duration::ZERO).await;
        assert_eq!(resp.unwrap_err(), RvError::ErrLeaseNotRenewable);

        // Wait and check token is not invalidated
        println!("sleep 2s");
        sleep(Duration::from_secs(2));

        let ret = token_store.lookup(&root.id).await;
        assert!(ret.is_ok());
        assert!(ret.unwrap().is_some());

        te.policies[0] = "default".into();
        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend::default());
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(60 * 60), ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        let result = expiration.revoke_lease_id(&id, true).await;
        assert!(result.is_ok());

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Revoke);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke_on_expire() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend::default());
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(1), ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());

        sleep(Duration::from_millis(1500));

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Revoke);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke_prefix() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend::default());
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let paths = ["prod/aws/foo", "prod/aws/sub/bar", "prod/aws/zip"];

        for path in paths.iter() {
            let mut req = Request::new(*path);
            req.client_token = "foobar".into();
            let mut resp = Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(1), ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "xyz",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            };

            let ret = expiration.register_secret(&mut req, &mut resp).await;
            assert!(ret.is_ok());
        }

        let result = expiration.revoke_prefix("prod/aws/").await;
        assert!(result.is_ok());

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 3);

        for r in req.iter() {
            assert_eq!(r.operation, Operation::Revoke);
        }

        let noop_paths = noop.paths.read().unwrap();
        let mut paths = noop_paths.clone();
        paths.sort();
        let mut expect = vec!["foo".to_string(), "sub/bar".to_string(), "zip".to_string()];
        expect.sort();
        assert_eq!(paths, expect);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke_by_token() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend::default());
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let paths = ["prod/aws/foo", "prod/aws/sub/bar", "prod/aws/zip"];

        for path in paths.iter() {
            let mut req = Request::new(*path);
            req.client_token = "foobar".into();
            let mut resp = Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(1), ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "xyz",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            };

            let ret = expiration.register_secret(&mut req, &mut resp).await;
            assert!(ret.is_ok());
        }

        let te = TokenEntry { id: "foobar".into(), ..Default::default() };

        let result = expiration.revoke_by_token(&te).await;
        assert!(result.is_ok());

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 3);

        for r in req.iter() {
            assert_eq!(r.operation, Operation::Revoke);
        }

        let noop_paths = noop.paths.read().unwrap();
        let mut paths = noop_paths.clone();
        paths.sort();
        let mut expect = vec!["foo".to_string(), "sub/bar".to_string(), "zip".to_string()];
        expect.sort();
        assert_eq!(paths, expect);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_token() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let mut auth = Auth {
            client_token: root.id.clone(),
            lease: Lease { ttl: Duration::from_secs(60 * 60), renewable: true, ..Default::default() },
            ..Default::default()
        };

        let te = TokenEntry { id: root.id, path: "auth/token/login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());

        let mut req = Request::default();

        let resp = expiration.renew_token(&mut req, &te, Duration::from_secs(0)).await.unwrap();
        assert!(resp.is_some());
        let resp_auth = resp.unwrap().auth;
        assert!(resp_auth.is_some());
        assert_eq!(auth.client_token, resp_auth.unwrap().client_token);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_token_period() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let mut root = TokenEntry {
            policies: vec!["root".to_string()],
            path: "auth/token/root".into(),
            display_name: "root".into(),
            creation_time: SystemTime::now(),
            period: Duration::from_secs(60),
            ..Default::default()
        };

        let result = token_store.create(&mut root).await;
        assert!(result.is_ok());

        let mut auth = Auth {
            client_token: root.id.clone(),
            lease: Lease { ttl: Duration::from_secs(60 * 60), renewable: true, ..Default::default() },
            period: Duration::from_secs(60),
            ..Default::default()
        };

        let te = TokenEntry { id: root.id, path: "auth/token/login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());
        assert_eq!(expiration.get_lease_count(), 1);

        let mut req = Request::default();

        let resp = expiration.renew_token(&mut req, &te, Duration::from_secs(0)).await.unwrap();
        assert!(resp.is_some());
        let resp_auth = resp.unwrap().auth;
        assert!(resp_auth.is_some());
        let auth = resp_auth.unwrap();
        assert_eq!(auth.client_token, auth.client_token);
        assert!(auth.ttl <= Duration::from_secs(60));

        assert_eq!(expiration.get_lease_count(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_token_period_backend() {
        let (core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                auth: Some(Auth {
                    lease: Lease { ttl: Duration::from_secs(10), renewable: true, ..Default::default() },
                    period: Duration::from_secs(5),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            default_lease_ttl: Duration::from_secs(5),
            max_lease_ttl: Duration::from_secs(5),
            ..Default::default()
        });
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "auth/foo/",
                Arc::new(RwLock::new(MountEntry {
                    path: "auth/foo/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut auth = Auth {
            client_token: root.id.clone(),
            lease: Lease { ttl: Duration::from_secs(10), renewable: true, ..Default::default() },
            period: Duration::from_secs(5),
            ..Default::default()
        };

        let te = TokenEntry { id: root.id, path: "auth/foo/login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());

        sleep(Duration::from_secs(3));

        let mut req = Request::default();

        let resp = expiration.renew_token(&mut req, &te, Duration::from_secs(0)).await.unwrap();
        assert!(resp.is_some());
        let resp_auth = resp.unwrap().auth;
        assert!(resp_auth.is_some());
        let auth = resp_auth.unwrap();
        assert!(auth.ttl != Duration::ZERO);
        assert!(auth.ttl <= Duration::from_secs(5));

        sleep(Duration::from_secs(3));

        let mut req = Request::default();

        let resp = expiration.renew_token(&mut req, &te, Duration::from_secs(0)).await.unwrap();
        assert!(resp.is_some());
        let resp_auth = resp.unwrap().auth;
        assert!(resp_auth.is_some());
        let auth = resp_auth.unwrap();
        assert!(auth.ttl >= Duration::from_secs(4));
        assert!(auth.ttl <= Duration::from_secs(5));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_token_not_renewable() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let mut auth = Auth {
            client_token: root.id.clone(),
            lease: Lease { ttl: Duration::from_secs(60 * 60), renewable: false, ..Default::default() },
            ..Default::default()
        };

        let te = TokenEntry { id: root.id.clone(), path: "auth/foo/login".into(), ..Default::default() };

        let result = expiration.register_auth(&te, &mut auth).await;
        assert!(result.is_ok());

        let mut req = Request::default();

        let te = TokenEntry { id: root.id, path: "auth/foo/login".into(), ..Default::default() };

        let resp = expiration.renew_token(&mut req, &te, Duration::from_secs(0)).await;
        assert!(resp.is_err());
        assert_eq!(resp.unwrap_err(), RvError::ErrLeaseNotRenewable);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(10), ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "123",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(1), renewable: true, ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        let renewal = expiration.renew(&id, Duration::ZERO).await.unwrap();
        assert_eq!((renewal.lease_id.as_str(), renewal.ttl), (id.as_str(), Duration::from_secs(10)));
        let renewed = expiration.load_lease_entry(&id).await.unwrap().unwrap();
        assert_eq!(Some(renewed.data), noop.response.as_ref().unwrap().data, "the backend's renewed data is kept");

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Renew);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_not_renewable() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend::default());

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(1), renewable: false, ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        let resp = expiration.renew(&id, Duration::ZERO).await;
        assert!(resp.is_err());
        assert_eq!(resp.unwrap_err(), RvError::ErrLeaseNotRenewable);

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_revoke_on_expire() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(1), ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "123",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(1), renewable: true, ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        let resp = expiration.renew(&id, Duration::ZERO).await;
        assert!(resp.is_ok());

        sleep(Duration::from_millis(1500));

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 2);
        assert_eq!(req[1].operation, Operation::Revoke);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_final_second() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(2), max_ttl: Duration::from_secs(2), ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "123",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(2), renewable: true, ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        sleep(Duration::from_millis(500));

        // A secret lease renewed in its final second: the backend's 2 s
        // max_ttl clamps it, and it stays tracked.
        let resp = expiration.renew(&id, Duration::ZERO).await;
        assert!(resp.as_ref().is_ok_and(|r| r.ttl <= Duration::from_secs(2)), "{resp:?}");

        assert_eq!(expiration.get_lease_count(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_final_second_lease() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend::default());

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "prod/aws/",
                Arc::new(RwLock::new(MountEntry {
                    path: "prod/aws/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut req = Request::new("prod/aws/foo");
        req.client_token = "foobar".into();
        let mut resp = Response {
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(2), renewable: true, ..Default::default() },
                ..Default::default()
            }),
            data: json!({
                "access_key": "xyz",
                "secret_key": "abcd",
            })
            .as_object()
            .cloned(),
            ..Default::default()
        };

        let ret = expiration.register_secret(&mut req, &mut resp).await;
        assert!(ret.is_ok());
        let id = ret.unwrap();

        let mut le = expiration.load_lease_entry(&id).await.unwrap().unwrap();
        le.auth = Some(Auth { lease: Lease { renewable: true, ..Default::default() }, ..Default::default() });

        let result = expiration.persist_lease_entry(&le).await;
        assert!(result.is_ok());

        sleep(Duration::from_secs(1));

        // A lease carrying an auth block is a token's lease: `renew` refuses
        // it (T62) instead of reporting a renewal, and it stays tracked.
        let resp = expiration.renew(&id, Duration::ZERO).await;
        assert!(matches!(resp, Err(RvError::ErrResponseStatus(501, _))), "{resp:?}");
        assert!(noop.requests.read().unwrap().iter().all(|r| r.operation != Operation::Renew), "backend not asked");

        assert_eq!(expiration.get_lease_count(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke_entry() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let noop = Arc::new(NoopBackend::default());
        let me_uuid = generate_uuid();

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "foo/bar/",
                Arc::new(RwLock::new(MountEntry {
                    path: "foo/bar/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let le = LeaseEntry {
            lease_id: "foo/bar/1234".into(),
            path: "foo/bar/".into(),
            issue_time: SystemTime::now(),
            expire_time: SystemTime::now(),
            data: json!({
                "testing": true
            })
            .as_object()
            .unwrap()
            .clone(),
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(60), ..Default::default() },
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = expiration.revoke_lease_entry(&le).await;
        assert!(result.is_ok());

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Revoke);
        assert_eq!(req[0].data, Some(le.data));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_revoke_entry_token() {
        let (_core, expiration, token_store) = mock_expiration_manager!();
        let root = token_store.root_token().await.unwrap();

        let le = LeaseEntry {
            client_token: root.id.clone(),
            lease_id: "foo/bar/1234".into(),
            path: "foo/bar/".into(),
            issue_time: SystemTime::now(),
            expire_time: SystemTime::now() + Duration::from_secs(60),
            auth: Some(Auth {
                client_token: root.id.clone(),
                lease: Lease { ttl: Duration::from_secs(60), ..Default::default() },
                ..Default::default()
            }),
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(60), ..Default::default() },
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = expiration.persist_lease_entry(&le).await;
        assert!(result.is_ok());

        let result = expiration.create_index_by_token(&le.client_token, &le.lease_id).await;
        assert!(result.is_ok());

        let index_entry = expiration.index_by_token(&le.client_token, &le.lease_id).await.unwrap();
        assert!(index_entry.is_some());

        let result = expiration.revoke_lease_entry(&le).await;
        assert!(result.is_ok());

        let index_entry = expiration.index_by_token(&le.client_token, &le.lease_id).await.unwrap();
        assert!(index_entry.is_none());

        let te = token_store.lookup(&le.client_token).await;
        assert!(te.is_ok());
        assert!(te.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_entry() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "logical/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                secret: Some(SecretData {
                    lease: Lease { ttl: Duration::from_secs(60 * 60), renewable: true, ..Default::default() },
                    ..Default::default()
                }),
                data: json!({
                    "access_key": "123",
                    "secret_key": "abcd",
                })
                .as_object()
                .cloned(),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "foo/bar/",
                Arc::new(RwLock::new(MountEntry {
                    path: "foo/bar/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let le = LeaseEntry {
            lease_id: "foo/bar/1234".into(),
            path: "foo/bar/".into(),
            issue_time: SystemTime::now(),
            expire_time: SystemTime::now(),
            data: json!({
                "testing": true
            })
            .as_object()
            .unwrap()
            .clone(),
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(60), ..Default::default() },
                ..Default::default()
            }),
            ..Default::default()
        };

        let resp = expiration.renew_secret_lease_entry(&le, Duration::ZERO).await;
        assert!(resp.is_ok());

        let resp = resp.unwrap();
        assert!(resp.is_some());

        let mut resp = resp.unwrap();
        let mut secret = resp.secret.clone().unwrap();
        secret.lease_id.clear();
        resp.secret = Some(secret);
        assert_eq!(Some(resp), noop.response);

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Renew);
        assert_eq!(req[0].data, Some(le.data));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_renew_auth_entry() {
        let (core, expiration, _token_store) = mock_expiration_manager!();
        let view = BarrierView::new(core.barrier().clone(), "auth/");
        let me_uuid = generate_uuid();
        let noop = Arc::new(NoopBackend {
            response: Some(Response {
                auth: Some(Auth {
                    lease: Lease { ttl: Duration::from_secs(60 * 60), renewable: true, ..Default::default() },
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert!(expiration
            .router
            .mount(
                noop.clone(),
                "auth/foo/",
                Arc::new(RwLock::new(MountEntry {
                    path: "auth/foo/".into(),
                    logical_type: "noop".into(),
                    uuid: me_uuid.clone(),
                    ..Default::default()
                })),
                view
            )
            .is_ok());

        let mut le_auth_internal_data: HashMap<String, String> = HashMap::new();
        le_auth_internal_data.insert("MySecret".to_string(), "secret".to_string());
        let le = LeaseEntry {
            lease_id: "auth/foo/1234".into(),
            path: "auth/foo/login".into(),
            auth: Some(Auth {
                lease: Lease { ttl: Duration::from_secs(60), renewable: true, ..Default::default() },
                internal_data: le_auth_internal_data.clone(),
                ..Default::default()
            }),
            issue_time: SystemTime::now(),
            expire_time: SystemTime::now() + Duration::from_secs(60),
            ..Default::default()
        };

        let mut req = Request::new("auth/foo/login");
        let resp = expiration.renew_auth_lease_entry(&mut req, &le, Duration::ZERO).await;
        assert!(resp.is_ok());

        let resp = resp.unwrap();
        assert!(resp.is_some());

        let resp = resp.unwrap();
        assert_eq!(Some(resp), noop.response);

        let req = noop.requests.read().unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].operation, Operation::Renew);
        assert_eq!(req[0].path, "login");
        assert_eq!(req[0].auth.clone().unwrap().internal_data, le_auth_internal_data);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_expiration_persist_load_delete() {
        let (_core, expiration, _token_store) = mock_expiration_manager!();

        let le = LeaseEntry {
            lease_id: "foo/bar/1234".into(),
            path: "foo/bar".into(),
            data: json!({
                "testing": true
            })
            .as_object()
            .unwrap()
            .clone(),
            secret: Some(SecretData {
                lease: Lease { ttl: Duration::from_secs(60), ..Default::default() },
                ..Default::default()
            }),
            issue_time: SystemTime::now(),
            expire_time: SystemTime::now(),
            ..Default::default()
        };

        let result = expiration.persist_lease_entry(&le).await;
        assert!(result.is_ok());

        let out = expiration.load_lease_entry("foo/bar/1234").await;
        assert!(out.is_ok());

        let out = out.unwrap();
        assert!(out.is_some());

        let out = out.unwrap();
        assert_eq!(le, out);

        let result = expiration.delete_lease_entry("foo/bar/1234").await;
        assert!(result.is_ok());

        let out = expiration.load_lease_entry("foo/bar/1234").await;
        assert!(out.is_ok());

        let out = out.unwrap();
        assert!(out.is_none());
    }
}
