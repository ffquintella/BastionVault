//! Host-owned connection pool, keyed by `(connection, root_credential_version,
//! config_generation)`. It enforces three rules: a target never has more than
//! `max_size` connections checked out; a connection opened under an old root
//! credential, an older `config/<name>` write or another TLS policy is never
//! handed out again (idle ones drop when the target changes, checked-out ones
//! on return, by the target's *epoch*); and the factory gets the host's TLS
//! policy, which verifies certificates unless the operator said otherwise.

use std::{
    collections::HashMap,
    future::Future,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::DynamicError;

/// How a target's server certificate is checked. The default verifies it
/// against the system trust store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    verify: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_pem: Option<String>,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self { verify: true, ca_pem: None }
    }
}

impl TlsPolicy {
    /// Verify against an operator-supplied CA bundle instead of the system store.
    pub fn verify_with_ca(ca_pem: String) -> Self {
        Self { verify: true, ca_pem: Some(ca_pem) }
    }

    /// Development only: no certificate verification. Every connection the
    /// pool opens under this policy is logged at WARN.
    pub fn insecure_skip_verify() -> Self {
        Self { verify: false, ca_pem: None }
    }

    pub fn verifies(&self) -> bool {
        self.verify
    }

    pub fn ca_pem(&self) -> Option<&str> {
        self.ca_pem.as_deref()
    }
}

/// What a pooled connection was opened for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolKey {
    pub connection: String,
    pub root_credential_version: u64,
    /// Bumped by the host on every `config/<name>` write (the operator may
    /// have changed the target or its root credential without `rotate-root`).
    #[serde(default)]
    pub config_generation: u64,
}

/// What the host knows about a target, from its connection record. Any change
/// drains the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSettings {
    pub root_credential_version: u64,
    pub config_generation: u64,
    pub tls: TlsPolicy,
}

/// Opens and checks connections. It is handed the pool's TLS policy and has no
/// other source for one.
pub trait ConnectionFactory: Send + Sync + 'static {
    type Conn: Send + 'static;

    fn connect(&self, key: &PoolKey, tls: &TlsPolicy) -> impl Future<Output = Result<Self::Conn, DynamicError>> + Send;

    fn validate(&self, conn: &mut Self::Conn) -> impl Future<Output = Result<(), DynamicError>> + Send;
}

#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Connections one target may have checked out at once.
    pub max_size: usize,
    /// How long a checkout waits for a free slot; zero means not at all.
    pub checkout_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { max_size: 8, checkout_timeout: Duration::from_secs(5) }
    }
}

struct Target<C> {
    settings: TargetSettings,
    /// Bumped whenever the settings change or the target rotates: a
    /// connection checked out under an older epoch is not returned.
    epoch: u64,
    permits: Arc<Semaphore>,
    idle: Vec<C>,
}

impl<C> Target<C> {
    fn key(&self, connection: &str) -> PoolKey {
        PoolKey {
            connection: connection.to_string(),
            root_credential_version: self.settings.root_credential_version,
            config_generation: self.settings.config_generation,
        }
    }

    /// Drop the idle connections and start a new epoch.
    fn drain(&mut self) -> usize {
        self.epoch += 1;
        std::mem::take(&mut self.idle).len()
    }
}

type Targets<C> = Mutex<HashMap<String, Target<C>>>;

pub struct ConnectionPool<F: ConnectionFactory> {
    factory: F,
    config: PoolConfig,
    targets: Arc<Targets<F::Conn>>,
}

fn lock<C>(targets: &Targets<C>) -> std::sync::MutexGuard<'_, HashMap<String, Target<C>>> {
    // Poisoning means a panic while the map was held; the map itself is still
    // consistent (every mutation is a single insert/remove/push/pop).
    targets.lock().unwrap_or_else(|p| p.into_inner())
}

impl<F: ConnectionFactory> ConnectionPool<F> {
    pub fn new(factory: F, config: PoolConfig) -> Self {
        let config = PoolConfig { max_size: config.max_size.max(1), ..config };
        Self { factory, config, targets: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Declare a target, or update it. Any change of root credential version,
    /// config generation or TLS policy drains it: idle connections are
    /// dropped and checked-out ones are dropped on return. Returns how many
    /// idle connections were dropped.
    pub fn configure(&self, connection: &str, settings: TargetSettings) -> usize {
        let mut targets = lock(&self.targets);
        match targets.get_mut(connection) {
            Some(t) if t.settings == settings => 0,
            Some(t) => {
                t.settings = settings;
                t.drain()
            }
            None => {
                let permits = Arc::new(Semaphore::new(self.config.max_size));
                targets.insert(connection.to_string(), Target { settings, epoch: 0, permits, idle: Vec::new() });
                0
            }
        }
    }

    /// The root credential of `connection` changed: drop its idle connections,
    /// and every one checked out now is dropped instead of returned. Returns
    /// how many idle connections were dropped.
    pub fn rotate(&self, connection: &str, new_version: u64) -> Result<usize, DynamicError> {
        let mut targets = lock(&self.targets);
        let t = targets.get_mut(connection).ok_or_else(|| DynamicError::UnknownConnection(connection.to_string()))?;
        t.settings.root_credential_version = new_version;
        Ok(t.drain())
    }

    /// Forget a target. Connections still checked out are dropped on return.
    pub fn remove(&self, connection: &str) {
        lock(&self.targets).remove(connection);
    }

    pub fn current_key(&self, connection: &str) -> Option<PoolKey> {
        lock(&self.targets).get(connection).map(|t| t.key(connection))
    }

    pub fn tls_policy(&self, connection: &str) -> Option<TlsPolicy> {
        lock(&self.targets).get(connection).map(|t| t.settings.tls.clone())
    }

    pub fn idle_count(&self, connection: &str) -> usize {
        lock(&self.targets).get(connection).map_or(0, |t| t.idle.len())
    }

    pub fn max_size(&self) -> usize {
        self.config.max_size
    }

    async fn acquire(&self, connection: &str, permits: Arc<Semaphore>) -> Result<OwnedSemaphorePermit, DynamicError> {
        let exhausted = || DynamicError::PoolExhausted(connection.to_string());
        if self.config.checkout_timeout.is_zero() {
            return permits.try_acquire_owned().map_err(|e| match e {
                TryAcquireError::NoPermits => exhausted(),
                TryAcquireError::Closed => DynamicError::UnknownConnection(connection.to_string()),
            });
        }
        match tokio::time::timeout(self.config.checkout_timeout, permits.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(DynamicError::UnknownConnection(connection.to_string())),
            Err(_elapsed) => Err(exhausted()),
        }
    }

    /// Check out a validated connection to `connection`, opening one when no
    /// idle connection passes validation.
    pub async fn checkout(&self, connection: &str) -> Result<Pooled<F::Conn>, DynamicError> {
        let permits = lock(&self.targets)
            .get(connection)
            .map(|t| t.permits.clone())
            .ok_or_else(|| DynamicError::UnknownConnection(connection.to_string()))?;
        let permit = self.acquire(connection, permits).await?;
        loop {
            // Re-read under the lock: the target may have rotated while we waited.
            let (key, epoch, tls, candidate) = {
                let mut targets = lock(&self.targets);
                let t = targets
                    .get_mut(connection)
                    .ok_or_else(|| DynamicError::UnknownConnection(connection.to_string()))?;
                (t.key(connection), t.epoch, t.settings.tls.clone(), t.idle.pop())
            };
            let conn = match candidate {
                Some(mut conn) => match self.factory.validate(&mut conn).await {
                    Ok(()) => conn,
                    Err(e) => {
                        log::debug!("pooled connection to `{connection}` failed validation and was dropped: {e}");
                        continue;
                    }
                },
                None => {
                    if !tls.verifies() {
                        log::warn!(
                            "opening a connection to `{connection}` with TLS certificate verification disabled \
                             (insecure_skip_tls_verify); this is for development only"
                        );
                    }
                    self.factory.connect(&key, &tls).await?
                }
            };
            return Ok(Pooled {
                conn: Some(conn),
                key,
                epoch,
                targets: Arc::downgrade(&self.targets),
                _permit: permit,
            });
        }
    }
}

/// A checked-out connection. Returned to the pool on drop, unless its target
/// changed (new epoch) or was removed meanwhile, or [`Pooled::discard`] was
/// called.
pub struct Pooled<C: Send + 'static> {
    conn: Option<C>,
    key: PoolKey,
    epoch: u64,
    targets: Weak<Targets<C>>,
    _permit: OwnedSemaphorePermit,
}

impl<C: Send + 'static> Pooled<C> {
    pub fn key(&self) -> &PoolKey {
        &self.key
    }

    /// Drop the connection instead of returning it (it is known broken).
    pub fn discard(mut self) {
        self.conn = None;
    }
}

impl<C: Send + 'static> Deref for Pooled<C> {
    type Target = C;
    fn deref(&self) -> &C {
        self.conn.as_ref().expect("a Pooled holds its connection until dropped")
    }
}

impl<C: Send + 'static> DerefMut for Pooled<C> {
    fn deref_mut(&mut self) -> &mut C {
        self.conn.as_mut().expect("a Pooled holds its connection until dropped")
    }
}

impl<C: Send + 'static> Drop for Pooled<C> {
    fn drop(&mut self) {
        let (Some(conn), Some(targets)) = (self.conn.take(), self.targets.upgrade()) else {
            return;
        };
        let mut targets = lock(&targets);
        if let Some(t) = targets.get_mut(&self.key.connection) {
            if t.epoch == self.epoch {
                t.idle.push(conn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[derive(Debug)]
    struct FakeConn {
        id: u64,
        key: PoolKey,
        tls: TlsPolicy,
    }

    #[derive(Default)]
    struct FakeFactory {
        opened: AtomicU64,
        /// Connection ids whose validation fails.
        broken: Mutex<Vec<u64>>,
    }

    impl ConnectionFactory for Arc<FakeFactory> {
        type Conn = FakeConn;

        async fn connect(&self, key: &PoolKey, tls: &TlsPolicy) -> Result<FakeConn, DynamicError> {
            let id = self.opened.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(FakeConn { id, key: key.clone(), tls: tls.clone() })
        }

        async fn validate(&self, conn: &mut FakeConn) -> Result<(), DynamicError> {
            if self.broken.lock().unwrap().contains(&conn.id) {
                return Err(DynamicError::Connect { connection: conn.key.connection.clone(), reason: "gone".into() });
            }
            Ok(())
        }
    }

    fn settings(version: u64, tls: TlsPolicy) -> TargetSettings {
        TargetSettings { root_credential_version: version, config_generation: 0, tls }
    }

    fn pool(max_size: usize) -> (ConnectionPool<Arc<FakeFactory>>, Arc<FakeFactory>) {
        let factory = Arc::new(FakeFactory::default());
        let pool = ConnectionPool::new(factory.clone(), PoolConfig { max_size, checkout_timeout: Duration::ZERO });
        pool.configure("pg", settings(1, TlsPolicy::default()));
        (pool, factory)
    }

    #[tokio::test]
    async fn max_size_is_enforced() {
        let (pool, _) = pool(2);
        let a = pool.checkout("pg").await.unwrap();
        let _b = pool.checkout("pg").await.unwrap();
        assert!(matches!(pool.checkout("pg").await, Err(DynamicError::PoolExhausted(_))));
        drop(a);
        assert!(pool.checkout("pg").await.is_ok(), "a returned slot is usable again");
    }

    #[tokio::test]
    async fn a_waiting_checkout_times_out() {
        let factory = Arc::new(FakeFactory::default());
        let pool =
            ConnectionPool::new(factory, PoolConfig { max_size: 1, checkout_timeout: Duration::from_millis(20) });
        pool.configure("pg", settings(1, TlsPolicy::default()));
        let _held = pool.checkout("pg").await.unwrap();
        assert!(matches!(pool.checkout("pg").await, Err(DynamicError::PoolExhausted(_))));
    }

    #[tokio::test]
    async fn returned_connections_are_reused() {
        let (pool, factory) = pool(2);
        let first_id = pool.checkout("pg").await.unwrap().id;
        assert_eq!(pool.idle_count("pg"), 1);
        assert_eq!(pool.checkout("pg").await.unwrap().id, first_id);
        assert_eq!(factory.opened.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_connection_that_fails_validation_is_replaced() {
        let (pool, factory) = pool(2);
        let first_id = pool.checkout("pg").await.unwrap().id;
        factory.broken.lock().unwrap().push(first_id);
        let next = pool.checkout("pg").await.unwrap();
        assert_ne!(next.id, first_id, "the broken connection is never handed out");
        assert_eq!(factory.opened.load(Ordering::SeqCst), 2);
        drop(next);
        assert_eq!(pool.idle_count("pg"), 1, "only the healthy connection went back");
    }

    #[tokio::test]
    async fn rotate_drains_idle_and_checked_out_connections() {
        let (pool, factory) = pool(4);
        drop(pool.checkout("pg").await.unwrap());
        let held = pool.checkout("pg").await.unwrap();
        let spare = pool.checkout("pg").await.unwrap();
        drop(spare);
        assert_eq!(pool.idle_count("pg"), 1);
        assert_eq!(pool.rotate("pg", 2).unwrap(), 1);
        assert_eq!(pool.idle_count("pg"), 0);
        drop(held);
        assert_eq!(pool.idle_count("pg"), 0, "a connection opened under the old root is not returned");
        let fresh = pool.checkout("pg").await.unwrap();
        assert_eq!(fresh.key().root_credential_version, 2);
        assert_eq!(fresh.key, PoolKey { connection: "pg".into(), root_credential_version: 2, config_generation: 0 });
        assert_eq!(factory.opened.load(Ordering::SeqCst), 3);
        assert!(matches!(pool.rotate("nope", 1), Err(DynamicError::UnknownConnection(_))));
    }

    /// A `config/<name>` write (new generation) or a TLS change drains the
    /// target like a rotation: a connection checked out before it, and opened
    /// under the old settings, is not handed out again.
    #[tokio::test]
    async fn a_config_or_tls_change_drains_checked_out_connections_too() {
        let (pool, factory) = pool(4);
        let held = pool.checkout("pg").await.unwrap();
        let regenerated = TargetSettings { config_generation: 1, ..settings(1, TlsPolicy::default()) };
        assert_eq!(pool.configure("pg", regenerated.clone()), 0);
        assert_eq!(pool.configure("pg", regenerated.clone()), 0, "unchanged settings drain nothing");
        drop(held);
        assert_eq!(pool.idle_count("pg"), 0, "opened under the previous config: not returned");

        let held = pool.checkout("pg").await.unwrap();
        assert_eq!(held.key().config_generation, 1);
        let insecure = TargetSettings { tls: TlsPolicy::insecure_skip_verify(), ..regenerated };
        pool.configure("pg", insecure);
        drop(held);
        assert_eq!(pool.idle_count("pg"), 0, "opened under the verifying policy: not returned");
        assert!(!pool.checkout("pg").await.unwrap().tls.verifies());
        assert_eq!(factory.opened.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn tls_verification_is_the_default_and_the_factory_cannot_choose() {
        assert!(TlsPolicy::default().verifies());
        let (pool, _) = pool(2);
        let c = pool.checkout("pg").await.unwrap();
        assert!(c.tls.verifies(), "the factory got the pool's verifying policy");
        assert_eq!(c.tls, TlsPolicy::default());
        drop(c);

        pool.configure("pg-ca", settings(1, TlsPolicy::verify_with_ca("-----BEGIN CERTIFICATE-----".into())));
        let c = pool.checkout("pg-ca").await.unwrap();
        assert!(c.tls.verifies());
        assert_eq!(c.tls.ca_pem(), Some("-----BEGIN CERTIFICATE-----"));
        drop(c);

        // Insecure is an explicit policy, and changing the policy drops idle
        // connections opened under the old one.
        assert_eq!(pool.configure("pg", settings(1, TlsPolicy::insecure_skip_verify())), 1);
        let c = pool.checkout("pg").await.unwrap();
        assert!(!c.tls.verifies());
    }

    #[tokio::test]
    async fn unknown_and_removed_targets_are_refused() {
        let (pool, _) = pool(1);
        assert!(matches!(pool.checkout("other").await, Err(DynamicError::UnknownConnection(_))));
        let held = pool.checkout("pg").await.unwrap();
        pool.remove("pg");
        drop(held);
        assert!(pool.current_key("pg").is_none());
        assert!(matches!(pool.checkout("pg").await, Err(DynamicError::UnknownConnection(_))));
    }

    #[test]
    fn tls_policy_serialises_without_the_ca_when_absent() {
        let v = serde_json::to_value(TlsPolicy::default()).unwrap();
        assert_eq!(v, serde_json::json!({ "verify": true }));
    }
}
