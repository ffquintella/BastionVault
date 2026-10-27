//! The process-wide pool behind `dynamic_pool_checkout`.
//!
//! The host carries no target drivers, so a pooled "connection" is a grant:
//! a slot counted against the target's `max_size`, keyed by the root
//! credential version and carrying the TLS policy the operator configured.
//! The plugin dials with that policy; the slot is released when its call ends.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use bv_dynamic::{
    pool::{ConnectionFactory, ConnectionPool, PoolConfig, PoolKey, Pooled, TlsPolicy},
    DynamicError,
};

/// One checked-out slot.
#[derive(Debug)]
pub struct Grant {
    pub id: u64,
    pub tls: TlsPolicy,
}

pub type HeldGrant = Pooled<Grant>;

#[derive(Default)]
pub struct GrantFactory {
    next: AtomicU64,
}

impl ConnectionFactory for GrantFactory {
    type Conn = Grant;

    async fn connect(&self, _key: &PoolKey, tls: &TlsPolicy) -> Result<Grant, DynamicError> {
        Ok(Grant { id: self.next.fetch_add(1, Ordering::SeqCst) + 1, tls: tls.clone() })
    }

    async fn validate(&self, _conn: &mut Grant) -> Result<(), DynamicError> {
        Ok(())
    }
}

static HOST_POOL: OnceLock<ConnectionPool<GrantFactory>> = OnceLock::new();

/// The shared pool: one per process, so every mount and every plugin process
/// targeting the same connection draws from the same slots.
pub fn host_pool() -> &'static ConnectionPool<GrantFactory> {
    HOST_POOL.get_or_init(|| ConnectionPool::new(GrantFactory::default(), PoolConfig::default()))
}

/// Pool key of `connection` on the mount `mount_id`: two mounts may both name
/// a connection `prod` and must never share its slots.
pub fn target_key(mount_id: &str, connection: &str) -> String {
    format!("{mount_id}/{connection}")
}
