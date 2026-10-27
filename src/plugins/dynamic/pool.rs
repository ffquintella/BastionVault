//! The process-wide pool behind `dynamic_pool_checkout`, and the host's
//! connectors. A checkout is a slot counted against the target's `max_size`,
//! keyed by root credential version and config generation, carrying the
//! operator's TLS policy. A plugin that dials itself gets only that; one that
//! asks the host to execute has the host dial with its own connector, under
//! that policy, and the live connection stays in the slot for reuse.

use std::sync::{OnceLock, RwLock};

use bv_dynamic::{
    connector::{Connectors, Slot, SlotFactory},
    pool::{ConnectionPool, PoolConfig, Pooled},
};

pub type HeldGrant = Pooled<Slot>;

static HOST_POOL: OnceLock<ConnectionPool<SlotFactory>> = OnceLock::new();

/// The shared pool: one per process, so every mount and every plugin process
/// targeting the same connection draws from the same slots.
pub fn host_pool() -> &'static ConnectionPool<SlotFactory> {
    HOST_POOL.get_or_init(|| ConnectionPool::new(SlotFactory::default(), PoolConfig::default()))
}

fn registry() -> &'static RwLock<Connectors> {
    static CONNECTORS: OnceLock<RwLock<Connectors>> = OnceLock::new();
    CONNECTORS.get_or_init(|| RwLock::new(Connectors::builtin()))
}

/// The host's connectors, for one checkout or execution.
pub fn connectors() -> Connectors {
    registry().read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Tests add a fake connector next to the built-in ones.
#[cfg(test)]
pub fn register_connector(connector: std::sync::Arc<dyn bv_dynamic::connector::Connector>) {
    let mut guard = registry().write().unwrap_or_else(|p| p.into_inner());
    *guard = guard.clone().with(connector);
}

/// Pool key of `connection` on the mount `mount_id`: two mounts may both name
/// a connection `prod` and must never share its slots.
pub fn target_key(mount_id: &str, connection: &str) -> String {
    format!("{mount_id}/{connection}")
}
