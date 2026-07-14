//! Per-namespace mount-router registry.
//!
//! ## Design: one shared router, namespace-prefixed mount keys
//!
//! The feature spec sketches "one [`Router`] per namespace indexed by UUID".
//! We achieve the same observable contract — full storage isolation and both
//! addressing forms — with far less risk by reusing the existing single global
//! [`Router`] and the existing [`MountsRouter`], which already supports a
//! `router_prefix`:
//!
//! - A child namespace `engineering` gets a [`MountsRouter`] that shares the
//!   global router, mounts under the trie prefix `engineering/`, and persists
//!   its own mount table at `namespaces/<uuid>/core/mounts`.
//! - Each of its mounts is barrier-isolated under
//!   `namespaces/<uuid>/logical/<mount_uuid>/`, so the physical backend never
//!   sees an un-prefixed key from another namespace.
//!
//! A request `/v1/engineering/secret/foo` (path-prefix form) matches the trie
//! key `engineering/secret/` directly. The header form
//! (`X-BastionVault-Namespace: engineering`, path `secret/foo`) is normalised
//! to the same path by [`super::router::rewrite_request_for_namespace`] before
//! routing. The pre-route auth pipeline runs unchanged for both.
//!
//! [`ensure_router`] itself never seeds mounts — a namespace with no persisted
//! mount table gets an empty one. New namespaces are instead seeded with a
//! default engine set at *create* time by the `sys/namespaces` write handler
//! (`SystemModule::seed_default_namespace_mounts`), and torn down by the
//! cascade in `handle_namespace_delete`, so the registry layer stays purely
//! mechanical.

use std::sync::Arc;

use dashmap::DashMap;

use crate::{
    core::Core,
    errors::RvError,
    mount::{MountTable, MountsRouter},
};

use super::router::{namespace_logical_prefix, namespace_mount_config_path};

/// Holds the [`MountsRouter`] for every non-root namespace, keyed by UUID.
/// The root namespace continues to use `Core::mounts_router`.
#[derive(Default)]
pub struct NamespaceMountRegistry {
    routers: DashMap<String, Arc<MountsRouter>>,
}

impl NamespaceMountRegistry {
    pub fn new() -> Self {
        Self { routers: DashMap::new() }
    }

    pub fn get(&self, uuid: &str) -> Option<Arc<MountsRouter>> {
        self.routers.get(uuid).map(|r| r.clone())
    }

    /// Number of mounts currently registered for a namespace (0 if the
    /// namespace has no router yet). Used by the delete guard.
    pub fn mount_count(&self, uuid: &str) -> usize {
        self.routers
            .get(uuid)
            .and_then(|r| r.mounts.entries.read().ok().map(|e| e.len()))
            .unwrap_or(0)
    }
}

#[maybe_async::maybe_async]
impl NamespaceMountRegistry {
    /// Build (or fetch the cached) [`MountsRouter`] for a namespace and wire
    /// its mounts into the shared global router. `ns_path` is the canonical
    /// namespace path (no trailing slash); it becomes the router prefix.
    /// `ns_uuid` selects the barrier storage prefix.
    pub async fn ensure_router(
        &self,
        core: &Arc<Core>,
        ns_uuid: &str,
        ns_path: &str,
    ) -> Result<Arc<MountsRouter>, RvError> {
        if let Some(existing) = self.get(ns_uuid) {
            return Ok(existing);
        }

        let mount_table = Arc::new(MountTable::new(&namespace_mount_config_path(ns_uuid)));
        // Namespace mount paths live under "<ns_path>/" in the shared router
        // trie. The trailing slash matches the existing convention (mounts are
        // stored with a trailing slash, e.g. "secret/").
        let router_prefix = format!("{}/", ns_path.trim_end_matches('/'));
        let mounts_router = Arc::new(MountsRouter::new(
            mount_table,
            core.router.clone(),
            core.barrier.clone(),
            &namespace_logical_prefix(ns_uuid),
            &router_prefix,
        ));

        // Register the backend factories the same way the root router does, so
        // a child namespace can mount any secret engine the deployment knows.
        // The factories are stateless closures resolved per request, so cloning
        // the type→factory map from the root router is sufficient.
        for kv in core.mounts_router().backends.iter() {
            let _ = mounts_router.add_backend(kv.key(), kv.value().clone());
        }

        // Load the persisted table; an absent table means a brand-new (empty)
        // namespace — create and persist an empty one rather than seeding the
        // default core mounts (child namespaces start functionally empty).
        match mount_table_load(&mounts_router, core).await {
            Ok(()) => {}
            Err(RvError::ErrConfigLoadFailed) => {
                mounts_router.mounts.persist(core.barrier.as_storage()).await?;
            }
            Err(e) => return Err(e),
        }

        mounts_router.setup(core.clone())?;

        // Cache atomically. Two concurrent first-touch requests to the same
        // namespace can both reach here (the `get` above is a check-then-act);
        // `entry(..).or_insert` makes exactly one router win the cache slot.
        // Both built routers are equivalent (same persisted table, same shared
        // trie), and `setup` above is idempotent, so the loser is simply
        // dropped rather than clobbering the winner mid-flight.
        let cached = self
            .routers
            .entry(ns_uuid.to_string())
            .or_insert_with(|| mounts_router.clone())
            .clone();
        Ok(cached)
    }

    /// Mount a backend inside a namespace. Ensures the namespace's router
    /// exists, then mounts the entry under `<ns_path>/<mount>` with storage
    /// isolated under `namespaces/<uuid>/logical/`.
    pub async fn mount(
        &self,
        core: &Arc<Core>,
        ns_uuid: &str,
        ns_path: &str,
        me: &crate::mount::MountEntry,
    ) -> Result<(), RvError> {
        let router = self.ensure_router(core, ns_uuid, ns_path).await?;
        let hmac_key = core.state.load().hmac_key.clone();
        router.mount_one(core.clone(), me, &hmac_key).await
    }

    /// Unmount a backend inside a namespace.
    pub async fn unmount(
        &self,
        core: &Arc<Core>,
        ns_uuid: &str,
        ns_path: &str,
        path: &str,
    ) -> Result<(), RvError> {
        let router = self.ensure_router(core, ns_uuid, ns_path).await?;
        router.unmount_one(path).await
    }

    /// List the mount paths registered in a namespace (`secret/`, ...).
    pub async fn list_mounts(
        &self,
        core: &Arc<Core>,
        ns_uuid: &str,
        ns_path: &str,
    ) -> Result<Vec<(String, String, String)>, RvError> {
        let router = self.ensure_router(core, ns_uuid, ns_path).await?;
        let mut out = Vec::new();
        for entry in router.mounts.entries.read()?.values() {
            let e = entry.read()?;
            out.push((e.path.clone(), e.logical_type.clone(), e.description.clone()));
        }
        out.sort();
        Ok(out)
    }

    /// Drop a namespace's router and clear its mounts from the shared router
    /// trie. Caller must have already confirmed the namespace is empty.
    pub fn forget(&self, ns_uuid: &str) {
        if let Some((_, router)) = self.routers.remove(ns_uuid) {
            let _ = router.unload();
        }
    }
}

#[maybe_async::maybe_async]
async fn mount_table_load(router: &Arc<MountsRouter>, core: &Arc<Core>) -> Result<(), RvError> {
    router
        .mounts
        .load(core.barrier.as_storage(), Some(&core.state.load().hmac_key), core.mount_entry_hmac_level)
        .await
        .map(|_| ())
}
