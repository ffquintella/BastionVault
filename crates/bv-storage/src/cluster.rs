//! Feature-independent view of the clustered physical backend.
//!
//! Everything an operator-facing surface needs to answer "is this node part
//! of a cluster, and what is its Raft role?" without naming
//! [`crate::hiqlite::HiqliteBackend`] — and therefore without the *asking*
//! crate having to be compiled with `storage_hiqlite` itself.
//!
//! That indirection is the whole point of this module. Before it,
//! `bv-server`'s `sys/health`, `sys/info` and `sys/cluster-status` handlers
//! each carried their own `#[cfg(feature = "storage_hiqlite")]` around a
//! downcast to `HiqliteBackend`. `bvault-cli` — the crate that builds the
//! `bvault` binary — forwarded `storage_hiqlite` to the library but not to
//! `bv-server`, so in every shipped binary those branches were compiled
//! out: a two-node Raft cluster reported `cluster: false`,
//! `storage_type: "file"`, and `standby: false` on the follower, from a
//! process whose storage layer was replicating normally. Nothing failed to
//! compile and no test covered it, because the feature *was* on for the
//! layer that owns the backend.
//!
//! Two rules keep that from coming back:
//!
//! 1. Callers ask through this module. It lives in the crate that owns the
//!    backend, so its answer is decided by whether the backend exists at
//!    all — not by the feature set of whoever is asking.
//! 2. Every entry point peels storage decorators first (see
//!    [`crate::physical_root`]). `Core::physical` is whatever
//!    [`crate::wrap_with_cache`] returned, so on a deployment with the
//!    ciphertext read cache enabled the outermost backend is a
//!    `CachingBackend`, and a bare downcast to the cluster backend answers
//!    "no" for a second, unrelated reason.
//!
//! "Not clustered" is reported as `None` / an empty list, never as a guessed
//! single-node answer. Callers that must distinguish "no cluster" from "the
//! cluster operation failed" get `Option<Result<..>>`.

use serde_json::Value;

use bv_errors::RvError;

use crate::Backend;

/// This node's place in the storage cluster, as the Raft engine sees it.
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    /// Raft node id of *this* process.
    pub node_id: u64,
    /// Is this node the current Raft leader?
    pub is_leader: bool,
    /// Does the Raft group have a quorum this node can reach?
    pub healthy: bool,
    /// Raft metrics as reported by the engine, when it answered.
    pub raft_metrics: Option<Value>,
}

/// The clustered backend behind `backend`, or `None` when this deployment is
/// not clustered.
///
/// Kept private: exposing it would re-export the concrete backend type and
/// invite the per-call-site downcast this module exists to remove.
#[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
fn cluster_backend(backend: &dyn Backend) -> Option<&crate::hiqlite::HiqliteBackend> {
    crate::as_hiqlite(backend)
}

/// Full status of this node in the cluster, or `None` when the physical
/// backend is not a clustered one.
pub async fn status(backend: &dyn Backend) -> Option<ClusterStatus> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        let cluster = cluster_backend(backend)?;
        return Some(ClusterStatus {
            node_id: cluster.node_id(),
            is_leader: cluster.is_leader().await,
            healthy: cluster.is_healthy().await,
            raft_metrics: cluster.cluster_metrics().await.ok(),
        });
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = backend;
        None
    }
}

/// This node's Raft node id, or `None` when not clustered.
///
/// The synchronous half of [`status`], for callers that only need identity
/// (record stamping) and must not await.
pub fn node_id(backend: &dyn Backend) -> Option<u64> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        return cluster_backend(backend).map(|cluster| cluster.node_id());
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = backend;
        None
    }
}

/// The addresses of every configured peer, or an empty list when not
/// clustered.
pub fn peer_addrs(backend: &dyn Backend) -> Vec<String> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        return cluster_backend(backend).map(|cluster| cluster.peer_addrs().to_vec()).unwrap_or_default();
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = backend;
        Vec::new()
    }
}

/// Remove `node_id` from the Raft membership. `None` when not clustered.
pub async fn remove_node(
    backend: &dyn Backend,
    node_id: u64,
    stay_as_learner: bool,
) -> Option<Result<(), RvError>> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        return cluster_backend(backend).map(|cluster| cluster.remove_node(node_id, stay_as_learner));
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = (backend, node_id, stay_as_learner);
        None
    }
}

/// Have this node leave the Raft membership. `None` when not clustered.
pub async fn leave(backend: &dyn Backend) -> Option<Result<(), RvError>> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        let cluster = cluster_backend(backend)?;
        return Some(cluster.leave_cluster().await);
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = backend;
        None
    }
}

/// Ask the Raft engine to hand leadership to another voter. `None` when not
/// clustered.
pub async fn failover(backend: &dyn Backend) -> Option<Result<(), RvError>> {
    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        let cluster = cluster_backend(backend)?;
        return Some(cluster.trigger_failover().await);
    }
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    {
        let _ = backend;
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{cache::CachingBackend, physical_root, test_support::new_test_backend};

    /// A non-clustered backend reports "no cluster" rather than a
    /// single-node guess, and reports its own kind.
    #[tokio::test]
    async fn file_backend_is_not_a_cluster() {
        let backend = new_test_backend("cluster_probe_file");

        assert_eq!(backend.backend_kind(), "file");
        assert!(status(backend.as_ref()).await.is_none());
        assert!(node_id(backend.as_ref()).is_none());
        assert!(peer_addrs(backend.as_ref()).is_empty());
    }

    /// The read-cache decorator must not change any answer about the
    /// physical layer: it is not a storage kind of its own, and it must not
    /// hide the backend underneath from `physical_root`. This is the second
    /// way the cluster-reporting bug can occur -- feature correctly
    /// forwarded, but `cache.secret_cache_ttl_secs > 0` in the operator's
    /// config, so `Core::physical` is the decorator and a bare downcast to
    /// the cluster backend answers "no".
    #[tokio::test]
    async fn cache_decorator_is_transparent_to_cluster_probes() {
        let inner = new_test_backend("cluster_probe_cached");
        let wrapped: Arc<dyn Backend> = Arc::new(CachingBackend::new(inner, 16, 30).unwrap());

        // The decorator reports the wrapped backend's kind, not its own...
        assert_eq!(wrapped.backend_kind(), "file");
        // ...and the peel reaches a backend that is no longer a decorator.
        let root: &dyn std::any::Any = physical_root(wrapped.as_ref());
        assert!(root.downcast_ref::<CachingBackend>().is_none());
        assert_eq!(physical_root(wrapped.as_ref()).backend_kind(), "file");

        assert!(status(wrapped.as_ref()).await.is_none());
        assert!(node_id(wrapped.as_ref()).is_none());
    }
}
