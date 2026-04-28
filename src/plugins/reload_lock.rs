//! Per-plugin in-flight gate for hot reload — Phase 5.6.
//!
//! Every invocation acquires a *read* on the plugin's gate; a reload
//! acquires the *write*. `tokio::sync::RwLock` gives us the right
//! semantics — pending writes block new readers, draining the
//! in-flight set. Reload supplies a per-call timeout; if the drain
//! doesn't finish, the host returns `plugin_reloading` to incoming
//! callers. Once the write is held the swap is atomic with respect
//! to invocations: the new module is loaded under the write, the
//! lock is released, and queued invocations resume against the new
//! version.
//!
//! Locks are global (`OnceLock<DashMap>`) so that the LogicalBackend
//! and the reload HTTP handler — which live in different scopes —
//! can share state without threading the gate through every callsite.

use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

type GateMap = DashMap<String, Arc<RwLock<()>>>;

static GATES: OnceLock<GateMap> = OnceLock::new();

fn gates() -> &'static GateMap {
    GATES.get_or_init(DashMap::new)
}

fn gate_for(plugin: &str) -> Arc<RwLock<()>> {
    gates()
        .entry(plugin.to_string())
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

/// Acquire an invocation gate. Held for the duration of the plugin's
/// run; reloads waiting on the write side block until every read
/// guard drops. Uses `read_owned()` so the guard owns its `Arc` —
/// avoids the borrow-vs-move dance with a static-lifetime extension.
pub async fn acquire_invoke(plugin: &str) -> InvokeGuard {
    let gate = gate_for(plugin);
    InvokeGuard {
        _guard: gate.read_owned().await,
    }
}

/// Acquire a reload gate. Drains every in-flight invocation before
/// returning; if `timeout` elapses first, returns
/// `Err(ReloadAcquireError::DrainTimeout)` and the caller should
/// refuse the reload with `plugin_reloading`.
pub async fn acquire_reload(
    plugin: &str,
    timeout: std::time::Duration,
) -> Result<ReloadGuard, ReloadAcquireError> {
    let gate = gate_for(plugin);
    match tokio::time::timeout(timeout, gate.write_owned()).await {
        Err(_elapsed) => Err(ReloadAcquireError::DrainTimeout),
        Ok(guard) => Ok(ReloadGuard { _guard: guard }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReloadAcquireError {
    #[error("plugin in-flight drain timed out; reload refused")]
    DrainTimeout,
}

pub struct InvokeGuard {
    _guard: OwnedRwLockReadGuard<()>,
}

pub struct ReloadGuard {
    _guard: OwnedRwLockWriteGuard<()>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn reload_blocks_on_in_flight_invoke() {
        let invoke = acquire_invoke("p1").await;
        // Reload with a short timeout should fail to drain.
        let r = acquire_reload("p1", Duration::from_millis(50)).await;
        assert!(matches!(r, Err(ReloadAcquireError::DrainTimeout)));
        drop(invoke);
        // Now reload succeeds.
        let r = acquire_reload("p1", Duration::from_millis(100)).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn invoke_waits_when_reload_holds_write() {
        let reload = acquire_reload("p2", Duration::from_secs(1)).await.unwrap();
        let invoke_fut = acquire_invoke("p2");
        // Race the invoke against a small drop delay — confirms the
        // invoke is genuinely blocked on the write.
        let result = tokio::time::timeout(Duration::from_millis(50), invoke_fut).await;
        assert!(result.is_err(), "invoke should be blocked while reload holds the write");
        drop(reload);
        // After release, invoke proceeds.
        let g = acquire_invoke("p2").await;
        drop(g);
    }
}
