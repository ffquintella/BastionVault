//! A generic keyed store of type-erased values, plus a registry of spawned
//! tasks to await at shutdown.
//!
//! Tier 0 of the workspace decomposition
//! (`roadmaps/workspace-decomposition.md`): this references nothing but the
//! error type, and `bv-logical` needs it — `Request`, `Path`, `Backend` and
//! `logical::mod` all take a `&Context`. Re-exported by the root crate as
//! `bastion_vault::context`.

use std::{
    any::Any,
    sync::{Arc, Mutex, RwLock},
};

use dashmap::DashMap;
use tokio::task::JoinHandle;

use bv_errors::RvError;

#[derive(Default, Debug)]
pub struct Context {
    tasks: Mutex<Vec<JoinHandle<()>>>,
    data_map: DashMap<String, Arc<dyn Any + Send + Sync>>,
    data_map_mut: DashMap<String, Arc<RwLock<dyn Any + Send + Sync>>>,
}

impl Context {
    pub fn new() -> Self {
        Self { data_map: DashMap::new(), data_map_mut: DashMap::new(), ..Default::default() }
    }

    pub fn set_mut(&self, key: &str, data: Arc<RwLock<dyn Any + Send + Sync>>) {
        self.data_map_mut.insert(key.to_string(), data);
    }

    pub fn get_mut(&self, key: &str) -> Option<Arc<RwLock<dyn Any + Send + Sync>>> {
        self.data_map_mut.get(key).map(|r| r.value().clone())
    }

    pub fn set(&self, key: &str, data: Arc<dyn Any + Send + Sync>) {
        self.data_map.insert(key.to_string(), data);
    }

    pub fn get(&self, key: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.data_map.get(key).map(|r| r.clone())
    }

    pub fn add_task(&self, task: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.push(task)
    }

    pub fn clear_task(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.clear()
    }

    /// Await every registered task.
    ///
    /// The handles are drained under the lock and awaited *outside* it. The
    /// previous version held the `MutexGuard` across the `await`, which is a
    /// deadlock, not just a lint: any awaited task that itself calls
    /// [`Context::add_task`] or [`Context::clear_task`] blocks forever on a
    /// mutex its awaiter will not release until that task completes. The
    /// AppRole secret-id tidy path does exactly that — it registers its
    /// sweep task with `req.ctx.add_task(...)` — so the window was reachable.
    /// Holding a `std::sync` guard across an await also makes this future
    /// `!Send`.
    ///
    /// Draining also makes the method idempotent. A `tokio::JoinHandle`
    /// panics if polled after completion, so the old version could only be
    /// called twice if the caller emptied the vec in between with
    /// `clear_task()`; now a second call is simply a no-op.
    pub async fn wait_task_finish(&self) -> Result<(), RvError> {
        let tasks: Vec<JoinHandle<()>> = {
            let mut guard = self.tasks.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        for task in tasks {
            task.await?;
        }

        Ok(())
    }
}
