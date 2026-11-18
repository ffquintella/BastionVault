//! In-memory physical storage whose operations under chosen key prefixes
//! fail, behind a real unsealed barrier: unit tests of what the identity and
//! auth modules do when storage refuses partway (T522). `cfg(test)` only.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::{
    errors::RvError,
    storage::{
        barrier::SecurityBarrier, barrier_aes_gcm::AESGCMBarrier, barrier_view::BarrierView, Backend, BackendEntry,
    },
};

#[derive(Default)]
pub(crate) struct FaultyBackend {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
    failing: Mutex<Vec<String>>,
}

impl FaultyBackend {
    /// Fail every operation on a key (or a listing) starting with `prefix`.
    pub(crate) fn fail_under(&self, prefix: &str) {
        self.failing.lock().unwrap().push(prefix.to_string());
    }

    pub(crate) fn heal(&self) {
        self.failing.lock().unwrap().clear();
    }

    fn check(&self, key: &str) -> Result<(), RvError> {
        if self.failing.lock().unwrap().iter().any(|p| key.starts_with(p.as_str())) {
            return Err(RvError::ErrString(format!("injected storage fault at {key}")));
        }
        Ok(())
    }
}

#[maybe_async::maybe_async]
impl Backend for FaultyBackend {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        self.check(prefix)?;
        let mut children: Vec<String> = Vec::new();
        for key in self.entries.lock().unwrap().keys() {
            let Some(rest) = key.strip_prefix(prefix) else { continue };
            let child = match rest.find('/') {
                Some(i) => rest[..=i].to_string(),
                None => rest.to_string(),
            };
            if !children.contains(&child) {
                children.push(child);
            }
        }
        Ok(children)
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        self.check(key)?;
        let value = self.entries.lock().unwrap().get(key).cloned();
        Ok(value.map(|value| BackendEntry { key: key.to_string(), value }))
    }

    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        self.check(&entry.key)?;
        self.entries.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.check(key)?;
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

/// A fresh backend and an unsealed barrier view over it at `prefix`.
#[maybe_async::maybe_async]
pub(crate) async fn view(prefix: &str) -> (Arc<FaultyBackend>, BarrierView) {
    let backend = Arc::new(FaultyBackend::default());
    let barrier = AESGCMBarrier::new(backend.clone());
    let key = barrier.generate_key().unwrap();
    barrier.init(&key).await.unwrap();
    barrier.unseal(&key).await.unwrap();
    let barrier: Arc<dyn SecurityBarrier> = Arc::new(barrier);
    (backend, BarrierView::new(barrier, prefix))
}
