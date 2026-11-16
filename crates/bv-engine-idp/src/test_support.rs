//! An in-memory `Storage` for the Phase 2 unit tests, with read-failure
//! injection by key prefix.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

#[derive(Default)]
pub struct MemStorage {
    map: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_gets_under: Mutex<Option<String>>,
}

#[maybe_async::maybe_async]
impl Storage for MemStorage {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        let map = self.map.lock().unwrap();
        let mut out: Vec<String> = Vec::new();
        for key in map.keys().filter(|k| k.starts_with(prefix)) {
            let rest = &key[prefix.len()..];
            let child = match rest.find('/') {
                Some(i) => rest[..=i].to_string(),
                None => rest.to_string(),
            };
            if !out.contains(&child) {
                out.push(child);
            }
        }
        Ok(out)
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        tokio::task::yield_now().await;
        if self.fail_gets_under.lock().unwrap().as_deref().is_some_and(|p| key.starts_with(p)) {
            return Err(RvError::ErrString("injected read failure".into()));
        }
        let map = self.map.lock().unwrap();
        Ok(map.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
    }

    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        tokio::task::yield_now().await;
        self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

impl MemStorage {
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn raw_put(&self, key: &str, value: &[u8]) {
        self.map.lock().unwrap().insert(key.to_string(), value.to_vec());
    }

    pub fn raw_get(&self, key: &str) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(key).cloned()
    }

    pub fn fail_gets_under(&self, prefix: Option<&str>) {
        *self.fail_gets_under.lock().unwrap() = prefix.map(str::to_string);
    }
}
