//! Backend storage helpers.
//!
//! All storage I/O goes through `req.storage_*` so the barrier
//! (ChaCha20-Poly1305) wraps every byte at rest. Plaintext key
//! material never persists.

use super::{policy::{KeyPolicy, POLICY_PREFIX}, TransitBackendInner};
use crate::{errors::RvError, logical::Request, storage::StorageEntry};

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub fn policy_path(name: &str) -> String {
        format!("{POLICY_PREFIX}{name}")
    }

    pub async fn get_policy(
        &self,
        req: &Request,
        name: &str,
    ) -> Result<Option<KeyPolicy>, RvError> {
        match req.storage_get(&Self::policy_path(name)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_policy(
        &self,
        req: &mut Request,
        policy: &KeyPolicy,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(policy)?;
        req.storage_put(&StorageEntry {
            key: Self::policy_path(&policy.name),
            value: bytes,
        })
        .await
    }

    pub async fn delete_policy(&self, req: &mut Request, name: &str) -> Result<(), RvError> {
        req.storage_delete(&Self::policy_path(name)).await
    }

    pub async fn list_policies(&self, req: &Request) -> Result<Vec<String>, RvError> {
        req.storage_list(POLICY_PREFIX).await
    }
}
