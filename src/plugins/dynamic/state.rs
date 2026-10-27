//! Host-owned state of one dynamic mount, kept in the mount's own storage
//! view under `bv-dynamic/`. The plugin's storage is elsewhere
//! (`core/plugins/<name>/data/`), so a plugin can neither read nor forge it.

use bv_dynamic::records::ConnectionRecord;

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

const MOUNT_ID_KEY: &str = "bv-dynamic/mount-id";
const CONNECTION_PREFIX: &str = "bv-dynamic/connections/";

/// A stable random id for the mount, created on first use. Scopes pool keys
/// without the backend having to know its mount path.
pub async fn mount_id(storage: &dyn Storage) -> Result<String, RvError> {
    if let Some(entry) = storage.get(MOUNT_ID_KEY).await? {
        if let Ok(id) = String::from_utf8(entry.value) {
            if !id.is_empty() {
                return Ok(id);
            }
        }
    }
    let mut raw = [0u8; 16];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut raw);
    }
    let id = hex::encode(raw);
    storage.put(&StorageEntry { key: MOUNT_ID_KEY.to_string(), value: id.clone().into_bytes() }).await?;
    Ok(id)
}

pub async fn load_connection(storage: &dyn Storage, name: &str) -> Result<Option<ConnectionRecord>, RvError> {
    match storage.get(&format!("{CONNECTION_PREFIX}{name}")).await? {
        None => Ok(None),
        Some(entry) => Ok(Some(ConnectionRecord::decode(&entry.value)?)),
    }
}

pub async fn save_connection(storage: &dyn Storage, name: &str, rec: &ConnectionRecord) -> Result<(), RvError> {
    storage.put(&StorageEntry { key: format!("{CONNECTION_PREFIX}{name}"), value: serde_json::to_vec(rec)? }).await
}

pub async fn delete_connection(storage: &dyn Storage, name: &str) -> Result<(), RvError> {
    storage.delete(&format!("{CONNECTION_PREFIX}{name}")).await
}
