//! Serialises AppRole role creation and deletion across every AppRole mount
//! and every node (T533), as `bv_auth_userpass::user_lock` does for userpass
//! users (T530): every HA node serves writes, so a process-local lock alone
//! covers no other node. The two crates share no dependency to hold one copy.

use std::any::Any;

use crate::{errors::RvError, storage::Storage};

/// The storage lock's name. Not a storage key: on the file backend it is a
/// lock file of its own, outside every mount's keys.
pub const ROLE_RECORDS_LOCK: &str = "bv-auth/approle/role-records";

#[cfg(not(feature = "sync_handler"))]
type LocalGuard = tokio::sync::MutexGuard<'static, ()>;
#[cfg(feature = "sync_handler")]
type LocalGuard = std::sync::MutexGuard<'static, ()>;

#[cfg(not(feature = "sync_handler"))]
static LOCAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(feature = "sync_handler")]
static LOCAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held while an AppRole role is created or deleted; dropping it releases
/// both locks.
pub struct RoleRecordsLock {
    // Declared first, so dropped first: the storage lock is released before
    // the next waiter in this process takes the local one.
    _storage: Box<dyn Any + Send>,
    _local: LocalGuard,
}

/// Take the lock through `storage`, any AppRole mount's view (one name for
/// all): an in-process mutex, so no two local tasks wait on the backend lock
/// (a polled lock file on the file backend), then the backend's lock, which
/// is cluster-wide on hiqlite and MySQL. A failure is returned, never
/// ignored. Take it after the role's own `role_locks` entry, never before.
#[maybe_async::maybe_async]
pub async fn lock_role_records(storage: &dyn Storage) -> Result<RoleRecordsLock, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    let local = LOCAL.lock().await;
    // The mutex guards `()`, so a panic while it was held broke no invariant.
    #[cfg(feature = "sync_handler")]
    let local = LOCAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let storage = storage.lock(ROLE_RECORDS_LOCK).await?;
    Ok(RoleRecordsLock { _storage: storage, _local: local })
}
