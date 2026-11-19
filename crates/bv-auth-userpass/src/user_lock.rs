//! Serialises the writes that create, remove or write back a userpass user
//! record, across every userpass mount and every node (T530, T531). Every HA
//! node serves writes, so a process-local lock alone covers no other node;
//! the reasoning is in `features/userpass-account-security.md`.

use std::any::Any;

use crate::{errors::RvError, storage::Storage};

/// The storage lock's name. Not a storage key: on the file backend it is a
/// lock file of its own, outside every mount's keys.
pub const USER_RECORDS_LOCK: &str = "bv-auth/userpass/user-records";

#[cfg(not(feature = "sync_handler"))]
type LocalGuard = tokio::sync::MutexGuard<'static, ()>;
#[cfg(feature = "sync_handler")]
type LocalGuard = std::sync::MutexGuard<'static, ()>;

#[cfg(not(feature = "sync_handler"))]
static LOCAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(feature = "sync_handler")]
static LOCAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held while a userpass user record is created, removed or written back;
/// dropping it releases both locks.
pub struct UserRecordsLock {
    // Declared first, so dropped first: the storage lock is released before
    // the next waiter in this process takes the local one.
    _storage: Box<dyn Any + Send>,
    _local: LocalGuard,
}

/// Take the lock through `storage`, any userpass mount's view (one name for
/// all): an in-process mutex, so no two local tasks wait on the backend lock
/// (a polled lock file on the file backend), then the backend's lock, which
/// is cluster-wide on hiqlite and MySQL. A failure is returned, never
/// ignored. Never hold it across bcrypt.
#[maybe_async::maybe_async]
pub async fn lock_user_records(storage: &dyn Storage) -> Result<UserRecordsLock, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    let local = LOCAL.lock().await;
    // The mutex guards `()`, so a panic while it was held broke no invariant.
    #[cfg(feature = "sync_handler")]
    let local = LOCAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let storage = storage.lock(USER_RECORDS_LOCK).await?;
    Ok(UserRecordsLock { _storage: storage, _local: local })
}
