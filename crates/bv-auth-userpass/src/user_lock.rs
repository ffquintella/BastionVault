//! Serialises every write of one userpass user record across every userpass
//! mount and every node: admin writes (T530), self-service writes (T531) and
//! the backend's own read-modify-writes (T544). One lock per lower-cased
//! name, hashed into a fixed-length hex lock name; why per name, and the HA
//! and backend behaviour, is in `features/userpass-account-security.md`.
//! Never hold two at once, nor one across bcrypt or a passkey verification.

use std::any::Any;

use crate::{errors::RvError, storage::Storage, utils};

/// Prefix of every record lock's name. Not a storage key: on the file backend
/// each lock is a lock file of its own, outside every mount's keys.
pub const USER_RECORD_LOCK_PREFIX: &str = "bv-auth/userpass/user/";

/// Hashed with the lower-cased name, so the lock name space is this module's.
const LOCK_NAME_DOMAIN: &str = "bastionvault/userpass/user-record-lock/v1\0";

/// Hex digits of the SHA-256 kept: 128 bits, a 54-character lock name, so
/// within MySQL's 64-character `GET_LOCK` limit. A collision only shares a lock.
const LOCK_NAME_HEX_DIGITS: usize = 32;

/// In-process stripes in front of the backend lock, so two local tasks never
/// wait on one backend lock together (the file backend polls a lock file with
/// a blocking sleep). A fixed set: names sprayed at the login route allocate
/// nothing, and two names on one stripe only share it.
const LOCAL_STRIPES: usize = 64;

#[cfg(not(feature = "sync_handler"))]
type LocalGuard = tokio::sync::MutexGuard<'static, ()>;
#[cfg(feature = "sync_handler")]
type LocalGuard = std::sync::MutexGuard<'static, ()>;

#[cfg(not(feature = "sync_handler"))]
static LOCAL: [tokio::sync::Mutex<()>; LOCAL_STRIPES] = [const { tokio::sync::Mutex::const_new(()) }; LOCAL_STRIPES];
#[cfg(feature = "sync_handler")]
static LOCAL: [std::sync::Mutex<()>; LOCAL_STRIPES] = [const { std::sync::Mutex::new(()) }; LOCAL_STRIPES];

/// Held while one user's record is read and written back; dropping it
/// releases both locks.
pub struct UserRecordLock {
    // Declared first, so dropped first: the storage lock is released before
    // the next waiter in this process takes the local one.
    _storage: Box<dyn Any + Send>,
    _local: LocalGuard,
}

/// The backend lock name for `username`'s record: the same on every mount
/// and node, whatever the letter case, and never a path whatever the name.
pub fn user_record_lock_name(username: &str) -> String {
    let digest = utils::sha256(format!("{LOCK_NAME_DOMAIN}{}", username.to_lowercase()).as_bytes());
    format!("{USER_RECORD_LOCK_PREFIX}{}", &digest[..LOCK_NAME_HEX_DIGITS])
}

/// The in-process stripe a lock name maps to.
fn local_stripe(lock_name: &str) -> usize {
    let hex = lock_name.strip_prefix(USER_RECORD_LOCK_PREFIX).unwrap_or(lock_name);
    hex.bytes().fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(usize::from(b))) % LOCAL_STRIPES
}

/// Take `username`'s record lock through `storage`, any userpass mount's view:
/// the in-process stripe, then the backend's lock (cluster-wide on hiqlite
/// and MySQL). A failure is returned, never ignored.
#[maybe_async::maybe_async]
pub async fn lock_user_record(storage: &dyn Storage, username: &str) -> Result<UserRecordLock, RvError> {
    let lock_name = user_record_lock_name(username);
    let stripe = &LOCAL[local_stripe(&lock_name)];
    #[cfg(not(feature = "sync_handler"))]
    let local = stripe.lock().await;
    // The mutex guards `()`, so a panic while it was held broke no invariant.
    #[cfg(feature = "sync_handler")]
    let local = stripe.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let storage = storage.lock(&lock_name).await?;
    Ok(UserRecordLock { _storage: storage, _local: local })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the username holds, the lock name is the prefix plus 32
    /// lower-case hex digits: no separator, no `..`, at most 64 characters.
    #[test]
    fn lock_names_are_fixed_length_hex() {
        let long = "a".repeat(10_000);
        for name in ["carol", "../../etc/passwd", "a/b\\c", "ünïcödé", "", "x\0y", long.as_str()] {
            let lock = user_record_lock_name(name);
            let hex = lock.strip_prefix(USER_RECORD_LOCK_PREFIX).expect("prefix");
            assert_eq!(hex.len(), LOCK_NAME_HEX_DIGITS, "{name:?}");
            assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{name:?}: {lock}");
            assert!(lock.len() <= 64, "MySQL GET_LOCK limit: {lock}");
        }
    }

    /// One principal across mounts and letter cases (T500), so one lock;
    /// different names get different locks.
    #[test]
    fn lock_names_follow_the_lower_cased_name() {
        assert_eq!(user_record_lock_name("Carol"), user_record_lock_name("carol"));
        assert_ne!(user_record_lock_name("carol"), user_record_lock_name("dave"));
        assert_ne!(user_record_lock_name("carol"), user_record_lock_name("carol2"));
    }

    /// `src/engine_tests/userpass_record_writes.rs` holds dave's lock while
    /// carol fails a login, which needs the two on different stripes.
    #[test]
    fn carol_and_dave_do_not_share_a_stripe() {
        let stripe = |name| local_stripe(&user_record_lock_name(name));
        assert_ne!(stripe("carol"), stripe("dave"));
    }
}
