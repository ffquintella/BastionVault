//! Legacy single-slot keychain entries.
//!
//! Pre-multi-vault revisions stored the active vault's unseal key
//! and root token directly in the OS keychain under fixed entries
//! `unseal-key` and `root-token`. The current keystore at
//! `local_keystore.rs` replaces that with a per-vault-id layer on
//! top of a single `local-master-key` keychain entry.
//!
//! This module now contains ONLY the read + delete paths, which
//! `local_keystore::migrate_legacy_if_needed` calls on every
//! `get_*` to pull values out of the legacy slots and wipe them.
//! The `store_*` write-side functions are gone — nothing should
//! ever write into the legacy slots again.

use keyring::Entry;

use crate::error::CommandError;

const SERVICE: &str = "bastion-vault-gui";

fn entry(key: &str) -> Result<Entry, CommandError> {
    Entry::new(SERVICE, key).map_err(|e| CommandError::from(format!("Keychain entry error: {e}")))
}

pub fn get_unseal_key() -> Result<Option<String>, CommandError> {
    match entry("unseal-key")?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn get_root_token() -> Result<Option<String>, CommandError> {
    match entry("root-token")?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn delete_all_keys() -> Result<(), CommandError> {
    // Best-effort deletion; ignore NoEntry errors.
    for key in &["unseal-key", "root-token"] {
        if let Ok(e) = Entry::new(SERVICE, key) {
            match e.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
