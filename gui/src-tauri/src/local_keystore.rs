//! Per-vault keystore — fixes the "switch vault overwrites the
//! keychain" bug.
//!
//! # Problem
//!
//! Before this module, the GUI stored the active vault's unseal key
//! directly in the OS keychain under a fixed service entry
//! (`bastion-vault-gui / unseal-key`). Initializing or opening a
//! *different* vault overwrote that single slot. Coming back to the
//! first vault then tried to unseal it with the second vault's key
//! and blew up with "BastionVault unseal failed."
//!
//! # Design
//!
//! Two layers:
//!
//! 1. **Local key** — a 32-byte symmetric key, generated once per
//!    installation, stored in the OS keychain under a single entry
//!    `bastion-vault-gui / local-master-key`. This is the only
//!    credential the keychain ever holds; everything per-vault
//!    lives inside the encrypted file below.
//!
//! 2. **Encrypted vault-keys file** at
//!    `<app-data>/vault-keys.enc`. Contents is JSON:
//!
//!    ```json
//!    { "version": 1,
//!      "vaults": {
//!        "<vault_id>": {
//!          "unseal_key_hex": "<hex>",
//!          "root_token":     "<str>",
//!          "created_at":     <unix_seconds>
//!        }
//!      }
//!    }
//!    ```
//!
//!    Encrypted with ChaCha20-Poly1305 (matching the vault core's
//!    barrier cipher), keyed by the local key. The nonce is 12
//!    random bytes, prepended to the ciphertext. A 4-byte magic
//!    header (`BVK\x01`) lets future format versions be detected
//!    cleanly.
//!
//! # Post-quantum posture
//!
//! ChaCha20-Poly1305 with a 256-bit key survives Grover's algorithm
//! with ~128 effective bits, which is the accepted PQC-safe
//! symmetric ceiling. A future phase (documented in
//! `docs/security-structure.md`) wraps the payload in an ML-KEM-768
//! envelope so that even a theoretical master-key compromise cannot
//! be converted into a retroactive decryption of a captured file.
//!
//! # YubiKey failsafe (deferred — scaffolded)
//!
//! A follow-up phase replaces the keychain-only local-key path with
//! a YubiKey-derived key: each registered YubiKey signs a per-key
//! salt (RSA-PKCS1 or ECDSA, deterministic) and the signature seeds
//! the local key via HKDF. Multiple YubiKeys register independent
//! salts so any one can recover the file — a spare-keys model for
//! loss/damage scenarios. See `docs/security-structure.md` §
//! "YubiKey failsafe design".
//!
//! # Migration
//!
//! On first read after upgrade, if the legacy keychain entries
//! (`unseal-key` / `root-token`) are present and `last_used_id` is
//! known, we migrate the values into the new file under that vault
//! id, then wipe the legacy entries. The migration path is run from
//! every `get_*` call so it is eventually-consistent and tolerant
//! of out-of-order upgrades.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::CommandError;

/// Keychain service prefix — same one already used by the legacy
/// `secure_store` module so both live side-by-side during migration.
const SERVICE: &str = "bastion-vault-gui";
/// Keychain entry holding the 32-byte local key, hex-encoded.
const LOCAL_KEY_ENTRY: &str = "local-master-key";
/// Relative path, inside `data_dir()`, of the encrypted vault-keys
/// file. Kept alongside vault data so a `reset_vault` call that
/// nukes the data dir also wipes the cached keys.
const KEYS_FILE_NAME: &str = "vault-keys.enc";
/// Magic prefix so old / future formats can be distinguished.
const MAGIC: &[u8; 4] = b"BVK\x01";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeys {
    pub unseal_key_hex: String,
    pub root_token: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileContents {
    version: u8,
    vaults: std::collections::BTreeMap<String, VaultKeys>,
}

/// Compute the on-disk path for the encrypted vault-keys file.
///
/// Anchored at `<data_local>/.bastion_vault_gui/` directly rather
/// than inside a storage-kind-specific subdirectory, so the file
/// survives switching between Hiqlite / File / Cloud storage
/// engines without needing migration. An optional
/// `BV_GUI_DATA_DIR_OVERRIDE` env var redirects the location during
/// integration tests so they don't collide with a developer's real
/// install.
fn keys_file_path() -> Result<PathBuf, CommandError> {
    let root = if let Ok(overridden) = std::env::var("BV_GUI_DATA_DIR_OVERRIDE") {
        PathBuf::from(overridden)
    } else {
        let base = dirs::data_local_dir()
            .or_else(dirs::home_dir)
            .ok_or("Cannot determine home directory")?;
        base.join(".bastion_vault_gui")
    };
    if !root.exists() {
        fs::create_dir_all(&root).map_err(|e| {
            CommandError::from(format!("create data dir {root:?}: {e}"))
        })?;
    }
    Ok(root.join(KEYS_FILE_NAME))
}

/// Fetch-or-mint the 32-byte local key from the OS keychain. The
/// keychain holds the key hex-encoded so any operator-side
/// inspection tool (Windows Credential Manager, macOS Keychain
/// Access, secret-tool on Linux) renders as a printable string.
fn load_or_create_local_key() -> Result<[u8; KEY_LEN], CommandError> {
    let entry = keyring::Entry::new(SERVICE, LOCAL_KEY_ENTRY)
        .map_err(|e| CommandError::from(format!("keyring entry: {e}")))?;

    match entry.get_password() {
        Ok(hex_str) => {
            let decoded = hex::decode(hex_str.trim()).map_err(|e| {
                CommandError::from(format!(
                    "local-master-key in keychain is not valid hex: {e}"
                ))
            })?;
            if decoded.len() != KEY_LEN {
                return Err(CommandError::from(format!(
                    "local-master-key in keychain has wrong length: \
                     got {} bytes, expected {KEY_LEN}",
                    decoded.len()
                )));
            }
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(&decoded);
            Ok(out)
        }
        Err(keyring::Error::NoEntry) => {
            // First run on this machine — mint a fresh key.
            let mut key = [0u8; KEY_LEN];
            rand::rng().fill_bytes(&mut key);
            entry
                .set_password(&hex::encode(key))
                .map_err(|e| CommandError::from(format!("keyring store: {e}")))?;
            Ok(key)
        }
        Err(e) => Err(CommandError::from(format!("keyring read: {e}"))),
    }
}

/// Encrypt the given plaintext with the local key, producing a blob
/// shaped `MAGIC || nonce(12) || ciphertext+tag`.
fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, CommandError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        CommandError::from(format!("vault-keys AEAD encrypt: {e}"))
    })?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(blob: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, CommandError> {
    if blob.len() < MAGIC.len() + NONCE_LEN {
        return Err(CommandError::from(
            "vault-keys file is truncated".to_string(),
        ));
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(CommandError::from(
            "vault-keys file has unrecognised magic header — \
             refusing to decode (format upgrade needed?)"
                .to_string(),
        ));
    }
    let nonce_start = MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, &blob[nonce_end..])
        .map_err(|e| CommandError::from(format!("vault-keys AEAD decrypt: {e}")))
}

fn load_contents() -> Result<FileContents, CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(FileContents {
            version: 1,
            vaults: Default::default(),
        });
    }
    let key = load_or_create_local_key()?;
    let blob = fs::read(&path)
        .map_err(|e| CommandError::from(format!("read {path:?}: {e}")))?;
    let plaintext = decrypt(&blob, &key)?;
    let parsed: FileContents = serde_json::from_slice(&plaintext).map_err(|e| {
        CommandError::from(format!("parse vault-keys JSON: {e}"))
    })?;
    Ok(parsed)
}

fn save_contents(contents: &FileContents) -> Result<(), CommandError> {
    let key = load_or_create_local_key()?;
    let plaintext = serde_json::to_vec(contents)
        .map_err(|e| CommandError::from(format!("serialize vault-keys JSON: {e}")))?;
    let blob = encrypt(&plaintext, &key)?;

    // Write atomically via tmp-then-rename so a crash mid-write
    // can't leave the file in a partial-ciphertext state that
    // would permanently lock out every vault.
    let path = keys_file_path()?;
    let tmp = path.with_extension("enc.tmp");
    let mut f = fs::File::create(&tmp)
        .map_err(|e| CommandError::from(format!("create {tmp:?}: {e}")))?;
    f.write_all(&blob)
        .map_err(|e| CommandError::from(format!("write {tmp:?}: {e}")))?;
    f.sync_all()
        .map_err(|e| CommandError::from(format!("sync {tmp:?}: {e}")))?;
    drop(f);
    fs::rename(&tmp, &path)
        .map_err(|e| CommandError::from(format!("rename {tmp:?} → {path:?}: {e}")))?;
    Ok(())
}

// ── Public API ─────────────────────────────────────────────────────

/// Read the unseal key for `vault_id`. Returns `None` if no entry
/// exists — the caller should treat that as "this vault has no
/// saved keys, prompt the operator."
pub fn get_unseal_key(vault_id: &str) -> Result<Option<String>, CommandError> {
    migrate_legacy_if_needed(vault_id)?;
    let contents = load_contents()?;
    Ok(contents
        .vaults
        .get(vault_id)
        .map(|k| k.unseal_key_hex.clone()))
}

/// Persist the unseal key (hex-encoded) for `vault_id`. Idempotent —
/// overwrites any prior value under the same id.
pub fn store_unseal_key(vault_id: &str, unseal_key_hex: &str) -> Result<(), CommandError> {
    if vault_id.trim().is_empty() {
        return Err(CommandError::from(
            "store_unseal_key: vault_id must be non-empty".to_string(),
        ));
    }
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let entry = contents.vaults.entry(vault_id.to_string()).or_insert(VaultKeys {
        unseal_key_hex: String::new(),
        root_token: String::new(),
        created_at: now_unix(),
    });
    entry.unseal_key_hex = unseal_key_hex.to_string();
    save_contents(&contents)
}

/// Read the root token saved at init time for `vault_id`.
pub fn get_root_token(vault_id: &str) -> Result<Option<String>, CommandError> {
    migrate_legacy_if_needed(vault_id)?;
    let contents = load_contents()?;
    Ok(contents
        .vaults
        .get(vault_id)
        .map(|k| k.root_token.clone()))
}

/// Persist the root token for `vault_id`. Same idempotent semantics
/// as `store_unseal_key`.
pub fn store_root_token(vault_id: &str, root_token: &str) -> Result<(), CommandError> {
    if vault_id.trim().is_empty() {
        return Err(CommandError::from(
            "store_root_token: vault_id must be non-empty".to_string(),
        ));
    }
    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let entry = contents.vaults.entry(vault_id.to_string()).or_insert(VaultKeys {
        unseal_key_hex: String::new(),
        root_token: String::new(),
        created_at: now_unix(),
    });
    entry.root_token = root_token.to_string();
    save_contents(&contents)
}

/// Drop the record for `vault_id` entirely — used by
/// `reset_vault`-style flows that need to forget a specific vault
/// without affecting the others in the keystore.
pub fn remove_vault(vault_id: &str) -> Result<(), CommandError> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let mut contents = load_contents()?;
    if contents.vaults.remove(vault_id).is_none() {
        return Ok(());
    }
    // If the keystore is now empty, remove the file entirely — a
    // leftover empty file would still require the local key to
    // decrypt and buys nothing.
    if contents.vaults.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    save_contents(&contents)
}

/// Blow away the whole keystore file + the local key. Used by
/// "reset everything" paths. Best-effort on errors so a partial
/// state still ends up closer to "nothing cached" than to "stuck
/// file we can't rewrite."
pub fn wipe_all() -> Result<(), CommandError> {
    if let Ok(path) = keys_file_path() {
        let _ = fs::remove_file(path);
    }
    if let Ok(entry) = keyring::Entry::new(SERVICE, LOCAL_KEY_ENTRY) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

/// Legacy-slot migration. If the old single-entry keychain slots
/// still hold values AND we haven't already populated the target
/// vault_id in the file, copy them over then delete the legacy
/// slots. Safe to call on every read — the check below is cheap
/// after the first run.
fn migrate_legacy_if_needed(vault_id: &str) -> Result<(), CommandError> {
    use crate::secure_store;

    let legacy_unseal = secure_store::get_unseal_key()?;
    let legacy_token = secure_store::get_root_token()?;
    if legacy_unseal.is_none() && legacy_token.is_none() {
        return Ok(());
    }

    let mut contents = load_contents().unwrap_or_default();
    if contents.version == 0 {
        contents.version = 1;
    }
    let already = contents.vaults.contains_key(vault_id);
    if !already {
        let entry = contents
            .vaults
            .entry(vault_id.to_string())
            .or_insert(VaultKeys {
                unseal_key_hex: String::new(),
                root_token: String::new(),
                created_at: now_unix(),
            });
        if let Some(k) = legacy_unseal {
            entry.unseal_key_hex = k;
        }
        if let Some(t) = legacy_token {
            entry.root_token = t;
        }
        save_contents(&contents)?;
    }

    // Regardless of whether we copied (another vault may have
    // already taken the legacy slot), purge the legacy entries so
    // they don't leak into the next switch.
    let _ = secure_store::delete_all_keys();
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_isolated_data_dir<F: FnOnce() -> R, R>(f: F) -> R {
        // Route `data_dir()` at a fresh tempdir for the test run
        // via the BV_GUI_DATA_DIR_OVERRIDE env var that
        // `embedded::data_dir()` reads (added for testability).
        let tmp = tempdir_path("bv-keystore-test");
        let prev = std::env::var("BV_GUI_DATA_DIR_OVERRIDE").ok();
        std::env::set_var("BV_GUI_DATA_DIR_OVERRIDE", tmp.to_str().unwrap());
        let r = f();
        match prev {
            Some(v) => std::env::set_var("BV_GUI_DATA_DIR_OVERRIDE", v),
            None => std::env::remove_var("BV_GUI_DATA_DIR_OVERRIDE"),
        }
        let _ = fs::remove_dir_all(&tmp);
        r
    }

    fn tempdir_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        p.push(format!("{tag}-{}", hex::encode(random)));
        p
    }

    #[test]
    fn encrypt_decrypt_roundtrips() {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        let blob = encrypt(b"hello world", &key).unwrap();
        assert_eq!(&blob[..4], MAGIC);
        assert!(blob.len() > 4 + NONCE_LEN);
        let plain = decrypt(&blob, &key).unwrap();
        assert_eq!(&plain, b"hello world");
    }

    #[test]
    fn decrypt_rejects_wrong_magic() {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        let mut blob = encrypt(b"x", &key).unwrap();
        blob[0] = b'X';
        let err = decrypt(&blob, &key).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("magic"));
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let mut k1 = [0u8; KEY_LEN];
        let mut k2 = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut k1);
        rand::rng().fill_bytes(&mut k2);
        let blob = encrypt(b"x", &k1).unwrap();
        assert!(decrypt(&blob, &k2).is_err());
    }

    #[test]
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "macos", target_os = "linux")),
        ignore
    )]
    fn per_vault_roundtrip_isolates_ids() {
        with_isolated_data_dir(|| {
            // Clean any stale keychain state from prior runs.
            let _ = wipe_all();

            store_unseal_key("vault-a", "aaaa1111").unwrap();
            store_root_token("vault-a", "tok-a").unwrap();
            store_unseal_key("vault-b", "bbbb2222").unwrap();
            store_root_token("vault-b", "tok-b").unwrap();

            assert_eq!(get_unseal_key("vault-a").unwrap().as_deref(), Some("aaaa1111"));
            assert_eq!(get_unseal_key("vault-b").unwrap().as_deref(), Some("bbbb2222"));
            assert_eq!(get_root_token("vault-a").unwrap().as_deref(), Some("tok-a"));
            assert_eq!(get_root_token("vault-b").unwrap().as_deref(), Some("tok-b"));

            remove_vault("vault-a").unwrap();
            assert!(get_unseal_key("vault-a").unwrap().is_none());
            assert_eq!(get_unseal_key("vault-b").unwrap().as_deref(), Some("bbbb2222"));

            // Cleanup — remove the final vault so the keychain
            // entry we minted doesn't leak across CI test runs.
            remove_vault("vault-b").unwrap();
            let _ = wipe_all();
        });
    }
}
