//! Password-encrypted full-vault backup / restore.
//!
//! Wraps the in-tree `bastion_vault::backup::{create,restore}` with an
//! outer password-based encryption envelope so the resulting file can
//! travel outside the vault (downloaded to the operator's disk,
//! emailed to a backup vault, etc.) without leaking the barrier HMAC
//! key. The inner blob is the same BVBK format used by the server-
//! side `/sys/raw/backup` HTTP endpoint and `bvault operator backup`
//! CLI; the outer envelope is independent.
//!
//! Wire format (little-endian length prefixes everywhere):
//!   - magic       : 8  bytes — `BVBKP1\0\0`
//!   - argon2_m_kib: 4  bytes — Argon2id memory cost (KiB)
//!   - argon2_t   : 4  bytes — Argon2id time cost (iterations)
//!   - argon2_p   : 4  bytes — Argon2id parallelism
//!   - salt       : 16 bytes
//!   - nonce      : 12 bytes  (ChaCha20-Poly1305 IETF nonce)
//!   - ciphertext : N  bytes  (inner BVBK blob, AEAD-encrypted)
//!   - tag        : 16 bytes  (Poly1305 tag, appended by the AEAD)
//!
//! Both export and restore require the caller's token to carry the
//! `root` policy. Password length ≥16 chars is enforced both
//! client- and server-side.

use std::io::{Cursor, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, TryRngCore};
use tauri::State;
use tokio::fs;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

const MIN_PASSWORD_LEN: usize = 16;
const MAGIC: &[u8; 8] = b"BVBKP1\0\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 56

// Argon2id parameters — 64 MiB / 3 iterations / 4 lanes. A
// reasonable balance between operator latency on the GUI and
// resistance to offline GPU cracking. The values are written into
// the file header so future tuning doesn't break old backups.
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

/// Look up the caller's policies and refuse if `root` is missing.
async fn require_root(state: &State<'_, AppState>) -> Result<(), CommandError> {
    use bastion_vault::logical::{Operation, Request};
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().ok_or("Not authenticated")?;
    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = "auth/token/lookup-self".into();
    req.client_token = token;
    let resp = core
        .handle_request(&mut req)
        .await
        .map_err(CommandError::from)?
        .ok_or("token lookup returned empty response")?;
    let policies: Vec<String> = resp
        .data
        .as_ref()
        .and_then(|d| d.get("policies"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if policies.iter().any(|p| p == "root") {
        Ok(())
    } else {
        Err("backup operations require the `root` policy".into())
    }
}

fn validate_password(password: &str) -> Result<(), CommandError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        Err(format!("backup password must be at least {MIN_PASSWORD_LEN} characters").into())
    } else {
        Ok(())
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CommandError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| CommandError::from(format!("argon2 params: {e}")))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    kdf.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CommandError::from(format!("argon2 derive: {e}")))?;
    Ok(key)
}

fn write_envelope(
    payload: &[u8],
    password: &str,
    out: &mut Vec<u8>,
) -> Result<(), CommandError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| CommandError::from(format!("rng: {e}")))?;
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| CommandError::from(format!("rng: {e}")))?;
    let key_bytes = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    // AAD = the file header (magic + argon2 params + salt + nonce) so
    // tampering with any of those bytes invalidates the AEAD tag.
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&ARGON2_M_KIB.to_le_bytes());
    header.extend_from_slice(&ARGON2_T.to_le_bytes());
    header.extend_from_slice(&ARGON2_P.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: payload, aad: &header })
        .map_err(|e| CommandError::from(format!("aead encrypt: {e}")))?;
    out.write_all(&header).ok();
    out.write_all(&ciphertext).ok();
    Ok(())
}

fn read_envelope(blob: &[u8], password: &str) -> Result<Vec<u8>, CommandError> {
    if blob.len() < HEADER_LEN + 16 {
        return Err("backup file is truncated".into());
    }
    let (header, ciphertext) = blob.split_at(HEADER_LEN);
    if &header[..8] != MAGIC {
        return Err("backup file has wrong magic (not a BastionVault password-wrapped backup)".into());
    }
    let m_kib = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let t = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let p = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let salt = &header[20..20 + SALT_LEN];
    let nonce_bytes = &header[20 + SALT_LEN..20 + SALT_LEN + NONCE_LEN];
    // Use the params from the file so backups taken at different
    // settings still restore correctly.
    let params = Params::new(m_kib, t, p, Some(32))
        .map_err(|e| CommandError::from(format!("argon2 params from file: {e}")))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    kdf.hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| CommandError::from(format!("argon2 derive: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: header })
        .map_err(|_| CommandError::from(
            "decrypt failed — wrong password or corrupted file".to_string(),
        ))
}

/// Generate a full vault backup, wrap it in the password envelope,
/// and write the result to `path`. Returns the number of vault
/// entries that were captured.
#[tauri::command]
pub async fn backup_export(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> CmdResult<u64> {
    require_root(&state).await?;
    validate_password(&password)?;
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard
        .as_ref()
        .ok_or("Vault not open")?
        .clone();
    drop(vault_guard);
    let core = vault.core.load();
    let hmac_key = core
        .barrier
        .derive_hmac_key()
        .map_err(|e| CommandError::from(format!("derive hmac key: {e}")))?;
    let mut inner = Vec::new();
    let entries = bastion_vault::backup::create::create_backup(
        core.physical.as_ref(),
        &hmac_key,
        &mut inner,
        true, // compress — the password envelope can't compress past AEAD, so do it underneath
    )
    .await
    .map_err(|e| CommandError::from(format!("create backup: {e}")))?;
    let mut envelope = Vec::with_capacity(inner.len() + HEADER_LEN + 16);
    write_envelope(&inner, &password, &mut envelope)?;
    fs::write(&path, &envelope)
        .await
        .map_err(|e| CommandError::from(format!("write {path}: {e}")))?;
    Ok(entries)
}

/// Read a password-wrapped backup file from `path`, decrypt with
/// `password`, and restore into the open vault. Returns the entry
/// count restored.
#[tauri::command]
pub async fn backup_restore(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> CmdResult<u64> {
    require_root(&state).await?;
    validate_password(&password)?;
    let blob = fs::read(&path)
        .await
        .map_err(|e| CommandError::from(format!("read {path}: {e}")))?;
    let inner = read_envelope(&blob, &password)?;
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard
        .as_ref()
        .ok_or("Vault not open")?
        .clone();
    drop(vault_guard);
    let core = vault.core.load();
    let hmac_key = core
        .barrier
        .derive_hmac_key()
        .map_err(|e| CommandError::from(format!("derive hmac key: {e}")))?;
    let mut reader = Cursor::new(inner);
    let count = bastion_vault::backup::restore::restore_backup(
        core.physical.as_ref(),
        &hmac_key,
        &mut reader,
    )
    .await
    .map_err(|e| CommandError::from(format!("restore backup: {e}")))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let pw = "this-password-is-16+chars-long";
        let mut env = Vec::new();
        write_envelope(payload, pw, &mut env).unwrap();
        let out = read_envelope(&env, pw).unwrap();
        assert_eq!(out.as_slice(), payload);
    }

    #[test]
    fn wrong_password_fails() {
        let mut env = Vec::new();
        write_envelope(b"data", "this-password-is-16+chars-long", &mut env).unwrap();
        let err = read_envelope(&env, "this-password-is-also-fine-yes").unwrap_err();
        assert!(format!("{err:?}").contains("wrong password"));
    }

    #[test]
    fn truncated_blob_fails() {
        let err = read_envelope(b"too short", "this-password-is-16+chars-long").unwrap_err();
        assert!(format!("{err:?}").contains("truncated"));
    }

    #[test]
    fn short_password_rejected() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("0123456789012345").is_ok()); // exactly 16
    }
}
