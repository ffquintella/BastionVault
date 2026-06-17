use std::path::PathBuf;

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

pub use crate::utils::string::{ensure_no_leading_slash, ensure_no_trailing_slash, ensure_trailing_slash};

pub fn sanitize_path(s: &str) -> String {
    ensure_no_trailing_slash(&ensure_no_leading_slash(s))
}

/// Marker prefix on an encrypted token-helper file. A file lacking this
/// prefix is treated as a legacy plaintext token (see `read_persisted_token`)
/// so existing deployments keep working until their next login re-writes the
/// file encrypted.
const TOKEN_ENC_PREFIX: &str = "BVTOK1:";
/// Additional authenticated data — also the HKDF `info`, so the key and the
/// AEAD are bound to this exact purpose and version.
const TOKEN_AAD: &[u8] = b"bastionvault.cli.token-helper.v1";
const XCHACHA_NONCE_LEN: usize = 24;

/// Resolve the path for the on-disk token helper. Honors `$BVAULT_TOKEN_FILE`
/// for deployments that pin the location (e.g. the puppet-bastionvault
/// wrapper sets it to a per-user file under a bind-mounted volume so the
/// token survives container restarts); otherwise falls back to the
/// HashiCorp Vault convention `~/.vault-token`.
///
/// Returns `None` when no path can be determined (no env override, no
/// `$HOME`). Callers treat that as "skip persistence silently" rather than
/// failing the command.
pub fn token_helper_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BVAULT_TOKEN_FILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".vault-token"))
}

/// Read this machine's stable identifier. The derived AEAD key is bound to
/// it, so a token file copied to another host (or lifted from a backup and
/// restored elsewhere) will not decrypt. Linux uses the systemd/dbus
/// machine-id; macOS reads the hardware `IOPlatformUUID`.
fn machine_id() -> Option<String> {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let Some(idx) = line.find("IOPlatformUUID") else {
                        continue;
                    };
                    if let Some(eq) = line[idx..].find('=') {
                        let val = line[idx + eq + 1..].trim().trim_matches('"');
                        if !val.is_empty() {
                            return Some(val.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Derive the 32-byte AEAD key for this machine. `None` when no machine id is
/// available (caller falls back to plaintext storage).
fn machine_key() -> Option<[u8; 32]> {
    let id = machine_id()?;
    let hk = Hkdf::<Sha256>::new(None, id.as_bytes());
    let mut key = [0u8; 32];
    // expand only fails for absurd output lengths; 32 bytes always succeeds.
    hk.expand(TOKEN_AAD, &mut key).ok()?;
    Some(key)
}

/// Encrypt `token` under `key`, returning the `BVTOK1:` prefixed,
/// base64-encoded `nonce || ciphertext` line written to disk.
fn encrypt_with_key(token: &str, key: &[u8; 32]) -> Option<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: token.as_bytes(), aad: TOKEN_AAD },
        )
        .ok()?;
    let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Some(format!(
        "{TOKEN_ENC_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    ))
}

/// Reverse of `encrypt_with_key`. Returns `None` on any malformed input or
/// authentication failure (wrong machine, tampered file).
fn decrypt_with_key(contents: &str, key: &[u8; 32]) -> Option<String> {
    let b64 = contents.trim().strip_prefix(TOKEN_ENC_PREFIX)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    if blob.len() <= XCHACHA_NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = blob.split_at(XCHACHA_NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ciphertext, aad: TOKEN_AAD },
        )
        .ok()?;
    let s = String::from_utf8(plaintext).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Read a previously persisted token (trailing whitespace trimmed). Files
/// written by current builds are machine-key encrypted (`BVTOK1:` prefix);
/// files without the prefix are read as legacy plaintext so an in-place
/// upgrade keeps working until the next login re-encrypts. Errors —
/// including the common `NotFound` case — collapse to `None` so the caller
/// can fall through to other token sources without noise.
pub fn read_persisted_token() -> Option<String> {
    let path = token_helper_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with(TOKEN_ENC_PREFIX) {
        // Encrypted form. If the machine key is gone or the file does not
        // authenticate (copied from another host, corrupted), there is no
        // usable token here — fall through to None rather than returning
        // ciphertext as if it were a token.
        return machine_key().and_then(|key| decrypt_with_key(trimmed, &key));
    }
    Some(trimmed.to_string())
}

/// Persist a token to the helper path with 0600 permissions on Unix. The
/// token is encrypted at rest under a key derived from this machine's id, so
/// the file is unusable if copied off the host or lifted from a backup. If no
/// machine id is available the token is written in plaintext (legacy
/// behavior) and a warning is logged — persistence must not silently fail.
///
/// Best effort: any I/O failure (e.g. read-only volume, missing parent dir)
/// is returned to the caller so they can surface a warning, but does NOT
/// abort the surrounding command — the token is still usable from this shell
/// via the printed value.
pub fn write_persisted_token(token: &str) -> std::io::Result<PathBuf> {
    let path = token_helper_path()
        .ok_or_else(|| std::io::Error::other("no token helper path"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let contents = match machine_key() {
        Some(mut key) => {
            let enc = encrypt_with_key(token, &key);
            key.zeroize();
            match enc {
                Some(c) => c,
                None => {
                    log::warn!(
                        "token helper: encryption failed; writing token in plaintext"
                    );
                    token.to_string()
                }
            }
        }
        None => {
            log::warn!(
                "token helper: no machine id available; writing token in plaintext"
            );
            token.to_string()
        }
    };

    std::fs::write(&path, contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = test_key();
        let token = "be170b06-4157-1f92-9add-603cae36ee53";
        let enc = encrypt_with_key(token, &key).expect("encrypt");
        assert!(enc.starts_with(TOKEN_ENC_PREFIX));
        assert!(!enc.contains(token), "ciphertext must not leak the token");
        assert_eq!(decrypt_with_key(&enc, &key).as_deref(), Some(token));
    }

    #[test]
    fn ciphertext_is_nondeterministic() {
        let key = test_key();
        let a = encrypt_with_key("tok", &key).unwrap();
        let b = encrypt_with_key("tok", &key).unwrap();
        assert_ne!(a, b, "random nonce should make each ciphertext unique");
    }

    #[test]
    fn wrong_machine_key_fails_closed() {
        let enc = encrypt_with_key("tok", &test_key()).unwrap();
        assert_eq!(decrypt_with_key(&enc, &[9u8; 32]), None);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = test_key();
        let mut enc = encrypt_with_key("tok", &key).unwrap();
        // Flip the last base64 char to corrupt the AEAD tag.
        let last = enc.pop().unwrap();
        enc.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(decrypt_with_key(&enc, &key), None);
    }

    #[test]
    fn non_prefixed_input_is_not_decrypted() {
        // A legacy plaintext token has no prefix; decrypt should refuse it
        // (read_persisted_token handles the plaintext passthrough instead).
        assert_eq!(decrypt_with_key("plain-token", &test_key()), None);
    }
}
