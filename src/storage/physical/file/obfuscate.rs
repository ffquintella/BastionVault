//! Key-obfuscation decorator for `FileTarget`.
//!
//! When cloud targets are enabled with `obfuscate_keys = true`, every
//! vault key is rewritten to `HMAC-SHA256(target_salt, raw_key)` hex-
//! encoded before reaching the underlying provider. The idea — called
//! out in `features/cloud-storage-backend.md` § "Key-name handling" —
//! is that someone with bucket read access can see object counts,
//! sizes, and timestamps, but can no longer reverse the string
//! labels into meaningful vault paths.
//!
//! The `target_salt` itself is 32 random bytes generated on first use
//! and stored at a well-known un-obfuscated key (`_bvault_salt`)
//! under the wrapped target. Subsequent starts reuse the stored
//! salt, so vault keys are stable across restarts (same HMAC input
//! → same HMAC output).
//!
//! # What this decorator does NOT do
//!
//! `list(prefix)` is the hard problem. HMAC is a pseudo-random
//! function; once the key `sys/policy/admin` hashes to
//! `8a4f...e12c`, there is no way to enumerate `sys/policy/` as a
//! prefix without a separate manifest. We take the narrow approach:
//!
//!   * `list("")` works — returns every hashed key under the target.
//!     Useful for the rekey workflow (read each, re-write under a
//!     new salt, delete old) and for vault-wide audits.
//!
//!   * `list("<anything-non-empty>")` returns a specific error so
//!     operators who mix obfuscation with code paths that depend
//!     on prefix enumeration see a loud signal rather than a silent
//!     empty result.
//!
//! Operators who need full prefix-based list under obfuscation can
//! run with `obfuscate_keys = false` and accept that provider
//! metadata reveals vault shape. The two options are documented
//! side-by-side in the feature doc.
//!
//! # The rekey flow (design, not yet implemented as a CLI)
//!
//!   1. Construct the old target with the current salt.
//!   2. Construct a new target wrapping the same underlying provider
//!      but with a freshly-generated salt (stored at a temporary
//!      salt key).
//!   3. For each raw-hashed key returned by `old.list("")`:
//!      a. `old.read(raw_key)` — decrypt at the barrier above.
//!      b. `new.write(orig_key, value)` — re-encrypt under new salt.
//!      c. `old.delete(raw_key)`.
//!   4. Replace `_bvault_salt` with the new salt atomically.
//!
//! Step 3a requires knowing the original `orig_key`, which the
//! hash alone doesn't give us. So rekey either needs a one-time
//! migration manifest (built up during normal operation), or the
//! operator runs `operator migrate` through a non-obfuscated
//! intermediate target. The CLI implementation is deferred; the
//! library pieces (decorator, salt rotation, `list("")`) are all
//! present.

use std::{any::Any, sync::Arc};

use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;

use crate::errors::RvError;

use super::target::FileTarget;

type HmacSha256 = Hmac<Sha256>;

/// Storage key where the target salt lives inside the wrapped
/// target. Chosen to start with `_` so it sorts away from real
/// vault data, and to be recognisably a BastionVault marker.
pub const SALT_KEY: &str = "_bvault_salt";

/// Size of the salt. 32 bytes is more than enough to make
/// pre-computation infeasible, matches SHA-256's block size, and is
/// small enough to keep the bootstrap read cheap.
const SALT_BYTES: usize = 32;

#[derive(Debug)]
pub struct ObfuscatingTarget {
    inner: Arc<dyn FileTarget>,
    salt: [u8; SALT_BYTES],
}

impl ObfuscatingTarget {
    /// Construct an `ObfuscatingTarget` wrapping `inner`, bootstrapping
    /// the salt from the wrapped target's `_bvault_salt` key. If no
    /// salt exists yet, generate one and persist it. Runs on the
    /// current thread — callers in an async context should invoke
    /// through `spawn_blocking` so the I/O doesn't park the runtime.
    pub async fn bootstrap(inner: Arc<dyn FileTarget>) -> Result<Self, RvError> {
        let salt = match inner.read(SALT_KEY).await? {
            Some(existing) if existing.len() == SALT_BYTES => {
                let mut out = [0u8; SALT_BYTES];
                out.copy_from_slice(&existing);
                out
            }
            Some(bad) => {
                return Err(RvError::ErrString(format!(
                    "obfuscate: stored salt has wrong length ({} bytes, expected {})",
                    bad.len(),
                    SALT_BYTES
                )));
            }
            None => {
                // First boot against this target — mint a fresh salt.
                let mut bytes = [0u8; SALT_BYTES];
                rand::rng().fill(&mut bytes);
                inner.write(SALT_KEY, &bytes).await?;
                bytes
            }
        };
        Ok(Self { inner, salt })
    }

    /// Build an obfuscated target with a caller-supplied salt.
    /// Reserved for the rekey workflow and for tests — production
    /// code always flows through `bootstrap`.
    pub fn with_salt(inner: Arc<dyn FileTarget>, salt: [u8; SALT_BYTES]) -> Self {
        Self { inner, salt }
    }

    /// HMAC-SHA256 the raw vault key with the target salt; return
    /// hex-encoded so the output is safe to use as a filesystem
    /// path or an S3 object name.
    fn obfuscate(&self, raw: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.salt)
            .expect("HMAC accepts any key length");
        mac.update(raw.as_bytes());
        let tag = mac.finalize().into_bytes();
        hex_encode(&tag)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[maybe_async::maybe_async]
impl FileTarget for ObfuscatingTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        // Salt lookups pass through unobfuscated so the bootstrap
        // path can find the salt. No other key starts with a `_` in
        // vault use; collisions would surface as a clear error here.
        if key == SALT_KEY {
            return self.inner.read(key).await;
        }
        let hashed = self.obfuscate(key);
        self.inner.read(&hashed).await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        if key == SALT_KEY {
            return self.inner.write(key, value).await;
        }
        let hashed = self.obfuscate(key);
        self.inner.write(&hashed, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        if key == SALT_KEY {
            return self.inner.delete(key).await;
        }
        let hashed = self.obfuscate(key);
        self.inner.delete(&hashed).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.is_empty() {
            // Full enumeration: return raw hashed keys as stored in
            // the underlying target. Useful for the rekey workflow.
            // The salt marker is filtered out so it isn't mistaken
            // for a vault value by iterating callers.
            let mut keys = self.inner.list("").await?;
            keys.retain(|k| k.trim_end_matches('/') != SALT_KEY);
            return Ok(keys);
        }
        Err(RvError::ErrString(format!(
            "obfuscate: `list(\"{prefix}\")` is not supported when `obfuscate_keys = true` — \
             HMAC'd keys don't preserve prefix structure. Use `list(\"\")` for a full \
             enumeration (rekey workflow), or disable `obfuscate_keys` if the calling code \
             depends on prefix-based listing."
        )))
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        // Lock names get the same hashing treatment so two concurrent
        // writers of `sys/policy/admin` serialize through the same
        // per-key mutex on the underlying target.
        if lock_name == SALT_KEY {
            return self.inner.lock(lock_name).await;
        }
        let hashed = self.obfuscate(lock_name);
        self.inner.lock(&hashed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Small recording target for decorator tests. Stores bytes in
    /// a `BTreeMap` keyed by the exact key string it was handed —
    /// lets tests inspect whether the decorator actually hashed
    /// before calling through.
    #[derive(Debug, Default)]
    struct RecordingTarget {
        writes: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[maybe_async::maybe_async]
    impl FileTarget for RecordingTarget {
        async fn read(&self, k: &str) -> Result<Option<Vec<u8>>, RvError> {
            Ok(self.writes.lock().unwrap().get(k).cloned())
        }
        async fn write(&self, k: &str, v: &[u8]) -> Result<(), RvError> {
            self.writes.lock().unwrap().insert(k.to_string(), v.to_vec());
            Ok(())
        }
        async fn delete(&self, k: &str) -> Result<(), RvError> {
            self.writes.lock().unwrap().remove(k);
            Ok(())
        }
        async fn list(&self, _prefix: &str) -> Result<Vec<String>, RvError> {
            Ok(self.writes.lock().unwrap().keys().cloned().collect())
        }
        async fn lock(&self, _: &str) -> Result<Box<dyn Any + Send>, RvError> {
            Ok(Box::new(()))
        }
    }

    #[tokio::test]
    async fn bootstrap_generates_and_persists_salt() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let _ = ObfuscatingTarget::bootstrap(inner.clone()).await.unwrap();
        let salt_bytes = inner.read(SALT_KEY).await.unwrap().unwrap();
        assert_eq!(salt_bytes.len(), SALT_BYTES);
    }

    #[tokio::test]
    async fn bootstrap_reuses_existing_salt() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t1 = ObfuscatingTarget::bootstrap(inner.clone()).await.unwrap();
        let salt1 = t1.salt;

        let t2 = ObfuscatingTarget::bootstrap(inner.clone()).await.unwrap();
        assert_eq!(salt1, t2.salt, "second bootstrap must reuse the persisted salt");
    }

    #[tokio::test]
    async fn bootstrap_rejects_salt_of_wrong_length() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        // Manually stash a bad salt so bootstrap sees it.
        inner.write(SALT_KEY, b"too-short").await.unwrap();
        let err = ObfuscatingTarget::bootstrap(inner).await.unwrap_err();
        assert!(format!("{err}").contains("wrong length"));
    }

    #[tokio::test]
    async fn write_stores_under_hashed_key() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner.clone(), [7u8; SALT_BYTES]);
        t.write("sys/policy/admin", b"ciphertext").await.unwrap();

        let stored = inner.list("").await.unwrap();
        // Exactly one entry in the underlying target, and it is
        // NOT the plaintext key.
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0], "sys/policy/admin");
        assert_eq!(stored[0].len(), 64, "hex-encoded SHA-256 is 64 chars");
    }

    #[tokio::test]
    async fn read_after_write_roundtrips() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner, [7u8; SALT_BYTES]);
        t.write("sys/policy/admin", b"ciphertext").await.unwrap();
        let got = t.read("sys/policy/admin").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"ciphertext".as_slice()));
    }

    #[tokio::test]
    async fn different_salts_produce_different_keys() {
        let inner_a: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let inner_b: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let a = ObfuscatingTarget::with_salt(inner_a.clone(), [1u8; SALT_BYTES]);
        let b = ObfuscatingTarget::with_salt(inner_b.clone(), [2u8; SALT_BYTES]);
        a.write("foo", b"x").await.unwrap();
        b.write("foo", b"x").await.unwrap();
        let list_a = inner_a.list("").await.unwrap();
        let list_b = inner_b.list("").await.unwrap();
        assert_ne!(list_a[0], list_b[0]);
    }

    #[tokio::test]
    async fn delete_removes_via_hash() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner.clone(), [7u8; SALT_BYTES]);
        t.write("k", b"v").await.unwrap();
        assert_eq!(inner.list("").await.unwrap().len(), 1);
        t.delete("k").await.unwrap();
        assert_eq!(inner.list("").await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn salt_key_passes_through_unhashed() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner.clone(), [7u8; SALT_BYTES]);
        // Write arbitrary bytes at SALT_KEY — the decorator must not
        // apply HMAC to its own bootstrap key.
        t.write(SALT_KEY, b"rotated-salt").await.unwrap();
        let raw = inner.read(SALT_KEY).await.unwrap();
        assert_eq!(raw.as_deref(), Some(b"rotated-salt".as_slice()));
    }

    #[tokio::test]
    async fn list_empty_prefix_returns_hashed_keys_minus_salt() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        // Pre-populate the salt so bootstrap doesn't mint a fresh one.
        inner.write(SALT_KEY, &[9u8; SALT_BYTES]).await.unwrap();
        let t = ObfuscatingTarget::bootstrap(inner.clone()).await.unwrap();
        t.write("a", b"1").await.unwrap();
        t.write("b", b"2").await.unwrap();

        let listed = t.list("").await.unwrap();
        assert_eq!(listed.len(), 2, "salt marker must be filtered out");
        for k in &listed {
            assert_ne!(k, "a");
            assert_ne!(k, "b");
            assert_ne!(k, SALT_KEY);
        }
    }

    #[tokio::test]
    async fn list_non_empty_prefix_errors_clearly() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner, [7u8; SALT_BYTES]);
        let err = t.list("sys/").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not supported"), "got: {msg}");
        assert!(msg.contains("obfuscate_keys"), "got: {msg}");
    }

    #[tokio::test]
    async fn obfuscate_is_deterministic_per_salt() {
        let inner: Arc<dyn FileTarget> = Arc::new(RecordingTarget::default());
        let t = ObfuscatingTarget::with_salt(inner, [5u8; SALT_BYTES]);
        let h1 = t.obfuscate("sys/foo");
        let h2 = t.obfuscate("sys/foo");
        assert_eq!(h1, h2);
        let h3 = t.obfuscate("sys/bar");
        assert_ne!(h1, h3);
    }
}
