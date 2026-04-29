//! `bvault operator cloud-target rekey-salt` — rotate the
//! per-target obfuscation salt.
//!
//! Drives the rekey workflow that was deferred when the obfuscation
//! decorator first shipped. The decorator's
//! [`with_salt`](crate::storage::physical::file::obfuscate::ObfuscatingTarget::with_salt)
//! constructor was the only library piece exposed; this CLI is the
//! orchestrator on top of it.
//!
//! # How it works
//!
//! The per-target plaintext-key manifest is what makes salt rotation
//! possible. Without it the HMAC alone can't be inverted to recover
//! the original key, so rotating the salt would require either a
//! full wipe + restore or an offline key map that no operator wants
//! to maintain. With the manifest in place every vault key is
//! recoverable from the target's own state.
//!
//! Rekey runs against an **unconfigured** target — no live vault
//! attached — and works at the underlying [`FileTarget`] layer:
//!
//! 1. Load `_bvault_salt` (old salt) and `_bvault_manifest` (the
//!    plaintext key set) directly from the underlying provider.
//! 2. Mint a fresh 32-byte salt.
//! 3. For each plaintext key in the manifest:
//!    a. Compute `old_hash = HMAC(old_salt, key)`.
//!    b. Read the ciphertext blob at `old_hash`.
//!    c. Compute `new_hash = HMAC(new_salt, key)`.
//!    d. Write the ciphertext blob at `new_hash`.
//! 4. Atomically replace `_bvault_salt` with the new value.
//! 5. Delete every old hash position so the bucket isn't littered
//!    with orphaned blobs.
//!
//! Steps 3–5 are crash-safe in the sense that an interruption
//! between any two leaves the target in a *recoverable* state: the
//! old salt is still in place until step 4 succeeds, so the vault
//! can boot against the old positions; after step 4 the new
//! positions are authoritative; step 5 cleanup is best-effort and
//! safe to re-run.
//!
//! # Operator workflow
//!
//! 1. **Seal the vault** so no concurrent writes race the rekey.
//! 2. Run `bvault operator cloud-target rekey-salt` with the same
//!    `--target-config` keys you'd hand to `operator backup` /
//!    `operator restore`. The rekey doesn't go through the vault
//!    process — it talks to the underlying provider directly.
//! 3. Re-unseal the vault. New writes immediately use the rotated
//!    salt; existing data is still there, just under new hash
//!    positions.

use std::collections::HashMap;
use std::sync::Arc;

use clap::Parser;
use serde_json::Value;

use crate::{
    cli::command::CommandExecutor,
    errors::RvError,
    storage::physical::file::{
        obfuscate::{ObfuscatingTarget, MANIFEST_KEY, SALT_BYTES, SALT_KEY},
        target::FileTarget,
    },
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Rotate the obfuscation salt of a cloud storage target",
    long_about = r#"Rotates the per-target obfuscation salt that protects vault key
names against an attacker with bucket-read access to your cloud
storage provider.

The vault must be sealed during the rekey so no concurrent writes
race the rotation. The CLI talks to the underlying provider
directly using the same --target-config keys you'd hand to
`operator backup` / `operator restore`.

Rekey workflow:

  1. Seal the vault.
  2. Run this command.
  3. Unseal the vault. New writes use the rotated salt; existing
     data has been re-written under new hash positions.

Example — S3:

  $ bvault operator cloud-target rekey-salt \
      --target-type s3 \
      --target-config bucket=mybucket \
      --target-config region=us-east-1 \
      --target-config credentials_ref=keychain:bv-cloud/s3 \
      --confirm

Use --dry-run to print the manifest size and intended action
without touching any data.
"#
)]
pub struct CloudTargetRekey {
    /// Underlying target kind (e.g. `s3`, `onedrive`, `gdrive`,
    /// `dropbox`). Same value you'd pass as `target=` in a vault
    /// config or as `--backend-config target=` to `operator backup`.
    #[arg(long)]
    target_type: String,

    /// Target config as `key=value` pairs (one per flag). Same
    /// shape `operator backup --backend-config` accepts.
    #[arg(
        long = "target-config",
        value_name = "key=value",
        action = clap::ArgAction::Append
    )]
    target_config: Vec<String>,

    /// Print the planned action and the manifest size without
    /// touching any data.
    #[arg(long)]
    dry_run: bool,

    /// Required for any non-dry-run mutating operation. Acts as the
    /// "yes I know the vault is sealed and I have a backup"
    /// confirmation gate.
    #[arg(long)]
    confirm: bool,
}

fn parse_config_pairs(pairs: &[String]) -> Result<HashMap<String, Value>, RvError> {
    let mut conf = HashMap::new();
    for pair in pairs {
        let (key, val) = pair
            .split_once('=')
            .ok_or(RvError::ErrConfigLoadFailed)?;
        let value = if let Ok(n) = val.parse::<u64>() {
            Value::Number(n.into())
        } else if val == "true" {
            Value::Bool(true)
        } else if val == "false" {
            Value::Bool(false)
        } else {
            Value::String(val.to_string())
        };
        conf.insert(key.to_string(), value);
    }
    Ok(conf)
}

impl CommandExecutor for CloudTargetRekey {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        if !self.dry_run && !self.confirm {
            return Err(RvError::ErrString(
                "rekey is destructive — pass --confirm (or --dry-run) once you've sealed \
                 the vault and have a backup."
                    .into(),
            ));
        }

        let mut conf = parse_config_pairs(&self.target_config)?;
        // Force `obfuscate_keys` to false here — we want raw
        // FileTarget access against the underlying provider, not a
        // pre-bootstrapped ObfuscatingTarget. We construct the
        // obfuscating layer ourselves with the right salt at each
        // step.
        conf.insert("obfuscate_keys".into(), Value::Bool(false));
        conf.insert("target".into(), Value::String(self.target_type.clone()));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let underlying = build_underlying_target(&conf).await?;
            run_rekey(underlying, self.dry_run).await
        })
    }
}

/// Construct the bare provider target (no obfuscation, no caching).
/// Goes through `FileBackend::new` and then unwraps the `target`
/// field — the simplest way to reuse all the per-provider config
/// parsing the engine already does.
async fn build_underlying_target(
    conf: &HashMap<String, Value>,
) -> Result<Arc<dyn FileTarget>, RvError> {
    use crate::storage::physical::file::FileBackend;
    let mut conf = conf.clone();
    // Disable the cache decorator too — we want straight reads /
    // writes during rekey, no stale-read window.
    conf.insert("cache".into(), Value::Bool(false));
    let backend = FileBackend::new(&conf)?;
    Ok(backend.target_arc())
}

async fn run_rekey(
    underlying: Arc<dyn FileTarget>,
    dry_run: bool,
) -> Result<(), RvError> {
    use rand::RngExt;

    // Step 1: load current salt + manifest.
    let old_salt_bytes = underlying
        .read(SALT_KEY)
        .await?
        .ok_or_else(|| {
            RvError::ErrString(format!(
                "rekey: target has no `{SALT_KEY}` — was it ever obfuscated?"
            ))
        })?;
    if old_salt_bytes.len() != SALT_BYTES {
        return Err(RvError::ErrString(format!(
            "rekey: stored salt is {} bytes, expected {SALT_BYTES}",
            old_salt_bytes.len()
        )));
    }
    let mut old_salt = [0u8; SALT_BYTES];
    old_salt.copy_from_slice(&old_salt_bytes);
    let old_target = ObfuscatingTarget::with_salt(underlying.clone(), old_salt);

    let manifest = old_target.read_manifest().await?;
    println!(
        "rekey: target carries {} key(s) under the current salt",
        manifest.len()
    );
    if dry_run {
        println!("rekey: --dry-run — no data will be touched");
        return Ok(());
    }

    // Step 2: mint a fresh salt.
    let mut new_salt = [0u8; SALT_BYTES];
    rand::rng().fill(&mut new_salt);
    let new_target = ObfuscatingTarget::with_salt(underlying.clone(), new_salt);
    println!("rekey: minted fresh salt");

    // Step 3: re-write each key under the new salt. Track the
    // (old_hash, new_hash) pairs so step 5 cleanup can drop the
    // old positions only after step 4 swaps the active salt.
    let mut renamed: Vec<(String, String)> = Vec::with_capacity(manifest.len());
    let mut copied = 0u64;
    for (idx, key) in manifest.iter().enumerate() {
        if (idx + 1) % 50 == 0 || idx == 0 {
            println!("rekey: re-writing {}/{}", idx + 1, manifest.len());
        }
        let old_hash = old_target.obfuscate(key);
        let new_hash = new_target.obfuscate(key);
        if old_hash == new_hash {
            // Identical hash means the salt didn't actually change
            // for this key (astronomically unlikely with 32-byte
            // salts; defend against the edge case anyway).
            continue;
        }
        let blob = match underlying.read(&old_hash).await? {
            Some(b) => b,
            None => {
                // Manifest claims this key but the underlying
                // storage has no blob — log and continue rather
                // than fail the whole rekey. The manifest will be
                // refreshed on the next vault write of this key.
                eprintln!(
                    "rekey: warning — manifest entry `{key}` has no underlying blob; skipping"
                );
                continue;
            }
        };
        underlying.write(&new_hash, &blob).await?;
        renamed.push((old_hash, new_hash));
        copied += 1;
    }
    println!("rekey: re-wrote {copied} entrie(s) under the new salt");

    // Step 4: atomically swap the active salt + persist a fresh
    // manifest under the new layout. Both writes go through
    // `underlying.write` (not the obfuscating wrapper) so the
    // hashing rules don't re-apply to the marker keys.
    underlying
        .write(SALT_KEY, &new_salt)
        .await
        .map_err(|e| RvError::ErrString(format!("rekey: swap salt: {e}")))?;
    let new_manifest_bytes =
        crate::storage::physical::file::obfuscate::encode_manifest(&manifest);
    underlying
        .write(MANIFEST_KEY, &new_manifest_bytes)
        .await
        .map_err(|e| RvError::ErrString(format!("rekey: rewrite manifest: {e}")))?;
    println!("rekey: swapped active salt — vault can now unseal against the new layout");

    // Step 5: best-effort cleanup of the old hash positions. A
    // failure here leaves orphaned blobs but doesn't break the
    // vault — operators can re-run the cleanup with another rekey
    // pass if they want, or live with the duplicate storage cost.
    let mut orphans = 0u64;
    for (old_hash, _) in &renamed {
        if let Err(e) = underlying.delete(old_hash).await {
            eprintln!("rekey: warning — orphan cleanup of `{old_hash}` failed: {e:?}");
            orphans += 1;
        }
    }
    if orphans > 0 {
        println!(
            "rekey: {orphans} orphan blob(s) left under the old salt (re-run the rekey to retry cleanup)"
        );
    } else {
        println!("rekey: all old-salt positions cleaned up");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::physical::file::local::LocalFsTarget;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "bvault-rekey-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// End-to-end rekey against a local-fs target. Plant data under
    /// the OLD salt, run `run_rekey`, confirm reads under the NEW
    /// salt (loaded back from the rotated `_bvault_salt`) return the
    /// same bytes and that the old hash positions are gone.
    #[tokio::test]
    async fn rekey_round_trip_against_local_fs() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let underlying: Arc<dyn FileTarget> =
            Arc::new(LocalFsTarget::new(dir.clone()).unwrap());

        // 1. Bootstrap the obfuscating target — mints a fresh salt.
        let old =
            ObfuscatingTarget::bootstrap(underlying.clone()).await.unwrap();
        let old_salt = *old.salt_bytes();
        old.write("kv/a", b"value-a").await.unwrap();
        old.write("kv/b", b"value-b").await.unwrap();
        old.write("sys/policy/admin", b"value-admin").await.unwrap();

        // Snapshot the OLD hash positions for the cleanup check.
        let old_hash_a = old.obfuscate("kv/a");
        let old_hash_b = old.obfuscate("kv/b");
        let old_hash_admin = old.obfuscate("sys/policy/admin");

        // 2. Run the rekey.
        run_rekey(underlying.clone(), false).await.unwrap();

        // 3. Reads through a fresh bootstrap (which now picks up
        //    the rotated salt) must return the same bytes.
        let after =
            ObfuscatingTarget::bootstrap(underlying.clone()).await.unwrap();
        assert_ne!(*after.salt_bytes(), old_salt, "salt must have rotated");
        assert_eq!(
            after.read("kv/a").await.unwrap().as_deref(),
            Some(b"value-a".as_slice())
        );
        assert_eq!(
            after.read("kv/b").await.unwrap().as_deref(),
            Some(b"value-b".as_slice())
        );
        assert_eq!(
            after.read("sys/policy/admin").await.unwrap().as_deref(),
            Some(b"value-admin".as_slice())
        );

        // 4. Old hash positions must have been cleaned up.
        assert!(underlying.read(&old_hash_a).await.unwrap().is_none());
        assert!(underlying.read(&old_hash_b).await.unwrap().is_none());
        assert!(underlying.read(&old_hash_admin).await.unwrap().is_none());

        // 5. Manifest under the new salt must list every key.
        let mut manifest = after.read_manifest().await.unwrap();
        manifest.sort();
        assert_eq!(
            manifest,
            vec!["kv/a", "kv/b", "sys/policy/admin"]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--dry-run` must touch nothing: salt unchanged, manifest
    /// unchanged, no extra entries written.
    #[tokio::test]
    async fn rekey_dry_run_is_a_noop() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let underlying: Arc<dyn FileTarget> =
            Arc::new(LocalFsTarget::new(dir.clone()).unwrap());

        let old =
            ObfuscatingTarget::bootstrap(underlying.clone()).await.unwrap();
        let salt_before = *old.salt_bytes();
        old.write("kv/x", b"v").await.unwrap();
        let listing_before = underlying.list("").await.unwrap();

        run_rekey(underlying.clone(), true).await.unwrap();

        let after =
            ObfuscatingTarget::bootstrap(underlying.clone()).await.unwrap();
        assert_eq!(*after.salt_bytes(), salt_before, "dry-run must leave the salt alone");
        let listing_after = underlying.list("").await.unwrap();
        assert_eq!(listing_before.len(), listing_after.len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rekey_refuses_on_target_without_salt() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let underlying: Arc<dyn FileTarget> =
            Arc::new(LocalFsTarget::new(dir.clone()).unwrap());

        // No salt persisted yet — rekey should refuse rather than
        // mint a fresh one (that would leave the operator thinking
        // their previous salt was rotated when in fact there was
        // never one to rotate).
        let err = run_rekey(underlying, false).await.unwrap_err();
        assert!(format!("{err}").contains("has no `_bvault_salt`"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
