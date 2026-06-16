//! Barrier re-rooting migration.
//!
//! The namespace design re-roots existing root-tenant data under
//! `namespaces/<root_uuid>/...` so every tenant — including the implicit root
//! — lives under a uniform prefix.
//!
//! ## Safety posture
//!
//! Re-rooting rewrites barrier keys on the seal/unseal critical path. A bug
//! that half-completes the move on a live secrets server risks unrecoverable
//! data, so the migration is split into two stages with an explicit operator
//! gate between them:
//!
//! 1. **Copy + verify (this module, idempotent, safe to run on upgrade).**
//!    Every barrier key under `core/mounts`, `sys/`, and `logical/` is *copied*
//!    (never moved) to `namespaces/<root_uuid>/...`. The original keys are left
//!    in place. A version marker records that the copy completed and was
//!    verified. Replaying the migration is a no-op once the marker is set.
//!
//! 2. **Activation (operator-gated, deferred).** Pointing `Core`'s boot-time
//!    system view and root mount table at the new prefix — so reads/writes
//!    land there and the legacy keys can be retired — is a deliberate,
//!    separately-validated step. It is gated behind the
//!    `BASTION_NAMESPACE_REROOT` opt-in and is not performed automatically,
//!    per `agent.md`'s "feature flags, staged rollouts, and format versioning
//!    for risky migrations". Operators validate the copy against a BVBK backup
//!    before activating; rollback is "restore the pre-migration backup".
//!
//! Until activation, the copy is shadow data: correct, verified, and ready,
//! but not yet authoritative. This keeps upgrades non-destructive and fully
//! reversible while still landing the migration machinery the feature needs.

use std::sync::Arc;

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::router::{namespace_logical_prefix, namespace_system_prefix};
use super::store::{NamespaceStore, NAMESPACE_REGISTRY_PREFIX};

/// Current re-rooting migration version. Bumped if the copy layout changes.
pub const REROOT_MIGRATION_VERSION: u32 = 1;

/// Registry key (relative to [`NAMESPACE_REGISTRY_PREFIX`]) recording the
/// completed-and-verified copy version. Absent ⇒ never migrated.
const MIGRATION_VERSION_KEY: &str = "migration-version";

/// Legacy root prefixes that get copied under `namespaces/<root_uuid>/`.
const LEGACY_LOGICAL_PREFIX: &str = "logical/";
const LEGACY_SYSTEM_PREFIX: &str = "sys/";
const LEGACY_MOUNT_CONFIG: &str = "core/mounts";

/// Outcome of a migration attempt, for logging/observability.
#[derive(Debug, Default, PartialEq)]
pub struct MigrationReport {
    pub already_done: bool,
    pub keys_copied: usize,
    pub keys_verified: usize,
}

/// Whether the operator has opted into *activating* the re-rooted prefix as
/// the authoritative root. Default false. The copy stage runs regardless; only
/// activation (a future, separately-reviewed step) consults this.
pub fn reroot_activation_opt_in() -> bool {
    std::env::var("BASTION_NAMESPACE_REROOT").map(|v| v == "1").unwrap_or(false)
}

#[maybe_async::maybe_async]
async fn read_migration_version(store_view: &dyn Storage) -> Result<Option<u32>, RvError> {
    let key = format!("{NAMESPACE_REGISTRY_PREFIX}{MIGRATION_VERSION_KEY}");
    match store_view.get(&key).await? {
        Some(entry) => {
            let s = String::from_utf8(entry.value)
                .map_err(|e| bv_error_string!(format!("corrupt migration-version: {e}")))?;
            let v = s.trim().parse::<u32>().map_err(|e| {
                bv_error_string!(format!("invalid migration-version {s:?}: {e}"))
            })?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

#[maybe_async::maybe_async]
async fn write_migration_version(store_view: &dyn Storage, version: u32) -> Result<(), RvError> {
    let key = format!("{NAMESPACE_REGISTRY_PREFIX}{MIGRATION_VERSION_KEY}");
    store_view
        .put(&StorageEntry { key, value: version.to_string().into_bytes() })
        .await
}

/// Recursively collect every concrete (non-directory) key under `prefix` from
/// the raw barrier storage.
#[maybe_async::maybe_async]
async fn collect_keys(barrier: &dyn Storage, prefix: &str) -> Result<Vec<String>, RvError> {
    let mut pending = vec![prefix.to_string()];
    let mut keys = Vec::new();
    while let Some(curr) = pending.pop() {
        for child in barrier.list(&curr).await? {
            let full = format!("{curr}{child}");
            if child.ends_with('/') {
                pending.push(full);
            } else {
                keys.push(full);
            }
        }
    }
    Ok(keys)
}

/// Copy a single legacy key to its re-rooted location. Returns true if a value
/// was copied (false if the source vanished between listing and reading).
#[maybe_async::maybe_async]
async fn copy_key(barrier: &dyn Storage, src: &str, dst: &str) -> Result<bool, RvError> {
    match barrier.get(src).await? {
        Some(entry) => {
            barrier.put(&StorageEntry { key: dst.to_string(), value: entry.value }).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Map a legacy root key to its re-rooted destination under
/// `namespaces/<root_uuid>/`. Returns `None` for keys outside the migrated
/// prefixes (left untouched).
fn reroot_destination(root_uuid: &str, key: &str) -> Option<String> {
    if let Some(rest) = key.strip_prefix(LEGACY_LOGICAL_PREFIX) {
        return Some(format!("{}{rest}", namespace_logical_prefix(root_uuid)));
    }
    if let Some(rest) = key.strip_prefix(LEGACY_SYSTEM_PREFIX) {
        return Some(format!("{}{rest}", namespace_system_prefix(root_uuid)));
    }
    if key == LEGACY_MOUNT_CONFIG {
        return Some(format!("namespaces/{root_uuid}/core/mounts"));
    }
    None
}

/// Run the copy + verify stage. Idempotent: a no-op once the version marker is
/// present. Must be called after the namespace store's root has been minted.
#[maybe_async::maybe_async]
pub async fn migrate_root_copy(
    core: &Arc<Core>,
    store: &NamespaceStore,
) -> Result<MigrationReport, RvError> {
    let barrier = core.barrier.as_storage();

    if let Some(v) = read_migration_version(barrier).await? {
        if v >= REROOT_MIGRATION_VERSION {
            return Ok(MigrationReport { already_done: true, ..Default::default() });
        }
    }

    let root_uuid = store.root_uuid()?;

    // Enumerate every legacy root key across the three migrated prefixes.
    let mut sources = Vec::new();
    sources.extend(collect_keys(barrier, LEGACY_LOGICAL_PREFIX).await?);
    sources.extend(collect_keys(barrier, LEGACY_SYSTEM_PREFIX).await?);
    if barrier.get(LEGACY_MOUNT_CONFIG).await?.is_some() {
        sources.push(LEGACY_MOUNT_CONFIG.to_string());
    }

    let mut report = MigrationReport::default();
    let mut copied_pairs: Vec<(String, String)> = Vec::new();
    for src in &sources {
        // Never copy the registry into itself (it is not under the legacy
        // prefixes, but guard against a future prefix overlap).
        if src.starts_with(NAMESPACE_REGISTRY_PREFIX) {
            continue;
        }
        let Some(dst) = reroot_destination(&root_uuid, src) else {
            continue;
        };
        if copy_key(barrier, src, &dst).await? {
            report.keys_copied += 1;
            copied_pairs.push((src.clone(), dst));
        }
    }

    // Verify: every copied destination is readable and byte-equal to its
    // source. A mismatch aborts before the version marker is written, so the
    // migration re-runs (and re-copies) on the next unseal.
    for (src, dst) in &copied_pairs {
        let s = barrier.get(src).await?;
        let d = barrier.get(dst).await?;
        match (s, d) {
            (Some(s), Some(d)) if s.value == d.value => report.keys_verified += 1,
            (None, _) => report.keys_verified += 1, // source deleted mid-flight; tolerate
            _ => {
                return Err(bv_error_string!(format!(
                    "namespace re-root verification failed for {src} -> {dst}"
                )))
            }
        }
    }

    write_migration_version(barrier, REROOT_MIGRATION_VERSION).await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::namespace::{NamespaceModule, NAMESPACE_MODULE_NAME};
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_reroot_copy_is_idempotent_and_non_destructive() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_reroot_copy").await;
        let store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        let core_arc = core.self_ptr.upgrade().unwrap();
        let root_uuid = store.root_uuid().unwrap();
        let barrier = core.barrier.as_storage();

        // post_unseal already ran the copy once; the legacy mount config and
        // its re-rooted copy must both be present (non-destructive), and a
        // re-run must be a no-op.
        assert!(barrier.get("core/mounts").await.unwrap().is_some(), "legacy data must survive");
        let dst = format!("namespaces/{root_uuid}/core/mounts");
        assert!(barrier.get(&dst).await.unwrap().is_some(), "re-rooted copy must exist");

        let report = migrate_root_copy(&core_arc, &store).await.unwrap();
        assert!(report.already_done, "second run must be a no-op");
    }

    #[test]
    fn test_reroot_destination_mapping() {
        assert_eq!(
            reroot_destination("ROOT", "logical/abc/secret"),
            Some("namespaces/ROOT/logical/abc/secret".to_string())
        );
        assert_eq!(
            reroot_destination("ROOT", "sys/policy/admin"),
            Some("namespaces/ROOT/sys/policy/admin".to_string())
        );
        assert_eq!(
            reroot_destination("ROOT", "core/mounts"),
            Some("namespaces/ROOT/core/mounts".to_string())
        );
        // Physical-layer / unrelated keys are left untouched.
        assert_eq!(reroot_destination("ROOT", "core/seal-config"), None);
        assert_eq!(reroot_destination("ROOT", "barrier/init"), None);
    }
}
