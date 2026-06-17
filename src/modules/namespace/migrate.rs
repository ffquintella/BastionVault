//! Barrier re-rooting migration.
//!
//! The namespace design re-roots existing root-tenant data under
//! `namespaces/<root_uuid>/...` so every tenant — including the implicit root
//! — lives under a uniform prefix.
//!
//! ## Safety posture
//!
//! Re-rooting is the **default for every install, with no opt-in** (see
//! [`resolve_root_activation`]). It rewrites barrier keys on the seal/unseal
//! critical path, so the design keeps two safety properties:
//!
//! 1. **Copy + verify is non-destructive and idempotent.** Every barrier key
//!    under `core/mounts`, `sys/`, and `logical/` is *copied* (never moved) to
//!    `namespaces/<root_uuid>/...`; the original keys are left in place. Each
//!    copied destination is read back and compared byte-for-byte before a
//!    version marker records completion. Replaying the migration is a no-op once
//!    the marker is set.
//!
//! 2. **Activation only flips after a verified copy, and fails safe.** On a
//!    brand-new install there is nothing to copy, so it activates immediately.
//!    On an existing install the copy + verify runs eagerly on the same boot and
//!    activation follows only if it succeeds; if verification fails, the legacy
//!    layout stays authoritative for that boot and the migration retries on the
//!    next unseal rather than blocking startup or pointing at unverified data.
//!    Activation is recorded by a persistent registry marker and is one-way.
//!
//! Because the legacy keys are retained, rollback to a pre-namespace build is
//! still "restore the pre-migration BVBK backup" (the legacy keys also remain in
//! place on disk after activation, unused).

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

/// Registry key recording that the re-rooted prefix is the *authoritative* root
/// (activation is in effect). Once set it is permanent: an activated deployment
/// always boots with `namespaces/<root_uuid>/…` as the live root.
const ACTIVATION_MARKER_KEY: &str = "reroot-active";

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

#[maybe_async::maybe_async]
async fn activation_active(barrier: &dyn Storage) -> Result<bool, RvError> {
    let key = format!("{NAMESPACE_REGISTRY_PREFIX}{ACTIVATION_MARKER_KEY}");
    Ok(barrier.get(&key).await?.is_some())
}

#[maybe_async::maybe_async]
async fn set_activation_active(barrier: &dyn Storage) -> Result<(), RvError> {
    let key = format!("{NAMESPACE_REGISTRY_PREFIX}{ACTIVATION_MARKER_KEY}");
    barrier.put(&StorageEntry { key, value: b"1".to_vec() }).await
}

/// Decide whether the re-rooted prefix should be the authoritative root for
/// this boot, and persist the decision. Returns `Some(root_uuid)` when
/// activation is in effect (caller repoints `Core` to `namespaces/<uuid>/…`),
/// `None` for the legacy layout (only when an existing install's copy could not
/// be completed/verified this boot — a fail-safe, not a gate).
///
/// Re-root is the **default for every install, with no opt-in**:
/// - **Already activated** (marker set) → activate. Activation is one-way and
///   persistent.
/// - **Brand-new install** (no legacy root mount table yet) → activate,
///   recording the marker and marking the copy stage complete (nothing to copy).
/// - **Existing pre-namespace install** → run the non-destructive copy + verify
///   eagerly *this boot*, then activate. If the copy cannot be verified, stay on
///   the legacy layout this boot (legacy keys are untouched) and retry next boot
///   rather than block unseal or point at unverified data.
#[maybe_async::maybe_async]
pub async fn resolve_root_activation(
    core: &Arc<Core>,
    store: &NamespaceStore,
) -> Result<Option<String>, RvError> {
    let barrier = core.barrier.as_storage();
    let root_uuid = store.root_uuid()?;

    if activation_active(barrier).await? {
        return Ok(Some(root_uuid));
    }

    // New-install detection: a fresh vault has no legacy root mount table yet
    // (it is created later in `post_unseal` by `load_or_default`).
    let legacy_present = barrier.get(LEGACY_MOUNT_CONFIG).await?.is_some();
    if !legacy_present {
        set_activation_active(barrier).await?;
        // Nothing to copy on a new install; mark the copy stage done so the
        // later copy pass is a no-op.
        write_migration_version(barrier, REROOT_MIGRATION_VERSION).await?;
        log::info!("namespace re-root activated by default for new install (root {root_uuid})");
        return Ok(Some(root_uuid));
    }

    // Existing install: re-root by default. Copy + verify the legacy data under
    // `namespaces/<root_uuid>/…` now (idempotent + non-destructive), then make
    // it authoritative this boot. A copy/verify failure is a fail-safe: leave
    // the legacy layout authoritative for this boot and retry on the next.
    match migrate_root_copy(core, store).await {
        Ok(report) => {
            set_activation_active(barrier).await?;
            log::info!(
                "namespace re-root activated for existing install (root {root_uuid}): \
                 {} keys copied, {} verified{}",
                report.keys_copied,
                report.keys_verified,
                if report.already_done { " (copy already complete)" } else { "" },
            );
            Ok(Some(root_uuid))
        }
        Err(e) => {
            log::warn!(
                "namespace re-root copy failed (legacy layout stays authoritative this boot, \
                 will retry next boot): {e}"
            );
            Ok(None)
        }
    }
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
    async fn test_reroot_activated_by_default_on_new_install() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_reroot_activation").await;
        let store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        let core_arc = core.self_ptr.upgrade().unwrap();
        let root_uuid = store.root_uuid().unwrap();
        let barrier = core.barrier.as_storage();

        // New installs activate re-rooting by default: the root tenant's mount
        // table lives under `namespaces/<root_uuid>/`, the legacy location is
        // never written, and Core is repointed at the active prefix.
        let dst = format!("namespaces/{root_uuid}/core/mounts");
        assert!(barrier.get(&dst).await.unwrap().is_some(), "activated mount table must exist");
        assert!(
            barrier.get("core/mounts").await.unwrap().is_none(),
            "legacy mount table must not be written on an activated new install"
        );
        assert_eq!(
            core.root_storage_prefix.load().as_str(),
            format!("namespaces/{root_uuid}/").as_str(),
            "Core must be repointed at the active root prefix"
        );

        // The copy stage is a no-op on a new install (nothing to copy; the
        // version marker was set when activation was recorded).
        let report = migrate_root_copy(&core_arc, &store).await.unwrap();
        assert!(report.already_done, "copy must be a no-op for an activated new install");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_reroot_activates_existing_install_by_default() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_reroot_existing").await;
        let store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        let core_arc = core.self_ptr.upgrade().unwrap();
        let barrier = core.barrier.as_storage();

        // Simulate a pre-namespace existing install: a legacy root mount table
        // + a legacy logical secret present, and the activation/version markers
        // cleared so the decision runs as if upgrading for the first time.
        barrier
            .put(&StorageEntry { key: "core/mounts".into(), value: b"legacy-table".to_vec() })
            .await
            .unwrap();
        barrier
            .put(&StorageEntry { key: "logical/seed/secret".into(), value: b"legacy-secret".to_vec() })
            .await
            .unwrap();
        barrier
            .delete(&format!("{NAMESPACE_REGISTRY_PREFIX}{ACTIVATION_MARKER_KEY}"))
            .await
            .unwrap();
        barrier
            .delete(&format!("{NAMESPACE_REGISTRY_PREFIX}{MIGRATION_VERSION_KEY}"))
            .await
            .unwrap();
        assert!(!activation_active(barrier).await.unwrap(), "precondition: not activated");

        // Re-root is the default with no opt-in: an existing install copies +
        // verifies and activates this boot.
        let res = resolve_root_activation(&core_arc, &store).await.unwrap();
        let root_uuid = res.expect("existing install must activate by default");

        // The legacy secret was copied under the re-rooted prefix and the
        // marker is now set; legacy keys are retained (non-destructive).
        assert!(
            barrier
                .get(&format!("namespaces/{root_uuid}/logical/seed/secret"))
                .await
                .unwrap()
                .is_some(),
            "legacy data must be copied under the re-rooted prefix"
        );
        assert!(activation_active(barrier).await.unwrap(), "activation marker must be set");
        assert!(
            barrier.get("logical/seed/secret").await.unwrap().is_some(),
            "legacy keys must be retained (non-destructive)"
        );
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
