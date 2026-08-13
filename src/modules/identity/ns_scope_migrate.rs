//! One-shot datafix: namespace-scope legacy resource and file owner/share keys.
//!
//! ## Why
//!
//! Resource, file, and asset-group owner records and `SecretShare`s were keyed
//! on the *bare* name (`sys/owner/resource/db1`, share target `resource|db1`)
//! while the objects themselves live in namespace-isolated storage. A resource
//! called `db1` in namespace `dti/esi` and one called `db1` at root therefore
//! shared one owner record and one set of shares — so a grant on either would
//! unlock both. KV paths never had this problem: they were namespace-scoped by
//! `OwnerStore::canonicalize_kv_path_scoped`.
//!
//! The live code now scopes these keys as `<ns>/<name>`
//! (`OwnerStore::scope_target_name`). Records written by earlier releases are
//! still bare, so a share created from inside a namespace stops resolving until
//! it is re-keyed. This migration does that re-keying once, on first unseal
//! after the upgrade.
//!
//! ## How the owning namespace is inferred
//!
//! Nothing in a legacy record says which namespace it belonged to — that is
//! precisely the bug. The owning namespace is instead inferred from where the
//! *object* lives, which is authoritative: each namespace's `resource` mounts
//! are enumerated from its own mount table and their `meta/<name>` keys listed.
//!
//! For each legacy bare key the outcome is one of:
//!
//! * **root holds it** — left untouched. At root the scoped form *is* the bare
//!   form, so the record is already correct. Takes precedence over any tenant
//!   match: a root object's records must never be moved out from under it.
//! * **exactly one namespace holds it** — re-keyed to `<ns>/<name>`.
//! * **no namespace holds it** — left untouched and counted as an orphan
//!   (the object was deleted without its records being cascaded).
//! * **two or more namespaces hold it** — left untouched and reported as
//!   ambiguous, with the candidate namespaces named in the log. Guessing here
//!   could hand one tenant's grant to another, so the migration refuses; an
//!   operator resolves those by re-granting the share in the right namespace.
//!
//! ## Safety
//!
//! * **Idempotent.** A version marker in the namespace registry records
//!   completion; a second run is a no-op. The marker is written only after the
//!   pass finishes without error, so an interrupted run retries on next unseal.
//! * **Write-new-then-delete-old,** per record: a crash mid-record leaves a
//!   resolvable duplicate, never an orphaned grantee. Share moves reuse
//!   `ShareStore::rename_target`, the same primitive resource rename uses.
//! * **Best-effort at the boot level.** A failure is logged and unseal
//!   continues — a not-yet-migrated share denies access (fail-closed), which
//!   must not be allowed to block the server from starting.

use std::collections::HashMap;

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    modules::identity::{owner_store::OwnerStore, share_store::ShareTargetKind, IdentityModule},
    modules::namespace::{
        router::{namespace_logical_prefix, namespace_mount_config_path},
        store::{NamespaceStore, NAMESPACE_REGISTRY_PREFIX},
    },
    mount::MountTable,
    storage::StorageEntry,
};

/// Current datafix version. Bump only if the re-keying rules change; a bumped
/// value makes the pass run again on the next unseal.
pub const OWNER_SHARE_NS_SCOPE_VERSION: u32 = 1;

/// Registry key (relative to [`NAMESPACE_REGISTRY_PREFIX`]) holding the
/// completed datafix version. Absent ⇒ never run.
const MARKER_KEY: &str = "owner-share-ns-scope-version";

/// Logical mount type whose entries this datafix enumerates.
const RESOURCE_MOUNT_TYPE: &str = "resource";
/// Key prefix the resource engine stores its per-resource metadata under.
const RESOURCE_META_PREFIX: &str = "meta/";

/// What the pass did, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NsScopeReport {
    /// Records re-keyed to `<ns>/<name>`.
    pub moved_owners: usize,
    pub moved_shares: usize,
    /// Left bare because root owns the object (already correct).
    pub kept_root: usize,
    /// Left bare because no namespace holds the object.
    pub orphaned: usize,
    /// Left bare because two or more namespaces hold an object of that name.
    pub ambiguous: usize,
    /// True when the marker was already set and nothing was scanned.
    pub skipped: bool,
}

fn marker_key() -> String {
    format!("{NAMESPACE_REGISTRY_PREFIX}{MARKER_KEY}")
}

async fn read_marker(core: &dyn VaultCtx) -> Result<u32, RvError> {
    let Some(e) = core.barrier().as_storage().get(&marker_key()).await? else {
        return Ok(0);
    };
    Ok(serde_json::from_slice::<u32>(&e.value).unwrap_or(0))
}

async fn write_marker(core: &dyn VaultCtx, version: u32) -> Result<(), RvError> {
    core.barrier()
        .as_storage()
        .put(&StorageEntry { key: marker_key(), value: serde_json::to_vec(&version)? })
        .await
}

/// Map every resource name to the namespace paths that actually hold a resource
/// of that name (`""` = root). Read straight from each namespace's own mount
/// table + logical storage, so it reflects the objects rather than the records
/// we are trying to repair.
async fn resource_locations(
    core: &dyn VaultCtx,
    ns_store: &NamespaceStore,
) -> Result<HashMap<String, Vec<String>>, RvError> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let __barrier = core.barrier();
    let storage = __barrier.as_storage();
    let hmac_key = core.hmac_key().clone();

    for ns in ns_store.list_all().await? {
        // Root's mounts live in the core mount table at the active root prefix;
        // every other namespace has its own table keyed by uuid.
        let (config_path, logical_prefix) = if ns.is_root() {
            (core.mounts_router().mounts.path.clone(), core.root_logical_prefix())
        } else {
            (namespace_mount_config_path(&ns.uuid), namespace_logical_prefix(&ns.uuid))
        };

        let table = MountTable::new(&config_path);
        // An absent table means the namespace has no mounts yet — skip it
        // rather than failing the whole pass.
        if table.load(storage, Some(&hmac_key), core.mount_entry_hmac_level()).await.is_err() {
            continue;
        }

        let mount_uuids: Vec<String> = {
            let entries = table.entries.read()?;
            entries
                .values()
                .filter_map(|e| {
                    let me = e.read().ok()?;
                    (me.logical_type == RESOURCE_MOUNT_TYPE).then(|| me.uuid.clone())
                })
                .collect()
        };

        for mount_uuid in mount_uuids {
            let prefix = format!("{logical_prefix}{mount_uuid}/{RESOURCE_META_PREFIX}");
            for key in storage.list(&prefix).await.unwrap_or_default() {
                let name = key.trim_end_matches('/').trim().to_lowercase();
                if name.is_empty() {
                    continue;
                }
                out.entry(name).or_default().push(ns.path.clone());
            }
        }
    }

    Ok(out)
}

/// Decide the destination for one legacy bare key, or `None` to leave it alone.
/// `report` is updated with the reason whenever the answer is "leave it".
fn destination_for(
    name: &str,
    locations: &HashMap<String, Vec<String>>,
    report: &mut NsScopeReport,
) -> Option<String> {
    let Some(holders) = locations.get(name) else {
        report.orphaned += 1;
        return None;
    };
    // Root wins outright: at root the bare key already *is* the scoped key, and
    // moving it would strand the root object's owner and shares.
    if holders.iter().any(|h| h.is_empty()) {
        report.kept_root += 1;
        return None;
    }
    let mut tenants: Vec<&String> = holders.iter().filter(|h| !h.is_empty()).collect();
    tenants.sort();
    tenants.dedup();
    match tenants.as_slice() {
        [] => {
            report.orphaned += 1;
            None
        }
        [one] => OwnerStore::scope_target_name(name, Some(one.as_str())),
        many => {
            report.ambiguous += 1;
            log::warn!(
                target: "migration",
                "owner/share ns-scope datafix: resource {name:?} exists in {} namespaces \
                 ({:?}); leaving its legacy records bare because re-keying to the wrong \
                 tenant would transfer access. Re-grant the share inside the intended \
                 namespace to resolve.",
                many.len(),
                many,
            );
            None
        }
    }
}

/// Run the datafix if it has not run before. Returns the report; a skipped run
/// reports `skipped = true` and zero counts.
///
/// Called from `Core::post_unseal` after module init (the identity stores must
/// exist). Errors propagate to the caller, which logs and continues — see the
/// safety notes in the module docs.
pub async fn run_if_needed(core: &dyn VaultCtx) -> Result<NsScopeReport, RvError> {
    let mut report = NsScopeReport::default();

    if read_marker(core).await? >= OWNER_SHARE_NS_SCOPE_VERSION {
        report.skipped = true;
        return Ok(report);
    }

    let Some(identity) = core.module_manager().get_module::<IdentityModule>("identity") else {
        return Err(crate::bv_error_string!(
            "owner/share ns-scope datafix: identity module unavailable"
        ));
    };
    let Some(owner_store) = identity.owner_store() else {
        return Err(crate::bv_error_string!(
            "owner/share ns-scope datafix: owner store unavailable"
        ));
    };
    let Some(share_store) = identity.share_store() else {
        return Err(crate::bv_error_string!(
            "owner/share ns-scope datafix: share store unavailable"
        ));
    };

    let ns_store = NamespaceStore::new(core)?;
    let locations = resource_locations(core, &ns_store).await?;

    // ── Owner records ──────────────────────────────────────────────────
    for name in owner_store.list_legacy_resource_owners().await? {
        let Some(dest) = destination_for(&name, &locations, &mut report) else {
            continue;
        };
        let Some(rec) = owner_store.get_resource_owner(&name).await? else {
            continue;
        };
        // Write-new-then-delete-old: a crash between the two leaves a duplicate
        // record that still resolves, not an unowned object.
        owner_store.set_resource_owner(&dest, &rec.entity_id).await?;
        owner_store.forget_resource_owner(&name).await?;
        report.moved_owners += 1;
        log::info!(
            target: "migration",
            "owner/share ns-scope datafix: moved resource owner {name:?} -> {dest:?}",
        );
    }

    // ── Share records ──────────────────────────────────────────────────
    // `rename_target` moves the primary record and both index pointers, and is
    // the same primitive a resource rename uses.
    for canonical in share_store.list_target_canonicals(ShareTargetKind::Resource).await? {
        // Already-scoped targets (written by this release) carry a `/`.
        if canonical.contains('/') {
            continue;
        }
        let mut per_share = NsScopeReport::default();
        let Some(dest) = destination_for(&canonical, &locations, &mut per_share) else {
            // Only count the "left alone" reasons once per name; the owner loop
            // above already counted names that had an owner record.
            report.orphaned += per_share.orphaned.min(1);
            report.kept_root += per_share.kept_root.min(1);
            report.ambiguous += per_share.ambiguous.min(1);
            continue;
        };
        let moved = share_store
            .rename_target(ShareTargetKind::Resource, &canonical, &dest, "ns-scope-datafix")
            .await?;
        if moved > 0 {
            report.moved_shares += moved;
            log::info!(
                target: "migration",
                "owner/share ns-scope datafix: re-keyed {moved} share(s) \
                 {canonical:?} -> {dest:?}",
            );
        }
    }

    write_marker(core, OWNER_SHARE_NS_SCOPE_VERSION).await?;
    log::info!(
        target: "migration",
        "owner/share ns-scope datafix v{OWNER_SHARE_NS_SCOPE_VERSION} complete: \
         {} owner record(s) and {} share(s) re-keyed; {} left at root, {} orphaned, \
         {} ambiguous",
        report.moved_owners,
        report.moved_shares,
        report.kept_root,
        report.orphaned,
        report.ambiguous,
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locations(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(n, nss)| {
                (n.to_string(), nss.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            })
            .collect()
    }

    #[test]
    fn root_holder_is_left_alone() {
        let loc = locations(&[("db1", &[""])]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("db1", &loc, &mut r), None);
        assert_eq!(r.kept_root, 1);
    }

    // Root wins even when a tenant also has the name: moving the record would
    // strand root's object, and root's bare key is already correct.
    #[test]
    fn root_wins_over_a_tenant_of_the_same_name() {
        let loc = locations(&[("db1", &["", "dti/esi"])]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("db1", &loc, &mut r), None);
        assert_eq!(r.kept_root, 1);
        assert_eq!(r.ambiguous, 0);
    }

    #[test]
    fn single_tenant_holder_is_rekeyed() {
        let loc = locations(&[("db1", &["dti/esi"])]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("db1", &loc, &mut r), Some("dti/esi/db1".to_string()));
        assert_eq!(r, NsScopeReport { ..Default::default() });
    }

    // Two tenants with the same resource name cannot be told apart, so the
    // record stays bare rather than being handed to a guess.
    #[test]
    fn two_tenant_holders_are_ambiguous() {
        let loc = locations(&[("db1", &["dti/esi", "dti/outro"])]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("db1", &loc, &mut r), None);
        assert_eq!(r.ambiguous, 1);
    }

    // The same namespace listed twice (two `resource` mounts holding the name)
    // is still one tenant, not an ambiguity.
    #[test]
    fn duplicate_namespace_entries_collapse() {
        let loc = locations(&[("db1", &["dti/esi", "dti/esi"])]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("db1", &loc, &mut r), Some("dti/esi/db1".to_string()));
        assert_eq!(r.ambiguous, 0);
    }

    #[test]
    fn unknown_name_is_orphaned() {
        let loc = locations(&[]);
        let mut r = NsScopeReport::default();
        assert_eq!(destination_for("gone", &loc, &mut r), None);
        assert_eq!(r.orphaned, 1);
    }
}
