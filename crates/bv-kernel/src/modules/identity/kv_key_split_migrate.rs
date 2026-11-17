//! One-shot datafix (T499): give every KV secret an owner and share key of its own.
//!
//! Before T499 a KV key was canonicalized twice, so `x` and `data/x` (and the
//! secrets of a namespace or mount named `data`) shared one record. For each
//! existing secret whose new key differs, the record its old key held is
//! copied to the new key, so no secret changes hands; then the asset-group
//! secret indexes, which had the same bug, are rebuilt from the group records.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    modules::{
        identity::{
            owner_store::{OwnerRecord, OwnerStore},
            share_store::{SecretShare, ShareGranteeKind, ShareStore, ShareTargetKind},
            IdentityModule,
        },
        namespace::{
            router::{namespace_logical_prefix, namespace_mount_config_path},
            store::{NamespaceStore, NAMESPACE_REGISTRY_PREFIX},
        },
        resource_group::{group_store::scope_of, ResourceGroupModule},
    },
    mount::MountTable,
    storage::{Storage, StorageEntry},
};

/// Datafix version; a bumped value runs the pass again on the next unseal.
pub const KV_KEY_SPLIT_VERSION: u32 = 1;
/// Registry keys (under [`NAMESPACE_REGISTRY_PREFIX`]): the completed version,
/// and the plan of a pass that has not finished yet.
const MARKER_KEY: &str = "kv-key-split-version";
const PLAN_KEY: &str = "kv-key-split-plan";
/// Actor recorded on the share history rows the datafix writes.
const ACTOR: &str = "kv-key-split-datafix";

/// What the pass did, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KvKeySplitReport {
    /// Owner records written under a secret's new key, or dropped from it.
    pub owners_copied: usize,
    pub owners_dropped: usize,
    /// Shares written under a secret's new key, or dropped from it.
    pub shares_copied: usize,
    pub shares_dropped: usize,
    /// New keys that already held a record of their own: kept, and logged.
    pub conflicts: usize,
    /// Asset-group scopes whose indexes were rebuilt.
    pub scopes_reindexed: usize,
    /// True when the marker was already set and nothing was done.
    pub skipped: bool,
}

/// One secret whose key changes: what its old key held moves to `new`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Move {
    old: String,
    new: String,
}

/// The writes a pass makes, persisted before the first one so a pass that
/// stops part-way resumes with the same writes instead of re-reading keys it
/// already changed.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Plan {
    /// `(new key, record)`; `None` drops the record at the new key.
    owners: Vec<(String, Option<OwnerRecord>)>,
    /// `(new key, shares to write, (grantee kind, grantee) to drop)`.
    shares: Vec<(String, Vec<SecretShare>, Vec<(String, String)>)>,
}

fn registry_key(leaf: &str) -> String {
    format!("{NAMESPACE_REGISTRY_PREFIX}{leaf}")
}

/// One KV mount: router key (namespace prefix included), engine, the
/// storage prefix of its secrets, and its namespace (`None` at root).
struct KvMount {
    router_key: String,
    v2: bool,
    secrets_prefix: String,
    ns: Option<String>,
}

impl KvMount {
    /// The path a version 1 data request for `name` takes.
    fn request_path(&self, name: &str) -> String {
        match self.v2 {
            true => format!("{}data/{name}", self.router_key),
            false => format!("{}{name}", self.router_key),
        }
    }

    /// `(old key, new key)` of the secret `name`.
    fn keys(&self, name: &str) -> (Option<String>, String) {
        let old = OwnerStore::legacy_kv_key(&self.request_path(name), self.ns.as_deref());
        (old, format!("{}{name}", self.router_key))
    }
}

/// Every `kv` and `kv-v2` mount of every namespace, from the stored tables.
async fn kv_mounts(core: &crate::core::Core, ns_store: &NamespaceStore) -> Result<Vec<KvMount>, RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let hmac_key = core.hmac_key().clone();
    let mut out = Vec::new();
    for ns in ns_store.list_all().await? {
        let (config_path, logical_prefix, router_prefix) = if ns.is_root() {
            (core.mounts_router().mounts.path.clone(), core.root_logical_prefix(), String::new())
        } else {
            let router_prefix = format!("{}/", ns.path.trim_end_matches('/'));
            (namespace_mount_config_path(&ns.uuid), namespace_logical_prefix(&ns.uuid), router_prefix)
        };
        let table = MountTable::new(&config_path);
        // An absent table means the namespace has no mounts yet.
        if table.load(storage, Some(&hmac_key), core.mount_entry_hmac_level()).await.is_err() {
            continue;
        }
        let kv: Vec<(String, String, bool)> = {
            let entries = table.entries.read()?;
            entries
                .values()
                .filter_map(|e| {
                    let me = e.read().ok()?;
                    let v2 = match me.logical_type.as_str() {
                        "kv-v2" => true,
                        "kv" => false,
                        _ => return None,
                    };
                    Some((me.path.clone(), me.uuid.clone(), v2))
                })
                .collect()
        };
        for (path, uuid, v2) in kv {
            let secrets = if v2 { "metadata/" } else { "" };
            out.push(KvMount {
                router_key: format!("{router_prefix}{path}"),
                v2,
                secrets_prefix: format!("{logical_prefix}{uuid}/{secrets}"),
                ns: (!ns.is_root()).then(|| ns.path.clone()),
            });
        }
    }
    Ok(out)
}

/// The names of `mount`'s secrets whose key changes. Only names under a
/// `data`/`metadata` segment change, unless the mount's own path or its
/// namespace was stripped too, in which case every secret is listed.
async fn changed_names(storage: &dyn Storage, mount: &KvMount) -> Result<Vec<String>, RvError> {
    let (old, new) = mount.keys("probe");
    let whole_mount = old.as_deref() != Some(new.as_str());
    let mut names = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    for key in storage.list(&mount.secrets_prefix).await? {
        let top = key.trim_end_matches('/');
        if !whole_mount && top != "data" && top != "metadata" {
            continue;
        }
        if key.ends_with('/') {
            folders.push(key);
        } else {
            names.push(key);
        }
    }
    while let Some(dir) = folders.pop() {
        for key in storage.list(&format!("{}{dir}", mount.secrets_prefix)).await? {
            let name = format!("{dir}{key}");
            if key.ends_with('/') {
                folders.push(name);
            } else {
                names.push(name);
            }
        }
    }
    Ok(names.into_iter().filter(|n| mount.keys(n).0.as_deref() != Some(mount.keys(n).1.as_str())).collect())
}

/// Every existing secret whose key changes, across all KV mounts.
async fn moves(core: &crate::core::Core) -> Result<Vec<Move>, RvError> {
    let ns_store = NamespaceStore::new(core)?;
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let mut out = Vec::new();
    for mount in kv_mounts(core, &ns_store).await? {
        for name in changed_names(storage, &mount).await? {
            let (Some(old), new) = mount.keys(&name) else {
                continue;
            };
            out.push(Move { old, new });
        }
    }
    Ok(out)
}

/// The writes that leave every moved secret with exactly what its old key
/// held. A new key that already holds a record and is no other secret's old
/// key is a record of its own (written since, or by another route): kept.
async fn build_plan(
    moves: &[Move],
    owners: &OwnerStore,
    shares: &ShareStore,
    report: &mut KvKeySplitReport,
) -> Result<Plan, RvError> {
    let old_keys: HashSet<&str> = moves.iter().map(|m| m.old.as_str()).collect();
    let mut plan = Plan::default();
    for m in moves {
        let shared_slot = old_keys.contains(m.new.as_str());
        let from = owners.get_kv_owner(&m.old).await?;
        let at = owners.get_kv_owner(&m.new).await?;
        if at.is_some() && !shared_slot {
            report.conflicts += 1;
            log::warn!(target: "migration", "kv key split: {:?} already has an owner record; kept", m.new);
        } else if from.is_some() || at.is_some() {
            plan.owners.push((m.new.clone(), from));
        }

        let from = shares.list_shares_for_target(ShareTargetKind::KvSecret, &m.old).await?;
        let at = shares.list_shares_for_target(ShareTargetKind::KvSecret, &m.new).await?;
        if !at.is_empty() && !shared_slot {
            report.conflicts += 1;
            log::warn!(target: "migration", "kv key split: {:?} already has shares; kept", m.new);
        } else if !from.is_empty() || !at.is_empty() {
            let keep: HashSet<(&str, &str)> =
                from.iter().map(|s| (s.grantee_kind.as_str(), s.grantee_entity_id.as_str())).collect();
            let drop = at
                .iter()
                .filter(|s| !keep.contains(&(s.grantee_kind.as_str(), s.grantee_entity_id.as_str())))
                .map(|s| (s.grantee_kind.clone(), s.grantee_entity_id.clone()))
                .collect();
            plan.shares.push((m.new.clone(), from, drop));
        }
    }
    Ok(plan)
}

async fn apply(
    plan: &Plan,
    owners: &OwnerStore,
    shares: &ShareStore,
    report: &mut KvKeySplitReport,
) -> Result<(), RvError> {
    for (key, rec) in &plan.owners {
        match rec {
            Some(rec) => {
                owners.put_kv_owner_record(key, rec).await?;
                report.owners_copied += 1;
            }
            None => {
                owners.forget_kv_owner(key).await?;
                report.owners_dropped += 1;
            }
        }
    }
    for (key, copy, drop) in &plan.shares {
        report.shares_copied += shares.copy_shares_to(ShareTargetKind::KvSecret, copy, key, ACTOR).await?;
        for (grantee_kind, grantee) in drop {
            let kind = ShareGranteeKind::parse(grantee_kind).unwrap_or(ShareGranteeKind::Entity);
            shares
                .delete_share_with_kind_audited(ShareTargetKind::KvSecret, key, kind, grantee, ACTOR, "revoke")
                .await?;
            report.shares_dropped += 1;
        }
    }
    Ok(())
}

/// Rebuild the asset-group indexes of every scope: they filed a member under
/// a second canonicalization of its path, which the group records never did.
async fn reindex_asset_groups(core: &crate::core::Core) -> Result<usize, RvError> {
    let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group");
    let Some(store) = module.and_then(|m| m.store()) else {
        return Ok(0);
    };
    let mut scopes = 0;
    for ns in NamespaceStore::new(core)?.list_all().await? {
        let scope = scope_of((!ns.is_root()).then_some(ns.path.as_str()));
        // A scope without groups has nothing to index, and its version stays.
        if !store.list_groups(&scope).await?.is_empty() {
            store.reindex(&scope).await?;
            scopes += 1;
        }
    }
    Ok(scopes)
}

/// Run the datafix unless it has run; until it completes, KV keys keep their
/// pre-T499 form (`OwnerStore::kv_keys_split` stays false), so records keep
/// resolving. Called from `Core::post_unseal` after module init; an error is
/// logged there and the pass retries on the next unseal.
pub async fn run_if_needed(core: &crate::core::Core) -> Result<KvKeySplitReport, RvError> {
    let mut report = KvKeySplitReport::default();
    let identity = core.module_manager().get_module::<IdentityModule>("identity");
    let identity = identity.ok_or_else(|| crate::bv_error_string!("kv key split: identity module unavailable"))?;
    let owners = identity.owner_store().ok_or_else(|| crate::bv_error_string!("kv key split: no owner store"))?;
    let shares = identity.share_store().ok_or_else(|| crate::bv_error_string!("kv key split: no share store"))?;

    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let done = match storage.get(&registry_key(MARKER_KEY)).await? {
        Some(e) => serde_json::from_slice::<u32>(&e.value).unwrap_or(0),
        None => 0,
    };
    if done >= KV_KEY_SPLIT_VERSION {
        owners.set_kv_keys_split();
        report.skipped = true;
        return Ok(report);
    }

    let plan = match storage.get(&registry_key(PLAN_KEY)).await? {
        Some(e) => serde_json::from_slice::<Plan>(&e.value)?,
        None => {
            let plan = build_plan(&moves(core).await?, &owners, &shares, &mut report).await?;
            storage.put(&StorageEntry { key: registry_key(PLAN_KEY), value: serde_json::to_vec(&plan)? }).await?;
            plan
        }
    };
    apply(&plan, &owners, &shares, &mut report).await?;
    report.scopes_reindexed = reindex_asset_groups(core).await?;

    let marker = serde_json::to_vec(&KV_KEY_SPLIT_VERSION)?;
    storage.put(&StorageEntry { key: registry_key(MARKER_KEY), value: marker }).await?;
    storage.delete(&registry_key(PLAN_KEY)).await?;
    owners.set_kv_keys_split();
    log::info!(target: "migration", "kv key split datafix v{KV_KEY_SPLIT_VERSION} complete: {report:?}");
    Ok(report)
}

/// Test support: forget that the datafix ran, so a test can plant pre-T499
/// records and run it. The in-memory switch stays as it is.
#[cfg(any(test, feature = "test-support"))]
pub async fn reset_for_test(core: &crate::core::Core) -> Result<(), RvError> {
    core.barrier().as_storage().delete(&registry_key(MARKER_KEY)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(router_key: &str, v2: bool, ns: Option<&str>) -> KvMount {
        KvMount { router_key: router_key.into(), v2, secrets_prefix: String::new(), ns: ns.map(String::from) }
    }

    #[test]
    fn the_keys_of_a_secret_before_and_after() {
        let root = mount("secret/", true, None);
        assert_eq!(root.keys("data/x"), (Some("secret/x".into()), "secret/data/x".into()));
        assert_eq!(root.keys("team/x"), (Some("secret/team/x".into()), "secret/team/x".into()));
        let v1 = mount("kv/", false, None);
        assert_eq!(v1.keys("data/metadata/x"), (Some("kv/x".into()), "kv/data/metadata/x".into()));
        let ns = mount("team/data/secret/", true, Some("team/data"));
        assert_eq!(ns.keys("x"), (Some("team/secret/x".into()), "team/data/secret/x".into()));
        let nested = mount("team/secret/", true, Some("team"));
        assert_eq!(nested.keys("data/x"), (Some("team/secret/data/x".into()), "team/secret/data/x".into()));
    }
}
