//! One-shot datafix (T499): give every KV secret an owner and share key of its own.
//!
//! Before T499 a KV key was canonicalized twice, so `x` and `data/x` (and the
//! secrets of a namespace or mount named `data`) shared one record. For each
//! existing secret whose new key differs, its new key is made to hold exactly
//! what its old key held, so no secret changes hands; then the asset-group
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
            store::NamespaceStore,
        },
        resource_group::{group_store::scope_of, ResourceGroupModule},
    },
    mount::MountTable,
    storage::Storage,
};

pub use super::owner_store::KV_KEY_SPLIT_VERSION;

/// The plan of a pass that has not finished yet, under `sys/owner/meta/`.
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
    /// New keys whose record or shares differed from the old key's and were
    /// replaced by them (each logged, key names only).
    pub replaced: usize,
    /// Moved secrets whose old key is another live secret's key: the two
    /// shared one record before T499 (each pair logged, key names only).
    pub shared_pairs: usize,
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
/// A namespace without a table has no mounts; any other failure to read one
/// fails the pass, so no namespace's secrets are skipped unseen.
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
        match table.load(storage, Some(&hmac_key), core.mount_entry_hmac_level()).await {
            Ok(_) => {}
            Err(RvError::ErrConfigLoadFailed) => continue,
            Err(e) => {
                log::warn!(target: "migration", "kv key split: the mount table of namespace {:?} is unreadable", ns.path);
                return Err(e);
            }
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

/// Whether `key` is the key of a secret that exists: the mount with the
/// longest router key it starts with holds a secret of the remaining name.
async fn is_live(storage: &dyn Storage, mounts: &[KvMount], key: &str) -> Result<bool, RvError> {
    let mount = mounts.iter().filter(|m| key.starts_with(&m.router_key)).max_by_key(|m| m.router_key.len());
    let Some(mount) = mount else {
        return Ok(false);
    };
    let name = &key[mount.router_key.len()..];
    Ok(!name.is_empty() && storage.get(&format!("{}{name}", mount.secrets_prefix)).await?.is_some())
}

/// Every existing secret whose key changes, across all KV mounts. A pair of
/// secrets that shared one record (the old key is a live secret's key) is
/// logged by key names, so operators can review who owns them.
async fn moves(core: &crate::core::Core, report: &mut KvKeySplitReport) -> Result<Vec<Move>, RvError> {
    let ns_store = NamespaceStore::new(core)?;
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let mounts = kv_mounts(core, &ns_store).await?;
    let mut out = Vec::new();
    for mount in &mounts {
        for name in changed_names(storage, mount).await? {
            let (Some(old), new) = mount.keys(&name) else {
                continue;
            };
            if is_live(storage, &mounts, &old).await? {
                report.shared_pairs += 1;
                log::warn!(
                    target: "migration",
                    "kv key split: {new:?} and {old:?} shared one owner and share record before T499; \
                     each keeps it, review who owns them"
                );
            }
            out.push(Move { old, new });
        }
    }
    Ok(out)
}

/// The writes that leave every moved secret with exactly what its old key
/// held, read from one snapshot before anything is written. A different
/// record already at a new key was never written by this release's keys
/// while the switch was off (a stale claim, a deleted nested secret's old
/// key): the old key's wins, and the replacement is logged.
async fn build_plan(
    moves: &[Move],
    owners: &OwnerStore,
    shares: &ShareStore,
    report: &mut KvKeySplitReport,
) -> Result<Plan, RvError> {
    let mut plan = Plan::default();
    for m in moves {
        let from = owners.get_kv_owner(&m.old).await?;
        let at = owners.get_kv_owner(&m.new).await?;
        let (from_id, at_id) = (from.as_ref().map(|r| &r.entity_id), at.as_ref().map(|r| &r.entity_id));
        if from_id != at_id {
            if at.is_some() {
                report.replaced += 1;
                log::warn!(target: "migration", "kv key split: the owner record at {:?} replaced by {:?}'s", m.new, m.old);
            }
            plan.owners.push((m.new.clone(), from));
        }

        let from = shares.list_shares_for_target(ShareTargetKind::KvSecret, &m.old).await?;
        let at = shares.list_shares_for_target(ShareTargetKind::KvSecret, &m.new).await?;
        let grantee = |s: &SecretShare| (s.grantee_kind.clone(), s.grantee_entity_id.clone());
        let keep: HashSet<(String, String)> = from.iter().map(grantee).collect();
        let drop: Vec<(String, String)> = at.iter().map(grantee).filter(|g| !keep.contains(g)).collect();
        if !from.is_empty() || !drop.is_empty() {
            if !drop.is_empty() {
                report.replaced += 1;
                log::warn!(target: "migration", "kv key split: the shares at {:?} replaced by {:?}'s", m.new, m.old);
            }
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
        for (grantee_kind, grantee) in drop {
            let kind = ShareGranteeKind::parse(grantee_kind).unwrap_or(ShareGranteeKind::Entity);
            shares
                .delete_share_with_kind_audited(ShareTargetKind::KvSecret, key, kind, grantee, ACTOR, "revoke")
                .await?;
            report.shares_dropped += 1;
        }
        report.shares_copied += shares.copy_shares_to(ShareTargetKind::KvSecret, copy, key, ACTOR).await?;
    }
    Ok(())
}

/// Rebuild the asset-group indexes of every scope that has groups: they filed
/// a member under a second canonicalization of its path, which the group
/// records never did.
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

/// Run the datafix unless its replicated marker is set; until it is, KV keys
/// keep their pre-T499 form on every node, so records keep resolving. Called
/// from `Core::post_unseal` on every node after module init; an error is
/// logged there and the pass retries on the next unseal, marker unset.
pub async fn run_if_needed(core: &crate::core::Core) -> Result<KvKeySplitReport, RvError> {
    let mut report = KvKeySplitReport::default();
    let identity = core.module_manager().get_module::<IdentityModule>("identity");
    let identity = identity.ok_or_else(|| crate::bv_error_string!("kv key split: identity module unavailable"))?;
    let owners = identity.owner_store().ok_or_else(|| crate::bv_error_string!("kv key split: no owner store"))?;
    let shares = identity.share_store().ok_or_else(|| crate::bv_error_string!("kv key split: no share store"))?;

    if owners.kv_keys_split().await? {
        report.skipped = true;
        return Ok(report);
    }

    let plan = match owners.meta_get(PLAN_KEY).await? {
        Some(raw) => serde_json::from_slice::<Plan>(&raw)?,
        None => {
            let plan = build_plan(&moves(core, &mut report).await?, &owners, &shares, &mut report).await?;
            // Another node may have finished while this one read (HA): no-op.
            if owners.kv_keys_split().await? {
                report.skipped = true;
                return Ok(report);
            }
            owners.meta_put(PLAN_KEY, serde_json::to_vec(&plan)?).await?;
            plan
        }
    };
    apply(&plan, &owners, &shares, &mut report).await?;
    report.scopes_reindexed = reindex_asset_groups(core).await?;

    owners.mark_kv_keys_split().await?;
    owners.meta_delete(PLAN_KEY).await?;
    log::info!(target: "migration", "kv key split datafix v{KV_KEY_SPLIT_VERSION} complete: {report:?}");
    Ok(report)
}

/// Test support: forget that the datafix ran (marker and switch), so a test
/// can plant pre-T499 records and run it.
#[cfg(any(test, feature = "test-support"))]
pub async fn reset_for_test(core: &crate::core::Core) -> Result<(), RvError> {
    let identity = core.module_manager().get_module::<IdentityModule>("identity");
    let owners = identity.and_then(|m| m.owner_store()).ok_or_else(|| crate::bv_error_string!("no owner store"))?;
    owners.unsplit_kv_keys_for_test().await
}

/// Test support: a pass that stops right after saving its plan, as one cut
/// short by a crash would; the next `run_if_needed` resumes from that plan.
#[cfg(any(test, feature = "test-support"))]
pub async fn plan_only_for_test(core: &crate::core::Core) -> Result<(), RvError> {
    let identity = core.module_manager().get_module::<IdentityModule>("identity");
    let identity = identity.ok_or_else(|| crate::bv_error_string!("no identity module"))?;
    let owners = identity.owner_store().ok_or_else(|| crate::bv_error_string!("no owner store"))?;
    let shares = identity.share_store().ok_or_else(|| crate::bv_error_string!("no share store"))?;
    let mut report = KvKeySplitReport::default();
    let plan = build_plan(&moves(core, &mut report).await?, &owners, &shares, &mut report).await?;
    owners.meta_put(PLAN_KEY, serde_json::to_vec(&plan)?).await
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
