//! One-shot migration (T507): key asset-group KV-secret members on the
//! secret's own name. A format 0 member lost a `data`/`metadata` second
//! segment whatever the mount (on a kv v1 mount `x`, `data/x` and `metadata/x`
//! were one member); it becomes every own name a pre-T507 lookup reached it
//! by, through its namespace's mount table: exactly the access it gave. One
//! that reached several keeps them all and is logged, so operators can prune.

use super::{
    group_store::{scope_of, ResourceGroupStore, SECRETS_FORMAT},
    secret_names::{convert_member, Conversion, NsMounts, Reading},
    ResourceGroupModule,
};
use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    modules::namespace::{router::namespace_mount_config_path, store::NamespaceStore},
    mount::MountTable,
};

/// Passes over the records before the pass gives up: a write landing between
/// a record's read and its conversion leaves it for the next pass.
const PASSES: usize = 3;

/// What the migration did, for the log and tests (key names only).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SecretNameReport {
    /// Group records converted to format 1.
    pub groups_converted: usize,
    /// Members that reached one secret, under another key than before.
    pub members_rekeyed: usize,
    /// Members that reached several secrets: each kept (logged as a list).
    pub members_ambiguous: usize,
    /// Members no lookup reaches with the current mounts: kept as written.
    pub members_unresolved: usize,
    /// True when the marker was already set and nothing was done.
    pub skipped: bool,
}

/// Every namespace's scope and logical mounts, from the stored tables. A
/// namespace without a table has none; any other failure fails the pass.
async fn scopes(core: &crate::core::Core) -> Result<Vec<(String, NsMounts)>, RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let hmac_key = core.hmac_key().clone();
    let mut out = Vec::new();
    for ns in NamespaceStore::new(core)?.list_all().await? {
        let config_path = match ns.is_root() {
            true => core.mounts_router().mounts.path.clone(),
            false => namespace_mount_config_path(&ns.uuid),
        };
        let table = MountTable::new(&config_path);
        let mounts = match table.load(storage, Some(&hmac_key), core.mount_entry_hmac_level()).await {
            Ok(_) => {
                let entries = table.entries.read()?;
                let rows =
                    entries.values().filter_map(|e| e.read().ok().map(|m| (m.path.clone(), m.logical_type.clone())));
                NsMounts(rows.collect())
            }
            Err(RvError::ErrConfigLoadFailed) => NsMounts::default(),
            Err(e) => {
                log::warn!(target: "migration", "asset-group key switch: the mount table of namespace {:?} is unreadable", ns.path);
                return Err(e);
            }
        };
        out.push((scope_of((!ns.is_root()).then_some(ns.path.as_str())), mounts));
    }
    Ok(out)
}

fn describe(scope: &str) -> String {
    match scope {
        "" => "the root namespace".to_string(),
        ns => format!("namespace {ns:?}"),
    }
}

/// Log and count one converted member (key names only, never values).
fn record(report: &mut SecretNameReport, group: &str, scope: &str, member: &str, c: &Conversion) {
    let at = describe(scope);
    match c.reading {
        Reading::One if c.keys.first().map(String::as_str) == Some(member) => {}
        Reading::One => {
            report.members_rekeyed += 1;
            log::info!(target: "migration", "asset-group key switch: member {member:?} of group {group:?} in {at} is now {:?}", c.keys[0]);
        }
        Reading::Several => {
            report.members_ambiguous += 1;
            log::warn!(
                target: "migration",
                "asset-group key switch: member {member:?} of group {group:?} in {at} reached {:?} before T507; \
                 each keeps the membership, remove from the group the ones it should not list",
                c.keys
            );
        }
        Reading::Unresolved => {
            report.members_unresolved += 1;
            log::warn!(
                target: "migration",
                "asset-group key switch: member {member:?} of group {group:?} in {at} matches no mount; kept as \
                 written, now read as a secret's own name"
            );
        }
    }
}

/// Convert every format 0 record of every scope and rebuild each scope's
/// name index. Returns the records still format 0 (changed under the pass).
async fn convert_all(
    store: &ResourceGroupStore,
    scopes: &[(String, NsMounts)],
    report: &mut SecretNameReport,
) -> Result<usize, RvError> {
    let mut left = 0;
    for (scope, mounts) in scopes {
        let groups = store.list_groups(scope).await?;
        if groups.is_empty() {
            continue;
        }
        for name in &groups {
            let Some(g) = store.get_group(name, scope).await? else {
                continue;
            };
            if g.secrets_format >= SECRETS_FORMAT {
                continue;
            }
            let conversions: Vec<(&String, Conversion)> = g
                .secrets
                .iter()
                .map(|m| convert_member(m, |p| Ok(mounts.target(p))).map(|c| (m, c)))
                .collect::<Result<_, RvError>>()?;
            let keys: Vec<String> = conversions.iter().flat_map(|(_, c)| c.keys.iter().cloned()).collect();
            if store.convert_record(name, scope, &g.secrets, &keys).await? {
                report.groups_converted += 1;
                for (member, c) in &conversions {
                    record(report, name, scope, member, c);
                }
            }
        }
        left += store.rebuild_name_index(scope).await?.len();
    }
    Ok(left)
}

/// Run the migration unless its replicated marker is set; until it is, lookups
/// keep the pre-T507 keys and secret-membership changes are refused. Called
/// from `Core::post_unseal` after the T499 datafix; a failure is retried in
/// the background (`identity::kv_key_split_retry`) and at the next unseal.
pub async fn run_if_needed(core: &crate::core::Core) -> Result<SecretNameReport, RvError> {
    let mut report = SecretNameReport::default();
    let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group");
    let store =
        module.and_then(|m| m.store()).ok_or_else(|| crate::bv_error_string!("asset-group store unavailable"))?;
    if store.secret_names().await? {
        report.skipped = true;
        return Ok(report);
    }
    let scopes = scopes(core).await?;
    let mut left = 0;
    for _ in 0..PASSES {
        left = convert_all(&store, &scopes, &mut report).await?;
        if left == 0 {
            break;
        }
    }
    if left > 0 {
        return Err(crate::bv_error_string!(format!(
            "asset-group key switch: {left} group records changed while being converted; the pass is retried"
        )));
    }
    store.mark_secret_names().await?;
    // A write prepared on a format 0 read and landing after the last pass:
    // once marked, no store method writes one back, so this pass is final.
    convert_all(&store, &scopes, &mut report).await?;
    log::info!(target: "migration", "asset-group key switch (format {SECRETS_FORMAT}) complete: {report:?}");
    Ok(report)
}

/// Test support: forget that the migration ran, so a test can plant format 0
/// records and run it.
#[cfg(any(test, feature = "test-support"))]
pub async fn reset_for_test(core: &crate::core::Core) -> Result<(), RvError> {
    let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group");
    let store = module.and_then(|m| m.store()).ok_or_else(|| crate::bv_error_string!("no asset-group store"))?;
    store.unmark_secret_names_for_test().await
}

/// Test support: a pass cut short after converting only the records of
/// `scope` named in `only`, as one interrupted by a crash; nothing is marked.
#[cfg(any(test, feature = "test-support"))]
pub async fn convert_some_for_test(core: &crate::core::Core, scope: &str, only: &[&str]) -> Result<(), RvError> {
    let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group");
    let store = module.and_then(|m| m.store()).ok_or_else(|| crate::bv_error_string!("no asset-group store"))?;
    let mounts = scopes(core).await?.into_iter().find(|(s, _)| s == scope).map(|(_, m)| m).unwrap_or_default();
    for name in only {
        let Some(g) = store.get_group(name, scope).await? else {
            continue;
        };
        let mut keys = Vec::new();
        for m in &g.secrets {
            keys.extend(convert_member(m, |p| Ok(mounts.target(p)))?.keys);
        }
        store.convert_record(name, scope, &g.secrets, &keys).await?;
    }
    Ok(())
}
