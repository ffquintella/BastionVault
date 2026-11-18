//! One-shot migration (T507): key asset-group KV-secret members on the
//! secret's own name. A format 0 member becomes every own name a pre-T507
//! lookup reached it by, through the mount table the shared router uses,
//! when that is exact; one that matched a kv-v2 secret through some routes
//! only, or no mount, is kept with the pre-T507 rule (Ruling BB: no
//! widening). Several secrets, or a kept member, are logged for operators.

use std::{collections::VecDeque, sync::Arc};

use super::{
    group_store::{scope_of, ResourceGroupStore, SECRETS_FORMAT},
    secret_names::{convert_member, AllMounts, Conversion, Reading},
    ResourceGroupModule,
};
use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    modules::namespace::{router::namespace_mount_config_path, store::NamespaceStore},
    mount::MountTable,
};

/// Verify passes before the pass gives up: a write landing between a
/// record's read and its conversion leaves it for the next one.
const PASSES: usize = 3;

/// What the migration did, for the log and tests (key names only).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecretNameReport {
    /// Group records converted to format 1.
    pub groups_converted: usize,
    /// Members that reached one secret, under another key than before.
    pub members_rekeyed: usize,
    /// Members that reached several secrets: each kept (logged as a list).
    pub members_ambiguous: usize,
    /// Members kept with the pre-T507 rule: route-specific, or no mount.
    pub members_kept_legacy: usize,
    /// True when the marker was already set and nothing was done.
    pub skipped: bool,
}

/// Every namespace's scope, and every logical mount by the router key the
/// shared router gives it, from the stored tables. A namespace without a
/// table has none; any other failure fails the pass.
async fn all_mounts(core: &crate::core::Core) -> Result<(Vec<String>, AllMounts), RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let hmac_key = core.hmac_key().clone();
    let (mut scopes, mut mounts) = (Vec::new(), Vec::new());
    for ns in NamespaceStore::new(core)?.list_all().await? {
        let (config_path, prefix) = match ns.is_root() {
            true => (core.mounts_router().mounts.path.clone(), String::new()),
            false => (namespace_mount_config_path(&ns.uuid), format!("{}/", ns.path.trim_end_matches('/'))),
        };
        let table = MountTable::new(&config_path);
        match table.load(storage, Some(&hmac_key), core.mount_entry_hmac_level()).await {
            Ok(_) => {
                let entries = table.entries.read()?;
                let rows =
                    entries.values().filter_map(|e| e.read().ok().map(|m| (m.path.clone(), m.logical_type.clone())));
                mounts.extend(rows.map(|(path, ty)| (format!("{prefix}{path}"), ty)));
            }
            Err(RvError::ErrConfigLoadFailed) => {}
            Err(e) => {
                log::warn!(target: "migration", "asset-group key switch: the mount table of namespace {:?} is unreadable", ns.path);
                return Err(e);
            }
        }
        scopes.push(scope_of((!ns.is_root()).then_some(ns.path.as_str())));
    }
    Ok((scopes, AllMounts(mounts)))
}

fn describe(scope: &str) -> String {
    match scope {
        "" => "the root namespace".to_string(),
        ns => format!("namespace {ns:?}"),
    }
}

/// Log and count one converted member (key names only, never values): a
/// re-key at info; several secrets, or a member kept with the pre-T507
/// rule, at warn; an unchanged one-secret member not at all.
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
        Reading::KeptRouteSpecific | Reading::KeptNoMount => {
            report.members_kept_legacy += 1;
            let why = match c.reading {
                Reading::KeptRouteSpecific => "matched a kv-v2 secret through some of its routes only",
                _ => "matches no mount",
            };
            log::warn!(
                target: "migration",
                "asset-group key switch: member {member:?} of group {group:?} in {at} {why}; it is kept with the \
                 pre-T507 rule (`secrets_legacy_kept`), whose data/x-is-x collision stays for it until it is \
                 removed and its secret added by its own name"
            );
        }
    }
}

/// One unit of the migration's work.
#[derive(Debug)]
enum Step {
    /// Convert one format 0 record.
    Convert { scope: String, group: String },
    /// Add any index entry a converted record lacks; re-queue what is left.
    Verify,
    /// Set the marker: lookups use own names from here on.
    Mark,
    /// Convert, additively, what a racing write left format 0 after Verify.
    Final { scope: String },
}

/// The migration as a sequence of small steps, so a test can check the
/// decisions requests get between any two of them. No step deletes an index
/// entry a lookup may read: entries are added before a record is written,
/// and the live indexes are never rebuilt (T507 review, fix round 1).
pub struct SecretNameMigration {
    store: Arc<ResourceGroupStore>,
    scopes: Vec<String>,
    mounts: AllMounts,
    steps: VecDeque<Step>,
    passes: usize,
    report: SecretNameReport,
}

impl SecretNameMigration {
    /// The pass, ready to step; `None` when its marker is already set.
    pub async fn start(core: &crate::core::Core) -> Result<Option<Self>, RvError> {
        let module = core.module_manager().get_module::<ResourceGroupModule>("resource-group");
        let store =
            module.and_then(|m| m.store()).ok_or_else(|| crate::bv_error_string!("asset-group store unavailable"))?;
        if store.secret_names().await? {
            return Ok(None);
        }
        let (scopes, mounts) = all_mounts(core).await?;
        let mut steps = VecDeque::new();
        for scope in &scopes {
            for group in store.list_groups(scope).await? {
                steps.push_back(Step::Convert { scope: scope.clone(), group });
            }
        }
        steps.push_back(Step::Verify);
        Ok(Some(Self { store, scopes, mounts, steps, passes: 0, report: SecretNameReport::default() }))
    }

    /// What the pass did so far.
    pub fn report(&self) -> &SecretNameReport {
        &self.report
    }

    /// Run the next step; `false` when none is left.
    pub async fn step(&mut self) -> Result<bool, RvError> {
        let Some(step) = self.steps.pop_front() else {
            return Ok(false);
        };
        match step {
            Step::Convert { scope, group } => self.convert(&scope, &group).await?,
            Step::Verify => self.verify().await?,
            Step::Mark => {
                self.store.mark_secret_names().await?;
                self.steps.extend(self.scopes.iter().map(|scope| Step::Final { scope: scope.clone() }));
            }
            Step::Final { scope } => {
                for group in self.store.list_groups(&scope).await? {
                    self.convert(&scope, &group).await?;
                }
            }
        }
        Ok(true)
    }

    /// Convert group `group` of `scope` if it is still format 0.
    async fn convert(&mut self, scope: &str, group: &str) -> Result<(), RvError> {
        let Some(g) = self.store.get_group(group, scope).await? else {
            return Ok(());
        };
        if g.secrets_format >= SECRETS_FORMAT {
            return Ok(());
        }
        let mounts = &self.mounts;
        let conversions: Vec<(&String, Conversion)> = g
            .secrets
            .iter()
            .map(|m| convert_member(m, |p| Ok(mounts.target(scope, p))).map(|c| (m, c)))
            .collect::<Result<_, RvError>>()?;
        let (mut own, mut kept) = (Vec::new(), Vec::new());
        for (_, c) in &conversions {
            match c.reading.kept() {
                true => kept.extend(c.keys.iter().cloned()),
                false => own.extend(c.keys.iter().cloned()),
            }
        }
        if self.store.convert_record(group, scope, &g.secrets, &own, &kept).await? {
            self.report.groups_converted += 1;
            for (member, c) in &conversions {
                record(&mut self.report, group, scope, member, c);
            }
        }
        Ok(())
    }

    /// Add what converted records lack in the indexes (additive only: while
    /// pending nothing may leave a group, so nothing stale can be re-added),
    /// then mark, or re-queue records a racing write kept at format 0.
    async fn verify(&mut self) -> Result<(), RvError> {
        // Another node finished and marked meanwhile: its own final pass ran.
        if self.store.secret_names().await? {
            self.steps.clear();
            return Ok(());
        }
        let mut left = Vec::new();
        for scope in &self.scopes {
            for group in self.store.repair_converted(scope).await? {
                left.push(Step::Convert { scope: scope.clone(), group });
            }
        }
        if left.is_empty() {
            self.steps.push_back(Step::Mark);
            return Ok(());
        }
        self.passes += 1;
        if self.passes >= PASSES {
            return Err(crate::bv_error_string!(format!(
                "asset-group key switch: {} group records changed while being converted; the pass is retried",
                left.len()
            )));
        }
        self.steps.extend(left);
        self.steps.push_back(Step::Verify);
        Ok(())
    }
}

/// Run the migration unless its replicated marker is set; until it is, lookups
/// keep the pre-T507 keys and secret-membership changes are refused. Called
/// from `Core::post_unseal` after the T499 datafix; a failure is retried in
/// the background (`identity::kv_key_split_retry`) and at the next unseal.
pub async fn run_if_needed(core: &crate::core::Core) -> Result<SecretNameReport, RvError> {
    let Some(mut pass) = SecretNameMigration::start(core).await? else {
        return Ok(SecretNameReport { skipped: true, ..Default::default() });
    };
    while pass.step().await? {}
    let report = pass.report().clone();
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
