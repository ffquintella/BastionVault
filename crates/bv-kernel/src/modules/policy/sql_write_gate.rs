//! The rolling-upgrade write gate for `sql_*` capabilities (D4).
//!
//! A pre-T124 node refuses a whole policy naming an unknown capability, and
//! cannot unseal when the stored `default` does. So `sql_*` is written only
//! once every Raft member reports a build that parses it, and the open gate
//! is latched. Design: features/sql-browser.md, "Phase 1, subsystem 4".

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::Ordering, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{policy::Capability, Policy};
use crate::{
    bv_error_response_status, bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// The policy language this build parses: 1 is the pre-T124 vocabulary, 2
/// adds the eleven `sql_*` capabilities.
pub const NODE_POLICY_SCHEMA: u32 = 2;
/// The first policy schema that parses `sql_*`.
pub const SQL_POLICY_SCHEMA: u32 = 2;
/// The plugin host ABI minor this build serves. The kernel sits below
/// `bv_plugin_manifest`, so it keeps a copy; the facade test
/// `node_host_abi_minor_matches_the_manifest_host` pins the two.
pub const NODE_HOST_ABI_MINOR: u32 = 4;
/// The plugin host ABI minor that ships the SQL browser host calls.
pub const SQL_MIN_HOST_ABI_MINOR: u32 = 4;
/// How often an unsealed node refreshes its record while the gate is closed.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
/// An older record is a node that stopped reporting, e.g. one rolled back to
/// a build that does not refresh it.
pub const RECORD_TTL_SECS: u64 = 180;
/// A record dated further ahead is refused, so a fast clock cannot keep a
/// record fresh past the TTL.
pub const MAX_FUTURE_SKEW_SECS: u64 = 30;
/// Version of [`NodeSchemaRecord`].
pub const NODE_RECORD_VERSION: u32 = 1;
/// Version of [`SqlGateLatch`].
pub const LATCH_VERSION: u32 = 1;
/// The label a deployment that is not a Raft cluster records itself under.
pub const STANDALONE_NODE: &str = "standalone";

// System-view keyspace: a sibling of `policy/`, never inside it, so neither
// record is ever listed or read as a policy.
const GATE_SUB_PATH: &str = "policy-schema/";
const NODES_PREFIX: &str = "nodes/";
const LATCH_KEY: &str = "sql-gate";

/// Opening marker of the SQL rule in a gated baseline (an HCL comment, so
/// the full text parses as it stands).
pub(crate) const SQL_RULE_BEGIN: &str = "# >>> gated: sql capabilities";
/// Closing marker of the SQL rule in a gated baseline.
pub(crate) const SQL_RULE_END: &str = "# <<< gated: sql capabilities";

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rfc3339(secs: u64) -> Value {
    match chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0) {
        Some(t) => Value::String(t.to_rfc3339()),
        None => Value::Null,
    }
}

/// One node's report, at `policy-schema/nodes/<node>`. Read strictly: another
/// `v`, or bytes that do not parse, do not count for the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSchemaRecord {
    pub v: u32,
    /// The Raft node id in decimal, or [`STANDALONE_NODE`].
    pub node: String,
    pub policy_schema: u32,
    pub host_abi_minor: u32,
    /// Unix seconds, from the writing node's clock.
    pub updated_at: u64,
}

impl NodeSchemaRecord {
    /// The record this build writes for `node` at `now`.
    pub fn this_build(node: &str, now: u64) -> Self {
        Self {
            v: NODE_RECORD_VERSION,
            node: node.to_string(),
            policy_schema: NODE_POLICY_SCHEMA,
            host_abi_minor: NODE_HOST_ABI_MINOR,
            updated_at: now,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let record: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("its version record is malformed ({e})"))?;
        if record.v != NODE_RECORD_VERSION {
            return Err(format!(
                "its version record has version {} and this build reads version {NODE_RECORD_VERSION}",
                record.v
            ));
        }
        if record.node.is_empty() {
            return Err("its version record names no node".to_string());
        }
        Ok(record)
    }
}

/// The latch at `policy-schema/sql-gate`: the gate opened, and on what
/// evidence. One that does not parse is not trusted; the gate is decided
/// from the node records again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlGateLatch {
    pub v: u32,
    /// Unix seconds, from the opening node's clock.
    pub opened_at: u64,
    pub opened_by: String,
    /// The members that qualified when the gate opened.
    pub members: Vec<String>,
}

impl SqlGateLatch {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let latch: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("the SQL write gate record is malformed ({e})"))?;
        if latch.v != LATCH_VERSION {
            return Err(format!(
                "the SQL write gate record has version {} and this build reads version {LATCH_VERSION}",
                latch.v
            ));
        }
        if latch.opened_by.is_empty() || latch.members.is_empty() {
            return Err("the SQL write gate record names no node".to_string());
        }
        Ok(latch)
    }
}

/// Which nodes must report before the gate opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Membership {
    /// Not a Raft cluster: the evaluating process is the only node.
    Standalone,
    /// The Raft membership, voters and learners.
    Raft(BTreeSet<u64>),
}

/// The Raft member ids in hiqlite's metrics (openraft `RaftMetrics`:
/// `membership_config.membership.{configs,nodes}`; learners are in `nodes`
/// only). Any other shape is an error, never an empty cluster.
pub fn raft_member_ids(metrics: &Value) -> Result<BTreeSet<u64>, String> {
    let membership = metrics
        .get("membership_config")
        .and_then(|m| m.get("membership"))
        .ok_or_else(|| "the Raft metrics carry no membership".to_string())?;
    let mut ids = BTreeSet::new();
    let Some(Value::Object(nodes)) = membership.get("nodes") else {
        return Err("the Raft membership has no node map".to_string());
    };
    for key in nodes.keys() {
        let id =
            key.parse::<u64>().map_err(|_| format!("the Raft membership names {key:?}, which is not a node id"))?;
        ids.insert(id);
    }
    let Some(Value::Array(configs)) = membership.get("configs") else {
        return Err("the Raft membership has no voter configuration".to_string());
    };
    for config in configs {
        let Value::Array(voters) = config else {
            return Err("a Raft voter configuration is not a list".to_string());
        };
        for voter in voters {
            ids.insert(voter.as_u64().ok_or_else(|| format!("the Raft voter {voter} is not a node id"))?);
        }
    }
    if ids.is_empty() {
        return Err("the Raft membership is empty".to_string());
    }
    Ok(ids)
}

/// Every record found, by the key it is stored under.
pub type NodeRecords = BTreeMap<String, Result<NodeSchemaRecord, String>>;

/// One node as the gate sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEvidence {
    pub node: String,
    /// Must this node report? A former member's record is listed only.
    pub member: bool,
    pub record: Option<NodeSchemaRecord>,
    /// Why this member keeps the gate closed; `None` if it qualifies or is
    /// not a member.
    pub problem: Option<String>,
}

/// What the gate decided from, and whether it may open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub this_node: String,
    pub membership: Result<Membership, String>,
    pub members: Vec<String>,
    pub nodes: Vec<NodeEvidence>,
    /// `None` when every member qualifies.
    pub blocker: Option<String>,
}

impl Evidence {
    pub fn ready(&self) -> bool {
        self.blocker.is_none()
    }
}

/// Why `record` does not let `node` count towards opening the gate at `now`.
fn judge(node: &str, record: Option<&Result<NodeSchemaRecord, String>>, now: u64) -> Option<String> {
    let record =
        match record {
            None => return Some(
                "no version record: it runs a build older than the SQL write gate, or has not unsealed since it was \
                 upgraded"
                    .to_string(),
            ),
            Some(Err(problem)) => return Some(problem.clone()),
            Some(Ok(record)) => record,
        };
    if record.node != node {
        return Some(format!("its version record names node {:?}", record.node));
    }
    if record.policy_schema < SQL_POLICY_SCHEMA {
        return Some(format!(
            "it reports policy schema {}, which cannot parse sql_* (needs {SQL_POLICY_SCHEMA})",
            record.policy_schema
        ));
    }
    if record.host_abi_minor < SQL_MIN_HOST_ABI_MINOR {
        return Some(format!(
            "it reports plugin host ABI 1.{} (needs 1.{SQL_MIN_HOST_ABI_MINOR})",
            record.host_abi_minor
        ));
    }
    if record.updated_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Some(format!(
            "its version record is dated {}s in the future; check the node clocks",
            record.updated_at - now
        ));
    }
    let age = now.saturating_sub(record.updated_at);
    if age > RECORD_TTL_SECS {
        return Some(format!(
            "its version record is {age}s old (limit {RECORD_TTL_SECS}s): the node has stopped reporting"
        ));
    }
    None
}

/// Decide the gate. Pure, so every fail-closed branch is unit-tested.
///
/// The evaluating process is this build by construction and is judged from
/// its constants, not from storage: a lagging write of its own record never
/// holds the gate shut, and a forged one cannot open it.
pub fn evaluate(
    this_node: &str,
    membership: Result<Membership, String>,
    records: Result<NodeRecords, String>,
    now: u64,
) -> Evidence {
    let mut records = match records {
        Ok(records) => records,
        Err(e) => {
            return Evidence {
                this_node: this_node.to_string(),
                membership,
                members: Vec::new(),
                nodes: Vec::new(),
                blocker: Some(format!("the node version records could not be read: {e}")),
            }
        }
    };
    records.insert(this_node.to_string(), Ok(NodeSchemaRecord::this_build(this_node, now)));

    let members: BTreeSet<String> = match &membership {
        Ok(Membership::Standalone) => [this_node.to_string()].into(),
        Ok(Membership::Raft(ids)) => ids.iter().map(u64::to_string).collect(),
        Err(_) => BTreeSet::new(),
    };
    let mut labels: BTreeSet<String> = records.keys().cloned().collect();
    labels.extend(members.iter().cloned());

    let mut nodes = Vec::new();
    let mut blockers = Vec::new();
    for label in labels {
        let member = members.contains(&label);
        let found = records.get(&label);
        let problem = if member { judge(&label, found, now) } else { None };
        if let Some(problem) = &problem {
            blockers.push(format!("node {label}: {problem}"));
        }
        nodes.push(NodeEvidence { node: label, member, record: found.and_then(|r| r.as_ref().ok()).cloned(), problem });
    }

    let blocker = match &membership {
        Err(e) => Some(format!("the cluster membership could not be read: {e}")),
        Ok(_) if members.is_empty() => Some("the cluster membership is empty".to_string()),
        Ok(_) => match blockers.len() {
            0 => None,
            1 => blockers.pop(),
            n => Some(format!("{} (and {} more)", blockers[0], n - 1)),
        },
    };
    Evidence { this_node: this_node.to_string(), membership, members: members.into_iter().collect(), nodes, blocker }
}

/// Does `policy` name any `sql_*` capability? Exactly what a pre-T124 node
/// cannot parse.
pub fn policy_names_sql_capabilities(policy: &Policy) -> bool {
    policy.paths.iter().any(|rule| {
        rule.capabilities.iter().any(Capability::is_sql)
            || rule.permissions.capabilities_bitmap & bv_policy_core::CAP_SQL_ALL != 0
    })
}

/// `text` without its one marked SQL rule; every other line is kept byte for
/// byte. Missing, repeated, nested or unbalanced markers are an error (a
/// programmer error in a built-in constant), never a guess.
pub(crate) fn without_gated_sql_rules(text: &str) -> Result<String, RvError> {
    let mut kept: Vec<&str> = Vec::new();
    let (mut begins, mut ends, mut inside) = (0usize, 0usize, false);
    for line in text.split('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with(SQL_RULE_BEGIN) {
            if inside {
                return Err(bv_error_string!("gated baseline: nested SQL rule marker"));
            }
            begins += 1;
            inside = true;
            continue;
        }
        if trimmed.starts_with(SQL_RULE_END) {
            if !inside {
                return Err(bv_error_string!("gated baseline: SQL rule end marker without a start"));
            }
            ends += 1;
            inside = false;
            continue;
        }
        if !inside {
            kept.push(line);
        }
    }
    if inside || begins != 1 || ends != 1 {
        return Err(bv_error_string!(format!(
            "gated baseline: expected exactly one marked SQL rule, found {begins} start and {ends} end markers"
        )));
    }
    Ok(kept.join("\n"))
}

/// The answer of `PolicyStore::sql_gate_check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlGateCheck {
    /// `None` when `sql_*` may be written.
    pub closed_reason: Option<String>,
    /// This call wrote the latch.
    pub newly_opened: bool,
}

impl SqlGateCheck {
    pub fn is_open(&self) -> bool {
        self.closed_reason.is_none()
    }
}

/// The refusal every gated write returns, naming what was refused and why.
fn gate_closed_error(what: &str, reason: &str) -> RvError {
    bv_error_response_status!(
        409,
        format!(
            "{what} names sql_* capabilities, which cannot be written until every cluster node parses them (policy \
             schema {SQL_POLICY_SCHEMA}, plugin host ABI 1.{SQL_MIN_HOST_ABI_MINOR}): {reason}. \
             `v2/sys/policy-schema` reports each node (features/sql-browser.md §13)"
        )
    )
}

/// Refuse a share that grants `sql_*` while the gate is closed. `store` is
/// `None` when the policy module cannot be reached: an unknown gate is a
/// closed gate.
pub async fn require_sql_share_writable(
    store: Option<&super::PolicyStore>,
    capabilities: &[String],
) -> Result<(), RvError> {
    let names_sql = capabilities
        .iter()
        .any(|c| crate::kernel_api::policy::SqlCapability::parse(&c.trim().to_lowercase()).is_some());
    if !names_sql {
        return Ok(());
    }
    match store {
        Some(store) => store.require_sql_writable("this share").await,
        None => Err(gate_closed_error("this share", "the policy module that holds the SQL write gate is unavailable")),
    }
}

/// Spawn the heartbeat (every [`HEARTBEAT_INTERVAL`], skipped while sealed;
/// a no-op once the gate is open and the baselines upgraded). Holds the core
/// weakly; detached, like the housekeeping task.
pub fn start_heartbeat(core: Weak<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let start = tokio::time::Instant::now() + HEARTBEAT_INTERVAL;
        let mut interval = tokio::time::interval_at(start, HEARTBEAT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let Some(core) = core.upgrade() else {
                log::debug!("policy schema: core dropped; heartbeat stopping");
                break;
            };
            if core.sealed() {
                continue;
            }
            let Some(module) = core.module_manager().get_module::<super::PolicyModule>("policy") else {
                continue;
            };
            let store = module.policy_store.load_full();
            drop(core);
            store.sql_gate_heartbeat().await;
        }
    })
}

/// The stored baselines that carry a marked SQL rule. `namespace-shared` is
/// parsed in process and never stored, so it needs no gate.
fn gated_baselines() -> [(&'static str, &'static str); 2] {
    [
        (super::policy_store::DEFAULT_POLICY_NAME, super::policy_store::DEFAULT_POLICY),
        (super::policy_store::SHARED_ACCESS_POLICY_NAME, super::policy_store::SHARED_ACCESS_POLICY),
    ]
}

#[maybe_async::maybe_async]
impl super::PolicyStore {
    fn sql_gate_view(&self) -> Result<BarrierView, RvError> {
        let system_view = self
            .system_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("system view unavailable for the policy-schema records"))?;
        Ok(system_view.new_sub_view(GATE_SUB_PATH))
    }

    /// This node's label and the membership that must report. No label when
    /// the core cannot be reached (a bare store).
    async fn sql_gate_topology(&self) -> (Option<String>, Result<Membership, String>) {
        if let Some((node, membership)) = self.sql_gate_test_topology() {
            return (Some(node), membership);
        }
        let Some(core) = self.core.upgrade() else {
            return (None, Err("the vault core is not reachable from this policy store".to_string()));
        };
        match crate::storage::cluster::status(core.physical.as_ref()).await {
            None => (Some(STANDALONE_NODE.to_string()), Ok(Membership::Standalone)),
            Some(status) => {
                let membership = match status.raft_metrics {
                    Some(metrics) => raft_member_ids(&metrics).map(Membership::Raft),
                    None => Err("the Raft engine did not return its metrics".to_string()),
                };
                (Some(status.node_id.to_string()), membership)
            }
        }
    }

    #[cfg(test)]
    fn sql_gate_test_topology(&self) -> Option<(String, Result<Membership, String>)> {
        self.sql_gate_test_topology.lock().unwrap().clone()
    }

    #[cfg(not(test))]
    fn sql_gate_test_topology(&self) -> Option<(String, Result<Membership, String>)> {
        None
    }

    /// Write this node's record. Called at unseal and by the heartbeat.
    pub async fn record_this_node(&self) -> Result<(), RvError> {
        let (node, _) = self.sql_gate_topology().await;
        let node =
            node.ok_or_else(|| bv_error_string!("this node's label is unknown: the vault core is not reachable"))?;
        let record = NodeSchemaRecord::this_build(&node, unix_now());
        let view = self.sql_gate_view()?;
        view.put(&StorageEntry::new(&format!("{NODES_PREFIX}{node}"), &record)?).await
    }

    async fn read_node_records(&self) -> Result<NodeRecords, String> {
        let view = self.sql_gate_view().map_err(|e| e.to_string())?;
        let keys = view.list(NODES_PREFIX).await.map_err(|e| e.to_string())?;
        let mut records = NodeRecords::new();
        for key in keys {
            if key.is_empty() || key.ends_with('/') {
                continue;
            }
            let parsed = match view.get(&format!("{NODES_PREFIX}{key}")).await {
                Ok(Some(entry)) => NodeSchemaRecord::parse(&entry.value),
                Ok(None) => continue,
                Err(e) => Err(format!("its version record could not be read ({e})")),
            };
            records.insert(key, parsed);
        }
        Ok(records)
    }

    /// The latch: `Ok(None)` when absent, `Err` when unreadable or malformed.
    async fn read_sql_gate_latch(&self) -> Result<Option<SqlGateLatch>, String> {
        let view = self.sql_gate_view().map_err(|e| e.to_string())?;
        match view.get(LATCH_KEY).await {
            Ok(None) => Ok(None),
            Ok(Some(entry)) => SqlGateLatch::parse(&entry.value).map(Some),
            Err(e) => Err(format!("the SQL write gate record could not be read ({e})")),
        }
    }

    /// The evidence the gate decides from, read fresh from storage.
    pub async fn sql_gate_evidence(&self) -> Evidence {
        let (node, membership) = self.sql_gate_topology().await;
        let records = self.read_node_records().await;
        let node = node.unwrap_or_else(|| "unknown".to_string());
        evaluate(&node, membership, records, unix_now())
    }

    /// May `sql_*` be written now? Latches the gate open when the evidence
    /// holds. Never fails: every error reads as closed, with its reason.
    pub async fn sql_gate_check(&self) -> SqlGateCheck {
        if self.sql_gate_open.load(Ordering::Acquire) {
            return SqlGateCheck { closed_reason: None, newly_opened: false };
        }
        match self.read_sql_gate_latch().await {
            Ok(Some(_)) => {
                self.sql_gate_open.store(true, Ordering::Release);
                return SqlGateCheck { closed_reason: None, newly_opened: false };
            }
            Ok(None) => {}
            Err(e) => log::warn!(
                target: "security",
                "policy schema: {e}; deciding the SQL write gate from the node version records instead"
            ),
        }

        let evidence = self.sql_gate_evidence().await;
        if let Some(blocker) = evidence.blocker {
            return SqlGateCheck { closed_reason: Some(blocker), newly_opened: false };
        }
        let latch = SqlGateLatch {
            v: LATCH_VERSION,
            opened_at: unix_now(),
            opened_by: evidence.this_node.clone(),
            members: evidence.members.clone(),
        };
        let written = match (self.sql_gate_view(), StorageEntry::new(LATCH_KEY, &latch)) {
            (Ok(view), Ok(entry)) => view.put(&entry).await,
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
        if let Err(e) = written {
            return SqlGateCheck {
                closed_reason: Some(format!(
                    "every node qualifies, but the SQL write gate record could not be written ({e})"
                )),
                newly_opened: false,
            };
        }
        self.sql_gate_open.store(true, Ordering::Release);
        log::info!(
            target: "security",
            "policy schema: every cluster node ({}) reports policy schema {SQL_POLICY_SCHEMA}+ and plugin host ABI \
             1.{SQL_MIN_HOST_ABI_MINOR}+; sql_* capabilities are now writable",
            evidence.members.join(", ")
        );
        SqlGateCheck { closed_reason: None, newly_opened: true }
    }

    /// Refuse a write that names `sql_*` unless the gate is open. Opening it
    /// here also upgrades the gated baselines.
    pub async fn require_sql_writable(&self, what: &str) -> Result<(), RvError> {
        self.sql_gate_open_or_reason().await.map_err(|reason| gate_closed_error(what, &reason))
    }

    /// The gate for a caller that words its own refusal (a BVBK restore,
    /// whose policies cannot be read before they land): `Err(reason)` while
    /// closed. Opening it here upgrades the gated baselines, as above.
    pub async fn sql_gate_open_or_reason(&self) -> Result<(), String> {
        let check = self.sql_gate_check().await;
        if check.newly_opened {
            self.upgrade_gated_baselines().await;
        }
        match check.closed_reason {
            None => Ok(()),
            Some(reason) => Err(reason),
        }
    }

    /// Force-load every gated baseline for the given gate state.
    pub(crate) async fn load_gated_baselines(&self, gate_open: bool) -> Result<(), RvError> {
        for (name, text) in gated_baselines() {
            self.force_load_gated_baseline(name, text, gate_open).await?;
        }
        Ok(())
    }

    /// Force-load a baseline whose bundled text carries a marked SQL rule:
    /// the full text when the gate is open, the text without the rule when it
    /// is closed. A stored copy that already carries `sql_*` is kept while the
    /// gate is closed, with an error logged: a stored `sql_*` policy is never
    /// removed automatically (D4).
    pub(crate) async fn force_load_gated_baseline(
        &self,
        policy_name: &str,
        full_text: &str,
        gate_open: bool,
    ) -> Result<(), RvError> {
        let name = self.sanitize_name(policy_name);
        let target = if gate_open { full_text.to_string() } else { without_gated_sql_rules(full_text)? };
        let existing = self.get_policy(&name, super::PolicyType::Acl).await?;
        if let Some(stored) = &existing {
            if stored.raw == target {
                return Ok(());
            }
            if !gate_open && policy_names_sql_capabilities(stored) {
                log::error!(
                    target: "security",
                    "policy schema: the stored `{name}` baseline carries sql_* rules while the SQL write gate is \
                     closed; it is left as stored (a stored sql_* policy is never removed automatically). A node \
                     older than policy schema {SQL_POLICY_SCHEMA} cannot load it"
                );
                return Ok(());
            }
        }
        let mut policy: Policy = target.parse()?;
        policy.name.clone_from(&name);
        policy.policy_type = super::PolicyType::Acl;
        self.put_policy_unchecked(std::sync::Arc::new(policy)).await
    }

    async fn upgrade_gated_baselines(&self) {
        match self.load_gated_baselines(true).await {
            Ok(()) => {
                self.sql_baselines_full.store(true, Ordering::Release);
                log::info!(
                    target: "security",
                    "policy schema: the `default` and `shared-access` baselines now carry their SQL rules"
                );
            }
            Err(e) => log::warn!(
                target: "security",
                "policy schema: the SQL write gate is open, but upgrading the `default` and `shared-access` \
                 baselines failed ({e}); the next heartbeat retries"
            ),
        }
    }

    /// One heartbeat: while the gate is closed, refresh this node's record
    /// and try to open it; once open, upgrade the gated baselines.
    pub async fn sql_gate_heartbeat(&self) {
        if self.sql_gate_open.load(Ordering::Acquire) && self.sql_baselines_full.load(Ordering::Acquire) {
            return;
        }
        if !self.sql_gate_open.load(Ordering::Acquire) {
            if let Err(e) = self.record_this_node().await {
                log::warn!("policy schema: this node's version record could not be written ({e})");
            }
            let check = self.sql_gate_check().await;
            if let Some(reason) = check.closed_reason {
                log::debug!("policy schema: the SQL write gate stays closed: {reason}");
                return;
            }
        }
        self.upgrade_gated_baselines().await;
    }

    /// `GET v2/sys/policy-schema`: the gate, each node's report and the
    /// gated baselines. Read-only: it never opens the gate.
    pub async fn sql_gate_status(&self) -> Map<String, Value> {
        let latch = self.read_sql_gate_latch().await;
        let evidence = self.sql_gate_evidence().await;
        let writable = self.sql_gate_open.load(Ordering::Acquire) || matches!(latch, Ok(Some(_)));

        let mut out = Map::new();
        out.insert("sql_capabilities_writable".into(), json!(writable));
        match &latch {
            Ok(Some(l)) => {
                out.insert("latched".into(), json!(true));
                out.insert("opened_at".into(), rfc3339(l.opened_at));
                out.insert("opened_by".into(), json!(l.opened_by));
            }
            Ok(None) => {
                out.insert("latched".into(), json!(false));
            }
            Err(e) => {
                out.insert("latched".into(), json!(false));
                out.insert("latch_error".into(), json!(e));
            }
        }
        out.insert("evidence_ready".into(), json!(evidence.ready()));
        if !writable {
            let reason = evidence
                .blocker
                .clone()
                .unwrap_or_else(|| "every node qualifies; the gate opens on the next policy write or heartbeat".into());
            out.insert("reason".into(), json!(reason));
        }
        out.insert(
            "this_node".into(),
            json!({
                "node": evidence.this_node,
                "policy_schema": NODE_POLICY_SCHEMA,
                "host_abi_minor": NODE_HOST_ABI_MINOR,
            }),
        );
        out.insert(
            "required".into(),
            json!({
                "policy_schema": SQL_POLICY_SCHEMA,
                "host_abi_minor": SQL_MIN_HOST_ABI_MINOR,
                "record_ttl_seconds": RECORD_TTL_SECS,
            }),
        );
        let membership = match &evidence.membership {
            Ok(Membership::Standalone) => "standalone",
            Ok(Membership::Raft(_)) => "raft",
            Err(_) => "unreadable",
        };
        out.insert("membership".into(), json!(membership));
        if let Err(e) = &evidence.membership {
            out.insert("membership_error".into(), json!(e));
        }
        let nodes: Vec<Value> = evidence
            .nodes
            .iter()
            .map(|n| {
                json!({
                    "node": n.node,
                    "member": n.member,
                    "policy_schema": n.record.as_ref().map(|r| r.policy_schema),
                    "host_abi_minor": n.record.as_ref().map(|r| r.host_abi_minor),
                    "updated_at": n.record.as_ref().map(|r| rfc3339(r.updated_at)),
                    "qualifies": n.member && n.problem.is_none(),
                    "problem": n.problem,
                })
            })
            .collect();
        out.insert("nodes".into(), Value::Array(nodes));

        let mut baselines = Map::new();
        for (name, _) in gated_baselines() {
            let state = match self.get_policy(name, super::PolicyType::Acl).await {
                Ok(Some(p)) if policy_names_sql_capabilities(&p) => "with-sql",
                Ok(Some(_)) => "without-sql",
                Ok(None) => "missing",
                Err(_) => "unreadable",
            };
            baselines.insert(name.to_string(), json!(state));
        }
        out.insert("baselines".into(), Value::Object(baselines));
        out
    }
}

#[cfg(test)]
#[path = "sql_write_gate_tests.rs"]
mod tests;
