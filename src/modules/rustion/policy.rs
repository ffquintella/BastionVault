//! Four-tier Rustion transport-and-bastion policy — Phase 7.
//!
//! Four tiers, in increasing specificity:
//!   1. **Global** (`sys/config/rustion`)        — root-gated.
//!   2. **Per-resource-type** (`ResourceTypeDef.connect.*`) — admin-gated.
//!   3. **Per-asset-group** (`AssetGroup.connect.*`)        — admin or group-owner gated.
//!   4. **Per-resource** (`Resource.connect.*`)             — resource owner.
//!
//! Each tier carries the same four knobs:
//!   - `transport`           ∈ {direct | rustion-preferred | rustion-required}
//!   - `bastions`            : Vec<bastion_id>   (pinned ordered list)
//!   - `bastion_group`       : String             (named pool, mutually-exclusive with `bastions`)
//!   - `recording`           ∈ {always | input-redacted | off}
//!   - `lock`                : bool               (lower tiers may not weaken this tier's settings)
//!
//! ### Resolution rules (mirrors the spec §Phase 7)
//!
//! - `transport`: **most-restrictive** wins (`rustion-required` > `rustion-preferred` > `direct`).
//! - `bastions` / `bastion_group`: **nearest-defined-tier** wins (resource > asset-group > type > global).
//! - `recording`: **strictest** wins (`always` > `input-redacted` > `off`).
//! - `lock`: any tier with `lock = true` freezes its knobs against weakening
//!   from lower tiers — a lower tier may *match or strengthen* (e.g. raise
//!   transport to `rustion-required` even when type-level locks
//!   `rustion-preferred`), but never *weaken*.
//!
//! Phase 7.1 ships the data model + storage + resolver + global-policy + bastion-groups CRUD.
//! Phase 7.2 wires the per-type / per-asset-group / per-resource editors into the GUI.

#![deny(unsafe_code)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::Core;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
use crate::bv_error_string;

const BASTION_GROUPS_SUB_PATH: &str = "rustion/bastion-groups/";
const GLOBAL_POLICY_KEY: &str = "rustion/policy/global";
const TYPE_POLICY_SUB_PATH: &str = "rustion/policy/type/";
const ASSET_GROUP_POLICY_SUB_PATH: &str = "rustion/policy/asset-group/";
const RESOURCE_POLICY_SUB_PATH: &str = "rustion/policy/resource/";

// ─── Enums ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Bypass Rustion entirely; the GUI dials the resource itself.
    #[default]
    Direct,
    /// Prefer Rustion-mediated; fall back to direct if no bastion is reachable.
    RustionPreferred,
    /// Refuse to open the session if no healthy bastion is available.
    RustionRequired,
}

impl Transport {
    /// Restrictiveness rank — higher = more restrictive.
    pub fn rank(self) -> u8 {
        match self {
            Transport::Direct => 0,
            Transport::RustionPreferred => 1,
            Transport::RustionRequired => 2,
        }
    }
    pub fn most_restrictive(a: Self, b: Self) -> Self {
        if a.rank() >= b.rank() {
            a
        } else {
            b
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Direct => "direct",
            Transport::RustionPreferred => "rustion-preferred",
            Transport::RustionRequired => "rustion-required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Recording {
    Off,
    InputRedacted,
    #[default]
    Always,
}

impl Recording {
    pub fn rank(self) -> u8 {
        match self {
            Recording::Off => 0,
            Recording::InputRedacted => 1,
            Recording::Always => 2,
        }
    }
    pub fn strictest(a: Self, b: Self) -> Self {
        if a.rank() >= b.rank() {
            a
        } else {
            b
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Recording::Off => "off",
            Recording::InputRedacted => "input-redacted",
            Recording::Always => "always",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Selection {
    #[default]
    Ordered,
    Random,
}

// ─── Bastion groups ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BastionGroup {
    pub name: String,
    /// Bastion target ids in this group. The dispatcher reads them in
    /// order when `selection = Ordered`, or shuffles when `Random`.
    pub members: Vec<String>,
    #[serde(default)]
    pub selection: Selection,
    #[serde(default)]
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Tier policies ──────────────────────────────────────────────────

/// Shared shape of every policy tier. All fields are `Option` so a
/// tier can leave a knob undefined ("fall through to a less specific
/// tier"). The resolver substitutes defaults at the end.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyTier {
    pub transport: Option<Transport>,
    /// Pinned ordered bastion ids. Mutually exclusive with
    /// `bastion_group` (`bastion_group` wins if both are set on the
    /// same tier — but the API should refuse that on write).
    #[serde(default)]
    pub bastions: Vec<String>,
    pub bastion_group: Option<String>,
    pub recording: Option<Recording>,
    /// When true, lower tiers may not *weaken* this tier's knobs.
    /// `lock` itself doesn't fall through — it's evaluated per-tier.
    #[serde(default)]
    pub lock: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(flatten)]
    pub tier: PolicyTier,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypePolicy {
    pub type_name: String,
    #[serde(flatten)]
    pub tier: PolicyTier,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetGroupPolicy {
    pub asset_group_id: String,
    /// Higher = wins on multi-group resolution. Tier resolution still
    /// applies (nearest-defined-tier for `bastions`, etc.).
    #[serde(default)]
    pub priority: i32,
    #[serde(flatten)]
    pub tier: PolicyTier,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub resource_id: String,
    #[serde(flatten)]
    pub tier: PolicyTier,
    pub updated_at: DateTime<Utc>,
}

// ─── Effective policy + resolver ────────────────────────────────────

/// The materialised policy a `session/open` call uses. Every knob is
/// resolved + every contributing tier is named so the GUI can show
/// the resolution chain ("Locked by: type") and the audit event can
/// stamp `policy.transport_source = "type"` etc.
#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub transport: Transport,
    pub transport_source: &'static str,
    pub bastions: Vec<String>,
    pub bastion_group: Option<String>,
    pub bastions_source: &'static str,
    pub recording: Recording,
    pub recording_source: &'static str,
    /// True if any contributing tier set `lock = true`. Lower tiers
    /// can still *strengthen* (raise transport, force a more verbose
    /// recording) — they can't weaken.
    pub locked_by: Vec<&'static str>,
    /// True when the request explicitly tried to weaken a locked tier.
    /// `session/open` returns 403 in this case.
    pub lock_violation: Option<LockViolation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockViolation {
    pub locking_tier: &'static str,
    pub field: &'static str,
    pub detail: String,
}

/// Resolve the effective policy given each tier in increasing order
/// of specificity. Asset-group tiers are sorted by `priority` (high
/// first) before resolution.
pub fn resolve(
    global: &GlobalPolicy,
    type_: Option<&TypePolicy>,
    asset_groups: &[AssetGroupPolicy],
    resource: Option<&ResourcePolicy>,
) -> EffectivePolicy {
    // Walk asset-groups LOW-priority first so HIGH-priority gets the
    // last word via the overwrite semantics in the loop below. Ties
    // broken by id (alphabetic) — stable so the audit chain stays
    // deterministic.
    let mut ag: Vec<&AssetGroupPolicy> = asset_groups.iter().collect();
    ag.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.asset_group_id.cmp(&b.asset_group_id))
    });

    // Walk in increasing specificity so the resolver can both:
    //   - track the *most-restrictive transport* (so a lower tier
    //     can RAISE transport but not lower it past a locked tier);
    //   - track the *nearest-defined-tier* for bastions / bastion_group.
    // Track as Option<_> so the resolver can tell "no tier set this"
    // from "a tier explicitly set this to the default value". We
    // substitute defaults at the end.
    let mut transport_opt: Option<(Transport, &'static str)> = None;
    let mut bastions: Vec<String> = Vec::new();
    let mut bastion_group: Option<String> = None;
    let mut bastions_source = "default";
    let mut recording_opt: Option<(Recording, &'static str)> = None;
    let mut locked_by: Vec<&'static str> = Vec::new();

    // Locked-knob snapshots — what value a locking tier set. Lower
    // tiers may match-or-strengthen but never go below these.
    let mut locked_transport: Option<(Transport, &'static str)> = None;
    let mut locked_recording: Option<(Recording, &'static str)> = None;

    let mut lock_violation: Option<LockViolation> = None;

    let tiers: Vec<(&'static str, &PolicyTier)> = {
        let mut v: Vec<(&'static str, &PolicyTier)> = Vec::new();
        v.push(("global", &global.tier));
        if let Some(t) = type_ {
            v.push(("type", &t.tier));
        }
        for ag in &ag {
            // We surface a single "asset-group" tag rather than
            // individual ids on the source field — the audit event
            // separately stamps which AGs contributed via priority.
            v.push(("asset-group", &ag.tier));
        }
        if let Some(r) = resource {
            v.push(("resource", &r.tier));
        }
        v
    };

    for (name, tier) in tiers.iter() {
        // transport: most-restrictive wins; locking tier freezes the floor.
        if let Some(t) = tier.transport {
            if let Some((locked_t, locking_src)) = locked_transport {
                if t.rank() < locked_t.rank() {
                lock_violation.get_or_insert(LockViolation {
                    locking_tier: locking_src,
                    field: "transport",
                    detail: format!(
                        "tier `{name}` set transport={} but tier `{locking_src}` locked it at {}",
                        t.as_str(),
                        locked_t.as_str()
                    ),
                });
                }
            }
            transport_opt = match transport_opt {
                None => Some((t, *name)),
                Some((cur, cur_src)) => {
                    let win = Transport::most_restrictive(cur, t);
                    if win == t && win != cur {
                        Some((t, *name))
                    } else {
                        Some((cur, cur_src))
                    }
                }
            };
        }
        // bastions: nearest-defined-tier wins; `bastion_group` wins over a list when on the same tier.
        if tier.bastion_group.is_some() || !tier.bastions.is_empty() {
            bastions = tier.bastions.clone();
            bastion_group = tier.bastion_group.clone();
            bastions_source = *name;
        }
        // recording: strictest wins; locked tier freezes the floor.
        if let Some(r) = tier.recording {
            if let Some((locked_r, locking_src)) = locked_recording {
                if r.rank() < locked_r.rank() {
                lock_violation.get_or_insert(LockViolation {
                    locking_tier: locking_src,
                    field: "recording",
                    detail: format!(
                        "tier `{name}` set recording={} but tier `{locking_src}` locked it at {}",
                        r.as_str(),
                        locked_r.as_str()
                    ),
                });
                }
            }
            recording_opt = match recording_opt {
                None => Some((r, *name)),
                Some((cur, cur_src)) => {
                    let win = Recording::strictest(cur, r);
                    if win == r && win != cur {
                        Some((r, *name))
                    } else {
                        Some((cur, cur_src))
                    }
                }
            };
        }
        // Lock processing: if this tier locks, snapshot the values it sees.
        if tier.lock {
            locked_by.push(*name);
            if let Some(t) = tier.transport {
                locked_transport = Some((t, *name));
            }
            if let Some(r) = tier.recording {
                locked_recording = Some((r, *name));
            }
        }
    }

    let (transport, transport_source) = transport_opt
        .unwrap_or((Transport::Direct, "default"));
    let (recording, recording_source) = recording_opt
        .unwrap_or((Recording::Always, "default"));

    EffectivePolicy {
        transport,
        transport_source,
        bastions,
        bastion_group,
        bastions_source,
        recording,
        recording_source,
        locked_by,
        lock_violation,
    }
}

// ─── Storage ────────────────────────────────────────────────────────

pub struct PolicyStore {
    bastion_groups_view: Arc<BarrierView>,
    type_view: Arc<BarrierView>,
    asset_group_view: Arc<BarrierView>,
    resource_view: Arc<BarrierView>,
    system_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl PolicyStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let bastion_groups_view = Arc::new(system_view.new_sub_view(BASTION_GROUPS_SUB_PATH));
        let type_view = Arc::new(system_view.new_sub_view(TYPE_POLICY_SUB_PATH));
        let asset_group_view = Arc::new(system_view.new_sub_view(ASSET_GROUP_POLICY_SUB_PATH));
        let resource_view = Arc::new(system_view.new_sub_view(RESOURCE_POLICY_SUB_PATH));
        Ok(Arc::new(Self {
            bastion_groups_view,
            type_view,
            asset_group_view,
            resource_view,
            system_view,
        }))
    }

    // ─── Bastion groups ─────────────────────────────────────────

    pub async fn list_groups(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.bastion_groups_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn get_group(&self, name: &str) -> Result<Option<BastionGroup>, RvError> {
        let name = sanitize(name)?;
        let Some(entry) = self.bastion_groups_view.get(&name).await? else {
            return Ok(None);
        };
        let g: BastionGroup = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode bastion group: {e}")))?;
        Ok(Some(g))
    }

    pub async fn put_group(&self, group: &BastionGroup) -> Result<(), RvError> {
        let name = sanitize(&group.name)?;
        let value = serde_json::to_vec(group)
            .map_err(|e| bv_error_string!(&format!("encode bastion group: {e}")))?;
        self.bastion_groups_view.put(&StorageEntry { key: name, value }).await
    }

    pub async fn delete_group(&self, name: &str) -> Result<(), RvError> {
        let name = sanitize(name)?;
        self.bastion_groups_view.delete(&name).await
    }

    // ─── Global policy ──────────────────────────────────────────

    pub async fn get_global(&self) -> Result<GlobalPolicy, RvError> {
        let Some(entry) = self.system_view.get(GLOBAL_POLICY_KEY).await? else {
            return Ok(GlobalPolicy::default());
        };
        serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode global policy: {e}")))
    }

    pub async fn put_global(&self, p: &GlobalPolicy) -> Result<(), RvError> {
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode global policy: {e}")))?;
        self.system_view
            .put(&StorageEntry {
                key: GLOBAL_POLICY_KEY.to_string(),
                value,
            })
            .await
    }

    // ─── Type policy ────────────────────────────────────────────

    pub async fn get_type(&self, type_name: &str) -> Result<Option<TypePolicy>, RvError> {
        let name = sanitize(type_name)?;
        let Some(entry) = self.type_view.get(&name).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.value)
            .map(Some)
            .map_err(|e| bv_error_string!(&format!("decode type policy: {e}")))
    }

    pub async fn put_type(&self, p: &TypePolicy) -> Result<(), RvError> {
        let name = sanitize(&p.type_name)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode type policy: {e}")))?;
        self.type_view.put(&StorageEntry { key: name, value }).await
    }

    pub async fn delete_type(&self, type_name: &str) -> Result<(), RvError> {
        let name = sanitize(type_name)?;
        self.type_view.delete(&name).await
    }

    // ─── Asset-group policy ─────────────────────────────────────

    pub async fn get_asset_group(
        &self,
        asset_group_id: &str,
    ) -> Result<Option<AssetGroupPolicy>, RvError> {
        let id = sanitize(asset_group_id)?;
        let Some(entry) = self.asset_group_view.get(&id).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.value)
            .map(Some)
            .map_err(|e| bv_error_string!(&format!("decode asset-group policy: {e}")))
    }

    pub async fn list_asset_groups(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.asset_group_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn put_asset_group(&self, p: &AssetGroupPolicy) -> Result<(), RvError> {
        let id = sanitize(&p.asset_group_id)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode asset-group policy: {e}")))?;
        self.asset_group_view.put(&StorageEntry { key: id, value }).await
    }

    // ─── Resource policy ────────────────────────────────────────

    pub async fn get_resource(
        &self,
        resource_id: &str,
    ) -> Result<Option<ResourcePolicy>, RvError> {
        let id = sanitize(resource_id)?;
        let Some(entry) = self.resource_view.get(&id).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.value)
            .map(Some)
            .map_err(|e| bv_error_string!(&format!("decode resource policy: {e}")))
    }

    pub async fn put_resource(&self, p: &ResourcePolicy) -> Result<(), RvError> {
        let id = sanitize(&p.resource_id)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode resource policy: {e}")))?;
        self.resource_view.put(&StorageEntry { key: id, value }).await
    }

    pub async fn list_types(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.type_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn list_resources(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.resource_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    // ─── Referential integrity ──────────────────────────────────

    /// Scan every policy tier for **locked** references to `group_name`.
    /// Returns a human-readable label per locked tier that pins this
    /// group (e.g. `global`, `type "database"`, `asset-group "pci"`).
    ///
    /// Only *locked* references are reported: an unlocked tier that names
    /// a now-deleted group simply falls through to the random pool at
    /// resolve time, which is a benign (if sloppy) state. A locked tier,
    /// by contrast, encodes a hard constraint — deleting the group out
    /// from under it would silently turn `rustion-required` into
    /// random-pool, defeating the lock. So those block the delete.
    pub async fn locked_group_references(
        &self,
        group_name: &str,
    ) -> Result<Vec<String>, RvError> {
        let mut refs = Vec::new();
        let pins = |t: &PolicyTier| t.lock && t.bastion_group.as_deref() == Some(group_name);

        let global = self.get_global().await?;
        if pins(&global.tier) {
            refs.push("global".to_string());
        }
        for type_name in self.list_types().await? {
            if let Some(p) = self.get_type(&type_name).await? {
                if pins(&p.tier) {
                    refs.push(format!("type \"{type_name}\""));
                }
            }
        }
        for ag_id in self.list_asset_groups().await? {
            if let Some(p) = self.get_asset_group(&ag_id).await? {
                if pins(&p.tier) {
                    refs.push(format!("asset-group \"{ag_id}\""));
                }
            }
        }
        for res_id in self.list_resources().await? {
            if let Some(p) = self.get_resource(&res_id).await? {
                if pins(&p.tier) {
                    refs.push(format!("resource \"{res_id}\""));
                }
            }
        }
        Ok(refs)
    }
}

fn sanitize(s: &str) -> Result<String, RvError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(bv_error_string!("policy key is required"));
    }
    if t.contains('/') || t.contains("..") {
        return Err(bv_error_string!("invalid policy key"));
    }
    Ok(t.to_string())
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ag(id: &str, priority: i32, tier: PolicyTier) -> AssetGroupPolicy {
        AssetGroupPolicy {
            asset_group_id: id.into(),
            priority,
            tier,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn transport_most_restrictive_wins() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    transport: Some(Transport::RustionPreferred),
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    transport: Some(Transport::Direct),
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        // Resource tried Direct, but the most-restrictive wins → RustionPreferred.
        assert_eq!(p.transport, Transport::RustionPreferred);
        assert_eq!(p.transport_source, "global");
    }

    #[test]
    fn resource_can_raise_transport() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    transport: Some(Transport::Direct),
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    transport: Some(Transport::RustionRequired),
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        assert_eq!(p.transport, Transport::RustionRequired);
        assert_eq!(p.transport_source, "resource");
    }

    #[test]
    fn lock_prevents_weakening_transport() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    transport: Some(Transport::RustionRequired),
                    lock: true,
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    transport: Some(Transport::Direct),
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        assert!(p.lock_violation.is_some());
        let lv = p.lock_violation.as_ref().unwrap();
        assert_eq!(lv.locking_tier, "global");
        assert_eq!(lv.field, "transport");
    }

    #[test]
    fn recording_strictest_wins() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    recording: Some(Recording::Off),
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    recording: Some(Recording::Always),
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        assert_eq!(p.recording, Recording::Always);
        assert_eq!(p.recording_source, "resource");
    }

    #[test]
    fn bastions_nearest_tier_wins() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    bastions: vec!["g1".into(), "g2".into()],
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    bastions: vec!["r1".into()],
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        assert_eq!(p.bastions, vec!["r1".to_string()]);
        assert_eq!(p.bastions_source, "resource");
    }

    #[test]
    fn asset_group_priority_breaks_ties() {
        let high = ag(
            "high",
            10,
            PolicyTier {
                bastions: vec!["high-b".into()],
                ..Default::default()
            },
        );
        let low = ag(
            "low",
            5,
            PolicyTier {
                bastions: vec!["low-b".into()],
                ..Default::default()
            },
        );
        let p = resolve(&GlobalPolicy::default(), None, &[low, high], None);
        // After sorting by priority desc, high is processed first, then
        // low overrides since nearest-defined-tier wins on the same tier
        // class. The asset-group bucket walks in priority order, so the
        // LAST one wins: by our policy the more specific "asset-group"
        // tier of higher priority should win. We sort high-first; the
        // loop overwrites bastions each time, so the LAST one wins —
        // which is low. That's wrong; let me check the loop order.
        // The contract: highest priority wins. Our sort puts high first,
        // but the loop semantics let later tiers overwrite. So we need
        // to sort low-first OR keep only the highest. Update test to
        // reflect actual sort order, then fix the resolver.
        assert_eq!(p.bastions, vec!["high-b".to_string()]);
        assert_eq!(p.bastions_source, "asset-group");
    }

    #[test]
    fn default_when_no_tiers_set() {
        let p = resolve(&GlobalPolicy::default(), None, &[], None);
        assert_eq!(p.transport, Transport::Direct);
        assert_eq!(p.recording, Recording::Always);
        assert!(p.bastions.is_empty());
        assert!(p.lock_violation.is_none());
        assert_eq!(p.transport_source, "default");
    }

    #[test]
    fn locked_recording_prevents_off_override() {
        let p = resolve(
            &GlobalPolicy {
                tier: PolicyTier {
                    recording: Some(Recording::Always),
                    lock: true,
                    ..Default::default()
                },
                updated_at: None,
            },
            None,
            &[],
            Some(&ResourcePolicy {
                resource_id: "r".into(),
                tier: PolicyTier {
                    recording: Some(Recording::Off),
                    ..Default::default()
                },
                updated_at: Utc::now(),
            }),
        );
        assert_eq!(p.recording, Recording::Always);
        assert!(p.lock_violation.is_some());
        assert_eq!(
            p.lock_violation.as_ref().unwrap().locking_tier,
            "global"
        );
        assert_eq!(p.lock_violation.as_ref().unwrap().field, "recording");
    }
}
