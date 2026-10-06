//! Four-tier Rustion transport-and-bastion policy — Phase 7.
//!
//! Four tiers, in increasing specificity:
//!   1. **Global** (`sys/config/rustion`)        — root-gated.
//!   2. **Per-resource-type** (`ResourceTypeDef.connect.*`) — admin-gated.
//!   3. **Per-asset-group** (`AssetGroup.connect.*`)        — admin or group-owner gated.
//!   4. **Per-resource** (`Resource.connect.*`)             — resource owner.
//!
//! Each tier carries the same knobs:
//!   - `transport`           ∈ {direct | rustion-preferred | rustion-required}
//!   - `bastions`            : Vec<bastion_id>   (pinned ordered list)
//!   - `bastion_group`       : String             (named pool, mutually-exclusive with `bastions`)
//!   - `recording`           ∈ {always | input-redacted | off}
//!   - `clipboard`           ∈ {off | host-to-session | session-to-host | bidirectional}
//!   - `clipboard_files`     ∈ the same four values, for RDP file copy
//!   - `lock`                : bool               (lower tiers may not weaken this tier's settings)
//!
//! ### Resolution rules (mirrors the spec §Phase 7)
//!
//! - `transport`: **most-restrictive** wins (`rustion-required` > `rustion-preferred` > `direct`).
//! - `bastions` / `bastion_group`: **nearest-defined-tier** wins (resource > asset-group > type > global).
//! - `recording`: **strictest** wins (`always` > `input-redacted` > `off`).
//! - `clipboard` / `clipboard_files`: **most-restrictive** wins, by
//!   *intersection* of the permitted directions — see [`ClipboardPolicy`].
//!   An unset knob constrains nothing; the connection profile's own
//!   `rdp_clipboard` / `rdp_clipboard_files` is then intersected with the
//!   result on the connect path (features/rdp-clipboard-redirection.md §6).
//! - `lock`: any tier with `lock = true` freezes its knobs against weakening
//!   from lower tiers — a lower tier may *match or strengthen* (e.g. raise
//!   transport to `rustion-required` even when type-level locks
//!   `rustion-preferred`), but never *weaken*.
//!
//! A weakened transport or recording is a [`LockViolation`], which
//! `session/open` and the GUI connect path refuse. A weakened clipboard
//! knob is reported separately, as [`EffectivePolicy::clipboard_lock_conflict`],
//! and does **not** refuse the session: the intersection already pins the
//! effective value at or below the lock, so refusing would only push the
//! operator onto a client the bastion never sees. It does refuse a
//! per-resource *write* that tries it.
//!
//! Phase 7.1 ships the data model + storage + resolver + global-policy + bastion-groups CRUD.
//! Phase 7.2 wires the per-type / per-asset-group / per-resource editors into the GUI.

#![deny(unsafe_code)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
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

/// Which way an RDP session's clipboard may carry content, as a policy
/// ceiling. Same four words as the connection-profile key `rdp_clipboard`
/// (features/rdp-clipboard-redirection.md §2), so a tier and a profile
/// say the same thing the same way.
///
/// The directions form a *set* — {host→session, session→host} — not a
/// line: `host-to-session` and `session-to-host` are incomparable, and the
/// most restrictive combination of the two is `off`. Tiers therefore
/// combine by intersection ([`ClipboardPolicy::meet`]), not by a rank.
///
/// Deliberately no `Default`: an unset tier is `None` ("constrains
/// nothing"), and a defaulted variant sitting next to that is how a caller
/// ends up silently opening or closing the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClipboardPolicy {
    /// No clipboard content in either direction.
    Off,
    /// Operator's machine → remote session only (ingress).
    HostToSession,
    /// Remote session → operator's machine only (egress).
    SessionToHost,
    Bidirectional,
}

impl ClipboardPolicy {
    pub fn allows_host_to_session(self) -> bool {
        matches!(self, Self::HostToSession | Self::Bidirectional)
    }

    pub fn allows_session_to_host(self) -> bool {
        matches!(self, Self::SessionToHost | Self::Bidirectional)
    }

    fn from_directions(host_to_session: bool, session_to_host: bool) -> Self {
        match (host_to_session, session_to_host) {
            (true, true) => Self::Bidirectional,
            (true, false) => Self::HostToSession,
            (false, true) => Self::SessionToHost,
            (false, false) => Self::Off,
        }
    }

    /// The most restrictive combination: a direction survives only if
    /// both sides permit it.
    pub fn meet(a: Self, b: Self) -> Self {
        Self::from_directions(
            a.allows_host_to_session() && b.allows_host_to_session(),
            a.allows_session_to_host() && b.allows_session_to_host(),
        )
    }

    /// True when `self` permits nothing `ceiling` forbids.
    pub fn within(self, ceiling: Self) -> bool {
        Self::meet(self, ceiling) == self
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::HostToSession => "host-to-session",
            Self::SessionToHost => "session-to-host",
            Self::Bidirectional => "bidirectional",
        }
    }

    /// Strict: exactly one of the four canonical spellings (surrounding
    /// whitespace aside). An unknown value is never mapped onto a default
    /// in either direction — the caller refuses it.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "off" => Some(Self::Off),
            "host-to-session" => Some(Self::HostToSession),
            "session-to-host" => Some(Self::SessionToHost),
            "bidirectional" => Some(Self::Bidirectional),
            _ => None,
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
    /// Ceiling on RDP clipboard redirection (text and images) for every
    /// resource this tier covers. `None` constrains nothing.
    ///
    /// `serde(default)` is the read-old half of the migration: a tier
    /// record written before this knob existed has no key and reads as
    /// `None`. Skipped when unset so a record that never used it is
    /// byte-identical to the old shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard: Option<ClipboardPolicy>,
    /// Ceiling on RDP *file* copy over the clipboard channel. Separate
    /// from `clipboard` because a file channel is a materially larger
    /// control question than text; same migration rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard_files: Option<ClipboardPolicy>,
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
    /// Intersection of every tier's `clipboard`. `Bidirectional` when no
    /// tier set one — i.e. the policy constrains nothing and the
    /// profile's own `rdp_clipboard` decides.
    pub clipboard: ClipboardPolicy,
    /// The last tier that narrowed `clipboard`, or `"default"`.
    pub clipboard_source: &'static str,
    /// Intersection of every tier's `clipboard_files`; same conventions.
    pub clipboard_files: ClipboardPolicy,
    pub clipboard_files_source: &'static str,
    /// Tiers that locked a clipboard knob they set, in resolution order.
    pub clipboard_locked_by: Vec<&'static str>,
    /// A lower tier asked for more clipboard than a locked tier allows.
    /// Informational at connect time — the intersection already holds
    /// the effective value at or below the lock — but a per-resource
    /// write that would create one is refused.
    pub clipboard_lock_conflict: Option<LockViolation>,
}

/// One clipboard knob's walk over the tiers: running intersection, who
/// narrowed it last, the locked ceiling so far, and the first conflict.
struct ClipboardWalk {
    field: &'static str,
    value: ClipboardPolicy,
    source: &'static str,
    ceiling: Option<(ClipboardPolicy, &'static str)>,
    conflict: Option<LockViolation>,
}

impl ClipboardWalk {
    fn new(field: &'static str) -> Self {
        Self { field, value: ClipboardPolicy::Bidirectional, source: "default", ceiling: None, conflict: None }
    }

    fn visit(
        &mut self,
        tier_name: &'static str,
        set: Option<ClipboardPolicy>,
        locks: bool,
        locked_by: &mut Vec<&'static str>,
    ) {
        let Some(c) = set else {
            return;
        };
        if let Some((ceiling, locking_tier)) = self.ceiling {
            if !c.within(ceiling) {
                self.conflict.get_or_insert(LockViolation {
                    locking_tier,
                    field: self.field,
                    detail: format!(
                        "tier `{tier_name}` set {}={} but tier `{locking_tier}` locked it at {}",
                        self.field,
                        c.as_str(),
                        ceiling.as_str()
                    ),
                });
            }
        }
        let narrowed = ClipboardPolicy::meet(self.value, c);
        if narrowed != self.value {
            self.value = narrowed;
            self.source = tier_name;
        }
        if locks {
            if !locked_by.contains(&tier_name) {
                locked_by.push(tier_name);
            }
            self.ceiling = Some(match self.ceiling {
                None => (c, tier_name),
                Some((prev, prev_src)) => {
                    let tighter = ClipboardPolicy::meet(prev, c);
                    (tighter, if tighter == prev { prev_src } else { tier_name })
                }
            });
        }
    }
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

    let mut clipboard = ClipboardWalk::new("clipboard");
    let mut clipboard_files = ClipboardWalk::new("clipboard_files");
    let mut clipboard_locked_by: Vec<&'static str> = Vec::new();

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
        // clipboard / clipboard_files: intersection; a locked tier caps
        // everything below it. Never a `lock_violation` — see the module
        // docs for why a clipboard conflict does not refuse the session.
        clipboard.visit(name, tier.clipboard, tier.lock, &mut clipboard_locked_by);
        clipboard_files.visit(name, tier.clipboard_files, tier.lock, &mut clipboard_locked_by);
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
        clipboard: clipboard.value,
        clipboard_source: clipboard.source,
        clipboard_files: clipboard_files.value,
        clipboard_files_source: clipboard_files.source,
        clipboard_locked_by,
        clipboard_lock_conflict: clipboard.conflict.or(clipboard_files.conflict),
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
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
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

    // ─── Clipboard knobs ────────────────────────────────────────────

    fn global_clip(clipboard: Option<ClipboardPolicy>, files: Option<ClipboardPolicy>, lock: bool) -> GlobalPolicy {
        GlobalPolicy {
            tier: PolicyTier { clipboard, clipboard_files: files, lock, ..Default::default() },
            updated_at: None,
        }
    }

    fn res_clip(clipboard: Option<ClipboardPolicy>, files: Option<ClipboardPolicy>) -> ResourcePolicy {
        ResourcePolicy {
            resource_id: "r".into(),
            tier: PolicyTier { clipboard, clipboard_files: files, ..Default::default() },
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn clipboard_meet_is_set_intersection() {
        use ClipboardPolicy::*;
        assert_eq!(ClipboardPolicy::meet(Bidirectional, HostToSession), HostToSession);
        assert_eq!(ClipboardPolicy::meet(Bidirectional, SessionToHost), SessionToHost);
        // The two single directions are incomparable: neither survives.
        assert_eq!(ClipboardPolicy::meet(HostToSession, SessionToHost), Off);
        assert_eq!(ClipboardPolicy::meet(Off, Bidirectional), Off);
        assert!(HostToSession.within(Bidirectional));
        assert!(!Bidirectional.within(HostToSession));
        assert!(!SessionToHost.within(HostToSession));
        assert!(Off.within(Off));
    }

    #[test]
    fn clipboard_parse_is_strict() {
        for (raw, want) in [
            ("off", ClipboardPolicy::Off),
            ("host-to-session", ClipboardPolicy::HostToSession),
            ("session-to-host", ClipboardPolicy::SessionToHost),
            (" bidirectional ", ClipboardPolicy::Bidirectional),
        ] {
            assert_eq!(ClipboardPolicy::parse(raw), Some(want), "{raw:?}");
        }
        // No aliases, no case folding, no typos resolving to anything.
        for raw in ["", "on", "both", "in", "Off", "bidirectionnal", "host_to_session", "none"] {
            assert_eq!(ClipboardPolicy::parse(raw), None, "{raw:?} must not parse");
        }
    }

    #[test]
    fn no_clipboard_tier_constrains_nothing() {
        let p = resolve(&GlobalPolicy::default(), None, &[], None);
        assert_eq!(p.clipboard, ClipboardPolicy::Bidirectional);
        assert_eq!(p.clipboard_source, "default");
        assert_eq!(p.clipboard_files, ClipboardPolicy::Bidirectional);
        assert_eq!(p.clipboard_files_source, "default");
        assert!(p.clipboard_locked_by.is_empty());
        assert!(p.clipboard_lock_conflict.is_none());
    }

    #[test]
    fn an_unlocked_upper_tier_still_narrows_a_lower_one() {
        // Most-restrictive wins whether or not anything is locked — the same
        // rule as transport. A resource cannot widen past its type.
        let type_ = TypePolicy {
            type_name: "server".into(),
            tier: PolicyTier { clipboard: Some(ClipboardPolicy::HostToSession), ..Default::default() },
            updated_at: Utc::now(),
        };
        let p = resolve(
            &GlobalPolicy::default(),
            Some(&type_),
            &[],
            Some(&res_clip(Some(ClipboardPolicy::Bidirectional), None)),
        );
        assert_eq!(p.clipboard, ClipboardPolicy::HostToSession);
        assert_eq!(p.clipboard_source, "type");
        assert!(p.clipboard_lock_conflict.is_none(), "nothing was locked");
    }

    #[test]
    fn a_locked_off_pins_the_clipboard_and_reports_a_conflict_without_a_lock_violation() {
        let p = resolve(
            &global_clip(Some(ClipboardPolicy::Off), None, true),
            None,
            &[],
            Some(&res_clip(Some(ClipboardPolicy::Bidirectional), None)),
        );
        assert_eq!(p.clipboard, ClipboardPolicy::Off);
        assert_eq!(p.clipboard_source, "global");
        assert_eq!(p.clipboard_locked_by, vec!["global"]);
        let c = p.clipboard_lock_conflict.as_ref().expect("the resource tried to widen a lock");
        assert_eq!(c.locking_tier, "global");
        assert_eq!(c.field, "clipboard");
        // Regression guard: a clipboard conflict must never become the
        // transport `lock_violation` that refuses the whole session.
        assert!(p.lock_violation.is_none());
    }

    #[test]
    fn single_directions_from_two_tiers_intersect_to_off() {
        let ag_in = ag("a", 1, PolicyTier { clipboard: Some(ClipboardPolicy::HostToSession), ..Default::default() });
        let ag_out = ag("b", 99, PolicyTier { clipboard: Some(ClipboardPolicy::SessionToHost), ..Default::default() });
        // Priority orders processing, it cannot win back a direction a
        // lower-priority group withheld.
        let p = resolve(&GlobalPolicy::default(), None, &[ag_in, ag_out], None);
        assert_eq!(p.clipboard, ClipboardPolicy::Off);
        assert_eq!(p.clipboard_source, "asset-group");
    }

    #[test]
    fn file_copy_is_its_own_knob() {
        // Locking files off says nothing about text, and the reverse.
        let p = resolve(&global_clip(None, Some(ClipboardPolicy::Off), true), None, &[], None);
        assert_eq!(p.clipboard, ClipboardPolicy::Bidirectional);
        assert_eq!(p.clipboard_files, ClipboardPolicy::Off);
        assert_eq!(p.clipboard_files_source, "global");

        let p = resolve(
            &global_clip(Some(ClipboardPolicy::SessionToHost), None, false),
            None,
            &[],
            Some(&res_clip(None, Some(ClipboardPolicy::Bidirectional))),
        );
        assert_eq!(p.clipboard, ClipboardPolicy::SessionToHost);
        assert_eq!(p.clipboard_files, ClipboardPolicy::Bidirectional);
    }

    #[test]
    fn a_lock_without_a_clipboard_value_does_not_cap_the_clipboard() {
        // `lock` is per tier and freezes only the knobs the tier sets: a
        // global transport lock is not a clipboard pin.
        let g = GlobalPolicy {
            tier: PolicyTier { transport: Some(Transport::RustionRequired), lock: true, ..Default::default() },
            updated_at: None,
        };
        let p = resolve(&g, None, &[], Some(&res_clip(Some(ClipboardPolicy::Bidirectional), None)));
        assert!(p.clipboard_lock_conflict.is_none());
        assert!(p.clipboard_locked_by.is_empty());
        assert_eq!(p.clipboard, ClipboardPolicy::Bidirectional);
    }

    #[test]
    fn a_tier_written_before_the_clipboard_knobs_reads_as_unset() {
        // Read-old: the exact shape `put_type` wrote before this change.
        let old = r#"{"type_name":"db","transport":"rustion-required","bastions":[],"bastion_group":null,"recording":"always","lock":true,"updated_at":"2026-01-01T00:00:00Z"}"#;
        let p: TypePolicy = serde_json::from_str(old).expect("old record must still decode");
        assert_eq!(p.tier.clipboard, None);
        assert_eq!(p.tier.clipboard_files, None);
        assert!(p.tier.lock);

        // Write-new: an unset knob is omitted, a set one round-trips.
        let unset = serde_json::to_value(&p).unwrap();
        assert!(unset.get("clipboard").is_none() && unset.get("clipboard_files").is_none());
        let mut set = p.clone();
        set.tier.clipboard = Some(ClipboardPolicy::HostToSession);
        set.tier.clipboard_files = Some(ClipboardPolicy::Off);
        let v = serde_json::to_value(&set).unwrap();
        assert_eq!(v["clipboard"], "host-to-session");
        assert_eq!(v["clipboard_files"], "off");
        let back: TypePolicy = serde_json::from_value(v).unwrap();
        assert_eq!(back.tier.clipboard, Some(ClipboardPolicy::HostToSession));
        assert_eq!(back.tier.clipboard_files, Some(ClipboardPolicy::Off));
    }

    #[test]
    fn a_stored_unknown_clipboard_value_fails_the_decode() {
        // A corrupted or future value is a decode error the operator sees,
        // never a silent `None` that would lift a pin.
        let bad = r#"{"clipboard":"sideways","lock":true}"#;
        assert!(serde_json::from_str::<GlobalPolicy>(bad).is_err());
    }
}
