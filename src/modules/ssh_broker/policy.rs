//! Four-tier SSH **login-class** policy.
//!
//! A direct structural mirror of the Rustion transport policy
//! (`crate::modules::rustion::policy`) — same four tiers, same
//! most-restrictive-wins + lock semantics, same `LockViolation` body —
//! so an admin reasons about one policy model, not two, and the two
//! policies compose cleanly on the Connection tab.
//!
//! Four tiers, in increasing specificity:
//!   1. **Global**            (`ssh-broker/policy/global`)        — root-gated.
//!   2. **Per-resource-type** (`ssh-broker/policy/type/<name>`)   — admin-gated.
//!   3. **Per-asset-group**   (`ssh-broker/policy/asset-group/<id>`) — admin / group-owner.
//!   4. **Per-resource**      (`ssh-broker/policy/resource/<id>`) — resource owner.
//!
//! Each tier carries a single knob plus a lock:
//!   - `login_class` ∈ {shared-credential | brokered}
//!   - `lock`        : bool  (lower tiers may not weaken this tier)
//!
//! ### Resolution rules
//!
//! - `login_class`: **most-restrictive** wins (`brokered` > `shared-credential`).
//! - `lock`: any tier with `lock = true` freezes its class against
//!   weakening from lower tiers — a lower tier may *match or strengthen*
//!   (raise `shared-credential` to `brokered`) but never *weaken* a
//!   locked `brokered` back to `shared-credential`.
//!
//! When the resolved class is `brokered`, the connect path requires the
//! profile's `credential_source` to be the SSH engine and forbids a
//! static SSH credential on the resource.

#![deny(unsafe_code)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bv_error_string;
use crate::core::Core;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};

const GLOBAL_POLICY_KEY: &str = "ssh-broker/policy/global";
const TYPE_POLICY_SUB_PATH: &str = "ssh-broker/policy/type/";
const ASSET_GROUP_POLICY_SUB_PATH: &str = "ssh-broker/policy/asset-group/";
const RESOURCE_POLICY_SUB_PATH: &str = "ssh-broker/policy/resource/";

// ─── Login class ────────────────────────────────────────────────────

/// How a resource's SSH login is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LoginClass {
    /// A static key / password lives on the resource (the `secret`
    /// credential source). The historical default.
    #[default]
    SharedCredential,
    /// Every login is minted per-connect from the SSH engine. The
    /// profile's `credential_source` MUST be `ssh-engine`; a static SSH
    /// credential may not be attached to the resource.
    Brokered,
}

impl LoginClass {
    /// Restrictiveness rank — higher = more restrictive.
    pub fn rank(self) -> u8 {
        match self {
            LoginClass::SharedCredential => 0,
            LoginClass::Brokered => 1,
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
            LoginClass::SharedCredential => "shared-credential",
            LoginClass::Brokered => "brokered",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "shared-credential" => Some(LoginClass::SharedCredential),
            "brokered" => Some(LoginClass::Brokered),
            _ => None,
        }
    }
}

// ─── Tier policies ──────────────────────────────────────────────────

/// Shared shape of every policy tier. `login_class` is `Option` so a
/// tier can leave the knob undefined ("fall through to a less specific
/// tier"); the resolver substitutes the default at the end.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginClassTier {
    pub login_class: Option<LoginClass>,
    /// When true, lower tiers may not *weaken* this tier's class.
    #[serde(default)]
    pub lock: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(flatten)]
    pub tier: LoginClassTier,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypePolicy {
    pub type_name: String,
    #[serde(flatten)]
    pub tier: LoginClassTier,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetGroupPolicy {
    pub asset_group_id: String,
    /// Higher = wins on multi-group resolution (matches the Rustion
    /// policy's asset-group priority semantics).
    #[serde(default)]
    pub priority: i32,
    #[serde(flatten)]
    pub tier: LoginClassTier,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub resource_id: String,
    #[serde(flatten)]
    pub tier: LoginClassTier,
    pub updated_at: DateTime<Utc>,
}

// ─── Effective policy + resolver ────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct LockViolation {
    pub locking_tier: &'static str,
    pub field: &'static str,
    pub detail: String,
}

/// The materialised login-class a connect call uses. Every contributing
/// tier is named so the GUI can render the resolution chain
/// ("brokered ← resource-type (locked)") and the audit event can stamp
/// `login_class_source` + `login_class_chain`.
#[derive(Debug, Clone, Serialize)]
pub struct EffectiveLoginClass {
    pub login_class: LoginClass,
    pub login_class_source: &'static str,
    /// Tiers that set `lock = true`, in resolution order.
    pub locked_by: Vec<&'static str>,
    /// The nearest locking tier (for the `locked_at_tier` error body).
    pub locked_at_tier: Option<&'static str>,
    /// Per-tier class contributions, in resolution order, for the audit
    /// `login_class_chain` field — e.g. `["global=shared-credential",
    /// "type=brokered"]`.
    pub chain: Vec<String>,
    /// Present when a request tried to weaken a locked tier. The connect
    /// path returns `403 login_class_locked` in this case.
    pub lock_violation: Option<LockViolation>,
}

/// Resolve the effective login class given each tier in increasing
/// order of specificity. Asset-group tiers are sorted by `priority`
/// (low first, so the highest-priority asset-group gets the last word).
pub fn resolve(
    global: &GlobalPolicy,
    type_: Option<&TypePolicy>,
    asset_groups: &[AssetGroupPolicy],
    resource: Option<&ResourcePolicy>,
) -> EffectiveLoginClass {
    let mut ag: Vec<&AssetGroupPolicy> = asset_groups.iter().collect();
    ag.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.asset_group_id.cmp(&b.asset_group_id))
    });

    let mut class_opt: Option<(LoginClass, &'static str)> = None;
    let mut locked_by: Vec<&'static str> = Vec::new();
    let mut locked_class: Option<(LoginClass, &'static str)> = None;
    let mut lock_violation: Option<LockViolation> = None;
    let mut chain: Vec<String> = Vec::new();

    let tiers: Vec<(&'static str, &LoginClassTier)> = {
        let mut v: Vec<(&'static str, &LoginClassTier)> = Vec::new();
        v.push(("global", &global.tier));
        if let Some(t) = type_ {
            v.push(("type", &t.tier));
        }
        for ag in &ag {
            v.push(("asset-group", &ag.tier));
        }
        if let Some(r) = resource {
            v.push(("resource", &r.tier));
        }
        v
    };

    for (name, tier) in tiers.iter() {
        if let Some(c) = tier.login_class {
            chain.push(format!("{name}={}", c.as_str()));
            // most-restrictive wins; a locking tier freezes the floor.
            if let Some((locked_c, locking_src)) = locked_class {
                if c.rank() < locked_c.rank() {
                    lock_violation.get_or_insert(LockViolation {
                        locking_tier: locking_src,
                        field: "login_class",
                        detail: format!(
                            "tier `{name}` set login_class={} but tier `{locking_src}` locked it at {}",
                            c.as_str(),
                            locked_c.as_str()
                        ),
                    });
                }
            }
            class_opt = match class_opt {
                None => Some((c, *name)),
                Some((cur, cur_src)) => {
                    let win = LoginClass::most_restrictive(cur, c);
                    if win == c && win != cur {
                        Some((c, *name))
                    } else {
                        Some((cur, cur_src))
                    }
                }
            };
        }
        if tier.lock {
            locked_by.push(*name);
            if let Some(c) = tier.login_class {
                locked_class = Some((c, *name));
            }
        }
    }

    let (login_class, login_class_source) =
        class_opt.unwrap_or((LoginClass::SharedCredential, "default"));

    EffectiveLoginClass {
        login_class,
        login_class_source,
        locked_at_tier: lock_violation.as_ref().map(|lv| lv.locking_tier),
        locked_by,
        chain,
        lock_violation,
    }
}

// ─── Storage ────────────────────────────────────────────────────────

pub struct PolicyStore {
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
        let type_view = Arc::new(system_view.new_sub_view(TYPE_POLICY_SUB_PATH));
        let asset_group_view = Arc::new(system_view.new_sub_view(ASSET_GROUP_POLICY_SUB_PATH));
        let resource_view = Arc::new(system_view.new_sub_view(RESOURCE_POLICY_SUB_PATH));
        Ok(Arc::new(Self {
            type_view,
            asset_group_view,
            resource_view,
            system_view,
        }))
    }

    // ─── Global policy ──────────────────────────────────────────

    pub async fn get_global(&self) -> Result<GlobalPolicy, RvError> {
        let Some(entry) = self.system_view.get(GLOBAL_POLICY_KEY).await? else {
            return Ok(GlobalPolicy::default());
        };
        serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode ssh-broker global policy: {e}")))
    }

    pub async fn put_global(&self, p: &GlobalPolicy) -> Result<(), RvError> {
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode ssh-broker global policy: {e}")))?;
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
            .map_err(|e| bv_error_string!(&format!("decode ssh-broker type policy: {e}")))
    }

    pub async fn put_type(&self, p: &TypePolicy) -> Result<(), RvError> {
        let name = sanitize(&p.type_name)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode ssh-broker type policy: {e}")))?;
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
            .map_err(|e| bv_error_string!(&format!("decode ssh-broker asset-group policy: {e}")))
    }

    pub async fn put_asset_group(&self, p: &AssetGroupPolicy) -> Result<(), RvError> {
        let id = sanitize(&p.asset_group_id)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode ssh-broker asset-group policy: {e}")))?;
        self.asset_group_view
            .put(&StorageEntry { key: id, value })
            .await
    }

    pub async fn delete_asset_group(&self, asset_group_id: &str) -> Result<(), RvError> {
        let id = sanitize(asset_group_id)?;
        self.asset_group_view.delete(&id).await
    }

    // ─── Resource policy ────────────────────────────────────────

    pub async fn get_resource(&self, resource_id: &str) -> Result<Option<ResourcePolicy>, RvError> {
        let id = sanitize(resource_id)?;
        let Some(entry) = self.resource_view.get(&id).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.value)
            .map(Some)
            .map_err(|e| bv_error_string!(&format!("decode ssh-broker resource policy: {e}")))
    }

    pub async fn put_resource(&self, p: &ResourcePolicy) -> Result<(), RvError> {
        let id = sanitize(&p.resource_id)?;
        let value = serde_json::to_vec(p)
            .map_err(|e| bv_error_string!(&format!("encode ssh-broker resource policy: {e}")))?;
        self.resource_view
            .put(&StorageEntry { key: id, value })
            .await
    }

    pub async fn delete_resource(&self, resource_id: &str) -> Result<(), RvError> {
        let id = sanitize(resource_id)?;
        self.resource_view.delete(&id).await
    }

    pub async fn list_types(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.type_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn list_asset_groups(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.asset_group_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn list_resources(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.resource_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    /// Resolve the effective login class for a single resource, walking
    /// all four tiers. `type_name`, `asset_group_ids`, and `resource_id`
    /// are the resource's classification hints (the caller pulls these
    /// from the resource record + asset-group memberships). An empty
    /// `type_name` / `resource_id` skips that tier.
    pub async fn resolve_for(
        &self,
        type_name: &str,
        asset_group_ids: &[String],
        resource_id: &str,
    ) -> Result<EffectiveLoginClass, RvError> {
        let global = self.get_global().await?;
        let type_ = if type_name.trim().is_empty() {
            None
        } else {
            self.get_type(type_name).await?
        };
        let mut ags: Vec<AssetGroupPolicy> = Vec::new();
        for id in asset_group_ids {
            if let Some(p) = self.get_asset_group(id).await? {
                ags.push(p);
            }
        }
        let resource = if resource_id.trim().is_empty() {
            None
        } else {
            self.get_resource(resource_id).await?
        };
        Ok(resolve(&global, type_.as_ref(), &ags, resource.as_ref()))
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

    fn res(class: LoginClass) -> ResourcePolicy {
        ResourcePolicy {
            resource_id: "r".into(),
            tier: LoginClassTier {
                login_class: Some(class),
                lock: false,
            },
            updated_at: Utc::now(),
        }
    }

    fn global(class: Option<LoginClass>, lock: bool) -> GlobalPolicy {
        GlobalPolicy {
            tier: LoginClassTier {
                login_class: class,
                lock,
            },
            updated_at: None,
        }
    }

    #[test]
    fn default_is_shared_credential() {
        let p = resolve(&GlobalPolicy::default(), None, &[], None);
        assert_eq!(p.login_class, LoginClass::SharedCredential);
        assert_eq!(p.login_class_source, "default");
        assert!(p.lock_violation.is_none());
    }

    #[test]
    fn most_restrictive_wins_brokered() {
        // global brokered, resource tries shared-credential → brokered wins.
        let p = resolve(
            &global(Some(LoginClass::Brokered), false),
            None,
            &[],
            Some(&res(LoginClass::SharedCredential)),
        );
        assert_eq!(p.login_class, LoginClass::Brokered);
        assert_eq!(p.login_class_source, "global");
        // No lock set, so weakening attempt is not a violation — it's
        // simply outvoted by most-restrictive-wins.
        assert!(p.lock_violation.is_none());
    }

    #[test]
    fn resource_can_raise_to_brokered() {
        let p = resolve(
            &global(Some(LoginClass::SharedCredential), false),
            None,
            &[],
            Some(&res(LoginClass::Brokered)),
        );
        assert_eq!(p.login_class, LoginClass::Brokered);
        assert_eq!(p.login_class_source, "resource");
    }

    #[test]
    fn lock_prevents_weakening() {
        let p = resolve(
            &global(Some(LoginClass::Brokered), true),
            None,
            &[],
            Some(&res(LoginClass::SharedCredential)),
        );
        assert_eq!(p.login_class, LoginClass::Brokered);
        let lv = p.lock_violation.as_ref().expect("lock violation");
        assert_eq!(lv.locking_tier, "global");
        assert_eq!(lv.field, "login_class");
        assert_eq!(p.locked_at_tier, Some("global"));
    }

    #[test]
    fn type_tier_locks_brokered_against_resource() {
        let type_ = TypePolicy {
            type_name: "database".into(),
            tier: LoginClassTier {
                login_class: Some(LoginClass::Brokered),
                lock: true,
            },
            updated_at: Utc::now(),
        };
        let p = resolve(
            &GlobalPolicy::default(),
            Some(&type_),
            &[],
            Some(&res(LoginClass::SharedCredential)),
        );
        assert_eq!(p.login_class, LoginClass::Brokered);
        assert_eq!(p.locked_at_tier, Some("type"));
        assert_eq!(
            p.chain,
            vec!["type=brokered".to_string(), "resource=shared-credential".to_string()]
        );
    }

    #[test]
    fn asset_group_priority_breaks_ties() {
        let high = AssetGroupPolicy {
            asset_group_id: "high".into(),
            priority: 10,
            tier: LoginClassTier {
                login_class: Some(LoginClass::Brokered),
                lock: false,
            },
            updated_at: Utc::now(),
        };
        let low = AssetGroupPolicy {
            asset_group_id: "low".into(),
            priority: 5,
            tier: LoginClassTier {
                login_class: Some(LoginClass::SharedCredential),
                lock: false,
            },
            updated_at: Utc::now(),
        };
        // Most-restrictive still wins overall (brokered), regardless of
        // priority — priority only orders same-tier processing.
        let p = resolve(&GlobalPolicy::default(), None, &[low, high], None);
        assert_eq!(p.login_class, LoginClass::Brokered);
        assert_eq!(p.login_class_source, "asset-group");
    }
}
