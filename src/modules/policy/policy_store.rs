//! The `policy_store.rs` file manages the storage and retrieval of security policies. It provides
//! mechanisms for setting, getting, listing, and deleting policies. This is crucial in systems
//! that rely on policy-based access controls.
//!
//! The main components include:
//! - PolicyEntry: Represents an individual policy with metadata.
//! - PolicyStore: Manages the lifecycle of policies, including caching and storage.
//!
//! Key functionality includes:
//! - Creation and management of ACL (Access Control List), RGP, and EGP policies.
//! - Policy caching to improve access speed.
//! - Methods to handle CRUD operations on policies.
//!
//! External dependencies:
//! - Uses `stretto` for caching and `dashmap` for concurrent collections.
//!
//! Note:
//! - The code includes placeholder functions (e.g., `handle_sentinel_policy`) intended for future implementation.
//! - The design assumes a highly concurrent environment, where caching is critical.

use std::{
    str::FromStr,
    sync::{Arc, Weak},
};

use better_default::Default;
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use stretto::Cache;

use super::{
    acl::{ACLResults, ACL},
    policy::SentinelPolicy,
    Policy, PolicyType,
};
use crate::{
    core::Core,
    errors::RvError,
    handler::{AuthHandler, Handler},
    logical::{auth::PolicyResults, Operation, Request, Response},
    modules::{
        identity::{IdentityModule, OwnerStore, ShareStore, ShareTargetKind},
        resource_group::{ResourceGroupModule, ResourceGroupStore},
    },
    router::Router,
    bv_error_response_status, bv_error_string,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};
use serde_json::Value;

// POLICY_ACL_SUB_PATH is the sub-path used for the policy store view. This is
// nested under the system view. POLICY_RGP_SUB_PATH/POLICY_EGP_SUB_PATH are
// similar but for RGPs/EGPs.
const POLICY_ACL_SUB_PATH: &str = "policy/";
const POLICY_RGP_SUB_PATH: &str = "policy-rgp/";
const POLICY_EGP_SUB_PATH: &str = "policy-egp/";
// POLICY_HISTORY_SUB_PATH stores append-only audit entries for ACL policy
// changes. Keys are `{name}/{20-digit-nanos}` so `list` returns entries
// in chronological order. History is retained when the policy is deleted
// so the audit trail remains available after removal.
const POLICY_HISTORY_SUB_PATH: &str = "policy-history/";


// DEFAULT_POLICY_NAME is the name of the default policy
const DEFAULT_POLICY_NAME: &str = "default";
pub static DEFAULT_POLICY: &str = r#"
# Allow tokens to look up their own properties
path "auth/token/lookup-self" {
    capabilities = ["read"]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own capabilities on a path
path "sys/capabilities-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own entity by id or name
path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read"]
}
path "identity/entity/name/{{identity.entity.name}}" {
  capabilities = ["read"]
}


# Allow a token to look up its resultant ACL from all policies. This is useful
# for UIs. It is an internal path because the format may change at any time
# based on how the internal ACL features and capabilities change.
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# Allow a token to renew a lease via lease_id in the request body; old path for
# old clients, new path for newer
path "sys/renew" {
    capabilities = ["update"]
}
path "sys/leases/renew" {
    capabilities = ["update"]
}

# Allow looking up lease properties. This requires knowing the lease ID ahead
# of time and does not divulge any sensitive information.
path "sys/leases/lookup" {
    capabilities = ["update"]
}

# Allow a token to manage its own cubbyhole
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow a token to wrap arbitrary values in a response-wrapping token
path "sys/wrapping/wrap" {
    capabilities = ["update"]
}

# Allow a token to look up the creation time and TTL of a given
# response-wrapping token
path "sys/wrapping/lookup" {
    capabilities = ["update"]
}

# Allow a token to unwrap a response-wrapping token. This is a convenience to
# avoid client token swapping since this is also part of the response wrapping
# policy.
path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}

# Allow general purpose tools
path "sys/tools/hash" {
    capabilities = ["update"]
}
path "sys/tools/hash/*" {
    capabilities = ["update"]
}

# Allow checking the status of a Control Group request if the user has the
# accessor
path "sys/control-group/request" {
    capabilities = ["update"]
}
"#;

static RESPONSE_WRAPPING_POLICY_NAME: &str = "response-wrapping";
static RESPONSE_WRAPPING_POLICY: &str = r#"
path "cubbyhole/response" {
    capabilities = ["create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
"#;

static CONTROL_GROUP_POLICY_NAME: &str = "control-group";
static CONTROL_GROUP_POLICY: &str = r#"
path "cubbyhole/control-group" {
    capabilities = ["update", "create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
"#;

/// Baseline policy for unprivileged users. Seeded on first unseal and
/// editable afterward (not in IMMUTABLE_POLICIES). Grants:
///   - read + list on all KV secrets (so users can read secrets they
///     created or that others granted them visibility to);
///   - create + read + list + update on resources and per-resource
///     secrets (so users can create new resources and populate them);
///   - no delete, no policy/user/mount/identity management;
///   - cubbyhole access + the usual token-self operations from the
///     `default` policy.
///
/// Note: BastionVault does not currently substitute `{{username}}` or
/// similar placeholders in policy paths, so this policy cannot express
/// "only the secrets *you* created". It intentionally grants broad
/// read/list scope across the shared `secret/` and `resources/` mounts;
/// operators who need per-user isolation should either adopt a path
/// convention per user and tighten this policy, or group users via the
/// identity backend so policy assignment is narrower per group.
static STANDARD_USER_POLICY_NAME: &str = "standard-user";
static STANDARD_USER_POLICY: &str = r#"
# --- Self service (mirrors the relevant parts of the default policy) ---

path "auth/token/lookup-self" {
    capabilities = ["read"]
}
path "auth/token/renew-self" {
    capabilities = ["update"]
}
path "auth/token/revoke-self" {
    capabilities = ["update"]
}
path "sys/capabilities-self" {
    capabilities = ["update"]
}
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# --- KV secrets ---

# KV-v1: read and list secrets under the default mount.
path "secret/*" {
    capabilities = ["read", "list"]
}

# KV-v2: data + metadata read/list paths.
path "secret/data/*" {
    capabilities = ["read", "list"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
}

# --- Resources ---

# Create new resources and read/list/update existing ones. Delete is
# intentionally not granted -- destructive operations on the shared
# resource inventory should require a privileged operator policy.
path "resources/*" {
    capabilities = ["create", "read", "update", "list"]
}

# --- Per-user workspace ---

# Each token gets its own private cubbyhole for scratch storage.
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// Read-only ownership-scoped baseline. Grants a user read+list on any
/// KV secret or resource they *own* (wrote) or that has been explicitly
/// shared with them (once sharing lands). Does not grant create,
/// update, delete, or any administrative capability.
///
/// Complements the existing broadly-scoped `standard-user` policy,
/// which operators can still assign for deployments that have not
/// opted into ownership-aware ACLs.
static STANDARD_USER_READONLY_POLICY_NAME: &str = "standard-user-readonly";
static STANDARD_USER_READONLY_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- KV secrets (owner-scoped read) ---
path "secret/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/data/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}

# --- Resources (owner-scoped read) ---
path "resources/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// Full-CRUD ownership-scoped role. The user manages what they
/// authored — create/read/update/delete/list on any KV secret or
/// resource they own (or have shared with them, once sharing lands).
/// No access to other users' objects without a share. No
/// administrative capabilities.
static SECRET_AUTHOR_POLICY_NAME: &str = "secret-author";
static SECRET_AUTHOR_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- KV secrets (full CRUD on authored/shared items) ---
path "secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list", "delete"]
    scopes       = ["owner", "shared"]
}

# --- Resources (full CRUD on authored/shared items) ---
path "resources/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// PKI consumer baseline. Grants a user the right to *use* a PKI mount
/// (issue certificates, sign CSRs, read public CA material and CRLs)
/// without granting any administrative capability over issuers, roles,
/// configuration, or revocation. Pair this with a wildcard mount path
/// (the default `pki/`) or a bespoke mount the operator has stood up
/// for the user's department.
///
/// Operators who run multiple PKI mounts can assign this policy to a
/// group and rely on the inherent path-prefix scoping to limit the
/// blast radius — the policy purposely uses the conventional `pki/`
/// path, so a user with this baseline who does not have access to a
/// `pki-corp/` mount cannot accidentally issue against it.
static PKI_USER_POLICY_NAME: &str = "pki-user";
static PKI_USER_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- PKI: issuance and signing (requires create/update on issue/sign) ---
path "pki/issue/*"          { capabilities = ["create", "update"] }
path "pki/sign/*"           { capabilities = ["create", "update"] }
path "pki/sign-verbatim"    { capabilities = ["create", "update"] }
path "pki/sign-verbatim/*"  { capabilities = ["create", "update"] }

# --- PKI: read public material ---
path "pki/ca"            { capabilities = ["read"] }
path "pki/ca/pem"        { capabilities = ["read"] }
path "pki/ca_chain"      { capabilities = ["read"] }
path "pki/cert/*"        { capabilities = ["read"] }
path "pki/certs"         { capabilities = ["list"] }
path "pki/crl"           { capabilities = ["read"] }
path "pki/crl/pem"       { capabilities = ["read"] }
path "pki/issuers"       { capabilities = ["list", "read"] }
path "pki/issuer/+/json" { capabilities = ["read"] }
path "pki/issuer/+/pem"  { capabilities = ["read"] }
path "pki/issuer/+/der"  { capabilities = ["read"] }
path "pki/issuer/+/crl"  { capabilities = ["read"] }
path "pki/roles"         { capabilities = ["list"] }
path "pki/roles/*"       { capabilities = ["read"] }

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// PKI administrator baseline. Grants full management of a PKI mount:
/// issuer lifecycle (root generation/import, intermediate signing,
/// rename/delete), role lifecycle, configuration (URLs, CRL settings),
/// tidy/scheduler control, and revocation. Inherits all `pki-user`
/// capabilities. Operators who want to delegate PKI administration to
/// a non-root identity should grant this without granting full `admin`.
static PKI_ADMIN_POLICY_NAME: &str = "pki-admin";
static PKI_ADMIN_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Mount discovery (PKI admin needs to see PKI mounts) ---
path "sys/mounts"   { capabilities = ["read", "list"] }
path "sys/mounts/*" { capabilities = ["read"] }

# --- PKI: full management ---
path "pki/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

static _POLICY_STORE_HELP: &str = r#"
TODO
"#;

lazy_static! {
    pub static ref IMMUTABLE_POLICIES: Vec<&'static str> =
        vec!["root", RESPONSE_WRAPPING_POLICY_NAME, CONTROL_GROUP_POLICY_NAME,];
    pub static ref NON_ASSIGNABLE_POLICIES: Vec<&'static str> =
        vec![RESPONSE_WRAPPING_POLICY_NAME, CONTROL_GROUP_POLICY_NAME,];
}

/// Represents a policy entry in the policy store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub version: u32,
    pub raw: String,
    pub templated: bool,
    #[default(PolicyType::Acl)]
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    pub sentinal_policy: SentinelPolicy,
}

/// Audit log entry for a policy change. Records the raw HCL before and
/// after the change so operators can reconstruct prior policy states and
/// roll back by re-submitting `before.raw` if needed. For `create`,
/// `before_raw` is empty; for `delete`, `after_raw` is empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub before_raw: String,
    #[serde(default)]
    pub after_raw: String,
}

/// The main policy store structure.
#[derive(Default)]
pub struct PolicyStore {
    pub router: Arc<Router>,
    /// Weak reference back to Core so `post_auth` can resolve optional
    /// subsystems (resource-group) without a strong cycle. Upgrade at
    /// use site; tolerate `None` so unit tests that construct a bare
    /// store continue to work.
    pub core: Weak<Core>,
    pub acl_view: Option<Arc<BarrierView>>,
    pub rgp_view: Option<Arc<BarrierView>>,
    pub egp_view: Option<Arc<BarrierView>>,
    pub history_view: Option<Arc<BarrierView>>,
    pub token_policies_lru: Option<Cache<String, Arc<Policy>>>,
    pub egp_lru: Option<Cache<String, Arc<Policy>>>,
    // Stores whether a token policy is ACL or RGP
    pub policy_type_map: DashMap<String, PolicyType>,
    pub self_ptr: Weak<PolicyStore>,
}

#[maybe_async::maybe_async]
impl PolicyStore {
    /// Creates a new `PolicyStore` with initial setup based on the given `Core`.
    ///
    /// This function initializes views and caches necessary for policy management.
    ///
    /// # Arguments
    ///
    /// * `core` - A reference to the `Core` struct used for initializing views and caches.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<PolicyStore>, RvError>` - An Arc-wrapped `PolicyStore` instance or an error.
    pub async fn new(core: &Core) -> Result<Arc<PolicyStore>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let acl_view = system_view.new_sub_view(POLICY_ACL_SUB_PATH);
        let rgp_view = system_view.new_sub_view(POLICY_RGP_SUB_PATH);
        let egp_view = system_view.new_sub_view(POLICY_EGP_SUB_PATH);
        let history_view = system_view.new_sub_view(POLICY_HISTORY_SUB_PATH);

        let keys = acl_view.get_keys().await?;

        let mut policy_store = PolicyStore {
            router: core.router.clone(),
            core: core.self_ptr.clone(),
            acl_view: Some(Arc::new(acl_view)),
            rgp_view: Some(Arc::new(rgp_view)),
            egp_view: Some(Arc::new(egp_view)),
            history_view: Some(Arc::new(history_view)),
            self_ptr: Weak::default(),
            ..Default::default()
        };

        let policy_cache_size = core.cache_config.policy_cache_size.max(1);
        policy_store.token_policies_lru = Some(
            Cache::builder(policy_cache_size * 10, policy_cache_size as i64)
                .set_ignore_internal_cost(true)
                .finalize()
                .unwrap(),
        );
        policy_store.egp_lru = Some(
            Cache::builder(policy_cache_size * 10, policy_cache_size as i64)
                .set_ignore_internal_cost(true)
                .finalize()
                .unwrap(),
        );

        for key in keys.iter() {
            policy_store.policy_type_map.insert(policy_store.cache_key(key.as_str()), PolicyType::Acl);
        }

        // Special-case root; doesn't exist on disk but does need to be found
        policy_store.policy_type_map.insert(policy_store.cache_key("root"), PolicyType::Acl);

        Ok(policy_store.wrap())
    }

    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    /// Set a policy in the policy store.
    /// This function validates the policy name, checks for immutability, and inserts the policy into the appropriate view.
    pub async fn set_policy(&self, policy: Policy) -> Result<(), RvError> {
        if policy.name.is_empty() {
            return Err(bv_error_string!("policy name missing"));
        }

        let name = self.sanitize_name(&policy.name);
        if IMMUTABLE_POLICIES.contains(&name.as_str()) {
            return Err(bv_error_string!(format!("cannot update {} policy", name)));
        }

        if name != policy.name {
            let mut p = policy.clone();
            p.name = name;
            return self.set_policy_internal(Arc::new(p)).await;
        }

        self.set_policy_internal(Arc::new(policy)).await
    }

    // Get a policy from the policy store.
    // This function retrieves the policy from the appropriate view, checks the cache, and handles policy type mapping.
    pub async fn get_policy(&self, name: &str, policy_type: PolicyType) -> Result<Option<Arc<Policy>>, RvError> {
        let name = self.sanitize_name(name);
        let index = self.cache_key(&name);
        let mut policy_type = policy_type;
        let (view, cache) = match policy_type {
            PolicyType::Acl => (Some(self.get_acl_view()?), &self.token_policies_lru),
            PolicyType::Rgp => (Some(self.get_rgp_view()?), &self.token_policies_lru),
            PolicyType::Egp => (Some(self.get_egp_view()?), &self.egp_lru),
            PolicyType::Token => {
                let (v, c) = if let Some(val) = self.policy_type_map.get(&index) {
                    policy_type = *val;
                    match *val {
                        PolicyType::Acl => (Some(self.get_acl_view()?), &self.token_policies_lru),
                        PolicyType::Rgp => (Some(self.get_rgp_view()?), &self.token_policies_lru),
                        _ => {
                            return Err(bv_error_string!(format!(
                                "invalid type of policy in type map: {}",
                                policy_type
                            )))
                        }
                    }
                } else {
                    (None, &None)
                };

                (v, c)
            }
        };

        if let Some(lru) = cache {
            if let Some(p) = lru.get(&index) {
                crate::metrics::cache_metrics::cache_metrics()
                    .record_hit(crate::metrics::cache_metrics::CacheLayer::Policy);
                return Ok(Some(p.value().clone()));
            }
            crate::metrics::cache_metrics::cache_metrics()
                .record_miss(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        if policy_type == PolicyType::Acl && name == "root" {
            let p = Arc::new(Policy { name: "root".into(), ..Default::default() });
            if let Some(lru) = cache {
                lru.insert(index.clone(), p.clone(), 1);
            }
            return Ok(Some(p));
        }

        if view.is_none() {
            return Err(bv_error_string!(format!("unable to get the barrier subview for policy type {}", policy_type)));
        }

        let view = view.unwrap();

        let entry = view.get(&name).await?;
        if entry.is_none() {
            return Ok(None);
        }

        let entry = entry.unwrap();

        let policy_entry: PolicyEntry = serde_json::from_slice(entry.value.as_slice())?;

        let mut policy = match policy_type {
            PolicyType::Acl => {
                let p = Policy::from_str(&policy_entry.raw)?;
                self.policy_type_map.insert(index.clone(), PolicyType::Acl);
                p
            }
            PolicyType::Rgp => {
                let p = Policy::default();
                self.handle_sentinel_policy(&p, view, &entry)?;
                self.policy_type_map.insert(index.clone(), PolicyType::Rgp);
                p
            }
            PolicyType::Egp => {
                let p = Policy::default();
                self.handle_sentinel_policy(&p, view, &entry)?;
                p
            }
            _ => {
                return Err(bv_error_string!("invalid type of policy"));
            }
        };

        policy.name = name.to_string();
        policy.policy_type = policy_entry.policy_type;
        policy.templated = policy_entry.templated;

        let p = Arc::new(policy);

        if let Some(lru) = cache {
            lru.insert(index.clone(), p.clone(), 1);
        }

        Ok(Some(p))
    }

    /// List policies of a specific type in the policy store.
    /// This function retrieves the keys from the appropriate view and filters out non-assignable policies for ACLs.
    pub async fn list_policy(&self, policy_type: PolicyType) -> Result<Vec<String>, RvError> {
        let view = self.get_barrier_view(policy_type)?;
        match policy_type {
            PolicyType::Acl => {
                let mut keys = view.get_keys().await?;
                keys.retain(|s| !NON_ASSIGNABLE_POLICIES.iter().any(|&x| s == x));
                Ok(keys)
            }
            PolicyType::Rgp | PolicyType::Egp => view.get_keys().await,
            _ => Err(bv_error_string!("invalid type of policy")),
        }
    }

    /// Delete a policy from the policy store.
    /// This function removes the policy from the appropriate view, updates the cache, and handles sentinel policy invalidation.
    pub async fn delete_policy(&self, name: &str, policy_type: PolicyType) -> Result<(), RvError> {
        let name = self.sanitize_name(name);
        let view = self.get_barrier_view(policy_type)?;
        let index = self.cache_key(&name);
        match policy_type {
            PolicyType::Acl => {
                if IMMUTABLE_POLICIES.contains(&name.as_str()) {
                    return Err(bv_error_response_status!(400, format!("cannot delete {} policy", name)));
                }
                if name == "default" {
                    return Err(bv_error_response_status!(400, "cannot delete default policy"));
                }
                view.delete(&name).await?;
                self.remove_token_policy_cache(&index)?;
                self.policy_type_map.remove(&index);
            }
            PolicyType::Rgp => {
                view.delete(&name).await?;
                self.remove_token_policy_cache(&index)?;
                self.policy_type_map.remove(&index);
                self.invalidate_sentinal_policy(policy_type, "")?;
            }
            PolicyType::Egp => {
                view.delete(&name).await?;
                self.remove_egp_cache(&index)?;
                self.invalidate_egp_tree_path("")?;
                self.invalidate_sentinal_policy(policy_type, "")?;
            }
            _ => {
                return Err(bv_error_string!("unknown policy type, cannot set"));
            }
        }
        Ok(())
    }

    /// Load an ACL policy into the policy store.
    /// This function retrieves the policy if it exists, validates immutability, and sets the policy.
    pub async fn load_acl_policy(&self, policy_name: &str, policy_text: &str) -> Result<(), RvError> {
        let name = self.sanitize_name(policy_name);
        let policy = self.get_policy(&name, PolicyType::Acl).await?;
        if policy.is_some() && (!IMMUTABLE_POLICIES.contains(&name.as_str()) || policy_text == policy.unwrap().raw) {
            return Ok(());
        }

        let mut policy = Policy::from_str(policy_text)?;
        policy.name.clone_from(&name);
        policy.policy_type = PolicyType::Acl;

        self.set_policy_internal(Arc::new(policy)).await
    }

    /// Load default ACL policies into the policy store.
    pub async fn load_default_acl_policy(&self) -> Result<(), RvError> {
        self.load_acl_policy(DEFAULT_POLICY_NAME, DEFAULT_POLICY).await?;
        self.load_acl_policy(RESPONSE_WRAPPING_POLICY_NAME, RESPONSE_WRAPPING_POLICY).await?;
        self.load_acl_policy(CONTROL_GROUP_POLICY_NAME, CONTROL_GROUP_POLICY).await?;
        self.load_acl_policy(STANDARD_USER_POLICY_NAME, STANDARD_USER_POLICY).await?;
        // Ownership-aware baselines. See `features/per-user-scoping.md`.
        self.load_acl_policy(STANDARD_USER_READONLY_POLICY_NAME, STANDARD_USER_READONLY_POLICY)
            .await?;
        self.load_acl_policy(SECRET_AUTHOR_POLICY_NAME, SECRET_AUTHOR_POLICY).await?;
        // PKI delegated baselines. `pki-user` grants issuance/signing
        // without admin authority; `pki-admin` grants full mount
        // management. See `features/pki-secret-engine.md`.
        self.load_acl_policy(PKI_USER_POLICY_NAME, PKI_USER_POLICY).await?;
        self.load_acl_policy(PKI_ADMIN_POLICY_NAME, PKI_ADMIN_POLICY).await?;
        Ok(())
    }

    /// Create a new ACL instance from a list of policy names and additional policies.
    /// This function retrieves policies by name, combines them with additional policies, and creates an ACL.
    pub async fn new_acl(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
    ) -> Result<ACL, RvError> {
        self.new_acl_inner(policy_names, additional_policies, None).await
    }

    /// ACL construction with templating context. Templated policies (those
    /// detected at parse time to contain `{{...}}` placeholders in their
    /// path strings) are deep-cloned and substituted using the caller's
    /// identity (`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`).
    /// Substitution rules mirror `features/per-user-scoping.md` §1:
    /// placeholders that cannot be resolved cause the owning path rule
    /// to be dropped (fail-closed) with a logged warning. Non-templated
    /// policies pass through untouched.
    pub async fn new_acl_for_request(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
        auth: &crate::logical::Auth,
    ) -> Result<ACL, RvError> {
        self.new_acl_inner(policy_names, additional_policies, Some(auth))
            .await
    }

    async fn new_acl_inner(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
        auth: Option<&crate::logical::Auth>,
    ) -> Result<ACL, RvError> {
        let mut all_policies: Vec<Arc<Policy>> = vec![];
        for policy_name in policy_names.iter() {
            if let Some(policy) = self.get_policy(policy_name.as_str(), PolicyType::Token).await? {
                all_policies.push(policy);
            }
        }

        if let Some(ap) = additional_policies {
            all_policies.extend(ap);
        }

        // Apply templating substitution to any policy flagged `templated`
        // when we have a caller context. Produces a parallel Vec of
        // Arc<Policy> that ACL::new consumes.
        let materialized: Vec<Arc<Policy>> = all_policies
            .into_iter()
            .filter_map(|p| {
                if p.templated {
                    match auth {
                        Some(a) => apply_templates(&p, a),
                        // No caller context: drop templated policies
                        // fail-closed rather than let literal `{{...}}`
                        // strings reach path matching where they would
                        // never hit a real request.
                        None => {
                            log::warn!(
                                "dropping templated policy '{}' because no caller \
                                 context is available for substitution",
                                p.name,
                            );
                            None
                        }
                    }
                } else {
                    Some(p)
                }
            })
            .collect();

        ACL::new(&materialized)
    }

    async fn set_policy_internal(&self, policy: Arc<Policy>) -> Result<(), RvError> {
        let view = self.get_barrier_view(policy.policy_type)?;
        let pe = PolicyEntry {
            version: 2,
            templated: policy.templated,
            raw: policy.raw.clone(),
            policy_type: policy.policy_type,
            sentinal_policy: policy.sentinal_policy,
        };

        let entry = StorageEntry::new(&policy.name, &pe)?;

        let index = self.cache_key(&policy.name);

        match policy.policy_type {
            PolicyType::Acl => {
                let rgp_view = self.get_rgp_view()?;
                let rgp = rgp_view.get(&policy.name).await?;
                if rgp.is_some() {
                    return Err(bv_error_string!("cannot reuse policy names between ACLs and RGPs"));
                }

                view.put(&entry).await?;

                self.policy_type_map.insert(index.clone(), PolicyType::Acl);

                self.save_token_policy_cache(index.clone(), policy.clone())?;
            }
            PolicyType::Rgp => {
                let acl_view = self.get_acl_view()?;
                let acl = acl_view.get(&policy.name).await?;
                if acl.is_some() {
                    return Err(bv_error_string!("cannot reuse policy names between ACLs and RGPs"));
                }

                self.handle_sentinel_policy(policy.as_ref(), view, &entry)?;

                self.policy_type_map.insert(index.clone(), PolicyType::Rgp);

                self.save_token_policy_cache(index.clone(), policy.clone())?;
            }
            PolicyType::Egp => {
                self.handle_sentinel_policy(policy.as_ref(), view, &entry)?;
                self.save_egp_cache(index.clone(), policy.clone())?;
            }
            _ => {
                return Err(bv_error_string!("unknown policy type, cannot set"));
            }
        }

        Ok(())
    }

    fn get_barrier_view(&self, _policy_type: PolicyType) -> Result<Arc<BarrierView>, RvError> {
        self.get_acl_view()
    }

    fn get_acl_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.acl_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type acl")),
        }
    }

    fn get_rgp_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.rgp_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type rpg")),
        }
    }

    fn get_egp_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.egp_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type epg")),
        }
    }

    fn save_token_policy_cache(&self, index: String, policy: Arc<Policy>) -> Result<(), RvError> {
        if let Some(lru) = &self.token_policies_lru {
            if !lru.insert(index, policy, 1) {
                return Err(bv_error_string!("save token policy cache failed!"));
            }
        }

        Ok(())
    }

    /// Flush every cached policy and zeroize the held Arcs. Called by
    /// `Core::flush_caches` on seal and by the `sys/cache/flush` admin
    /// endpoint. Safe to call when the cache is already empty.
    pub fn flush_caches(&self) {
        if let Some(lru) = &self.token_policies_lru {
            lru.clear().ok();
        }
        if let Some(lru) = &self.egp_lru {
            lru.clear().ok();
        }
    }

    fn remove_token_policy_cache(&self, index: &String) -> Result<(), RvError> {
        if let Some(lru) = &self.token_policies_lru {
            lru.remove(index);
            crate::metrics::cache_metrics::cache_metrics()
                .record_eviction(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        Ok(())
    }

    fn save_egp_cache(&self, index: String, policy: Arc<Policy>) -> Result<(), RvError> {
        if let Some(lru) = &self.egp_lru {
            if !lru.insert(index, policy, 1) {
                return Err(bv_error_string!("save token policy cache failed!"));
            }
        }

        Ok(())
    }

    fn remove_egp_cache(&self, index: &String) -> Result<(), RvError> {
        if let Some(lru) = &self.egp_lru {
            lru.remove(index);
            crate::metrics::cache_metrics::cache_metrics()
                .record_eviction(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        Ok(())
    }

    fn handle_sentinel_policy(
        &self,
        _policy: &Policy,
        _view: Arc<BarrierView>,
        _entry: &StorageEntry,
    ) -> Result<(), RvError> {
        Ok(())
    }

    fn invalidate_sentinal_policy(&self, _policy_type: PolicyType, _index: &str) -> Result<(), RvError> {
        Ok(())
    }

    fn invalidate_egp_tree_path(&self, _index: &str) -> Result<(), RvError> {
        Ok(())
    }

    /// Sanitize a policy name by converting it to lowercase.
    fn sanitize_name(&self, name: &str) -> String {
        name.to_lowercase().to_string()
    }

    /// Generate a cache key for a given policy name.
    fn cache_key(&self, name: &str) -> String {
        name.to_string()
    }

    /// Append an audit entry for a policy change. The entry is keyed by
    /// `{name}/{20-digit-nanos}` so history for a single policy can be
    /// listed in chronological order by sorting.
    pub async fn append_history(
        &self,
        name: &str,
        entry: PolicyHistoryEntry,
    ) -> Result<(), RvError> {
        let view = self
            .history_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("policy history view unavailable"))?;
        let name = self.sanitize_name(name);
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Return the full history for a single policy, newest entry first.
    /// History persists after the policy is deleted so audit records
    /// remain available until explicitly purged.
    pub async fn list_history(
        &self,
        name: &str,
    ) -> Result<Vec<PolicyHistoryEntry>, RvError> {
        let view = self
            .history_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("policy history view unavailable"))?;
        let name = self.sanitize_name(name);
        let prefix = format!("{name}/");
        let mut keys = view.list(&prefix).await?;
        keys.sort();
        keys.reverse();

        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<PolicyHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }
}

/// Extract a resource name from `request_path` if it targets the
/// resource engine. The resource module is mounted at `resources/` and
/// its internal paths include `resources/<name>` (metadata) and
/// `secrets/<resource>/<key>` (per-resource secrets). The full request
/// path (pre-mount-strip) therefore looks like `resources/resources/<name>`
/// or `resources/secrets/<resource>/<key>`. Returns `None` for any other
/// path shape, which is the signal to treat `asset_groups` as empty.
fn resource_name_from_path(req_path: &str) -> Option<String> {
    let p = req_path.strip_prefix('/').unwrap_or(req_path);
    let rest = p.strip_prefix("resources/")?;
    let rest = rest.strip_prefix("resources/").or_else(|| rest.strip_prefix("secrets/"))?;
    let name = rest.split('/').next()?;
    if name.is_empty() { None } else { Some(name.to_lowercase()) }
}

/// Extract a file id from `request_path` if it targets the files
/// engine. The files module is mounted at `files/` and its metadata
/// path is `files/<id>` (plus optional sub-segments like `/content` or
/// `/history`). The full request path is therefore
/// `files/files/<id>[/...]`. Returns the id on match (ownership hooks
/// only fire on the metadata endpoint; `/content` and `/history`
/// should not restamp ownership).
fn file_id_from_path(req_path: &str) -> Option<String> {
    let p = req_path.strip_prefix('/').unwrap_or(req_path);
    let rest = p.strip_prefix("files/")?;
    let rest = rest.strip_prefix("files/")?;
    let mut parts = rest.splitn(2, '/');
    let id = parts.next()?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_lowercase())
}

/// As `file_id_from_path`, but only returns the id when the remainder
/// of the path is empty — i.e. the request targets the file metadata
/// directly and not a sub-endpoint like `/content` or `/history`.
fn file_id_from_metadata_path(req_path: &str) -> Option<String> {
    let p = req_path.strip_prefix('/').unwrap_or(req_path);
    let rest = p.strip_prefix("files/")?;
    let rest = rest.strip_prefix("files/")?;
    // No further `/` segment means this is the metadata leaf path.
    if rest.contains('/') {
        return None;
    }
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_lowercase())
}

/// Does `request_path` look like a KV (v1 or v2) request? The routing
/// layer puts KV mounts under their operator-chosen path (default
/// `secret/`). We can't enumerate mounts from here cheaply, so we use
/// a permissive heuristic: anything that is *not* one of the fixed
/// non-KV prefixes (`sys/`, `auth/`, `identity/`, `resource-group/`,
/// `cubbyhole/`, `resources/`) is treated as a candidate KV path. If
/// the secret-index has no entry for it, `groups_for_secret` returns
/// an empty vec and the evaluator moves on. Worst case: a request for
/// a non-KV path outside this allowlist hits one extra index lookup.
fn looks_like_kv_path(req_path: &str) -> bool {
    let p = req_path.strip_prefix('/').unwrap_or(req_path);
    const NON_KV_PREFIXES: &[&str] = &[
        "sys/",
        "auth/",
        "identity/",
        "resource-group/",
        "cubbyhole/",
        "resources/",
        "files/",
    ];
    !p.is_empty() && !NON_KV_PREFIXES.iter().any(|pref| p.starts_with(pref))
}

/// Best-effort resolve of the owner entity_id for the request target.
/// Returns an empty string on any failure (module absent, no owner
/// record, path shape we don't recognize). `scope_passes` treats an
/// empty `asset_owner` as "no owner match", so a resolution miss can
/// only narrow access for owner-scoped rules.
async fn resolve_asset_owner(core: &Weak<Core>, req_path: &str) -> String {
    let Some(core) = core.upgrade() else {
        return String::new();
    };
    let Some(module) = core.module_manager.get_module::<IdentityModule>("identity") else {
        return String::new();
    };
    let Some(store) = module.owner_store() else {
        return String::new();
    };
    if let Some(name) = resource_name_from_path(req_path) {
        if let Ok(Some(rec)) = store.get_resource_owner(&name).await {
            return rec.entity_id;
        }
    }
    if let Some(id) = file_id_from_path(req_path) {
        if let Ok(Some(rec)) = store.get_file_owner(&id).await {
            return rec.entity_id;
        }
    }
    if looks_like_kv_path(req_path) {
        if let Ok(Some(rec)) = store.get_kv_owner(req_path).await {
            return rec.entity_id;
        }
    }
    String::new()
}

/// Best-effort lookup of the capabilities the caller has on the
/// request target via any non-expired `SecretShare`. Returns an
/// empty vec on any failure (module absent, store not yet
/// initialized, caller has no `entity_id`, path shape we don't
/// recognize). A resolution miss can only narrow access for
/// shared-scoped rules — fail-closed.
async fn resolve_target_shared_caps(
    core: &Weak<Core>,
    req: &Request,
) -> Vec<String> {
    let Some(caller_id) = req
        .auth
        .as_ref()
        .and_then(|a| a.metadata.get("entity_id"))
        .cloned()
    else {
        return Vec::new();
    };
    if caller_id.is_empty() {
        return Vec::new();
    }
    let Some(core) = core.upgrade() else {
        return Vec::new();
    };
    let Some(module) = core.module_manager.get_module::<IdentityModule>("identity") else {
        return Vec::new();
    };
    let Some(store) = module.share_store() else {
        return Vec::new();
    };

    // Direct shares first (kind = resource or kv-secret), then
    // indirect shares via asset-group membership — a share granted
    // on a group name covers every current member of the group.
    // Capabilities from all matching shares union together.
    let mut caps: Vec<String> = Vec::new();
    let mut merge = |more: Vec<String>| {
        for c in more {
            if !caps.iter().any(|x| x == &c) {
                caps.push(c);
            }
        }
    };

    if let Some(name) = resource_name_from_path(&req.path) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::Resource, &name, &caller_id)
            .await
        {
            merge(v);
        }
    }
    if looks_like_kv_path(&req.path) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::KvSecret, &req.path, &caller_id)
            .await
        {
            merge(v);
        }
    }
    if let Some(id) = file_id_from_path(&req.path) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::File, &id, &caller_id)
            .await
        {
            merge(v);
        }
    }

    // Indirect: walk the caller's asset-group memberships for this
    // target and union any asset-group shares addressed to them. We
    // already have the list on `req.asset_groups` — `post_auth`
    // populated it before this helper runs, so no extra lookup is
    // needed against the reverse index. Silent on any failure.
    if !req.asset_groups.is_empty() {
        for group in &req.asset_groups {
            if let Ok(v) = store
                .shared_capabilities(ShareTargetKind::AssetGroup, group, &caller_id)
                .await
            {
                merge(v);
            }
        }
    }

    caps
}

/// Best-effort lookup of the asset-groups that contain the request
/// target. Consults the resource-index when the path looks like a
/// resource engine path, then (independently) the secret-index when
/// the path looks like a KV path. The two lookups can both contribute
/// — a group-gated policy rule can reference a group whose members
/// include both resources and secrets, and either kind of target
/// passing the gate is enough for the rule to apply.
///
/// Returns an empty vec on any failure (module absent, store not yet
/// initialized, path we don't recognize, storage error). The ACL
/// evaluator treats empty here as "target is in no groups", so a
/// lookup failure can only narrow access, never widen it.
async fn resolve_asset_groups(core: &Weak<Core>, req_path: &str) -> Vec<String> {
    let Some(core) = core.upgrade() else {
        return Vec::new();
    };
    let Some(module) = core.module_manager.get_module::<ResourceGroupModule>("resource-group") else {
        return Vec::new();
    };
    let Some(store) = module.store() else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();

    if let Some(name) = resource_name_from_path(req_path) {
        if let Ok(groups) = store.groups_for_resource(&name).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    if looks_like_kv_path(req_path) {
        if let Ok(groups) = store.groups_for_secret(req_path).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    if let Some(id) = file_id_from_path(req_path) {
        if let Ok(groups) = store.groups_for_file(&id).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    out
}

/// Substitute `{{username}}`, `{{entity.id}}`, and `{{auth.mount}}`
/// in every path of a templated policy using the caller's `Auth`.
///
/// Returns a cloned `Arc<Policy>` with substituted paths on success,
/// or `None` when every path rule dropped (unresolved placeholders).
/// Path rules whose substitution fails are dropped individually; the
/// rest of the policy is retained. Warnings are logged.
///
/// Substitution vocabulary (v1):
///   `{{username}}`   — `auth.metadata["username"]`, falling back to
///                      `auth.display_name`.
///   `{{entity.id}}`  — `auth.metadata["entity_id"]`.
///   `{{auth.mount}}` — `auth.metadata["mount_path"]` (populated by
///                      the auth backend when available).
fn apply_templates(
    policy: &Arc<Policy>,
    auth: &crate::logical::Auth,
) -> Option<Arc<Policy>> {
    let username = auth
        .metadata
        .get("username")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| auth.display_name.clone());
    let entity_id = auth
        .metadata
        .get("entity_id")
        .cloned()
        .unwrap_or_default();
    let auth_mount = auth
        .metadata
        .get("mount_path")
        .cloned()
        .unwrap_or_default();

    let mut cloned: Policy = Policy::clone(policy);
    let mut kept: Vec<crate::modules::policy::PolicyPathRules> =
        Vec::with_capacity(cloned.paths.len());
    let mut dropped = 0usize;

    for mut rule in cloned.paths.drain(..) {
        match substitute_path(&rule.path, &username, &entity_id, &auth_mount) {
            Some(new_path) => {
                rule.path = new_path;
                kept.push(rule);
            }
            None => {
                log::warn!(
                    "policy '{}': dropping path rule '{}' — unresolved template placeholder",
                    cloned.name,
                    rule.path,
                );
                dropped += 1;
            }
        }
    }

    if kept.is_empty() {
        log::warn!(
            "policy '{}': all {} path rule(s) dropped due to unresolved template placeholders; \
             policy contributes no authorization this turn",
            cloned.name,
            dropped,
        );
        return None;
    }

    cloned.paths = kept;
    Some(Arc::new(cloned))
}

/// Replace every supported `{{...}}` placeholder with its value.
/// Returns `None` if any `{{...}}` placeholder cannot be resolved
/// (e.g., `{{username}}` on a root-token request where auth metadata
/// is empty). An unknown placeholder name (outside the v1 vocabulary)
/// is also treated as unresolved, so typos are fail-closed.
fn substitute_path(
    path: &str,
    username: &str,
    entity_id: &str,
    auth_mount: &str,
) -> Option<String> {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}")?;
        let key = after[..end].trim();
        let value = match key {
            // BastionVault-native vocabulary.
            "username" | "identity.entity.name" => {
                if username.is_empty() {
                    return None;
                }
                username
            }
            "entity.id" | "identity.entity.id" => {
                if entity_id.is_empty() {
                    return None;
                }
                entity_id
            }
            "auth.mount" | "identity.entity.mount" => {
                if auth_mount.is_empty() {
                    return None;
                }
                auth_mount
            }
            _ => return None,
        };
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Some(out)
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch, used
/// as the suffix of history log keys so listing returns entries in
/// chronological order. Mirrors the resource/identity modules.
fn hist_seq() -> String {
    let n = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

#[maybe_async::maybe_async]
impl AuthHandler for PolicyStore {
    fn name(&self) -> String {
        "policy_store".to_string()
    }

    /// Handle authentication for a given request.
    /// This function checks the request path, performs capability checks, and updates authentication results.
    async fn post_auth(&self, req: &mut Request) -> Result<(), RvError> {
        let is_root_path = self.router.is_root_path(&req.path)?;

        if req.auth.is_none() && is_root_path {
            return Err(bv_error_string!("cannot access root path in unauthenticated request"));
        }

        let mut acl_result = ACLResults::default();

        if let Some(auth) = &req.auth {
            if auth.policies.is_empty() {
                return Ok(());
            }

            // Resolve the request target's resource-group membership once so
            // the (sync) ACL evaluator can enforce the `groups = [...]`
            // policy qualifier against it. Cheap lookup — one read against
            // the reverse member-index view. Absence of the subsystem, or a
            // non-resource path, leaves `asset_groups` empty (= the path
            // matches no groups, and any `groups`-gated rule is skipped).
            req.asset_groups = resolve_asset_groups(&self.core, &req.path).await;
            // Resolve the request target's owner entity_id for the
            // `scopes = ["owner"]` check. Same shape as asset_groups:
            // empty on any failure, which is fail-closed for
            // owner-scoped rules.
            req.asset_owner = resolve_asset_owner(&self.core, &req.path).await;
            // Resolve any active `SecretShare` capabilities the caller
            // has on this target so `scopes = ["shared"]` rules can be
            // evaluated synchronously downstream. Empty when the
            // caller has no entity_id, no share exists, or the share
            // has expired.
            req.target_shared_caps = resolve_target_shared_caps(&self.core, req).await;

            let acl = self.new_acl_for_request(&auth.policies, None, auth).await?;
            acl_result = acl.allow_operation(req, false)?;
        }

        // Stash the list-filter groups + scopes on the request so the
        // post-route pass can filter the response keys. See the
        // `Handler::post_route` impl below.
        req.list_filter_groups = acl_result.list_filter_groups.clone();
        req.list_filter_scopes = acl_result.list_filter_scopes.clone();

        if let Some(auth) = &mut req.auth {
            if is_root_path && !acl_result.root_privs && req.operation != Operation::Help {
                return Err(bv_error_string!("cannot access root path in unauthenticated request"));
            }

            let allowed = acl_result.allowed;

            auth.policy_results = Some(PolicyResults { allowed, granting_policies: acl_result.granting_policies });

            if !allowed {
                log::warn!(
                    "preflight capability check returned 403, please ensure client's policies grant access to path \
                     \"{}\"",
                    req.path
                );
                return Err(RvError::ErrPermissionDenied);
            }
        }

        Ok(())
    }
}

#[maybe_async::maybe_async]
impl Handler for PolicyStore {
    fn name(&self) -> String {
        "policy_store".to_string()
    }

    /// Post-route pass. Covers two asset-group integration concerns:
    ///
    /// 1. **List-filter.** If `req.list_filter_groups` is non-empty
    ///    (set by `post_auth` when the list was authorized only by a
    ///    `groups = [...]`-gated rule), restrict the response keys to
    ///    those whose resolved full path is a member of any listed
    ///    group. Respects both the resource-index (for `resources/`
    ///    paths) and the secret-index (for KV paths).
    ///
    /// 2. **KV-delete prune.** On a successful `Delete` of a KV path,
    ///    call `ResourceGroupStore::prune_secret` so the deleted
    ///    secret disappears from every asset group it was a member
    ///    of. Parallels the resource-delete hook in the resource
    ///    module. Failures are logged but never fail the delete —
    ///    `resource-group/reindex` is the recovery path.
    async fn post_route(
        &self,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        let rg_store = self.resource_group_store();
        let owner_store = self.owner_store();

        // --- Asset-group list filter ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::List && !req.list_filter_groups.is_empty() {
                if let Some(response) = resp.as_mut() {
                    filter_list_response(response, &req.path, &req.list_filter_groups, store).await;
                }
            }
        }

        // --- Ownership list filter ---
        // Narrows LIST response keys to entries the caller owns (and,
        // once sharing lands, entries shared with them). Operates
        // independently of the asset-group filter; a LIST granted by
        // both a `scopes=["owner"]` rule and a `groups=[...]` rule
        // applies both filters in sequence, which is the intended
        // intersection — each filter narrows further.
        if let Some(store) = owner_store.as_ref() {
            if req.operation == Operation::List && !req.list_filter_scopes.is_empty() {
                if let Some(response) = resp.as_mut() {
                    let caller_id = req
                        .auth
                        .as_ref()
                        .and_then(|a| a.metadata.get("entity_id"))
                        .cloned()
                        .unwrap_or_default();
                    let share_store = self.share_store();
                    filter_list_by_ownership(
                        response,
                        &req.path,
                        &req.list_filter_scopes,
                        &caller_id,
                        store,
                        share_store.as_ref(),
                    )
                    .await;
                }
            }
        }

        // --- Owner bookkeeping ---
        if let Some(store) = owner_store.as_ref() {
            // `caller_id` is the caller's `entity_id` when present,
            // otherwise `display_name` (so root-token writes stamp
            // `"root"` rather than orphan the record). This matches the
            // audit-actor fallback and keeps the Owner card on the GUI
            // useful for admin-created resources — an earlier version of
            // this hook skipped ownership capture whenever `entity_id`
            // was empty, which left every root-created resource
            // permanently "Unowned".
            //
            // ACL impact is zero: root bypasses policy, and for other
            // callers the comparison in `scope_passes` is entity_id vs
            // entity_id — a literal "root" owner cannot accidentally
            // grant owner-scope access because no other caller has
            // `entity_id = "root"` in their auth metadata.
            //
            // `audit_actor` (already defined below for share-cascade
            // revoke audit rows) computes the same value, so reuse it.
            let audit_actor = crate::modules::identity::caller_audit_actor(req);
            let caller_id = audit_actor.clone();

            match req.operation {
                Operation::Write => {
                    if looks_like_kv_path(&req.path) && !caller_id.is_empty() {
                        let _ = store.record_kv_owner_if_absent(&req.path, &caller_id).await;
                    }
                    if let Some(name) = resource_name_from_path(&req.path) {
                        // Only stamp ownership on the metadata create
                        // path (`resources/resources/<name>`), not on
                        // per-resource secret writes under
                        // `resources/secrets/<name>/...`.
                        let trimmed = req.path.trim_start_matches('/');
                        if trimmed.starts_with("resources/resources/") && !caller_id.is_empty() {
                            let _ = store
                                .record_resource_owner_if_absent(&name, &caller_id)
                                .await;
                        }
                    }
                    // File resources: stamp owner on the metadata
                    // path (`files/files/<id>`, i.e. a replace-by-id
                    // write). For the create path (`files/files`
                    // without id), the file engine stamps the owner
                    // inline — post_route cannot because the new id is
                    // only visible to the module that assigned it.
                    if let Some(id) = file_id_from_metadata_path(&req.path) {
                        if !caller_id.is_empty() {
                            let _ = store
                                .record_file_owner_if_absent(&id, &caller_id)
                                .await;
                        }
                    }
                }
                Operation::Delete => {
                    if looks_like_kv_path(&req.path) {
                        let _ = store.forget_kv_owner(&req.path).await;
                    }
                    if let Some(name) = resource_name_from_path(&req.path) {
                        let trimmed = req.path.trim_start_matches('/');
                        if trimmed.starts_with("resources/resources/") {
                            let _ = store.forget_resource_owner(&name).await;
                        }
                    }
                    if let Some(id) = file_id_from_metadata_path(&req.path) {
                        let _ = store.forget_file_owner(&id).await;
                    }
                    // Cascade-delete every SecretShare referencing this
                    // target so dangling share rows do not outlive the
                    // secret/resource. Failures are logged but never
                    // fail the delete — stale share records deny
                    // access anyway once `get_share` returns None.
                    //
                    // The audited variant stamps the caller's entity_id
                    // on each emitted cascade-revoke event so the
                    // Admin → Audit page attributes the action to the
                    // user that triggered the target delete.
                    if let Some(sshare) = self.share_store() {
                        if looks_like_kv_path(&req.path) {
                            if let Err(e) = sshare
                                .cascade_delete_target_audited(
                                    ShareTargetKind::KvSecret,
                                    &req.path,
                                    &audit_actor,
                                )
                                .await
                            {
                                log::warn!(
                                    "share cascade-delete failed for KV path '{}': {e}",
                                    req.path,
                                );
                            }
                        }
                        if let Some(name) = resource_name_from_path(&req.path) {
                            let trimmed = req.path.trim_start_matches('/');
                            if trimmed.starts_with("resources/resources/") {
                                if let Err(e) = sshare
                                    .cascade_delete_target_audited(
                                        ShareTargetKind::Resource,
                                        &name,
                                        &audit_actor,
                                    )
                                    .await
                                {
                                    log::warn!(
                                        "share cascade-delete failed for resource '{}': {e}",
                                        name,
                                    );
                                }
                            }
                        }
                        if let Some(id) = file_id_from_metadata_path(&req.path) {
                            if let Err(e) = sshare
                                .cascade_delete_target_audited(
                                    ShareTargetKind::File,
                                    &id,
                                    &audit_actor,
                                )
                                .await
                            {
                                log::warn!(
                                    "share cascade-delete failed for file '{}': {e}",
                                    id,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // --- KV-delete prune from asset-groups ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::Delete && looks_like_kv_path(&req.path) {
                if let Err(e) = store.prune_secret(&req.path).await {
                    log::warn!(
                        "resource-group prune failed for deleted KV secret '{}': {e}. \
                         Use the resource-group/reindex endpoint to clean up.",
                        req.path,
                    );
                }
            }
        }

        // --- File-delete prune from asset-groups ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::Delete {
                if let Some(id) = file_id_from_metadata_path(&req.path) {
                    if let Err(e) = store.prune_file(&id).await {
                        log::warn!(
                            "resource-group prune failed for deleted file '{}': {e}. \
                             Use the resource-group/reindex endpoint to clean up.",
                            id,
                        );
                    }
                }
            }
        }

        let _ = resp;
        Err(RvError::ErrHandlerDefault)
    }
}

impl PolicyStore {
    /// Upgrade the weak Core reference and fetch the resource-group
    /// store, if the subsystem is loaded. Returns `None` otherwise —
    /// callers treat that as "no asset-group integration this turn".
    fn resource_group_store(&self) -> Option<Arc<ResourceGroupStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager
            .get_module::<ResourceGroupModule>("resource-group")?;
        module.store()
    }

    /// Upgrade the weak Core reference and fetch the owner store from
    /// the identity module. Returns `None` when the subsystem is not
    /// loaded — callers treat that as "no per-user-scoping this turn".
    fn owner_store(&self) -> Option<Arc<OwnerStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager
            .get_module::<IdentityModule>("identity")?;
        module.owner_store()
    }

    /// Probe whether `auth` is permitted to perform `op` on `path`.
    ///
    /// Runs the same per-target resolution and ACL evaluation as
    /// `post_auth` — asset groups, owner record, and active shares
    /// are all consulted — but in a dry-run mode that doesn't mutate
    /// anything and doesn't care about side-effects. Intended for
    /// handler code that needs to preview an authorization decision
    /// against a *different* target than the one that triggered the
    /// current request (e.g., the asset-group read handler deciding
    /// whether to redact a member the caller can't see).
    ///
    /// Returns `Ok(false)` on any resolution error so a failure
    /// silently narrows access rather than leaking it.
    pub async fn can_operate(
        &self,
        auth: &crate::logical::Auth,
        path: &str,
        op: Operation,
    ) -> bool {
        if auth.policies.is_empty() {
            return false;
        }

        let asset_groups = resolve_asset_groups(&self.core, path).await;
        let asset_owner = resolve_asset_owner(&self.core, path).await;

        let mut req = Request::default();
        req.path = path.to_string();
        req.operation = op;
        req.auth = Some(auth.clone());
        req.asset_groups = asset_groups;
        req.asset_owner = asset_owner;
        req.target_shared_caps = resolve_target_shared_caps(&self.core, &req).await;

        let acl = match self
            .new_acl_for_request(&auth.policies, None, auth)
            .await
        {
            Ok(a) => a,
            Err(_) => return false,
        };
        // `check_only=false` is required — with `true`, `Permissions::check`
        // short-circuits without setting `allowed`, always returning
        // `allowed=false`. The full gate is cheap for a read probe.
        acl.allow_operation(&req, false).map(|r| r.allowed).unwrap_or(false)
    }

    /// Upgrade the weak Core reference and fetch the share store from
    /// the identity module. Returns `None` when the subsystem is not
    /// loaded.
    fn share_store(&self) -> Option<Arc<ShareStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager
            .get_module::<IdentityModule>("identity")?;
        module.share_store()
    }
}

/// Filter a list response's `keys` array down to entries that are
/// members of any asset-group in `filter_groups`. The full logical
/// path of each key is reconstructed by joining `list_path` with the
/// key; `ResourceGroupStore::groups_for_resource` /
/// `groups_for_secret` do the membership lookup. Unknown paths and
/// folder entries (trailing slash) are dropped.
async fn filter_list_response(
    response: &mut Response,
    list_path: &str,
    filter_groups: &[String],
    store: &Arc<ResourceGroupStore>,
) {
    let Some(data) = response.data.as_mut() else { return };
    let Some(keys_val) = data.get_mut("keys") else { return };
    let Some(keys_arr) = keys_val.as_array() else { return };

    let prefix = if list_path.ends_with('/') {
        list_path.to_string()
    } else {
        format!("{list_path}/")
    };

    let mut kept: Vec<Value> = Vec::with_capacity(keys_arr.len());
    for v in keys_arr.iter() {
        let Some(k) = v.as_str() else { continue };
        if k.ends_with('/') {
            // Folders don't have a single logical path to look up.
            // Drop them from filtered output to avoid exposing
            // subtree structure the caller shouldn't see via this
            // group grant.
            continue;
        }
        let full = format!("{prefix}{k}");
        let groups = resolve_groups_for_any(store, &full).await;
        if groups.iter().any(|g| filter_groups.iter().any(|f| f == g)) {
            kept.push(v.clone());
        }
    }

    *keys_val = Value::Array(kept);
}

/// Narrow a LIST response's `keys` array to entries that match any
/// active ownership scope:
///
/// - `owner`: each key's resolved owner matches the caller's
///   `entity_id`.
/// - `shared`: an explicit `SecretShare` grants the caller any
///   capability on the key. `SecretShare` presence alone is enough
///   for list inclusion — the shared `list` capability is not
///   separately required, matching how `list_shares_for_grantee`
///   surfaces "what is shared with me?".
///
/// Folder keys (trailing `/`) are dropped since they have no single
/// owner or share record. A key surviving *any* active scope is kept
/// (scopes OR together).
async fn filter_list_by_ownership(
    response: &mut Response,
    list_path: &str,
    filter_scopes: &[String],
    caller_entity_id: &str,
    store: &Arc<OwnerStore>,
    share_store: Option<&Arc<ShareStore>>,
) {
    let Some(data) = response.data.as_mut() else { return };
    let Some(keys_val) = data.get_mut("keys") else { return };
    let Some(keys_arr) = keys_val.as_array() else { return };

    let want_owner = filter_scopes.iter().any(|s| s == "owner");
    let want_shared = filter_scopes.iter().any(|s| s == "shared");

    let prefix = if list_path.ends_with('/') {
        list_path.to_string()
    } else {
        format!("{list_path}/")
    };

    let mut kept: Vec<Value> = Vec::with_capacity(keys_arr.len());
    for v in keys_arr.iter() {
        let Some(k) = v.as_str() else { continue };
        if k.ends_with('/') {
            continue;
        }
        let full = format!("{prefix}{k}");

        if caller_entity_id.is_empty() {
            continue;
        }

        let mut included = false;

        if want_owner {
            // Try both owner lookups: a key may be a KV secret or a
            // resource. Either match is sufficient.
            if let Ok(Some(rec)) = store.get_kv_owner(&full).await {
                if rec.entity_id == caller_entity_id {
                    included = true;
                }
            }
            if !included {
                if let Some(name) = resource_name_from_path(&full) {
                    if let Ok(Some(rec)) = store.get_resource_owner(&name).await {
                        if rec.entity_id == caller_entity_id {
                            included = true;
                        }
                    }
                }
            }
        }

        if !included && want_shared {
            if let Some(sstore) = share_store {
                if let Ok(caps) = sstore
                    .shared_capabilities(ShareTargetKind::KvSecret, &full, caller_entity_id)
                    .await
                {
                    if !caps.is_empty() {
                        included = true;
                    }
                }
                if !included {
                    if let Some(name) = resource_name_from_path(&full) {
                        if let Ok(caps) = sstore
                            .shared_capabilities(ShareTargetKind::Resource, &name, caller_entity_id)
                            .await
                        {
                            if !caps.is_empty() {
                                included = true;
                            }
                        }
                    }
                }
            }
        }

        if included {
            kept.push(v.clone());
        }
    }

    *keys_val = Value::Array(kept);
}

/// Look up asset-group membership for any target path — tries the
/// resource-name extraction first (for `resources/resources/<name>`
/// and `resources/secrets/<name>/...`), then falls back to the
/// secret-index (treating the path as a KV path). Mirrors
/// `resolve_asset_groups`.
async fn resolve_groups_for_any(store: &Arc<ResourceGroupStore>, path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(name) = resource_name_from_path(path) {
        if let Ok(groups) = store.groups_for_resource(&name).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }
    if looks_like_kv_path(path) {
        if let Ok(groups) = store.groups_for_secret(path).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod templating_tests {
    use super::*;

    #[test]
    fn test_substitute_path_happy_cases() {
        let got = substitute_path(
            "secret/data/users/{{username}}/*",
            "alice",
            "ent-123",
            "userpass/",
        );
        assert_eq!(got.as_deref(), Some("secret/data/users/alice/*"));

        let got = substitute_path(
            "kv/{{entity.id}}/inbox",
            "alice",
            "ent-123",
            "",
        );
        assert_eq!(got.as_deref(), Some("kv/ent-123/inbox"));

        let got = substitute_path(
            "{{auth.mount}}login",
            "alice",
            "ent-123",
            "userpass/",
        );
        assert_eq!(got.as_deref(), Some("userpass/login"));
    }

    #[test]
    fn test_substitute_path_fail_closed_on_unknown_placeholder() {
        // Unknown key — typo — must drop the rule, not widen access.
        assert_eq!(
            substitute_path("secret/{{uzername}}", "alice", "ent-123", "userpass/"),
            None
        );
    }

    #[test]
    fn test_substitute_path_fail_closed_on_missing_value() {
        // `{{username}}` but username is empty — drop.
        assert_eq!(
            substitute_path("secret/{{username}}/*", "", "ent-123", "userpass/"),
            None
        );
        // `{{entity.id}}` but entity_id empty — drop.
        assert_eq!(
            substitute_path("secret/{{entity.id}}", "alice", "", "userpass/"),
            None
        );
    }

    #[test]
    fn test_substitute_path_no_placeholders_is_identity() {
        assert_eq!(
            substitute_path("secret/foo/bar", "alice", "ent-123", "userpass/").as_deref(),
            Some("secret/foo/bar")
        );
    }

    // ── apply_templates wrapper ──────────────────────────────────────

    use crate::{
        logical::Auth,
        modules::policy::{Policy, PolicyPathRules, PolicyType},
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn policy_with_paths(paths: Vec<&str>) -> Arc<Policy> {
        let mut p = Policy::default();
        p.name = "test-templated".to_string();
        p.policy_type = PolicyType::Acl;
        p.templated = true;
        p.paths = paths
            .into_iter()
            .map(|path| {
                let mut rule = PolicyPathRules::default();
                rule.path = path.to_string();
                rule
            })
            .collect();
        Arc::new(p)
    }

    fn auth_with(
        username: Option<&str>,
        entity_id: Option<&str>,
        mount_path: Option<&str>,
        display_name: &str,
    ) -> Auth {
        let mut meta = HashMap::new();
        if let Some(u) = username {
            meta.insert("username".into(), u.into());
        }
        if let Some(e) = entity_id {
            meta.insert("entity_id".into(), e.into());
        }
        if let Some(m) = mount_path {
            meta.insert("mount_path".into(), m.into());
        }
        Auth {
            display_name: display_name.into(),
            metadata: meta,
            ..Auth::default()
        }
    }

    #[test]
    fn test_apply_templates_substitutes_in_all_paths() {
        let policy = policy_with_paths(vec![
            "secret/data/users/{{username}}/*",
            "kv/{{entity.id}}/inbox",
        ]);
        let auth = auth_with(Some("alice"), Some("ent-abc"), Some("userpass/"), "alice");
        let got = apply_templates(&policy, &auth).expect("policy must survive");
        let paths: Vec<&str> = got.paths.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["secret/data/users/alice/*", "kv/ent-abc/inbox"],
            "every templated path must be substituted with caller values"
        );
    }

    #[test]
    fn test_apply_templates_username_falls_back_to_display_name() {
        // No `username` metadata key, but display_name is set — apply_templates
        // must fall back so a FIDO2 or cert login with only display_name
        // still authorizes a `{{username}}` rule.
        let policy = policy_with_paths(vec!["secret/data/users/{{username}}/*"]);
        let auth = auth_with(None, Some("ent-abc"), Some("userpass/"), "bob");
        let got = apply_templates(&policy, &auth).expect("policy must survive");
        assert_eq!(got.paths[0].path, "secret/data/users/bob/*");
    }

    #[test]
    fn test_apply_templates_drops_individual_unresolved_rules() {
        // Two rules: one resolvable, one needs `{{auth.mount}}` which is
        // absent from metadata. The resolvable rule survives; the other
        // is dropped fail-closed, policy still contributes.
        let policy = policy_with_paths(vec![
            "secret/data/users/{{username}}/*",
            "{{auth.mount}}login",
        ]);
        let auth = auth_with(Some("alice"), Some("ent-abc"), None, "alice");
        let got = apply_templates(&policy, &auth).expect("at least one rule survives");
        let paths: Vec<&str> = got.paths.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["secret/data/users/alice/*"]);
    }

    #[test]
    fn test_apply_templates_returns_none_when_all_rules_drop() {
        // Every rule references something the auth doesn't have. Fail
        // closed: policy contributes no authorization.
        let policy = policy_with_paths(vec![
            "{{auth.mount}}login",
            "secret/{{entity.id}}",
        ]);
        let auth = auth_with(Some("alice"), None, None, "alice");
        assert!(
            apply_templates(&policy, &auth).is_none(),
            "all-rules-dropped must return None so the policy grants nothing"
        );
    }

    #[test]
    fn test_apply_templates_preserves_rule_capabilities() {
        // Rules carry more than just `path` — capabilities / scopes /
        // groups must survive the substitution.
        let mut policy = Policy::default();
        policy.name = "keep-fields".into();
        policy.templated = true;
        let mut rule = PolicyPathRules::default();
        rule.path = "secret/data/users/{{username}}/*".into();
        rule.capabilities = vec![
            crate::modules::policy::policy::Capability::Read,
            crate::modules::policy::policy::Capability::Update,
        ];
        rule.scopes = vec!["owner".into(), "shared".into()];
        policy.paths = vec![rule];

        let auth = auth_with(Some("carol"), Some("ent-c"), Some("userpass/"), "carol");
        let got = apply_templates(&Arc::new(policy), &auth).expect("survives");
        let r = &got.paths[0];
        assert_eq!(r.path, "secret/data/users/carol/*");
        assert_eq!(r.capabilities.len(), 2);
        assert_eq!(r.scopes, vec!["owner", "shared"]);
    }
}

#[cfg(test)]
mod mod_policy_store_tests {
    use super::{super::policy::Capability, *};
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_store_crud() {
        let (_bvault, core, _root_token) = new_unseal_test_bastion_vault("test_policy_store_crud").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        let policy1_name = "test-policy1";
        let policy1_hcl = r#"
        path "secret/data/test1" {
            capabilities = ["read", "list"]
        }"#;

        let policy2_name = "test-policy2";
        let policy2_hcl = r#"
        path "secret/data/test2" {
            capabilities = ["create", "delete"]
        }"#;

        let mut policy1 = Policy::from_str(policy1_hcl).unwrap();
        policy1.name = policy1_name.to_string();

        let mut policy2 = Policy::from_str(policy2_hcl).unwrap();
        policy2.name = policy2_name.to_string();

        // Set the policy
        let result = policy_store.set_policy(policy1).await;
        assert!(result.is_ok());
        let result = policy_store.set_policy(policy2).await;
        assert!(result.is_ok());

        // Verify the policy is set
        let retrieved_policy = policy_store.get_policy(policy1_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_some());
        let retrieved_policy = retrieved_policy.unwrap();
        assert_eq!(retrieved_policy.name, policy1_name);
        assert_eq!(retrieved_policy.raw, policy1_hcl);
        let retrieved_policy = policy_store.get_policy(policy2_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_some());
        let retrieved_policy = retrieved_policy.unwrap();
        assert_eq!(retrieved_policy.name, policy2_name);
        assert_eq!(retrieved_policy.raw, policy2_hcl);

        // List policies
        let policies = policy_store.list_policy(PolicyType::Acl).await.unwrap();
        assert!(policies.contains(&policy1_name.to_string()));
        assert!(policies.contains(&policy2_name.to_string()));

        // Delete the policy
        let result = policy_store.delete_policy(policy1_name, PolicyType::Acl).await;
        assert!(result.is_ok());
        let retrieved_policy = policy_store.get_policy(policy1_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_none());

        // List policies again
        let policies = policy_store.list_policy(PolicyType::Acl).await.unwrap();
        assert!(!policies.contains(&policy1_name.to_string()));
        assert!(policies.contains(&policy2_name.to_string()));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_load_default() {
        let (_bvault, core, _root_token) = new_unseal_test_bastion_vault("test_policy_load_default").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        // Load default ACL policies
        policy_store.load_default_acl_policy().await.unwrap();

        // Verify the default policies are loaded
        let default_policy = policy_store.get_policy("default", PolicyType::Acl).await.unwrap();
        assert!(default_policy.is_some());

        let response_wrapping_policy = policy_store.get_policy("response-wrapping", PolicyType::Acl).await.unwrap();
        assert!(response_wrapping_policy.is_some());

        let control_group_policy = policy_store.get_policy("control-group", PolicyType::Acl).await.unwrap();
        assert!(control_group_policy.is_some());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_root() {
        let (_, core, _) = new_unseal_test_bastion_vault("test_policy_root").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        // Get should return a special policy
        let root_policy = policy_store.get_policy("root", PolicyType::Token).await.unwrap();
        assert!(root_policy.is_some());
        let root_policy = root_policy.unwrap();
        assert_eq!(root_policy.name, "root");

        // Set should fail
        let result = policy_store.set_policy(Policy { name: "root".into(), ..Default::default() }).await;
        assert!(result.is_err());

        // Delete should fail
        let result = policy_store.delete_policy("root", PolicyType::Acl).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_new_acl() {
        let (_, core, _) = new_unseal_test_bastion_vault("test_policy_new_acl").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        let policy1_name = "test-policy1";
        let policy1_hcl = r#"
        path "secret/data/test1/*" {
            capabilities = ["read", "list"]
        }"#;

        let policy2_name = "test-policy2";
        let policy2_hcl = r#"
        path "secret/data/test2" {
            capabilities = ["create", "delete"]
        }"#;

        let mut policy1 = Policy::from_str(policy1_hcl).unwrap();
        policy1.name = policy1_name.to_string();

        let mut policy2 = Policy::from_str(policy2_hcl).unwrap();
        policy2.name = policy2_name.to_string();

        // Set the policy
        policy_store.set_policy(policy1).await.unwrap();
        policy_store.set_policy(policy2).await.unwrap();

        // Load default ACL policies
        policy_store.load_default_acl_policy().await.unwrap();

        // Create a new ACL
        let acl = policy_store.new_acl(&vec![policy1_name.to_string(), policy2_name.to_string()], None).await.unwrap();

        // Verify the ACL contains the policies
        assert_eq!(
            acl.prefix_rules.get_ancestor_value("secret/data/test1/kk/vv").unwrap().capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits()
        );
        assert_eq!(
            acl.exact_rules.get("secret/data/test2").unwrap().capabilities_bitmap,
            Capability::Create.to_bits() | Capability::Delete.to_bits()
        );
    }
}
