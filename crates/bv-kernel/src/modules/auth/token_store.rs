//! This module implements a token storage system for managing token creation, lookup,
//! revocation, and renewal. The system supports various operations and provides the
//! logical backend interface through the `TokenStore` struct. Additionally, it implements
//! the `Handler` trait to provide authentication and authorization functionality at
//! different stages of request handling, such as pre-routing and post-routing.
#[cfg(not(feature = "sync_handler"))]
use std::future::Future;
#[cfg(not(feature = "sync_handler"))]
use std::pin::Pin;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use better_default::Default;
use humantime::parse_duration;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    expiration::{ExpirationManager, DEFAULT_LEASE_DURATION_SECS, MAX_LEASE_DURATION_SECS},
    AUTH_ROUTER_PREFIX,
};
use crate::kernel_api::VaultCtx;
use crate::{
    cache::TokenCache,
    context::Context,
    errors::RvError,
    handler::{AuthHandler, HandlePhase, Handler},
    logical::{
        is_reserved_token_meta_key, lease::calculate_ttl, Auth, Backend, Field, FieldType, Lease, LogicalBackend,
        Operation, Path, PathOperation, Request, Response, SPIFFE_ID_META,
    },
    modules::policy::policy_store::NON_ASSIGNABLE_POLICIES,
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    router::Router,
    bv_error_response, bv_error_string,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::{
        cidr, default_system_time, deserialize_duration, deserialize_system_time, generate_uuid, is_str_subset,
        policy::sanitize_policies,
        serialize_duration, serialize_system_time, sha1,
        token_util::{DEFAULT_LEASE_TTL, MAX_LEASE_TTL},
    },
};

const TOKEN_LOOKUP_PREFIX: &str = "id/";
const TOKEN_PARENT_PREFIX: &str = "parent/";
const TOKEN_SALT_LOCATION: &str = "salt";
const TOKEN_SUB_PATH: &str = "token/";

static AUTH_TOKEN_HELP: &str = r#"
TODO
"#;

lazy_static! {
    static ref DISPLAY_NAME_SANITIZE: Regex = Regex::new(r"[^a-zA-Z0-9-]").unwrap();
}

// The reserved-metadata list itself lives in `bv_logical::auth` — beside the
// key constants it is built from, and where the OIDC and SAML backends (which
// project an IdP-controlled claim onto an operator-chosen metadata key, the
// second write point for the same set) can also see it. See
// [`RESERVED_TOKEN_META_KEYS`] for the rule and the reasoning; the enforcement
// for *this* write point is `reject_reserved_meta` below.

/// Metadata key prefixes a child token **inherits** from its parent on
/// `auth/token/create`.
///
/// Refusing a forged key ([`RESERVED_TOKEN_META_KEYS`]) stops a child from
/// *gaining* a backend-owned key. It does nothing about the opposite escape:
/// `handle_create` builds the child's `meta` from the request body, so a key
/// the parent carries is simply *absent* on the child. For a key that names an
/// identity that is harmless. For a key that carries a **restriction** it is a
/// bypass — the restriction is escapable by one `auth/token/create`, which is
/// exactly the reasoning already recorded for `bound_cidrs` a few lines into
/// the [`TokenEntry`] literal below.
///
/// `approle_env_` is such a restriction: AppRole stamps `approle_env_scoped` /
/// `_secret` / `_machine` on an environment-scoped login and
/// `bv-engine-kv`'s `enforce_env_scope` refuses any KV v2 data operation
/// outside the allowed environments — *and passes through unchanged when
/// `approle_env_scoped` is absent*. A scoped AppID with a grant on
/// `auth/token/create` therefore minted itself a child that read every
/// environment, including the base (non-env) secrets a scoped token is
/// explicitly barred from. The prefix (rather than the three key names) is
/// deliberate, for the same reason it is a prefix in
/// `bv_logical::auth::RESERVED_TOKEN_META_PREFIXES`: a fourth `approle_env_*`
/// key added later is inherited on the day it is written, not the day someone
/// remembers this list.
///
/// **Why this is not simply "inherit everything in
/// [`RESERVED_TOKEN_META_KEYS`]".** That set is "backend-owned", which is the
/// right property to *refuse* and the wrong one to *inherit*, because most of
/// it names an identity rather than a restriction, and inheriting an identity
/// **widens**:
///
/// * `spiffe_id` is the whole of what "machine-bound" means to
///   [`machine_identity_satisfied`], so inheriting it would make every child of
///   a machine-bound token pass the server-wide `require_machine_identity`
///   gate with no attestation of its own — the gate would be satisfied by
///   descent instead of by proof.
/// * `mount_path` = `"ferrogate/"` is what `bv-auth-approle`'s login checks
///   before accepting a token as a `machine_token`; inheriting it would make
///   any child of a FerroGate token replayable as a machine credential.
/// * `username` / `entity_id` / `role_name` drive policy templating, the
///   namespace assignment lookup in
///   `namespace::token_binding::assignment_principal`, and the principal
///   columns of both audit trails. Inheriting them would attribute the child's
///   actions to the parent's principal and hand it the parent's
///   operator-authored namespace grants.
///
/// So the rule for *this* set is narrower and stated as a question: **does the
/// key's presence take access away?** If yes, inherit it — dropping it is a
/// bypass. If it grants, identifies or attributes, do not — inheriting it is
/// the bypass. Fail closed in both directions.
///
/// The namespace binding (`namespace_path`, `child_visible`) is the other
/// restriction on a token's metadata and is *not* handled here: it is written
/// explicitly further down `handle_create`, from the request header, and is
/// clamped to the parent's binding there.
///
/// Unlike the reserved list, this one stays in `bv-kernel`: the reserved list
/// has two write points (this path, and the OIDC/SAML claim projection) and
/// moved to `bv-logical` to be visible to both. Inheritance has exactly one
/// write point -- `handle_create` -- so putting it in the contract crate would
/// advertise a rule no one else can apply.
const INHERITED_TOKEN_META_PREFIXES: &[&str] = &["approle_env_"];

/// Copy the restriction-bearing backend-owned keys of `parent_meta` onto a
/// child token's metadata map. See [`INHERITED_TOKEN_META_PREFIXES`].
///
/// Overwrites rather than skipping an existing entry. `reject_reserved_meta`
/// has already refused every one of these keys in a caller-supplied `meta`, so
/// there is nothing to overwrite today; overwriting is what keeps that true if
/// the two lists ever diverge.
fn inherit_restriction_meta(parent_meta: &HashMap<String, String>, child_meta: &mut HashMap<String, String>) {
    for (key, value) in parent_meta {
        if INHERITED_TOKEN_META_PREFIXES.iter().any(|p| key.starts_with(p)) {
            child_meta.insert(key.clone(), value.clone());
        }
    }
}

/// Reject any backend-owned key in a caller-supplied `auth/token/create`
/// `meta` map.
///
/// Names *every* offending key, sorted, so an operator hitting this with a
/// legitimate integration sees the whole list in one round trip and the same
/// body always produces the same message — `meta` is a `HashMap`, so reporting
/// the first key encountered would name an arbitrary one of several. The
/// values are not logged: a caller controls them, and these keys name
/// principals.
fn reject_reserved_meta(meta: &HashMap<String, String>, display_name: &str) -> Result<(), RvError> {
    let mut offenders: Vec<&str> = meta
        .keys()
        .map(String::as_str)
        .filter(|key| is_reserved_token_meta_key(key))
        .collect();
    if offenders.is_empty() {
        return Ok(());
    }
    offenders.sort_unstable();

    let keys = offenders.join("`, `");
    log::warn!(
        target: "security",
        "token create refused: reserved metadata key(s) `{keys}` may only be set by an auth backend \
         (parent display_name={display_name})"
    );
    Err(bv_error_response!(&format!(
        "meta key(s) `{keys}` are reserved: they are set by the auth backend that authenticated the \
         principal and may not be supplied on token create"
    )))
}

#[derive(Serialize, Deserialize)]
struct TokenReqData {
    #[serde(default)]
    id: String,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    meta: HashMap<String, String>,
    #[serde(default)]
    no_parent: bool,
    #[serde(default)]
    lease: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    num_uses: u32,
    #[serde(default)]
    renewable: bool,
    /// Multi-tenancy: make this token usable in descendant namespaces of the
    /// namespace it is issued in. Opt-in, immutable after create.
    #[serde(default)]
    child_visible: bool,
    #[serde(default, deserialize_with = "deserialize_duration")]
    period: Duration,
    #[serde(default, deserialize_with = "deserialize_duration")]
    explicit_max_ttl: Duration,
}

/// Data structure representing a stored token entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenEntry {
    #[default(generate_uuid())]
    pub id: String,
    pub parent: String,
    pub policies: Vec<String>,
    pub path: String,
    pub meta: HashMap<String, String>,
    pub display_name: String,
    pub num_uses: u32,
    pub ttl: u64,
    #[default(SystemTime::now())]
    #[serde(
        default = "default_system_time",
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub creation_time: SystemTime,
    #[serde(default, serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub period: Duration,
    #[serde(default, serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub explicit_max_ttl: Duration,
    /// The set of CIDR blocks this token may be used from, in the canonical
    /// string form `SockAddrMarshaler` serializes to. Empty means
    /// unrestricted.
    ///
    /// Stamped at issuance from the auth backend's `token_bound_cidrs` (via
    /// [`Auth::bound_cidrs`]) and enforced by
    /// [`TokenStore::check_token`] against the request's client IP.
    ///
    /// `#[serde(default)]` is load-bearing for upgrades: a token entry
    /// persisted before this field existed deserializes to an empty list and
    /// stays unrestricted, so enabling enforcement cannot retroactively lock
    /// out a token that is already in circulation. Only tokens minted after
    /// the upgrade carry a binding.
    #[serde(default)]
    pub bound_cidrs: Vec<String>,
    /// This token is exempt from the server-wide FerroGate
    /// `require_machine_identity` gate (see [`TokenStore::pre_route`]).
    ///
    /// Stamped at issuance from [`Auth::machine_identity_exempt`], which
    /// only an auth backend that authenticated the principal *without*
    /// machine attestation sets -- today AppRole's per-role
    /// `bypass_machine_binding`. Deliberately not a metadata key: the
    /// `auth/token/create` body's `meta` map is copied onto the new token, so a
    /// metadata-keyed exemption would be forgeable by any holder of a grant on
    /// that path. [`RESERVED_TOKEN_META_KEYS`] now refuses that spelling too,
    /// but the typed field is what makes the exemption unforgeable by
    /// construction rather than by a check someone has to remember to keep.
    ///
    /// `#[serde(default)]` means every token persisted before this field
    /// existed reads back as *not* exempt, i.e. the gate keeps applying to
    /// it. Failing closed is the right direction here: the worst case is a
    /// bypassed AppID having to log in again to pick up the exemption.
    #[serde(default)]
    pub machine_identity_exempt: bool,
}

/// Does this token satisfy the server-wide FerroGate machine-identity
/// requirement?
///
/// The single predicate behind the `require_machine_identity` gate in
/// [`TokenStore::pre_route`]. `SystemModule`'s denial-audit classifier
/// re-evaluates it to label a 403 `reason=machine-identity`, so it lives here
/// as one function rather than two copies that can drift.
///
/// Three ways to satisfy it:
///
/// * **Root.** Keeps the bootstrap/approval chain and break-glass admin
///   working while the gate is on.
/// * **Machine-bound.** The token carries a non-empty `spiffe_id` metadata
///   value. Only an auth backend that verified a machine attestation emits it
///   -- the FerroGate login handler, and AppRole on a machine-bound login --
///   and [`RESERVED_TOKEN_META_KEYS`] is what keeps a caller on
///   `auth/token/create` from writing it directly. The emptiness check is not
///   redundant: `contains_key` alone accepted `"spiffe_id": ""`, which
///   [`bv_logical::split_principal`] then audits as *not* machine-bound, so the
///   gate and the audit trail disagreed about the same token.
/// * **Exempt.** [`Auth::machine_identity_exempt`], set by an auth backend that
///   authenticated this principal without machine attestation on purpose --
///   today AppRole's per-role `bypass_machine_binding`. Without this arm the
///   per-AppID bypass was decorative on any server with the gate on: the login
///   succeeded and then every request the token made was refused here.
pub fn machine_identity_satisfied(auth: &Auth) -> bool {
    auth.policies.iter().any(|p| p == "root")
        || auth.metadata.get(SPIFFE_ID_META).is_some_and(|id| !id.is_empty())
        || auth.machine_identity_exempt
}

/// Manages the storage and handling of tokens.
pub struct TokenStore {
    pub self_ptr: Weak<Self>,
    pub router: Arc<Router>,
    pub view: Option<Arc<dyn Storage + Send + Sync>>,
    pub salt: String,
    pub expiration: Arc<ExpirationManager>,
    pub auth_handlers: ArcSwap<Vec<Arc<dyn AuthHandler>>>,
    /// Optional TTL-scoped cache of salted token entries. `None` when the
    /// operator has set `cache.token_cache_ttl_secs = 0` (the cache is
    /// off). Values are zeroized on drop and the raw bearer-token string
    /// is never stored — the key is the same non-reversible `salt_id`
    /// already used as the storage key.
    pub token_cache: Option<Arc<TokenCache>>,
    /// Shared mirror of [`crate::core::Core::require_machine_identity`]. When
    /// `true`, `pre_route` rejects any authenticated request whose token is not
    /// FerroGate machine-bound (or root). Cloned from `Core` at construction so
    /// the hot path reads an atomic, never storage.
    pub require_machine_identity: Arc<AtomicBool>,
    /// Root system view, captured at construction. Used by `revoke-self`
    /// to append a logout event to the login-audit trail (the token
    /// store holds no `Core` reference). `None` only if built sealed.
    pub system_view: Option<Arc<BarrierView>>,
}

#[maybe_async::maybe_async]
impl TokenStore {
    /// Wraps the `TokenStore` instance in an `Arc` and sets its weak pointer reference.
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

    /// Creates a new `TokenStore` and initializes it with the necessary components.
    pub async fn new(core: &dyn VaultCtx, expiration: Arc<ExpirationManager>) -> Result<TokenStore, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let view = system_view.new_sub_view(TOKEN_SUB_PATH);
        let salt = view.get(TOKEN_SALT_LOCATION).await?;

        let token_cache = TokenCache::new(
            core.cache_config().token_cache_size,
            core.cache_config().token_cache_ttl_secs,
        )?
        .map(Arc::new);

        let mut token_store = TokenStore {
            self_ptr: Weak::new(),
            router: core.router().clone(),
            view: None,
            salt: String::new(),
            auth_handlers: ArcSwap::new(core.auth_handlers()),
            expiration,
            token_cache,
            require_machine_identity: core.require_machine_identity(),
            system_view: Some(system_view.clone()),
        };

        if salt.is_some() {
            token_store.salt = String::from_utf8_lossy(&salt.unwrap().value).to_string();
        }

        if token_store.salt.is_empty() {
            token_store.salt = generate_uuid();
            let raw =
                StorageEntry { key: TOKEN_SALT_LOCATION.to_string(), value: token_store.salt.as_bytes().to_vec() };
            view.put(&raw).await?;
        }

        token_store.view = Some(Arc::new(view));

        Ok(token_store)
    }

    /// Creates a new logical backend for token operations.
    pub fn new_backend(&self) -> LogicalBackend {
        let ts_inner_arc1 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc2 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc3 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc4 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc5 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc6 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc7 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc8 = self.self_ptr.upgrade().unwrap().clone();
        let ts_inner_arc9 = self.self_ptr.upgrade().unwrap().clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "create*",
                    fields: {
                        "num_uses": {
                            field_type: FieldType::Int,
                            description: "Max number of uses for this token"
                        },
                        "period": {
                            field_type: FieldType::Str,
                            description: "Renew period"
                        },
                        "ttl": {
                            field_type: FieldType::DurationSecond,
                            description: "Time to live for this token"
                        },
                        "renewable": {
                            field_type: FieldType::Bool,
                            default: true,
                            description: "Allow token to be renewed past its initial TTL up to system/mount maximum TTL"
                        },
                        "policies": {
                            field_type: FieldType::Array,
                            description: "List of policies for the token"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc1.handle_create}
                    ],
                    help: "The token create path is used to create new tokens."
                },
                {
                    pattern: "lookup/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to lookup"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: ts_inner_arc2.handle_lookup}
                    ],
                    help: "This endpoint will lookup a token and its properties."
                },
                {
                    pattern: "lookup-self$",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to lookup"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: ts_inner_arc3.handle_lookup_self}
                    ],
                    help: "This endpoint will lookup a token and its properties."
                },
                {
                    pattern: "revoke-self$",
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc8.handle_revoke_self}
                    ],
                    help: "This endpoint revokes the calling token and its child tokens (logout)."
                },
                {
                    pattern: "audit-login$",
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc9.handle_audit_login}
                    ],
                    help: "This endpoint records a `login` event for the calling token (GUI token sign-in)."
                },
                {
                    pattern: "revoke/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to revoke"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc4.handle_revoke_tree}
                    ],
                    help: "This endpoint will delete the token and all of its child tokens."
                },
                {
                    pattern: "revoke-orphan/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to revoke (request body)"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc5.handle_revoke_orphan}
                    ],
                    help: "This endpoint will delete the token and orphan its child tokens."
                },
                {
                    pattern: "renew/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to renew (request body)"
                        },
                        "increment": {
                            field_type: FieldType::Int,
                            description: "The desired increment in seconds to the token expiration"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc6.handle_renew}
                    ],
                    help: "This endpoint will renew the token and prevent expiration."
                }
            ],
            auth_renew_handler: ts_inner_arc7.auth_renew,
            root_paths: ["revoke-orphan/*"],
            help: AUTH_TOKEN_HELP,
        });

        backend
    }

    /// Drop every cached token entry and zeroize the held payloads.
    /// Called by `Core::flush_caches` on seal and by the
    /// `sys/cache/flush` admin endpoint. No-op when the token cache is
    /// disabled.
    pub fn flush_cache(&self) {
        if let Some(cache) = self.token_cache.as_ref() {
            cache.clear();
        }
    }

    /// Returns a salted hash of a token ID.
    pub fn salt_id(&self, id: &str) -> String {
        let salted_id = format!("{}{}", self.salt, id);
        sha1(salted_id.as_bytes())
    }

    /// Generates a root token with 'root' policy.
    pub async fn root_token(&self) -> Result<TokenEntry, RvError> {
        let mut te = TokenEntry {
            policies: vec!["root".to_string()],
            path: "auth/token/root".to_string(),
            display_name: "root".to_string(),
            ..TokenEntry::default()
        };

        self.create(&mut te).await?;

        Ok(te)
    }

    /// Creates a token entry in the storage.
    pub async fn create(&self, entry: &mut TokenEntry) -> Result<(), RvError> {
        let Some(view) = self.view.as_ref() else {
            return Err(RvError::ErrModuleNotInit);
        };

        if entry.id.is_empty() {
            entry.id = generate_uuid();
        }

        let salted_id = self.salt_id(&entry.id);

        let value = serde_json::to_string(&entry)?;

        if !entry.parent.is_empty() {
            let parent = self.lookup(&entry.parent).await?;
            if parent.is_none() {
                return Err(RvError::ErrAuthTokenNotFound);
            }

            let path = format!("{}{}/{}", TOKEN_PARENT_PREFIX, self.salt_id(&entry.parent), salted_id);
            let entry = StorageEntry { key: path, ..StorageEntry::default() };

            view.put(&entry).await?;
        }

        view.put(&StorageEntry { key: format!("{TOKEN_LOOKUP_PREFIX}{salted_id}"), value: value.as_bytes().to_vec() })
            .await?;

        // Invalidate any stale cache entry; the next lookup repopulates
        // from storage. Cheaper than speculatively caching on create, and
        // avoids caching entries that the caller may still mutate before
        // first use.
        if let Some(cache) = self.token_cache.as_ref() {
            cache.invalidate(&salted_id);
        }

        Ok(())
    }

    /// Uses the token and decrements its use count.
    pub async fn use_token(&self, entry: &mut TokenEntry) -> Result<(), RvError> {
        let Some(view) = self.view.as_ref() else {
            return Err(RvError::ErrModuleNotInit);
        };

        if entry.num_uses == 0 {
            return Ok(());
        }

        entry.num_uses -= 1;

        if entry.num_uses == 0 {
            return self.revoke(&entry.id).await;
        }

        let salted_id = self.salt_id(&entry.id);
        let value = serde_json::to_string(&entry)?;

        let path = format!("{TOKEN_LOOKUP_PREFIX}{salted_id}");
        let storage_entry = StorageEntry { key: path, value: value.as_bytes().to_vec() };

        view.put(&storage_entry).await?;

        // `num_uses` changed on disk; drop the cached copy so the next
        // lookup sees the decremented count.
        if let Some(cache) = self.token_cache.as_ref() {
            cache.invalidate(&salted_id);
        }

        Ok(())
    }

    /// Checks the validity of a token and returns the associated authentication data.
    ///
    /// `client_ip` is the bare source address the token is being presented
    /// from — [`bv_logical::Connection::client_ip`], never `peer_addr`
    /// verbatim. It is what the token's [`TokenEntry::bound_cidrs`] are
    /// evaluated against. Pass `""` only when there genuinely is no
    /// connection to attribute the request to; a token that carries a
    /// source-address restriction is then refused, because an unknown
    /// address cannot be shown to satisfy the rule.
    ///
    /// The restriction is enforced here rather than in `pre_route` on
    /// purpose: this is the one function every authenticated path resolves a
    /// token through, including the `sys/internal/ui/*` and `/metrics`
    /// callers that build an ACL directly instead of going through
    /// `Core::handle_request`. Enforcing it a layer up would leave those
    /// paths unbound.
    pub async fn check_token(&self, path: &str, token: &str, client_ip: &str) -> Result<Option<Auth>, RvError> {
        if token.is_empty() {
            return Err(RvError::ErrRequestClientTokenMissing);
        }

        log::debug!("check token: {token}");
        let te = self.lookup(token).await?;
        if te.is_none() {
            return Err(RvError::ErrPermissionDenied);
        }

        let mut entry = te.unwrap();

        // Source-address binding, before `use_token`: a refused request must
        // not burn one of a use-limited token's uses.
        if !entry.bound_cidrs.is_empty() && !cidr::remote_addr_in_bound_cidrs(client_ip, &entry.bound_cidrs) {
            log::warn!(
                target: "security",
                "request denied: token is bound to {:?} but was presented from {} (path={}, display_name={})",
                entry.bound_cidrs,
                if client_ip.is_empty() { "an unknown address" } else { client_ip },
                path,
                entry.display_name
            );
            return Err(RvError::ErrPermissionDenied);
        }

        self.use_token(&mut entry).await?;

        let mut auth = Auth {
            client_token: token.to_string(),
            display_name: entry.display_name,
            token_policies: entry.policies.clone(),
            policies: entry.policies.clone(),
            metadata: entry.meta,
            bound_cidrs: entry.bound_cidrs,
            machine_identity_exempt: entry.machine_identity_exempt,
            ..Auth::default()
        };

        sanitize_policies(&mut auth.policies, false);

        Ok(Some(auth))
    }

    /// Looks up the token entry with the given ID.
    pub async fn lookup(&self, id: &str) -> Result<Option<TokenEntry>, RvError> {
        if id.is_empty() {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.lookup_salted(self.salt_id(id).as_str()).await
    }

    pub async fn lookup_salted(&self, salted_id: &str) -> Result<Option<TokenEntry>, RvError> {
        let Some(view) = self.view.as_ref() else {
            return Err(RvError::ErrModuleNotInit);
        };

        if let Some(cache) = self.token_cache.as_ref() {
            if let Some(entry) = cache.lookup(salted_id) {
                return Ok(Some(entry));
            }
        }

        let path = format!("{TOKEN_LOOKUP_PREFIX}{salted_id}");
        let raw = view.get(&path).await?;
        if raw.is_none() {
            return Ok(None);
        }

        let entry: TokenEntry = serde_json::from_slice(raw.unwrap().value.as_slice())?;

        if let Some(cache) = self.token_cache.as_ref() {
            cache.insert(salted_id, &entry);
        }

        Ok(Some(entry))
    }

    pub async fn revoke(&self, id: &str) -> Result<(), RvError> {
        if id.is_empty() {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.revoke_salted(self.salt_id(id).as_str()).await
    }

    pub async fn revoke_salted(&self, salted_id: &str) -> Result<(), RvError> {
        let Some(view) = self.view.as_ref() else {
            return Err(RvError::ErrModuleNotInit);
        };

        // Evict up front so the `lookup_salted` below doesn't repopulate
        // the cache with an entry we are about to delete, and so a racing
        // lookup on another task can't observe the about-to-be-gone
        // entry as live after this returns.
        if let Some(cache) = self.token_cache.as_ref() {
            cache.invalidate(salted_id);
        }

        let entry = self.lookup_salted(salted_id).await?;

        let path = format!("{TOKEN_LOOKUP_PREFIX}{salted_id}");

        view.delete(&path).await?;

        if let Some(cache) = self.token_cache.as_ref() {
            cache.invalidate(salted_id);
        }

        if entry.is_some() {
            let entry = entry.unwrap();
            if entry.parent.as_str() != "" {
                let path = format!("{}{}/{}", TOKEN_PARENT_PREFIX, self.salt_id(&entry.parent), salted_id);
                view.delete(&path).await?;
            }
            //Revoke all secrets under this token
            self.expiration.revoke_by_token(&entry).await?;
        }

        Ok(())
    }

    /// Revokes the token with the given ID and all its child tokens.
    ///
    /// # Arguments
    /// - id: The ID of the token to revoke.
    ///
    /// # Returns
    /// - Result<(), RvError>: Ok(()) if successful, or an error if not.
    pub async fn revoke_tree(&self, id: &str) -> Result<(), RvError> {
        if id.is_empty() {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.revoke_tree_salted(self.salt_id(id).as_str()).await
    }

    #[cfg(not(feature = "sync_handler"))]
    pub fn revoke_tree_salted(
        &self,
        salted_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RvError>> + Send + '_>> {
        let self_ref = self;
        let salted_id = salted_id.to_owned();

        Box::pin(async move {
            let view = self_ref.view.as_ref().ok_or(RvError::ErrModuleNotInit)?;
            let path = format!("{TOKEN_PARENT_PREFIX}{}", &salted_id);
            let children = view.list(&path).await?;

            for child in children {
                self_ref.revoke_tree_salted(&child).await?;
            }

            self_ref.revoke_salted(&salted_id).await?;

            Ok(())
        })
    }

    #[cfg(feature = "sync_handler")]
    pub fn revoke_tree_salted(&self, salted_id: &str) -> Result<(), RvError> {
        let Some(view) = self.view.as_ref() else {
            return Err(RvError::ErrModuleNotInit);
        };

        let path = format!("{TOKEN_PARENT_PREFIX}{salted_id}/");

        let children = view.list(&path)?;
        for child in children.iter() {
            self.revoke_tree_salted(child)?;
        }

        self.revoke_salted(salted_id)
    }

    pub async fn handle_create(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let parent = self.lookup(&req.client_token).await?;
        if parent.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let parent = parent.unwrap();
        if parent.num_uses > 0 {
            return Err(RvError::ErrRequestInvalid);
        }

        let is_root = parent.policies.iter().any(|s| s.as_str() == "root");

        let mut data: TokenReqData = serde_json::from_value(Value::Object(req.body.as_ref().unwrap().clone()))?;

        // Before the map is copied onto the new entry: the caller may annotate
        // a token, but may not write the backend-owned keys the kernel and the
        // engines read as authorization input.
        reject_reserved_meta(&data.meta, &parent.display_name)?;

        // Caller-supplied annotations (`reject_reserved_meta` above has already
        // refused every backend-owned key, so none of these is read as
        // authorization input), plus the restriction-bearing keys the child
        // must not be able to shed by omitting them from the body -- today the
        // AppRole environment scope. See `INHERITED_TOKEN_META_PREFIXES` for
        // why only the restrictions are inherited and the identities are not.
        let mut child_meta = data.meta.clone();
        inherit_restriction_meta(&parent.meta, &mut child_meta);

        let mut te = TokenEntry {
            parent: req.client_token.clone(),
            path: "auth/token/create".into(),
            meta: child_meta,
            display_name: "token".into(),
            num_uses: data.num_uses,
            // Inherit the parent's source-address binding. A bound token must
            // not be able to mint an unbound child, which would make the
            // restriction trivially escapable by one `auth/token/create`.
            bound_cidrs: parent.bound_cidrs.clone(),
            // Inherit the machine-identity exemption, which is a property of
            // how the parent authenticated. Inheriting cannot escalate -- an
            // exempt parent could already reach every path the child can --
            // and without it a bypassed AppID's child token would be refused
            // by a gate its parent is exempt from.
            machine_identity_exempt: parent.machine_identity_exempt,
            ..TokenEntry::default()
        };

        // Multi-tenancy: bind the new token to the namespace it is issued in
        // (named by the X-BastionVault-Namespace header; the parent's own
        // namespace by default). The binding rides in the token metadata so it
        // flows into `Auth.metadata` on lookup and is enforced on every routed
        // request.
        //
        // The binding is a *restriction*, so the same rule as `bound_cidrs`
        // applies: it is clamped to the parent's. `auth/` is header-scoped
        // (`namespace::router::is_header_scoped_path`), so
        // `enforce_request_token_binding` never checked *this* request against
        // the parent's binding -- which meant a `tenant-a`-bound token holding
        // a grant on `auth/token/create` could mint a child bound to the root
        // namespace (no header) or to a sibling tenant (any header), and a
        // parent that is not child-visible could mint a `child_visible` child
        // that reaches every descendant namespace the parent cannot. Root is
        // exempt because a root token already operates in every namespace
        // (`token_binding::token_operable`).
        {
            use crate::modules::namespace::{
                router::{namespace_header_from_map, NAMESPACE_HEADER},
                store::normalize_path,
                token_binding,
            };
            let (parent_ns_path, parent_child_visible) = token_binding::binding_from_metadata(&parent.meta);

            // An absent (or empty) header inherits the parent's namespace
            // rather than defaulting to root: the previous default silently
            // *widened* every child of a namespace-bound token. A *malformed*
            // header is an error rather than a fall back to either -- this is
            // the one place a namespace header decides a credential's binding
            // instead of where a single request lands, so the caller must get
            // the binding it named or nothing.
            let requested_ns = match namespace_header_from_map(req.headers.as_ref())
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
            {
                None => None,
                Some(header) => Some(normalize_path(&header).map_err(|e| {
                    bv_error_response!(&format!("invalid {} header on token create: {e}", NAMESPACE_HEADER))
                })?),
            };

            let ns_path = match requested_ns {
                None => parent_ns_path.clone(),
                Some(ns) => {
                    if !is_root && !token_binding::token_may_operate(&parent_ns_path, parent_child_visible, &ns) {
                        log::warn!(
                            target: "security",
                            "token create refused: parent bound to namespace {parent_ns_path:?} \
                             (child_visible={parent_child_visible}) may not mint a token in {ns:?} \
                             (parent display_name={})",
                            parent.display_name
                        );
                        return Err(bv_error_response!(&format!(
                            "cannot create a token in namespace {ns:?}: the parent token is bound to \
                             {parent_ns_path:?} and may not operate there"
                        )));
                    }
                    ns
                }
            };

            // Refused, not silently downgraded (AGENTS.md §7): a caller that
            // asked for a reach it cannot have gets an error, not a token that
            // quietly lacks the flag it requested.
            if data.child_visible && !is_root && !parent_child_visible {
                log::warn!(
                    target: "security",
                    "token create refused: child_visible requested by a parent that is not itself \
                     child-visible (parent namespace={parent_ns_path:?}, display_name={})",
                    parent.display_name
                );
                return Err(bv_error_response!(
                    "cannot set child_visible: the parent token is not child-visible, so the child \
                     would reach descendant namespaces the parent cannot"
                ));
            }

            te.meta.insert(token_binding::NS_PATH_META.to_string(), ns_path);
            te.meta
                .insert(token_binding::CHILD_VISIBLE_META.to_string(), data.child_visible.to_string());
        }

        let mut renewable = data.renewable;

        if !data.display_name.is_empty() {
            let mut full = format!("token-{}", data.display_name);
            full = DISPLAY_NAME_SANITIZE.replace_all(&full, "-").to_string();
            full = full.trim_end_matches('-').to_string();
            te.display_name = full;
        }

        if !data.id.is_empty() {
            if !is_root {
                return Err(RvError::ErrRequestInvalid);
            }
            te.id.clone_from(&data.id);
        }

        if data.policies.is_empty() {
            data.policies.clone_from(&parent.policies);
            sanitize_policies(&mut data.policies, false);
        }

        if !is_root && !is_str_subset(&data.policies, &parent.policies) {
            return Err(RvError::ErrRequestInvalid);
        }

        te.policies.clone_from(&data.policies);

        for policy in te.policies.iter() {
            if NON_ASSIGNABLE_POLICIES.contains(&policy.as_str()) {
                return Err(bv_error_response!(&format!("cannot assign policy {policy}")));
            }
        }

        if te.policies.contains(&"root".into()) && !parent.policies.contains(&"root".into()) {
            return Err(bv_error_response!("root tokens may not be created without parent token being root"));
        }

        if data.no_parent {
            if !is_root {
                return Err(RvError::ErrRequestInvalid);
            }
            te.parent = "".into();
        }

        if !data.ttl.is_empty() {
            let dur = parse_duration(&data.ttl)?;
            te.ttl = dur.as_secs();
        } else if !data.lease.is_empty() {
            let dur = parse_duration(&data.lease)?;
            te.ttl = dur.as_secs();
        }

        te.period = data.period;
        te.explicit_max_ttl = data.explicit_max_ttl;

        if te.period.as_secs() > 0 || te.ttl > 0 || (te.ttl == 0 && !te.policies.contains(&"root".to_string())) {
            te.ttl = calculate_ttl(
                MAX_LEASE_TTL,
                DEFAULT_LEASE_TTL,
                Duration::ZERO,
                te.period,
                Duration::from_secs(te.ttl),
                Duration::ZERO,
                te.explicit_max_ttl,
                te.creation_time,
            )?
            .as_secs();
        }

        if te.ttl == 0 && te.explicit_max_ttl.as_secs() > 0 {
            te.ttl = te.explicit_max_ttl.as_secs();
        }

        if data.no_parent {
            // TODO: Only allow an orphan token if the client has sudo policy
            te.parent.clear();
        }

        if te.ttl == 0 {
            if parent.ttl != 0 {
                return Err(bv_error_response!("expiring root tokens cannot create non-expiring root tokens"));
            }
            renewable = false;
        }

        self.create(&mut te).await?;

        let auth = Auth {
            lease: Lease { ttl: Duration::from_secs(te.ttl), renewable, ..Lease::default() },
            client_token: te.id.clone(),
            display_name: te.display_name.clone(),
            policies: te.policies.clone(),
            period: te.period,
            explicit_max_ttl: te.explicit_max_ttl,
            metadata: te.meta.clone(),
            ..Default::default()
        };
        let resp = Response { auth: Some(auth), ..Response::default() };

        Ok(Some(resp))
    }

    pub async fn handle_revoke_tree(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.get_data_as_str("token")?;
        if id.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        self.revoke_tree(&id).await?;

        Ok(None)
    }

    pub async fn handle_revoke_orphan(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.get_data_as_str("token")?;
        if id.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        self.revoke(&id).await?;

        Ok(None)
    }

    /// `auth/token/revoke-self` — the Vault-compatible self-service
    /// logout endpoint. Revokes the calling token and its child tokens,
    /// then records a best-effort `logout` event to the login-audit
    /// trail so the session end surfaces on the admin Audit page.
    ///
    /// A root-policy token is left valid: it is typically the operator's
    /// only break-glass access, and self-revoking it on logout would
    /// require an unseal-key ceremony to recover. The logout is still
    /// recorded. Every other token is revoked along with its tree.
    pub async fn handle_revoke_self(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.client_token.clone();
        if id.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        // Capture the principal for the audit row before the entry is
        // gone. A missing entry (already-expired token) still produces a
        // logout row, just with generic identity.
        let (username, mount, is_root) = match self.lookup(&id).await {
            Ok(Some(te)) => {
                let username = te
                    .meta
                    .get("username")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        if te.display_name.is_empty() {
                            "(token)".to_string()
                        } else {
                            te.display_name.clone()
                        }
                    });
                let mount = te.meta.get("mount_path").cloned().unwrap_or_default();
                let is_root = te.policies.iter().any(|p| p == "root");
                (username, mount, is_root)
            }
            _ => ("(unknown)".to_string(), String::new(), false),
        };
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        if is_root {
            log::info!(target: "security", "revoke-self on a root-policy token: logout recorded, token left valid");
        } else {
            self.revoke_tree(&id).await?;
        }

        if let Some(system_view) = self.system_view.as_ref() {
            crate::modules::credential::login_audit_store::record_logout(
                system_view,
                &mount,
                &username,
                &remote_addr,
            )
            .await;
        }

        Ok(None)
    }

    /// `auth/token/audit-login` — record a `login` event for the calling
    /// token. Presenting an existing token to the GUI (the "Login with
    /// token" path) is not a credential-backend login, so it produces no
    /// `record_login` call on the server. The GUI invokes this endpoint
    /// once after it has validated the token via `lookup-self`, so the
    /// sign-in surfaces on the admin Audit page alongside password / FIDO2
    /// / SSO logins. The token's own ACL (the `default` policy grants it)
    /// gates access, and the principal is derived server-side from the
    /// authenticated request — never trusted from the caller.
    ///
    /// The liveness probe (`token_status`) also calls `lookup-self`, but
    /// never this endpoint, so repeated probes do not spam the trail.
    /// Recording is best-effort and never fails the request.
    pub async fn handle_audit_login(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Identity comes from the authenticated request (populated by
        // `pre_route` from the token entry), mirroring how
        // `handle_revoke_self` resolves the logout principal: prefer the
        // mapped `username` metadata, then the token's display name.
        let auth = req.auth.as_ref();
        let username = auth
            .and_then(|a| a.metadata.get("username").cloned())
            .filter(|s| !s.is_empty())
            .or_else(|| auth.map(|a| a.display_name.clone()).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "(token)".to_string());
        let policies = auth.map(|a| a.policies.join(",")).unwrap_or_default();
        let details = if policies.is_empty() {
            String::new()
        } else {
            format!("policies={policies}")
        };
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        if let Some(system_view) = self.system_view.as_ref() {
            crate::modules::credential::login_audit_store::record_login_via_view(
                system_view,
                "token/",
                &username,
                true,
                &remote_addr,
                &details,
            )
            .await;
        }

        Ok(None)
    }

    pub async fn handle_lookup_self(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        if let Some(data) = req.data.as_mut() {
            data.insert("token".to_string(), Value::String(req.client_token.clone()));
        } else {
            req.data = json!({
                "token": req.client_token.clone(),
            })
            .as_object()
            .cloned();
        }

        self.handle_lookup(backend, req).await
    }

    pub async fn handle_lookup(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        log::debug!("lookup token");
        let mut id = req.get_data_as_str("token")?;
        if id.is_empty() {
            id.clone_from(&req.client_token);
        }

        if id.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let te = self.lookup(&id).await?;
        if te.is_none() {
            return Ok(None);
        }

        let te = te.unwrap();

        let meta = serde_json::to_value(&te.meta)?;

        let mut data = serde_json::json!({
            "id": te.id.clone(),
            "policies": te.policies.clone(),
            "path": te.path.clone(),
            "meta": meta,
            "display_name": te.display_name.clone(),
            "num_uses": te.num_uses,
            "ttl": 0,
            "creation_time": te.creation_time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "creation_ttl": te.ttl,
            "explicit_max_ttl": te.explicit_max_ttl.as_secs(),
        })
        .as_object()
        .unwrap()
        .clone();

        if te.period.as_secs() > 0 {
            data.insert("period".to_string(), json!(te.period.as_secs()));
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = req.get_data_as_str("token")?;
        if id.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let te = self.lookup(&id).await?.ok_or(RvError::ErrRequestInvalid)?;

        let increment_raw: i32 = serde_json::from_value(req.get_data("increment")?)?;
        let increment = Duration::from_secs(increment_raw as u64);

        self.expiration.renew_token(req, &te, increment).await
    }

    pub async fn auth_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.auth.is_none() {
            return Err(bv_error_string!("request auth is nil"));
        }

        let id = &req.auth.as_ref().unwrap().client_token;
        let te = self.lookup(id).await?.ok_or(bv_error_string!("no token entry found during lookup"))?;

        let auth = req.auth.as_mut().unwrap();
        auth.period = te.period;
        auth.explicit_max_ttl = te.explicit_max_ttl;

        Ok(Some(Response { auth: Some(auth.clone()), ..Default::default() }))
    }
}

#[maybe_async::maybe_async]
impl Handler for TokenStore {
    fn name(&self) -> String {
        "auth_token".to_string()
    }

    /// Process the request before routing. If the module has registered the pre_auth phase, execute it.
    /// It can handle custom tokens. If pre_auth returns Auth, skip the default check_token operation.
    /// If pre_auth returns None or is not registered, perform the default check_token operation.
    /// After check_token, there's the post_auth phase where the registered post_auth function of the
    /// module runs. For example, the policy module does ACL checks in the post_auth phase.
    async fn pre_route(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let is_unauth_path = self.router.is_unauth_path(&req.path)?;
        if is_unauth_path {
            return Ok(None);
        }

        let mut auth: Option<Auth> = None;

        req.handle_phase = HandlePhase::PreAuth;

        let auth_handlers = self.auth_handlers.load();

        for auth_handler in auth_handlers.iter() {
            match auth_handler.pre_auth(req).await {
                Ok(Some(ret)) => {
                    auth = Some(ret);
                    break;
                }
                Ok(None) | Err(RvError::ErrHandlerDefault) => continue,
                Err(e) => return Err(e),
            }
        }

        if auth.is_none() {
            let client_ip = req.connection.as_ref().map(|c| c.client_ip()).unwrap_or_default();
            auth = self.check_token(&req.path, &req.client_token, &client_ip).await?;
        }

        if auth.is_none() {
            return Err(RvError::ErrPermissionDenied);
        }

        req.name.clone_from(&auth.as_ref().unwrap().display_name);
        req.auth = auth;

        // Server-enforced machine identity: when the FerroGate mount requires
        // it, every authenticated request must ride a token that satisfies
        // `machine_identity_satisfied` — machine-bound, root, or explicitly
        // exempted by the auth backend that issued it. Unauth paths already
        // returned above. This is the single chokepoint every authenticated
        // request crosses, so it covers all auth backends uniformly and cannot
        // be bypassed by a non-cooperating client.
        if self.require_machine_identity.load(Ordering::Relaxed) {
            let a = req.auth.as_ref().unwrap();
            if !machine_identity_satisfied(a) {
                log::warn!(
                    target: "security",
                    "request denied: server requires FerroGate machine identity but token is not machine-bound (path={}, display_name={}, role_name={})",
                    req.path,
                    a.display_name,
                    a.metadata.get("role_name").map(String::as_str).unwrap_or("-")
                );
                return Err(RvError::ErrPermissionDenied);
            }
        }

        req.handle_phase = HandlePhase::PostAuth;

        for auth_handler in auth_handlers.iter() {
            match auth_handler.post_auth(req).await {
                Ok(()) | Err(RvError::ErrHandlerDefault) => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    /// Handles post-routing logic after routing a request. The main operation here is the expiration
    /// time management of secrets and tokens.
    async fn post_route(&self, req: &mut Request, resp: &mut Option<Response>) -> Result<(), RvError> {
        if resp.is_none() {
            return Ok(());
        }

        let is_unauth_path = self.router.is_unauth_path(&req.path)?;

        let resp = resp.as_mut().unwrap();

        if !is_unauth_path && resp.secret.is_some() && !req.path.starts_with("/sys/renew") {
            let mut register_lease = true;
            let me = self.router.matching_mount_entry(&req.path)?;
            if me.is_none() {
                register_lease = false;
            }

            {
                let mount_entry = me.as_ref().unwrap().read()?;

                if let Some(ref options) = mount_entry.options {
                    if let Some(leased_passthrough) = options.get("leased_passthrough") {
                        if leased_passthrough != "true" {
                            register_lease = false;
                        }
                    } else {
                        register_lease = false;
                    }
                } else {
                    register_lease = false;
                }
            }

            if register_lease {
                self.expiration.register_secret(req, resp).await?;
            }
        }

        if let Some(auth) = resp.auth.as_mut() {
            if is_unauth_path {
                let source = self.router.matching_mount(&req.path)?;
                let source = source.as_str().trim_start_matches(AUTH_ROUTER_PREFIX).replace('/', "-");
                auth.display_name = (source + &auth.display_name).trim_end_matches('-').to_string();
                req.name.clone_from(&auth.display_name);
            } else if !req.path.starts_with("auth/token/") {
                return Err(RvError::ErrPermissionDenied);
            }

            if auth.ttl.as_secs() == 0 {
                auth.ttl = DEFAULT_LEASE_DURATION_SECS;
            }

            if auth.ttl > MAX_LEASE_DURATION_SECS {
                auth.ttl = MAX_LEASE_DURATION_SECS;
            }

            let token_ttl = calculate_ttl(
                MAX_LEASE_TTL,
                DEFAULT_LEASE_TTL,
                Duration::ZERO,
                auth.period,
                auth.ttl,
                auth.max_ttl,
                auth.explicit_max_ttl,
                SystemTime::now(),
            )?;

            auth.token_policies.clone_from(&auth.policies);
            sanitize_policies(&mut auth.token_policies, !auth.no_default_policy);

            let all_policies = auth.token_policies.clone();

            // TODO: add identity_policies to all_policies

            if all_policies.contains(&"root".to_string()) {
                return Err(bv_error_response!("auth methods cannot create root tokens"));
            }

            let mut te = TokenEntry {
                path: req.path.clone(),
                meta: auth.metadata.clone(),
                display_name: auth.display_name.clone(),
                ttl: token_ttl.as_secs(),
                policies: auth.token_policies.clone(),
                explicit_max_ttl: auth.explicit_max_ttl,
                period: auth.period,
                // The auth backend's `token_bound_cidrs`, carried here on the
                // Auth by `TokenParams::populate_token_auth`. Without this the
                // field is parsed, persisted on the role and echoed back on a
                // read, but never reaches the token it is supposed to restrict.
                bound_cidrs: auth.bound_cidrs.clone(),
                // Set by an auth backend that authenticated this principal
                // without machine attestation (AppRole `bypass_machine_binding`).
                machine_identity_exempt: auth.machine_identity_exempt,
                ..Default::default()
            };

            self.create(&mut te).await?;

            auth.client_token.clone_from(&te.id);
            auth.ttl = Duration::from_secs(te.ttl);

            self.expiration.register_auth(&te, auth).await?;

            auth.policies = all_policies;
        }

        Ok(())
    }
}

#[cfg(test)]
mod mod_token_store_tests {
    use super::*;
    // Metadata keys only the tests name: the production paths reach the
    // namespace pair through `token_binding`, and the reserved list itself is
    // consumed via `is_reserved_token_meta_key`.
    use crate::logical::{CHILD_VISIBLE_META, NS_PATH_META, RESERVED_TOKEN_META_KEYS, USERNAME_META};
    use crate::{
        context::Context,
        logical::{Backend, Request, Response, Secret},
        test_utils::new_unseal_test_bastion_vault,
    };

    macro_rules! mock_token_store {
        () => {{
            let name = format!("{}_{}", file!(), line!()).replace("/", "_").replace("\\", "_").replace(".", "_");
            println!("init_test_bastion_vault, name: {}", name);
            #[cfg(not(feature = "sync_handler"))]
            let (_, core, _) = new_unseal_test_bastion_vault(&name).await;
            #[cfg(feature = "sync_handler")]
            let (_, core, _) = new_unseal_test_bastion_vault(&name);

            let expiration = ExpirationManager::new(&core).unwrap().wrap();
            #[cfg(not(feature = "sync_handler"))]
            let token_store = TokenStore::new(&core, expiration.clone()).await.unwrap().wrap();
            #[cfg(feature = "sync_handler")]
            let token_store = TokenStore::new(&core, expiration.clone()).unwrap().wrap();

            expiration.set_token_store(&token_store).unwrap();

            token_store
        }};
    }

    pub struct MockBackend(());

    #[maybe_async::maybe_async]
    impl Backend for MockBackend {
        fn init(&mut self) -> Result<(), RvError> {
            Ok(())
        }
        fn setup(&self, _key: &str) -> Result<(), RvError> {
            Ok(())
        }
        fn cleanup(&self) -> Result<(), RvError> {
            Ok(())
        }
        fn get_unauth_paths(&self) -> Option<Arc<Vec<String>>> {
            None
        }
        fn get_root_paths(&self) -> Option<Arc<Vec<String>>> {
            None
        }
        fn get_ctx(&self) -> Option<Arc<Context>> {
            None
        }
        async fn handle_request(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
            Ok(None)
        }
        fn secret(&self, _key: &str) -> Option<&Arc<Secret>> {
            None
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_create_and_lookup() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "test-token".to_string(),
            ..TokenEntry::default()
        };

        token_store.create(&mut entry).await.unwrap();

        let result = token_store.lookup(&entry.id).await.unwrap();
        assert!(result.is_some());
        let looked_up_entry = result.unwrap();
        assert_eq!(looked_up_entry.id, entry.id);
        assert_eq!(looked_up_entry.policies, entry.policies);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_revoke() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "test-token".to_string(),
            ..TokenEntry::default()
        };

        token_store.create(&mut entry).await.unwrap();

        token_store.revoke(&entry.id).await.unwrap();

        let result = token_store.lookup(&entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_revoke_tree() {
        let token_store = mock_token_store!();

        let mut parent_entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "parent-token".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut parent_entry).await.unwrap();

        let mut child_entry = TokenEntry {
            parent: parent_entry.id.clone(),
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "child-token".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut child_entry).await.unwrap();

        let result = token_store.revoke_tree(&parent_entry.id).await;
        assert!(result.is_ok());

        let parent_result = token_store.lookup(&parent_entry.id).await.unwrap();
        let child_result = token_store.lookup(&child_entry.id).await.unwrap();
        assert!(parent_result.is_none());
        assert!(child_result.is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_cache_is_enabled_by_default() {
        // With default CacheConfig, token cache is enabled (TTL = 30s).
        let token_store = mock_token_store!();
        assert!(
            token_store.token_cache.is_some(),
            "default CacheConfig must enable the token cache"
        );

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "cache-probe".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();

        // First lookup misses, fills cache; second lookup hits cache.
        let first = token_store.lookup(&entry.id).await.unwrap().unwrap();
        assert_eq!(first.display_name, entry.display_name);

        let salted = token_store.salt_id(&entry.id);
        // Stretto populates its admission window asynchronously; wait a
        // beat so the insert becomes visible before we probe.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let cached: TokenEntry = token_store
            .token_cache
            .as_ref()
            .unwrap()
            .lookup(&salted)
            .expect("second lookup must have populated the cache");
        assert_eq!(cached.id, entry.id);
        assert_eq!(cached.policies, entry.policies);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_cache_invalidated_on_revoke() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "revoke-probe".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();

        // Populate cache.
        token_store.lookup(&entry.id).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let salted = token_store.salt_id(&entry.id);
        assert!(token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted).is_some());

        token_store.revoke(&entry.id).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(
            token_store.token_cache.as_ref().unwrap().lookup::<TokenEntry>(&salted).is_none(),
            "revoke must evict cache entry"
        );
        assert!(
            token_store.lookup(&entry.id).await.unwrap().is_none(),
            "revoked token must not be resurrectable via cache"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_handle_create_request() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "test-token".to_string(),
            ..TokenEntry::default()
        };

        token_store.create(&mut entry).await.unwrap();

        let result = token_store.lookup(&entry.id).await.unwrap();
        assert!(result.is_some());

        let mut req = Request {
            client_token: entry.id.clone(),
            body: json!({
                "policies": ["default"],
                "display_name": "test-token",
            })
            .as_object()
            .cloned(),
            ..Request::default()
        };

        let response = token_store.handle_create(&mock_backend, &mut req).await.unwrap();
        assert!(response.is_some());
        let resp = response.unwrap();
        assert!(resp.auth.is_some());
        let auth = resp.auth.unwrap();
        assert_eq!(auth.display_name, "token-test-token");
        assert_eq!(auth.policies, vec!["default".to_owned()]);
    }

    /// `token_bound_cidrs`, once stamped on a token entry, is enforced by
    /// `check_token` against the client IP the token is presented from.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_bound_cidrs_are_enforced_on_use() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/approle/login".to_string(),
            display_name: "bound-token".to_string(),
            bound_cidrs: vec!["10.0.0.0/24".to_string()],
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();

        // Allowed: inside the bound block.
        let auth = token_store.check_token("kv/data/x", &entry.id, "10.0.0.7").await.unwrap();
        assert!(auth.is_some(), "a client inside the bound CIDR must be admitted");
        // The binding is surfaced on the Auth so a caller can see why.
        assert_eq!(auth.unwrap().bound_cidrs, vec!["10.0.0.0/24".to_string()]);

        // Denied: outside the bound block.
        let err = token_store.check_token("kv/data/x", &entry.id, "10.0.1.7").await.unwrap_err();
        assert!(
            matches!(err, RvError::ErrPermissionDenied),
            "a client outside the bound CIDR must be denied, got: {err}"
        );

        // Denied: unknown client address. An address we cannot determine
        // cannot be shown to satisfy the rule, so it fails closed.
        let err = token_store.check_token("kv/data/x", &entry.id, "").await.unwrap_err();
        assert!(
            matches!(err, RvError::ErrPermissionDenied),
            "an unknown client address must be denied, got: {err}"
        );

        // Denied: the raw `ip:port` socket address is not silently trusted as
        // a different host — the network still decides, so this one is inside.
        assert!(token_store.check_token("kv/data/x", &entry.id, "10.0.0.7:41222").await.is_ok());
    }

    /// A token with no binding is unrestricted, including one persisted before
    /// the field existed (which deserializes to an empty list). This is what
    /// keeps enabling enforcement from locking out tokens already in
    /// circulation at upgrade time.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unbound_token_is_unrestricted_from_any_address() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/token/create".to_string(),
            display_name: "unbound".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();

        for ip in ["10.0.0.7", "203.0.113.9", ""] {
            assert!(
                token_store.check_token("kv/data/x", &entry.id, ip).await.unwrap().is_some(),
                "an unbound token must be usable from {ip:?}"
            );
        }

        // A record written before `bound_cidrs` existed has no such key at
        // all; it must deserialize to "unrestricted" rather than fail.
        let legacy = r#"{"id":"legacy-token","parent":"","policies":["default"],"path":"auth/token/create",
            "meta":{},"display_name":"legacy","num_uses":0,"ttl":0}"#;
        let decoded: TokenEntry = serde_json::from_str(legacy).unwrap();
        assert!(decoded.bound_cidrs.is_empty(), "a pre-upgrade token entry must decode as unrestricted");
    }

    /// A bound token must not be able to mint an unbound child, which would
    /// make the restriction escapable with one `auth/token/create`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_child_token_inherits_the_parent_binding() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let mut parent = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/approle/login".to_string(),
            display_name: "bound-parent".to_string(),
            bound_cidrs: vec!["10.0.0.0/24".to_string()],
            ..TokenEntry::default()
        };
        token_store.create(&mut parent).await.unwrap();

        let mut req = Request {
            client_token: parent.id.clone(),
            body: json!({ "policies": ["default"], "display_name": "child" }).as_object().cloned(),
            ..Request::default()
        };

        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child_token = resp.auth.unwrap().client_token;
        let child = token_store.lookup(&child_token).await.unwrap().unwrap();

        assert_eq!(
            child.bound_cidrs,
            vec!["10.0.0.0/24".to_string()],
            "the child must inherit the parent's source-address binding"
        );
        let err = token_store.check_token("kv/data/x", &child_token, "203.0.113.9").await.unwrap_err();
        assert!(matches!(err, RvError::ErrPermissionDenied), "the inherited binding must be enforced, got: {err}");
    }

    /// The machine-identity gate's predicate: root, machine-bound, or an
    /// explicit backend-set exemption satisfies it — and nothing a caller can
    /// put in a token's metadata does.
    ///
    /// The last case is why the exemption is a typed field: `handle_create`
    /// copies the request body's `meta` map onto the new token, so an exemption
    /// keyed on metadata would be mintable by any holder of a grant on
    /// `auth/token/create` — which is now refused outright by
    /// [`RESERVED_TOKEN_META_KEYS`], but must not be the only thing standing
    /// between a caller and the gate.
    #[test]
    fn test_machine_identity_predicate() {
        let plain = Auth { policies: vec!["default".into()], ..Auth::default() };
        assert!(!machine_identity_satisfied(&plain));

        let root = Auth { policies: vec!["root".into()], ..Auth::default() };
        assert!(machine_identity_satisfied(&root), "root must stay exempt for break-glass");

        let mut bound = plain.clone();
        bound.metadata.insert("spiffe_id".into(), "spiffe://td/host/abc".into());
        assert!(machine_identity_satisfied(&bound));

        let exempt = Auth { machine_identity_exempt: true, ..plain.clone() };
        assert!(machine_identity_satisfied(&exempt), "a backend-set exemption must satisfy the gate");

        // Metadata a caller could supply on `auth/token/create` must not.
        let mut forged = plain.clone();
        forged.metadata.insert("approle_machine_bypass".into(), "true".into());
        forged.metadata.insert("machine_identity_exempt".into(), "true".into());
        assert!(!machine_identity_satisfied(&forged), "the exemption must not be forgeable through token metadata");

        // An empty `spiffe_id` is not a machine identity. `contains_key` alone
        // accepted it, while `split_principal` audited the same token as not
        // machine-bound.
        let mut blank = plain.clone();
        blank.metadata.insert(SPIFFE_ID_META.into(), String::new());
        assert!(!machine_identity_satisfied(&blank), "an empty spiffe_id must not satisfy the gate");
    }

    /// A caller holding a grant on `auth/token/create` must not be able to
    /// write any backend-owned metadata key onto the token it mints.
    ///
    /// The `spiffe_id` case is the one with teeth: it is the whole of what
    /// "machine-bound" means to [`machine_identity_satisfied`], so before this
    /// was refused, one `auth/token/create` call minted a token that passed the
    /// server-wide `require_machine_identity` gate with no attestation of any
    /// kind — and, via `meta.mount_path = "ferrogate/"`, could then be replayed
    /// as the `machine_token` of an AppRole machine-bound login.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_create_refuses_reserved_metadata_keys() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let mut parent = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/userpass/login".to_string(),
            display_name: "userpass-alice".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut parent).await.unwrap();

        // Every reserved key, plus one from each reserved prefix, and the
        // fourth `approle_env_*` key nobody has added yet.
        let forgeries: Vec<String> = RESERVED_TOKEN_META_KEYS
            .iter()
            .map(|k| (*k).to_string())
            .chain(
                ["approle_env_scoped", "approle_env_secret", "approle_env_machine", "approle_env_future"]
                    .map(String::from),
            )
            .collect();

        for key in &forgeries {
            let mut req = Request::new("auth/token/create");
            req.client_token = parent.id.clone();
            req.body = json!({ "policies": ["default"], "meta": { key.as_str(): "forged" } })
                .as_object()
                .cloned();

            let err = token_store
                .handle_create(&mock_backend, &mut req)
                .await
                .expect_err(&format!("`meta.{key}` must be refused on token create"));
            match err {
                RvError::ErrResponse(msg) => assert!(
                    msg.contains(key.as_str()) && msg.contains("are reserved"),
                    "the error must name the refused key, got: {msg}"
                ),
                other => panic!("expected a response error naming `{key}`, got: {other}"),
            }
        }

        // The forged `spiffe_id` never reaches a token, so it can never reach
        // the gate: assert the end state, not just the error.
        let mut req = Request::new("auth/token/create");
        req.client_token = parent.id.clone();
        req.body = json!({
            "policies": ["default"],
            "meta": { SPIFFE_ID_META: "spiffe://forged/host/attacker" },
        })
        .as_object()
        .cloned();
        assert!(token_store.handle_create(&mock_backend, &mut req).await.is_err());

        // And a caller-supplied annotation that is *not* reserved still works,
        // still lands on the token, and still does not satisfy the gate.
        let mut req = Request::new("auth/token/create");
        req.client_token = parent.id.clone();
        req.body = json!({ "policies": ["default"], "meta": { "ticket": "CHG-4417" } }).as_object().cloned();
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child_token = resp.auth.unwrap().client_token;
        let child = token_store.lookup(&child_token).await.unwrap().unwrap();
        assert_eq!(child.meta.get("ticket").map(String::as_str), Some("CHG-4417"));
        assert!(!child.meta.contains_key(SPIFFE_ID_META));

        let auth = token_store.check_token("kv/data/x", &child_token, "10.0.0.7").await.unwrap().unwrap();
        assert!(
            !machine_identity_satisfied(&auth),
            "a token minted from `auth/token/create` must not satisfy the machine-identity gate"
        );
    }

    /// The exemption is a property of how the parent authenticated, so a child
    /// inherits it — and a child of a non-exempt parent cannot acquire one,
    /// whatever it puts in `meta`. (The metadata spellings of the exemption are
    /// refused outright now; see `test_token_create_refuses_reserved_metadata_keys`.
    /// This test covers what is left: that the typed field, and only the typed
    /// field, decides.)
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_child_token_inherits_the_machine_identity_exemption() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let create_child = |parent_id: &str| {
            let mut req = Request::new("auth/token/create");
            req.client_token = parent_id.to_string();
            req.body = json!({ "policies": ["default"], "meta": { "ticket": "CHG-4417" } })
                .as_object()
                .cloned();
            req
        };

        for (exempt, expected) in [(true, true), (false, false)] {
            let mut parent = TokenEntry {
                policies: vec!["default".to_string()],
                path: "auth/approle/login".to_string(),
                display_name: "approle-app".to_string(),
                machine_identity_exempt: exempt,
                ..TokenEntry::default()
            };
            token_store.create(&mut parent).await.unwrap();

            let mut req = create_child(&parent.id);
            let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
            let child_token = resp.auth.unwrap().client_token;
            let child = token_store.lookup(&child_token).await.unwrap().unwrap();

            assert_eq!(
                child.machine_identity_exempt, expected,
                "a child of an exempt={exempt} parent must be exempt={expected}; only the typed field decides"
            );
            // And it round-trips onto the Auth the gate reads.
            let auth = token_store.check_token("kv/data/x", &child_token, "10.0.0.7").await.unwrap().unwrap();
            assert_eq!(auth.machine_identity_exempt, expected);
        }

        // A token entry persisted before the field existed reads back as not
        // exempt, i.e. the gate keeps applying to it.
        let legacy = r#"{"id":"legacy-token","parent":"","policies":["default"],"path":"auth/approle/login",
            "meta":{},"display_name":"legacy","num_uses":0,"ttl":0}"#;
        let decoded: TokenEntry = serde_json::from_str(legacy).unwrap();
        assert!(!decoded.machine_identity_exempt, "a pre-upgrade token entry must decode as not exempt");
    }

    /// Every prefix in [`INHERITED_TOKEN_META_PREFIXES`] must also be
    /// reserved. The two lists live in different crates -- inheritance in
    /// `bv-kernel` because `handle_create` is its only write point, the
    /// reserved set in `bv-logical` because it has two -- so nothing but this
    /// keeps them in step.
    ///
    /// An inherited-but-unreserved prefix would be the worst of both: the
    /// caller could supply the key in the body, and `inherit_restriction_meta`
    /// would then silently overwrite whatever they sent with the parent's
    /// value. Asserted through `is_reserved_token_meta_key` rather than
    /// against either list, so the invariant holds however the reserved set is
    /// spelled.
    #[test]
    fn test_inherited_meta_prefixes_are_all_reserved() {
        for prefix in INHERITED_TOKEN_META_PREFIXES {
            assert!(
                is_reserved_token_meta_key(&format!("{prefix}anything")),
                "`{prefix}` is inherited from the parent but not refused in the request body: a \
                 caller could set it, and the inherit pass would then overwrite their value"
            );
        }
    }

    /// A *restriction* carried in a token's metadata must survive
    /// `auth/token/create`, and an *identity* must not be inherited by it.
    ///
    /// `handle_create` builds the child's `meta` from the request body, so
    /// before this a restriction the parent carried was simply absent on the
    /// child. `bv-engine-kv`'s `enforce_env_scope` passes a token through
    /// unchanged when `approle_env_scoped` is absent, so an env-scoped AppID
    /// with a grant on `auth/token/create` minted itself a child that read
    /// every environment -- including the base (non-env) secrets a scoped
    /// token is explicitly barred from. Rejecting the forged spelling (see
    /// `test_token_create_refuses_reserved_metadata_keys`) closed the "gain a
    /// key" direction and left this one open.
    ///
    /// The negative half is not incidental: inheriting `spiffe_id` would make
    /// every child of a machine-bound token satisfy the server-wide
    /// `require_machine_identity` gate by descent instead of by attestation,
    /// and inheriting `username` would attribute the child's actions to the
    /// parent's principal. See `INHERITED_TOKEN_META_PREFIXES`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_child_token_inherits_the_approle_environment_scope() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let mut parent = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/approle/login".to_string(),
            display_name: "approle-payments".to_string(),
            meta: HashMap::from([
                // The restriction: inherited.
                ("approle_env_scoped".to_string(), "true".to_string()),
                ("approle_env_secret".to_string(), "prod,staging".to_string()),
                ("approle_env_machine".to_string(), "prod".to_string()),
                // A key nobody has added yet, covered by the prefix rule.
                ("approle_env_future".to_string(), "whatever".to_string()),
                // The identities: not inherited.
                (SPIFFE_ID_META.to_string(), "spiffe://td/host/payments".to_string()),
                (USERNAME_META.to_string(), "payments-api".to_string()),
                ("mount_path".to_string(), "approle/".to_string()),
            ]),
            ..TokenEntry::default()
        };
        token_store.create(&mut parent).await.unwrap();

        let mut req = Request::new("auth/token/create");
        req.client_token = parent.id.clone();
        req.body = json!({ "policies": ["default"], "meta": { "ticket": "CHG-4417" } }).as_object().cloned();
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child_token = resp.auth.unwrap().client_token;
        let child = token_store.lookup(&child_token).await.unwrap().unwrap();

        for (key, expected) in [
            ("approle_env_scoped", "true"),
            ("approle_env_secret", "prod,staging"),
            ("approle_env_machine", "prod"),
            ("approle_env_future", "whatever"),
        ] {
            assert_eq!(
                child.meta.get(key).map(String::as_str),
                Some(expected),
                "the child must inherit the parent's `{key}`; dropping it escapes the environment scope"
            );
        }

        // The caller's own annotation still lands.
        assert_eq!(child.meta.get("ticket").map(String::as_str), Some("CHG-4417"));

        // Identity keys stay with the parent.
        for key in [SPIFFE_ID_META, USERNAME_META, "mount_path"] {
            assert!(
                !child.meta.contains_key(key),
                "`{key}` names a principal, not a restriction: inheriting it would widen the child"
            );
        }
        let auth = token_store.check_token("kvenv/data/svc", &child_token, "10.0.0.7").await.unwrap().unwrap();
        assert_eq!(
            auth.metadata.get("approle_env_scoped").map(String::as_str),
            Some("true"),
            "the inherited scope must reach the `Auth` the KV engine reads"
        );
        assert!(
            !machine_identity_satisfied(&auth),
            "a child of a machine-bound token must not satisfy the machine-identity gate by descent"
        );

        // An unscoped parent's child stays unscoped: this inherits a
        // restriction, it does not invent one.
        let mut plain = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/userpass/login".to_string(),
            display_name: "userpass-alice".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut plain).await.unwrap();

        let mut req = Request::new("auth/token/create");
        req.client_token = plain.id.clone();
        req.body = json!({ "policies": ["default"] }).as_object().cloned();
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert!(
            !child.meta.keys().any(|k| k.starts_with("approle_env_")),
            "a child of an unscoped parent must not acquire an environment scope"
        );
    }

    /// The namespace binding is a restriction too, and `auth/` is
    /// header-scoped -- so `enforce_request_token_binding` never checked an
    /// `auth/token/create` request against the parent's binding. A
    /// `tenant-a`-bound token could therefore mint a child bound to the root
    /// namespace (by omitting the header) or to a sibling tenant (by naming
    /// it), and a parent that is not child-visible could mint a
    /// `child_visible` child that reaches descendants the parent cannot.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_child_token_cannot_escape_the_parents_namespace_binding() {
        let token_store = mock_token_store!();
        let mock_backend = MockBackend(());

        let bound_parent = |ns: &str, child_visible: bool| TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/userpass/login".to_string(),
            display_name: "userpass-alice".to_string(),
            meta: HashMap::from([
                (NS_PATH_META.to_string(), ns.to_string()),
                (CHILD_VISIBLE_META.to_string(), child_visible.to_string()),
            ]),
            ..TokenEntry::default()
        };

        let create = |parent_id: &str, ns_header: Option<&str>, child_visible: bool| {
            let mut req = Request::new("auth/token/create");
            req.client_token = parent_id.to_string();
            req.body = json!({ "policies": ["default"], "child_visible": child_visible }).as_object().cloned();
            if let Some(ns) = ns_header {
                req.headers =
                    Some(HashMap::from([("X-BastionVault-Namespace".to_string(), ns.to_string())]));
            }
            req
        };

        let mut parent = bound_parent("tenant-a", false);
        token_store.create(&mut parent).await.unwrap();

        // No header: inherit the parent's namespace, not root.
        let mut req = create(&parent.id, None, false);
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert_eq!(
            child.meta.get(NS_PATH_META).map(String::as_str),
            Some("tenant-a"),
            "an absent namespace header must inherit the parent's binding, not default to root"
        );

        // Naming the parent's own namespace is fine.
        let mut req = create(&parent.id, Some("tenant-a/"), false);
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert_eq!(child.meta.get(NS_PATH_META).map(String::as_str), Some("tenant-a"));

        // An explicitly *empty* header reads as "unset" -- the same reading
        // `namespace::token_binding::resolve_login_namespace` gives it -- so it
        // inherits too rather than naming root.
        let mut req = create(&parent.id, Some("  "), false);
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert_eq!(
            child.meta.get(NS_PATH_META).map(String::as_str),
            Some("tenant-a"),
            "an empty namespace header must inherit the parent's binding, not name root"
        );

        // A sibling tenant is refused, as is a descendant the parent cannot
        // itself reach, and so is root -- named as `/`, which normalizes to the
        // root path rather than reading as an unset header.
        for ns in ["tenant-b", "tenant-a/sub", "/"] {
            let mut req = create(&parent.id, Some(ns), false);
            let err = token_store
                .handle_create(&mock_backend, &mut req)
                .await
                .expect_err(&format!("a tenant-a-bound parent must not mint a token in {ns:?}"));
            match err {
                RvError::ErrResponse(msg) => {
                    assert!(msg.contains("may not operate there"), "expected a namespace refusal, got: {msg}")
                }
                other => panic!("expected a response error for {ns:?}, got: {other}"),
            }
        }

        // A malformed header is an error, not a silent fall back to the
        // parent's namespace (or, as before, to root): `..` used to normalize
        // away and leave the child bound wherever the fallback pointed.
        for ns in ["tenant-a/../tenant-b", "tenant-*", "tenant-a/ sub"] {
            let mut req = create(&parent.id, Some(ns), false);
            let err = token_store
                .handle_create(&mock_backend, &mut req)
                .await
                .expect_err(&format!("a malformed namespace header {ns:?} must be refused"));
            match err {
                RvError::ErrResponse(msg) => {
                    assert!(msg.contains("invalid"), "expected a malformed-header refusal, got: {msg}")
                }
                other => panic!("expected a response error for {ns:?}, got: {other}"),
            }
        }

        // `child_visible` cannot be acquired by a parent that lacks it.
        let mut req = create(&parent.id, Some("tenant-a"), true);
        let err = token_store.handle_create(&mock_backend, &mut req).await.expect_err(
            "a parent that is not child-visible must not mint a child-visible child",
        );
        match err {
            RvError::ErrResponse(msg) => {
                assert!(msg.contains("child_visible"), "expected a child_visible refusal, got: {msg}")
            }
            other => panic!("expected a response error, got: {other}"),
        }

        // A child-visible parent may reach a descendant, and pass the flag on.
        let mut visible = bound_parent("tenant-a", true);
        token_store.create(&mut visible).await.unwrap();
        let mut req = create(&visible.id, Some("tenant-a/sub"), true);
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert_eq!(child.meta.get(NS_PATH_META).map(String::as_str), Some("tenant-a/sub"));
        assert_eq!(child.meta.get(CHILD_VISIBLE_META).map(String::as_str), Some("true"));

        // Root operates in every namespace, so it keeps minting anywhere.
        let mut root = TokenEntry {
            policies: vec!["root".to_string()],
            path: "auth/token/root".to_string(),
            display_name: "root".to_string(),
            ..TokenEntry::default()
        };
        token_store.create(&mut root).await.unwrap();
        let mut req = create(&root.id, Some("tenant-b"), true);
        let resp = token_store.handle_create(&mock_backend, &mut req).await.unwrap().unwrap();
        let child = token_store.lookup(&resp.auth.unwrap().client_token).await.unwrap().unwrap();
        assert_eq!(child.meta.get(NS_PATH_META).map(String::as_str), Some("tenant-b"));
        assert_eq!(child.meta.get(CHILD_VISIBLE_META).map(String::as_str), Some("true"));
    }

    /// A denied request must not consume one of a use-limited token's uses,
    /// or an attacker from a blocked address could burn a token remotely.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_denied_bound_cidr_does_not_burn_a_use() {
        let token_store = mock_token_store!();

        let mut entry = TokenEntry {
            policies: vec!["default".to_string()],
            path: "auth/approle/login".to_string(),
            display_name: "bound-limited".to_string(),
            bound_cidrs: vec!["10.0.0.0/24".to_string()],
            num_uses: 3,
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();

        for _ in 0..5 {
            assert!(token_store.check_token("kv/data/x", &entry.id, "203.0.113.9").await.is_err());
        }

        let after = token_store.lookup(&entry.id).await.unwrap().unwrap();
        assert_eq!(after.num_uses, 3, "a refused request must not decrement num_uses");

        // The token is still good for its three uses from an allowed address.
        assert!(token_store.check_token("kv/data/x", &entry.id, "10.0.0.7").await.is_ok());
        let after = token_store.lookup(&entry.id).await.unwrap().unwrap();
        assert_eq!(after.num_uses, 2);
    }
}
