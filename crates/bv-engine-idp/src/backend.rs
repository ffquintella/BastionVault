//! The `v2/idp/...` logical surface: identities CRUD, the lifecycle state
//! endpoint, `idp/config`, (Phase 2, [`authz`]) environments and
//! entitlements, (Phase 3, [`ssh`]) SSH sign, the KRL and the deny feed,
//! and (Phase 4, [`radius`]) the RADIUS provider's configuration, NAS
//! clients, attribute profiles and self-service passcodes.
//! Every handler runs [`IdpBackendInner::guard`] first: v2 only, root
//! namespace only, root-table mount only.

mod authz;
mod radius;
mod ssh;

use std::{collections::HashMap, sync::Arc};

use bv_errors::bv_error_response_status;
use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
};
use derive_more::Deref;
use serde_json::{Map, Value};

use crate::{
    context::Context,
    entitlement::{gate::IssueGate, EntitlementStoreSlot},
    errors::RvError,
    kernel_api::{namespace::caller_namespace, VaultCtx},
    logical::{Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response},
    posix::{
        allocator::AllocatorState,
        model::{parse_id, parse_id_list, IdKind, IdentityState, PosixConfig, PosixError, UidSource},
        store::{ConfigUpdate, IdentityWrite, PosixStore},
    },
    provider::radius::RadiusRuntime,
    IssuanceSlot, PosixStoreSlot, IDP_LOGICAL_TYPE,
};

static IDP_BACKEND_HELP: &str = r#"
The idp backend is BastionVault's outbound identity provider. It holds the
canonical workforce identities (one immutable login, uid and primary gid per
entity, never reused, with an active -> disabled -> removed lifecycle), the
environments they may enter (each bound to one namespace, mapping role names
to that namespace's policies) and the entitlements that grant them. It signs
identity-bound SSH certificates through the SSH engine and publishes their
revocation as an OpenSSH KRL and a signed, versioned deny feed. It answers
RADIUS Access-Requests from registered NAS clients (RadSec by default, UDP
opt-in) with per-role vendor attributes, against one-time passcodes the
human mints here. Served under /v2 only, from the root namespace only.
"#;

pub struct IdpBackendInner {
    pub core: Arc<dyn VaultCtx>,
    pub store: Arc<PosixStoreSlot>,
    pub authz: Arc<EntitlementStoreSlot>,
    pub issuance: Arc<IssuanceSlot>,
    pub radius: Arc<RadiusRuntime>,
}

#[derive(Deref)]
pub struct IdpBackend {
    #[deref]
    pub inner: Arc<IdpBackendInner>,
}

impl IdpBackend {
    pub fn new(
        core: Arc<dyn VaultCtx>,
        store: Arc<PosixStoreSlot>,
        authz: Arc<EntitlementStoreSlot>,
        issuance: Arc<IssuanceSlot>,
        radius: Arc<RadiusRuntime>,
    ) -> Self {
        Self { inner: Arc::new(IdpBackendInner { core, store, authz, issuance, radius }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_config_read = self.inner.clone();
        let h_config_write = self.inner.clone();
        let h_list = self.inner.clone();
        let h_state = self.inner.clone();
        let h_read = self.inner.clone();
        let h_write = self.inner.clone();
        let h_delete = self.inner.clone();
        let h_env_list = self.inner.clone();
        let h_env_read = self.inner.clone();
        let h_env_write = self.inner.clone();
        let h_env_delete = self.inner.clone();
        let h_ent_list = self.inner.clone();
        let h_ent_read = self.inner.clone();
        let h_ent_write = self.inner.clone();
        let h_ent_delete = self.inner.clone();
        let h_ssh_config_read = self.inner.clone();
        let h_ssh_config_write = self.inner.clone();
        let h_ssh_sign = self.inner.clone();
        let h_ssh_krl = self.inner.clone();
        let h_feed = self.inner.clone();
        let h_feed_key = self.inner.clone();
        let h_radius_config_read = self.inner.clone();
        let h_radius_config_write = self.inner.clone();
        let h_radius_client_list = self.inner.clone();
        let h_radius_client_read = self.inner.clone();
        let h_radius_client_write = self.inner.clone();
        let h_radius_client_delete = self.inner.clone();
        let h_radius_profile_list = self.inner.clone();
        let h_radius_profile_read = self.inner.clone();
        let h_radius_profile_write = self.inner.clone();
        let h_radius_profile_delete = self.inner.clone();
        let h_radius_passcode = self.inner.clone();

        new_logical_backend!({
            paths: [
                {
                    pattern: r"config$",
                    fields: {
                        "uid_min": { field_type: FieldType::Int, required: false, description: "Lowest uid the allocator hands out." },
                        "uid_max": { field_type: FieldType::Int, required: false, description: "Highest uid the allocator hands out." },
                        "gid_min": { field_type: FieldType::Int, required: false, description: "Lowest primary gid the allocator hands out." },
                        "gid_max": { field_type: FieldType::Int, required: false, description: "Highest primary gid the allocator hands out." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_config_read.handle_config_read},
                        {op: Operation::Write, handler: h_config_write.handle_config_write}
                    ],
                    help: "uid/gid allocation ranges and allocator status."
                },
                {
                    pattern: r"identities/?$",
                    operations: [
                        {op: Operation::List, handler: h_list.handle_identity_list}
                    ],
                    help: "List workforce identities (entity ids, with login/uid/state in key_info)."
                },
                {
                    pattern: r"identities/(?P<entity_id>[^/]+)/state$",
                    fields: {
                        "entity_id": { field_type: FieldType::Str, required: false, description: "Entity id." },
                        "state": { field_type: FieldType::Str, required: false, description: "active | disabled | removed" },
                        "reason": { field_type: FieldType::Str, required: false, description: "Optional operator note, at most 256 characters." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_state.handle_state_write}
                    ],
                    help: "Move an identity through active -> disabled -> removed (disabled -> active reinstates)."
                },
                {
                    pattern: r"identities/(?P<entity_id>[^/]+)$",
                    fields: {
                        "entity_id": { field_type: FieldType::Str, required: false, description: "Entity id." },
                        "login": { field_type: FieldType::Str, required: false, description: "POSIX login; immutable." },
                        "uid": { field_type: FieldType::Int, required: false, description: "Imported uid (uid_source=imported only)." },
                        "primary_gid": { field_type: FieldType::Int, required: false, description: "Imported primary gid (defaults to uid)." },
                        "uid_source": { field_type: FieldType::Str, required: false, description: "vault (default) | imported" },
                        "display_name": { field_type: FieldType::Str, required: false, description: "GECOS display name." },
                        "gids": { field_type: FieldType::Array, required: false, description: "Supplementary gids." },
                        "reason": { field_type: FieldType::Str, required: false, description: "Removal note (DELETE)." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_read.handle_identity_read},
                        {op: Operation::Write, handler: h_write.handle_identity_write},
                        {op: Operation::Delete, handler: h_delete.handle_identity_delete}
                    ],
                    help: "Allocate, import, read or update a workforce identity. DELETE removes it (tombstones the uid)."
                },
                {
                    pattern: r"environments/?$",
                    operations: [
                        {op: Operation::List, handler: h_env_list.handle_environment_list}
                    ],
                    help: "List environments (names, with namespace/state/roles in key_info)."
                },
                {
                    pattern: r"environments/(?P<environment>[^/]+)$",
                    fields: {
                        "environment": { field_type: FieldType::Str, required: false, description: "Environment name." },
                        "namespace": { field_type: FieldType::Str, required: false, description: "Namespace path the environment is bound to (\"\" = root); required to create, immutable." },
                        "roles": { field_type: FieldType::Map, required: false, description: "Role name -> array of ACL policy names in that namespace. Replaces the whole map." },
                        "description": { field_type: FieldType::Str, required: false, description: "Free-text note, at most 256 characters." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_env_read.handle_environment_read},
                        {op: Operation::Write, handler: h_env_write.handle_environment_write},
                        {op: Operation::Delete, handler: h_env_delete.handle_environment_delete}
                    ],
                    help: "Create, read or update an environment. DELETE retires it; a retired name is never reused."
                },
                {
                    pattern: r"entitlements/(?P<entity_id>[^/]+)/(?P<environment>[^/]+)$",
                    fields: {
                        "entity_id": { field_type: FieldType::Str, required: false, description: "Entity id." },
                        "environment": { field_type: FieldType::Str, required: false, description: "Environment name." },
                        "roles": { field_type: FieldType::Array, required: false, description: "Roles granted; each must be defined on the environment." },
                        "not_after": { field_type: FieldType::Str, required: false, description: "Optional RFC 3339 expiry, in the future." },
                        "source": { field_type: FieldType::Str, required: false, description: "manual (default) | external" }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_ent_read.handle_entitlement_read},
                        {op: Operation::Write, handler: h_ent_write.handle_entitlement_write},
                        {op: Operation::Delete, handler: h_ent_delete.handle_entitlement_delete}
                    ],
                    help: "Grant, read or revoke one entitlement. A write replaces the whole grant."
                },
                {
                    pattern: r"entitlements/(?P<entity_id>[^/]+)/?$",
                    fields: {
                        "entity_id": { field_type: FieldType::Str, required: false, description: "Entity id." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_ent_list.handle_entitlement_list}
                    ],
                    help: "Every entitlement of one workforce identity, keyed by environment."
                },
                {
                    pattern: r"ssh/config$",
                    fields: {
                        "mount": { field_type: FieldType::Str, required: false, description: "SSH engine mount, resolved in each environment's namespace (default ssh)." },
                        "role": { field_type: FieldType::Str, required: false, description: "CA-mode role on that mount (default idp)." },
                        "default_ttl": { field_type: FieldType::Str, required: false, description: "Default certificate lifetime (e.g. 30m)." },
                        "max_ttl": { field_type: FieldType::Str, required: false, description: "Largest lifetime a caller may ask for; at most 8h." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_ssh_config_read.handle_ssh_config_read},
                        {op: Operation::Write, handler: h_ssh_config_write.handle_ssh_config_write}
                    ],
                    help: "SSH provider settings. Until written, the provider is off and nothing is signed."
                },
                {
                    pattern: r"ssh/sign/(?P<environment>[^/]+)$",
                    fields: {
                        "environment": { field_type: FieldType::Str, required: false, description: "Environment name." },
                        "public_key": { field_type: FieldType::Str, required: false, description: "The caller's OpenSSH public key." },
                        "ttl": { field_type: FieldType::Str, required: false, description: "Requested lifetime; above max_ttl is refused." },
                        "roles": { field_type: FieldType::Array, required: false, description: "Subset of the entitled roles; default all." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_ssh_sign.handle_ssh_sign}
                    ],
                    help: "Sign the caller's own key into an identity certificate for one environment (self-service; the entity is the token's)."
                },
                {
                    pattern: r"ssh/krl$",
                    operations: [
                        {op: Operation::Read, handler: h_ssh_krl.handle_ssh_krl}
                    ],
                    help: "OpenSSH KRL (base64) of every revoked, unexpired identity certificate."
                },
                {
                    pattern: r"deny-feed/key$",
                    operations: [
                        {op: Operation::Read, handler: h_feed_key.handle_deny_feed_key}
                    ],
                    help: "The deny feed's verification key (Ed25519 + ML-DSA-65), for hosts to pin."
                },
                {
                    pattern: r"deny-feed$",
                    operations: [
                        {op: Operation::Read, handler: h_feed.handle_deny_feed}
                    ],
                    help: "The signed, versioned deny feed: identities that are not active and revoked certificate serials."
                },
                {
                    pattern: r"radius/config$",
                    fields: {
                        "enabled": { field_type: FieldType::Bool, required: false, description: "Run the listeners (default false)." },
                        "radsec_listen": { field_type: FieldType::Str, required: false, description: "RadSec IP:port (\"\" clears)." },
                        "udp_enabled": { field_type: FieldType::Bool, required: false, description: "Allow classic UDP RADIUS (default false; trusted segments only)." },
                        "udp_listen": { field_type: FieldType::Str, required: false, description: "UDP IP:port; needs udp_enabled (\"\" clears)." },
                        "allow_unspecified_bind": { field_type: FieldType::Bool, required: false, description: "Permit 0.0.0.0 / :: listen addresses (default false)." },
                        "tls_cert_pem": { field_type: FieldType::Str, required: false, description: "RadSec server certificate chain (PEM)." },
                        "tls_key_pem": { field_type: FieldType::SecretStr, required: false, description: "RadSec server private key (PEM); never returned." },
                        "client_ca_pem": { field_type: FieldType::Str, required: false, description: "CA that NAS client certificates must chain to (PEM)." },
                        "rate_limit_per_minute": { field_type: FieldType::Int, required: false, description: "Requests per source address per minute (default 120)." },
                        "passcode_default_ttl": { field_type: FieldType::Str, required: false, description: "Default passcode lifetime (default 2m)." },
                        "passcode_max_ttl": { field_type: FieldType::Str, required: false, description: "Longest passcode lifetime (default 5m, at most 15m)." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_radius_config_read.handle_radius_config_read},
                        {op: Operation::Write, handler: h_radius_config_write.handle_radius_config_write}
                    ],
                    help: "RADIUS provider settings and listener status. Until enabled, nothing listens and no passcode is minted."
                },
                {
                    pattern: r"radius/clients/?$",
                    operations: [
                        {op: Operation::List, handler: h_radius_client_list.handle_radius_client_list}
                    ],
                    help: "List RADIUS NAS clients."
                },
                {
                    pattern: r"radius/clients/(?P<name>[^/]+)$",
                    fields: {
                        "name": { field_type: FieldType::Str, required: false, description: "Client name." },
                        "transport": { field_type: FieldType::Str, required: false, description: "radsec | udp; fixed at creation." },
                        "environment": { field_type: FieldType::Str, required: false, description: "The one environment this NAS serves; fixed at creation." },
                        "profile": { field_type: FieldType::Str, required: false, description: "Attribute profile of that environment." },
                        "address": { field_type: FieldType::Str, required: false, description: "udp: the NAS source IP address." },
                        "secret": { field_type: FieldType::SecretStr, required: false, description: "udp: shared secret, 16-128 printable characters; never returned." },
                        "cert_sha256": { field_type: FieldType::Str, required: false, description: "radsec: SHA-256 (hex) of the NAS certificate." },
                        "description": { field_type: FieldType::Str, required: false, description: "Free-text note." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_radius_client_read.handle_radius_client_read},
                        {op: Operation::Write, handler: h_radius_client_write.handle_radius_client_write},
                        {op: Operation::Delete, handler: h_radius_client_delete.handle_radius_client_delete}
                    ],
                    help: "Register, read, update or remove a NAS client."
                },
                {
                    pattern: r"radius/profiles/?$",
                    operations: [
                        {op: Operation::List, handler: h_radius_profile_list.handle_radius_profile_list}
                    ],
                    help: "List RADIUS attribute profiles."
                },
                {
                    pattern: r"radius/profiles/(?P<name>[^/]+)$",
                    fields: {
                        "name": { field_type: FieldType::Str, required: false, description: "Profile name." },
                        "environment": { field_type: FieldType::Str, required: false, description: "Environment; fixed at creation." },
                        "roles": { field_type: FieldType::Map, required: false, description: "Role -> array of attributes ({attribute, value} or {attribute: vsa, vendor_id, vendor_type, value})." },
                        "description": { field_type: FieldType::Str, required: false, description: "Free-text note." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_radius_profile_read.handle_radius_profile_read},
                        {op: Operation::Write, handler: h_radius_profile_write.handle_radius_profile_write},
                        {op: Operation::Delete, handler: h_radius_profile_delete.handle_radius_profile_delete}
                    ],
                    help: "Vendor attributes an Access-Accept carries per environment role (fortinet-group-name, ...)."
                },
                {
                    pattern: r"radius/passcode/(?P<environment>[^/]+)$",
                    fields: {
                        "environment": { field_type: FieldType::Str, required: false, description: "Environment name." },
                        "roles": { field_type: FieldType::Array, required: false, description: "Subset of the entitled roles; default all." },
                        "ttl": { field_type: FieldType::Str, required: false, description: "Lifetime; at most passcode_max_ttl." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_radius_passcode.handle_radius_passcode}
                    ],
                    help: "Mint a one-time RADIUS passcode for the caller's own identity in one environment (self-service, gated)."
                }
            ],
            help: IDP_BACKEND_HELP,
        })
    }
}

/// Whether the request reached this backend through an `idp` mount of the
/// root mount table. A child namespace that mounts the `idp` type is
/// refused, whichever addressing form it uses, so no tenant can reach the
/// deployment-wide store.
fn served_by_root_mount(ctx: &dyn VaultCtx, req: &Request) -> Result<bool, RvError> {
    let Some(served) = req.storage.as_ref() else {
        return Ok(false);
    };
    let mounts = ctx.mounts_router();
    // Collect first: never hold a mount-table lock while taking the router's.
    let mut idp_paths = Vec::new();
    for entry in mounts.mounts.entries.read()?.values() {
        let entry = entry.read()?;
        if entry.logical_type == IDP_LOGICAL_TYPE {
            idp_paths.push(format!("{}{}", mounts.router_prefix, entry.path));
        }
    }
    let router = ctx.router();
    for path in idp_paths {
        if let Some(view) = router.matching_view(&path)? {
            if std::ptr::addr_eq(Arc::as_ptr(served), Arc::as_ptr(&view)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn field(req: &Request, key: &str) -> Result<Option<Value>, RvError> {
    match req.get_data(key) {
        Ok(Value::Null) => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(RvError::ErrRequestFieldNotFound) | Err(RvError::ErrRequestNoData) => Ok(None),
        Err(RvError::ErrRequestFieldInvalid) => {
            Err(PosixError::Invalid(format!("field `{key}` has the wrong type")).into())
        }
        Err(e) => Err(e),
    }
}

fn str_field(req: &Request, key: &str) -> Result<Option<String>, RvError> {
    match field(req, key)? {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(PosixError::Invalid(format!("field `{key}` must be a string")).into()),
    }
}

fn id_field(req: &Request, key: &str) -> Result<Option<u32>, RvError> {
    field(req, key)?.map(|v| parse_id(key, &v)).transpose().map_err(Into::into)
}

fn entity_id(req: &Request) -> Result<String, RvError> {
    str_field(req, "entity_id")?.ok_or_else(|| PosixError::Invalid("entity_id is missing from the path".into()).into())
}

fn config_map(cfg: &PosixConfig, pinned: bool, uid: &AllocatorState, gid: &AllocatorState) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("version".into(), Value::from(cfg.version));
    m.insert("uid_min".into(), Value::from(cfg.uid_range.min));
    m.insert("uid_max".into(), Value::from(cfg.uid_range.max));
    m.insert("gid_min".into(), Value::from(cfg.gid_range.min));
    m.insert("gid_max".into(), Value::from(cfg.gid_range.max));
    m.insert("pinned".into(), Value::from(pinned));
    m.insert("updated_at".into(), cfg.updated_at.map(|t| Value::from(t.to_rfc3339())).into());
    for (prefix, state) in [("uid", uid), ("gid", gid)] {
        m.insert(format!("{prefix}_high_water"), state.high_water.map(Value::from).into());
        m.insert(format!("{prefix}_used"), Value::from(state.used.count()));
        m.insert(format!("{prefix}_retired"), Value::from(state.retired.count()));
    }
    m
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    /// v2 only, root namespace only, root-table mount only; then the store.
    async fn guard(&self, req: &Request) -> Result<Arc<PosixStore>, RvError> {
        if req.api_version < 2 {
            return Err(bv_error_response_status!(400, "the identity provider is served under /v2 only"));
        }
        let root_only =
            || bv_error_response_status!(403, "the identity provider is served from the root namespace only");
        if !caller_namespace(self.core.as_ref(), req).await?.is_empty() {
            return Err(root_only());
        }
        if !served_by_root_mount(self.core.as_ref(), req)? {
            return Err(root_only());
        }
        self.store.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)
    }

    /// The issue gate over this backend's stores; see [`IssueGate`].
    pub fn issue_gate(&self) -> IssueGate {
        crate::issue_gate(&self.core, &self.store, &self.authz)
    }

    async fn config_response(&self, store: &PosixStore) -> Result<Option<Response>, RvError> {
        let stored = store.stored_config().await?;
        let pinned = stored.is_some();
        let cfg = stored.unwrap_or_default();
        let uid = store.allocator(IdKind::Uid).await?;
        let gid = store.allocator(IdKind::Gid).await?;
        Ok(Some(Response::data_response(Some(config_map(&cfg, pinned, &uid, &gid)))))
    }

    pub async fn handle_config_read(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        self.config_response(&store).await
    }

    pub async fn handle_config_write(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let update = ConfigUpdate {
            uid_min: id_field(req, "uid_min")?,
            uid_max: id_field(req, "uid_max")?,
            gid_min: id_field(req, "gid_min")?,
            gid_max: id_field(req, "gid_max")?,
        };
        store.put_config(update).await?;
        self.config_response(&store).await
    }

    pub async fn handle_identity_list(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let records = store.list_identities().await?;
        let keys: Vec<String> = records.iter().map(|r| r.entity_id.clone()).collect();
        let mut info = Map::new();
        for r in &records {
            let mut m = Map::new();
            m.insert("login".into(), Value::from(r.login.clone()));
            m.insert("uid".into(), Value::from(r.uid));
            m.insert("primary_gid".into(), Value::from(r.primary_gid));
            m.insert("state".into(), Value::from(r.state.as_str()));
            info.insert(r.entity_id.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_identity_read(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let id = entity_id(req)?;
        match store.get_identity(&id).await? {
            Some(rec) => Ok(Some(Response::data_response(Some(rec.to_map())))),
            None => Err(PosixError::NotFound(format!("no workforce identity for entity `{id}`")).into()),
        }
    }

    pub async fn handle_identity_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let id = entity_id(req)?;
        let write = IdentityWrite {
            entity_id: id.clone(),
            login: str_field(req, "login")?,
            uid: id_field(req, "uid")?,
            primary_gid: id_field(req, "primary_gid")?,
            uid_source: str_field(req, "uid_source")?.map(|s| UidSource::parse(&s)).transpose()?,
            display_name: str_field(req, "display_name")?,
            gids: field(req, "gids")?.map(|v| parse_id_list("gids", &v)).transpose()?,
        };
        // A new identity must name an existing entity. Updates (and every
        // lifecycle change) stay possible after the entity itself is gone.
        if store.get_identity(&id).await?.is_none() {
            let identity = self.core.identity().ok_or_else(|| {
                bv_error_response_status!(503, "identity service unavailable; cannot verify the entity")
            })?;
            if identity.entity_profile(&id).await?.is_none() {
                return Err(PosixError::NotFound(format!("no entity `{id}` in the identity store")).into());
            }
        }
        let (rec, created) = store.create_or_update(write).await?;
        let mut data = rec.to_map();
        data.insert("created".into(), Value::from(created));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_identity_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let id = entity_id(req)?;
        let reason = str_field(req, "reason")?;
        Ok(Some(self.transition_and_propagate(&store, &id, IdentityState::Removed, reason).await?))
    }

    pub async fn handle_state_write(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.guard(req).await?;
        let id = entity_id(req)?;
        let state = str_field(req, "state")?.ok_or_else(|| PosixError::Invalid("state is required".into()))?;
        let to = IdentityState::parse(&state)?;
        let reason = str_field(req, "reason")?;
        Ok(Some(self.transition_and_propagate(&store, &id, to, reason).await?))
    }
}
