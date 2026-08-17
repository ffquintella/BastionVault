//! Identity module: user groups and application groups.
//!
//! Provides a flat grouping layer that sits between auth backends and the
//! policy subsystem. A group of kind `user` holds a list of UserPass usernames;
//! a group of kind `app` holds a list of AppRole role names. Each group also
//! carries a list of policy names; at login time those policies are unioned
//! with the caller's directly-attached policies.
//!
//! See `features/identity-groups.md` for the design document.

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use derive_more::Deref;
use serde::Deserialize;
use serde_json::{Map, Value};
use chrono::Utc;

use super::Module;
use crate::kernel_api::VaultCtx;
use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation,
        Request, Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
    bv_error_response_status, bv_error_string,
};

pub mod default_account;
pub mod entity_store;
pub mod group_store;
pub mod kernel_service;
pub mod ns_scope_migrate;
pub mod owner_store;
pub mod share_store;
pub mod ssh_security_key;
pub mod user_audit_store;
pub use default_account::{DefaultResourceAccount, DefaultResourceAccountStore};
pub use ssh_security_key::{SshSecurityKey, SshSecurityKeyStore};
pub use entity_store::{Entity, EntityStore};
pub use group_store::{GroupEntry, GroupHistoryEntry, GroupKind, GroupStore};
pub use owner_store::{OwnerRecord, OwnerStore};
pub use share_store::{
    SecretShare, ShareByGranteePointer, ShareGranteeKind, ShareStore, ShareTargetKind,
};
pub use user_audit_store::{UserAuditEntry, UserAuditStore};

/// Best-effort caller identity for audit rows.
///
/// Re-exported from `kernel_api::identity`, where it has to live so an engine
/// can stamp an audit actor without naming this module. Every engine that
/// writes an owner record or an audit row calls it.
pub use crate::kernel_api::identity::caller_audit_actor;

static IDENTITY_BACKEND_HELP: &str = r#"
The identity backend manages user groups and application groups. Each group
holds a list of members (usernames for user groups, AppID role names for
application groups) and a list of policies. At login time, policies attached
to a caller's groups are unioned with their directly-attached policies.
"#;

#[derive(Default)]
pub struct IdentityModule {
    pub name: String,
    pub core: Arc<Core>,
    pub group_store: ArcSwap<Option<Arc<GroupStore>>>,
    pub entity_store: ArcSwap<Option<Arc<EntityStore>>>,
    pub owner_store: ArcSwap<Option<Arc<OwnerStore>>>,
    pub share_store: ArcSwap<Option<Arc<ShareStore>>>,
    pub user_audit_store: ArcSwap<Option<Arc<UserAuditStore>>>,
}

pub struct IdentityBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct IdentityBackend {
    #[deref]
    pub inner: Arc<IdentityBackendInner>,
}

impl IdentityBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(IdentityBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        // Handlers for user-group CRUD
        let h_user_list = self.inner.clone();
        let h_user_read = self.inner.clone();
        let h_user_write = self.inner.clone();
        let h_user_delete = self.inner.clone();

        // Handlers for app-group CRUD
        let h_app_list = self.inner.clone();
        let h_app_read = self.inner.clone();
        let h_app_write = self.inner.clone();
        let h_app_delete = self.inner.clone();

        // History handlers
        let h_user_hist = self.inner.clone();
        let h_app_hist = self.inner.clone();

        // Sharing handlers
        let h_share_by_grantee = self.inner.clone();
        let h_share_target_list = self.inner.clone();
        let h_share_get = self.inner.clone();
        let h_share_put = self.inner.clone();
        let h_share_delete = self.inner.clone();
        let h_share_for_me = self.inner.clone();
        let h_share_for_me2 = self.inner.clone();

        // Entity + owner lookup handlers
        let h_entity_self = self.inner.clone();
        let h_entity_aliases = self.inner.clone();
        let h_entity_aliases2 = self.inner.clone();
        let h_owner_kv = self.inner.clone();
        let h_owner_resource = self.inner.clone();
        let h_owner_file = self.inner.clone();

        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: r"group/user/?$",
                    operations: [
                        {op: Operation::List, handler: h_user_list.handle_user_group_list}
                    ],
                    help: "List user group names."
                },
                {
                    pattern: r"group/user/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Group name."
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Human-readable description of the group."
                        },
                        "members": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "UserPass usernames that belong to this group."
                        },
                        "policies": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Policies attached to this group."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_user_read.handle_user_group_read},
                        {op: Operation::Write, handler: h_user_write.handle_user_group_write},
                        {op: Operation::Delete, handler: h_user_delete.handle_user_group_delete}
                    ],
                    help: "Read, create/update, or delete a user group."
                },
                {
                    pattern: r"group/app/?$",
                    operations: [
                        {op: Operation::List, handler: h_app_list.handle_app_group_list}
                    ],
                    help: "List application group names."
                },
                {
                    pattern: r"group/user/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Group name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_user_hist.handle_user_group_history}
                    ],
                    help: "Read the change history for a user group."
                },
                {
                    pattern: r"group/app/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Group name."
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Human-readable description of the group."
                        },
                        "members": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "AppID role names that belong to this group."
                        },
                        "policies": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Policies attached to this group."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_app_read.handle_app_group_read},
                        {op: Operation::Write, handler: h_app_write.handle_app_group_write},
                        {op: Operation::Delete, handler: h_app_delete.handle_app_group_delete}
                    ],
                    help: "Read, create/update, or delete an application group."
                },
                {
                    pattern: r"group/app/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Group name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_app_hist.handle_app_group_history}
                    ],
                    help: "Read the change history for an application group."
                },
                // ── Sharing ─────────────────────────────────────────
                //
                // `target` is base64url(canonical_path) so paths
                // containing '/' fit a single URL segment. `kind` is
                // "kv-secret" or "resource".
                {
                    pattern: r"sharing/by-grantee/(?P<grantee>[^/]+)/?$",
                    fields: {
                        "grantee": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Grantee entity_id."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_share_by_grantee.handle_share_by_grantee_list}
                    ],
                    help: "List every share granted to this entity."
                },
                // Caller-introspection: union of direct entity shares
                // and group shares the caller is entitled to (group
                // shares only surface when at least one of the caller's
                // policies carries `metadata { group_shared_resources
                // = \"true\" }`). Lazy-resolves the caller's entity_id
                // by alias when the token has none in metadata, so
                // pre-existing tokens don't require re-login. See
                // `features/identity-groups.md` for the policy snippet.
                {
                    pattern: r"sharing/for-me/?$",
                    operations: [
                        {op: Operation::List, handler: h_share_for_me.handle_share_for_me_list},
                        {op: Operation::Read, handler: h_share_for_me2.handle_share_for_me_list}
                    ],
                    help: "List shares granted to the caller (direct + via groups)."
                },
                {
                    pattern: r"sharing/by-target/(?P<kind>[^/]+)/(?P<target>[^/]+)/?$",
                    fields: {
                        "kind": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Target kind: kv-secret or resource."
                        },
                        "target": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "base64url(canonical-path) of the target."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_share_target_list.handle_share_by_target_list}
                    ],
                    help: "List every share granted on this target."
                },
                // ── Entity lookup (caller introspection) ────────────
                {
                    pattern: r"entity/self$",
                    operations: [
                        {op: Operation::Read, handler: h_entity_self.handle_entity_self}
                    ],
                    help: "Read the caller's own entity record (id, primary mount, aliases)."
                },
                // ── Alias list (GUI user-picker source) ──────────────
                //
                // Lists every known alias as (mount, name, entity_id)
                // so the GUI's user-picker can resolve a login to the
                // grantee_entity_id. Authorization on this route is
                // the usual ACL gate on `identity/entity/aliases`:
                // by default, unprivileged callers are denied.
                {
                    pattern: r"entity/aliases/?$",
                    operations: [
                        {op: Operation::List, handler: h_entity_aliases.handle_entity_aliases_list},
                        {op: Operation::Read, handler: h_entity_aliases2.handle_entity_aliases_list}
                    ],
                    help: "List every known (mount, name, entity_id) alias."
                },
                // ── Owner lookup (for GUI 'owner' badges) ───────────
                //
                // `path` is base64url(canonical path) for the KV case so
                // slashes fit one URL segment, matching the sharing API.
                {
                    pattern: r"owner/kv/(?P<path>[^/]+)$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "base64url(canonical KV path)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_owner_kv.handle_kv_owner_read}
                    ],
                    help: "Read the owner record for a KV secret."
                },
                {
                    pattern: r"owner/resource/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_owner_resource.handle_resource_owner_read}
                    ],
                    help: "Read the owner record for a resource."
                },
                {
                    pattern: r"owner/file/(?P<id>[^/]+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id (UUID)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_owner_file.handle_file_owner_read}
                    ],
                    help: "Read the owner record for a file resource."
                },
                {
                    pattern: r"sharing/by-target/(?P<kind>[^/]+)/(?P<target>[^/]+)/(?P<grantee>[^/]+)$",
                    fields: {
                        "kind": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Target kind: kv-secret or resource."
                        },
                        "target": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "base64url(canonical-path) of the target. When writing, `target_path` in the body overrides this."
                        },
                        "grantee": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Grantee entity_id (for grantee_kind=entity) or identity-group name (for grantee_kind=group_user / group_app)."
                        },
                        "grantee_kind": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "entity (default) | group_user | group_app. Group grantees only resolve to access when the caller is both a member of the group and carries a policy with `metadata.group_shared_resources = \"true\"`."
                        },
                        "target_kind": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Override the kind on write. Accepted values: kv-secret, resource."
                        },
                        "target_path": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Raw (non-encoded) target path on write. Overrides the URL segment."
                        },
                        "capabilities": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Capabilities the grantee is allowed: subset of read, list, update, delete, create, connect. `connect` (resources only) authorizes opening a session against the resource's credential and is never implied by read."
                        },
                        "expires_at": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Optional RFC3339 timestamp; share is inert once expired."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_share_get.handle_share_get},
                        {op: Operation::Write, handler: h_share_put.handle_share_put},
                        {op: Operation::Delete, handler: h_share_delete.handle_share_delete}
                    ],
                    help: "Read, create/update, or delete a single share."
                }
            ],
            secrets: [{
                secret_type: "identity",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: IDENTITY_BACKEND_HELP,
        });

        backend
    }
}

#[derive(Debug, Default, Deserialize)]
struct GroupWritePayload {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    members: Option<Vec<String>>,
    #[serde(default)]
    policies: Option<Vec<String>>,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Resolve the namespace a group-management request targets from its
/// `X-BastionVault-Namespace` header (canonicalised; `""` = root). Identity
/// paths are not namespace-rewritten, so the header is read directly. Groups in
/// a namespace are isolated from root and sibling namespaces.
fn group_ns_from_req(req: &Request) -> String {
    crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref())
}

/// Best-effort caller identity for audit entries. Prefers the `username`
/// metadata field (populated by UserPass login), then `auth.display_name`,
/// and falls back to `"unknown"` for root-token writes or paths where
/// auth was not resolved. Mirrors the resource module.
fn caller_username(req: &Request) -> String {
    if let Some(auth) = req.auth.as_ref() {
        if let Some(u) = auth.metadata.get("username") {
            if !u.is_empty() {
                return u.clone();
            }
        }
        if !auth.display_name.is_empty() {
            return auth.display_name.clone();
        }
    }
    "unknown".to_string()
}

/// Compute the diff between two group states. Returns the list of
/// changed field names plus two JSON maps holding the *values* of
/// exactly those fields before and after the change. `members` and
/// `policies` are compared as sets, so pure reordering is not a change.
///
/// Passing `None` for `old` represents creation; passing `None` for
/// `new` represents deletion. In both cases the "missing" side of the
/// diff is left empty.
fn diff_with_values(
    old: Option<&GroupEntry>,
    new: Option<&GroupEntry>,
) -> (Vec<String>, Map<String, Value>, Map<String, Value>) {
    let empty = GroupEntry::default();
    let o = old.unwrap_or(&empty);
    let n = new.unwrap_or(&empty);

    let mut changed: Vec<String> = Vec::new();
    let mut before = Map::new();
    let mut after = Map::new();

    if o.description != n.description {
        changed.push("description".to_string());
        if old.is_some() {
            before.insert("description".into(), Value::String(o.description.clone()));
        }
        if new.is_some() {
            after.insert("description".into(), Value::String(n.description.clone()));
        }
    }
    if !same_set(&o.members, &n.members) {
        changed.push("members".to_string());
        if old.is_some() {
            before.insert("members".into(), string_array(&o.members));
        }
        if new.is_some() {
            after.insert("members".into(), string_array(&n.members));
        }
    }
    if !same_set(&o.policies, &n.policies) {
        changed.push("policies".to_string());
        if old.is_some() {
            before.insert("policies".into(), string_array(&o.policies));
        }
        if new.is_some() {
            after.insert("policies".into(), string_array(&n.policies));
        }
    }

    (changed, before, after)
}

fn string_array(v: &[String]) -> Value {
    Value::Array(v.iter().cloned().map(Value::String).collect())
}

fn same_set(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().all(|x| b.contains(x))
}

fn group_to_response(entry: &GroupEntry, kind: GroupKind) -> Response {
    let mut data: Map<String, Value> = Map::new();
    data.insert("name".into(), Value::String(entry.name.clone()));
    data.insert("kind".into(), Value::String(kind.to_string()));
    data.insert("description".into(), Value::String(entry.description.clone()));
    data.insert(
        "members".into(),
        Value::Array(entry.members.iter().cloned().map(Value::String).collect()),
    );
    data.insert(
        "policies".into(),
        Value::Array(entry.policies.iter().cloned().map(Value::String).collect()),
    );
    data.insert("created_at".into(), Value::String(entry.created_at.clone()));
    data.insert("updated_at".into(), Value::String(entry.updated_at.clone()));
    Response::data_response(Some(data))
}

fn parse_write_payload(req: &Request) -> Result<GroupWritePayload, RvError> {
    // Accept either the typed `req.data` or the raw `req.body` JSON object.
    // Typed `req.data` is populated by the path's field declarations.
    let mut payload = GroupWritePayload::default();

    if let Ok(v) = req.get_data("description") {
        if let Some(s) = v.as_str() {
            payload.description = Some(s.to_string());
        }
    }

    if let Ok(v) = req.get_data("members") {
        payload.members = Some(value_to_string_vec(&v));
    }

    if let Ok(v) = req.get_data("policies") {
        payload.policies = Some(value_to_string_vec(&v));
    }

    Ok(payload)
}

/// Decode a base64url(no-pad) URL segment into the original path.
/// Returns `None` on any decoding failure or when the decoded bytes
/// are not valid UTF-8. Used for share API URL segments.
fn decode_b64url_path(segment: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = URL_SAFE_NO_PAD.decode(segment.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

/// Pull `(kind, target_path, grantee)` out of the URL fields on a
/// share request. Fails with a 400-ish error when any segment is
/// missing or invalid.
fn extract_share_identifiers(
    req: &Request,
) -> Result<(ShareTargetKind, String, String), RvError> {
    let kind_str = req.get_data("kind")?.as_str().unwrap_or("").to_string();
    let target_b64 = req.get_data("target")?.as_str().unwrap_or("").to_string();
    let grantee = req.get_data("grantee")?.as_str().unwrap_or("").to_string();

    let kind = ShareTargetKind::parse(&kind_str)
        .ok_or_else(|| bv_error_string!("invalid share kind"))?;
    let target_path = decode_b64url_path(&target_b64)
        .ok_or_else(|| bv_error_string!("invalid target segment (expected base64url)"))?;
    let target_path = scope_share_target(kind, target_path, req);
    if grantee.trim().is_empty() {
        return Err(bv_error_string!("grantee is required"));
    }
    Ok((kind, target_path, grantee))
}

/// Namespace-qualify a share target so it keys on the same string that
/// `post_route` stamps ownership under and that `require_share_admin` /
/// `resolve_target_shared_caps` look up.
///
/// The GUI sends mount-relative targets (`secret/github`, `db1`) with the
/// active namespace in the request header. Without this qualification a
/// child-namespace share would be stored and queried under a key that never
/// matches the owner record — and, worse for the name-keyed kinds, under the
/// *same* key as a root object of the same name, so a share granted at root
/// would unlock a tenant's `db1` and vice versa.
///
/// KV paths go through `canonicalize_kv_path_scoped` (which also strips the
/// v2 `data`/`metadata` infix); resource, file, and asset-group names go
/// through `scope_target_name`. Root (no namespace header) is a no-op for both,
/// so existing root records and callers are unaffected. Idempotent: a target
/// that already carries the namespace prefix is left as-is.
/// Inverse of [`scope_share_target`]: render a stored canonical target back in
/// the mount-relative form the caller supplied and expects to see.
///
/// Storage keys are namespace-scoped (`dti/esi/segdc1vds0005`,
/// `dti/esi/secret/github`) so two namespaces cannot collide, but that key is
/// an internal detail. Clients send — and render — mount-relative names: the
/// GUI feeds `target_path` straight back into `readResource(name)` and prints
/// it on the "Shared with me" card. Returning the raw key made every shared
/// resource unreadable (there is no resource literally named
/// `dti/esi/segdc1vds0005`) and printed the key in the UI.
///
/// Only a prefix matching the *active* namespace is stripped, so a record from
/// another namespace is never silently rewritten into a local-looking name.
fn display_share_target(target_path: &str, req: &Request) -> String {
    let Some(ns) = req
        .namespace_path
        .as_deref()
        .map(|n| n.trim().trim_matches('/'))
        .filter(|n| !n.is_empty())
    else {
        return target_path.to_string();
    };
    target_path
        .strip_prefix(&format!("{ns}/"))
        .unwrap_or(target_path)
        .to_string()
}

fn scope_share_target(kind: ShareTargetKind, target_path: String, req: &Request) -> String {
    let ns = req.namespace_path.as_deref();
    match kind {
        ShareTargetKind::KvSecret => {
            owner_store::OwnerStore::canonicalize_kv_path_scoped(&target_path, ns)
                .unwrap_or(target_path)
        }
        ShareTargetKind::Resource | ShareTargetKind::File | ShareTargetKind::AssetGroup => {
            owner_store::OwnerStore::scope_target_name(&target_path, ns).unwrap_or(target_path)
        }
    }
}

/// Render an optional `OwnerRecord` plus the inquired target into a
/// JSON object. When `rec` is `None` the response still carries the
/// target identifiers with empty owner fields so the GUI can tell
/// "not yet owned" from "lookup failed".
fn owner_response(
    kind: &str,
    target: &str,
    rec: Option<OwnerRecord>,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("target_kind".into(), Value::String(kind.to_string()));
    m.insert("target".into(), Value::String(target.to_string()));
    match rec {
        Some(r) => {
            m.insert("entity_id".into(), Value::String(r.entity_id));
            m.insert("created_at".into(), Value::String(r.created_at));
            m.insert("owned".into(), Value::Bool(true));
        }
        None => {
            m.insert("entity_id".into(), Value::String(String::new()));
            m.insert("created_at".into(), Value::String(String::new()));
            m.insert("owned".into(), Value::Bool(false));
        }
    }
    m
}

/// Render a `SecretShare` into a JSON object for HTTP responses.
fn share_to_value(share: &SecretShare, req: &Request) -> Value {
    let mut m = Map::new();
    m.insert("target_kind".into(), Value::String(share.target_kind.clone()));
    m.insert(
        "target_path".into(),
        Value::String(display_share_target(&share.target_path, req)),
    );
    m.insert(
        "grantee_kind".into(),
        Value::String(if share.grantee_kind.is_empty() {
            "entity".to_string()
        } else {
            share.grantee_kind.clone()
        }),
    );
    m.insert(
        "grantee_entity_id".into(),
        Value::String(share.grantee_entity_id.clone()),
    );
    m.insert(
        "granted_by_entity_id".into(),
        Value::String(share.granted_by_entity_id.clone()),
    );
    m.insert(
        "capabilities".into(),
        Value::Array(
            share
                .capabilities
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    m.insert("granted_at".into(), Value::String(share.granted_at.clone()));
    m.insert("expires_at".into(), Value::String(share.expires_at.clone()));
    m.insert("expired".into(), Value::Bool(share.is_expired()));
    Value::Object(m)
}

fn value_to_string_vec(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

#[maybe_async::maybe_async]
impl IdentityBackendInner {
    fn resolve_store(&self) -> Result<Arc<GroupStore>, RvError> {
        self.core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .and_then(|m| m.group_store())
            .ok_or_else(|| bv_error_string!("identity group store unavailable"))
    }

    async fn handle_group_list(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ns = group_ns_from_req(req);
        let keys = store.list_groups_ns(kind, &ns).await?;
        Ok(Some(Response::list_response(&keys)))
    }

    async fn handle_group_read(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ns = group_ns_from_req(req);
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        match store.get_group_ns(kind, &name, &ns).await? {
            Some(entry) => Ok(Some(group_to_response(&entry, kind))),
            None => Err(bv_error_response_status!(404, &format!("no {} group named: {}", kind, name))),
        }
    }

    async fn handle_group_write(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ns = group_ns_from_req(req);
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        if name.trim().is_empty() {
            return Err(bv_error_string!("group name missing"));
        }

        let payload = parse_write_payload(req)?;

        // Merge against any existing entry so partial updates preserve fields.
        let existing = store.get_group_ns(kind, &name, &ns).await?;
        let mut entry = existing.clone().unwrap_or_default();
        entry.name = name.clone();

        if let Some(d) = &payload.description {
            entry.description = d.clone();
        }
        if let Some(m) = &payload.members {
            entry.members = m.clone();
        }
        if let Some(p) = &payload.policies {
            entry.policies = p.clone();
        }

        let now = now_iso();
        if existing.is_none() {
            entry.created_at = now.clone();
        }
        entry.updated_at = now;

        // Compute changed fields *before* persisting, using the post-store
        // normalization rules so the diff matches what actually gets saved.
        let op = if existing.is_some() { "update" } else { "create" };
        let (changed_fields, before, after) =
            diff_with_values(existing.as_ref(), Some(&entry));
        let record_history = op == "create" || !changed_fields.is_empty();

        store.set_group_ns(kind, entry, &ns).await?;

        if record_history {
            let hist = GroupHistoryEntry {
                ts: now_iso(),
                user: caller_username(req),
                op: op.to_string(),
                changed_fields,
                before,
                after,
            };
            // History failures should not fail the write.
            let _ = store.append_history_ns(kind, &name, hist, &ns).await;
        }

        Ok(None)
    }

    async fn handle_group_delete(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ns = group_ns_from_req(req);
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();

        // Capture the full prior state so the delete entry retains the
        // group's final contents for audit and possible restoration.
        let previous = store.get_group_ns(kind, &name, &ns).await?;
        let (changed_fields, before, _after) = diff_with_values(previous.as_ref(), None);

        let hist = GroupHistoryEntry {
            ts: now_iso(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields,
            before,
            after: Map::new(),
        };
        let _ = store.append_history_ns(kind, &name, hist, &ns).await;

        store.delete_group_ns(kind, &name, &ns).await?;
        Ok(None)
    }

    async fn handle_group_history(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ns = group_ns_from_req(req);
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let entries = store.list_history_ns(kind, &name, &ns).await?;

        let arr = Value::Array(
            entries
                .iter()
                .map(|e| {
                    let mut m = Map::new();
                    m.insert("ts".into(), Value::String(e.ts.clone()));
                    m.insert("user".into(), Value::String(e.user.clone()));
                    m.insert("op".into(), Value::String(e.op.clone()));
                    m.insert(
                        "changed_fields".into(),
                        Value::Array(
                            e.changed_fields
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    m.insert("before".into(), Value::Object(e.before.clone()));
                    m.insert("after".into(), Value::Object(e.after.clone()));
                    Value::Object(m)
                })
                .collect(),
        );
        let mut data = Map::new();
        data.insert("entries".into(), arr);
        Ok(Some(Response::data_response(Some(data))))
    }

    // ── User-group routes ───────────────────────────────────────────

    pub async fn handle_user_group_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_list(GroupKind::User, req).await
    }

    pub async fn handle_user_group_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_read(GroupKind::User, req).await
    }

    pub async fn handle_user_group_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_write(GroupKind::User, req).await
    }

    pub async fn handle_user_group_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_delete(GroupKind::User, req).await
    }

    pub async fn handle_user_group_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_history(GroupKind::User, req).await
    }

    // ── App-group routes ────────────────────────────────────────────

    pub async fn handle_app_group_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_list(GroupKind::App, req).await
    }

    pub async fn handle_app_group_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_read(GroupKind::App, req).await
    }

    pub async fn handle_app_group_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_write(GroupKind::App, req).await
    }

    pub async fn handle_app_group_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_delete(GroupKind::App, req).await
    }

    pub async fn handle_app_group_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_history(GroupKind::App, req).await
    }

    // ── Sharing ─────────────────────────────────────────────────────

    fn resolve_share_store(&self) -> Result<Arc<ShareStore>, RvError> {
        self.core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .and_then(|m| m.share_store())
            .ok_or_else(|| bv_error_string!("share store unavailable"))
    }

    /// Authorize the caller to manage shares on `(kind, target_path)`.
    ///
    /// A token is allowed when either:
    ///   1. it carries the root or `admin` policy, or
    ///   2. its resolved entity_id matches the owner_store record for
    ///      the target (for `AssetGroup`, the `ResourceGroupStore`'s
    ///      `owner_entity_id`).
    ///
    /// All other tokens are rejected with HTTP 403 -- including those
    /// whose ACL granted them write access to the underlying resource
    /// but who do not actually own it. Sharing is an authority transfer
    /// and must originate from the data owner.
    async fn require_share_admin(
        &self,
        req: &Request,
        kind: ShareTargetKind,
        target_path: &str,
    ) -> Result<(), RvError> {
        let auth = req
            .auth
            .as_ref()
            .ok_or_else(|| bv_error_response_status!(401, "no authenticated caller"))?;

        if auth.policies.iter().any(|p| p == "root" || p == "admin") {
            return Ok(());
        }

        // Resolve the caller's entity_id with the same alias-fallback
        // used by handle_share_for_me_list / handle_entity_self, so
        // tokens issued before login-time entity provisioning landed
        // are still recognised as owners of their pre-existing data.
        let mut entity_id = auth
            .metadata
            .get("entity_id")
            .cloned()
            .unwrap_or_default();
        if entity_id.is_empty() {
            let username = auth.metadata.get("username").cloned().unwrap_or_default();
            let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();
            let mount_path = auth.metadata.get("mount_path").cloned().unwrap_or_default();
            if !mount_path.is_empty() {
                let alias_name = if !username.is_empty() { &username } else { &role_name };
                if !alias_name.is_empty() {
                    if let Some(module) = self
                        .core
                        .module_manager()
                        .get_module::<IdentityModule>("identity")
                    {
                        if let Some(es) = module.entity_store() {
                            if let Ok(e) = es
                                .get_or_create_entity(mount_path.as_str(), alias_name.as_str())
                                .await
                            {
                                entity_id = e.id;
                            }
                        }
                    }
                }
            }
        }

        if entity_id.is_empty() {
            return Err(bv_error_response_status!(
                403,
                "only the target's owner can manage its shares"
            ));
        }

        let module = self
            .core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let owner_store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        let owner = match kind {
            ShareTargetKind::KvSecret => owner_store.get_kv_owner(target_path).await?,
            ShareTargetKind::Resource => owner_store.get_resource_owner(target_path).await?,
            ShareTargetKind::File => owner_store.get_file_owner(target_path).await?,
            ShareTargetKind::AssetGroup => {
                let rg_module = self
                    .core
                    .module_manager()
                    .get_module::<crate::modules::resource_group::ResourceGroupModule>(
                        "resource-group",
                    )
                    .ok_or_else(|| bv_error_string!("resource-group module unavailable"))?;
                let rg_store = rg_module
                    .store()
                    .ok_or_else(|| bv_error_string!("resource-group store unavailable"))?;
                rg_store
                    .get_group(target_path)
                    .await?
                    .filter(|entry| !entry.owner_entity_id.is_empty())
                    .map(|entry| OwnerRecord {
                        entity_id: entry.owner_entity_id,
                        created_at: String::new(),
                    })
            }
        };

        match owner {
            Some(rec) if rec.entity_id == entity_id => Ok(()),
            _ => Err(bv_error_response_status!(
                403,
                "only the target's owner can manage its shares"
            )),
        }
    }

    pub async fn handle_share_by_grantee_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let grantee = req.get_data("grantee")?.as_str().unwrap_or("").to_string();
        // Optional body field: `"grantee_kind": "entity" | "group_user" | "group_app"`.
        // Defaults to entity for backward compatibility with the
        // original single-tenant by-grantee endpoint.
        let grantee_kind_str = req
            .get_data("grantee_kind")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let grantee_kind = ShareGranteeKind::parse(&grantee_kind_str)
            .ok_or_else(|| bv_error_string!("invalid grantee_kind"))?;
        let ptrs = store
            .list_shares_for_grantee_kinded(grantee_kind, &grantee)
            .await?;

        let mut data = Map::new();
        data.insert("grantee".into(), Value::String(grantee));
        data.insert(
            "grantee_kind".into(),
            Value::String(grantee_kind.as_str().to_string()),
        );
        data.insert(
            "entries".into(),
            Value::Array(
                ptrs.iter()
                    .map(|p| {
                        let mut m = Map::new();
                        m.insert("target_kind".into(), Value::String(p.target_kind.clone()));
                        m.insert(
                            "target_path".into(),
                            Value::String(display_share_target(&p.target_path, req)),
                        );
                        m.insert(
                            "grantee_kind".into(),
                            Value::String(if p.grantee_kind.is_empty() {
                                grantee_kind.as_str().to_string()
                            } else {
                                p.grantee_kind.clone()
                            }),
                        );
                        Value::Object(m)
                    })
                    .collect(),
            ),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Union of every share the caller is entitled to: direct entity
    /// shares, plus group shares (`group_user` / `group_app`) when the
    /// caller's effective policies include `group_shared_resources =
    /// "true"`. Group membership is determined the same way as the
    /// userpass-login flow does it (`expand_identity_group_policies`
    /// in `path_login.rs`): a case-insensitive scan of every group
    /// looking for the caller's `username` (or `role_name` for app
    /// grantees).
    pub async fn handle_share_for_me_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let auth = req
            .auth
            .as_ref()
            .ok_or_else(|| bv_error_response_status!(401, "no authenticated caller"))?;

        let mut entity_id = auth
            .metadata
            .get("entity_id")
            .cloned()
            .unwrap_or_default();
        let username = auth
            .metadata
            .get("username")
            .cloned()
            .unwrap_or_default();
        let role_name = auth
            .metadata
            .get("role_name")
            .cloned()
            .unwrap_or_default();
        let mount_path = auth
            .metadata
            .get("mount_path")
            .cloned()
            .unwrap_or_default();
        let policies: Vec<String> = auth.policies.clone();

        // Lazy entity-id resolution — matches the alias-fallback in
        // handle_entity_self so callers with pre-existing tokens still
        // see their direct shares.
        if entity_id.is_empty() && !mount_path.is_empty() {
            let alias_name = if !username.is_empty() { &username } else { &role_name };
            if !alias_name.is_empty() {
                if let Some(module) = self
                    .core
                    .module_manager()
                    .get_module::<IdentityModule>("identity")
                {
                    if let Some(es) = module.entity_store() {
                        if let Ok(e) = es.get_or_create_entity(&mount_path, alias_name).await {
                            entity_id = e.id;
                        }
                    }
                }
            }
        }

        // Walk the caller's policies looking for the opt-in metadata
        // tag. The presence of `group_shared_resources = "true"` on
        // *any* attached policy enables group-share visibility for
        // this caller; absence keeps the response set narrow.
        let mut group_shared_enabled = false;
        if let Some(pmodule) = self
            .core
            .module_manager()
            .get_module::<crate::modules::policy::PolicyModule>("policy")
        {
            let pstore = pmodule.policy_store.load();
            for name in &policies {
                if let Ok(Some(p)) = pstore
                    .get_policy(name, crate::modules::policy::policy::PolicyType::Acl)
                    .await
                {
                    if p.metadata
                        .get("group_shared_resources")
                        .map(|v| v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false)
                    {
                        group_shared_enabled = true;
                        break;
                    }
                }
            }
        }

        let mut ptrs: Vec<ShareByGranteePointer> = Vec::new();
        if !entity_id.is_empty() {
            ptrs.extend(
                store
                    .list_shares_for_grantee_kinded(ShareGranteeKind::Entity, &entity_id)
                    .await?,
            );
        }

        if group_shared_enabled {
            if let Some(imodule) = self
                .core
                .module_manager()
                .get_module::<IdentityModule>("identity")
            {
                if let Some(gs) = imodule.group_store() {
                    // User groups keyed by username; app groups keyed
                    // by role_name. We probe both independently so a
                    // token that carries either metadata flavour
                    // resolves correctly.
                    for (kind, member, gk) in [
                        (GroupKind::User, &username, ShareGranteeKind::GroupUser),
                        (GroupKind::App, &role_name, ShareGranteeKind::GroupApp),
                    ] {
                        if member.is_empty() {
                            continue;
                        }
                        let names = gs.list_groups(kind).await?;
                        let m_lc = member.trim().to_lowercase();
                        for g_name in names {
                            let Some(g) = gs.get_group(kind, &g_name).await? else {
                                continue;
                            };
                            let is_member =
                                g.members.iter().any(|m| m.trim().to_lowercase() == m_lc);
                            if !is_member {
                                continue;
                            }
                            ptrs.extend(
                                store
                                    .list_shares_for_grantee_kinded(gk, &g_name)
                                    .await?,
                            );
                        }
                    }
                }
            }
        }

        // Expand any asset-group pointers into individual
        // resource/kv-secret/file pointers. Without this the GUI
        // surfaces an opaque "asset-group" row whose Open link goes to
        // a non-existent path. The caller's ACL still gates the actual
        // open; this expansion is purely a visibility step. Asset
        // groups are read directly from the resource-group store
        // (bypassing the caller's ACL) — membership in this list
        // implies the share itself was already authorised, so the
        // member resources are by definition shared with the caller.
        if ptrs.iter().any(|p| p.target_kind == "asset-group") {
            if let Some(rg_module) = self
                .core
                .module_manager()
                .get_module::<crate::modules::resource_group::ResourceGroupModule>(
                    "resource-group",
                )
            {
                if let Some(rg_store) = rg_module.store() {
                    let mut expanded: Vec<ShareByGranteePointer> = Vec::with_capacity(ptrs.len());
                    for p in ptrs.drain(..) {
                        if p.target_kind != "asset-group" {
                            expanded.push(p);
                            continue;
                        }
                        let Some(g) = rg_store.get_group(&p.target_path).await? else {
                            continue;
                        };
                        for r in g.members {
                            expanded.push(ShareByGranteePointer {
                                target_kind: "resource".to_string(),
                                target_path: r,
                                grantee_kind: p.grantee_kind.clone(),
                            });
                        }
                        for s in g.secrets {
                            expanded.push(ShareByGranteePointer {
                                target_kind: "kv-secret".to_string(),
                                target_path: s,
                                grantee_kind: p.grantee_kind.clone(),
                            });
                        }
                        for f in g.files {
                            expanded.push(ShareByGranteePointer {
                                target_kind: "file".to_string(),
                                target_path: f,
                                grantee_kind: p.grantee_kind.clone(),
                            });
                        }
                    }
                    ptrs = expanded;
                }
            }
        }

        let mut data = Map::new();
        data.insert("entity_id".into(), Value::String(entity_id));
        data.insert(
            "group_shared_resources".into(),
            Value::Bool(group_shared_enabled),
        );
        data.insert(
            "entries".into(),
            Value::Array(
                ptrs.iter()
                    .map(|p| {
                        let mut m = Map::new();
                        m.insert("target_kind".into(), Value::String(p.target_kind.clone()));
                        m.insert(
                            "target_path".into(),
                            Value::String(display_share_target(&p.target_path, req)),
                        );
                        m.insert(
                            "grantee_kind".into(),
                            Value::String(if p.grantee_kind.is_empty() {
                                "entity".to_string()
                            } else {
                                p.grantee_kind.clone()
                            }),
                        );
                        Value::Object(m)
                    })
                    .collect(),
            ),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_share_by_target_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let kind_str = req.get_data("kind")?.as_str().unwrap_or("").to_string();
        let target_b64 = req.get_data("target")?.as_str().unwrap_or("").to_string();

        let kind = ShareTargetKind::parse(&kind_str)
            .ok_or_else(|| bv_error_string!("invalid share kind"))?;
        let target_path = decode_b64url_path(&target_b64)
            .ok_or_else(|| bv_error_string!("invalid target segment (expected base64url)"))?;
        let target_path = scope_share_target(kind, target_path, req);

        self.require_share_admin(req, kind, &target_path).await?;

        let shares = store.list_shares_for_target(kind, &target_path).await?;

        let mut data = Map::new();
        data.insert("target_kind".into(), Value::String(kind_str));
        data.insert(
            "target_path".into(),
            Value::String(display_share_target(&target_path, req)),
        );
        data.insert(
            "entries".into(),
            Value::Array(shares.iter().map(|s| share_to_value(s, req)).collect()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_share_get(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let (kind, target_path, grantee) = extract_share_identifiers(req)?;

        self.require_share_admin(req, kind, &target_path).await?;

        match store.get_share(kind, &target_path, &grantee).await? {
            Some(share) => Ok(Some(Response::data_response(Some(
                share_to_value(&share, req).as_object().cloned().unwrap_or_default(),
            )))),
            None => Err(bv_error_response_status!(
                404,
                &format!(
                    "no share found for kind={}, path={}, grantee={}",
                    kind.as_str(),
                    target_path,
                    grantee
                )
            )),
        }
    }

    pub async fn handle_share_put(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let (url_kind, url_target_path, grantee) = extract_share_identifiers(req)?;

        // Body can override kind/path with the raw (non-encoded) form.
        // Grantee is always taken from the URL.
        let kind = if let Ok(v) = req.get_data("target_kind") {
            if let Some(s) = v.as_str() {
                let s = s.trim();
                if s.is_empty() {
                    url_kind
                } else {
                    ShareTargetKind::parse(s)
                        .ok_or_else(|| bv_error_string!("invalid target_kind"))?
                }
            } else {
                url_kind
            }
        } else {
            url_kind
        };

        // A body `target_path` override arrives in raw (non-encoded) form and
        // must be namespace-qualified the same way `extract_share_identifiers`
        // qualifies the URL form (which produced `url_target_path`).
        let target_path = req
            .get_data("target_path")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .map(|p| scope_share_target(kind, p, req))
            .unwrap_or(url_target_path);

        let capabilities: Vec<String> = req
            .get_data("capabilities")
            .ok()
            .map(|v| value_to_string_vec(&v))
            .unwrap_or_default();

        let expires_at = req
            .get_data("expires_at")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let granted_by = caller_audit_actor(req);

        let grantee_kind_str = req
            .get_data("grantee_kind")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let grantee_kind = ShareGranteeKind::parse(&grantee_kind_str)
            .ok_or_else(|| bv_error_string!("invalid grantee_kind"))?;

        self.require_share_admin(req, kind, &target_path).await?;

        let share = SecretShare {
            target_kind: kind.as_str().to_string(),
            target_path,
            grantee_kind: grantee_kind.as_str().to_string(),
            grantee_entity_id: grantee,
            granted_by_entity_id: granted_by,
            capabilities,
            granted_at: String::new(),
            expires_at,
        };

        let stored = store.set_share(share).await?;
        Ok(Some(Response::data_response(Some(
            share_to_value(&stored, req).as_object().cloned().unwrap_or_default(),
        ))))
    }

    pub async fn handle_share_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let (kind, target_path, grantee) = extract_share_identifiers(req)?;

        self.require_share_admin(req, kind, &target_path).await?;

        let actor = caller_audit_actor(req);
        // Optional `grantee_kind` body field tells us which by-grantee
        // pointer prefix to clear. Absent = legacy entity grantee.
        let grantee_kind_str = req
            .get_data("grantee_kind")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let grantee_kind = ShareGranteeKind::parse(&grantee_kind_str)
            .ok_or_else(|| bv_error_string!("invalid grantee_kind"))?;
        store
            .delete_share_with_kind_audited(
                kind,
                &target_path,
                grantee_kind,
                &grantee,
                &actor,
                "revoke",
            )
            .await?;
        Ok(None)
    }

    // ── Entity + owner lookup ──────────────────────────────────────

    /// Return the caller's own entity record. Populated from the auth
    /// metadata the identity-aware login handlers stamp on the token.
    /// Useful for the GUI to decide ownership in the client (owner ==
    /// caller.entity_id) without issuing a second network round-trip.
    pub async fn handle_entity_self(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let auth = req.auth.as_ref().ok_or_else(|| {
            bv_error_response_status!(401, "no authenticated caller")
        })?;

        let mut entity_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
        let username = auth.metadata.get("username").cloned().unwrap_or_default();
        let mount_path = auth.metadata.get("mount_path").cloned().unwrap_or_default();
        let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();

        // Lazy alias-fallback: a token issued before `resolve_entity_id`
        // was wired through the login path carries no `entity_id`
        // metadata. Look the entity up by alias (mount + login name) so
        // ownership-aware UI (Sharing > Shared with me, owner-scoped
        // policies) keeps working without forcing a re-login. If the
        // alias has never been seen, materialize it now — same semantics
        // as the login-time `get_or_create_entity` call.
        if entity_id.is_empty() && !mount_path.is_empty() {
            let alias_name = if !username.is_empty() { &username } else { &role_name };
            if !alias_name.is_empty() {
                if let Some(module) = self
                    .core
                    .module_manager()
                    .get_module::<IdentityModule>("identity")
                {
                    if let Some(store) = module.entity_store() {
                        if let Ok(entity) =
                            store.get_or_create_entity(&mount_path, alias_name).await
                        {
                            entity_id = entity.id;
                        }
                    }
                }
            }
        }

        let mut data = Map::new();
        data.insert("entity_id".into(), Value::String(entity_id.clone()));
        data.insert("username".into(), Value::String(username));
        data.insert("mount_path".into(), Value::String(mount_path));
        data.insert("role_name".into(), Value::String(role_name));

        // Hydrate the stored Entity record when the identity module is
        // loaded so the caller sees their creation time and aliases.
        if !entity_id.is_empty() {
            if let Some(module) = self
                .core
                .module_manager()
                .get_module::<IdentityModule>("identity")
            {
                if let Some(store) = module.entity_store() {
                    if let Ok(Some(entity)) = store.get_entity(&entity_id).await {
                        data.insert(
                            "primary_mount".into(),
                            Value::String(entity.primary_mount),
                        );
                        data.insert(
                            "primary_name".into(),
                            Value::String(entity.primary_name),
                        );
                        data.insert(
                            "created_at".into(),
                            Value::String(entity.created_at),
                        );
                        data.insert(
                            "aliases".into(),
                            Value::Array(
                                entity
                                    .aliases
                                    .into_iter()
                                    .map(|a| {
                                        let mut m = Map::new();
                                        m.insert(
                                            "mount".into(),
                                            Value::String(a.mount),
                                        );
                                        m.insert("name".into(), Value::String(a.name));
                                        Value::Object(m)
                                    })
                                    .collect(),
                            ),
                        );
                    }
                }
            }
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    /// List every known alias tuple. Used by the GUI's user-picker
    /// to resolve a login (mount + username / role name) to the
    /// grantee's `entity_id` when granting shares.
    pub async fn handle_entity_aliases_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let module = self
            .core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .entity_store()
            .ok_or_else(|| bv_error_string!("entity store unavailable"))?;

        let ns = group_ns_from_req(req);
        let aliases = store.list_aliases_ns(&ns).await?;
        let arr = Value::Array(
            aliases
                .iter()
                .map(|a| {
                    let mut m = Map::new();
                    m.insert("mount".into(), Value::String(a.mount.clone()));
                    m.insert("name".into(), Value::String(a.name.clone()));
                    m.insert("entity_id".into(), Value::String(a.entity_id.clone()));
                    Value::Object(m)
                })
                .collect(),
        );
        let mut data = Map::new();
        data.insert("aliases".into(), arr);
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_kv_owner_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path_b64 = req.get_data("path")?.as_str().unwrap_or("").to_string();
        let path = decode_b64url_path(&path_b64)
            .ok_or_else(|| bv_error_string!("invalid path segment (expected base64url)"))?;

        let module = self
            .core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        // The GUI sends the mount-relative path (`secret/github`) with the
        // active namespace in the request header. Look the owner up under the
        // namespace-scoped canonical key so a child-namespace secret's owner —
        // stamped as `<ns>/<mount>/<key>` by `post_route` — is found. The
        // mount-relative `path` is still echoed for display.
        let key = owner_store::OwnerStore::canonicalize_kv_path_scoped(
            &path,
            req.namespace_path.as_deref(),
        )
        .unwrap_or_else(|| path.clone());
        let rec = store.get_kv_owner(&key).await?;
        Ok(Some(Response::data_response(Some(owner_response(
            "kv-secret",
            &path,
            rec,
        )))))
    }

    pub async fn handle_resource_owner_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();

        let module = self
            .core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        // Namespace-scope the lookup key for the same reason the KV read
        // above does: the record lives under `<ns>/<name>` in a namespace, and
        // a bare lookup would return the *root* resource of that name. The
        // mount-relative name is still echoed for display.
        let key = owner_store::OwnerStore::scope_target_name(&name, req.namespace_path.as_deref())
            .unwrap_or_else(|| name.clone());
        let rec = store.get_resource_owner(&key).await?;
        Ok(Some(Response::data_response(Some(owner_response(
            "resource", &name, rec,
        )))))
    }

    pub async fn handle_file_owner_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.get_data("id")?.as_str().unwrap_or("").to_string();

        let module = self
            .core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        let key = owner_store::OwnerStore::scope_target_name(&id, req.namespace_path.as_deref())
            .unwrap_or_else(|| id.clone());
        let rec = store.get_file_owner(&key).await?;
        Ok(Some(Response::data_response(Some(owner_response(
            "file", &id, rec,
        )))))
    }

    pub async fn handle_noop(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl IdentityModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "identity".to_string(),
            core,
            group_store: ArcSwap::new(Arc::new(None)),
            entity_store: ArcSwap::new(Arc::new(None)),
            owner_store: ArcSwap::new(Arc::new(None)),
            share_store: ArcSwap::new(Arc::new(None)),
            user_audit_store: ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn group_store(&self) -> Option<Arc<GroupStore>> {
        self.group_store.load().as_ref().clone()
    }

    pub fn entity_store(&self) -> Option<Arc<EntityStore>> {
        self.entity_store.load().as_ref().clone()
    }

    pub fn owner_store(&self) -> Option<Arc<OwnerStore>> {
        self.owner_store.load().as_ref().clone()
    }

    pub fn share_store(&self) -> Option<Arc<ShareStore>> {
        self.share_store.load().as_ref().clone()
    }

    pub fn user_audit_store(&self) -> Option<Arc<UserAuditStore>> {
        self.user_audit_store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for IdentityModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        // Register the logical backend factory so the `identity/` mount can
        // bind on first unseal, before the per-module `init` runs. The backend
        // resolves the group store lazily via the module manager.
        let core_for_backend = self.core.clone();
        let backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            // This backend is not on `VaultCtx` yet, so it needs the concrete
            // `Core`. Captured from the module rather than taken from the
            // parameter: there is exactly one `Core` per server, so it is the
            // same value, and this keeps the retype from cascading.
            let mut b = IdentityBackend::new(core_for_backend.clone()).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("identity", Arc::new(backend_new_func))
    }

    async fn init(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        let gs = GroupStore::new(&self.core).await?;
        self.group_store.store(Arc::new(Some(gs)));
        let es = EntityStore::new(&self.core).await?;
        self.entity_store.store(Arc::new(Some(es)));
        let os = OwnerStore::new(&self.core).await?;
        self.owner_store.store(Arc::new(Some(os)));
        let ss = ShareStore::new(&self.core).await?;
        self.share_store.store(Arc::new(Some(ss)));
        let uas = UserAuditStore::new(&self.core).await?;
        self.user_audit_store.store(Arc::new(Some(uas)));
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        self.group_store.store(Arc::new(None));
        self.entity_store.store(Arc::new(None));
        self.owner_store.store(Arc::new(None));
        self.share_store.store(Arc::new(None));
        self.user_audit_store.store(Arc::new(None));
        core.delete_logical_backend("identity")
    }
}



