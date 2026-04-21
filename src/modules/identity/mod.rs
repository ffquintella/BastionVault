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

pub mod entity_store;
pub mod group_store;
pub mod owner_store;
pub mod share_store;
pub use entity_store::{Entity, EntityStore};
pub use group_store::{GroupEntry, GroupHistoryEntry, GroupKind, GroupStore};
pub use owner_store::{OwnerRecord, OwnerStore};
pub use share_store::{SecretShare, ShareByGranteePointer, ShareStore, ShareTargetKind};

static IDENTITY_BACKEND_HELP: &str = r#"
The identity backend manages user groups and application groups. Each group
holds a list of members (usernames for user groups, AppRole role names for
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

        // Entity + owner lookup handlers
        let h_entity_self = self.inner.clone();
        let h_entity_aliases = self.inner.clone();
        let h_entity_aliases2 = self.inner.clone();
        let h_owner_kv = self.inner.clone();
        let h_owner_resource = self.inner.clone();

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
                            description: "AppRole role names that belong to this group."
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
                            description: "Grantee entity_id."
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
                            description: "Capabilities the grantee is allowed: subset of read, list, update, delete, create."
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
    if grantee.trim().is_empty() {
        return Err(bv_error_string!("grantee is required"));
    }
    Ok((kind, target_path, grantee))
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
fn share_to_value(share: &SecretShare) -> Value {
    let mut m = Map::new();
    m.insert("target_kind".into(), Value::String(share.target_kind.clone()));
    m.insert("target_path".into(), Value::String(share.target_path.clone()));
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
            .module_manager
            .get_module::<IdentityModule>("identity")
            .and_then(|m| m.group_store())
            .ok_or_else(|| bv_error_string!("identity group store unavailable"))
    }

    async fn handle_group_list(
        &self,
        kind: GroupKind,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let keys = store.list_groups(kind).await?;
        Ok(Some(Response::list_response(&keys)))
    }

    async fn handle_group_read(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        match store.get_group(kind, &name).await? {
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
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        if name.trim().is_empty() {
            return Err(bv_error_string!("group name missing"));
        }

        let payload = parse_write_payload(req)?;

        // Merge against any existing entry so partial updates preserve fields.
        let existing = store.get_group(kind, &name).await?;
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

        store.set_group(kind, entry).await?;

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
            let _ = store.append_history(kind, &name, hist).await;
        }

        Ok(None)
    }

    async fn handle_group_delete(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();

        // Capture the full prior state so the delete entry retains the
        // group's final contents for audit and possible restoration.
        let previous = store.get_group(kind, &name).await?;
        let (changed_fields, before, _after) = diff_with_values(previous.as_ref(), None);

        let hist = GroupHistoryEntry {
            ts: now_iso(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields,
            before,
            after: Map::new(),
        };
        let _ = store.append_history(kind, &name, hist).await;

        store.delete_group(kind, &name).await?;
        Ok(None)
    }

    async fn handle_group_history(
        &self,
        kind: GroupKind,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let entries = store.list_history(kind, &name).await?;

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
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_list(GroupKind::User).await
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
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.handle_group_list(GroupKind::App).await
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
            .module_manager
            .get_module::<IdentityModule>("identity")
            .and_then(|m| m.share_store())
            .ok_or_else(|| bv_error_string!("share store unavailable"))
    }

    pub async fn handle_share_by_grantee_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let grantee = req.get_data("grantee")?.as_str().unwrap_or("").to_string();
        let ptrs = store.list_shares_for_grantee(&grantee).await?;

        let mut data = Map::new();
        data.insert("grantee".into(), Value::String(grantee));
        data.insert(
            "entries".into(),
            Value::Array(
                ptrs.iter()
                    .map(|p| {
                        let mut m = Map::new();
                        m.insert("target_kind".into(), Value::String(p.target_kind.clone()));
                        m.insert("target_path".into(), Value::String(p.target_path.clone()));
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

        let shares = store.list_shares_for_target(kind, &target_path).await?;

        let mut data = Map::new();
        data.insert("target_kind".into(), Value::String(kind_str));
        data.insert("target_path".into(), Value::String(target_path));
        data.insert(
            "entries".into(),
            Value::Array(shares.iter().map(share_to_value).collect()),
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

        match store.get_share(kind, &target_path, &grantee).await? {
            Some(share) => Ok(Some(Response::data_response(Some(
                share_to_value(&share).as_object().cloned().unwrap_or_default(),
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

        let target_path = req
            .get_data("target_path")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
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

        let granted_by = req
            .auth
            .as_ref()
            .and_then(|a| a.metadata.get("entity_id"))
            .cloned()
            .unwrap_or_default();

        let share = SecretShare {
            target_kind: kind.as_str().to_string(),
            target_path,
            grantee_entity_id: grantee,
            granted_by_entity_id: granted_by,
            capabilities,
            granted_at: String::new(),
            expires_at,
        };

        let stored = store.set_share(share).await?;
        Ok(Some(Response::data_response(Some(
            share_to_value(&stored).as_object().cloned().unwrap_or_default(),
        ))))
    }

    pub async fn handle_share_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_share_store()?;
        let (kind, target_path, grantee) = extract_share_identifiers(req)?;
        store.delete_share(kind, &target_path, &grantee).await?;
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

        let entity_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
        let username = auth.metadata.get("username").cloned().unwrap_or_default();
        let mount_path = auth.metadata.get("mount_path").cloned().unwrap_or_default();
        let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();

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
                .module_manager
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
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .entity_store()
            .ok_or_else(|| bv_error_string!("entity store unavailable"))?;

        let aliases = store.list_aliases().await?;
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
            .module_manager
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        let rec = store.get_kv_owner(&path).await?;
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
            .module_manager
            .get_module::<IdentityModule>("identity")
            .ok_or_else(|| bv_error_string!("identity module unavailable"))?;
        let store = module
            .owner_store()
            .ok_or_else(|| bv_error_string!("owner store unavailable"))?;

        let rec = store.get_resource_owner(&name).await?;
        Ok(Some(Response::data_response(Some(owner_response(
            "resource", &name, rec,
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
}

#[maybe_async::maybe_async]
impl Module for IdentityModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        // Register the logical backend factory so the `identity/` mount can
        // bind on first unseal, before the per-module `init` runs. The backend
        // resolves the group store lazily via the module manager.
        let backend_new_func = move |c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = IdentityBackend::new(c).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("identity", Arc::new(backend_new_func))
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let gs = GroupStore::new(core).await?;
        self.group_store.store(Arc::new(Some(gs)));
        let es = EntityStore::new(core).await?;
        self.entity_store.store(Arc::new(Some(es)));
        let os = OwnerStore::new(core).await?;
        self.owner_store.store(Arc::new(Some(os)));
        let ss = ShareStore::new(core).await?;
        self.share_store.store(Arc::new(Some(ss)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.group_store.store(Arc::new(None));
        self.entity_store.store(Arc::new(None));
        self.owner_store.store(Arc::new(None));
        self.share_store.store(Arc::new(None));
        core.delete_logical_backend("identity")
    }
}

#[cfg(test)]
mod identity_tests {
    use serde_json::json;

    use super::*;
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api,
        test_write_api,
    };

    /// Regression: a userpass user that has never logged in must
    /// still appear in the alias list that drives the GUI user-picker.
    /// Before the pre-provision hook in `write_user`, the alias was
    /// only created on first login, so admins couldn't grant shares
    /// to a freshly-created user until after they authenticated once.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_userpass_create_preprovisions_entity_alias() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_userpass_create_preprovisions_entity_alias").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/pass/users/felipe",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "default",
            })
            .as_object()
            .cloned(),
        )
        .await
        .unwrap();

        // The aliases list — which the GUI reads — must now contain
        // felipe even though felipe has never logged in.
        let resp = test_read_api(&core, &root_token, "identity/entity/aliases", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        let arr = body.get("aliases").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let has_felipe = arr.iter().any(|v| {
            let o = v.as_object();
            o.and_then(|o| o.get("name").and_then(|v| v.as_str())) == Some("felipe")
                && o.and_then(|o| o.get("mount").and_then(|v| v.as_str())) == Some("userpass/")
                && o.and_then(|o| o.get("entity_id").and_then(|v| v.as_str()))
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
        });
        assert!(
            has_felipe,
            "freshly-created userpass user should appear in the alias list: {arr:?}",
        );

        // Delete the user → alias disappears from the list (entity
        // record itself stays so audit trails are preserved, but the
        // (mount,name) lookup is gone).
        let _ = test_delete_api(&core, &root_token, "auth/pass/users/felipe", true, None).await;

        let resp = test_read_api(&core, &root_token, "identity/entity/aliases", true)
            .await
            .unwrap()
            .unwrap();
        let body = resp.data.unwrap();
        let arr = body.get("aliases").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let still_there = arr.iter().any(|v| {
            v.as_object()
                .and_then(|o| o.get("name").and_then(|v| v.as_str()))
                == Some("felipe")
        });
        assert!(!still_there, "delete-user should forget the alias: {arr:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_store_roundtrip_and_cascade() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_share_store_roundtrip_and_cascade").await;

        let store = ShareStore::new(&core).await.unwrap();

        // Create a KV-secret share for grantee 'ent-bob' on 'secret/foo'.
        let share = SecretShare {
            target_kind: "kv-secret".into(),
            target_path: "secret/foo".into(),
            grantee_entity_id: "ent-bob".into(),
            granted_by_entity_id: "ent-alice".into(),
            capabilities: vec!["read".into(), "list".into()],
            granted_at: String::new(),
            expires_at: String::new(),
        };
        let stored = store.set_share(share).await.unwrap();
        assert_eq!(stored.capabilities, vec!["read".to_string(), "list".to_string()]);

        // Round-trip read.
        let got = store
            .get_share(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got.is_some(), "share should be readable by (kind, path, grantee)");

        // KV-v2 path form resolves to the same canonical key.
        let got_v2 = store
            .get_share(ShareTargetKind::KvSecret, "secret/data/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got_v2.is_some(), "v2 `secret/data/foo` should canonicalize to `secret/foo`");

        // shared_capabilities returns the stored list.
        let caps = store
            .shared_capabilities(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert_eq!(caps, vec!["read".to_string(), "list".to_string()]);

        // by-grantee lookup returns one pointer.
        let ptrs = store.list_shares_for_grantee("ent-bob").await.unwrap();
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].target_kind, "kv-secret");
        assert_eq!(ptrs[0].target_path, "secret/foo");

        // by-target lookup returns one share.
        let shares = store
            .list_shares_for_target(ShareTargetKind::KvSecret, "secret/foo")
            .await
            .unwrap();
        assert_eq!(shares.len(), 1);

        // Cascade delete drops the share, reverse pointer, and capabilities.
        let removed = store
            .cascade_delete_target(ShareTargetKind::KvSecret, "secret/foo")
            .await
            .unwrap();
        assert_eq!(removed, 1);

        let got = store
            .get_share(ShareTargetKind::KvSecret, "secret/foo", "ent-bob")
            .await
            .unwrap();
        assert!(got.is_none());
        let ptrs = store.list_shares_for_grantee("ent-bob").await.unwrap();
        assert!(ptrs.is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_share_store_rejects_invalid_inputs() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_share_store_rejects_invalid_inputs").await;
        let store = ShareStore::new(&core).await.unwrap();

        // Empty grantee → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "".into(),
                capabilities: vec!["read".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Empty capabilities → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec![],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Unknown capability is filtered out; if nothing remains → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec!["sudo".into(), "deny".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());

        // Bad target_kind → error.
        let err = store
            .set_share(SecretShare {
                target_kind: "not-a-kind".into(),
                target_path: "secret/foo".into(),
                grantee_entity_id: "ent-x".into(),
                capabilities: vec!["read".into()],
                ..Default::default()
            })
            .await;
        assert!(err.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_user_group_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_user_group_crud").await;

        // Create a user group with members and policies.
        let data = json!({
            "description": "platform engineers",
            "members": "alice,bob",
            "policies": "ops,readonly",
        })
        .as_object()
        .cloned();
        let ret = test_write_api(&core, &root_token, "identity/group/user/platform", true, data).await;
        assert!(ret.is_ok());

        // Read it back.
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["name"], "platform");
        assert_eq!(data["kind"], "user");
        assert_eq!(data["description"], "platform engineers");
        assert_eq!(data["members"], json!(["alice", "bob"]));
        assert_eq!(data["policies"], json!(["ops", "readonly"]));

        // List.
        let resp = test_list_api(&core, &root_token, "identity/group/user", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["platform"]));

        // Partial update (members only) preserves other fields.
        let patch = json!({ "members": "alice,bob,carol" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "identity/group/user/platform", true, patch).await;
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["members"], json!(["alice", "bob", "carol"]));
        assert_eq!(data["policies"], json!(["ops", "readonly"]));

        // Delete.
        let _ = test_delete_api(&core, &root_token, "identity/group/user/platform", true, None).await;
        let resp = test_read_api(&core, &root_token, "identity/group/user/platform", false).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_app_group_isolated_from_user_group() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_app_group_isolated_from_user_group").await;

        let app_data = json!({
            "members": "payments-api,billing-api",
            "policies": "app-readonly",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "identity/group/app/services", true, app_data).await;

        // Listing user groups must not see the app group.
        let resp = test_list_api(&core, &root_token, "identity/group/user", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data.get("keys").cloned().unwrap_or(json!([])), json!([] as [String; 0]));

        // Listing app groups sees it.
        let resp = test_list_api(&core, &root_token, "identity/group/app", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["services"]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_group_policy_expansion_at_login() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_group_policy_expansion_at_login").await;

        // Define two policies: one attached directly to the user, one via group.
        let direct_hcl = r#"
            path "path1/direct" {
                capabilities = ["read", "create", "update"]
            }
        "#;
        let group_hcl = r#"
            path "path1/group-only" {
                capabilities = ["read", "create", "update"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-direct",
            true,
            json!({ "policy": direct_hcl }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-group",
            true,
            json!({ "policy": group_hcl }).as_object().cloned(),
        )
        .await;

        // Mount userpass and create user with only the direct policy.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/pass/users/alice",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "p-direct",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Mount kv so the policies apply to a real path.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/path1/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;

        // Login and capture the token.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;

        // Without group membership: direct path works, group path denied.
        let _ = test_write_api(
            &core,
            &token,
            "path1/direct",
            true,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        let err = test_write_api(
            &core,
            &token,
            "path1/group-only",
            false,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        assert!(err.is_err());

        // Add alice to a user-group that grants p-group.
        let _ = test_write_api(
            &core,
            &root_token,
            "identity/group/user/platform",
            true,
            json!({
                "members": "alice",
                "policies": "p-group",
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Re-login to pick up new policies; group path must now work.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token2 = resp.auth.unwrap().client_token;

        let _ = test_write_api(
            &core,
            &token2,
            "path1/group-only",
            true,
            json!({ "v": "2" }).as_object().cloned(),
        )
        .await;
        // Direct path still works too.
        let _ = test_write_api(
            &core,
            &token2,
            "path1/direct",
            true,
            json!({ "v": "3" }).as_object().cloned(),
        )
        .await;
    }

    // ── Per-user scoping tests ─────────────────────────────────────

    /// Alice writes a secret; Bob (secret-author policy) cannot read
    /// it because the `scopes = ["owner", "shared"]` filter denies
    /// access to non-owned entries without a share. Alice herself
    /// reads her own secret fine.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_per_user_scoping_owner_denies_non_owner() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_per_user_scoping_owner_denies_non_owner").await;

        // The default `secret/` mount is KV-v2; the seeded
        // `secret-author` policy grants CRUD on `secret/data/*` with
        // `scopes=["owner","shared"]`.
        //
        // Userpass with two users, both assigned `secret-author`.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        for name in ["alice", "bob"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("auth/pass/users/{name}"),
                true,
                json!({
                    "password": "hunter22XX!",
                    "token_policies": "secret-author",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
            )
            .await;
        }

        // Login as alice and write a KV-v2 secret under secret/data/.
        let alice_token = login_pass(&core, "alice").await;
        let _ = test_write_api(
            &core,
            &alice_token,
            "secret/data/alice-secret",
            true,
            json!({ "data": { "v": "hello" } }).as_object().cloned(),
        )
        .await;

        // Alice can read her own secret (owner match).
        let _ = test_read_api(&core, &alice_token, "secret/data/alice-secret", true).await;

        // Bob with secret-author cannot read alice's secret: the
        // scopes=["owner","shared"] filter denies him because he is
        // not the owner and no share exists.
        let bob_token = login_pass(&core, "bob").await;
        let err = test_read_api(&core, &bob_token, "secret/data/alice-secret", false).await;
        assert!(err.is_err(), "bob should be denied on alice's secret");
    }

    /// `secret-author` grants full CRUD on KV secrets the caller owns.
    /// A non-root user can write, read, update, and delete their own
    /// secret end-to-end.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_secret_author_full_crud_on_owned_secret() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_secret_author_full_crud_on_owned_secret").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "auth/pass/users/carol",
            true,
            json!({
                "password": "hunter22XX!",
                "token_policies": "secret-author",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        let carol_token = login_pass(&core, "carol").await;

        // Write: carol becomes owner on the first write.
        let _ = test_write_api(
            &core,
            &carol_token,
            "secret/data/carol-db",
            true,
            json!({ "data": { "v": "pw1" } }).as_object().cloned(),
        )
        .await;
        // Read own.
        let _ = test_read_api(&core, &carol_token, "secret/data/carol-db", true).await;
        // Update own (same path, new value).
        let _ = test_write_api(
            &core,
            &carol_token,
            "secret/data/carol-db",
            true,
            json!({ "data": { "v": "pw2" } }).as_object().cloned(),
        )
        .await;
        // Delete own.
        let _ = test_delete_api(&core, &carol_token, "secret/data/carol-db", true, None).await;
    }

    /// `secret-author` listing a KV mount sees only their own
    /// entries. Alice writes two secrets, bob writes one; bob lists
    /// and only sees bob's own key.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_list_filter_by_ownership() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_list_filter_by_ownership").await;

        let _ = test_write_api(
            &core,
            &root_token,
            "sys/auth/pass",
            true,
            json!({ "type": "userpass" }).as_object().cloned(),
        )
        .await;
        for name in ["alice", "bob"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("auth/pass/users/{name}"),
                true,
                json!({
                    "password": "hunter22XX!",
                    "token_policies": "secret-author",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
            )
            .await;
        }

        // Alice writes two secrets on the default KV-v2 mount.
        let alice_token = login_pass(&core, "alice").await;
        for k in ["a1", "a2"] {
            let _ = test_write_api(
                &core,
                &alice_token,
                &format!("secret/data/{k}"),
                true,
                json!({ "data": { "v": "x" } }).as_object().cloned(),
            )
            .await;
        }

        // Bob writes one.
        let bob_token = login_pass(&core, "bob").await;
        let _ = test_write_api(
            &core,
            &bob_token,
            "secret/data/b1",
            true,
            json!({ "data": { "v": "x" } }).as_object().cloned(),
        )
        .await;

        // Bob listing the secret metadata index sees only "b1" —
        // a1/a2 are alice-owned and get filtered out by the
        // scopes=["owner","shared"] list gate.
        let resp = test_list_api(&core, &bob_token, "secret/metadata/", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let keys: Vec<&str> = data["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(keys.contains(&"b1"), "bob should see his own key in {keys:?}");
        assert!(!keys.contains(&"a1"), "bob should not see a1 in {keys:?}");
        assert!(!keys.contains(&"a2"), "bob should not see a2 in {keys:?}");
    }

    /// Helper: login via userpass with the shared password used
    /// across per-user-scoping tests.
    #[cfg(test)]
    async fn login_pass(core: &Core, username: &str) -> String {
        let mut login_req = Request::new(format!("auth/pass/login/{username}"));
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        resp.auth.unwrap().client_token
    }
}

