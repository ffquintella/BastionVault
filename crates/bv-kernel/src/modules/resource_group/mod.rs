//! Resource-group module: named collections of resources.
//!
//! A resource-group bundles a list of resource names under a human
//! meaningful label ("project-phoenix", "office-routers"). The store
//! maintains a reverse index so authorization checks and GUI filtering
//! can look up "which groups is this resource in?" in O(1) per resource.
//!
//! This is the resource-scoped subset of the broader asset-groups design
//! (see `features/asset-groups.md`): it implements the data model, CRUD,
//! reverse index, lifecycle-prune hook, history, and HTTP API, but does
//! *not* yet extend the ACL grammar with a `groups = [...]` qualifier —
//! that phase is tracked in the asset-groups roadmap and will land when
//! the policy evaluator is ready for it.
//!
//! See `features/resource-groups.md` for the design document.

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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

pub mod group_store;
pub mod kernel_service;
pub use group_store::{ResourceGroupEntry, ResourceGroupHistoryEntry, ResourceGroupStore};

/// Sentinel returned in the `members` / `secrets` list when the caller
/// has group-read access but not read access on an individual member.
/// Keeps group cardinality truthful without leaking paths.
pub const REDACTED_MEMBER: &str = "<hidden>";

static RESOURCE_GROUP_BACKEND_HELP: &str = r#"
The resource-group backend manages named collections of resources. Each
group holds a list of resource names and carries a change-history log.
A reverse index maps each resource to the groups it belongs to so the
"which groups contain this resource?" lookup stays cheap.
"#;

#[derive(Default)]
pub struct ResourceGroupModule {
    pub name: String,
    pub core: Arc<Core>,
    pub store: ArcSwap<Option<Arc<ResourceGroupStore>>>,
}

pub struct ResourceGroupBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct ResourceGroupBackend {
    #[deref]
    pub inner: Arc<ResourceGroupBackendInner>,
}

impl ResourceGroupBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(ResourceGroupBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_list = self.inner.clone();
        let h_read = self.inner.clone();
        let h_write = self.inner.clone();
        let h_delete = self.inner.clone();
        let h_hist = self.inner.clone();
        let h_by_res = self.inner.clone();
        let h_by_secret = self.inner.clone();
        let h_reindex = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: r"groups/?$",
                    operations: [
                        {op: Operation::List, handler: h_list.handle_list}
                    ],
                    help: "List resource-group names."
                },
                {
                    pattern: r"groups/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource-group name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_hist.handle_history}
                    ],
                    help: "Read the change history for a resource group."
                },
                {
                    pattern: r"groups/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource-group name."
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Human-readable description of the group."
                        },
                        "members": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Resource names that belong to this group."
                        },
                        "secrets": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "KV-secret paths that belong to this group. Accepts either the logical form (secret/foo/bar) or the KV-v2 API form (secret/data/foo/bar); stored canonicalized."
                        },
                        "files": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "File-resource ids (UUIDs from `files/files`) that belong to this group."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_read.handle_read},
                        {op: Operation::Write, handler: h_write.handle_write},
                        {op: Operation::Delete, handler: h_delete.handle_delete}
                    ],
                    help: "Read, create/update, or delete a resource group."
                },
                {
                    pattern: r"by-resource/(?P<resource>[^/]+)$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_by_res.handle_by_resource}
                    ],
                    help: "List the resource groups that currently contain a given resource."
                },
                {
                    // Reverse lookup for KV-secret membership. The `path`
                    // is a base64url-encoded (no padding) KV path, so
                    // the '/' characters in the path don't clash with
                    // the URL's path separators. Callers may encode
                    // either the canonical form or the KV-v2 API form —
                    // the handler canonicalizes both sides before
                    // consulting the secret-index.
                    pattern: r"by-secret/(?P<path>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "base64url(no-pad) encoded KV-secret path."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_by_secret.handle_by_secret}
                    ],
                    help: "List the resource groups that currently contain a given KV-secret path. The `path` segment is base64url(no-pad)-encoded to avoid ambiguity with URL path separators."
                },
                {
                    pattern: r"reindex$",
                    operations: [
                        {op: Operation::Write, handler: h_reindex.handle_reindex}
                    ],
                    help: "Rebuild the reverse membership index from the primary records. Admin-only."
                }
            ],
            secrets: [{
                secret_type: "resource-group",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: RESOURCE_GROUP_BACKEND_HELP,
        });

        backend
    }
}

#[derive(Debug, Default, Deserialize)]
struct WritePayload {
    #[serde(default)]
    description: Option<String>,
    /// Resource names. `None` means "don't touch"; `Some(vec)` replaces
    /// the stored list wholesale (partial updates use a separate call).
    #[serde(default)]
    members: Option<Vec<String>>,
    /// KV-secret paths. Same semantics as `members`.
    #[serde(default)]
    secrets: Option<Vec<String>>,
    /// File-resource ids (UUIDs). Same semantics as `members`.
    #[serde(default)]
    files: Option<Vec<String>>,
}

/// Replace each member in `entry.members` / `entry.secrets` with the
/// `REDACTED_MEMBER` sentinel when `auth` does not have `Read` access
/// on the corresponding target path. The owner and admin short-circuit
/// (which bypasses this helper entirely) avoids the per-member cost
/// for the common case where a caller sees their own groups in full.
///
/// Silent on any probe failure: if the policy module or subsystem is
/// unavailable, the helper returns without modifying the entry, which
/// preserves the pre-redaction behavior. Callers who want fail-closed
/// behavior should guard at the handler level.
async fn redact_inaccessible_members(
    core: &Arc<Core>,
    auth: &crate::logical::Auth,
    entry: &mut ResourceGroupEntry,
) {
    use crate::modules::policy::PolicyModule;

    let Some(policy_module) = core.module_manager().get_module::<PolicyModule>("policy") else {
        return;
    };
    let store = policy_module.policy_store.load();

    // Resource members — probe `resources/resources/<name>`.
    for m in entry.members.iter_mut() {
        if m == REDACTED_MEMBER {
            continue;
        }
        let path = format!("resources/resources/{m}");
        if !store.can_operate(auth, &path, Operation::Read, None).await {
            *m = REDACTED_MEMBER.to_string();
        }
    }

    // KV-secret members — stored in canonical logical form (no
    // `data/` / `metadata/` segment). Policies on KV-v2 mounts are
    // usually written against the v2 `<mount>/data/...` form, so we
    // probe both shapes and consider the member visible if either
    // check allows `Read`. Cheap on the common case (first probe
    // matches).
    for s in entry.secrets.iter_mut() {
        if s == REDACTED_MEMBER {
            continue;
        }
        let allowed = store.can_operate(auth, s, Operation::Read, None).await
            || store
                .can_operate(auth, &kv_v2_data_form(s), Operation::Read, None)
                .await;
        if !allowed {
            *s = REDACTED_MEMBER.to_string();
        }
    }
}

/// Rewrite a canonical KV path (e.g., `secret/foo/bar`) into the
/// KV-v2 API form (`secret/data/foo/bar`) for authorization probes.
/// Returns the input unchanged when it already contains `/data/` or
/// has no segments to insert into.
fn kv_v2_data_form(canonical: &str) -> String {
    let trimmed = canonical.trim_matches('/');
    match trimmed.split_once('/') {
        Some((head, rest)) if !rest.starts_with("data/") && !rest.starts_with("metadata/") => {
            format!("{head}/data/{rest}")
        }
        _ => canonical.to_string(),
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Best-effort caller identity for audit entries. Mirrors the identity
/// module: prefer `auth.metadata["username"]`, then `auth.display_name`,
/// then `"unknown"`.
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

/// Compute before/after diffs for `description` and `members`. `members`
/// is compared as a set so pure reordering is not recorded as a change.
/// Passing `None` for one side represents creation/deletion; the missing
/// side's map is left empty.
fn diff_with_values(
    old: Option<&ResourceGroupEntry>,
    new: Option<&ResourceGroupEntry>,
) -> (Vec<String>, Map<String, Value>, Map<String, Value>) {
    let empty = ResourceGroupEntry::default();
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
    if !same_set(&o.secrets, &n.secrets) {
        changed.push("secrets".to_string());
        if old.is_some() {
            before.insert("secrets".into(), string_array(&o.secrets));
        }
        if new.is_some() {
            after.insert("secrets".into(), string_array(&n.secrets));
        }
    }
    if !same_set(&o.files, &n.files) {
        changed.push("files".to_string());
        if old.is_some() {
            before.insert("files".into(), string_array(&o.files));
        }
        if new.is_some() {
            after.insert("files".into(), string_array(&n.files));
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

fn group_to_response(entry: &ResourceGroupEntry) -> Response {
    let mut data: Map<String, Value> = Map::new();
    data.insert("name".into(), Value::String(entry.name.clone()));
    data.insert("description".into(), Value::String(entry.description.clone()));
    data.insert(
        "members".into(),
        Value::Array(entry.members.iter().cloned().map(Value::String).collect()),
    );
    data.insert(
        "secrets".into(),
        Value::Array(entry.secrets.iter().cloned().map(Value::String).collect()),
    );
    data.insert(
        "files".into(),
        Value::Array(entry.files.iter().cloned().map(Value::String).collect()),
    );
    data.insert(
        "owner_entity_id".into(),
        Value::String(entry.owner_entity_id.clone()),
    );
    data.insert("created_at".into(), Value::String(entry.created_at.clone()));
    data.insert("updated_at".into(), Value::String(entry.updated_at.clone()));
    Response::data_response(Some(data))
}

fn parse_write_payload(req: &Request) -> Result<WritePayload, RvError> {
    let mut payload = WritePayload::default();

    if let Ok(v) = req.get_data("description") {
        if let Some(s) = v.as_str() {
            payload.description = Some(s.to_string());
        }
    }

    if let Ok(v) = req.get_data("members") {
        payload.members = Some(value_to_string_vec(&v));
    }

    if let Ok(v) = req.get_data("secrets") {
        payload.secrets = Some(value_to_string_vec(&v));
    }

    if let Ok(v) = req.get_data("files") {
        payload.files = Some(value_to_string_vec(&v));
    }

    Ok(payload)
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
impl ResourceGroupBackendInner {
    fn resolve_store(&self) -> Result<Arc<ResourceGroupStore>, RvError> {
        self.core
            .module_manager()
            .get_module::<ResourceGroupModule>("resource-group")
            .and_then(|m| m.store())
            .ok_or_else(|| bv_error_string!("resource-group store unavailable"))
    }

    pub async fn handle_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let keys = store.list_groups().await?;

        // Admins and root see every group. Non-admin callers see only
        // groups they own or have an active share on (direct entity
        // share or share to an identity group they belong to). The
        // group-list endpoint shouldn't leak group names a caller has
        // no read access on — those would 403 on follow-up read and
        // pollute the GUI's group picker with un-openable rows.
        let auth = match req.auth.as_ref() {
            Some(a) => a.clone(),
            None => return Ok(Some(Response::list_response(&keys))),
        };
        let is_admin = auth
            .policies
            .iter()
            .any(|p| p == "root" || p == "admin" || p == "administrator" || p == "super-admin");
        if is_admin {
            return Ok(Some(Response::list_response(&keys)));
        }

        let caller_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
        let username = auth.metadata.get("username").cloned().unwrap_or_default();
        let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();

        let id_module = self
            .core
            .module_manager()
            .get_module::<crate::modules::identity::IdentityModule>("identity");
        let share_store = id_module.as_ref().and_then(|m| m.share_store());
        let group_store = id_module.as_ref().and_then(|m| m.group_store());

        // Identity groups the caller belongs to (used to resolve
        // group-grantee shares against the asset group).
        let mut caller_groups: Vec<(crate::modules::identity::ShareGranteeKind, String)> =
            Vec::new();
        if let Some(gs) = &group_store {
            for (kind, member, gk) in [
                (
                    crate::modules::identity::GroupKind::User,
                    &username,
                    crate::modules::identity::ShareGranteeKind::GroupUser,
                ),
                (
                    crate::modules::identity::GroupKind::App,
                    &role_name,
                    crate::modules::identity::ShareGranteeKind::GroupApp,
                ),
            ] {
                if member.is_empty() {
                    continue;
                }
                let m_lc = member.trim().to_lowercase();
                if let Ok(names) = gs.list_groups(kind).await {
                    for g_name in names {
                        if let Ok(Some(g)) = gs.get_group(kind, &g_name).await {
                            if g.members.iter().any(|m| m.trim().to_lowercase() == m_lc) {
                                caller_groups.push((gk, g_name));
                            }
                        }
                    }
                }
            }
        }

        let mut visible: Vec<String> = Vec::new();
        for name in keys {
            // Owner pass: cheap, single read against the group entry.
            let owned = match store.get_group(&name).await {
                Ok(Some(g)) => !g.owner_entity_id.is_empty() && g.owner_entity_id == caller_id,
                _ => false,
            };
            if owned {
                visible.push(name);
                continue;
            }

            // Share pass: direct entity share OR share to any of the
            // caller's identity groups.
            let mut has_share = false;
            if let Some(ss) = &share_store {
                if !caller_id.is_empty() {
                    if let Ok(Some(s)) = ss
                        .get_share(
                            crate::modules::identity::ShareTargetKind::AssetGroup,
                            &name,
                            &caller_id,
                        )
                        .await
                    {
                        if !s.is_expired() {
                            has_share = true;
                        }
                    }
                }
                if !has_share {
                    for (_gk, g_name) in &caller_groups {
                        if let Ok(Some(s)) = ss
                            .get_share(
                                crate::modules::identity::ShareTargetKind::AssetGroup,
                                &name,
                                g_name,
                            )
                            .await
                        {
                            if !s.is_expired() {
                                has_share = true;
                                break;
                            }
                        }
                    }
                }
            }
            if has_share {
                visible.push(name);
            }
        }

        Ok(Some(Response::list_response(&visible)))
    }

    pub async fn handle_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        match store.get_group(&name).await? {
            Some(mut entry) => {
                // Member redaction: callers with read access on the
                // group but not on a specific member see the member
                // replaced by `<hidden>` rather than the path, so
                // group cardinality remains truthful without leaking
                // paths the caller can't read anyway.
                //
                // The owner sees everything unredacted (they wrote
                // the members list in the first place); so do callers
                // holding a broad admin policy. For everyone else we
                // probe `Read` on each member's logical path via
                // `PolicyStore::can_operate` and swap the path for
                // the sentinel string on denial.
                let caller_entity_id = req
                    .auth
                    .as_ref()
                    .and_then(|a| a.metadata.get("entity_id"))
                    .cloned()
                    .unwrap_or_default();
                let caller_is_owner = !entry.owner_entity_id.is_empty()
                    && entry.owner_entity_id == caller_entity_id;
                let caller_is_admin = req
                    .auth
                    .as_ref()
                    .map(|a| a.policies.iter().any(|p| p == "root" || p == "admin"))
                    .unwrap_or(false);

                if !caller_is_owner && !caller_is_admin {
                    if let Some(auth) = req.auth.clone() {
                        redact_inaccessible_members(&self.core, &auth, &mut entry).await;
                    }
                }

                Ok(Some(group_to_response(&entry)))
            }
            None => Err(bv_error_response_status!(404, &format!("no resource group named: {}", name))),
        }
    }

    pub async fn handle_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        if name.trim().is_empty() {
            return Err(bv_error_string!("group name missing"));
        }

        let payload = parse_write_payload(req)?;

        let existing = store.get_group(&name).await?;
        let mut entry = existing.clone().unwrap_or_default();
        entry.name = name.clone();

        if let Some(d) = &payload.description {
            entry.description = d.clone();
        }
        if let Some(m) = &payload.members {
            entry.members = m.clone();
        }
        if let Some(s) = &payload.secrets {
            entry.secrets = s.clone();
        }
        if let Some(f) = &payload.files {
            entry.files = f.clone();
        }

        let now = now_iso();
        if existing.is_none() {
            entry.created_at = now.clone();
            // Capture the caller's `entity_id` as the group owner on
            // the first write. Empty for root-token callers — admins
            // can use `sys/asset-group-owner/transfer` to adopt.
            entry.owner_entity_id = req
                .auth
                .as_ref()
                .and_then(|a| a.metadata.get("entity_id"))
                .cloned()
                .unwrap_or_default();
        }
        entry.updated_at = now;

        // `set_group` canonicalizes members and persists the record. Use
        // the returned entry (with normalized membership) for the history
        // diff so `before`/`after` match what is actually stored.
        let stored = store.set_group(entry).await?;

        let op = if existing.is_some() { "update" } else { "create" };
        let (changed_fields, before, after) =
            diff_with_values(existing.as_ref(), Some(&stored));
        let record_history = op == "create" || !changed_fields.is_empty();
        if record_history {
            let hist = ResourceGroupHistoryEntry {
                ts: now_iso(),
                user: caller_username(req),
                op: op.to_string(),
                changed_fields,
                before,
                after,
            };
            // History failures must not fail the write.
            let _ = store.append_history(&name, hist).await;
        }

        Ok(None)
    }

    pub async fn handle_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();

        let previous = store.get_group(&name).await?;
        let (changed_fields, before, _after) = diff_with_values(previous.as_ref(), None);
        let hist = ResourceGroupHistoryEntry {
            ts: now_iso(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields,
            before,
            after: Map::new(),
        };
        let _ = store.append_history(&name, hist).await;

        store.delete_group(&name).await?;
        Ok(None)
    }

    pub async fn handle_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let entries = store.list_history(&name).await?;

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

    pub async fn handle_by_resource(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("resource")?.as_str().unwrap_or("").to_string();
        let groups = store.groups_for_resource(&name).await?;
        let mut data = Map::new();
        data.insert("resource".into(), Value::String(name));
        data.insert("groups".into(), string_array(&groups));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_by_secret(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let encoded = req.get_data("path")?.as_str().unwrap_or("").to_string();
        let decoded_bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|e| bv_error_string!(format!("invalid base64url path: {e}")))?;
        let path = String::from_utf8(decoded_bytes)
            .map_err(|e| bv_error_string!(format!("invalid utf-8 in decoded path: {e}")))?;
        let groups = store.groups_for_secret(&path).await?;
        let mut data = Map::new();
        data.insert("path".into(), Value::String(path));
        data.insert("groups".into(), string_array(&groups));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_reindex(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let touched = store.reindex().await?;
        let mut data = Map::new();
        data.insert("indexed_members".into(), Value::Number(serde_json::Number::from(touched)));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_noop(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl ResourceGroupModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "resource-group".to_string(),
            core,
            store: ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn store(&self) -> Option<Arc<ResourceGroupStore>> {
        self.store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for ResourceGroupModule {
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
        // Register the logical backend factory so the mount can bind on
        // first unseal, before per-module `init` runs. The backend
        // resolves the store lazily via the module manager.
        let core_for_backend = self.core.clone();
        let backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            // This backend is not on `VaultCtx` yet, so it needs the concrete
            // `Core`. Captured from the module rather than taken from the
            // parameter: there is exactly one `Core` per server, so it is the
            // same value, and this keeps the retype from cascading.
            let mut b = ResourceGroupBackend::new(core_for_backend.clone()).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("resource-group", Arc::new(backend_new_func))
    }

    async fn init(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        let store = ResourceGroupStore::new(&self.core).await?;
        self.store.store(Arc::new(Some(store)));
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        core.delete_logical_backend("resource-group")
    }
}


