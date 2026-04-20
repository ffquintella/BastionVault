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
pub use group_store::{ResourceGroupEntry, ResourceGroupHistoryEntry, ResourceGroupStore};

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
            .module_manager
            .get_module::<ResourceGroupModule>("resource-group")
            .and_then(|m| m.store())
            .ok_or_else(|| bv_error_string!("resource-group store unavailable"))
    }

    pub async fn handle_list(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let keys = store.list_groups().await?;
        Ok(Some(Response::list_response(&keys)))
    }

    pub async fn handle_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        match store.get_group(&name).await? {
            Some(entry) => Ok(Some(group_to_response(&entry))),
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

        let now = now_iso();
        if existing.is_none() {
            entry.created_at = now.clone();
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

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        // Register the logical backend factory so the mount can bind on
        // first unseal, before per-module `init` runs. The backend
        // resolves the store lazily via the module manager.
        let backend_new_func = move |c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = ResourceGroupBackend::new(c).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("resource-group", Arc::new(backend_new_func))
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let store = ResourceGroupStore::new(core).await?;
        self.store.store(Arc::new(Some(store)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        core.delete_logical_backend("resource-group")
    }
}

#[cfg(test)]
mod resource_group_tests {
    use serde_json::json;

    use super::*;
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api,
        test_write_api,
    };

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_crud() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_crud").await;

        // Create a group with members.
        let data = json!({
            "description": "project phoenix resources",
            "members": "web-01,db-01",
        })
        .as_object()
        .cloned();
        let ret = test_write_api(&core, &root_token, "resource-group/groups/phoenix", true, data).await;
        assert!(ret.is_ok());

        // Read back.
        let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["name"], "phoenix");
        assert_eq!(data["description"], "project phoenix resources");
        // Members are canonicalized: lowercased, deduped, sorted.
        assert_eq!(data["members"], json!(["db-01", "web-01"]));
        // No secrets were supplied; the field is present and empty.
        assert_eq!(data["secrets"], json!([] as [String; 0]));

        // List.
        let resp = test_list_api(&core, &root_token, "resource-group/groups", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["keys"], json!(["phoenix"]));

        // Partial update: description only, members preserved.
        let patch = json!({ "description": "project phoenix (updated)" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/phoenix", true, patch).await;
        let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["description"], "project phoenix (updated)");
        assert_eq!(data["members"], json!(["db-01", "web-01"]));

        // Delete.
        let _ = test_delete_api(&core, &root_token, "resource-group/groups/phoenix", true, None).await;
        let resp = test_read_api(&core, &root_token, "resource-group/groups/phoenix", false).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_reverse_index() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_reverse_index").await;

        // `web-01` lives in two groups.
        let a = json!({ "members": "web-01,db-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, a).await;

        let b = json!({ "members": "web-01,api-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/beta", true, b).await;

        // by-resource lookup returns both group names, sorted.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["alpha", "beta"]));

        // `db-01` is only in alpha.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/db-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["alpha"]));

        // Remove web-01 from alpha -> by-resource should only return beta.
        let patch = json!({ "members": "db-01" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/alpha", true, patch).await;

        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!(["beta"]));

        // Delete beta -> web-01 is in no groups; by-resource returns empty.
        let _ = test_delete_api(&core, &root_token, "resource-group/groups/beta", true, None).await;
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["groups"], json!([] as [String; 0]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_acl_groups_qualifier() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_acl_groups_qualifier").await;

        // Policy that grants read on any resource, but only when the
        // target resource is a member of the "club" asset-group.
        let gated_hcl = r#"
            path "resources/resources/*" {
                capabilities = ["read"]
                groups = ["club"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-gated",
            true,
            json!({ "policy": gated_hcl }).as_object().cloned(),
        )
        .await;

        // Create two resources as root so there is something to read.
        let _ = test_write_api(
            &core,
            &root_token,
            "resources/resources/alpha",
            true,
            json!({ "type": "server", "hostname": "alpha.local" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "resources/resources/beta",
            true,
            json!({ "type": "server", "hostname": "beta.local" }).as_object().cloned(),
        )
        .await;

        // Put alpha in the "club" resource-group; leave beta out.
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/club",
            true,
            json!({ "members": "alpha" }).as_object().cloned(),
        )
        .await;

        // Mount userpass and create alice with only the gated policy.
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
                "token_policies": "p-gated",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Login as alice.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;

        // alpha is in "club" → read allowed.
        let _ = test_read_api(&core, &token, "resources/resources/alpha", true).await;

        // beta is not in "club" → read denied by the `groups` gate.
        let err = test_read_api(&core, &token, "resources/resources/beta", false).await;
        assert!(err.is_err());

        // Move membership: drop alpha, add beta. Membership changes take
        // effect on the next request without re-login — the evaluator
        // resolves asset-groups per post_auth call.
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/club",
            true,
            json!({ "members": "beta" }).as_object().cloned(),
        )
        .await;

        let _ = test_read_api(&core, &token, "resources/resources/beta", true).await;
        let err = test_read_api(&core, &token, "resources/resources/alpha", false).await;
        assert!(err.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_delete_prunes_from_groups() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_delete_prunes_from_groups").await;

        // Create resource + group containing it.
        let _ = test_write_api(
            &core,
            &root_token,
            "resources/resources/web-01",
            true,
            json!({ "type": "server" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/ops",
            true,
            json!({ "members": "web-01,db-01" }).as_object().cloned(),
        )
        .await;

        // Verify before-state: web-01 is listed in the group.
        let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["members"], json!(["db-01", "web-01"]));

        // Delete the resource. Lifecycle hook must prune it from the group.
        let _ = test_delete_api(&core, &root_token, "resources/resources/web-01", true, None).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/ops", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["members"], json!(["db-01"]));

        // And the reverse-lookup for the deleted resource is empty.
        let resp = test_read_api(&core, &root_token, "resource-group/by-resource/web-01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_secret_membership_and_canonicalization() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_secret_membership_and_canonicalization").await;

        // Group with a mix of resources and secrets. Secrets are
        // supplied in three different forms; they must all canonicalize
        // to two distinct entries (`secret/foo/bar` and `secret/baz`).
        let data = json!({
            "members": "web-01",
            "secrets": "secret/foo/bar,secret/data/foo/bar,secret/metadata/baz,secret/baz",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/mix", true, data).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/mix", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["members"], json!(["web-01"]));
        // Canonicalized form: `/data/` and `/metadata/` stripped; deduped
        // and sorted lexicographically.
        assert_eq!(data["secrets"], json!(["secret/baz", "secret/foo/bar"]));

        // by-secret reverse lookup. The handler accepts base64url(no-pad).
        fn b64(s: &str) -> String {
            URL_SAFE_NO_PAD.encode(s.as_bytes())
        }

        // Canonical form matches.
        let path = format!("resource-group/by-secret/{}", b64("secret/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

        // KV-v2 data/ form matches the same entry.
        let path = format!("resource-group/by-secret/{}", b64("secret/data/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

        // KV-v2 metadata/ form matches the same entry.
        let path = format!("resource-group/by-secret/{}", b64("secret/metadata/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["mix"]));

        // Unrelated path → empty result.
        let path = format!("resource-group/by-secret/{}", b64("secret/other"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

        // Removing the secret from the group clears the reverse index.
        let patch = json!({ "secrets": "secret/baz" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/mix", true, patch).await;
        let path = format!("resource-group/by-secret/{}", b64("secret/foo/bar"));
        let resp = test_read_api(&core, &root_token, &path, true).await.unwrap().unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_acl_groups_qualifier_kv() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_acl_groups_qualifier_kv").await;

        // Policy granting read on any KV v1 path, gated on membership
        // in asset-group "kv-club". Uses KV-v1 to keep the path shape
        // simple (no v2 `/data/` hop).
        let gated_hcl = r#"
            path "kv/*" {
                capabilities = ["read"]
                groups = ["kv-club"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-gated-kv",
            true,
            json!({ "policy": gated_hcl }).as_object().cloned(),
        )
        .await;

        // Mount KV-v1 at `kv/` and put two values in it.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/alpha",
            true,
            json!({ "v": "1" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/beta",
            true,
            json!({ "v": "2" }).as_object().cloned(),
        )
        .await;

        // Put kv/alpha (only) in the "kv-club" asset-group.
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/kv-club",
            true,
            json!({ "secrets": "kv/alpha" }).as_object().cloned(),
        )
        .await;

        // Create user alice with only the gated policy.
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
                "token_policies": "p-gated-kv",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        // Login as alice.
        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;

        // kv/alpha is in "kv-club" → read allowed.
        let _ = test_read_api(&core, &token, "kv/alpha", true).await;

        // kv/beta is not in any group → gated rule contributes nothing
        // and no other rule applies → denied.
        let err = test_read_api(&core, &token, "kv/beta", false).await;
        assert!(err.is_err());

        // Swap membership: kv/beta joins, kv/alpha leaves.
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/kv-club",
            true,
            json!({ "secrets": "kv/beta" }).as_object().cloned(),
        )
        .await;

        let _ = test_read_api(&core, &token, "kv/beta", true).await;
        let err = test_read_api(&core, &token, "kv/alpha", false).await;
        assert!(err.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_resource_group_history() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_resource_group_history").await;

        let create = json!({
            "description": "initial",
            "members": "a,b",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, create).await;

        let update = json!({ "members": "a,b,c" }).as_object().cloned();
        let _ = test_write_api(&core, &root_token, "resource-group/groups/team", true, update).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/team/history", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let entries = data["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        // Newest first: the update entry.
        assert_eq!(entries[0]["op"], "update");
        assert_eq!(entries[0]["changed_fields"], json!(["members"]));
        assert_eq!(entries[0]["before"]["members"], json!(["a", "b"]));
        assert_eq!(entries[0]["after"]["members"], json!(["a", "b", "c"]));
        // Oldest last: the create.
        assert_eq!(entries[1]["op"], "create");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_list_filter_on_groups_gated_list_kv() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_list_filter_on_groups_gated_list_kv").await;

        // Policy grants read+list on kv/*, gated on membership in "crew".
        // The list op can't literally "belong to a group" — the
        // post-route filter narrows the returned keys to group members.
        let gated_hcl = r#"
            path "kv/*" {
                capabilities = ["read", "list"]
                groups = ["crew"]
            }
        "#;
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-list-gated",
            true,
            json!({ "policy": gated_hcl }).as_object().cloned(),
        )
        .await;

        // KV-v1 mount with three secrets; two join the crew, one stays out.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        for k in ["alpha", "beta", "gamma"] {
            let _ = test_write_api(
                &core,
                &root_token,
                &format!("kv/{k}"),
                true,
                json!({ "v": "x" }).as_object().cloned(),
            )
            .await;
        }
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/crew",
            true,
            json!({ "secrets": "kv/alpha,kv/beta" }).as_object().cloned(),
        )
        .await;

        // alice gets the gated policy.
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
                "token_policies": "p-list-gated",
                "ttl": 0,
            })
            .as_object()
            .cloned(),
        )
        .await;

        let mut login_req = Request::new("auth/pass/login/alice");
        login_req.operation = Operation::Write;
        login_req.body = json!({ "password": "hunter22XX!" }).as_object().cloned();
        let resp = core.handle_request(&mut login_req).await.unwrap().unwrap();
        let token = resp.auth.unwrap().client_token;

        // Listing kv/ as alice returns only group members — alpha, beta.
        // gamma lives in no group, so it is filtered out.
        let resp = test_list_api(&core, &token, "kv/", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let keys = data["keys"].as_array().unwrap();
        let names: Vec<&str> = keys.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"alpha"), "expected alpha in {names:?}");
        assert!(names.contains(&"beta"), "expected beta in {names:?}");
        assert!(!names.contains(&"gamma"), "gamma should be filtered out of {names:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_kv_delete_prunes_from_groups() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_kv_delete_prunes_from_groups").await;

        // KV-v1 mount, one secret, and a group containing it.
        let _ = test_write_api(
            &core,
            &root_token,
            "sys/mounts/kv/",
            true,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "kv/s1",
            true,
            json!({ "v": "x" }).as_object().cloned(),
        )
        .await;
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/club",
            true,
            json!({ "secrets": "kv/s1,kv/s2" }).as_object().cloned(),
        )
        .await;

        // Precondition: s1 and s2 are both listed as members.
        let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s1", "kv/s2"]));

        // Delete kv/s1 — the post-route hook prunes it from the group.
        let _ = test_delete_api(&core, &root_token, "kv/s1", true, None).await;

        let resp = test_read_api(&core, &root_token, "resource-group/groups/club", true)
            .await
            .unwrap()
            .unwrap();
        // kv/s1 is gone; kv/s2 remains (never deleted).
        assert_eq!(resp.data.unwrap()["secrets"], json!(["kv/s2"]));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_write_warns_on_unknown_groups() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_policy_write_warns_on_unknown_groups").await;

        // Create one real group so the check can distinguish "unknown"
        // from "no group subsystem present".
        let _ = test_write_api(
            &core,
            &root_token,
            "resource-group/groups/real",
            true,
            json!({}).as_object().cloned(),
        )
        .await;

        let policy_hcl = r#"
            path "resources/resources/*" {
                capabilities = ["read"]
                groups = ["real", "typo-here", "other-typo"]
            }
        "#;

        // Write the policy. Unknown group names trigger a warning on
        // the response; the write still succeeds.
        let resp = test_write_api(
            &core,
            &root_token,
            "sys/policy/p-typo",
            true,
            json!({ "policy": policy_hcl }).as_object().cloned(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(resp.warnings.len(), 1, "expected one warning, got {:?}", resp.warnings);
        let w = &resp.warnings[0];
        assert!(w.contains("typo-here"), "warning did not mention typo-here: {w}");
        assert!(w.contains("other-typo"), "warning did not mention other-typo: {w}");
        assert!(!w.contains("\"real\""), "warning should not flag the real group: {w}");
    }
}
