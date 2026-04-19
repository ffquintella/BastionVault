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

pub mod group_store;
pub use group_store::{GroupEntry, GroupHistoryEntry, GroupKind, GroupStore};

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
        }
    }

    pub fn group_store(&self) -> Option<Arc<GroupStore>> {
        self.group_store.load().as_ref().clone()
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
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.group_store.store(Arc::new(None));
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
}

