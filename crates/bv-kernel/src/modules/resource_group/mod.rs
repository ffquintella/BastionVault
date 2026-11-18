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

use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use derive_more::Deref;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::Module;
use crate::kernel_api::VaultCtx;
use crate::{
    bv_error_response_status, bv_error_string,
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
};

pub mod group_store;
pub mod kernel_service;
pub mod secret_name_migrate;
pub(crate) mod secret_names;
use group_store::{scope_of, SECRETS_FORMAT};
pub use group_store::{ResourceGroupEntry, ResourceGroupHistoryEntry, ResourceGroupStore};
use secret_names::{legacy_path_of_name, member_paths, pending_refusal, split_members_via};

/// Sentinel returned in the `members` / `secrets` list when the caller
/// has group-read access but not read access on an individual member.
/// Keeps group cardinality truthful without leaking paths.
pub const REDACTED_MEMBER: &str = "<hidden>";

/// Mount path of the backend in every namespace (root and tenants alike).
const RESOURCE_GROUP_MOUNT: &str = "resource-group/";

/// `None` for the root scope, else `Some(scope)`: the form the policy
/// store's probes and the owner/share key helpers take.
fn ns_opt(scope: &str) -> Option<&str> {
    if scope.is_empty() {
        None
    } else {
        Some(scope)
    }
}

/// The scope a *header-scoped* request (`sys/asset-group-owner/transfer`)
/// acts in. On those paths the router leaves an unknown namespace header as
/// root; acting on root's same-name group then would be a silent fallback,
/// so a header that named a namespace which did not resolve is refused.
pub fn header_scope(req: &Request) -> Result<String, RvError> {
    let scope = scope_of(req.namespace_path.as_deref());
    let header = crate::kernel_api::namespace::namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
    let named = header.trim().trim_matches('/');
    if scope.is_empty() && !named.is_empty() {
        return Err(bv_error_response_status!(404, &format!("no such namespace: {named:?}")));
    }
    Ok(scope)
}

/// A scope as an operator reads it in a message.
fn describe_scope(scope: &str) -> String {
    match ns_opt(scope) {
        Some(ns) => format!("namespace '{ns}'"),
        None => "the root namespace".to_string(),
    }
}

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
        let h_batch = self.inner.clone();
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
                    // v2 only (v1 is frozen): every group the caller may list
                    // and read, in one request. See `handle_batch`.
                    pattern: r"v2/groups/batch$",
                    fields: {
                        "shape": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "`full` (default): every group as GET groups/<name> returns it. `slim`: \
                                          only by_resource / by_secret / by_file maps of group names."
                        },
                        "since": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "A `version` from an earlier response. When nothing visible from this \
                                          namespace changed since, the response is {unchanged: true, version}."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_batch.handle_batch}
                    ],
                    help: "Read every asset group visible to the caller in one request, with a change version \
                           for cheap revalidation."
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
                            description: "KV secrets that belong to this group, each by its own `<mount>/<name>` (on KV v2 `secret/data/x` is the secret named `data/x`), stored as given (T507)."
                        },
                        "secrets_legacy_kept": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Members the T507 migration kept with the pre-T507 rule. A write may only remove entries; their secrets are re-added by own name in `secrets`."
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
                    // is base64url (no padding) of the secret's own
                    // `<mount>/<name>`, so its '/' characters don't clash
                    // with the URL's separators (T507: nothing stripped).
                    pattern: r"by-secret/(?P<path>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "base64url(no-pad) of the KV secret's own `<mount>/<name>`."
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
    /// Kept pre-T507 members: only removals are accepted.
    #[serde(default)]
    secrets_legacy_kept: Option<Vec<String>>,
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
/// Inside a namespace the probe path carries the `<ns>/` prefix, the only form
/// a tenant policy may use (`refuse_cross_namespace_paths`), and `ns_path` is
/// handed to `can_operate` so owner and share lookups resolve the target's
/// namespaced key. A bare path matches no tenant rule and hid every member.
///
/// Silent on any probe failure: if the policy module or subsystem is
/// unavailable, the helper returns without modifying the entry, which
/// preserves the pre-redaction behavior. Callers who want fail-closed
/// behavior should guard at the handler level.
async fn redact_inaccessible_members(
    core: &Arc<Core>,
    auth: &crate::logical::Auth,
    ns_path: Option<&str>,
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
        if !resource_member_readable(&store, auth, ns_path, m).await {
            *m = REDACTED_MEMBER.to_string();
        }
    }

    // KV-secret members: probed through the paths a request to the secret
    // takes (`secret_probe_paths`); either allowing `Read` is enough. An
    // unreadable T507 marker hides them all (fail closed).
    let switched = secret_names_switched(core).await;
    for (list, own) in [(&mut entry.secrets, true), (&mut entry.secrets_legacy_kept, false)] {
        for s in list.iter_mut() {
            if s == REDACTED_MEMBER {
                continue;
            }
            let readable = match switched {
                Some(switched) => {
                    let probes = secret_probe_paths(core, ns_path, s, switched && own);
                    secret_member_readable(&store, auth, ns_path, &probes).await
                }
                None => false,
            };
            if !readable {
                *s = REDACTED_MEMBER.to_string();
            }
        }
    }
}

/// Whether the T507 switch is set; `None` when its marker cannot be read,
/// which callers treat as nothing readable (never a guess at either keys).
async fn secret_names_switched(core: &Core) -> Option<bool> {
    let store = core.module_manager().get_module::<ResourceGroupModule>("resource-group").and_then(|m| m.store())?;
    store.secret_names().await.ok()
}

/// The paths a `Read` probe of KV-secret member `secret` takes, namespaced:
/// for an own-name member (`by_own_name`, once switched) the routes whose key
/// is that member, none when no route has it (hidden); for a pre-T507 member
/// (pending, or kept) the member as is and in the KV-v2 `data/` form.
fn secret_probe_paths(core: &Core, ns_path: Option<&str>, secret: &str, by_own_name: bool) -> Vec<String> {
    if by_own_name {
        return member_paths(&core.router(), secret, ns_path);
    }
    vec![namespaced_probe_path(ns_path, secret), namespaced_probe_path(ns_path, &kv_v2_data_form(secret))]
}

/// The KV-secret members of `g` as callers see them, `(secrets, kept)`: own
/// names and kept pre-T507 members once switched (a format 0 record found
/// then read on the fly), the pre-T507 list and none while the T507 switch
/// is pending. Never the rollback copy.
fn shown_secrets(
    core: &Core,
    ns_path: Option<&str>,
    g: &ResourceGroupEntry,
    switched: bool,
) -> Result<(Vec<String>, Vec<String>), RvError> {
    if !switched {
        return Ok((g.legacy_list().to_vec(), Vec::new()));
    }
    split_members_via(&core.router(), g, ns_path)
}

/// `g` as callers see it: [`shown_secrets`] in place of the stored lists.
fn shown(core: &Core, home: &str, mut g: ResourceGroupEntry, switched: bool) -> Result<ResourceGroupEntry, RvError> {
    (g.secrets, g.secrets_legacy_kept) = shown_secrets(core, ns_opt(home), &g, switched)?;
    g.legacy_secrets.clear();
    Ok(g)
}

/// `Read` probe on one resource member, in the namespaced form the ACL sees.
async fn resource_member_readable(
    store: &crate::modules::policy::PolicyStore,
    auth: &crate::logical::Auth,
    ns_path: Option<&str>,
    member: &str,
) -> bool {
    let path = namespaced_probe_path(ns_path, &format!("resources/resources/{member}"));
    store.can_operate(auth, &path, Operation::Read, ns_path).await
}

/// `Read` probe on one KV-secret member through `probes` (from
/// [`secret_probe_paths`]): any one allowing `Read` is enough.
async fn secret_member_readable(
    store: &crate::modules::policy::PolicyStore,
    auth: &crate::logical::Auth,
    ns_path: Option<&str>,
    probes: &[String],
) -> bool {
    for path in probes {
        if store.can_operate(auth, path, Operation::Read, ns_path).await {
            return true;
        }
    }
    false
}

/// True when `auth` can `Read` at least one member of `entry`. A caller who may
/// read a member of a group is shown the group in listings, so the listing and
/// the member redaction in `handle_read` apply the same rule. Fails closed: if
/// the policy module is unavailable the group stays hidden, since this only
/// widens visibility.
async fn caller_reads_any_member(
    core: &Arc<Core>,
    auth: &crate::logical::Auth,
    ns_path: Option<&str>,
    entry: &ResourceGroupEntry,
) -> bool {
    use crate::modules::policy::PolicyModule;

    let Some(policy_module) = core.module_manager().get_module::<PolicyModule>("policy") else {
        return false;
    };
    let store = policy_module.policy_store.load();

    for m in entry.members.iter().filter(|m| m.as_str() != REDACTED_MEMBER) {
        if resource_member_readable(&store, auth, ns_path, m).await {
            return true;
        }
    }
    let Some(switched) = secret_names_switched(core).await else {
        return false;
    };
    let Ok((secrets, kept)) = shown_secrets(core, ns_path, entry, switched) else {
        return false;
    };
    let members = secrets.iter().map(|s| (s, switched)).chain(kept.iter().map(|s| (s, false)));
    for (sec, by_own_name) in members.filter(|(s, _)| s.as_str() != REDACTED_MEMBER) {
        let probes = secret_probe_paths(core, ns_path, sec, by_own_name);
        if secret_member_readable(&store, auth, ns_path, &probes).await {
            return true;
        }
    }
    false
}

/// Prefix a mount-relative probe path with the request's namespace, the form
/// the ACL sees for a namespaced request. Root (no namespace) is unchanged.
fn namespaced_probe_path(ns_path: Option<&str>, path: &str) -> String {
    match ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) {
        Some(ns) => format!("{ns}/{}", path.trim_start_matches('/')),
        None => path.to_string(),
    }
}

/// Rewrite a pre-T507 member (e.g., `secret/foo/bar`) into the KV-v2
/// API form (`secret/data/foo/bar`) for authorization probes while the
/// T507 switch is pending. Returns the input unchanged when it already
/// contains `/data/` or has no segments to insert into.
fn kv_v2_data_form(canonical: &str) -> String {
    let trimmed = canonical.trim_matches('/');
    match trimmed.split_once('/') {
        Some((head, rest)) if !rest.starts_with("data/") && !rest.starts_with("metadata/") => {
            format!("{head}/data/{rest}")
        }
        _ => canonical.to_string(),
    }
}

/// One group a caller is shown when listing from a scope.
struct VisibleGroup {
    name: String,
    /// The scope the record lives in; the nearest scope wins a name.
    home: String,
    /// The record, when the visibility decision had to read it.
    entry: Option<ResourceGroupEntry>,
}

/// What `v2/groups/batch` returns per group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchShape {
    /// Every group as `GET groups/<name>` returns it.
    Full,
    /// Only `member -> [group names]` maps.
    Slim,
}

impl BatchShape {
    fn parse(raw: Option<&str>) -> Result<Self, RvError> {
        match raw.map(str::trim).unwrap_or("") {
            "" | "full" => Ok(Self::Full),
            "slim" => Ok(Self::Slim),
            other => {
                Err(bv_error_response_status!(400, &format!("unknown shape {other:?}; expected `full` or `slim`")))
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Slim => "slim",
        }
    }
}

/// An optional string field: absent is `None`, any other type a 400.
fn optional_str(req: &Request, key: &str) -> Result<Option<String>, RvError> {
    match req.get_data(key) {
        Ok(Value::String(s)) => Ok(Some(s)),
        Ok(Value::Null) => Ok(None),
        Err(RvError::ErrRequestNoData | RvError::ErrRequestFieldNotFound) => Ok(None),
        Ok(_) | Err(RvError::ErrRequestFieldInvalid) => {
            Err(bv_error_response_status!(400, &format!("`{key}` must be a string")))
        }
        Err(e) => Err(e),
    }
}

/// `member -> [group names]` for the resources, secrets and files of `groups`,
/// leaving redacted members out. Keys and name lists are sorted.
fn reverse_maps<'a>(groups: impl Iterator<Item = &'a ResourceGroupEntry>) -> (Value, Value, Value) {
    type Index = BTreeMap<String, BTreeSet<String>>;
    let (mut by_resource, mut by_secret, mut by_file) = (Index::new(), Index::new(), Index::new());
    for g in groups {
        for (index, members) in [(&mut by_resource, &g.members), (&mut by_secret, &g.secrets), (&mut by_file, &g.files)]
        {
            for m in members.iter().filter(|m| m.as_str() != REDACTED_MEMBER) {
                index.entry(m.clone()).or_default().insert(g.name.clone());
            }
        }
    }
    let to_value = |index: Index| {
        Value::Object(
            index.into_iter().map(|(k, v)| (k, Value::Array(v.into_iter().map(Value::String).collect()))).collect(),
        )
    };
    (to_value(by_resource), to_value(by_secret), to_value(by_file))
}

/// [`redact_inaccessible_members`] over many groups, with the same verdict per
/// member as `handle_read`: root/admin callers and a group's owner see it whole;
/// every other member is probed in its group's home namespace. Each distinct
/// member is probed once, with one ACL build per namespace.
async fn redact_members_of_many(
    core: &Core,
    store: &crate::modules::policy::PolicyStore,
    auth: &crate::logical::Auth,
    groups: &mut [(String, ResourceGroupEntry)],
    switched: bool,
) {
    if auth.policies.iter().any(|p| p == "root" || p == "admin") {
        return;
    }
    let caller_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
    let owned = |g: &ResourceGroupEntry| !g.owner_entity_id.is_empty() && g.owner_entity_id == caller_id;

    // Home scope -> (resource members, (secret member, by own name)) to decide.
    type Wanted = (BTreeSet<String>, BTreeSet<(String, bool)>);
    let mut wanted: BTreeMap<String, Wanted> = BTreeMap::new();
    for (home, g) in groups.iter() {
        if owned(g) {
            continue;
        }
        let slot = wanted.entry(home.clone()).or_default();
        slot.0.extend(g.members.iter().filter(|m| m.as_str() != REDACTED_MEMBER).cloned());
        let own = g.secrets.iter().map(|s| (s, switched));
        let all = own.chain(g.secrets_legacy_kept.iter().map(|s| (s, false)));
        slot.1.extend(all.filter(|(s, _)| s.as_str() != REDACTED_MEMBER).map(|(s, by)| (s.clone(), by)));
    }

    let mut readable_resources: HashSet<(String, String)> = HashSet::new();
    let mut readable_secrets: HashSet<(String, String, bool)> = HashSet::new();
    for (home, (resources, secrets)) in wanted {
        let ns = ns_opt(&home);
        let resources: Vec<String> = resources.into_iter().collect();
        let paths: Vec<String> =
            resources.iter().map(|m| namespaced_probe_path(ns, &format!("resources/resources/{m}"))).collect();
        for (m, ok) in resources.into_iter().zip(store.can_operate_many(auth, &paths, Operation::Read, ns).await) {
            if ok {
                readable_resources.insert((home.clone(), m));
            }
        }

        // As `secret_member_readable`: each member's probe paths in one
        // batch, readable when any of them allows `Read`.
        let probes: Vec<((String, bool), String)> = secrets
            .into_iter()
            .flat_map(|(s, by)| secret_probe_paths(core, ns, &s, by).into_iter().map(move |p| ((s.clone(), by), p)))
            .collect();
        let paths: Vec<String> = probes.iter().map(|(_, p)| p.clone()).collect();
        for (((s, by), _), ok) in
            probes.into_iter().zip(store.can_operate_many(auth, &paths, Operation::Read, ns).await)
        {
            if ok {
                readable_secrets.insert((home.clone(), s, by));
            }
        }
    }

    for (home, g) in groups.iter_mut() {
        if owned(g) {
            continue;
        }
        for m in g.members.iter_mut() {
            if m != REDACTED_MEMBER && !readable_resources.contains(&(home.clone(), m.clone())) {
                *m = REDACTED_MEMBER.to_string();
            }
        }
        for (list, by) in [(&mut g.secrets, switched), (&mut g.secrets_legacy_kept, false)] {
            for s in list.iter_mut() {
                if s != REDACTED_MEMBER && !readable_secrets.contains(&(home.clone(), s.clone(), by)) {
                    *s = REDACTED_MEMBER.to_string();
                }
            }
        }
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
    if !same_set(&o.secrets_legacy_kept, &n.secrets_legacy_kept) {
        changed.push("secrets_legacy_kept".to_string());
        if old.is_some() {
            before.insert("secrets_legacy_kept".into(), string_array(&o.secrets_legacy_kept));
        }
        if new.is_some() {
            after.insert("secrets_legacy_kept".into(), string_array(&n.secrets_legacy_kept));
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

/// Whether the KV-secret list a client sent names the members `stored`, as
/// sets, with surrounding whitespace and `/` ignored.
fn same_members(sent: &[String], stored: &[String]) -> bool {
    let set =
        |v: &[String]| v.iter().filter_map(|s| ResourceGroupStore::checked_secret_name(s)).collect::<BTreeSet<_>>();
    set(sent) == set(stored)
}

fn same_set(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().all(|x| b.contains(x))
}

/// `home` is the namespace the record lives in; `inherited` is true when that
/// is an ancestor of the requesting namespace (the group is read-only there).
fn group_to_response(entry: &ResourceGroupEntry, home: &str, inherited: bool) -> Response {
    Response::data_response(Some(group_data(entry, home, inherited)))
}

/// The body of `GET groups/<name>`, shared with the batch read's full shape so
/// the two cannot drift.
fn group_data(entry: &ResourceGroupEntry, home: &str, inherited: bool) -> Map<String, Value> {
    let mut data: Map<String, Value> = Map::new();
    data.insert("namespace".into(), Value::String(home.to_string()));
    data.insert("inherited".into(), Value::Bool(inherited));
    data.insert("name".into(), Value::String(entry.name.clone()));
    data.insert("description".into(), Value::String(entry.description.clone()));
    data.insert("members".into(), Value::Array(entry.members.iter().cloned().map(Value::String).collect()));
    data.insert("secrets".into(), Value::Array(entry.secrets.iter().cloned().map(Value::String).collect()));
    data.insert("secrets_legacy_kept".into(), string_array(&entry.secrets_legacy_kept));
    data.insert("files".into(), Value::Array(entry.files.iter().cloned().map(Value::String).collect()));
    data.insert("owner_entity_id".into(), Value::String(entry.owner_entity_id.clone()));
    data.insert("created_at".into(), Value::String(entry.created_at.clone()));
    data.insert("updated_at".into(), Value::String(entry.updated_at.clone()));
    data
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

    if let Ok(v) = req.get_data("secrets_legacy_kept") {
        payload.secrets_legacy_kept = Some(value_to_string_vec(&v));
    }

    if let Ok(v) = req.get_data("files") {
        payload.files = Some(value_to_string_vec(&v));
    }

    Ok(payload)
}

fn value_to_string_vec(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => {
            arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).filter(|s| !s.trim().is_empty()).collect()
        }
        Value::String(s) => s.split(',').map(|x| x.trim().to_string()).filter(|s| !s.is_empty()).collect(),
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

    /// The scope a request acts in: `req.namespace_path`, once checked that the
    /// request was routed to that namespace's own `resource-group/` mount. The
    /// path-prefix form (`<ns>/resource-group/…`, no namespace header) reaches a
    /// tenant mount with no namespace on the request; acting on root there
    /// would let a tenant write root's groups, so it is refused.
    fn request_scope(&self, req: &Request) -> Result<String, RvError> {
        let scope = scope_of(req.namespace_path.as_deref());
        let mount = match ns_opt(&scope) {
            Some(ns) => format!("{ns}/{RESOURCE_GROUP_MOUNT}"),
            None => RESOURCE_GROUP_MOUNT.to_string(),
        };
        let expected = self.core.router().matching_view(&mount)?;
        // Same allocation: the router hands its mount view to the request.
        let routed_here = match (expected.as_ref(), req.storage.as_ref()) {
            (Some(view), Some(storage)) => std::ptr::addr_eq(Arc::as_ptr(view), Arc::as_ptr(storage)),
            _ => false,
        };
        if !routed_here {
            return Err(bv_error_response_status!(
                400,
                "this asset-group request does not match its namespace; address a namespace's asset groups \
                 with the X-BastionVault-Namespace header"
            ));
        }
        Ok(scope)
    }

    pub async fn handle_list(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let keys: Vec<String> = self.visible_groups(req, &store, &scope).await?.into_iter().map(|g| g.name).collect();
        Ok(Some(Response::list_response(&keys)))
    }

    /// The groups `req`'s caller is shown when listing from `scope`, sorted by
    /// name. The one visibility rule, shared by `LIST groups` and the v2 batch
    /// read so the two cannot disagree.
    async fn visible_groups(
        &self,
        req: &Request,
        store: &ResourceGroupStore,
        scope: &str,
    ) -> Result<Vec<VisibleGroup>, RvError> {
        // The scope's own groups plus every ancestor's, each with its home
        // scope; a nearer scope shadows a farther one of the same name.
        let visible_groups = store.list_visible_groups(scope).await?;
        let everything = |groups: Vec<(String, String)>| -> Vec<VisibleGroup> {
            groups.into_iter().map(|(name, home)| VisibleGroup { name, home, entry: None }).collect()
        };

        // Admins and root see every group. Non-admin callers see only
        // groups they own or have an active share on (direct entity
        // share or share to an identity group they belong to). The
        // group-list endpoint shouldn't leak group names a caller has
        // no read access on — those would 403 on follow-up read and
        // pollute the GUI's group picker with un-openable rows.
        let auth = match req.auth.as_ref() {
            Some(a) => a.clone(),
            None => return Ok(everything(visible_groups)),
        };
        let is_admin =
            auth.policies.iter().any(|p| p == "root" || p == "admin" || p == "administrator" || p == "super-admin");
        if is_admin {
            return Ok(everything(visible_groups));
        }

        let caller_id = auth.metadata.get("entity_id").cloned().unwrap_or_default();
        let username = auth.metadata.get("username").cloned().unwrap_or_default();
        let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();

        let id_module = self.core.module_manager().get_module::<crate::modules::identity::IdentityModule>("identity");
        let share_store = id_module.as_ref().and_then(|m| m.share_store());
        let group_store = id_module.as_ref().and_then(|m| m.group_store());

        // Identity groups the caller belongs to (used to resolve
        // group-grantee shares against the asset group). They are
        // namespace-scoped and read from the token's binding namespace, as
        // login and `resolve_target_shared_caps` read them.
        let binding_ns = crate::modules::namespace::token_binding::binding_from_metadata(&auth.metadata).0;
        let mut caller_groups: Vec<(crate::modules::identity::ShareGranteeKind, String)> = Vec::new();
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
                if let Ok(names) = gs.list_groups_ns(kind, &binding_ns).await {
                    for g_name in names {
                        if let Ok(Some(g)) = gs.get_group_ns(kind, &g_name, &binding_ns).await {
                            if g.members.iter().any(|m| m.trim().to_lowercase() == m_lc) {
                                caller_groups.push((gk, g_name));
                            }
                        }
                    }
                }
            }
        }

        let mut visible: Vec<VisibleGroup> = Vec::new();
        for (name, home) in visible_groups {
            // Owner pass: cheap, single read against the group entry.
            let entry = store.get_group(&name, &home).await.ok().flatten();
            let owned = entry
                .as_ref()
                .map(|g| !g.owner_entity_id.is_empty() && g.owner_entity_id == caller_id)
                .unwrap_or(false);
            if owned {
                visible.push(VisibleGroup { name, home, entry });
                continue;
            }

            // Share pass: direct entity share OR share to any of the
            // caller's identity groups. Keyed on the group's *home*
            // namespace (`<ns>/<name>`, bare at root), as the share was.
            let mut has_share = false;
            let share_key = crate::modules::identity::OwnerStore::scope_target_name(&name, ns_opt(&home));
            if let (Some(ss), Some(share_key)) = (&share_store, share_key.as_deref()) {
                if !caller_id.is_empty() {
                    if let Ok(Some(s)) =
                        ss.get_share(crate::modules::identity::ShareTargetKind::AssetGroup, share_key, &caller_id).await
                    {
                        if !s.is_expired() {
                            has_share = true;
                        }
                    }
                }
                if !has_share {
                    for (_gk, g_name) in &caller_groups {
                        if let Ok(Some(s)) =
                            ss.get_share(crate::modules::identity::ShareTargetKind::AssetGroup, share_key, g_name).await
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
                visible.push(VisibleGroup { name, home, entry });
                continue;
            }

            // Member pass: a caller whose policy reads any member of the group
            // sees the group, the same rule `handle_read` uses to decide which
            // members to redact. Members are the home namespace's objects, so
            // they are probed there, never as the requester's same-name ones.
            if let Some(record) = &entry {
                if caller_reads_any_member(&self.core, &auth, ns_opt(&home), record).await {
                    visible.push(VisibleGroup { name, home, entry });
                }
            }
        }

        Ok(visible)
    }

    /// `GET v2/groups/batch[?shape=full|slim][&since=<version>]`: every group the
    /// caller may both list and read on its own, in one request (one audit
    /// entry). `full` is each group as `GET groups/<name>` returns it; `slim` is
    /// name maps over this namespace's own groups with the same member
    /// redaction (a hidden member is left out). `since` equal to the current
    /// `version` answers `{unchanged: true}` without reading a group.
    pub async fn handle_batch(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let shape = BatchShape::parse(optional_str(req, "shape")?.as_deref())?;
        let since = optional_str(req, "since")?.filter(|s| !s.is_empty());
        if let Some(s) = &since {
            if s.len() > 128 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err(bv_error_response_status!(400, "`since` must be a version from an earlier response"));
            }
        }
        let Some(auth) = req.auth.clone() else {
            return Err(bv_error_response_status!(403, "the asset-group batch read requires an authenticated caller"));
        };

        // The version is read before any group: a write landing in between
        // pairs the old version with newer data (one extra refetch later),
        // never a new version with old data. `None` (an unreadable record)
        // never answers "unchanged".
        let version = store.chain_version(&scope).await;
        if let (Some(since), Some(current)) = (since.as_deref(), version.as_deref()) {
            if since == current {
                let mut data = Map::new();
                data.insert("unchanged".into(), Value::Bool(true));
                data.insert("version".into(), Value::String(current.to_string()));
                data.insert("shape".into(), Value::String(shape.as_str().to_string()));
                data.insert("namespace".into(), Value::String(scope));
                return Ok(Some(Response::data_response(Some(data))));
            }
        }

        let mut warnings: Vec<String> = Vec::new();
        let mut groups: Vec<(String, ResourceGroupEntry)> = Vec::new();
        for g in self.visible_groups(req, &store, &scope).await? {
            let entry = match g.entry {
                Some(e) => e,
                None => match store.get_group(&g.name, &g.home).await {
                    Ok(Some(e)) => e,
                    // Deleted since it was listed.
                    Ok(None) => continue,
                    Err(e) => {
                        warnings.push(format!("asset group '{}' could not be read and is omitted: {e}", g.name));
                        continue;
                    }
                },
            };
            groups.push((g.home, entry));
        }
        let switched = store.secret_names().await?;
        let groups: Vec<(String, ResourceGroupEntry)> = groups
            .into_iter()
            .map(|(home, g)| shown(&self.core, &home, g, switched).map(|g| (home, g)))
            .collect::<Result<_, RvError>>()?;

        // The policy store answers both checks below. Without it nothing can be
        // shown safely, so refuse rather than return unredacted members.
        let policy_store = {
            use crate::modules::policy::PolicyModule;
            let Some(module) = self.core.module_manager().get_module::<PolicyModule>("policy") else {
                return Err(bv_error_response_status!(500, "policy subsystem unavailable"));
            };
            module.policy_store.load_full()
        };

        // Per-group read check: the decision `GET groups/<name>` gets in this
        // namespace (owner and share scopes resolve against the group's home).
        let gate_paths: Vec<String> = groups
            .iter()
            .map(|(_, g)| namespaced_probe_path(ns_opt(&scope), &format!("resource-group/groups/{}", g.name)))
            .collect();
        let readable = policy_store.can_operate_many(&auth, &gate_paths, Operation::Read, ns_opt(&scope)).await;
        let mut groups: Vec<(String, ResourceGroupEntry)> =
            groups.into_iter().zip(readable).filter_map(|(g, ok)| ok.then_some(g)).collect();

        redact_members_of_many(&self.core, &policy_store, &auth, &mut groups, switched).await;

        let mut data = Map::new();
        data.insert("unchanged".into(), Value::Bool(false));
        data.insert("version".into(), version.map(Value::String).unwrap_or(Value::Null));
        data.insert("shape".into(), Value::String(shape.as_str().to_string()));
        data.insert("namespace".into(), Value::String(scope.clone()));
        match shape {
            BatchShape::Full => {
                let rows = groups.iter().map(|(home, g)| Value::Object(group_data(g, home, *home != scope))).collect();
                data.insert("groups".into(), Value::Array(rows));
            }
            BatchShape::Slim => {
                let names: Vec<String> = groups.iter().map(|(_, g)| g.name.clone()).collect();
                data.insert("groups".into(), string_array(&names));
                // This namespace's own groups only: an inherited group's members
                // are its ancestor's objects, and keying them here would pin the
                // group on this namespace's same-name objects. The reverse index
                // and the ACL qualifier never inherit for the same reason.
                let own = groups.iter().filter(|(home, _)| *home == scope).map(|(_, g)| g);
                let (by_resource, by_secret, by_file) = reverse_maps(own);
                data.insert("by_resource".into(), by_resource);
                data.insert("by_secret".into(), by_secret);
                data.insert("by_file".into(), by_file);
            }
        }
        let mut resp = Response::data_response(Some(data));
        resp.warnings = warnings;
        Ok(Some(resp))
    }

    pub async fn handle_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        // Own scope first, then ancestors: a parent's group is readable here.
        let switched = store.secret_names().await?;
        match store.resolve_group(&name, &scope).await? {
            Some((home, entry)) => {
                let mut entry = shown(&self.core, &home, entry, switched)?;
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
                let caller_entity_id =
                    req.auth.as_ref().and_then(|a| a.metadata.get("entity_id")).cloned().unwrap_or_default();
                let caller_is_owner = !entry.owner_entity_id.is_empty() && entry.owner_entity_id == caller_entity_id;
                let caller_is_admin =
                    req.auth.as_ref().map(|a| a.policies.iter().any(|p| p == "root" || p == "admin")).unwrap_or(false);

                if !caller_is_owner && !caller_is_admin {
                    if let Some(auth) = req.auth.clone() {
                        // Probe the members where they live: the home namespace.
                        redact_inaccessible_members(&self.core, &auth, ns_opt(&home), &mut entry).await;
                    }
                }

                Ok(Some(group_to_response(&entry, &home, home != scope)))
            }
            None => Err(bv_error_response_status!(404, &format!("no resource group named: {}", name))),
        }
    }

    pub async fn handle_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        if name.trim().is_empty() {
            return Err(bv_error_string!("group name missing"));
        }

        let payload = parse_write_payload(req)?;
        let switched = store.secret_names().await?;

        // Writes act on this scope only. A name only an ancestor holds is
        // created here as a new group that shadows the inherited one, which
        // itself is never modified; the response says so.
        let mut existing = store.get_group(&name, &scope).await?;
        if let (true, Some(g)) = (switched, &existing) {
            // A format 0 record found once switched (a raw `.bvx` import) is
            // converted first, as the T507 migration would have.
            if g.secrets_format < SECRETS_FORMAT && !g.secrets.is_empty() {
                let (own, kept) = split_members_via(&self.core.router(), g, ns_opt(&scope))?;
                store.convert_record(&name, &scope, &g.secrets, &own, &kept).await?;
                existing = store.get_group(&name, &scope).await?;
            }
        }
        let shadows = match existing {
            Some(_) => None,
            None => store.resolve_group(&name, &scope).await?.map(|(home, _)| home),
        };
        let mut entry = existing.clone().unwrap_or_default();
        entry.name = name.clone();
        if existing.is_none() && switched {
            entry.secrets_format = SECRETS_FORMAT;
        }

        if let Some(d) = &payload.description {
            entry.description = d.clone();
        }
        if let Some(m) = &payload.members {
            entry.members = m.clone();
        }
        if let Some(s) = &payload.secrets {
            if switched {
                // Each secret by its own `<mount>/<name>`, stored as given (T507).
                entry.secrets = s.clone();
            } else if !same_members(s, existing.as_ref().map(|g| g.legacy_list()).unwrap_or_default()) {
                // While the switch is pending no secret joins or leaves a
                // group: the migration converts the lists as they stand.
                return Err(pending_refusal());
            }
        }
        if let Some(k) = &payload.secrets_legacy_kept {
            if switched {
                // Only removals: the store refuses an entry it does not keep.
                entry.secrets_legacy_kept = k.clone();
            } else if !k.is_empty() {
                // Shown empty while pending: anything else is a change.
                return Err(pending_refusal());
            }
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
            entry.owner_entity_id =
                req.auth.as_ref().and_then(|a| a.metadata.get("entity_id")).cloned().unwrap_or_default();
        }
        entry.updated_at = now;

        // `set_group` canonicalizes members and persists the record. Use
        // the returned entry (with normalized membership) for the history
        // diff so `before`/`after` match what is actually stored.
        let stored = store.set_group(entry, &scope).await?;

        let op = if existing.is_some() { "update" } else { "create" };
        let (changed_fields, before, after) = diff_with_values(existing.as_ref(), Some(&stored));
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
            let _ = store.append_history(&name, hist, &scope).await;
        }

        match shadows {
            Some(home) => Ok(Some(Response {
                warnings: vec![format!(
                    "asset group '{}' was created in this namespace and now shadows the group of the same name \
                     inherited from {}; the inherited group is unchanged",
                    stored.name,
                    describe_scope(&home)
                )],
                ..Response::default()
            })),
            None => Ok(None),
        }
    }

    pub async fn handle_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();

        let previous = store.get_group(&name, &scope).await?;
        // While the T507 switch is pending no secret leaves a group.
        if previous.as_ref().is_some_and(|g| !g.secrets.is_empty()) && !store.secret_names().await? {
            return Err(pending_refusal());
        }
        // An inherited group is read-only here: refuse rather than report a
        // delete that removed nothing while the group stays listed.
        if previous.is_none() {
            if let Some((home, _)) = store.resolve_group(&name, &scope).await? {
                return Err(bv_error_response_status!(
                    403,
                    &format!(
                        "asset group '{}' is inherited from {} and is read-only in this namespace",
                        name.trim().to_lowercase(),
                        describe_scope(&home)
                    )
                ));
            }
        }
        let (changed_fields, before, _after) = diff_with_values(previous.as_ref(), None);
        let hist = ResourceGroupHistoryEntry {
            ts: now_iso(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields,
            before,
            after: Map::new(),
        };
        let _ = store.append_history(&name, hist, &scope).await;

        store.delete_group(&name, &scope).await?;
        Ok(None)
    }

    pub async fn handle_history(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        let name = req.get_data("name")?.as_str().unwrap_or("").to_string();
        // The history of the group a read here resolves to; this scope's own
        // history when no group of that name is visible (it outlives deletes).
        let home = store.resolve_group(&name, &scope).await?.map(|(home, _)| home).unwrap_or(scope);
        let entries = store.list_history(&name, &home).await?;

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
                        Value::Array(e.changed_fields.iter().cloned().map(Value::String).collect()),
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
        let scope = self.request_scope(req)?;
        let name = req.get_data("resource")?.as_str().unwrap_or("").to_string();
        let groups = store.groups_for_resource(&name, &scope).await?;
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
        let scope = self.request_scope(req)?;
        let encoded = req.get_data("path")?.as_str().unwrap_or("").to_string();
        let decoded_bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|e| bv_error_string!(format!("invalid base64url path: {e}")))?;
        let path = String::from_utf8(decoded_bytes)
            .map_err(|e| bv_error_string!(format!("invalid utf-8 in decoded path: {e}")))?;
        // The secret's own `<mount>/<name>`: looked up as given once switched,
        // by the key its `data/` path had while the switch is pending (T507).
        let groups = match store.secret_names().await? {
            true => store.groups_for_secret_name(&path, &scope).await?,
            false => {
                let legacy = legacy_path_of_name(&self.core.router(), &path, ns_opt(&scope));
                store.groups_for_legacy_secret(&legacy, &scope).await?
            }
        };
        let mut data = Map::new();
        data.insert("path".into(), Value::String(path));
        data.insert("groups".into(), string_array(&groups));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_reindex(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let scope = self.request_scope(req)?;
        // Once switched, a format 0 record (a raw `.bvx` import) is converted
        // as the T507 migration would have before the indexes are rebuilt.
        if store.secret_names().await? {
            for name in store.list_groups(&scope).await? {
                let Some(g) = store.get_group(&name, &scope).await? else {
                    continue;
                };
                if g.secrets_format < SECRETS_FORMAT && !g.secrets.is_empty() {
                    let (own, kept) = split_members_via(&self.core.router(), &g, ns_opt(&scope))?;
                    store.convert_record(&name, &scope, &g.secrets, &own, &kept).await?;
                }
            }
        }
        let touched = store.reindex(&scope).await?;
        let mut data = Map::new();
        data.insert("indexed_members".into(), Value::Number(serde_json::Number::from(touched)));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl ResourceGroupModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "resource-group".to_string(), core, store: ArcSwap::new(Arc::new(None)) }
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
        // One store serves every namespace; each call names its scope.
        let store = ResourceGroupStore::new(&self.core).await?;
        self.store.store(Arc::new(Some(store)));
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        core.delete_logical_backend("resource-group")
    }
}
