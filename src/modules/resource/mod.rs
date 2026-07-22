//! Dedicated resource storage engine.
//!
//! Stores resource metadata and per-resource secrets behind the vault barrier,
//! completely independent of the KV secret engine. All data is encrypted at rest.
//!
//! Storage layout within the mount's barrier view:
//!   meta/<name>                         -> ResourceEntry JSON (current)
//!   hist/<name>/<20-digit-nanos>        -> ResourceHistoryEntry JSON (append-only
//!                                          audit log of who-changed-what; values
//!                                          are NOT stored here)
//!   secret/<resource>/<key>             -> current value of a resource secret
//!                                          (kept for fast reads + backward compat)
//!   smeta/<resource>/<key>              -> ResourceSecretMeta JSON (version index)
//!   sver/<resource>/<key>/<version>     -> ResourceSecretVersion JSON (old values)

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    bv_error_response_status, bv_error_string,
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation,
        Request, Response,
    },
    modules::{resource_group::ResourceGroupModule, Module},
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
    storage::StorageEntry,
};

static RESOURCE_BACKEND_HELP: &str = r#"
The resource backend provides dedicated storage for infrastructure resources
(servers, databases, network devices, etc.) and their associated secrets.
All data is encrypted behind the vault barrier.

Each resource metadata write is recorded in an append-only history log
(who + when + which fields changed). Each resource-secret write snapshots
the previous value into a versioned entry so the full change history is
available for audit.
"#;

/// True when a resource-secret body looks like a *static SSH login
/// credential* — i.e. it carries a non-empty `private_key` or `password`
/// field, exactly the shape the SSH `secret` credential source feeds to
/// the dialler (`resolve_secret_ssh`). Brokered resources reject these at
/// attach time. A bare `passphrase` (a modifier, not a credential) does
/// not count on its own.
fn static_ssh_credential_shape(body: &Map<String, Value>) -> bool {
    let nonempty = |k: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    };
    nonempty("private_key") || nonempty("password")
}

// Storage key prefixes within this mount's barrier view
const META_PREFIX: &str = "meta/";
const HIST_PREFIX: &str = "hist/";
const SECRET_PREFIX: &str = "secret/";
const SMETA_PREFIX: &str = "smeta/";
const SVER_PREFIX: &str = "sver/";

/// Projection of `ResourceMetadata` that the search endpoint returns.
/// Carries exactly what the GUI's card needs to render — keeping the
/// payload small so a page-of-30 response stays well under a few KB
/// even with tag-heavy resources.
#[derive(Debug, Serialize)]
pub struct ResourceCardEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

impl ResourceCardEntry {
    fn from_metadata(name: &str, data: &Map<String, Value>) -> Self {
        let str_field = |k: &str| -> Option<String> {
            data.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .filter(|s| !s.is_empty())
        };
        Self {
            name: name.to_string(),
            kind: str_field("type").unwrap_or_default(),
            hostname: str_field("hostname"),
            ip_address: str_field("ip_address"),
            tags: str_field("tags"),
        }
    }
}

// Resource-metadata fields that are not meaningful in a change-tracking diff.
// Timestamps are always updated on every write, and `name` is part of the
// identity -- including them would make every entry look like a change.
const HIST_IGNORED_FIELDS: &[&str] = &["created_at", "updated_at", "name"];

// ── Data types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tags: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Audit log entry for a resource metadata change. Stores *what* field
/// names changed but not the before/after values -- per requirement, the
/// resource timeline is "who and when made the changes (and what field)".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

/// Per-version metadata for a resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretVersionMeta {
    pub created_time: String,
    pub username: String,
    /// "create" | "update" | "restore"
    pub operation: String,
}

/// Version index for a single resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretMeta {
    pub current_version: u64,
    pub versions: HashMap<String, ResourceSecretVersionMeta>,
}

/// On-disk payload for a single historical version of a resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretVersion {
    pub data: Map<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub username: String,
    pub operation: String,
}

// ── Module boilerplate ─────────────────────────────────────────────

pub struct ResourceModule {
    pub name: String,
    pub backend: Arc<ResourceBackend>,
}

pub struct ResourceBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct ResourceBackend {
    #[deref]
    pub inner: Arc<ResourceBackendInner>,
}

impl ResourceBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(ResourceBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_cfg_read = self.inner.clone();
        let h_cfg_write = self.inner.clone();
        let h_res_read = self.inner.clone();
        let h_res_write = self.inner.clone();
        let h_res_delete = self.inner.clone();
        let h_res_rename = self.inner.clone();
        let h_res_list = self.inner.clone();
        let h_res_search = self.inner.clone();
        let h_res_hist = self.inner.clone();
        let h_sec_read = self.inner.clone();
        let h_sec_write = self.inner.clone();
        let h_sec_delete = self.inner.clone();
        let h_sec_list = self.inner.clone();
        let h_sec_hist = self.inner.clone();
        let h_sec_ver = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    // Resource type configuration (read/write the type schema)
                    pattern: "config/types$",
                    operations: [
                        {op: Operation::Read, handler: h_cfg_read.handle_config_types_read},
                        {op: Operation::Write, handler: h_cfg_write.handle_config_types_write}
                    ],
                    help: "Read or write the resource type definitions (fields per type)."
                },
                {
                    // List all resources
                    pattern: "resources/?$",
                    operations: [
                        {op: Operation::List, handler: h_res_list.handle_resource_list}
                    ],
                    help: "List all resources."
                },
                {
                    // Paginated metadata search. POST body fields:
                    // q, type, offset, limit (all optional).
                    pattern: "resources/search$",
                    operations: [
                        {op: Operation::Write, handler: h_res_search.handle_resource_search}
                    ],
                    help: "Search and paginate resource metadata."
                },
                {
                    // Change history for a single resource (timeline of who/when/what fields)
                    pattern: r"resources/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_res_hist.handle_resource_history}
                    ],
                    help: "Read the change history for a resource."
                },
                {
                    // Rename a resource: move its identity (and all
                    // associated data) to `new_name`. Write-only.
                    pattern: r"resources/(?P<name>[^/]+)/rename$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Current resource name."
                        },
                        "new_name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "New resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_res_rename.handle_resource_rename}
                    ],
                    help: "Rename a resource, migrating metadata, history, secrets, \
                           shares, group membership, and ownership to the new name."
                },
                {
                    // CRUD a single resource
                    pattern: r"resources/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_res_read.handle_resource_read},
                        {op: Operation::Write, handler: h_res_write.handle_resource_write},
                        {op: Operation::Delete, handler: h_res_delete.handle_resource_delete}
                    ],
                    help: "Read, create/update, or delete a resource."
                },
                {
                    // List secrets for a resource
                    pattern: r"secrets/(?P<resource>[^/]+)/?$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_sec_list.handle_secret_list}
                    ],
                    help: "List secrets for a resource."
                },
                {
                    // History of a single resource secret (all versions with user/ts).
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)/history/?$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        },
                        "key": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Secret key name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sec_hist.handle_secret_history}
                    ],
                    help: "Read the version list (history) of a resource secret."
                },
                {
                    // Read a specific historical version of a resource secret.
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)/version/(?P<version>\d+)$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        },
                        "key": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Secret key name."
                        },
                        "version": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Version number."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sec_ver.handle_secret_version_read}
                    ],
                    help: "Read a specific version of a resource secret."
                },
                {
                    // CRUD a single secret within a resource
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        },
                        "key": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Secret key name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sec_read.handle_secret_read},
                        {op: Operation::Write, handler: h_sec_write.handle_secret_write},
                        {op: Operation::Delete, handler: h_sec_delete.handle_secret_delete}
                    ],
                    help: "Read, create/update, or delete a secret within a resource."
                }
            ],
            secrets: [{
                secret_type: "resource",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: RESOURCE_BACKEND_HELP,
        });

        backend
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch, used
/// as the suffix of history log keys so `storage_list()` returns entries
/// in chronological order.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

/// Best-effort caller identity for audit purposes. Prefers the `username`
/// metadata field (populated by userpass login), falls back to
/// `auth.display_name`, and finally to `"unknown"` for root-token writes
/// and any path where auth was not resolved.
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

/// Return the sorted, deduped list of top-level field names that changed
/// between `old` and `new`, ignoring timestamp/identity fields.
fn diff_field_names(old: Option<&Map<String, Value>>, new: &Map<String, Value>) -> Vec<String> {
    let empty = Map::new();
    let old = old.unwrap_or(&empty);
    let mut changed: Vec<String> = Vec::new();

    for (k, v) in new {
        if HIST_IGNORED_FIELDS.contains(&k.as_str()) {
            continue;
        }
        match old.get(k) {
            Some(ov) if ov == v => { /* unchanged */ }
            _ => changed.push(k.clone()),
        }
    }
    for k in old.keys() {
        if HIST_IGNORED_FIELDS.contains(&k.as_str()) {
            continue;
        }
        if !new.contains_key(k) {
            changed.push(k.clone());
        }
    }
    changed.sort();
    changed.dedup();
    changed
}

/// Resolve a resource name from the request URL into the actual storage
/// key in use. New resources are written under their lowercase form; for
/// new writes this is the canonical name. Legacy data, however, was
/// written with mixed case (the resource module preserved case while the
/// resource-group store always lowercased its member references), so a
/// lowercase probe alone would 404 on every PMP-imported resource.
///
/// Lookup order:
///   1. Exact lowercase `meta/<lower>` — the canonical form going forward.
///   2. Exact as-supplied `meta/<raw>` — covers a caller that already
///      passes the legacy mixed-case form.
///   3. Case-insensitive scan of `meta/` — resolves legacy mixed-case
///      keys when the caller passes lowercase (the common path from
///      asset-group filtering, since group members are stored lowercase).
///
/// If nothing matches, returns the lowercase form so a fresh write lands
/// at the canonical key — i.e., new resources are always lowercase, and
/// any existing CI-equal record is updated in place rather than
/// duplicated.
async fn resolve_resource_name(
    req: &mut Request,
    raw: &str,
) -> Result<String, RvError> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();

    if req.storage_get(&format!("{META_PREFIX}{lower}")).await?.is_some() {
        return Ok(lower);
    }
    if trimmed != lower
        && req.storage_get(&format!("{META_PREFIX}{trimmed}")).await?.is_some()
    {
        return Ok(trimmed.to_string());
    }
    for k in req.storage_list(META_PREFIX).await? {
        if k.eq_ignore_ascii_case(trimmed) {
            return Ok(k);
        }
    }
    Ok(lower)
}

// ── Handlers ───────────────────────────────────────────────────────

#[maybe_async::maybe_async]
impl ResourceBackendInner {
    // ── Config (type definitions) ────────────────────────────────

    pub async fn handle_config_types_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let entry = req.storage_get("config/types").await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None), // no config yet — frontend uses defaults
        }
    }

    pub async fn handle_config_types_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?;
        let data = serde_json::to_string(body)?;
        let entry = StorageEntry {
            key: "config/types".to_string(),
            value: data.into_bytes(),
        };
        req.storage_put(&entry).await?;
        Ok(None)
    }

    // ── Resource CRUD ──────────────────────────────────────────────

    pub async fn handle_resource_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(META_PREFIX).await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    /// Paginated search over resource metadata.
    ///
    /// Request body fields (all optional):
    ///   - `q`      — substring matched (case-insensitive) against
    ///                `name`, `hostname`, `ip_address`, and `tags`.
    ///   - `type`   — exact match against the `type` metadata field.
    ///   - `offset` — 0-based start of the page (default 0).
    ///   - `limit`  — page size, clamped to `[1, 200]` (default 30).
    ///
    /// Response:
    ///   ```json
    ///   {
    ///     "items":   [{ "name", "type", "hostname", "ip_address", "tags" }, …],
    ///     "total":    <u64>,
    ///     "has_more": <bool>
    ///   }
    ///   ```
    ///
    /// Implementation walks `META_PREFIX` once per call and reads each
    /// metadata blob (we don't yet maintain a search index — at the
    /// volumes this is built for, the cost is dominated by storage
    /// read latency, which Hiqlite/embedded SQLite serves in single-
    /// digit microseconds per row). If profiling later shows search
    /// latency dominating, add an `RwLock<Option<Arc<Index>>>` on
    /// `ResourceBackendInner` populated lazily and invalidated by
    /// `handle_resource_write` / `handle_resource_delete`.
    pub async fn handle_resource_search(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let body = req.body.clone().unwrap_or_default();
        let q = body
            .get("q")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let type_filter = body
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let offset = body
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let limit = body
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .clamp(1, 200) as usize;

        let keys = req.storage_list(META_PREFIX).await?;

        // Scan every metadata blob so we honour the full match surface
        // (name, hostname, ip_address, tags). An earlier revision had
        // a name-only fast path that skipped reads when only `q` was
        // set, but that silently dropped tag-only matches — exactly
        // the case a tag-organised vault relies on. If query latency
        // becomes a bottleneck past ~5k resources, add a lazy
        // `RwLock<Option<Arc<SearchIndex>>>` on `ResourceBackendInner`,
        // populated on first search and invalidated by
        // `handle_resource_write` / `handle_resource_delete`. The
        // embedded SQLite/file backends serve 5k reads well under
        // 100ms today.
        let mut matches: Vec<(String, ResourceCardEntry)> = Vec::new();
        for key in &keys {
            let storage_key = format!("{META_PREFIX}{key}");
            let entry = match req.storage_get(&storage_key).await? {
                Some(e) => e,
                None => continue,
            };
            let data: Map<String, Value> = match serde_json::from_slice(&entry.value) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(t) = &type_filter {
                if data.get("type").and_then(|v| v.as_str()) != Some(t.as_str()) {
                    continue;
                }
            }
            if let Some(needle) = &q {
                let name_lc = key.to_ascii_lowercase();
                let host_lc = data
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let ip_lc = data
                    .get("ip_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let tags_lc = data
                    .get("tags")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                if !name_lc.contains(needle)
                    && !host_lc.contains(needle)
                    && !ip_lc.contains(needle)
                    && !tags_lc.contains(needle)
                {
                    continue;
                }
            }
            matches.push((key.clone(), ResourceCardEntry::from_metadata(key, &data)));
        }

        // Stable sort by name so paging is deterministic across calls.
        matches.sort_by(|a, b| a.0.cmp(&b.0));

        let total = matches.len();
        let page_end = (offset + limit).min(total);
        let items: Vec<Value> = if offset >= total {
            Vec::new()
        } else {
            matches[offset..page_end]
                .iter()
                .map(|(_, card)| serde_json::to_value(card).unwrap_or(Value::Null))
                .collect()
        };

        let mut resp = Map::new();
        resp.insert("items".into(), Value::Array(items));
        resp.insert("total".into(), Value::Number((total as u64).into()));
        resp.insert("has_more".into(), Value::Bool(page_end < total));
        Ok(Some(Response::data_response(Some(resp))))
    }

    pub async fn handle_resource_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;
        let key = format!("{META_PREFIX}{name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_resource_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        // Resolve to either the existing storage key (any case) or the
        // canonical lowercase form for a fresh write. This collapses
        // would-be duplicates from PMP-style imports that send mixed
        // case after we've already standardized on lowercase.
        let name = resolve_resource_name(req, &raw).await?;
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();
        let key = format!("{META_PREFIX}{name}");

        // Load previous value (if any) so we can compute the field diff
        // before overwriting.
        let previous: Option<Map<String, Value>> = match req.storage_get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).ok(),
            None => None,
        };
        let mut op = if previous.is_some() { "update" } else { "create" };
        let mut changed_fields = diff_field_names(previous.as_ref(), &body);

        // A write whose only diff is `recent_sessions` came from the
        // GUI's session-recorder (`record_recent_session` in
        // `commands/connect.rs`). That isn't a metadata edit — it's the
        // operator opening a session — so we relabel it as a "connect"
        // event with no field pill, and surface it on the security log
        // so an operator tailing security.log sees connection activity
        // without having to cross-reference operations.log.
        let is_connect = op == "update"
            && changed_fields.len() == 1
            && changed_fields[0] == "recent_sessions";
        if is_connect {
            op = "connect";
            changed_fields.clear();
            log::info!(
                target: "security",
                "resource-connect: user={} resource={}",
                caller_username(req),
                name
            );
        }

        // Only append a history entry if something actually changed -- the
        // GUI saves on every Save button click which may be a no-op.
        // (Always record the initial create, though, even if `body` is empty.)
        let record_history = op == "create" || op == "connect" || !changed_fields.is_empty();

        // Write the new metadata.
        let data = serde_json::to_string(&body)?;
        let entry = StorageEntry {
            key,
            value: data.into_bytes(),
        };
        req.storage_put(&entry).await?;

        if record_history {
            let hist = ResourceHistoryEntry {
                ts: now_rfc3339(),
                user: caller_username(req),
                op: op.to_string(),
                changed_fields,
            };
            let hist_key = format!("{HIST_PREFIX}{name}/{}", hist_seq());
            let hist_entry = StorageEntry {
                key: hist_key,
                value: serde_json::to_string(&hist)?.into_bytes(),
            };
            req.storage_put(&hist_entry).await?;
        }

        Ok(None)
    }

    pub async fn handle_resource_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;

        // Record the delete in the history log *before* wiping it. The
        // entry stays available for audit even after the resource is gone
        // (until the caller also purges the hist/ prefix).
        let hist = ResourceHistoryEntry {
            ts: now_rfc3339(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields: Vec::new(),
        };
        let hist_key = format!("{HIST_PREFIX}{name}/{}", hist_seq());
        let hist_entry = StorageEntry {
            key: hist_key,
            value: serde_json::to_string(&hist)?.into_bytes(),
        };
        req.storage_put(&hist_entry).await?;

        // Delete the resource metadata.
        let meta_key = format!("{META_PREFIX}{name}");
        req.storage_delete(&meta_key).await?;

        // Prune the resource from every resource-group it is a member of.
        // Resource-groups are an optional subsystem — if the module isn't
        // loaded or the store isn't initialized yet, skip the prune.
        // Failures are logged but do not block resource deletion: a stale
        // group member will be cleaned up on the next group write or by
        // the `resource-group/reindex` endpoint.
        if let Some(rg_module) = self
            .core
            .module_manager
            .get_module::<ResourceGroupModule>("resource-group")
        {
            if let Some(rg_store) = rg_module.store() {
                if let Err(e) = rg_store.prune_resource(&name).await {
                    log::warn!(
                        "resource-group prune failed for deleted resource '{name}': {e}. \
                         Use the resource-group/reindex endpoint to clean up.",
                    );
                }
            }
        }

        // Delete all current-value secrets under this resource.
        let secret_prefix = format!("{SECRET_PREFIX}{name}/");
        for k in req.storage_list(&secret_prefix).await? {
            req.storage_delete(&format!("{secret_prefix}{k}")).await?;
        }

        // Delete all secret version metadata + version payloads.
        let smeta_prefix = format!("{SMETA_PREFIX}{name}/");
        for k in req.storage_list(&smeta_prefix).await? {
            req.storage_delete(&format!("{smeta_prefix}{k}")).await?;
        }
        let sver_prefix = format!("{SVER_PREFIX}{name}/");
        // The sver/ tree is two levels deep: <resource>/<key>/<version>.
        // storage_list returns the next-level children; recurse one step.
        for k in req.storage_list(&sver_prefix).await? {
            let sub = format!("{sver_prefix}{k}");
            // k typically ends with "/" because there is a further level.
            // Strip any trailing slash and iterate its children.
            let sub_prefix = if sub.ends_with('/') { sub.clone() } else { format!("{sub}/") };
            for v in req.storage_list(&sub_prefix).await? {
                req.storage_delete(&format!("{sub_prefix}{v}")).await?;
            }
            // Some backends may also return a leaf without a trailing slash;
            // delete that too (no-op if already gone).
            let _ = req.storage_delete(&sub).await;
        }

        Ok(None)
    }

    /// Rename a resource, moving its identity and every piece of data
    /// keyed by name to `new_name`. This is a multi-step migration across
    /// several storage domains — there is no cross-backend transaction, so
    /// the order is deliberately **write-new-then-delete-old**: a failure
    /// partway through leaves a recoverable duplicate under the old name,
    /// never a half-deleted resource.
    ///
    /// Migrated in this handler:
    ///   - `meta/<name>` (this mount's view)
    ///   - `secret/`, `smeta/`, `sver/` (this mount's view)
    ///   - `hist/<name>/*` (copied forward; a `rename` entry is appended)
    ///   - asset-group membership + reverse index (resource-group store)
    ///   - explicit share grants (identity share store)
    ///   - ownership record (identity owner store)
    ///
    /// File resources (`FileEntry.resource`) live in a separate mount and
    /// are re-pointed by the caller via the files engine's
    /// `files/repoint-resource` endpoint — they are NOT touched here.
    ///
    /// Policy documents that reference the old ACL path are intentionally
    /// left untouched (they may use globs/templates that cannot be safely
    /// rewritten); the operator is warned in the GUI to update them.
    pub async fn handle_resource_rename(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw_old = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let old = resolve_resource_name(req, &raw_old).await?;

        // Validate the target name. Names are the storage key *and* the
        // ACL path segment, so reject anything that could escape the key
        // space or collide with a sub-path.
        let raw_new = req
            .get_data("new_name")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        if raw_new.is_empty() {
            return Err(bv_error_string!("new_name is required"));
        }
        let new = raw_new.to_ascii_lowercase();
        if new.contains('/') || new.contains("..") {
            return Err(bv_error_string!(
                "new_name must not contain '/' or '..'"
            ));
        }
        if new == old {
            return Err(bv_error_string!(
                "new_name is the same as the current name"
            ));
        }

        // Source must exist.
        let old_meta_key = format!("{META_PREFIX}{old}");
        let Some(old_entry) = req.storage_get(&old_meta_key).await? else {
            return Err(bv_error_string!("resource not found"));
        };

        // Target must be free. Check the canonical key and a
        // case-insensitive scan (mirrors `resolve_resource_name`) so a
        // rename can never silently clobber a differently-cased record.
        let new_meta_key = format!("{META_PREFIX}{new}");
        if req.storage_get(&new_meta_key).await?.is_some() {
            return Err(bv_error_string!(format!(
                "a resource named '{new}' already exists"
            )));
        }
        for k in req.storage_list(META_PREFIX).await? {
            if k.eq_ignore_ascii_case(&new) {
                return Err(bv_error_string!(format!(
                    "a resource named '{new}' already exists"
                )));
            }
        }

        // ── 1. Metadata: write the new record (name + updated_at) ──────
        let mut meta: Map<String, Value> =
            serde_json::from_slice(&old_entry.value).unwrap_or_default();
        meta.insert("name".to_string(), Value::String(new.clone()));
        meta.insert(
            "updated_at".to_string(),
            Value::String(now_rfc3339()),
        );
        req.storage_put(&StorageEntry {
            key: new_meta_key,
            value: serde_json::to_vec(&meta)?,
        })
        .await?;

        // ── 2. Secrets: current values, version index, version payloads ─
        // Copy every key from the old prefix to the new, then delete the
        // old copies. Mirrors the enumeration in `handle_resource_delete`.
        let old_secret_prefix = format!("{SECRET_PREFIX}{old}/");
        let new_secret_prefix = format!("{SECRET_PREFIX}{new}/");
        for k in req.storage_list(&old_secret_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_secret_prefix}{k}")).await? {
                req.storage_put(&StorageEntry {
                    key: format!("{new_secret_prefix}{k}"),
                    value: e.value,
                })
                .await?;
            }
        }

        let old_smeta_prefix = format!("{SMETA_PREFIX}{old}/");
        let new_smeta_prefix = format!("{SMETA_PREFIX}{new}/");
        for k in req.storage_list(&old_smeta_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_smeta_prefix}{k}")).await? {
                req.storage_put(&StorageEntry {
                    key: format!("{new_smeta_prefix}{k}"),
                    value: e.value,
                })
                .await?;
            }
        }

        // The sver/ tree is two levels deep: <resource>/<key>/<version>.
        let old_sver_prefix = format!("{SVER_PREFIX}{old}/");
        let new_sver_prefix = format!("{SVER_PREFIX}{new}/");
        for k in req.storage_list(&old_sver_prefix).await? {
            let key_seg = k.trim_end_matches('/');
            let old_sub = format!("{old_sver_prefix}{key_seg}/");
            let new_sub = format!("{new_sver_prefix}{key_seg}/");
            for v in req.storage_list(&old_sub).await? {
                if let Some(e) = req.storage_get(&format!("{old_sub}{v}")).await? {
                    req.storage_put(&StorageEntry {
                        key: format!("{new_sub}{v}"),
                        value: e.value,
                    })
                    .await?;
                }
            }
        }

        // ── 3. History: carry the timeline forward, then log the rename ─
        let old_hist_prefix = format!("{HIST_PREFIX}{old}/");
        let new_hist_prefix = format!("{HIST_PREFIX}{new}/");
        for k in req.storage_list(&old_hist_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_hist_prefix}{k}")).await? {
                req.storage_put(&StorageEntry {
                    key: format!("{new_hist_prefix}{k}"),
                    value: e.value,
                })
                .await?;
            }
        }
        let hist = ResourceHistoryEntry {
            ts: now_rfc3339(),
            user: caller_username(req),
            op: "rename".to_string(),
            changed_fields: vec![format!("{old} -> {new}")],
        };
        req.storage_put(&StorageEntry {
            key: format!("{new_hist_prefix}{}", hist_seq()),
            value: serde_json::to_vec(&hist)?,
        })
        .await?;
        log::info!(
            target: "security",
            "resource-rename: user={} old={} new={}",
            caller_username(req),
            old,
            new
        );

        // ── 4. Cross-module references (best-effort, like delete) ──────
        // Asset-group membership + reverse index.
        if let Some(rg_module) = self
            .core
            .module_manager
            .get_module::<ResourceGroupModule>("resource-group")
        {
            if let Some(rg_store) = rg_module.store() {
                if let Err(e) = rg_store.rename_resource(&old, &new).await {
                    log::warn!(
                        "resource-group rename failed for '{old}' -> '{new}': {e}. \
                         Use the resource-group/reindex endpoint to clean up.",
                    );
                }
            }
        }

        // Shares + ownership (identity module, system view stores).
        if let Some(identity) = self
            .core
            .module_manager
            .get_module::<crate::modules::identity::IdentityModule>("identity")
        {
            let actor = crate::modules::identity::caller_audit_actor(req);
            if let Some(share_store) = identity.share_store() {
                if let Err(e) = share_store
                    .rename_target(
                        crate::modules::identity::share_store::ShareTargetKind::Resource,
                        &old,
                        &new,
                        &actor,
                    )
                    .await
                {
                    log::warn!(
                        "share rename failed for resource '{old}' -> '{new}': {e}",
                    );
                }
            }
            if let Some(owner_store) = identity.owner_store() {
                match owner_store.get_resource_owner(&old).await {
                    Ok(Some(rec)) if !rec.entity_id.is_empty() => {
                        if let Err(e) =
                            owner_store.set_resource_owner(&new, &rec.entity_id).await
                        {
                            log::warn!(
                                "owner rename failed for resource '{old}' -> '{new}': {e}",
                            );
                        } else {
                            let _ = owner_store.forget_resource_owner(&old).await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!(
                        "owner lookup failed for resource '{old}' during rename: {e}",
                    ),
                }
            }
        }

        // ── 5. Delete the old resource-mount keys (identity now moved) ──
        req.storage_delete(&old_meta_key).await?;
        for k in req.storage_list(&old_secret_prefix).await? {
            req.storage_delete(&format!("{old_secret_prefix}{k}")).await?;
        }
        for k in req.storage_list(&old_smeta_prefix).await? {
            req.storage_delete(&format!("{old_smeta_prefix}{k}")).await?;
        }
        for k in req.storage_list(&old_sver_prefix).await? {
            let key_seg = k.trim_end_matches('/');
            let old_sub = format!("{old_sver_prefix}{key_seg}/");
            for v in req.storage_list(&old_sub).await? {
                req.storage_delete(&format!("{old_sub}{v}")).await?;
            }
            let _ = req.storage_delete(&format!("{old_sver_prefix}{key_seg}")).await;
        }
        for k in req.storage_list(&old_hist_prefix).await? {
            req.storage_delete(&format!("{old_hist_prefix}{k}")).await?;
        }

        let mut data = Map::new();
        data.insert("name".to_string(), Value::String(new));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_resource_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;
        let prefix = format!("{HIST_PREFIX}{name}/");

        let mut keys = req.storage_list(&prefix).await?;
        // storage_list returns children in insertion order for some backends
        // and lexicographic order for others; sort explicitly so timelines
        // always render newest-first after the reverse() below.
        keys.sort();
        keys.reverse();

        let mut entries: Vec<Value> = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = req.storage_get(&full).await? {
                if let Ok(v) = serde_json::from_slice::<Value>(&e.value) {
                    entries.push(v);
                }
            }
        }

        let mut data = Map::new();
        data.insert("entries".to_string(), Value::Array(entries));
        Ok(Some(Response::data_response(Some(data))))
    }

    // ── Per-resource secret CRUD ───────────────────────────────────

    pub async fn handle_secret_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let prefix = format!("{SECRET_PREFIX}{resource}/");
        let keys = req.storage_list(&prefix).await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    pub async fn handle_secret_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                // Read of a secret value is the most sensitive event
                // this module produces. The dispatcher's audit broker
                // already records the request, but mirroring it on the
                // security target gets it into security.log alongside
                // the connect events, where ops watches for "who is
                // pulling credentials right now."
                log::info!(
                    target: "security",
                    "resource-secret-read: user={} resource={} key={}",
                    caller_username(req),
                    resource,
                    key_name
                );
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    /// Resolve the effective SSH login class for a resource, walking the
    /// four-tier `ssh-broker` policy. Returns `SharedCredential` (the
    /// default) when the ssh-broker module isn't registered or no tier is
    /// set — so a deployment that never configures brokering is
    /// unaffected. The resource's classification hints (type + asset-group
    /// memberships) come from the resource record and the resource-group
    /// reverse index.
    async fn resolve_login_class(
        &self,
        req: &Request,
        resource: &str,
    ) -> Result<crate::modules::ssh_broker::policy::EffectiveLoginClass, RvError> {
        use crate::modules::ssh_broker::policy::{EffectiveLoginClass, LoginClass};

        let default = || EffectiveLoginClass {
            login_class: LoginClass::SharedCredential,
            login_class_source: "default",
            locked_by: Vec::new(),
            locked_at_tier: None,
            chain: Vec::new(),
            lock_violation: None,
        };

        let Some(sb) = self
            .core
            .module_manager
            .get_module::<crate::modules::ssh_broker::SshBrokerModule>("ssh-broker")
        else {
            return Ok(default());
        };
        let Some(pol) = sb.policy_store() else {
            return Ok(default());
        };

        // Resource type from the metadata record.
        let resource_type = match req.storage_get(&format!("{META_PREFIX}{resource}")).await? {
            Some(e) => serde_json::from_slice::<Map<String, Value>>(&e.value)
                .ok()
                .and_then(|m| m.get("type").and_then(|v| v.as_str().map(String::from)))
                .unwrap_or_default(),
            None => String::new(),
        };

        // Asset-group memberships from the resource-group reverse index.
        let asset_groups = match self
            .core
            .module_manager
            .get_module::<crate::modules::resource_group::ResourceGroupModule>("resource-group")
            .and_then(|m| m.store())
        {
            Some(store) => store.groups_for_resource(resource).await.unwrap_or_default(),
            None => Vec::new(),
        };

        pol.resolve_for(&resource_type, &asset_groups, resource).await
    }

    pub async fn handle_secret_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();

        // Brokered-resource enforcement: a resource pinned to `brokered`
        // (at any tier) may not carry a *static SSH credential*. Reject at
        // attach time — not merely hidden in the GUI — so the control is
        // enforceable, not advisory. A static secret carrying a
        // `private_key` or `password` is exactly what the SSH `secret`
        // credential source would hand the dialler; on a brokered resource
        // every login must be minted per-connect from the SSH engine.
        if static_ssh_credential_shape(&body) {
            let eff = self.resolve_login_class(req, &resource).await?;
            if eff.login_class == crate::modules::ssh_broker::policy::LoginClass::Brokered {
                return Err(bv_error_response_status!(
                    409,
                    &format!(
                        "brokered_resource_no_static_credential: resource `{resource}` is \
                         brokered (login_class via tier `{}`); a static SSH credential may \
                         not be attached — every SSH login is minted per-connect from the \
                         SSH engine. Bind an `ssh-engine` credential source instead.",
                        eff.login_class_source
                    )
                ));
            }
        }

        let curr_key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");

        // Load (or initialize) the version index for this secret.
        let mut meta: ResourceSecretMeta = match req.storage_get(&smeta_key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => ResourceSecretMeta::default(),
        };

        let new_version = meta.current_version + 1;
        let now = now_rfc3339();
        let user = caller_username(req);
        let op = if new_version == 1 { "create" } else { "update" };

        // Snapshot the new value to the version store.
        let ver_payload = ResourceSecretVersion {
            data: body.clone(),
            version: new_version,
            created_time: now.clone(),
            username: user.clone(),
            operation: op.to_string(),
        };
        let ver_key = format!("{SVER_PREFIX}{resource}/{key_name}/{new_version}");
        req.storage_put(&StorageEntry {
            key: ver_key,
            value: serde_json::to_string(&ver_payload)?.into_bytes(),
        })
        .await?;

        // Keep the current-value entry for O(1) reads.
        let data = serde_json::to_string(&body)?;
        req.storage_put(&StorageEntry {
            key: curr_key,
            value: data.into_bytes(),
        })
        .await?;

        // Update and persist the version index.
        meta.current_version = new_version;
        meta.versions.insert(
            new_version.to_string(),
            ResourceSecretVersionMeta {
                created_time: now,
                username: user,
                operation: op.to_string(),
            },
        );
        req.storage_put(&StorageEntry {
            key: smeta_key,
            value: serde_json::to_string(&meta)?.into_bytes(),
        })
        .await?;

        Ok(None)
    }

    pub async fn handle_secret_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();

        // Delete current value.
        let curr_key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        req.storage_delete(&curr_key).await?;

        // Delete all version payloads.
        let sver_prefix = format!("{SVER_PREFIX}{resource}/{key_name}/");
        for v in req.storage_list(&sver_prefix).await? {
            req.storage_delete(&format!("{sver_prefix}{v}")).await?;
        }

        // Delete the version index.
        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");
        req.storage_delete(&smeta_key).await?;

        Ok(None)
    }

    pub async fn handle_secret_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();

        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");
        let meta: ResourceSecretMeta = match req.storage_get(&smeta_key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => {
                // No version index yet (legacy secret written before
                // versioning). Return an empty list rather than an error.
                let mut data = Map::new();
                data.insert("current_version".to_string(), Value::from(0u64));
                data.insert("versions".to_string(), Value::Array(Vec::new()));
                return Ok(Some(Response::data_response(Some(data))));
            }
        };

        // Convert the HashMap<String, VersionMeta> into a sorted array for
        // the frontend. Descending version order puts the newest first.
        let mut versions: Vec<(u64, &ResourceSecretVersionMeta)> = meta
            .versions
            .iter()
            .filter_map(|(k, v)| k.parse::<u64>().ok().map(|n| (n, v)))
            .collect();
        versions.sort_by_key(|v| std::cmp::Reverse(v.0));

        let mut entries = Vec::with_capacity(versions.len());
        for (ver, vm) in versions {
            let mut e = Map::new();
            e.insert("version".to_string(), Value::from(ver));
            e.insert("created_time".to_string(), Value::from(vm.created_time.clone()));
            e.insert("username".to_string(), Value::from(vm.username.clone()));
            e.insert("operation".to_string(), Value::from(vm.operation.clone()));
            entries.push(Value::Object(e));
        }

        let mut data = Map::new();
        data.insert(
            "current_version".to_string(),
            Value::from(meta.current_version),
        );
        data.insert("versions".to_string(), Value::Array(entries));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_secret_version_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let version_str = req.get_data("version")?.as_str().unwrap().to_string();
        let version: u64 = version_str
            .parse()
            .map_err(|_| RvError::ErrRequestInvalid)?;

        let ver_key = format!("{SVER_PREFIX}{resource}/{key_name}/{version}");
        let entry = match req.storage_get(&ver_key).await? {
            Some(e) => e,
            None => return Ok(None),
        };
        let v: ResourceSecretVersion =
            serde_json::from_slice(&entry.value).map_err(|_| RvError::ErrRequestInvalid)?;

        let mut data = Map::new();
        data.insert("version".to_string(), Value::from(v.version));
        data.insert("created_time".to_string(), Value::from(v.created_time));
        data.insert("username".to_string(), Value::from(v.username));
        data.insert("operation".to_string(), Value::from(v.operation));
        data.insert("data".to_string(), Value::Object(v.data));
        // Historical-version reads disclose secret material just like
        // current-value reads; record them on the same security
        // channel with the version tag included.
        log::info!(
            target: "security",
            "resource-secret-read: user={} resource={} key={} version={}",
            caller_username(req),
            resource,
            key_name,
            version
        );
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

// ── Module registration ────────────────────────────────────────────

impl ResourceModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "resource".to_string(),
            backend: Arc::new(ResourceBackend::new(core)),
        }
    }
}

impl Module for ResourceModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("resource", Arc::new(backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("resource")
    }
}

// ── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn diff_create_treats_everything_as_changed() {
        let new = obj(json!({
            "hostname": "h",
            "owner": "alice",
            "created_at": "t",
            "updated_at": "t",
            "name": "x",
        }));
        let changed = diff_field_names(None, &new);
        // name/created_at/updated_at are ignored; the rest is considered changed.
        assert_eq!(changed, vec!["hostname".to_string(), "owner".to_string()]);
    }

    #[test]
    fn diff_equal_returns_empty() {
        let a = obj(json!({ "hostname": "h", "owner": "alice" }));
        let b = a.clone();
        assert!(diff_field_names(Some(&a), &b).is_empty());
    }

    #[test]
    fn diff_detects_changed_added_and_removed_fields() {
        let old = obj(json!({ "hostname": "old", "port": 22, "owner": "alice" }));
        let new = obj(json!({ "hostname": "new", "port": 22, "tags": "web" }));
        // Changed: hostname; added: tags; removed: owner.
        let changed = diff_field_names(Some(&old), &new);
        assert_eq!(
            changed,
            vec!["hostname".to_string(), "owner".to_string(), "tags".to_string()]
        );
    }

    #[test]
    fn diff_ignores_timestamps_even_when_different() {
        let old = obj(json!({ "hostname": "h", "updated_at": "2020" }));
        let new = obj(json!({ "hostname": "h", "updated_at": "2030" }));
        assert!(diff_field_names(Some(&old), &new).is_empty());
    }

    #[test]
    fn hist_seq_is_sortable_and_20_digits() {
        let a = hist_seq();
        // Sleep a hair so nanos advance even on fast CPUs.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = hist_seq();
        assert_eq!(a.len(), 20);
        assert_eq!(b.len(), 20);
        assert!(a < b, "expected {a} < {b}");
    }

    #[test]
    fn static_ssh_credential_shape_detects_key_and_password() {
        assert!(static_ssh_credential_shape(&obj(json!({ "private_key": "x" }))));
        assert!(static_ssh_credential_shape(&obj(json!({ "password": "p" }))));
        // Empty values don't count as a credential.
        assert!(!static_ssh_credential_shape(&obj(json!({ "password": "" }))));
        // A bare passphrase or a generic KV blob is not a static credential.
        assert!(!static_ssh_credential_shape(&obj(json!({ "passphrase": "p" }))));
        assert!(!static_ssh_credential_shape(&obj(json!({ "token": "t" }))));
    }
}

#[cfg(test)]
mod brokered_enforcement_tests {
    use crate::test_utils::TestHttpServer;
    use serde_json::json;

    /// End-to-end proof of the brokered attach guard + the four-tier
    /// login-class lock:
    ///   - A resource whose type is pinned `brokered` rejects a static SSH
    ///     credential (private_key / password) with 409.
    ///   - A resource on the default (`shared-credential`) tier still
    ///     accepts a static credential.
    ///   - A per-resource attempt to weaken a locked global `brokered`
    ///     floor is refused with 403 `login_class_locked`.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_brokered_attach_guard_and_lock() {
        let mut server = TestHttpServer::new("test_brokered_attach_guard", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        // Pin the `database` resource type to brokered.
        let (st, _) = server
            .write(
                "ssh-broker/policy/type/database",
                json!({ "login_class": "brokered", "lock": true }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "type policy write status: {st}");

        // Create a database-typed resource and a web-typed one.
        for (name, ty) in [("db01", "database"), ("web01", "web")] {
            let (st, _) = server
                .write(
                    &format!("resources/resources/{name}"),
                    json!({ "name": name, "type": ty }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
            assert!(st == 200 || st == 204, "resource {name} write status: {st}");
        }

        // The effective class for db01 resolves to brokered via the type tier.
        let (st, resp) = server
            .write(
                "ssh-broker/policy/effective",
                json!({ "resource_id": "db01", "resource_type": "database" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 200, "effective resolve status: {st} {resp:?}");
        assert_eq!(resp["data"]["login_class"], json!("brokered"), "{resp:?}");

        // Attaching a static SSH credential to the brokered resource → 409.
        let (st, resp) = server
            .write(
                "resources/secrets/db01/sshkey",
                json!({ "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 409, "brokered attach must be refused: {resp:?}");

        // The same secret on a shared-credential resource succeeds.
        let (st, _) = server
            .write(
                "resources/secrets/web01/sshkey",
                json!({ "password": "hunter2" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "shared-credential attach status: {st}");

        // Lock the global tier at brokered, then try to relax it per-resource.
        let (st, _) = server
            .write(
                "ssh-broker/policy/global",
                json!({ "login_class_default": "brokered", "login_class_lock": true })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(st == 200 || st == 204, "global lock write status: {st}");
        let (st, resp) = server
            .write(
                "ssh-broker/policy/resource/db01",
                json!({ "login_class": "shared-credential" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(st, 403, "relaxing a locked tier must be refused: {resp:?}");
    }
}

#[cfg(test)]
mod rename_tests {
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_read_api, test_write_api,
    };
    use serde_json::json;

    /// End-to-end proof that a rename moves the resource's identity and all
    /// data reachable through the logical API: metadata, secret (+version),
    /// change history, asset-group membership, and attached files. Shares
    /// and ownership are covered by store-level tests in the identity module.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_migrates_everything() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_migrates_everything").await;

        // Metadata.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/old01",
            true,
            json!({ "name": "old01", "type": "server", "hostname": "h.example" })
                .as_object()
                .cloned(),
        )
        .await;

        // Secret (creates secret/, smeta/, sver/ entries).
        let _ = test_write_api(
            &core,
            &root,
            "resources/secrets/old01/login",
            true,
            json!({ "username": "u", "password": "p" }).as_object().cloned(),
        )
        .await;

        // Asset-group membership.
        let _ = test_write_api(
            &core,
            &root,
            "resource-group/groups/alpha",
            true,
            json!({ "members": "old01" }).as_object().cloned(),
        )
        .await;

        // A file attached to the resource ("hello" base64).
        let create = test_write_api(
            &core,
            &root,
            "files/files",
            true,
            json!({ "name": "key.pem", "resource": "old01", "content_base64": "aGVsbG8=" })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let file_id = create.data.unwrap()["id"].as_str().unwrap().to_string();

        // ── Rename ──────────────────────────────────────────────────
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/old01/rename",
            true,
            json!({ "new_name": "new01" }).as_object().cloned(),
        )
        .await;
        // Files live in a separate mount — re-point them explicitly, as
        // the Tauri orchestrator does.
        let _ = test_write_api(
            &core,
            &root,
            "files/files/repoint-resource",
            true,
            json!({ "old_resource": "old01", "new_resource": "new01" })
                .as_object()
                .cloned(),
        )
        .await;

        // Old metadata is gone (a missing read returns `Ok(None)`).
        let gone = test_read_api(&core, &root, "resources/resources/old01", true)
            .await
            .unwrap();
        assert!(gone.is_none(), "old metadata should be gone: {gone:?}");

        // New metadata exists and carries the new name.
        let resp = test_read_api(&core, &root, "resources/resources/new01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["name"], json!("new01"));

        // Secret moved to the new name.
        let resp = test_read_api(&core, &root, "resources/secrets/new01/login", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["password"], json!("p"));
        // ...and is gone under the old name (missing read → `Ok(None)`).
        let gone = test_read_api(&core, &root, "resources/secrets/old01/login", true)
            .await
            .unwrap();
        assert!(gone.is_none(), "old secret should be gone: {gone:?}");

        // History carried forward, ending with the rename entry.
        let resp = test_read_api(&core, &root, "resources/resources/new01/history", true)
            .await
            .unwrap()
            .unwrap();
        let entries = resp.data.unwrap()["entries"].as_array().cloned().unwrap();
        let rename_entry = entries
            .iter()
            .find(|e| e["op"] == json!("rename"))
            .unwrap_or_else(|| panic!("expected a rename history entry: {entries:?}"));
        // Audit record: who (user), when (ts), what (old -> new).
        assert!(
            rename_entry["user"].as_str().map(|u| !u.is_empty()).unwrap_or(false),
            "rename entry must record the actor: {rename_entry:?}"
        );
        assert!(
            rename_entry["ts"].as_str().map(|t| !t.is_empty()).unwrap_or(false),
            "rename entry must record a timestamp: {rename_entry:?}"
        );
        assert_eq!(
            rename_entry["changed_fields"],
            json!(["old01 -> new01"]),
            "rename entry must record the old -> new change: {rename_entry:?}"
        );

        // Asset-group membership re-pointed.
        let resp = test_read_api(&core, &root, "resource-group/by-resource/new01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!(["alpha"]));
        let resp = test_read_api(&core, &root, "resource-group/by-resource/old01", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["groups"], json!([] as [String; 0]));

        // File re-pointed to the new resource name; blob untouched.
        let resp = test_read_api(&core, &root, &format!("files/files/{file_id}"), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["resource"], json!("new01"));
    }

    /// Renaming onto an existing name must be refused so a rename can never
    /// silently clobber another resource.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_rejects_collision() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_rejects_collision").await;

        for name in ["a01", "b01"] {
            let _ = test_write_api(
                &core,
                &root,
                &format!("resources/resources/{name}"),
                true,
                json!({ "name": name, "type": "server" }).as_object().cloned(),
            )
            .await;
        }

        // a01 -> b01 collides.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/a01/rename",
            false,
            json!({ "new_name": "b01" }).as_object().cloned(),
        )
        .await;
        // a01 still exists.
        let _ = test_read_api(&core, &root, "resources/resources/a01", true).await;
    }

    /// An invalid or same-name target is refused.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn test_resource_rename_rejects_invalid_and_noop() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_resource_rename_rejects_invalid_and_noop").await;

        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01",
            true,
            json!({ "name": "host01", "type": "server" }).as_object().cloned(),
        )
        .await;

        // Path-escaping name.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "bad/name" }).as_object().cloned(),
        )
        .await;
        // No-op (same canonical name).
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "HOST01" }).as_object().cloned(),
        )
        .await;
        // Empty.
        let _ = test_write_api(
            &core,
            &root,
            "resources/resources/host01/rename",
            false,
            json!({ "new_name": "  " }).as_object().cloned(),
        )
        .await;
    }
}
