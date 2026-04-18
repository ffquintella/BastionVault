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
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation,
        Request, Response,
    },
    modules::Module,
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

// Storage key prefixes within this mount's barrier view
const META_PREFIX: &str = "meta/";
const HIST_PREFIX: &str = "hist/";
const SECRET_PREFIX: &str = "secret/";
const SMETA_PREFIX: &str = "smeta/";
const SVER_PREFIX: &str = "sver/";

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
        let h_res_list = self.inner.clone();
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

    pub async fn handle_resource_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap().to_string();
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
        let name = req.get_data("name")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();
        let key = format!("{META_PREFIX}{name}");

        // Load previous value (if any) so we can compute the field diff
        // before overwriting.
        let previous: Option<Map<String, Value>> = match req.storage_get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).ok(),
            None => None,
        };
        let op = if previous.is_some() { "update" } else { "create" };
        let changed_fields = diff_field_names(previous.as_ref(), &body);

        // Only append a history entry if something actually changed -- the
        // GUI saves on every Save button click which may be a no-op.
        // (Always record the initial create, though, even if `body` is empty.)
        let record_history = op == "create" || !changed_fields.is_empty();

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
        let name = req.get_data("name")?.as_str().unwrap().to_string();

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

    pub async fn handle_resource_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap().to_string();
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
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
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
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_secret_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();

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
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
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
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
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
        versions.sort_by(|a, b| b.0.cmp(&a.0));

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
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
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
