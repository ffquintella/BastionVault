//! KV v2 secret engine with versioning, soft-delete, destroy, undelete, and CAS support.
//!
//! Storage layout per secret:
//!   metadata/<name>            -> SecretMetadata JSON
//!   versions/<name>/<version>  -> VersionData JSON
//!   config                     -> EngineConfig JSON

pub mod metadata;
pub mod version;

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    context::Context,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
    storage::{Storage, StorageEntry},
};
use bv_kernel_api::{Module, VaultCtx};

use self::metadata::{EngineConfig, SecretMetadata, VersionMetadata};
use self::version::{merge_env, KvVersionBundle, VersionData};

static KV_V2_BACKEND_HELP: &str = r#"
The KV v2 backend stores versioned key-value secrets. Each write creates
a new version. Secrets support soft-delete with recovery, permanent
destruction, and check-and-set (CAS) for concurrency control.

All secrets are encrypted/decrypted by BastionVault and never stored
unencrypted in the backend.
"#;

pub struct KvV2Module {
    pub name: String,
    pub backend: Arc<KvV2Backend>,
}

pub struct KvV2BackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct KvV2Backend {
    #[deref]
    pub inner: Arc<KvV2BackendInner>,
}

impl KvV2Backend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { inner: Arc::new(KvV2BackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_config_read = self.inner.clone();
        let h_config_write = self.inner.clone();
        let h_data_read = self.inner.clone();
        let h_data_write = self.inner.clone();
        let h_data_delete = self.inner.clone();
        let h_metadata_list_prefix = self.inner.clone();
        let h_metadata_list_subprefix = self.inner.clone();
        let h_metadata_read = self.inner.clone();
        let h_metadata_delete = self.inner.clone();
        let h_destroy = self.inner.clone();
        let h_undelete = self.inner.clone();
        let h_transfer_import = self.inner.clone();
        let h_renew = self.inner.clone();
        let h_revoke = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "config$",
                    fields: {
                        "max_versions": {
                            field_type: FieldType::Int,
                            default: "0",
                            description: "Maximum number of versions per secret (0 = unlimited)"
                        },
                        "cas_required": {
                            field_type: FieldType::Bool,
                            default: "false",
                            description: "If true, all writes must include a cas parameter"
                        },
                        "delete_version_after": {
                            field_type: FieldType::Str,
                            default: "0s",
                            description: "Duration after which versions are automatically soft-deleted"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_config_read.handle_config_read},
                        {op: Operation::Write, handler: h_config_write.handle_config_write}
                    ],
                    help: "Configure the KV v2 engine settings."
                },
                {
                    pattern: "data/(?P<name>.+)",
                    fields: {
                        "version": {
                            field_type: FieldType::Int,
                            default: "0",
                            description: "Version number to read (0 = latest)"
                        },
                        "env": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Environment selector; read returns the base secret merged with this environment's overrides"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_data_read.handle_data_read},
                        {op: Operation::Write, handler: h_data_write.handle_data_write},
                        {op: Operation::Delete, handler: h_data_delete.handle_data_delete}
                    ],
                    help: "Read, write, or soft-delete versioned secret data."
                },
                {
                    pattern: "metadata/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Prefix"
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_metadata_list_prefix.handle_metadata_list}
                    ],
                    help: "List all secret names."
                },
                {
                    // Listing under a sub-prefix (e.g.
                    // `metadata/pmp-import/2026-Q2/`). The trailing
                    // `/` distinguishes a List from a Read on the
                    // single-name route below — Vault clients use
                    // a trailing slash on LIST URLs, and the
                    // router only invokes the List handler when
                    // it's present.
                    pattern: "metadata/(?P<prefix>.+)/$",
                    fields: {
                        "prefix": {
                            field_type: FieldType::Str,
                            description: "Sub-prefix to list under"
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_metadata_list_subprefix.handle_metadata_list_subprefix}
                    ],
                    help: "List secret names under a sub-prefix."
                },
                {
                    pattern: "metadata/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_metadata_read.handle_metadata_read},
                        {op: Operation::Delete, handler: h_metadata_delete.handle_metadata_delete}
                    ],
                    help: "Read or delete secret metadata."
                },
                {
                    pattern: "destroy/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_destroy.handle_destroy}
                    ],
                    help: "Permanently destroy specific versions of a secret."
                },
                {
                    pattern: "undelete/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_undelete.handle_undelete}
                    ],
                    help: "Recover soft-deleted versions of a secret."
                },
                {
                    // Cross-namespace transfer, destination side
                    // (features/cross-namespace-copy-move.md). See
                    // `handle_transfer_import` for what one ACL check covers.
                    pattern: TRANSFER_IMPORT_PATTERN,
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Destination secret path."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_transfer_import.handle_transfer_import}
                    ],
                    help: "Import a secret with every version (numbers, timestamps, delete and destroy state, \
                           environments) under a path. Body: versions, current, metadata, on_conflict \
                           (refuse|rename). Authorized as a write of <mount>/<path>; the caller becomes \
                           the owner of the secret written. Shares and asset groups are not written."
                }
            ],
            secrets: [{
                secret_type: "kv-v2",
                renew_handler: h_renew.handle_noop,
                revoke_handler: h_revoke.handle_noop,
            }],
            help: KV_V2_BACKEND_HELP,
        });

        backend
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
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

fn get_name_from_request(req: &Request) -> Result<String, RvError> {
    if let Some(data) = req.data.as_ref() {
        if let Some(name) = data.get("name") {
            if let Some(s) = name.as_str() {
                if !s.is_empty() {
                    return Ok(s.to_string());
                }
            }
        }
    }
    Err(RvError::ErrRequestFieldNotFound)
}

/// Read the optional `env` selector — query (`req.data`) first, then the JSON
/// body. Empty or absent yields `None`.
fn get_env_from_request(req: &Request) -> Option<String> {
    for map in [req.data.as_ref(), req.body.as_ref()].into_iter().flatten() {
        if let Some(v) = map.get("env").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Read the requested version (0 = latest) — query (`req.data`) first, then
/// the JSON body.
fn get_version_from_request(req: &Request) -> u64 {
    for map in [req.data.as_ref(), req.body.as_ref()].into_iter().flatten() {
        if let Some(v) = map.get("version").and_then(|v| v.as_u64()) {
            return v;
        }
    }
    0
}

/// Env names are advisory (free-form is allowed) but must not break the stored
/// JSON or be meaningless: non-empty, no `/`, no control characters.
fn sanitize_env_name(name: &str) -> Result<(), RvError> {
    if name.is_empty() || name.contains('/') || name.chars().any(|c| c.is_control()) {
        return Err(RvError::ErrRequestInvalid);
    }
    Ok(())
}

/// Enforce AppRole environment scoping stamped on the caller's token.
///
/// When the token is env-scoped (`approle_env_scoped == "true"`, set at
/// AppRole login from the secret_id and machine-binding scopes), a KV data
/// operation must carry an `env` parameter that glob-matches BOTH the secret_id
/// scope (`approle_env_secret`) and the machine scope (`approle_env_machine`).
/// An empty list for a dimension means "no restriction" for that dimension.
/// This is the force-env-and-restrict rule: a scoped token may only touch
/// environment-scoped secrets, and only the environments it is allowed.
///
/// Non-scoped tokens (the common case, incl. all non-AppRole tokens) pass
/// through unchanged.
fn enforce_env_scope(req: &Request, env: Option<&str>) -> Result<(), RvError> {
    let Some(auth) = req.auth.as_ref() else {
        return Ok(());
    };
    if auth.metadata.get("approle_env_scoped").map(String::as_str) != Some("true") {
        return Ok(());
    }

    // Force env: a scoped token may not read/write base (non-env) secrets.
    let Some(env) = env.filter(|e| !e.is_empty()) else {
        return Err(RvError::ErrPermissionDenied);
    };

    if env_scope_allows(
        auth.metadata.get("approle_env_secret").map(String::as_str),
        auth.metadata.get("approle_env_machine").map(String::as_str),
        env,
    ) {
        Ok(())
    } else {
        Err(RvError::ErrPermissionDenied)
    }
}

/// Pure core of [`enforce_env_scope`]: does `env` satisfy both the secret_id
/// scope and the machine scope? Each scope is a comma-separated glob list; an
/// empty/absent list is "no restriction" for that dimension. `*` matches any
/// environment. Both dimensions must allow `env`.
fn env_scope_allows(secret_csv: Option<&str>, machine_csv: Option<&str>, env: &str) -> bool {
    let dimension_ok = |csv: Option<&str>| -> bool {
        match csv {
            None | Some("") => true,
            Some(list) => list
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .any(|p| p == "*" || crate::utils::string::globbed_strings_match(p, env)),
        }
    };
    dimension_ok(secret_csv) && dimension_ok(machine_csv)
}

fn get_versions_from_body(req: &Request) -> Vec<u64> {
    if let Some(body) = req.body.as_ref() {
        if let Some(versions) = body.get("versions") {
            if let Some(arr) = versions.as_array() {
                return arr.iter().filter_map(|v| v.as_u64()).collect();
            }
        }
    }
    Vec::new()
}

// ── Transfer import (`v2/transfer/import/<path>`) ──────────────────
//
// The destination side of a cross-namespace copy or move
// (features/cross-namespace-copy-move.md). The pieces below take the mount's
// storage view rather than a request so they are testable in-crate.

/// Mount-relative route; `name` keeps every segment of a nested path.
const TRANSFER_IMPORT_PATTERN: &str = r"v2/transfer/import/(?P<name>.+)";

/// Secret-level settings in a transfer bundle: `SecretMetadata` minus the
/// version index, which the import derives from `versions`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvSecretSettings {
    #[serde(default)]
    pub max_versions: u64,
    #[serde(default)]
    pub cas_required: bool,
    /// Empty means `0s`, the engine default.
    #[serde(default)]
    pub delete_version_after: String,
    /// Empty means the oldest version's `created_time`.
    #[serde(default)]
    pub created_time: String,
    /// Empty means the import time.
    #[serde(default)]
    pub updated_time: String,
}

/// The body of `v2/transfer/import/<path>`: a secret with its whole version
/// history. No `Debug`: it carries secret values.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvSecretBundle {
    pub versions: Vec<KvVersionBundle>,
    /// The highest version number, deleted or not, as `current_version` is.
    pub current: u64,
    #[serde(default)]
    pub metadata: KvSecretSettings,
    /// `refuse` (default, also when empty) | `rename`. There is no overwrite:
    /// the caller deletes the destination first (`DELETE metadata/<path>`).
    #[serde(default)]
    pub on_conflict: String,
}

/// What an import wrote: the final path (differs from the requested one
/// under `rename`) and how many versions it recorded, destroyed included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KvImportSummary {
    pub path: String,
    pub versions: usize,
}

/// Upper bound on the `<path>-<n>` candidates `on_conflict = rename` tries.
const IMPORT_RENAME_MAX_SUFFIX: u32 = 1000;

/// Highest importable version number: exact in every JSON client (2^53 - 1),
/// and far enough from `u64::MAX` that the next write's `+ 1` cannot overflow.
const IMPORT_MAX_VERSION: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportConflict {
    Refuse,
    Rename,
}

impl ImportConflict {
    /// An unknown mode is refused, never read as the default. `overwrite` is
    /// refused too: through this route it would skip the delete ACL and the
    /// owner, share and asset-group cleanup a real delete runs.
    fn parse(raw: &str) -> Result<Self, RvError> {
        match raw.trim() {
            "" | "refuse" => Ok(Self::Refuse),
            "rename" => Ok(Self::Rename),
            "overwrite" => Err(bad_import(
                "on_conflict must be refuse or rename; to overwrite, DELETE metadata/<path> first, then import",
            )),
            other => Err(bad_import(format!("on_conflict must be refuse or rename, not '{other}'"))),
        }
    }
}

fn bad_import(message: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(400, format!("invalid KV import: {}", message.into()))
}

fn import_conflict(message: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(409, message.into())
}

fn is_rfc3339(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

/// A destination path that stays one secret under `metadata/` and
/// `versions/`: no empty or `.` segment, no control characters, and no `..`
/// anywhere, which `BarrierView::sanity_check` refuses in any key.
fn validate_kv_path(path: &str) -> Result<(), RvError> {
    if path.is_empty() {
        return Err(bad_import("path is required"));
    }
    if path.contains("..") || path.split('/').any(|s| s.is_empty() || s == ".") {
        return Err(bad_import("path must not contain '..', '.' or empty segments, or start or end with '/'"));
    }
    if path.chars().any(char::is_control) {
        return Err(bad_import("path must not contain control characters"));
    }
    Ok(())
}

/// Decode a request body into a [`KvSecretBundle`]. serde quotes the
/// offending value on a type error, and in a bundle that can be secret
/// material, so only missing- and unknown-field messages (field names) pass.
fn parse_kv_bundle(body: &Map<String, Value>) -> Result<KvSecretBundle, RvError> {
    serde_json::from_value(Value::Object(body.clone())).map_err(|e| {
        let message = e.to_string();
        if message.starts_with("missing field") || message.starts_with("unknown field") {
            bad_import(message)
        } else {
            bad_import(
                "the body does not have the bundle's shape (versions: [{version, created_time, deleted, \
                 destroyed, deletion_time, data: object, envs: object, username, operation}]; current: \
                 number; metadata: {max_versions, cas_required, delete_version_after, created_time, \
                 updated_time}; on_conflict: string)",
            )
        }
    })
}

/// Everything about a bundle that can be checked without storage: versions
/// are distinct, contiguous and >= 1, `current` is the highest, timestamps
/// are RFC 3339, deletion state is consistent and env names are writable.
fn validate_kv_bundle(bundle: &KvSecretBundle) -> Result<(), RvError> {
    let mut numbers = std::collections::BTreeSet::new();
    for (i, v) in bundle.versions.iter().enumerate() {
        if v.version == 0 || v.version > IMPORT_MAX_VERSION {
            return Err(bad_import(format!("versions[{i}].version must be between 1 and {IMPORT_MAX_VERSION}")));
        }
        if !numbers.insert(v.version) {
            return Err(bad_import(format!("versions[{i}].version {} appears twice", v.version)));
        }
        if !is_rfc3339(&v.created_time) {
            return Err(bad_import(format!("versions[{i}].created_time is not an RFC 3339 timestamp")));
        }
        match (v.deleted || v.destroyed, v.deletion_time.is_empty()) {
            (true, true) => {
                return Err(bad_import(format!("versions[{i}] is deleted or destroyed but has no deletion_time")))
            }
            (false, false) => {
                return Err(bad_import(format!(
                    "versions[{i}] has a deletion_time but is neither deleted nor destroyed"
                )))
            }
            (true, false) if !is_rfc3339(&v.deletion_time) => {
                return Err(bad_import(format!("versions[{i}].deletion_time is not an RFC 3339 timestamp")))
            }
            _ => {}
        }
        if v.destroyed {
            if v.data.as_ref().is_some_and(|d| !d.is_empty()) || !v.envs.is_empty() {
                return Err(bad_import(format!("versions[{i}] is destroyed and must carry no data or envs")));
            }
        } else if v.data.is_none() {
            return Err(bad_import(format!("versions[{i}].data is required unless the version is destroyed")));
        }
        // The rule `handle_data_write` applies to env names; never echoed.
        if v.envs.keys().any(|name| sanitize_env_name(name).is_err()) {
            return Err(bad_import(format!("versions[{i}].envs has an empty or invalid environment name")));
        }
    }

    let (Some(&oldest), Some(&latest)) = (numbers.first(), numbers.last()) else {
        return Err(bad_import("versions must not be empty"));
    };
    if latest - oldest + 1 != numbers.len() as u64 {
        return Err(bad_import(format!("versions must be contiguous from {oldest} to {latest}")));
    }
    if bundle.current != latest {
        return Err(bad_import(format!("current must be the highest version, {latest}")));
    }

    let settings = &bundle.metadata;
    for (field, value) in [("created_time", &settings.created_time), ("updated_time", &settings.updated_time)] {
        if !value.is_empty() && !is_rfc3339(value) {
            return Err(bad_import(format!("metadata.{field} is not an RFC 3339 timestamp")));
        }
    }
    if !settings.delete_version_after.is_empty() && humantime::parse_duration(&settings.delete_version_after).is_err() {
        return Err(bad_import("metadata.delete_version_after is not a duration"));
    }
    Ok(())
}

/// A validated import, ready to write.
struct KvImportPlan {
    /// The destination, free of any secret: the requested path, or under
    /// `rename` the first free `<path>-<n>`.
    path: String,
    bundle: KvSecretBundle,
}

/// True when version payloads are stored for `path` itself. Sub-trees
/// (`<child>/`) are nested secrets, not this one's versions. Without a
/// record this is what an interrupted import leaves (it writes metadata last).
#[maybe_async::maybe_async]
async fn has_version_data_in(view: &dyn Storage, path: &str) -> Result<bool, RvError> {
    Ok(view.list(&format!("versions/{path}/")).await?.iter().any(|k| !k.ends_with('/')))
}

/// True when anything of a secret is stored at `path`, record or payloads.
#[maybe_async::maybe_async]
async fn kv_path_taken_in(view: &dyn Storage, path: &str) -> Result<bool, RvError> {
    Ok(view.get(&format!("metadata/{path}")).await?.is_some() || has_version_data_in(view, path).await?)
}

/// The first `<base>-<n>` (n from 2) with neither a record nor payloads.
#[maybe_async::maybe_async]
async fn free_kv_path_in(view: &dyn Storage, base: &str) -> Result<String, RvError> {
    for n in 2..=IMPORT_RENAME_MAX_SUFFIX {
        let candidate = format!("{base}-{n}");
        if !kv_path_taken_in(view, &candidate).await? {
            return Ok(candidate);
        }
    }
    Err(import_conflict(format!("no free path for '{base}' up to '{base}-{IMPORT_RENAME_MAX_SUFFIX}'")))
}

/// Validate a bundle and settle the destination path. Writes nothing.
#[maybe_async::maybe_async]
async fn plan_kv_import(view: &dyn Storage, path: &str, bundle: KvSecretBundle) -> Result<KvImportPlan, RvError> {
    validate_kv_path(path)?;
    let mode = ImportConflict::parse(&bundle.on_conflict)?;
    validate_kv_bundle(&bundle)?;

    let path = path.to_string();
    let existing = view.get(&format!("metadata/{path}")).await?.is_some();
    let leftovers = has_version_data_in(view, &path).await?;
    let path = match mode {
        _ if !existing && !leftovers => path,
        ImportConflict::Refuse if existing => {
            return Err(import_conflict(format!("a secret already exists at '{path}'")));
        }
        ImportConflict::Refuse => {
            return Err(import_conflict(format!(
                "version data with no metadata record is stored at '{path}' (an interrupted import?); \
                 import with on_conflict=rename to use another path"
            )));
        }
        ImportConflict::Rename => free_kv_path_in(view, &path).await?,
    };
    Ok(KvImportPlan { path, bundle })
}

/// Write a planned import: every version payload, then `metadata/` last. An
/// import that fails partway thus leaves no record, and a retry sees the
/// payloads as a collision.
#[maybe_async::maybe_async]
async fn apply_kv_import(view: &dyn Storage, plan: KvImportPlan) -> Result<KvImportSummary, RvError> {
    let KvImportPlan { path, bundle } = plan;
    let KvSecretBundle { mut versions, current, metadata: settings, .. } = bundle;

    versions.sort_by_key(|v| v.version);
    // `validate_kv_bundle` refused an empty list.
    let oldest = versions.first().ok_or_else(|| bad_import("versions must not be empty"))?;
    let (oldest_version, oldest_created) = (oldest.version, oldest.created_time.clone());
    let count = versions.len();
    let mut index = HashMap::with_capacity(count);
    for v in versions {
        index.insert(v.version.to_string(), v.version_metadata());
        if let Some(payload) = v.into_version_data() {
            let key = format!("versions/{path}/{}", payload.version);
            view.put(&StorageEntry { key, value: serde_json::to_vec(&payload)? }).await?;
        }
    }

    // The defaults `KvSecretSettings` documents for an empty field.
    let given_or = |value: String, fallback: String| if value.is_empty() { fallback } else { value };
    let meta = SecretMetadata {
        current_version: current,
        oldest_version,
        max_versions: settings.max_versions,
        cas_required: settings.cas_required,
        delete_version_after: given_or(settings.delete_version_after, "0s".to_string()),
        created_time: given_or(settings.created_time, oldest_created),
        updated_time: given_or(settings.updated_time, now_rfc3339()),
        versions: index,
    };
    view.put(&StorageEntry { key: format!("metadata/{path}"), value: serde_json::to_vec(&meta)? }).await?;
    Ok(KvImportSummary { path, versions: count })
}

/// What `handle_transfer_import` does with a routed request. A token scoped
/// to environments is refused: an import writes base data, which
/// `enforce_env_scope` denies to such a token.
#[maybe_async::maybe_async]
async fn import_from_request(req: &Request) -> Result<KvImportSummary, RvError> {
    let path = req.data.as_ref().and_then(|d| d.get("name")).and_then(Value::as_str).unwrap_or("").to_string();
    enforce_env_scope(req, None)?;
    let bundle = parse_kv_bundle(req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?)?;
    let storage = req.storage.clone().ok_or(RvError::ErrRequestNotReady)?;
    let plan = plan_kv_import(storage.as_ref(), &path, bundle).await?;
    apply_kv_import(storage.as_ref(), plan).await
}

#[maybe_async::maybe_async]
impl KvV2BackendInner {
    async fn read_config(&self, req: &Request) -> Result<EngineConfig, RvError> {
        let entry = req.storage_get("config").await?;
        match entry {
            Some(e) => Ok(serde_json::from_slice(&e.value)?),
            None => Ok(EngineConfig::default()),
        }
    }

    async fn write_config(&self, req: &Request, config: &EngineConfig) -> Result<(), RvError> {
        let data = serde_json::to_vec(config)?;
        let entry = StorageEntry { key: "config".to_string(), value: data };
        req.storage_put(&entry).await
    }

    async fn read_metadata(&self, req: &Request, name: &str) -> Result<Option<SecretMetadata>, RvError> {
        let key = format!("metadata/{}", name);
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    async fn write_metadata(&self, req: &Request, name: &str, meta: &SecretMetadata) -> Result<(), RvError> {
        let key = format!("metadata/{}", name);
        let data = serde_json::to_vec(meta)?;
        let entry = StorageEntry { key, value: data };
        req.storage_put(&entry).await
    }

    async fn read_version(&self, req: &Request, name: &str, version: u64) -> Result<Option<VersionData>, RvError> {
        let key = format!("versions/{}/{}", name, version);
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    async fn write_version(&self, req: &Request, name: &str, vd: &VersionData) -> Result<(), RvError> {
        let key = format!("versions/{}/{}", name, vd.version);
        let data = serde_json::to_vec(vd)?;
        let entry = StorageEntry { key, value: data };
        req.storage_put(&entry).await
    }

    async fn delete_version_storage(&self, req: &Request, name: &str, version: u64) -> Result<(), RvError> {
        let key = format!("versions/{}/{}", name, version);
        req.storage_delete(&key).await
    }

    async fn prune_old_versions(
        &self,
        req: &Request,
        name: &str,
        meta: &mut SecretMetadata,
        max_versions: u64,
    ) -> Result<(), RvError> {
        if max_versions == 0 {
            return Ok(());
        }

        while meta.versions.len() as u64 > max_versions {
            let oldest = meta.oldest_version;
            self.delete_version_storage(req, name, oldest).await?;
            meta.versions.remove(&oldest.to_string());

            // Find the next oldest
            let mut next_oldest = oldest + 1;
            while next_oldest <= meta.current_version && !meta.versions.contains_key(&next_oldest.to_string()) {
                next_oldest += 1;
            }
            meta.oldest_version = next_oldest;
        }

        Ok(())
    }

    pub async fn handle_config_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.read_config(req).await?;
        let data = serde_json::to_value(&config)?.as_object().cloned();
        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_config_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut config = self.read_config(req).await?;

        if let Some(body) = req.body.as_ref() {
            if let Some(v) = body.get("max_versions").and_then(|v| v.as_u64()) {
                config.max_versions = v;
            }
            if let Some(v) = body.get("cas_required").and_then(|v| v.as_bool()) {
                config.cas_required = v;
            }
            if let Some(v) = body.get("delete_version_after").and_then(|v| v.as_str()) {
                config.delete_version_after = v.to_string();
            }
            if let Some(arr) = body.get("environments").and_then(|v| v.as_array()) {
                let mut envs: Vec<String> = Vec::new();
                for item in arr {
                    if let Some(s) = item.as_str() {
                        sanitize_env_name(s)?;
                        if !envs.iter().any(|e| e == s) {
                            envs.push(s.to_string());
                        }
                    }
                }
                config.environments = envs;
            }
        }

        self.write_config(req, &config).await?;
        Ok(None)
    }

    pub async fn handle_data_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;
        let env = get_env_from_request(req);

        enforce_env_scope(req, env.as_deref())?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Determine which version to read (query string or body; 0 = latest).
        let requested_version = get_version_from_request(req);

        let version = if requested_version == 0 { meta.current_version } else { requested_version };

        let version_key = version.to_string();
        let vm = match meta.versions.get(&version_key) {
            Some(vm) => vm,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        if vm.destroyed {
            return Err(RvError::ErrModuleKvV2VersionDestroyed);
        }

        if vm.is_soft_deleted() {
            let mut resp = Response::new();
            resp.data = json!({
                "data": null,
                "metadata": {
                    "version": version,
                    "created_time": vm.created_time,
                    "deletion_time": vm.deletion_time,
                    "destroyed": false,
                }
            })
            .as_object()
            .cloned();
            resp.add_warning(&format!("version {} has been deleted", version));
            return Ok(Some(resp));
        }

        let vd = match self.read_version(req, &name, version).await? {
            Some(vd) => vd,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        // Resolve the effective data for the requested environment:
        //   - no env, or secret has no envs at all -> base data (legacy/plain).
        //   - env present and declared -> base merged with that env's overrides.
        //   - env present but the secret declares envs and not this one ->
        //     strict miss: return None (HTTP maps a None read to 404).
        let (resolved_data, resolved_env) = match &env {
            Some(e) if !vd.envs.is_empty() => match vd.envs.get(e) {
                Some(overrides) => (merge_env(&vd.data, overrides), Some(e.clone())),
                None => return Ok(None),
            },
            _ => (vd.data.clone(), None),
        };

        let available_envs: Vec<String> = vd.envs.keys().cloned().collect();

        let resp_data = json!({
            "data": resolved_data,
            "metadata": {
                "version": vd.version,
                "created_time": vd.created_time,
                "deletion_time": vd.deletion_time,
                "destroyed": vd.destroyed,
                "username": vd.username,
                "operation": vd.operation,
                "resolved_env": resolved_env,
                "available_envs": available_envs,
            }
        });

        Ok(Some(Response::data_response(resp_data.as_object().cloned())))
    }

    pub async fn handle_data_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        // Extract everything from the body as owned values up front so the
        // immutable borrow ends before we touch storage below.
        let (secret_data, env_target, envs_payload, cas_value) = {
            let body = req.body.as_ref().ok_or(RvError::ErrModuleKvV2DataFieldMissing)?;
            let secret_data = match body.get("data") {
                Some(Value::Object(d)) => d.clone(),
                _ => return Err(RvError::ErrModuleKvV2DataFieldMissing),
            };
            let env_target = body.get("env").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            let envs_payload = body.get("envs").and_then(|v| v.as_object()).cloned();
            let cas_value = body.get("options").and_then(|o| o.get("cas")).and_then(|c| c.as_u64());
            (secret_data, env_target, envs_payload, cas_value)
        };

        // `env` (targeted single-environment patch) and `envs` (full multi-env
        // write) are mutually exclusive ways to express the env map.
        if env_target.is_some() && envs_payload.is_some() {
            return Err(RvError::ErrRequestInvalid);
        }

        // Enforce AppRole environment scoping: a scoped token may only write a
        // single targeted environment it is allowed to (base/full-envs writes
        // carry no `env` and are denied by the force-env rule).
        enforce_env_scope(req, env_target.as_deref())?;

        let config = self.read_config(req).await?;
        let mut meta = self.read_metadata(req, &name).await?.unwrap_or_else(|| {
            let now = now_rfc3339();
            SecretMetadata {
                current_version: 0,
                oldest_version: 0,
                max_versions: 0,
                cas_required: false,
                delete_version_after: "0s".to_string(),
                created_time: now.clone(),
                updated_time: now,
                versions: std::collections::HashMap::new(),
            }
        });

        // CAS validation
        let cas_required = config.cas_required || meta.cas_required;
        if cas_required && cas_value.is_none() {
            return Err(RvError::ErrModuleKvV2CasRequired);
        }
        if let Some(cas) = cas_value {
            if cas != meta.current_version {
                return Err(RvError::ErrModuleKvV2CasMismatch);
            }
        }

        // Increment version
        let new_version = meta.current_version + 1;
        let now = now_rfc3339();
        let user = caller_username(req);
        let op = if new_version == 1 { "create" } else { "update" };

        // Assemble base + envs for the new version per the write mode. One
        // version per write always captures the whole object (base + all envs).
        let (base_data, envs_map) = if let Some(env_name) = env_target.as_deref() {
            sanitize_env_name(env_name)?;
            // Targeted patch: carry the current version's base + other envs
            // forward, then set just this environment's overrides from `data`.
            let (base, mut envs) = if meta.current_version > 0 {
                match self.read_version(req, &name, meta.current_version).await? {
                    Some(prev) => (prev.data, prev.envs),
                    None => (Map::new(), Map::new()),
                }
            } else {
                (Map::new(), Map::new())
            };
            envs.insert(env_name.to_string(), Value::Object(secret_data));
            (base, envs)
        } else if let Some(envs_obj) = envs_payload {
            // Full multi-env write: `data` is the base, `envs` replaces the map.
            for k in envs_obj.keys() {
                sanitize_env_name(k)?;
            }
            (secret_data, envs_obj)
        } else {
            // Legacy base-only write: replace base, but carry existing envs
            // forward so a plain write doesn't silently wipe per-env values.
            let envs = if meta.current_version > 0 {
                self.read_version(req, &name, meta.current_version).await?.map(|p| p.envs).unwrap_or_default()
            } else {
                Map::new()
            };
            (secret_data, envs)
        };

        let vd = VersionData {
            data: base_data,
            envs: envs_map,
            version: new_version,
            created_time: now.clone(),
            deletion_time: String::new(),
            destroyed: false,
            username: user.clone(),
            operation: op.to_string(),
        };

        // Store version data
        self.write_version(req, &name, &vd).await?;

        // Update metadata
        meta.current_version = new_version;
        if meta.oldest_version == 0 {
            meta.oldest_version = 1;
        }
        meta.updated_time = now.clone();
        meta.versions.insert(
            new_version.to_string(),
            VersionMetadata {
                created_time: now,
                deletion_time: String::new(),
                destroyed: false,
                username: user,
                operation: op.to_string(),
            },
        );

        // Determine effective max_versions
        let effective_max = if meta.max_versions > 0 {
            meta.max_versions
        } else if config.max_versions > 0 {
            config.max_versions
        } else {
            0
        };

        self.prune_old_versions(req, &name, &mut meta, effective_max).await?;
        self.write_metadata(req, &name, &meta).await?;

        let resp_data = json!({
            "version": vd.version,
            "created_time": vd.created_time,
            "deletion_time": vd.deletion_time,
            "destroyed": vd.destroyed,
        });

        Ok(Some(Response::data_response(resp_data.as_object().cloned())))
    }

    pub async fn handle_data_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        let versions_to_delete = get_versions_from_body(req);
        let now = now_rfc3339();

        if versions_to_delete.is_empty() {
            // Soft-delete the latest version
            let key = meta.current_version.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if !vm.destroyed && vm.deletion_time.is_empty() {
                    vm.deletion_time = now.clone();
                }
            }
        } else {
            for ver in &versions_to_delete {
                let key = ver.to_string();
                if let Some(vm) = meta.versions.get_mut(&key) {
                    if !vm.destroyed && vm.deletion_time.is_empty() {
                        vm.deletion_time = now.clone();
                    }
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    pub async fn handle_metadata_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        let data = serde_json::to_value(&meta)?.as_object().cloned();
        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_metadata_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Delete all version data
        for ver_key in meta.versions.keys() {
            if let Ok(ver) = ver_key.parse::<u64>() {
                let _ = self.delete_version_storage(req, &name, ver).await;
            }
        }

        // Delete metadata
        let meta_key = format!("metadata/{}", name);
        req.storage_delete(&meta_key).await?;

        Ok(None)
    }

    pub async fn handle_metadata_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list("metadata/").await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    /// List the immediate children of a sub-prefix under the
    /// metadata namespace. Mirrors `handle_metadata_list` but
    /// honours the `prefix` capture from the route, so an operator
    /// can drill into nested folders (e.g.
    /// `secret/metadata/pmp-import/2026-Q2/`) the same way Vault's
    /// reference KV-v2 does.
    pub async fn handle_metadata_list_subprefix(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let prefix = req.get_data("prefix").ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
        // Defence-in-depth — keep the listing scoped to the
        // backend's `metadata/` namespace and refuse anything that
        // tries to climb out via `..`.
        if prefix.contains("..") {
            return Err(RvError::ErrRequestInvalid);
        }
        let path = if prefix.is_empty() {
            "metadata/".to_string()
        } else if prefix.ends_with('/') {
            format!("metadata/{prefix}")
        } else {
            format!("metadata/{prefix}/")
        };
        let keys = req.storage_list(&path).await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    pub async fn handle_destroy(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let versions_to_destroy = get_versions_from_body(req);
        if versions_to_destroy.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        let now = now_rfc3339();
        for ver in &versions_to_destroy {
            let key = ver.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if !vm.destroyed {
                    self.delete_version_storage(req, &name, *ver).await?;
                    vm.destroyed = true;
                    if vm.deletion_time.is_empty() {
                        vm.deletion_time = now.clone();
                    }
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    pub async fn handle_undelete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let versions_to_undelete = get_versions_from_body(req);
        if versions_to_undelete.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        let now = now_rfc3339();
        for ver in &versions_to_undelete {
            let key = ver.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if vm.is_soft_deleted() {
                    vm.deletion_time = String::new();
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    /// `<mount>/v2/transfer/import/<path>`: destination side of a cross-namespace
    /// copy or move; writes a [`KvSecretBundle`], `metadata/` last. One ACL check,
    /// on `<mount>/<path>` (the policy layer's `transfer_target`), covers every
    /// version; `post_route` stamps the caller as owner of the path written. Only
    /// `refuse` or `rename`: overwrite is `DELETE metadata/<path>` first. Shares
    /// and asset groups are untouched; `cas_required` and `max_versions` are
    /// stored, not applied (no CAS check, no pruning).
    pub async fn handle_transfer_import(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let summary = import_from_request(req).await?;
        let data = json!({ "path": summary.path, "versions": summary.versions });
        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn handle_noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl KvV2Module {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { name: "kv-v2".to_string(), backend: Arc::new(KvV2Backend::new(core)) }
    }
}

impl Module for KvV2Module {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let kv = self.backend.clone();
        let kv_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut kv_backend = kv.new_backend();
            kv_backend.init()?;
            Ok(Arc::new(kv_backend))
        };
        core.add_logical_backend("kv-v2", Arc::new(kv_backend_new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("kv-v2")
    }
}

#[cfg(test)]
mod env_scope_tests {
    use super::env_scope_allows;

    #[test]
    fn unrestricted_dimensions_allow_any_env() {
        // Both empty/absent => no restriction on either dimension.
        assert!(env_scope_allows(None, None, "prod"));
        assert!(env_scope_allows(Some(""), Some(""), "anything"));
    }

    #[test]
    fn secret_scope_restricts() {
        assert!(env_scope_allows(Some("prod,staging"), None, "prod"));
        assert!(env_scope_allows(Some("prod,staging"), None, "staging"));
        assert!(!env_scope_allows(Some("prod,staging"), None, "dev"));
    }

    #[test]
    fn machine_scope_restricts() {
        assert!(env_scope_allows(None, Some("staging"), "staging"));
        assert!(!env_scope_allows(None, Some("staging"), "prod"));
    }

    #[test]
    fn both_dimensions_must_allow() {
        // secret allows prod+staging, machine allows only staging => intersection.
        assert!(env_scope_allows(Some("prod,staging"), Some("staging"), "staging"));
        assert!(!env_scope_allows(Some("prod,staging"), Some("staging"), "prod"));
    }

    #[test]
    fn wildcards_match() {
        assert!(env_scope_allows(Some("prod-*"), None, "prod-eu"));
        assert!(env_scope_allows(Some("prod-*"), None, "prod-us"));
        assert!(!env_scope_allows(Some("prod-*"), None, "staging"));
        // A bare "*" matches everything.
        assert!(env_scope_allows(Some("*"), Some("*"), "whatever"));
    }
}

// The import is async-only here: the crate has no async runtime dev-dependency,
// so `block_on` below drives `MemStorage` futures, which never wait.
#[cfg(all(test, not(feature = "sync_handler")))]
mod transfer_import_tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;
    use crate::logical::Auth;

    /// A flat in-memory `Storage` with the barrier's `list` semantics
    /// (immediate children, sub-trees as `name/`) that also records the
    /// order of every `put`, so a test can assert what was written last.
    #[derive(Default)]
    struct MemStorage {
        map: Mutex<BTreeMap<String, Vec<u8>>>,
        puts: Mutex<Vec<String>>,
    }

    impl MemStorage {
        fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
            self.map.lock().unwrap().clone()
        }

        fn json(&self, key: &str) -> Value {
            let map = self.map.lock().unwrap();
            let raw = map.get(key).unwrap_or_else(|| panic!("missing storage key {key}"));
            serde_json::from_slice(raw).unwrap()
        }

        fn seed(&self, key: &str, value: Value) {
            self.map.lock().unwrap().insert(key.to_string(), serde_json::to_vec(&value).unwrap());
        }

        fn has(&self, key: &str) -> bool {
            self.map.lock().unwrap().contains_key(key)
        }

        fn last_put(&self) -> Option<String> {
            self.puts.lock().unwrap().last().cloned()
        }
    }

    #[maybe_async::maybe_async]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let map = self.map.lock().unwrap();
            let mut out: Vec<String> = Vec::new();
            for k in map.keys().filter(|k| k.starts_with(prefix)) {
                let rest = &k[prefix.len()..];
                let child = match rest.find('/') {
                    Some(i) => rest[..=i].to_string(),
                    None => rest.to_string(),
                };
                if !out.contains(&child) {
                    out.push(child);
                }
            }
            Ok(out)
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            Ok(self.map.lock().unwrap().get(key).map(|v| StorageEntry { key: key.into(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.puts.lock().unwrap().push(entry.key.clone());
            self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// Poll a future once; every `MemStorage` call is ready immediately.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => out,
            std::task::Poll::Pending => panic!("an in-memory import never waits"),
        }
    }

    /// The request the router hands `handle_transfer_import` for `path`.
    fn request(mem: &Arc<MemStorage>, path: &str, body: Value) -> Request {
        let mut req = Request::default();
        req.storage = Some(mem.clone() as Arc<dyn Storage>);
        req.data = json!({ "name": path }).as_object().cloned();
        req.body = body.as_object().cloned();
        req
    }

    fn import(mem: &Arc<MemStorage>, path: &str, body: Value) -> Result<KvImportSummary, RvError> {
        block_on(import_from_request(&request(mem, path, body)))
    }

    fn status(r: Result<KvImportSummary, RvError>) -> u16 {
        match r {
            Err(RvError::ErrResponseStatus(s, _)) => s,
            other => panic!("expected a status error, got {other:?}"),
        }
    }

    /// Three versions, out of order: v1 destroyed, v2 soft-deleted, v3 live
    /// with a `prod` environment override.
    fn bundle() -> Value {
        json!({
            "versions": [
                {"version": 3, "created_time": "2025-01-03T00:00:00+00:00", "deleted": false,
                 "data": {"password": "v3-S3CRET"}, "envs": {"prod": {"password": "v3-PROD-S3CRET"}},
                 "username": "bob", "operation": "update"},
                {"version": 1, "created_time": "2025-01-01T00:00:00+00:00", "destroyed": true,
                 "deletion_time": "2025-01-04T00:00:00+00:00", "username": "alice", "operation": "create"},
                {"version": 2, "created_time": "2025-01-02T00:00:00+00:00", "deleted": true,
                 "deletion_time": "2025-01-05T00:00:00+00:00", "data": {"password": "v2-S3CRET"},
                 "username": "alice", "operation": "update"}
            ],
            "current": 3,
            "metadata": {
                "max_versions": 10,
                "cas_required": true,
                "delete_version_after": "0s",
                "created_time": "2024-12-31T00:00:00+00:00",
                "updated_time": "2025-01-05T00:00:00+00:00"
            }
        })
    }

    fn live(n: u64) -> Value {
        json!({"version": n, "created_time": "2025-02-01T00:00:00+00:00", "data": {"k": format!("v{n}")}})
    }

    /// `body` with the value at `pointer` replaced, or added to its parent
    /// object when absent.
    fn with(mut body: Value, pointer: &str, value: Value) -> Value {
        if let Some(slot) = body.pointer_mut(pointer) {
            *slot = value;
            return body;
        }
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        let parent = body.pointer_mut(parent).and_then(Value::as_object_mut);
        parent.unwrap_or_else(|| panic!("no parent object for {pointer}")).insert(field.to_string(), value);
        body
    }

    /// An existing secret at `path` with versions 1..=n, every payload stored.
    fn seed_secret(mem: &MemStorage, path: &str, n: u64) {
        let mut versions = HashMap::new();
        for v in 1..=n {
            let vm = VersionMetadata { created_time: "2020-01-01T00:00:00+00:00".into(), ..Default::default() };
            versions.insert(v.to_string(), vm);
            let vd = json!({"data": {"password": format!("old-{v}")}, "version": v,
                            "created_time": "2020-01-01T00:00:00+00:00", "deletion_time": "", "destroyed": false});
            mem.seed(&format!("versions/{path}/{v}"), vd);
        }
        let meta = SecretMetadata { current_version: n, oldest_version: 1, versions, ..Default::default() };
        mem.seed(&format!("metadata/{path}"), serde_json::to_value(meta).unwrap());
    }

    fn metadata(mem: &MemStorage, path: &str) -> SecretMetadata {
        serde_json::from_value(mem.json(&format!("metadata/{path}"))).unwrap()
    }

    fn payload(mem: &MemStorage, path: &str, n: u64) -> VersionData {
        serde_json::from_value(mem.json(&format!("versions/{path}/{n}"))).unwrap()
    }

    #[test]
    fn import_preserves_version_numbers_and_flags() {
        let mem = Arc::new(MemStorage::default());
        let summary = import(&mem, "team/db", bundle()).unwrap();
        assert_eq!(summary, KvImportSummary { path: "team/db".into(), versions: 3 });

        let meta = metadata(&mem, "team/db");
        assert_eq!((meta.current_version, meta.oldest_version), (3, 1));
        assert_eq!((meta.max_versions, meta.cas_required), (10, true));
        assert_eq!(meta.delete_version_after, "0s");
        assert_eq!(meta.created_time, "2024-12-31T00:00:00+00:00");
        assert_eq!(meta.updated_time, "2025-01-05T00:00:00+00:00");
        assert_eq!(meta.versions.len(), 3);

        let v1 = &meta.versions["1"];
        assert!(v1.destroyed);
        assert_eq!(v1.created_time, "2025-01-01T00:00:00+00:00");
        assert_eq!(v1.deletion_time, "2025-01-04T00:00:00+00:00");
        assert_eq!((v1.username.as_str(), v1.operation.as_str()), ("alice", "create"));
        assert!(!mem.has("versions/team/db/1"), "a destroyed version carries no data");

        let v2 = &meta.versions["2"];
        assert!(v2.is_soft_deleted());
        assert_eq!(v2.deletion_time, "2025-01-05T00:00:00+00:00");
        let p2 = payload(&mem, "team/db", 2);
        assert_eq!((p2.version, p2.created_time.as_str()), (2, "2025-01-02T00:00:00+00:00"));
        assert_eq!(p2.data["password"], "v2-S3CRET", "a soft-deleted version stays recoverable");
        assert!(p2.deletion_time.is_empty() && !p2.destroyed, "deletion lives in metadata only");

        let v3 = &meta.versions["3"];
        assert!(v3.deletion_time.is_empty() && !v3.destroyed);
        assert_eq!((v3.username.as_str(), v3.operation.as_str()), ("bob", "update"));
        let p3 = payload(&mem, "team/db", 3);
        assert_eq!((p3.version, p3.created_time.as_str()), (3, "2025-01-03T00:00:00+00:00"));
        assert_eq!(p3.data["password"], "v3-S3CRET");
        assert_eq!(merge_env(&p3.data, &p3.envs["prod"])["password"], "v3-PROD-S3CRET");

        // `metadata/` is written last, so a half-written import is invisible.
        assert_eq!(mem.last_put().as_deref(), Some("metadata/team/db"));

        // A pruned history starts above 1; unset settings take their defaults.
        let mem = Arc::new(MemStorage::default());
        let body = json!({"versions": [live(8), live(7)], "current": 8});
        assert_eq!(import(&mem, "pruned", body).unwrap().versions, 2);
        let meta = metadata(&mem, "pruned");
        assert_eq!((meta.current_version, meta.oldest_version), (8, 7));
        assert_eq!(meta.delete_version_after, "0s");
        assert_eq!(meta.created_time, "2025-02-01T00:00:00+00:00", "the oldest version's");
        assert!(chrono::DateTime::parse_from_rfc3339(&meta.updated_time).is_ok(), "{}", meta.updated_time);
        assert_eq!(payload(&mem, "pruned", 7).data["k"], "v7");
    }

    #[test]
    fn import_refuses_existing_path_by_default() {
        let mem = Arc::new(MemStorage::default());
        seed_secret(&mem, "team/db", 2);
        let before = mem.snapshot();
        assert_eq!(status(import(&mem, "team/db", bundle())), 409);
        assert_eq!(status(import(&mem, "team/db", with(bundle(), "/on_conflict", json!("refuse")))), 409);
        assert_eq!(mem.snapshot(), before, "a refused import writes nothing");

        // Version data left under a path with no metadata record (an
        // interrupted import) is a collision too: never merged into.
        let mem = Arc::new(MemStorage::default());
        mem.seed("versions/team/db/4", json!({"data": {"password": "left-behind"}, "version": 4}));
        let before = mem.snapshot();
        assert_eq!(status(import(&mem, "team/db", bundle())), 409);
        assert_eq!(mem.snapshot(), before);

        // An unknown conflict mode is refused, not read as the default.
        let mem = Arc::new(MemStorage::default());
        assert_eq!(status(import(&mem, "team/db", with(bundle(), "/on_conflict", json!("merge")))), 400);
        assert!(mem.snapshot().is_empty());
    }

    #[test]
    fn import_refuses_overwrite() {
        // Through this route an overwrite would skip the delete ACL and the
        // owner, share and asset-group cleanup of a real delete: the caller
        // deletes the destination first, then imports with `refuse`.
        let body = || with(bundle(), "/on_conflict", json!("overwrite"));
        let refusal = |r: Result<KvImportSummary, RvError>| match r {
            Err(RvError::ErrResponseStatus(400, m)) => m,
            other => panic!("expected a 400, got {other:?}"),
        };

        let mem = Arc::new(MemStorage::default());
        seed_secret(&mem, "team/db", 6);
        let before = mem.snapshot();
        let message = refusal(import(&mem, "team/db", body()));
        assert!(message.contains("refuse or rename"), "{message}");
        assert_eq!(mem.snapshot(), before, "a refused import writes nothing");

        // Refused as a mode, not only on a collision: an empty path too.
        let mem = Arc::new(MemStorage::default());
        refusal(import(&mem, "team/db", body()));
        assert!(mem.snapshot().is_empty());
        mem.seed("versions/team/db/9", json!({"data": {"password": "left-behind"}, "version": 9}));
        refusal(import(&mem, "team/db", body()));
        assert!(mem.has("versions/team/db/9") && !mem.has("metadata/team/db"));
    }

    #[test]
    fn import_rename_picks_a_free_path() {
        let mem = Arc::new(MemStorage::default());
        seed_secret(&mem, "team/db", 2);
        let existing = mem.snapshot();

        let renamed = import(&mem, "team/db", with(bundle(), "/on_conflict", json!("rename"))).unwrap();
        assert_eq!(renamed.path, "team/db-2");
        assert_eq!(metadata(&mem, "team/db-2").current_version, 3);
        assert_eq!(payload(&mem, "team/db-2", 3).data["password"], "v3-S3CRET");
        for (k, v) in &existing {
            assert_eq!(mem.snapshot().get(k), Some(v), "{k} changed under a rename import");
        }

        // Leftover version data makes a candidate taken, too.
        mem.seed("versions/team/db-3/1", json!({"data": {}, "version": 1}));
        let again = import(&mem, "team/db", with(bundle(), "/on_conflict", json!("rename"))).unwrap();
        assert_eq!(again.path, "team/db-4");

        // Nothing in the way keeps the requested path.
        let fresh = import(&mem, "fresh", with(bundle(), "/on_conflict", json!("rename"))).unwrap();
        assert_eq!(fresh.path, "fresh");
    }

    #[test]
    fn import_does_not_count_nested_secrets_as_a_collision() {
        // `team/db/child` lists as `db/` under `team/` and as `child/` under
        // `team/db/`: neither is a secret at `team/db`.
        let mem = Arc::new(MemStorage::default());
        seed_secret(&mem, "team/db/child", 1);
        assert_eq!(import(&mem, "team/db", bundle()).unwrap().path, "team/db");
        assert_eq!(metadata(&mem, "team/db/child").current_version, 1);
    }

    #[test]
    fn import_rejects_unsafe_paths() {
        let mem = Arc::new(MemStorage::default());
        for path in
            ["", "/a", "a/", "a//b", "..", "../x", "a/../b", "a/..", ".", "./a", "a/./b", "a/.", "a\u{7}b", "a\nb"]
        {
            assert_eq!(status(import(&mem, path, bundle())), 400, "path {path:?}");
        }
        assert!(mem.snapshot().is_empty(), "a refused import writes nothing");
    }

    #[test]
    fn import_refuses_dot_dot_anywhere_and_accepts_single_dots() {
        // `BarrierView::sanity_check` refuses any key containing `..` (a 500
        // in production), so no such secret can exist: refuse it with a 400.
        let mem = Arc::new(MemStorage::default());
        for path in ["a..b", "a/../b", "...", "team/v1..v2"] {
            assert_eq!(status(import(&mem, path, bundle())), 400, "path {path:?}");
        }
        assert!(mem.snapshot().is_empty(), "a refused import writes nothing");

        // A single dot inside a segment is an ordinary name.
        for path in ["v1.2", "team/v1.2", ".env"] {
            assert_eq!(import(&mem, path, bundle()).unwrap().path, path);
            assert_eq!(metadata(&mem, path).current_version, 3, "{path}");
        }
    }

    #[test]
    fn import_rejects_malformed_bundles() {
        // (case, body, a fragment of the refusal naming the rule it broke)
        let cases: Vec<(&str, Value, &str)> = vec![
            ("no versions", json!({"versions": [], "current": 0}), "must not be empty"),
            ("version 0", json!({"versions": [live(0)], "current": 0}), "between 1 and"),
            // The next write's `current_version + 1` must not overflow.
            ("version 2^53", json!({"versions": [live(1 << 53)], "current": 1u64 << 53}), "between 1 and"),
            ("version u64::MAX", json!({"versions": [live(u64::MAX)], "current": u64::MAX}), "between 1 and"),
            ("duplicate version", json!({"versions": [live(1), live(1)], "current": 1}), "appears twice"),
            ("non-contiguous", json!({"versions": [live(1), live(3)], "current": 3}), "contiguous from 1 to 3"),
            ("current not the highest", with(bundle(), "/current", json!(2)), "current must be the highest"),
            ("current above every version", with(bundle(), "/current", json!(4)), "current must be the highest"),
            ("bad created_time", with(bundle(), "/versions/0/created_time", json!("yesterday")), "created_time"),
            ("deleted, no deletion_time", with(bundle(), "/versions/2/deletion_time", json!("")), "no deletion_time"),
            ("destroyed, no deletion_time", with(bundle(), "/versions/1/deletion_time", json!("")), "no deletion_time"),
            ("bad deletion_time", with(bundle(), "/versions/2/deletion_time", json!("soon")), "deletion_time is not"),
            (
                "deletion_time on a live version",
                with(bundle(), "/versions/0/deletion_time", json!("2025-01-06T00:00:00+00:00")),
                "neither deleted nor destroyed",
            ),
            ("destroyed with data", with(bundle(), "/versions/1/data", json!({"password": "x"})), "carry no data"),
            ("destroyed with envs", with(bundle(), "/versions/1/envs", json!({"prod": {}})), "carry no data"),
            ("live without data", with(bundle(), "/versions/0/data", Value::Null), "data is required"),
            ("deleted without data", with(bundle(), "/versions/2/data", Value::Null), "data is required"),
            ("env name with '/'", with(bundle(), "/versions/0/envs", json!({"a/b": {}})), "environment name"),
            ("empty env name", with(bundle(), "/versions/0/envs", json!({"": {}})), "environment name"),
            ("bad created_time", with(bundle(), "/metadata/created_time", json!("x")), "metadata.created_time"),
            ("bad updated_time", with(bundle(), "/metadata/updated_time", json!("x")), "metadata.updated_time"),
            ("bad duration", with(bundle(), "/metadata/delete_version_after", json!("forever")), "delete_version"),
            ("unknown metadata field", with(bundle(), "/metadata/custom_metadata", json!({})), "custom_metadata"),
            ("unknown version field", with(bundle(), "/versions/0/note", json!("x")), "unknown field `note`"),
            ("unknown top-level field", with(bundle(), "/origin", json!("ns-a/x")), "unknown field `origin`"),
            ("version not a number", with(bundle(), "/versions/0/version", json!("3/../4")), "bundle's shape"),
            (
                "current missing",
                {
                    let mut b = bundle();
                    b.as_object_mut().unwrap().remove("current");
                    b
                },
                "missing field `current`",
            ),
        ];
        for (what, body, rule) in cases {
            let mem = Arc::new(MemStorage::default());
            let err = import(&mem, "team/db", body).err().unwrap_or_else(|| panic!("{what}: imported"));
            assert!(matches!(&err, RvError::ErrResponseStatus(400, m) if m.contains(rule)), "{what}: {err}");
            assert!(mem.snapshot().is_empty(), "{what}: a refused import writes nothing");
        }
    }

    #[test]
    fn import_parse_errors_never_echo_values() {
        // serde's own type-error message quotes the offending string, which
        // in a bundle can be secret material; validation must not echo either.
        for pointer in ["/versions/0/data", "/versions/0/envs", "/versions/0/version", "/versions/0/created_time"] {
            let mem = Arc::new(MemStorage::default());
            let body = with(bundle(), pointer, json!("hunter2-S3CRET"));
            let err = import(&mem, "team/db", body).expect_err("not a valid value for the field");
            assert!(matches!(err, RvError::ErrResponseStatus(400, _)), "{pointer}: {err:?}");
            assert!(!format!("{err:?} {err}").contains("hunter2"), "{pointer}: {err:?}");
        }

        // A missing or unknown field is named: a field name is not a value.
        let mut body = bundle();
        body.as_object_mut().unwrap().remove("current");
        let err = import(&Arc::new(MemStorage::default()), "team/db", body).err().unwrap();
        assert!(format!("{err}").contains("current"), "{err}");
        let body = with(bundle(), "/metadata/custom_metadata", json!({}));
        let err = import(&Arc::new(MemStorage::default()), "team/db", body).err().unwrap();
        assert!(format!("{err}").contains("custom_metadata"), "{err}");
    }

    #[test]
    fn import_denies_env_scoped_tokens() {
        // An AppRole token scoped to environments may not write base data
        // (`enforce_env_scope`), and an import writes it.
        let mem = Arc::new(MemStorage::default());
        let mut req = request(&mem, "team/db", bundle());
        let mut auth = Auth::default();
        auth.metadata.insert("approle_env_scoped".into(), "true".into());
        auth.metadata.insert("approle_env_secret".into(), "*".into());
        req.auth = Some(auth);
        let err = block_on(import_from_request(&req)).err().unwrap();
        assert!(matches!(err, RvError::ErrPermissionDenied), "{err:?}");
        assert!(mem.snapshot().is_empty());
    }

    #[test]
    fn import_route_captures_the_whole_nested_path() {
        let mut backend = LogicalBackend::new();
        backend.paths.push(Arc::new(Path::new(TRANSFER_IMPORT_PATTERN)));
        backend.init().unwrap();
        let (_, captures) = backend.match_path("v2/transfer/import/team/db").unwrap();
        assert_eq!(captures["name"], "team/db");
        // Anchored: a secret named like the route is not the route.
        assert!(backend.match_path("data/v2/transfer/import/x").is_none());
    }
}
