use std::collections::HashMap;

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

use super::make_request;

/// The dedicated resource engine is mounted at this path.
const RESOURCE_MOUNT: &str = "resources/";

// ── Resource Metadata ──────────────────────────────────────────────

/// ResourceMetadata is now a flexible JSON object — the frontend defines the schema
/// based on the resource type configuration. We just pass it through.
type ResourceMetadata = Map<String, Value>;

#[derive(Serialize)]
pub struct ResourceListResult {
    pub resources: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceSecretListResult {
    pub keys: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceSecretData {
    pub data: HashMap<String, Value>,
}

// ── Type Configuration ─────────────────────────────────────────────

#[tauri::command]
pub async fn resource_types_read(state: State<'_, AppState>) -> CmdResult<Option<Value>> {
    let path = format!("{RESOURCE_MOUNT}config/types");
    let resp = make_request(&state, Operation::Read, path, None).await?;
    match resp {
        Some(r) => Ok(r.data.map(Value::Object)),
        None => Ok(None),
    }
}

/// The type configuration the server enforces for the active namespace:
/// `{ source: "mount" | "root" | "none", types: object | null }`. A child
/// namespace that saved none inherits the root namespace's.
#[tauri::command]
pub async fn resource_types_read_effective(state: State<'_, AppState>) -> CmdResult<Value> {
    let path = format!("{RESOURCE_MOUNT}v2/config/types/effective");
    let resp = make_request(&state, Operation::Read, path, None).await?;
    resp.and_then(|r| r.data)
        .map(Value::Object)
        .ok_or_else(|| CommandError::from("the effective resource type configuration read returned no data"))
}

#[tauri::command]
pub async fn resource_types_write(state: State<'_, AppState>, types: Value) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}config/types");
    let body = types.as_object().cloned().ok_or_else(|| CommandError::from("types must be a JSON object"))?;
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

// ── Resource CRUD ──────────────────────────────────────────────────
// Uses the dedicated resource engine at resources/

// ── Paginated metadata search ─────────────────────────────────────
//
// Routes through the resource backend's `resources/search` POST
// handler, which scans META_PREFIX and returns a page of card-shaped
// metadata. Used by the Resources page to avoid the
// list-then-fan-out-reads pattern that doesn't scale past a few
// hundred resources.

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSearchInput {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default, rename = "type")]
    pub type_filter: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ResourceSearchResult {
    pub items: Vec<Value>,
    pub total: u64,
    pub has_more: bool,
}

#[tauri::command]
pub async fn search_resources(
    state: State<'_, AppState>,
    input: ResourceSearchInput,
) -> CmdResult<ResourceSearchResult> {
    let path = format!("{RESOURCE_MOUNT}resources/search");
    let mut body = Map::new();
    if let Some(q) = input.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        body.insert("q".into(), Value::String(q.to_string()));
    }
    if let Some(t) = input.type_filter.as_deref().filter(|s| !s.is_empty()) {
        body.insert("type".into(), Value::String(t.to_string()));
    }
    body.insert("offset".into(), Value::Number(input.offset.unwrap_or(0).into()));
    body.insert("limit".into(), Value::Number(input.limit.unwrap_or(30).into()));

    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let data = resp.and_then(|r| r.data).ok_or_else(|| CommandError::from("search returned no data"))?;

    let items = data
        .get("items")
        .cloned()
        .and_then(|v| match v {
            Value::Array(xs) => Some(xs),
            _ => None,
        })
        .unwrap_or_default();
    let total = data.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let has_more = data.get("has_more").and_then(|v| v.as_bool()).unwrap_or(false);

    Ok(ResourceSearchResult { items, total, has_more })
}

#[tauri::command]
pub async fn list_resources(
    state: State<'_, AppState>,
    // mount and mount_type kept for API compat but ignored — we always use RESOURCE_MOUNT
    #[allow(unused_variables)] mount: Option<String>,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceListResult> {
    let path = format!("{RESOURCE_MOUNT}resources/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let resources = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(ResourceListResult { resources });
                }
            }
            Ok(ResourceListResult { resources: vec![] })
        }
        None => Ok(ResourceListResult { resources: vec![] }),
    }
}

#[tauri::command]
pub async fn read_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceMetadata> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = r.data {
                return Ok(data);
            }
            Err("Resource not found".into())
        }
        None => Err("Resource not found".into()),
    }
}

/// The caller's own effective SQL capabilities on a database resource
/// (`resources/v2/sql/privileges/<resource>`, features/sql-browser.md §9.5):
/// `server`, `resource_wide` and, for `objects` (`catalog/schema/object`
/// triples), per-object lists. A display read: nothing is enforced from it.
#[tauri::command]
pub async fn resource_sql_privileges(
    state: State<'_, AppState>,
    resource: String,
    objects: Option<Vec<String>>,
) -> CmdResult<Value> {
    // The name is one path segment and the objects ride in the query string:
    // refuse anything that would change either.
    if resource.is_empty() || resource.contains(['/', '?', '#']) {
        return Err("resource name must be a single path segment".into());
    }
    let mut path = format!("{RESOURCE_MOUNT}v2/sql/privileges/{resource}");
    if let Some(triples) = objects.filter(|o| !o.is_empty()) {
        path.push_str("?objects=");
        path.push_str(&triples.join(","));
    }
    let resp = make_request(&state, Operation::Read, path, None).await?;
    Ok(Value::Object(resp.and_then(|r| r.data).unwrap_or_default()))
}

#[tauri::command]
pub async fn write_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    metadata: ResourceMetadata,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");

    let mut body = metadata;
    body.insert("name".to_string(), Value::String(name));
    let now = chrono::Utc::now().to_rfc3339();
    if !body.contains_key("created_at") || body.get("created_at").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        body.insert("created_at".to_string(), Value::String(now.clone()));
    }
    body.insert("updated_at".to_string(), Value::String(now));

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

/// True for the router's "no engine mounted at this path" error
/// (`RvError::ErrRouterMountNotFound`, rendered as `Router mount not found.`).
fn is_mount_not_found(message: &str) -> bool {
    message.contains("Router mount not found")
}

/// Rename a resource, moving its identity and every piece of associated
/// data to `new_name`. Two engine calls, orchestrated here because they
/// live in separate mounts:
///
///   1. The resource engine's `resources/<old>/rename` migrates the
///      metadata, change history, secrets (+ versions), asset-group
///      membership, share grants, and ownership record. It returns the
///      canonical (lowercased) new name.
///   2. The files engine's `files/repoint-resource` re-points every file
///      attached to the old name at the (canonical) new name.
///
/// Files are re-pointed with the *canonical* name returned by step 1 so
/// the file's `resource` field matches the renamed resource's key. A
/// failure in step 1 aborts before any file is touched; a failure in
/// step 2 leaves the resource renamed but its files still pointing at the
/// old name (surfaced to the caller as an error so it can be retried).
///
/// Returns the canonical new name.
#[tauri::command]
pub async fn rename_resource(state: State<'_, AppState>, old_name: String, new_name: String) -> CmdResult<String> {
    let mut body = Map::new();
    body.insert("new_name".to_string(), Value::String(new_name.clone()));
    let path = format!("{RESOURCE_MOUNT}resources/{old_name}/rename");
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;

    // Prefer the canonical name the engine echoes back; fall back to a
    // trimmed+lowercased form so a terse response still re-points files
    // at the right key.
    let canonical = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("name").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_else(|| new_name.trim().to_ascii_lowercase());

    let mut repoint = Map::new();
    repoint.insert("old_resource".to_string(), Value::String(old_name));
    repoint.insert("new_resource".to_string(), Value::String(canonical.clone()));
    // The files engine is mounted at `files/` and its backend paths repeat
    // the `files/` segment, so the full path is `files/files/...`.
    //
    // When the files engine is not mounted (or not mounted in the active
    // namespace) no file can be attached to this resource, so the router's
    // "mount not found" means there is nothing to re-point. Any other error
    // still surfaces: the resource is already renamed and the caller retries.
    match make_request(&state, Operation::Write, "files/files/repoint-resource".to_string(), Some(repoint)).await {
        Ok(_) => {}
        Err(e) if is_mount_not_found(&e.message) => {}
        Err(e) => return Err(e),
    }

    Ok(canonical)
}

// ── Namespace transfer (copy / move to another namespace) ──────────

/// One side of a transfer, as `v2/sys/namespace-transfer/{copy|move}` takes
/// it. `namespace` is `""` for the root namespace; `mount` carries no
/// namespace prefix (the server refuses one).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransferLocation {
    pub namespace: String,
    pub mount: String,
    pub path: String,
}

/// What the transfer wrote (or, on a dry run, would write).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TransferCounts {
    #[serde(default)]
    pub secrets: u64,
    #[serde(default)]
    pub versions: u64,
    #[serde(default)]
    pub history: u64,
    #[serde(default)]
    pub shares: u64,
}

/// A non-fatal finding: something the destination will not carry or a
/// choice the server made. `subject` names the grantee, group or item.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TransferWarning {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub message: String,
}

/// Counts and warnings only; the server never returns a secret value.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TransferResult {
    #[serde(default)]
    pub transferred: TransferCounts,
    #[serde(default)]
    pub warnings: Vec<TransferWarning>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub destination: TransferLocation,
}

/// Validate the closed vocabularies and build the route and body. Kept
/// apart from the command so the request shape is testable without a vault.
fn transfer_request(
    op: &str,
    kind: &str,
    source: &TransferLocation,
    destination: &TransferLocation,
    on_conflict: Option<&str>,
    dry_run: bool,
) -> CmdResult<(String, Map<String, Value>)> {
    if !matches!(op, "copy" | "move") {
        return Err(CommandError::from("op must be \"copy\" or \"move\""));
    }
    if !matches!(kind, "resource" | "kv-secret") {
        return Err(CommandError::from("kind must be \"resource\" or \"kv-secret\""));
    }
    let on_conflict = on_conflict.filter(|c| !c.is_empty()).unwrap_or("refuse");
    if !matches!(on_conflict, "refuse" | "rename" | "overwrite") {
        return Err(CommandError::from("on_conflict must be \"refuse\", \"rename\" or \"overwrite\""));
    }
    let side = |l: &TransferLocation| serde_json::json!({ "namespace": l.namespace, "mount": l.mount, "path": l.path });
    let mut body = Map::new();
    body.insert("kind".into(), Value::String(kind.into()));
    body.insert("source".into(), side(source));
    body.insert("destination".into(), side(destination));
    body.insert("on_conflict".into(), Value::String(on_conflict.into()));
    body.insert("dry_run".into(), Value::Bool(dry_run));
    Ok((format!("sys/namespace-transfer/{op}"), body))
}

/// Copy or move one resource (or KV secret) to another namespace through
/// `v2/sys/namespace-transfer/{copy|move}`. The server does every step as the
/// caller, so a missing right is a 403 naming it. The request is made in the
/// active namespace; `source` and `destination` name their own namespaces.
/// `dry_run` reads and checks everything and writes nothing. Never logs.
#[tauri::command]
pub async fn transfer_object(
    state: State<'_, AppState>,
    op: String,
    kind: String,
    source: TransferLocation,
    destination: TransferLocation,
    on_conflict: Option<String>,
    dry_run: Option<bool>,
) -> CmdResult<TransferResult> {
    let (path, body) =
        transfer_request(&op, &kind, &source, &destination, on_conflict.as_deref(), dry_run.unwrap_or(false))?;
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let data = resp.and_then(|r| r.data).ok_or_else(|| CommandError::from("the transfer answered without a result"))?;
    serde_json::from_value(Value::Object(data))
        .map_err(|e| CommandError::from(format!("unreadable transfer result: {e}")))
}

#[cfg(test)]
mod transfer_tests {
    use super::*;

    fn loc(ns: &str, mount: &str, path: &str) -> TransferLocation {
        TransferLocation { namespace: ns.into(), mount: mount.into(), path: path.into() }
    }

    #[test]
    fn request_matches_the_api_shape() {
        let (path, body) = transfer_request(
            "move",
            "resource",
            &loc("a", "resources", "db1"),
            &loc("", "resources", "db2"),
            None,
            true,
        )
        .unwrap();
        assert_eq!(path, "sys/namespace-transfer/move");
        assert_eq!(
            Value::Object(body),
            serde_json::json!({
                "kind": "resource",
                "source": { "namespace": "a", "mount": "resources", "path": "db1" },
                "destination": { "namespace": "", "mount": "resources", "path": "db2" },
                "on_conflict": "refuse",
                "dry_run": true,
            })
        );
    }

    #[test]
    fn closed_vocabularies_are_enforced() {
        let l = loc("", "resources", "x");
        assert!(transfer_request("rename", "resource", &l, &l, None, false).is_err());
        assert!(transfer_request("copy", "files", &l, &l, None, false).is_err());
        assert!(transfer_request("copy", "resource", &l, &l, Some("merge"), false).is_err());
        assert!(transfer_request("copy", "kv-secret", &l, &l, Some("overwrite"), false).is_ok());
    }

    #[test]
    fn result_parses_with_missing_parts() {
        let v = serde_json::json!({ "transferred": { "secrets": 2 }, "warnings": [{ "code": "renamed" }] });
        let r: TransferResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.transferred.secrets, 2);
        assert_eq!(r.warnings[0].code, "renamed");
        assert!(!r.dry_run);
    }
}

// ── Resource Secrets ───────────────────────────────────────────────

#[tauri::command]
pub async fn list_resource_secrets(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceSecretListResult> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let keys = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(ResourceSecretListResult { keys });
                }
            }
            Ok(ResourceSecretListResult { keys: vec![] })
        }
        None => Ok(ResourceSecretListResult { keys: vec![] }),
    }
}

#[tauri::command]
pub async fn read_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceSecretData> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let data = r.data.map(|m| m.into_iter().collect::<HashMap<String, Value>>()).unwrap_or_default();
            Ok(ResourceSecretData { data })
        }
        None => Err("Secret not found".into()),
    }
}

#[tauri::command]
pub async fn write_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    data: HashMap<String, String>,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    let mut body = Map::new();
    for (k, v) in data {
        body.insert(k, Value::String(v));
    }
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

// ── History / versions ─────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct ResourceHistoryEntry {
    pub ts: String,
    pub user: String,
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceHistoryResult {
    pub entries: Vec<ResourceHistoryEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ResourceSecretVersionInfo {
    pub version: u64,
    pub created_time: String,
    pub username: String,
    pub operation: String,
}

#[derive(Serialize)]
pub struct ResourceSecretVersionListResult {
    pub current_version: u64,
    pub versions: Vec<ResourceSecretVersionInfo>,
}

#[derive(Serialize)]
pub struct ResourceSecretVersionData {
    pub data: HashMap<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub username: String,
    pub operation: String,
}

/// Return the change history for a resource (newest first). Each entry
/// identifies who made the change, when, and which top-level fields were
/// modified. Before/after values are NOT returned (resource history is
/// field-level only, by design).
#[tauri::command]
pub async fn list_resource_history(state: State<'_, AppState>, name: String) -> CmdResult<ResourceHistoryResult> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}/history");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    let entries = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("entries").cloned())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    let out: Vec<ResourceHistoryEntry> =
        entries.into_iter().filter_map(|v| serde_json::from_value::<ResourceHistoryEntry>(v).ok()).collect();
    Ok(ResourceHistoryResult { entries: out })
}

/// List every stored version of a resource secret (newest first). Each
/// version has its own timestamp + username so the caller can render a
/// timeline. Use `read_resource_secret_version` to fetch a specific
/// payload.
#[tauri::command]
pub async fn list_resource_secret_versions(
    state: State<'_, AppState>,
    name: String,
    key: String,
) -> CmdResult<ResourceSecretVersionListResult> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}/history");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    let data = match resp.and_then(|r| r.data) {
        Some(d) => d,
        None => {
            return Ok(ResourceSecretVersionListResult { current_version: 0, versions: vec![] });
        }
    };

    let current_version = data.get("current_version").and_then(|v| v.as_u64()).unwrap_or(0);
    let versions = data.get("versions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let versions: Vec<ResourceSecretVersionInfo> =
        versions.into_iter().filter_map(|v| serde_json::from_value::<ResourceSecretVersionInfo>(v).ok()).collect();

    Ok(ResourceSecretVersionListResult { current_version, versions })
}

/// Read one historical version of a resource secret.
#[tauri::command]
pub async fn read_resource_secret_version(
    state: State<'_, AppState>,
    name: String,
    key: String,
    version: u64,
) -> CmdResult<ResourceSecretVersionData> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}/version/{version}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    let data = resp.and_then(|r| r.data).ok_or("Version not found")?;
    let data_map = data.get("data").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    Ok(ResourceSecretVersionData {
        data: data_map.into_iter().collect(),
        version: data.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
        created_time: data.get("created_time").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        username: data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        operation: data.get("operation").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    })
}

#[tauri::command]
pub async fn delete_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_mount_not_found;

    #[test]
    fn mount_not_found_matches_router_error_only() {
        assert!(is_mount_not_found("HTTP 404: Router mount not found."));
        assert!(is_mount_not_found("Router mount not found."));
        assert!(!is_mount_not_found("HTTP 404: file not found"));
        assert!(!is_mount_not_found("permission denied"));
    }
}
