use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

/// The dedicated files engine is mounted at this path.
const FILES_MOUNT: &str = "files/";

async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<bastion_vault::logical::Response>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = operation;
    req.path = path;
    req.client_token = token;
    req.body = body;

    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)
}

// ── Types ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct FileMeta {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct FileListResult {
    pub ids: Vec<String>,
}

#[derive(Serialize)]
pub struct FileContentResult {
    pub id: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub content_base64: String,
}

#[derive(Serialize, Deserialize)]
pub struct FileSyncTarget {
    pub name: String,
    pub kind: String,
    pub target_path: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub sync_on_write: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub state: FileSyncState,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FileSyncState {
    #[serde(default)]
    pub last_success_at: String,
    #[serde(default)]
    pub last_success_sha256: String,
    #[serde(default)]
    pub last_failure_at: String,
    #[serde(default)]
    pub last_error: String,
}

#[derive(Serialize)]
pub struct FileSyncListResult {
    pub id: String,
    pub targets: Vec<FileSyncTarget>,
}

#[derive(Serialize, Deserialize)]
pub struct FileHistoryEntry {
    pub ts: String,
    pub user: String,
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

#[derive(Serialize)]
pub struct FileHistoryResult {
    pub id: String,
    pub entries: Vec<FileHistoryEntry>,
}

// ── File CRUD ──────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_files(state: State<'_, AppState>) -> CmdResult<FileListResult> {
    let path = format!("{FILES_MOUNT}files");
    let resp = make_request(&state, Operation::List, path, None).await?;
    let ids: Vec<String> = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("keys").cloned())
        .and_then(|v| {
            v.as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        })
        .unwrap_or_default();
    Ok(FileListResult { ids })
}

#[tauri::command]
pub async fn read_file_meta(state: State<'_, AppState>, id: String) -> CmdResult<FileMeta> {
    let path = format!("{FILES_MOUNT}files/{id}");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .ok_or("file not found")?;
    let meta: FileMeta = serde_json::from_value(Value::Object(resp))
        .map_err(|e| CommandError::from(e.to_string()))?;
    Ok(meta)
}

#[tauri::command]
pub async fn read_file_content(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<FileContentResult> {
    let path = format!("{FILES_MOUNT}files/{id}/content");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .ok_or("file not found")?;
    Ok(FileContentResult {
        id: resp.get("id").and_then(|v| v.as_str()).unwrap_or_default().into(),
        mime_type: resp.get("mime_type").and_then(|v| v.as_str()).unwrap_or_default().into(),
        size_bytes: resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or_default(),
        content_base64: resp
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .into(),
    })
}

#[tauri::command]
pub async fn create_file(
    state: State<'_, AppState>,
    name: String,
    content_base64: String,
    resource: Option<String>,
    mime_type: Option<String>,
    tags: Option<Vec<String>>,
    notes: Option<String>,
) -> CmdResult<FileMeta> {
    let mut body = Map::new();
    body.insert("name".into(), Value::String(name));
    body.insert("content_base64".into(), Value::String(content_base64));
    if let Some(r) = resource {
        body.insert("resource".into(), Value::String(r));
    }
    if let Some(m) = mime_type {
        body.insert("mime_type".into(), Value::String(m));
    }
    if let Some(t) = tags {
        body.insert(
            "tags".into(),
            Value::Array(t.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(n) = notes {
        body.insert("notes".into(), Value::String(n));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{FILES_MOUNT}files"),
        Some(body),
    )
    .await?
    .and_then(|r| r.data)
    .ok_or("create did not return an id")?;
    // The create response only carries { id, size_bytes, sha256 }; fetch
    // the full meta so the caller gets a consistent shape.
    let id = resp
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("create did not return an id")?
        .to_string();
    read_file_meta(state, id).await
}

#[tauri::command]
pub async fn update_file_content(
    state: State<'_, AppState>,
    id: String,
    content_base64: String,
    name: Option<String>,
    resource: Option<String>,
    mime_type: Option<String>,
    tags: Option<Vec<String>>,
    notes: Option<String>,
) -> CmdResult<FileMeta> {
    let mut body = Map::new();
    body.insert("content_base64".into(), Value::String(content_base64));
    if let Some(n) = name {
        body.insert("name".into(), Value::String(n));
    }
    if let Some(r) = resource {
        body.insert("resource".into(), Value::String(r));
    }
    if let Some(m) = mime_type {
        body.insert("mime_type".into(), Value::String(m));
    }
    if let Some(t) = tags {
        body.insert(
            "tags".into(),
            Value::Array(t.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(n) = notes {
        body.insert("notes".into(), Value::String(n));
    }
    let _ = make_request(
        &state,
        Operation::Write,
        format!("{FILES_MOUNT}files/{id}"),
        Some(body),
    )
    .await?;
    read_file_meta(state, id).await
}

#[tauri::command]
pub async fn delete_file(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let path = format!("{FILES_MOUNT}files/{id}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[tauri::command]
pub async fn list_file_history(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<FileHistoryResult> {
    let path = format!("{FILES_MOUNT}files/{id}/history");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .unwrap_or_default();
    let entries: Vec<FileHistoryEntry> = resp
        .get("entries")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    Ok(FileHistoryResult { id, entries })
}

// ── Sync targets ───────────────────────────────────────────────────

#[tauri::command]
pub async fn list_file_sync_targets(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<FileSyncListResult> {
    let path = format!("{FILES_MOUNT}files/{id}/sync");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .unwrap_or_default();
    let targets: Vec<FileSyncTarget> = resp
        .get("targets")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    Ok(FileSyncListResult { id, targets })
}

#[tauri::command]
pub async fn write_file_sync_target(
    state: State<'_, AppState>,
    id: String,
    name: String,
    kind: String,
    target_path: String,
    mode: Option<String>,
    sync_on_write: Option<bool>,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("kind".into(), Value::String(kind));
    body.insert("target_path".into(), Value::String(target_path));
    if let Some(m) = mode {
        body.insert("mode".into(), Value::String(m));
    }
    if let Some(s) = sync_on_write {
        body.insert("sync_on_write".into(), Value::Bool(s));
    }
    make_request(
        &state,
        Operation::Write,
        format!("{FILES_MOUNT}files/{id}/sync/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_file_sync_target(
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("{FILES_MOUNT}files/{id}/sync/{name}"),
        None,
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn push_file_sync_target(
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> CmdResult<HashMap<String, Value>> {
    let path = format!("{FILES_MOUNT}files/{id}/sync/{name}/push");
    let resp = make_request(&state, Operation::Write, path, None)
        .await?
        .and_then(|r| r.data)
        .unwrap_or_default();
    Ok(resp.into_iter().collect())
}

// ── Content versioning (Phase 8) ──────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct FileVersionInfo {
    pub version: u64,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    pub created_at: String,
    pub user: String,
}

#[derive(Serialize)]
pub struct FileVersionListResult {
    pub id: String,
    pub current_version: u64,
    pub versions: Vec<FileVersionInfo>,
}

#[tauri::command]
pub async fn list_file_versions(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<FileVersionListResult> {
    let path = format!("{FILES_MOUNT}files/{id}/versions");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .unwrap_or_default();
    let current_version = resp.get("current_version").and_then(|v| v.as_u64()).unwrap_or(0);
    let versions: Vec<FileVersionInfo> = resp
        .get("versions")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    Ok(FileVersionListResult { id, current_version, versions })
}

#[tauri::command]
pub async fn read_file_version_content(
    state: State<'_, AppState>,
    id: String,
    version: u64,
) -> CmdResult<FileContentResult> {
    let path = format!("{FILES_MOUNT}files/{id}/versions/{version}/content");
    let resp = make_request(&state, Operation::Read, path, None)
        .await?
        .and_then(|r| r.data)
        .ok_or("version not found")?;
    Ok(FileContentResult {
        id: resp.get("id").and_then(|v| v.as_str()).unwrap_or_default().into(),
        mime_type: resp.get("mime_type").and_then(|v| v.as_str()).unwrap_or_default().into(),
        size_bytes: resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or_default(),
        content_base64: resp
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .into(),
    })
}

#[tauri::command]
pub async fn restore_file_version(
    state: State<'_, AppState>,
    id: String,
    version: u64,
) -> CmdResult<HashMap<String, Value>> {
    let path = format!("{FILES_MOUNT}files/{id}/versions/{version}/restore");
    let resp = make_request(&state, Operation::Write, path, None)
        .await?
        .and_then(|r| r.data)
        .unwrap_or_default();
    Ok(resp.into_iter().collect())
}
