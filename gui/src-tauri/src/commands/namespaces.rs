//! Namespace management commands (multi-tenancy).
//!
//! These drive the `v2/sys/namespaces` CRUD surface. They operate on the root
//! namespace's view (no `X-BastionVault-Namespace` header): `list` returns the
//! root's direct children and `write`/`read`/`delete` address namespaces by
//! their full slash-delimited path. A namespace *switcher* that scopes other
//! requests to a child namespace requires per-request header plumbing through
//! the `bv_client` backend trait and is tracked as a follow-up.

use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request_root;

#[derive(Serialize, Default)]
pub struct NamespaceQuotas {
    pub max_storage_bytes: u64,
    pub max_leases: u64,
    pub request_rate: u64,
    pub max_mounts: u64,
    pub max_entities: u64,
    pub max_child_namespaces: u64,
}

#[derive(Serialize)]
pub struct NamespaceInfo {
    pub uuid: String,
    pub path: String,
    pub parent_uuid: String,
    pub created_at: String,
    pub child_visible_default: bool,
    pub quotas: NamespaceQuotas,
}

#[derive(Serialize)]
pub struct NamespaceListResult {
    pub namespaces: Vec<String>,
}

fn u64_at(data: Option<&Map<String, Value>>, key: &str) -> u64 {
    data.and_then(|d| d.get("quotas"))
        .and_then(|q| q.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn to_info(data: Option<&Map<String, Value>>, fallback_path: &str) -> NamespaceInfo {
    NamespaceInfo {
        uuid: data.and_then(|d| d.get("uuid")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
        path: data
            .and_then(|d| d.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback_path)
            .to_string(),
        parent_uuid: data
            .and_then(|d| d.get("parent_uuid"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created_at: data
            .and_then(|d| d.get("created_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        child_visible_default: data
            .and_then(|d| d.get("child_visible_default"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        quotas: NamespaceQuotas {
            max_storage_bytes: u64_at(data, "max_storage_bytes"),
            max_leases: u64_at(data, "max_leases"),
            request_rate: u64_at(data, "request_rate"),
            max_mounts: u64_at(data, "max_mounts"),
            max_entities: u64_at(data, "max_entities"),
            max_child_namespaces: u64_at(data, "max_child_namespaces"),
        },
    }
}

#[tauri::command]
pub async fn list_namespaces(state: State<'_, AppState>) -> CmdResult<NamespaceListResult> {
    let resp =
        make_request_root(&state, Operation::List, "sys/namespaces".to_string(), None).await?;
    match resp {
        Some(r) => {
            let namespaces = r
                .data
                .as_ref()
                .and_then(|d| d.get("keys"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            Ok(NamespaceListResult { namespaces })
        }
        None => Ok(NamespaceListResult { namespaces: vec![] }),
    }
}

#[tauri::command]
pub async fn read_namespace(state: State<'_, AppState>, path: String) -> CmdResult<NamespaceInfo> {
    let resp =
        make_request_root(&state, Operation::Read, format!("sys/namespaces/{path}"), None).await?;
    match resp {
        Some(r) => Ok(to_info(r.data.as_ref(), &path)),
        None => Err("Namespace not found".into()),
    }
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn write_namespace(
    state: State<'_, AppState>,
    path: String,
    max_storage_bytes: u64,
    max_leases: u64,
    request_rate: u64,
    max_mounts: u64,
    max_entities: u64,
    max_child_namespaces: u64,
    child_visible_default: bool,
) -> CmdResult<NamespaceInfo> {
    let mut body = Map::new();
    body.insert("max_storage_bytes".into(), Value::from(max_storage_bytes));
    body.insert("max_leases".into(), Value::from(max_leases));
    body.insert("request_rate".into(), Value::from(request_rate));
    body.insert("max_mounts".into(), Value::from(max_mounts));
    body.insert("max_entities".into(), Value::from(max_entities));
    body.insert("max_child_namespaces".into(), Value::from(max_child_namespaces));
    body.insert("child_visible_default".into(), Value::Bool(child_visible_default));

    let resp = make_request_root(&state, Operation::Write, format!("sys/namespaces/{path}"), Some(body))
        .await?;
    Ok(to_info(resp.and_then(|r| r.data).as_ref(), &path))
}

#[tauri::command]
pub async fn delete_namespace(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request_root(&state, Operation::Delete, format!("sys/namespaces/{path}"), None).await?;
    Ok(())
}

#[derive(Serialize, Default)]
pub struct NsAssignmentResult {
    /// Allowed namespace paths (canonical; `""` = root). Empty ⇒ unrestricted.
    pub namespaces: Vec<String>,
}

fn ns_paths_from(data: Option<&Map<String, Value>>) -> Vec<String> {
    data.and_then(|d| d.get("namespaces"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Read a principal's namespace assignment (login-restriction). An empty list
/// means unrestricted — the principal may authenticate into any namespace.
/// Root-scoped: the assignment is a deployment-level fact, independent of the
/// session's active namespace.
#[tauri::command]
pub async fn get_ns_assignment(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<NsAssignmentResult> {
    let resp = make_request_root(
        &state,
        Operation::Read,
        format!("sys/identity/ns-assignment/{mount}{name}"),
        None,
    )
    .await?;
    Ok(NsAssignmentResult { namespaces: ns_paths_from(resp.and_then(|r| r.data).as_ref()) })
}

/// Set a principal's allowed namespaces. An empty list clears the restriction
/// (back to unrestricted).
#[tauri::command]
pub async fn set_ns_assignment(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    namespaces: Vec<String>,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("namespaces".into(), Value::from(namespaces));
    make_request_root(
        &state,
        Operation::Write,
        format!("sys/identity/ns-assignment/{mount}{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

/// Remove a principal's restriction (back to unrestricted). Idempotent.
#[tauri::command]
pub async fn delete_ns_assignment(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    make_request_root(
        &state,
        Operation::Delete,
        format!("sys/identity/ns-assignment/{mount}{name}"),
        None,
    )
    .await?;
    Ok(())
}

/// Set the session's active namespace (multi-tenancy switcher). An empty/blank
/// path selects the root namespace. Subsequent logical requests carry the
/// `X-BastionVault-Namespace` header for this namespace.
#[tauri::command]
pub async fn set_active_namespace(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let trimmed = path.trim().trim_matches('/').to_string();
    let mut guard = state.active_namespace.lock().await;
    *guard = if trimmed.is_empty() { None } else { Some(trimmed) };
    Ok(())
}

/// Read the session's active namespace (`""` = root).
#[tauri::command]
pub async fn get_active_namespace(state: State<'_, AppState>) -> CmdResult<String> {
    Ok(state.active_namespace.lock().await.clone().unwrap_or_default())
}
