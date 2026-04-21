//! Tauri commands for the per-user-scoping GUI: entity introspection,
//! owner lookup, sharing CRUD, and admin ownership transfer.
//!
//! All calls route through the embedded vault's logical layer so the
//! same policy/scope/share evaluation a remote client sees applies to
//! local GUI calls too.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bastion_vault::logical::{Operation, Request};
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

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

fn b64url(path: &str) -> String {
    URL_SAFE_NO_PAD.encode(path.as_bytes())
}

// ── Entity self ────────────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct EntitySelf {
    pub entity_id: String,
    pub username: String,
    pub mount_path: String,
    pub role_name: String,
    pub primary_mount: String,
    pub primary_name: String,
    pub created_at: String,
}

/// Lightweight alias record for the GUI user-picker. Mirrors the
/// `EntityStore::AliasRecord` shape on the backend but kept separate
/// so the Tauri surface doesn't leak internal types.
#[derive(Serialize)]
pub struct EntityAliasInfo {
    pub mount: String,
    pub name: String,
    pub entity_id: String,
}

/// Enumerate every known alias so the frontend can resolve a login
/// to an `entity_id` without making operators paste raw UUIDs into
/// the share dialog. Hits `identity/entity/aliases`, which is ACL-
/// gated; callers without access get an empty list rather than a
/// leak.
#[tauri::command]
pub async fn list_entity_aliases(
    state: State<'_, AppState>,
) -> CmdResult<Vec<EntityAliasInfo>> {
    let resp = make_request(
        &state,
        Operation::List,
        "identity/entity/aliases".into(),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let arr = data.get("aliases").and_then(|v| v.as_array()).cloned();
    let out = arr
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(EntityAliasInfo {
                mount: o
                    .get("mount")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                entity_id: o
                    .get("entity_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(out)
}

#[tauri::command]
pub async fn get_entity_self(state: State<'_, AppState>) -> CmdResult<EntitySelf> {
    let resp = make_request(&state, Operation::Read, "identity/entity/self".into(), None)
        .await?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or("no data returned for entity/self")?;

    fn s(d: &Map<String, Value>, k: &str) -> String {
        d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    Ok(EntitySelf {
        entity_id: s(&data, "entity_id"),
        username: s(&data, "username"),
        mount_path: s(&data, "mount_path"),
        role_name: s(&data, "role_name"),
        primary_mount: s(&data, "primary_mount"),
        primary_name: s(&data, "primary_name"),
        created_at: s(&data, "created_at"),
    })
}

// ── Owner lookup ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct OwnerInfo {
    pub target_kind: String,
    pub target: String,
    pub entity_id: String,
    pub owned: bool,
    pub created_at: String,
}

fn parse_owner(data: &Map<String, Value>) -> OwnerInfo {
    OwnerInfo {
        target_kind: data
            .get("target_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        target: data
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        entity_id: data
            .get("entity_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        owned: data.get("owned").and_then(|v| v.as_bool()).unwrap_or(false),
        created_at: data
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    }
}

#[tauri::command]
pub async fn get_kv_owner(
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<OwnerInfo> {
    let segment = b64url(&path);
    let resp = make_request(
        &state,
        Operation::Read,
        format!("identity/owner/kv/{segment}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(parse_owner(&data))
}

#[tauri::command]
pub async fn get_resource_owner(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<OwnerInfo> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("identity/owner/resource/{name}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(parse_owner(&data))
}

// ── Sharing ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ShareEntry {
    pub target_kind: String,
    pub target_path: String,
    pub grantee_entity_id: String,
    pub granted_by_entity_id: String,
    pub capabilities: Vec<String>,
    pub granted_at: String,
    pub expires_at: String,
    pub expired: bool,
}

#[derive(Serialize, Default)]
pub struct SharePointer {
    pub target_kind: String,
    pub target_path: String,
}

fn parse_share(v: &Value) -> Option<ShareEntry> {
    let o = v.as_object()?;
    fn s(o: &Map<String, Value>, k: &str) -> String {
        o.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
    }
    Some(ShareEntry {
        target_kind: s(o, "target_kind"),
        target_path: s(o, "target_path"),
        grantee_entity_id: s(o, "grantee_entity_id"),
        granted_by_entity_id: s(o, "granted_by_entity_id"),
        capabilities: o
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        granted_at: s(o, "granted_at"),
        expires_at: s(o, "expires_at"),
        expired: o.get("expired").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

#[tauri::command]
pub async fn list_shares_for_grantee(
    state: State<'_, AppState>,
    grantee: String,
) -> CmdResult<Vec<SharePointer>> {
    let resp = make_request(
        &state,
        Operation::List,
        format!("identity/sharing/by-grantee/{grantee}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let arr = data.get("entries").and_then(|v| v.as_array()).cloned();
    let out = arr
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(SharePointer {
                target_kind: o
                    .get("target_kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                target_path: o
                    .get("target_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect();
    Ok(out)
}

#[tauri::command]
pub async fn list_shares_for_target(
    state: State<'_, AppState>,
    kind: String,
    target_path: String,
) -> CmdResult<Vec<ShareEntry>> {
    let target = b64url(&target_path);
    let resp = make_request(
        &state,
        Operation::List,
        format!("identity/sharing/by-target/{kind}/{target}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let arr = data.get("entries").and_then(|v| v.as_array()).cloned();
    Ok(arr
        .unwrap_or_default()
        .iter()
        .filter_map(parse_share)
        .collect())
}

#[tauri::command]
pub async fn put_share(
    state: State<'_, AppState>,
    kind: String,
    target_path: String,
    grantee: String,
    capabilities: Vec<String>,
    expires_at: String,
) -> CmdResult<ShareEntry> {
    let target = b64url(&target_path);
    let mut body = Map::new();
    body.insert("target_kind".into(), Value::String(kind.clone()));
    body.insert("target_path".into(), Value::String(target_path));
    body.insert(
        "capabilities".into(),
        Value::Array(capabilities.into_iter().map(Value::String).collect()),
    );
    if !expires_at.is_empty() {
        body.insert("expires_at".into(), Value::String(expires_at));
    }

    let resp = make_request(
        &state,
        Operation::Write,
        format!("identity/sharing/by-target/{kind}/{target}/{grantee}"),
        Some(body),
    )
    .await?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or("share write returned no data")?;
    parse_share(&Value::Object(data)).ok_or_else(|| "malformed share response".into())
}

#[tauri::command]
pub async fn delete_share(
    state: State<'_, AppState>,
    kind: String,
    target_path: String,
    grantee: String,
) -> CmdResult<()> {
    let target = b64url(&target_path);
    make_request(
        &state,
        Operation::Delete,
        format!("identity/sharing/by-target/{kind}/{target}/{grantee}"),
        None,
    )
    .await?;
    Ok(())
}

// ── Ownership transfer ────────────────────────────────────────────

#[tauri::command]
pub async fn transfer_kv_owner(
    state: State<'_, AppState>,
    path: String,
    new_owner_entity_id: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("path".into(), Value::String(path));
    body.insert(
        "new_owner_entity_id".into(),
        Value::String(new_owner_entity_id),
    );
    make_request(
        &state,
        Operation::Write,
        "sys/kv-owner/transfer".into(),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn transfer_asset_group_owner(
    state: State<'_, AppState>,
    name: String,
    new_owner_entity_id: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("name".into(), Value::String(name));
    body.insert(
        "new_owner_entity_id".into(),
        Value::String(new_owner_entity_id),
    );
    make_request(
        &state,
        Operation::Write,
        "sys/asset-group-owner/transfer".into(),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn transfer_resource_owner(
    state: State<'_, AppState>,
    resource: String,
    new_owner_entity_id: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(resource));
    body.insert(
        "new_owner_entity_id".into(),
        Value::String(new_owner_entity_id),
    );
    make_request(
        &state,
        Operation::Write,
        "sys/resource-owner/transfer".into(),
        Some(body),
    )
    .await?;
    Ok(())
}
