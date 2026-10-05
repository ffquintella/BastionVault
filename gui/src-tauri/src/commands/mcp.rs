//! Tauri commands for MCP Access (`features/mcp-access.md`, Phase 5).
//!
//! Two surfaces:
//!
//! * **Admin -> MCP Apps** -- the vault-side registry (`sys/mcp/apps`,
//!   `sys/mcp/tokens`, `sys/mcp/config`). Each command routes through
//!   `make_request`, so it works against an embedded or a remote vault alike.
//! * **Settings -> AI Assistants** -- the workstation-side pairing store that
//!   `bvault mcp` maintains. It is read through `bv_mcp::pairing`, the same
//!   code and on-disk format the CLI uses, so the two can never disagree about
//!   what a pairing is. The store holds no tokens, so nothing here can leak
//!   one; a loopback-HTTP pairing's bearer is stored only as a hash and is not
//!   even passed to the frontend.

use bv_client::Operation;
use bv_mcp::pairing::{now_secs, PairingStore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct McpMachineWaiver {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub granted_by: String,
    #[serde(default)]
    pub granted_at: u64,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct McpApp {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub approle_role: String,
    #[serde(default)]
    pub entity_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    #[serde(default)]
    pub path_scope: Vec<String>,
    #[serde(default)]
    pub reveal_allowed: bool,
    #[serde(default)]
    pub destructive_allowed: bool,
    #[serde(default)]
    pub ttl_secs: u64,
    #[serde(default)]
    pub machine_waiver: Option<McpMachineWaiver>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct McpToken {
    #[serde(default)]
    pub accessor: String,
    /// `"app"` or `"pairing"`.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub client_version: String,
    #[serde(default)]
    pub issued_at: u64,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct McpConfig {
    #[serde(default)]
    pub default_ttl_secs: u64,
    #[serde(default)]
    pub max_ttl_secs: u64,
    #[serde(default)]
    pub waiver_max_days: u32,
    #[serde(default)]
    pub catalogue_pin: Option<String>,
}

#[derive(Serialize)]
pub struct McpCatalogueTool {
    pub name: String,
    pub description: String,
    /// `read`, `reveal`, `write` or `write+reveal`.
    pub kind: String,
}

#[derive(Serialize)]
pub struct McpCatalogue {
    pub hash: String,
    pub tools: Vec<McpCatalogueTool>,
}

/// A local pairing, minus anything secret. `pairing_token_hash` is left out
/// deliberately: the frontend has no use for it.
#[derive(Serialize)]
pub struct McpPairing {
    pub id: String,
    pub client_name: String,
    pub client_version: String,
    pub transport: String,
    pub peer_uid: Option<u32>,
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    pub ttl_secs: u64,
    pub approved_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: u64,
    pub expired: bool,
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn to_value_list(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(Value::String).collect())
}

// ── Admin -> MCP Apps ──────────────────────────────────────────────────────

#[tauri::command]
pub async fn mcp_list_apps(state: State<'_, AppState>) -> CmdResult<Vec<McpApp>> {
    let resp = make_request(&state, Operation::List, "sys/mcp/apps".into(), None).await?;
    let names = str_list(resp.and_then(|r| r.data).and_then(|d| d.get("keys").cloned()).as_ref());
    let mut apps = Vec::with_capacity(names.len());
    for name in names {
        let name = name.trim_end_matches('/').to_string();
        let read = make_request(&state, Operation::Read, format!("sys/mcp/apps/{name}"), None).await?;
        if let Some(app) =
            read.and_then(|r| r.data).and_then(|d| serde_json::from_value::<McpApp>(Value::Object(d)).ok())
        {
            apps.push(app);
        }
    }
    Ok(apps)
}

/// Create or update. The vault merges onto an existing record, so the edit
/// form sends every field it shows.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn mcp_write_app(
    state: State<'_, AppState>,
    name: String,
    approle_role: String,
    description: String,
    tool_allowlist: Vec<String>,
    path_scope: Vec<String>,
    reveal_allowed: bool,
    destructive_allowed: bool,
    ttl_secs: u64,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("approle_role".into(), Value::String(approle_role));
    body.insert("description".into(), Value::String(description));
    body.insert("tool_allowlist".into(), to_value_list(tool_allowlist));
    body.insert("path_scope".into(), to_value_list(path_scope));
    body.insert("reveal_allowed".into(), Value::Bool(reveal_allowed));
    body.insert("destructive_allowed".into(), Value::Bool(destructive_allowed));
    body.insert("ttl_secs".into(), Value::Number(ttl_secs.into()));
    make_request(&state, Operation::Write, format!("sys/mcp/apps/{name}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_delete_app(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/mcp/apps/{name}"), None).await?;
    Ok(())
}

/// Needs `sudo` on the path; the vault enforces that, this only relays.
#[tauri::command]
pub async fn mcp_grant_waiver(
    state: State<'_, AppState>,
    name: String,
    reason: String,
    expires_in_days: u64,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("reason".into(), Value::String(reason));
    body.insert("expires_in_days".into(), Value::Number(expires_in_days.into()));
    make_request(&state, Operation::Write, format!("sys/mcp/apps/{name}/machine-waiver"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_revoke_waiver(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/mcp/apps/{name}/machine-waiver"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_list_tokens(state: State<'_, AppState>) -> CmdResult<Vec<McpToken>> {
    let resp = make_request(&state, Operation::List, "sys/mcp/tokens".into(), None).await?;
    let rows = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("tokens").cloned())
        .and_then(|v| if let Value::Array(a) = v { Some(a) } else { None })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| serde_json::from_value(t).ok())
        .collect();
    Ok(rows)
}

#[tauri::command]
pub async fn mcp_revoke_token(state: State<'_, AppState>, accessor: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/mcp/tokens/{accessor}"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_read_config(state: State<'_, AppState>) -> CmdResult<McpConfig> {
    let resp = make_request(&state, Operation::Read, "sys/mcp/config".into(), None).await?;
    Ok(resp.and_then(|r| r.data).and_then(|d| serde_json::from_value(Value::Object(d)).ok()).unwrap_or_default())
}

/// An empty `catalogue_pin` clears the pin.
#[tauri::command]
pub async fn mcp_write_config(
    state: State<'_, AppState>,
    default_ttl_secs: u64,
    max_ttl_secs: u64,
    waiver_max_days: u64,
    catalogue_pin: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("default_ttl_secs".into(), Value::Number(default_ttl_secs.into()));
    body.insert("max_ttl_secs".into(), Value::Number(max_ttl_secs.into()));
    body.insert("waiver_max_days".into(), Value::Number(waiver_max_days.into()));
    body.insert("catalogue_pin".into(), Value::String(catalogue_pin.trim().to_string()));
    make_request(&state, Operation::Write, "sys/mcp/config".into(), Some(body)).await?;
    Ok(())
}

/// The catalogue compiled into *this* build and its pinnable hash. Shown so
/// an operator can pin exactly what they reviewed; it matches what the
/// server reports only when client and server are the same release.
#[tauri::command]
pub fn mcp_catalogue() -> McpCatalogue {
    let tools = bv_mcp::catalogue::catalogue()
        .iter()
        .map(|t| McpCatalogueTool {
            name: t.name.to_string(),
            description: t.description.to_string(),
            kind: match (t.destructive, t.is_reveal) {
                (true, true) => "write+reveal",
                (true, false) => "write",
                (false, true) => "reveal",
                (false, false) => "read",
            }
            .to_string(),
        })
        .collect();
    McpCatalogue { hash: bv_mcp::catalogue::catalogue_hash(), tools }
}

// ── Settings -> AI Assistants (local pairings) ─────────────────────────────

#[tauri::command]
pub fn mcp_pairings_path() -> CmdResult<String> {
    Ok(PairingStore::default_path()?.display().to_string())
}

#[tauri::command]
pub fn mcp_list_pairings() -> CmdResult<Vec<McpPairing>> {
    let records = PairingStore::at(PairingStore::default_path()?).load()?;
    let now = now_secs();
    Ok(records
        .into_iter()
        .map(|r| McpPairing {
            expired: r.is_expired(now),
            id: r.id,
            client_name: r.client_name,
            client_version: r.client_version,
            transport: r.transport,
            peer_uid: r.peer_uid,
            tool_allowlist: r.tool_allowlist,
            path_scope: r.path_scope,
            reveal_allowed: r.reveal_allowed,
            destructive_allowed: r.destructive_allowed,
            confirm_reveal: r.confirm_reveal,
            confirm_destructive: r.confirm_destructive,
            ttl_secs: r.ttl_secs,
            approved_at: r.approved_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
        })
        .collect())
}

/// Removes the local record first -- so no new token can be minted even if
/// the vault is unreachable -- then revokes the pairing's tokens on the
/// vault. A vault failure after the local removal is reported, not hidden:
/// the orphaned tokens then simply expire.
#[tauri::command]
pub async fn mcp_revoke_pairing(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let store = PairingStore::at(PairingStore::default_path()?);
    let Some(record) = store.remove(&id)? else {
        return Err(format!("no pairing with id `{id}`").into());
    };
    make_request(&state, Operation::Delete, format!("sys/mcp/pairings/{id}"), None).await.map_err(|e| {
        format!(
            "the pairing is removed from this machine, but the vault did not revoke its tokens ({e}); they expire on their own within {} hours",
            record.ttl_secs / 3600
        )
    })?;
    Ok(())
}
