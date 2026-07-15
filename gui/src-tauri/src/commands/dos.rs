//! IP-based DoS / request-abuse protection commands.
//!
//! Drive the `v2/sys/dos/*` surface: read/update the thresholds
//! (`dos/config`), read live per-IP statistics and active bans (`dos/stats`),
//! and manually ban/unban a client IP (`dos/bans/{ip}`). All are root-scoped
//! operator actions, so they dispatch via [`make_request_root`].

use bv_client::{JsonResponse, Operation};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request_root;

/// Unwrap the response `data` map into a JSON value (null when absent), which
/// the frontend models with its own TypeScript interfaces.
fn data_of(resp: Option<JsonResponse>) -> Value {
    resp.and_then(|r| r.data).map(Value::Object).unwrap_or(Value::Null)
}

#[tauri::command]
pub async fn get_dos_config(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = make_request_root(&state, Operation::Read, "sys/dos/config".into(), None).await?;
    Ok(data_of(resp))
}

/// Update DoS thresholds. `config` is a partial object — only supplied keys are
/// changed. Returns the effective (server-sanitized) config.
#[tauri::command]
pub async fn set_dos_config(
    state: State<'_, AppState>,
    config: Map<String, Value>,
) -> CmdResult<Value> {
    let resp =
        make_request_root(&state, Operation::Write, "sys/dos/config".into(), Some(config)).await?;
    Ok(data_of(resp))
}

#[tauri::command]
pub async fn get_dos_stats(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = make_request_root(&state, Operation::Read, "sys/dos/stats".into(), None).await?;
    Ok(data_of(resp))
}

/// Manually ban a client IP. `ttl_secs` defaults server-side to the configured
/// ban duration when omitted.
#[tauri::command]
pub async fn ban_ip(
    state: State<'_, AppState>,
    ip: String,
    ttl_secs: Option<u64>,
    reason: Option<String>,
) -> CmdResult<Value> {
    let mut body = Map::new();
    if let Some(ttl) = ttl_secs {
        body.insert("ttl_secs".into(), Value::from(ttl));
    }
    if let Some(reason) = reason {
        body.insert("reason".into(), Value::from(reason));
    }
    let resp =
        make_request_root(&state, Operation::Write, format!("sys/dos/bans/{ip}"), Some(body)).await?;
    Ok(data_of(resp))
}

#[tauri::command]
pub async fn unban_ip(state: State<'_, AppState>, ip: String) -> CmdResult<Value> {
    let resp =
        make_request_root(&state, Operation::Delete, format!("sys/dos/bans/{ip}"), None).await?;
    Ok(data_of(resp))
}
