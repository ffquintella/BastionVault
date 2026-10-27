//! Tauri commands behind the Leases page (T62, features/dynamic-secrets.md
//! Phase 5); thin wrappers over existing host paths, no new server route.
//! The remote backend speaks `/v2`. `sys/renew` and `sys/revoke` have no HTTP
//! route (docs/api.md § Leases), so remote mode sends them as one `POST
//! /v2/sys/batch` operation. Lease paths refuse a namespace header, so every
//! request here is root-scoped. Only lease state is read, never lease data.

use bv_client::{JsonResponse, Operation};
use serde::Serialize;
use serde_json::{json, Map, Value};
use tauri::State;

use super::make_request_root;
use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, VaultMode};

/// One `revoke_failed` lease, as `LIST v2/sys/leases/revoke-failed` lists it.
#[derive(Debug, Serialize, PartialEq)]
pub struct RevokeFailedLease {
    pub lease_id: String,
    pub path: String,
    pub issue_time: Option<String>,
    pub expire_time: Option<String>,
    pub attempts: u64,
    pub max_attempts: u64,
    pub exhausted: bool,
    pub first_failed_at: Option<String>,
    pub last_failed_at: Option<String>,
    /// Absent once the retries are exhausted.
    pub next_attempt_at: Option<String>,
    /// Already cut to 256 characters by the host.
    pub last_error: String,
    pub origin: String,
}

/// What a renewal reports. A remote renew goes through `sys/batch`, which
/// drops the lease block, so `lease_duration` / `renewable` are `None` there.
#[derive(Debug, Serialize, PartialEq)]
pub struct LeaseRenewResult {
    pub lease_id: String,
    pub lease_duration: Option<u64>,
    pub renewable: Option<bool>,
}

#[tauri::command]
pub async fn leases_list_revoke_failed(state: State<'_, AppState>) -> CmdResult<Vec<RevokeFailedLease>> {
    let resp = make_request_root(&state, Operation::List, "sys/leases/revoke-failed".into(), None).await?;
    Ok(revoke_failed_rows(resp.and_then(|r| r.data).as_ref()))
}

/// Force-clear: drops the lease record without asking its backend. Only for
/// after an operator cleaned the target up by hand; the host audits it first.
#[tauri::command]
pub async fn leases_force_clear_revoke_failed(state: State<'_, AppState>, lease_id: String) -> CmdResult<()> {
    let lease_id = checked_lease_id(&lease_id)?;
    let path = format!("sys/leases/revoke-failed/{lease_id}");
    make_request_root(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[tauri::command]
pub async fn leases_renew(
    state: State<'_, AppState>,
    lease_id: String,
    increment: Option<u64>,
) -> CmdResult<LeaseRenewResult> {
    let lease_id = checked_lease_id(&lease_id)?;
    let body = increment.map(|secs| json!({ "increment": secs })).and_then(|v| v.as_object().cloned());
    let resp = lease_write(&state, format!("sys/renew/{lease_id}"), body).await?;
    Ok(renew_result(lease_id, resp))
}

#[tauri::command]
pub async fn leases_revoke(state: State<'_, AppState>, lease_id: String) -> CmdResult<()> {
    let lease_id = checked_lease_id(&lease_id)?;
    lease_write(&state, format!("sys/revoke/{lease_id}"), None).await?;
    Ok(())
}

/// A `write` on one of Vault's lease paths: direct in embedded mode, one
/// `sys/batch` operation in remote mode (its refusals arrive in `results`).
async fn lease_write(
    state: &State<'_, AppState>,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Option<JsonResponse>> {
    if !matches!(*state.mode.lock().await, VaultMode::Remote) {
        return make_request_root(state, Operation::Write, path, body).await;
    }
    let mut op = json!({ "operation": "write", "path": path });
    if let Some(body) = body {
        op["data"] = Value::Object(body);
    }
    let batch = json!({ "operations": [op] }).as_object().cloned();
    let resp = make_request_root(state, Operation::Write, "sys/batch".into(), batch).await?;
    batch_outcome(resp.and_then(|r| r.data).as_ref()).map_err(CommandError::from)?;
    Ok(None)
}

/// The single operation's result of a `sys/batch` answer: `Err` with the
/// host's reason for a non-2xx status, in the `HTTP <status>: …` form the
/// remote client uses for a direct call.
fn batch_outcome(data: Option<&Map<String, Value>>) -> Result<(), String> {
    let result = data
        .and_then(|d| d.get("results"))
        .and_then(Value::as_array)
        .and_then(|r| r.first())
        .ok_or("sys/batch answered without a result")?;
    let status = result.get("status").and_then(Value::as_u64).unwrap_or(500);
    if (200..300).contains(&status) {
        return Ok(());
    }
    let errors: Vec<&str> = result
        .get("errors")
        .and_then(Value::as_array)
        .map(|e| e.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let reason = if errors.is_empty() { "request failed".to_string() } else { errors.join("; ") };
    Err(format!("HTTP {status}: {reason}"))
}

fn renew_result(lease_id: &str, resp: Option<JsonResponse>) -> LeaseRenewResult {
    let resp = resp.unwrap_or_default();
    LeaseRenewResult {
        lease_id: resp.lease_id.unwrap_or_else(|| lease_id.to_string()),
        lease_duration: resp.lease_duration,
        renewable: resp.renewable,
    }
}

fn revoke_failed_rows(data: Option<&Map<String, Value>>) -> Vec<RevokeFailedLease> {
    let empty = Map::new();
    let info = data.and_then(|d| d.get("key_info")).and_then(Value::as_object).unwrap_or(&empty);
    let keys = data.and_then(|d| d.get("keys")).and_then(Value::as_array).cloned().unwrap_or_default();
    keys.iter()
        .filter_map(Value::as_str)
        .map(|lease_id| {
            let row = info.get(lease_id).and_then(Value::as_object).unwrap_or(&empty);
            let text = |k: &str| row.get(k).and_then(Value::as_str).map(String::from);
            let count = |k: &str| row.get(k).and_then(Value::as_u64).unwrap_or(0);
            RevokeFailedLease {
                lease_id: lease_id.to_string(),
                path: text("path").unwrap_or_default(),
                issue_time: text("issue_time"),
                expire_time: text("expire_time"),
                attempts: count("attempts"),
                max_attempts: count("max_attempts"),
                exhausted: row.get("exhausted").and_then(Value::as_bool).unwrap_or(false),
                first_failed_at: text("first_failed_at"),
                last_failed_at: text("last_failed_at"),
                next_attempt_at: text("next_attempt_at"),
                last_error: text("last_error").unwrap_or_default(),
                origin: text("origin").unwrap_or_default(),
            }
        })
        .collect()
}

/// A lease id is a relative lease path. `?` and `#` would be read as a query
/// or fragment by the remote client's URL builder, so they are refused here
/// rather than sent; the host applies its own `..` / absolute-path check.
pub(crate) fn checked_lease_id(lease_id: &str) -> Result<&str, CommandError> {
    let id = lease_id.trim();
    let bad = id.is_empty()
        || id.starts_with('/')
        || id.contains("..")
        || id.contains(['?', '#'])
        || id.chars().any(char::is_control);
    if bad {
        return Err("invalid lease id: expected a relative lease path such as `database/creds/ro/<id>`".into());
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_failed_rows_keep_state_only() {
        let data = json!({
            "keys": ["db/creds/ro/a1"],
            "key_info": { "db/creds/ro/a1": {
                "path": "db/creds/ro", "attempts": 3, "max_attempts": 6, "exhausted": false,
                "next_attempt_at": "2026-10-26T10:00:00Z", "last_error": "connection refused",
                "origin": "expiry", "expire_time": "2026-10-26T09:00:00Z"
            }}
        });
        let rows = revoke_failed_rows(data.as_object());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].lease_id, "db/creds/ro/a1");
        assert_eq!((rows[0].attempts, rows[0].max_attempts), (3, 6));
        assert_eq!(rows[0].next_attempt_at.as_deref(), Some("2026-10-26T10:00:00Z"));
        assert!(revoke_failed_rows(None).is_empty());
    }

    #[test]
    fn batch_outcome_reports_the_hosts_refusal() {
        assert!(batch_outcome(json!({ "results": [{ "status": 204, "path": "p" }] }).as_object()).is_ok());
        let refused = json!({ "results": [{ "status": 403, "path": "p", "errors": ["permission denied"] }] });
        assert_eq!(batch_outcome(refused.as_object()).unwrap_err(), "HTTP 403: permission denied");
        assert!(batch_outcome(json!({ "results": [] }).as_object()).is_err());
    }

    #[test]
    fn lease_ids_that_would_change_the_url_are_refused() {
        assert_eq!(checked_lease_id(" db/creds/ro/a1 ").unwrap(), "db/creds/ro/a1");
        for bad in ["", "/db/x", "db/../x", "db/x?list=true", "db/x#frag", "db/\nx"] {
            assert!(checked_lease_id(bad).is_err(), "{bad:?}");
        }
    }
}
