//! `sys/capabilities-self` — report the calling token's effective
//! capabilities on a set of paths so the UI can hide affordances it must
//! not offer (e.g. credential values when the caller holds only `connect`,
//! not `read`, on a resource's secrets).

use std::collections::HashMap;

use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::{AppState, VaultMode};

use super::make_request;

#[derive(Serialize)]
pub struct CapabilitiesResult {
    /// Path → the caller's capability strings on it (e.g. `["connect"]`,
    /// `["read", "list", "connect"]`, or `["deny"]`).
    pub paths: HashMap<String, Vec<String>>,
}

#[tauri::command]
pub async fn capabilities_self(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> CmdResult<CapabilitiesResult> {
    // capabilities-self is a v2-only route. In embedded mode the request
    // routes by logical path (`sys/capabilities-self`); in remote mode the
    // leading slash bypasses bv-client's default `/v1` prefix so it lands
    // on `/v2/sys/capabilities-self`.
    let path = match *state.mode.lock().await {
        VaultMode::Embedded => "sys/capabilities-self".to_string(),
        VaultMode::Remote => "/v2/sys/capabilities-self".to_string(),
    };

    let mut body = Map::new();
    body.insert(
        "paths".into(),
        Value::Array(paths.into_iter().map(Value::String).collect()),
    );

    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(Value::Object(caps)) = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("capabilities").cloned())
    {
        for (k, v) in caps {
            if let Value::Array(arr) = v {
                out.insert(
                    k,
                    arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                );
            }
        }
    }

    Ok(CapabilitiesResult { paths: out })
}
