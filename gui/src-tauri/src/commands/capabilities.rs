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
use crate::state::AppState;

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
    // capabilities-self is a v2-only route. Embedded mode routes by logical
    // path; the remote backend now defaults to the `/v2` prefix, so the same
    // relative path lands on `/v2/sys/capabilities-self` in both modes.
    let path = "sys/capabilities-self".to_string();

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
