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
    /// Multi-tenancy: `false` when the active-namespace header names a
    /// namespace the current token may not operate in — in that case every
    /// advertised capability set is empty and the caller should surface the
    /// binding mismatch rather than offer write controls that will 403.
    /// `true` for root-scoped requests and operable namespaces.
    pub namespace_operable: bool,
    /// The namespace path the token is bound to (`""` = root). Only meaningful
    /// when `namespace_operable` is `false`; empty otherwise.
    pub token_namespace: String,
    /// The active namespace the request targeted (`""` = root). Only meaningful
    /// when `namespace_operable` is `false`.
    pub active_namespace: String,
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
    let data = resp.and_then(|r| r.data);

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(Value::Object(caps)) = data.as_ref().and_then(|d| d.get("capabilities").cloned()) {
        for (k, v) in caps {
            if let Value::Array(arr) = v {
                out.insert(
                    k,
                    arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                );
            }
        }
    }

    // `namespace_operable` is absent on older servers / non-namespace builds;
    // treat its absence as "operable" so single-tenant deployments behave
    // exactly as before.
    let str_field = |k: &str| -> String {
        data.as_ref()
            .and_then(|d| d.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let namespace_operable = data
        .as_ref()
        .and_then(|d| d.get("namespace_operable"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Ok(CapabilitiesResult {
        paths: out,
        namespace_operable,
        token_namespace: str_field("token_namespace"),
        active_namespace: str_field("active_namespace"),
    })
}
