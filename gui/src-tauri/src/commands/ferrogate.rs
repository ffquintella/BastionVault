//! Tauri commands for the FerroGate machine-auth admin page. Each routes
//! through `make_request` to the `auth/ferrogate/*` endpoints. Mirrors the
//! AppRole command pattern.

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

/// Trust-anchor configuration for the ferrogate mount.
#[derive(Serialize, Deserialize, Default)]
pub struct FerroGateConfig {
    #[serde(default)]
    pub trust_domain: String,
    #[serde(default)]
    pub expected_audience: String,
    #[serde(default)]
    pub jwks_source: String,
    #[serde(default)]
    pub cmis_endpoint: String,
    #[serde(default)]
    pub cmis_spki_pins: Vec<String>,
    #[serde(default)]
    pub static_jwks: String,
    #[serde(default)]
    pub accept_svid: bool,
    #[serde(default)]
    pub clock_leeway_secs: i64,
    #[serde(default)]
    pub default_token_ttl: u64,
    #[serde(default)]
    pub cmis_tls_enable: bool,
    #[serde(default)]
    pub jwks_refresh_secs: i64,
    #[serde(default)]
    pub bootstrap_root_auto_approve: bool,
    #[serde(default)]
    pub bootstrap_policies: Vec<String>,
}

/// A machine enrolment summary as listed by the admin endpoint.
#[derive(Serialize, Deserialize, Default)]
pub struct FerroGateMachine {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub spiffe_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub ek_cert_sha384: String,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub parent_svid: String,
    #[serde(default)]
    pub first_seen_at: i64,
    #[serde(default)]
    pub approved_at: i64,
    #[serde(default)]
    pub approver: String,
    #[serde(default)]
    pub last_login_at: i64,
    #[serde(default)]
    pub last_login_ip: String,
    #[serde(default)]
    pub reject_reason: String,
    #[serde(default)]
    pub comment: String,
}

#[tauri::command]
pub async fn ferrogate_read_config(state: State<'_, AppState>) -> CmdResult<FerroGateConfig> {
    let resp = make_request(&state, Operation::Read, "auth/ferrogate/config".into(), None).await?;
    match resp.and_then(|r| r.data) {
        Some(data) => Ok(serde_json::from_value(Value::Object(data)).unwrap_or_default()),
        None => Ok(FerroGateConfig::default()),
    }
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn ferrogate_write_config(
    state: State<'_, AppState>,
    trust_domain: String,
    expected_audience: String,
    jwks_source: String,
    cmis_endpoint: String,
    cmis_spki_pins: String,
    static_jwks: String,
    accept_svid: bool,
    cmis_tls_enable: bool,
    bootstrap_root_auto_approve: bool,
    bootstrap_policies: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("trust_domain".into(), Value::String(trust_domain));
    body.insert("expected_audience".into(), Value::String(expected_audience));
    if !jwks_source.is_empty() {
        body.insert("jwks_source".into(), Value::String(jwks_source));
    }
    body.insert("cmis_endpoint".into(), Value::String(cmis_endpoint));
    body.insert("cmis_spki_pins".into(), Value::String(cmis_spki_pins));
    body.insert("static_jwks".into(), Value::String(static_jwks));
    body.insert("accept_svid".into(), Value::Bool(accept_svid));
    body.insert("cmis_tls_enable".into(), Value::Bool(cmis_tls_enable));
    body.insert("bootstrap_root_auto_approve".into(), Value::Bool(bootstrap_root_auto_approve));
    body.insert("bootstrap_policies".into(), Value::String(bootstrap_policies));

    make_request(&state, Operation::Write, "auth/ferrogate/config".into(), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_list_machines(state: State<'_, AppState>) -> CmdResult<Vec<FerroGateMachine>> {
    let resp = make_request(&state, Operation::List, "auth/ferrogate/machines".into(), None).await?;
    let machines = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("machines").cloned())
        .and_then(|v| if let Value::Array(a) = v { Some(a) } else { None })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| serde_json::from_value(m).ok())
        .collect();
    Ok(machines)
}

#[tauri::command]
pub async fn ferrogate_approve(
    state: State<'_, AppState>,
    id: String,
    policies: String,
    ttl_seconds: i64,
    comment: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !policies.is_empty() {
        body.insert("policies".into(), Value::String(policies));
    }
    body.insert("ttl_seconds".into(), Value::Number(ttl_seconds.max(0).into()));
    if !comment.is_empty() {
        body.insert("comment".into(), Value::String(comment));
    }
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/approve"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_reject(state: State<'_, AppState>, id: String, reason: String) -> CmdResult<()> {
    let mut body = Map::new();
    if !reason.is_empty() {
        body.insert("reason".into(), Value::String(reason));
    }
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/reject"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_revoke(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(&state, Operation::Write, format!("auth/ferrogate/machines/{id}/revoke"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn ferrogate_delete_machine(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("auth/ferrogate/machines/{id}"), None).await?;
    Ok(())
}
