//! Tauri commands for the Rustion bastion integration. Mirrors the
//! HTTP surface in `src/modules/rustion/mod.rs`:
//!
//!   rustion_target_list / read / upsert / delete
//!   rustion_target_health_all
//!   rustion_target_probe (one or all)
//!   rustion_master_read / pubkey_export
//!
//! Phase 1 of the feature spec — the GUI uses these to render the
//! Settings → Rustion Bastions section (target table, enrolment
//! wizard, per-row health dot, Test Connection button).

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

const RUSTION_MOUNT: &str = "rustion/";

#[derive(Serialize, Default)]
pub struct RustionTargetSummary {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub fingerprint: String,
    pub description: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub default_recording_dir: String,
    pub created_at: String,
    pub updated_at: String,
    pub public_key_ed25519: String,
    pub public_key_mldsa65: String,
    pub kem_public_key: String,
}

#[derive(Serialize, Default)]
pub struct RustionTargetHealth {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub status: String,
    pub last_ok_at: String,
    pub last_error: String,
    pub latency_ms_p50: u32,
    pub consecutive_failures: u32,
    pub version: String,
    pub active_sessions: u64,
    pub updated_at: String,
}

#[derive(Serialize, Default)]
pub struct RustionTargetProbeResult {
    pub id: String,
    pub name: String,
    pub status: String,
    pub last_error: String,
    pub latency_ms_p50: u32,
    pub version: String,
    pub active_sessions: u64,
    pub consecutive_failures: u32,
    pub last_ok_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct RustionMasterConfig {
    pub pki_mount: String,
    pub pki_role: String,
    pub issuer_ref: String,
    pub algorithm: String,
    pub default_ttl_secs: u64,
    pub rotate_grace_secs: u64,
    pub current_serial: String,
    pub current_not_after: String,
    pub updated_at: String,
    pub configured: bool,
}

#[derive(Serialize, Default)]
pub struct RustionMasterPubkey {
    pub algorithm: String,
    pub ed25519_pem: String,
    pub mldsa65_pem: String,
    pub fingerprint: String,
    pub current_serial: String,
    pub current_not_after: String,
    pub issued: bool,
}

#[derive(Deserialize, Default)]
pub struct RustionTargetInput {
    pub name: String,
    pub endpoint: String,
    pub public_key_ed25519: String,
    pub public_key_mldsa65: String,
    #[serde(default)]
    pub kem_public_key: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub default_recording_dir: String,
}

fn default_enabled() -> bool {
    true
}

#[tauri::command]
pub async fn rustion_target_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<RustionTargetSummary>> {
    let resp = make_request(
        &state,
        Operation::List,
        format!("{RUSTION_MOUNT}targets/"),
        None,
    )
    .await?;
    let keys: Vec<String> = resp
        .as_ref()
        .and_then(|r| r.data.as_ref())
        .and_then(|d| d.get("keys"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::with_capacity(keys.len());
    for id in keys {
        if let Ok(t) = rustion_target_read(state.clone(), id).await {
            out.push(t);
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn rustion_target_read(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<RustionTargetSummary> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}targets/{id}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(target_summary_from_map(&data))
}

#[tauri::command]
pub async fn rustion_target_upsert(
    state: State<'_, AppState>,
    id: Option<String>,
    input: RustionTargetInput,
) -> CmdResult<RustionTargetSummary> {
    let mut body = Map::new();
    body.insert("name".into(), Value::String(input.name));
    body.insert("endpoint".into(), Value::String(input.endpoint));
    body.insert(
        "public_key_ed25519".into(),
        Value::String(input.public_key_ed25519),
    );
    body.insert(
        "public_key_mldsa65".into(),
        Value::String(input.public_key_mldsa65),
    );
    body.insert(
        "kem_public_key".into(),
        Value::String(input.kem_public_key),
    );
    body.insert("description".into(), Value::String(input.description));
    body.insert(
        "tags".into(),
        Value::Array(input.tags.into_iter().map(Value::String).collect()),
    );
    body.insert("enabled".into(), Value::Bool(input.enabled));
    body.insert(
        "default_recording_dir".into(),
        Value::String(input.default_recording_dir),
    );

    let path = match id {
        Some(id) => format!("{RUSTION_MOUNT}targets/{id}"),
        None => format!("{RUSTION_MOUNT}targets/"),
    };
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(target_summary_from_map(&data))
}

#[tauri::command]
pub async fn rustion_target_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("{RUSTION_MOUNT}targets/{id}"),
        None,
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_target_health_all(
    state: State<'_, AppState>,
) -> CmdResult<Vec<RustionTargetHealth>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}targets/health"),
        None,
    )
    .await?;
    let arr = resp
        .as_ref()
        .and_then(|r| r.data.as_ref())
        .and_then(|d| d.get("targets"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(arr.into_iter().map(health_from_value).collect())
}

#[tauri::command]
pub async fn rustion_target_probe(
    state: State<'_, AppState>,
    id: Option<String>,
) -> CmdResult<RustionTargetProbeResult> {
    let path = match id {
        Some(id) => format!("{RUSTION_MOUNT}targets/{id}/probe"),
        None => format!("{RUSTION_MOUNT}targets/probe"),
    };
    let resp = make_request(&state, Operation::Write, path, None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionTargetProbeResult {
        id: s(&data, "id"),
        name: s(&data, "name"),
        status: s(&data, "status"),
        last_error: s(&data, "last_error"),
        latency_ms_p50: u32_field(&data, "latency_ms_p50"),
        version: s(&data, "version"),
        active_sessions: u64_field(&data, "active_sessions"),
        consecutive_failures: u32_field(&data, "consecutive_failures"),
        last_ok_at: s(&data, "last_ok_at"),
        updated_at: s(&data, "updated_at"),
    })
}

#[tauri::command]
pub async fn rustion_master_read(state: State<'_, AppState>) -> CmdResult<RustionMasterConfig> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}master/config"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionMasterConfig {
        pki_mount: s(&data, "pki_mount"),
        pki_role: s(&data, "pki_role"),
        issuer_ref: s(&data, "issuer_ref"),
        algorithm: s(&data, "algorithm"),
        default_ttl_secs: u64_field(&data, "default_ttl_secs"),
        rotate_grace_secs: u64_field(&data, "rotate_grace_secs"),
        current_serial: s(&data, "current_serial"),
        current_not_after: s(&data, "current_not_after"),
        updated_at: s(&data, "updated_at"),
        configured: data
            .get("configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

#[tauri::command]
pub async fn rustion_master_write(
    state: State<'_, AppState>,
    input: RustionMasterConfig,
) -> CmdResult<RustionMasterConfig> {
    let mut body = Map::new();
    if !input.pki_mount.is_empty() {
        body.insert("pki_mount".into(), Value::String(input.pki_mount));
    }
    if !input.pki_role.is_empty() {
        body.insert("pki_role".into(), Value::String(input.pki_role));
    }
    if !input.issuer_ref.is_empty() {
        body.insert("issuer_ref".into(), Value::String(input.issuer_ref));
    }
    if input.default_ttl_secs > 0 {
        body.insert(
            "default_ttl_secs".into(),
            Value::Number(input.default_ttl_secs.into()),
        );
    }
    if input.rotate_grace_secs > 0 {
        body.insert(
            "rotate_grace_secs".into(),
            Value::Number(input.rotate_grace_secs.into()),
        );
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}master/config"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionMasterConfig {
        pki_mount: s(&data, "pki_mount"),
        pki_role: s(&data, "pki_role"),
        issuer_ref: s(&data, "issuer_ref"),
        algorithm: s(&data, "algorithm"),
        default_ttl_secs: u64_field(&data, "default_ttl_secs"),
        rotate_grace_secs: u64_field(&data, "rotate_grace_secs"),
        current_serial: s(&data, "current_serial"),
        current_not_after: s(&data, "current_not_after"),
        updated_at: s(&data, "updated_at"),
        configured: data
            .get("configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

// ─── Session open ────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct RustionSessionOpenRequest {
    pub target_host: String,
    pub target_port: u16,
    pub target_protocol: String,
    #[serde(default)]
    pub target_hostkey_pin: Option<String>,
    pub credential_kind: String,
    pub credential_username: String,
    /// Base64-encoded credential bytes — the GUI never sees the raw
    /// material; it pulls it from a resolved credential source on the
    /// host side and forwards as a single string here.
    pub credential_material_b64: String,
    pub ttl_secs: u32,
    pub max_renewals: u8,
    pub recording: String,
    #[serde(default)]
    pub bastions: Option<Vec<String>>,
}

#[derive(Serialize, Default)]
pub struct RustionSessionOpenResult {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub ticket: String,
    pub expires_at: String,
    pub protocol: String,
    pub recording_id: String,
    pub bastion_id: String,
    pub bastion_name: String,
    pub bastion_selection: String,
    pub bastion_candidates_tried: Vec<String>,
    /// Correlation id BV stamped on the open envelope. Required input
    /// for subsequent `rustion_session_renew` / `rustion_session_kill`
    /// calls. Phase 5.
    pub correlation_id: String,
}

#[tauri::command]
pub async fn rustion_session_open(
    state: State<'_, AppState>,
    request: RustionSessionOpenRequest,
) -> CmdResult<RustionSessionOpenResult> {
    let mut body = Map::new();
    body.insert("target_host".into(), Value::String(request.target_host));
    body.insert("target_port".into(), Value::Number(request.target_port.into()));
    body.insert(
        "target_protocol".into(),
        Value::String(request.target_protocol),
    );
    if let Some(pin) = request.target_hostkey_pin {
        body.insert("target_hostkey_pin".into(), Value::String(pin));
    }
    body.insert(
        "credential_kind".into(),
        Value::String(request.credential_kind),
    );
    body.insert(
        "credential_username".into(),
        Value::String(request.credential_username),
    );
    body.insert(
        "credential_material".into(),
        Value::String(request.credential_material_b64),
    );
    body.insert("ttl_secs".into(), Value::Number(request.ttl_secs.into()));
    body.insert(
        "max_renewals".into(),
        Value::Number(request.max_renewals.into()),
    );
    body.insert("recording".into(), Value::String(request.recording));
    if let Some(list) = request.bastions {
        body.insert(
            "bastions".into(),
            Value::Array(list.into_iter().map(Value::String).collect()),
        );
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}session/open"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let tried = data
        .get("bastion_candidates_tried")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(RustionSessionOpenResult {
        session_id: s(&data, "session_id"),
        host: s(&data, "host"),
        port: data
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0),
        ticket: s(&data, "ticket"),
        expires_at: s(&data, "expires_at"),
        protocol: s(&data, "protocol"),
        recording_id: s(&data, "recording_id"),
        bastion_id: s(&data, "bastion_id"),
        bastion_name: s(&data, "bastion_name"),
        bastion_selection: s(&data, "bastion_selection"),
        bastion_candidates_tried: tried,
        correlation_id: s(&data, "correlation_id"),
    })
}

// ─── Phase 5: renew + kill ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionSessionRenewRequest {
    pub bastion_id: String,
    pub session_id: String,
    pub correlation_id: String,
    pub extend_secs: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionSessionRenewResult {
    pub session_id: String,
    pub expires_at: String,
    pub renewals_used: u32,
    pub max_renewals: u32,
    pub bastion_id: String,
}

#[tauri::command]
pub async fn rustion_session_renew(
    state: State<'_, AppState>,
    request: RustionSessionRenewRequest,
) -> CmdResult<RustionSessionRenewResult> {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(request.bastion_id));
    body.insert("session_id".into(), Value::String(request.session_id));
    body.insert(
        "correlation_id".into(),
        Value::String(request.correlation_id),
    );
    body.insert(
        "extend_secs".into(),
        Value::Number(request.extend_secs.into()),
    );
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}session/renew"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionSessionRenewResult {
        session_id: s(&data, "session_id"),
        expires_at: s(&data, "expires_at"),
        renewals_used: data
            .get("renewals_used")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(0),
        max_renewals: data
            .get("max_renewals")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(0),
        bastion_id: s(&data, "bastion_id"),
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionSessionKillRequest {
    pub bastion_id: String,
    pub session_id: String,
    pub correlation_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionSessionKillResult {
    pub session_id: String,
    pub terminated_at: String,
    pub bastion_id: String,
}

#[tauri::command]
pub async fn rustion_session_kill(
    state: State<'_, AppState>,
    request: RustionSessionKillRequest,
) -> CmdResult<RustionSessionKillResult> {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(request.bastion_id));
    body.insert("session_id".into(), Value::String(request.session_id));
    body.insert(
        "correlation_id".into(),
        Value::String(request.correlation_id),
    );
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}session/kill"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionSessionKillResult {
        session_id: s(&data, "session_id"),
        terminated_at: s(&data, "terminated_at"),
        bastion_id: s(&data, "bastion_id"),
    })
}

#[tauri::command]
pub async fn rustion_master_pubkey_export(
    state: State<'_, AppState>,
) -> CmdResult<RustionMasterPubkey> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}master/pubkey"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionMasterPubkey {
        algorithm: s(&data, "algorithm"),
        ed25519_pem: s(&data, "ed25519_pem"),
        mldsa65_pem: s(&data, "mldsa65_pem"),
        fingerprint: s(&data, "fingerprint"),
        current_serial: s(&data, "current_serial"),
        current_not_after: s(&data, "current_not_after"),
        issued: data
            .get("issued")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

// ─── helpers ───────────────────────────────────────────────────────

fn s(data: &Map<String, Value>, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default()
}

fn u32_field(data: &Map<String, Value>, key: &str) -> u32 {
    data.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

fn u64_field(data: &Map<String, Value>, key: &str) -> u64 {
    data.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn target_summary_from_map(data: &Map<String, Value>) -> RustionTargetSummary {
    let (ed25519, mldsa65) = data
        .get("public_key")
        .and_then(|v| v.as_object())
        .map(|pk| {
            (
                pk.get("ed25519")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_default(),
                pk.get("mldsa65")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let tags = data
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    RustionTargetSummary {
        id: s(data, "id"),
        name: s(data, "name"),
        endpoint: s(data, "endpoint"),
        fingerprint: s(data, "fingerprint"),
        description: s(data, "description"),
        tags,
        enabled: data
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        default_recording_dir: s(data, "default_recording_dir"),
        created_at: s(data, "created_at"),
        updated_at: s(data, "updated_at"),
        public_key_ed25519: ed25519,
        public_key_mldsa65: mldsa65,
        kem_public_key: s(data, "kem_public_key"),
    }
}

fn health_from_value(v: Value) -> RustionTargetHealth {
    let Value::Object(data) = v else {
        return RustionTargetHealth::default();
    };
    RustionTargetHealth {
        id: s(&data, "id"),
        name: s(&data, "name"),
        endpoint: s(&data, "endpoint"),
        enabled: data
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        status: s(&data, "status"),
        last_ok_at: s(&data, "last_ok_at"),
        last_error: s(&data, "last_error"),
        latency_ms_p50: u32_field(&data, "latency_ms_p50"),
        consecutive_failures: u32_field(&data, "consecutive_failures"),
        version: s(&data, "version"),
        active_sessions: u64_field(&data, "active_sessions"),
        updated_at: s(&data, "updated_at"),
    }
}
