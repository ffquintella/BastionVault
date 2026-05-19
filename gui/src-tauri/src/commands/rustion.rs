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
    /// Phase 7.3 — hints the BV policy resolver uses to look up the
    /// full per-tier chain. Optional; resolver falls back to global
    /// when omitted.
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub asset_group_ids: Option<Vec<String>>,
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
    // Phase 7.3 — policy resolver hints. BV looks these up in its
    // policy store to walk the full type → asset-group → resource
    // tier chain on top of the global policy.
    if let Some(rid) = request.resource_id {
        body.insert("resource_id".into(), Value::String(rid));
    }
    if let Some(rt) = request.resource_type {
        body.insert("resource_type".into(), Value::String(rt));
    }
    if let Some(ags) = request.asset_group_ids {
        body.insert(
            "asset_group_ids".into(),
            Value::Array(ags.into_iter().map(Value::String).collect()),
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

// ─── Phase 6.2/6.3: recordings ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionRecordingEntry {
    pub recording_id: String,
    pub session_id: String,
    pub authority: String,
    pub format: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub started_at: String,
    pub finished_at: String,
    pub target_host: String,
    pub target_user: String,
    pub correlation_id: String,
    pub bastion_id: String,
    pub received_at: String,
    pub delivery_mode: String,
}

fn recording_from_map(data: &Map<String, Value>) -> RustionRecordingEntry {
    RustionRecordingEntry {
        recording_id: s(data, "recording_id"),
        session_id: s(data, "session_id"),
        authority: s(data, "authority"),
        format: s(data, "format"),
        sha256: s(data, "sha256"),
        size_bytes: u64_field(data, "size_bytes"),
        started_at: s(data, "started_at"),
        finished_at: s(data, "finished_at"),
        target_host: s(data, "target_host"),
        target_user: s(data, "target_user"),
        correlation_id: s(data, "correlation_id"),
        bastion_id: s(data, "bastion_id"),
        received_at: s(data, "received_at"),
        delivery_mode: s(data, "delivery_mode"),
    }
}

#[tauri::command]
pub async fn rustion_recordings_list(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}recordings"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("recordings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_recording_read(
    state: State<'_, AppState>,
    recording_id: String,
) -> CmdResult<RustionRecordingEntry> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}recordings/{recording_id}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(recording_from_map(&data))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionRecordingPullRequest {
    pub bastion_id: String,
    pub session_id: String,
}

#[tauri::command]
pub async fn rustion_recording_pull(
    state: State<'_, AppState>,
    request: RustionRecordingPullRequest,
) -> CmdResult<RustionRecordingEntry> {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(request.bastion_id));
    body.insert("session_id".into(), Value::String(request.session_id));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}recordings/pull"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(recording_from_map(&data))
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionRecordingBlob {
    pub recording_id: String,
    pub format: String,
    pub sha256: String,
    /// Base64-encoded recording bytes. The frontend decodes via
    /// `atob` into a Uint8Array before handing to the player. Kept
    /// as base64 over the Tauri boundary because the IPC layer
    /// flattens binary into JSON anyway — avoiding the array→JSON
    /// blow-up.
    pub bytes_b64: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionRecordingReplayLog {
    pub recording_id: String,
    /// Set to true when the blob's recomputed sha256 didn't match
    /// the sidecar's. The audit event surfaces this so SOC tooling
    /// can flag tampered downloads.
    pub sha256_mismatch: bool,
}

#[tauri::command]
pub async fn rustion_recording_replay_log(
    state: State<'_, AppState>,
    input: RustionRecordingReplayLog,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert(
        "recording_id".into(),
        Value::String(input.recording_id),
    );
    body.insert(
        "sha256_mismatch".into(),
        Value::Bool(input.sha256_mismatch),
    );
    make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}recordings/replay-log"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_recording_blob(
    state: State<'_, AppState>,
    recording_id: String,
) -> CmdResult<RustionRecordingBlob> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}recordings/{recording_id}/blob"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionRecordingBlob {
        recording_id: s(&data, "recording_id"),
        format: s(&data, "format"),
        sha256: s(&data, "sha256"),
        bytes_b64: s(&data, "bytes_b64"),
        size_bytes: u64_field(&data, "size_bytes"),
    })
}

// ─── Phase 7: policy + bastion groups ────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionPolicyTier {
    pub transport: String,
    pub bastions: Vec<String>,
    pub bastion_group: String,
    pub recording: String,
    pub lock: bool,
}

#[tauri::command]
pub async fn rustion_policy_global_read(
    state: State<'_, AppState>,
) -> CmdResult<RustionPolicyTier> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}policy/global"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionPolicyTier {
        transport: s(&data, "transport"),
        bastions: data
            .get("bastions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bastion_group: s(&data, "bastion_group"),
        recording: s(&data, "recording"),
        lock: data.get("lock").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

#[tauri::command]
pub async fn rustion_policy_global_write(
    state: State<'_, AppState>,
    input: RustionPolicyTier,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !input.transport.is_empty() {
        body.insert("transport".into(), Value::String(input.transport));
    }
    body.insert(
        "bastions".into(),
        Value::Array(input.bastions.into_iter().map(Value::String).collect()),
    );
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}policy/global"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionBastionGroup {
    pub name: String,
    pub members: Vec<String>,
    pub selection: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

fn group_from_map(data: &Map<String, Value>) -> RustionBastionGroup {
    RustionBastionGroup {
        name: s(data, "name"),
        members: data
            .get("members")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        selection: s(data, "selection"),
        description: s(data, "description"),
        created_at: s(data, "created_at"),
        updated_at: s(data, "updated_at"),
    }
}

#[tauri::command]
pub async fn rustion_bastion_group_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<String>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}bastion-groups"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_bastion_group_read(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<RustionBastionGroup> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}bastion-groups/{name}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(group_from_map(&data))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionBastionGroupInput {
    pub name: String,
    pub members: Vec<String>,
    pub selection: String,
    pub description: String,
}

#[tauri::command]
pub async fn rustion_bastion_group_create(
    state: State<'_, AppState>,
    input: RustionBastionGroupInput,
) -> CmdResult<RustionBastionGroup> {
    let mut body = Map::new();
    body.insert("name".into(), Value::String(input.name));
    body.insert(
        "members".into(),
        Value::Array(input.members.into_iter().map(Value::String).collect()),
    );
    body.insert("selection".into(), Value::String(input.selection));
    body.insert("description".into(), Value::String(input.description));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}bastion-groups"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(group_from_map(&data))
}

#[tauri::command]
pub async fn rustion_bastion_group_update(
    state: State<'_, AppState>,
    name: String,
    input: RustionBastionGroupInput,
) -> CmdResult<RustionBastionGroup> {
    let mut body = Map::new();
    body.insert(
        "members".into(),
        Value::Array(input.members.into_iter().map(Value::String).collect()),
    );
    body.insert("selection".into(), Value::String(input.selection));
    body.insert("description".into(), Value::String(input.description));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}bastion-groups/{name}"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(group_from_map(&data))
}

#[tauri::command]
pub async fn rustion_bastion_group_delete(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("{RUSTION_MOUNT}bastion-groups/{name}"),
        None,
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionTypePolicy {
    pub name: String,
    pub transport: String,
    pub bastions: Vec<String>,
    pub bastion_group: String,
    pub recording: String,
    pub lock: bool,
    pub updated_at: String,
}

fn type_policy_from_map(data: &Map<String, Value>) -> RustionTypePolicy {
    RustionTypePolicy {
        name: s(data, "name"),
        transport: s(data, "transport"),
        bastions: data
            .get("bastions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bastion_group: s(data, "bastion_group"),
        recording: s(data, "recording"),
        lock: data.get("lock").and_then(|v| v.as_bool()).unwrap_or(false),
        updated_at: s(data, "updated_at"),
    }
}

#[tauri::command]
pub async fn rustion_policy_type_read(
    state: State<'_, AppState>,
    type_name: String,
) -> CmdResult<RustionTypePolicy> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}policy/type/{type_name}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(type_policy_from_map(&data))
}

#[tauri::command]
pub async fn rustion_policy_type_write(
    state: State<'_, AppState>,
    type_name: String,
    input: RustionPolicyTier,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !input.transport.is_empty() {
        body.insert("transport".into(), Value::String(input.transport));
    }
    body.insert(
        "bastions".into(),
        Value::Array(input.bastions.into_iter().map(Value::String).collect()),
    );
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}policy/type/{type_name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_policy_type_delete(
    state: State<'_, AppState>,
    type_name: String,
) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("{RUSTION_MOUNT}policy/type/{type_name}"),
        None,
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionAssetGroupPolicy {
    pub priority: i32,
    pub transport: String,
    pub bastions: Vec<String>,
    pub bastion_group: String,
    pub recording: String,
    pub lock: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionAssetGroupPolicyInput {
    pub priority: i32,
    pub transport: String,
    pub bastions: Vec<String>,
    pub bastion_group: String,
    pub recording: String,
    pub lock: bool,
}

#[tauri::command]
pub async fn rustion_policy_asset_group_read(
    state: State<'_, AppState>,
    asset_group_id: String,
) -> CmdResult<RustionAssetGroupPolicy> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}policy/asset-group/{asset_group_id}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionAssetGroupPolicy {
        priority: data
            .get("priority")
            .and_then(|v| v.as_i64())
            .map(|n| n as i32)
            .unwrap_or(0),
        transport: s(&data, "transport"),
        bastions: data
            .get("bastions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bastion_group: s(&data, "bastion_group"),
        recording: s(&data, "recording"),
        lock: data.get("lock").and_then(|v| v.as_bool()).unwrap_or(false),
        updated_at: s(&data, "updated_at"),
    })
}

#[tauri::command]
pub async fn rustion_policy_asset_group_write(
    state: State<'_, AppState>,
    asset_group_id: String,
    input: RustionAssetGroupPolicyInput,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("priority".into(), Value::Number(input.priority.into()));
    if !input.transport.is_empty() {
        body.insert("transport".into(), Value::String(input.transport));
    }
    body.insert(
        "bastions".into(),
        Value::Array(input.bastions.into_iter().map(Value::String).collect()),
    );
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}policy/asset-group/{asset_group_id}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_policy_resource_read(
    state: State<'_, AppState>,
    resource_id: String,
) -> CmdResult<RustionPolicyTier> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}policy/resource/{resource_id}"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionPolicyTier {
        transport: s(&data, "transport"),
        bastions: data
            .get("bastions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bastion_group: s(&data, "bastion_group"),
        recording: s(&data, "recording"),
        lock: false, // per-resource cannot lock
    })
}

#[tauri::command]
pub async fn rustion_policy_resource_write(
    state: State<'_, AppState>,
    resource_id: String,
    input: RustionPolicyTier,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !input.transport.is_empty() {
        body.insert("transport".into(), Value::String(input.transport));
    }
    body.insert(
        "bastions".into(),
        Value::Array(input.bastions.into_iter().map(Value::String).collect()),
    );
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(false));
    make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}policy/resource/{resource_id}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionForceRustionResult {
    pub current_transport: String,
    pub current_lock: bool,
    pub proposed_transport: String,
    pub proposed_lock: bool,
    pub applied: bool,
    pub note: String,
}

#[tauri::command]
pub async fn rustion_policy_force_rustion(
    state: State<'_, AppState>,
    confirm: bool,
) -> CmdResult<RustionForceRustionResult> {
    let mut body = Map::new();
    body.insert("confirm".into(), Value::Bool(confirm));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}policy/force-rustion"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionForceRustionResult {
        current_transport: s(&data, "current_transport"),
        current_lock: data
            .get("current_lock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        proposed_transport: s(&data, "proposed_transport"),
        proposed_lock: data
            .get("proposed_lock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        applied: data.get("applied").and_then(|v| v.as_bool()).unwrap_or(false),
        note: s(&data, "note"),
    })
}

// ─── Phase 8.1: telemetry ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionTelemetrySession {
    pub session_id: String,
    pub authority: String,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_user: String,
    pub operator_vault_user: String,
    pub operator_src_ip: String,
    pub correlation_id: String,
    pub opened_at: String,
    pub expires_at: String,
    pub renewals_used: u32,
    pub max_renewals: u32,
    pub killed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionTelemetryStats {
    pub active: u64,
    pub total: u64,
    pub total_duration_secs: u64,
    pub top_targets: Vec<(String, u64)>,
    pub top_operators: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionAuditEntry {
    pub sequence: u64,
    pub timestamp: String,
    pub actor: String,
    pub session_id: Option<String>,
    pub source_addr: Option<String>,
    pub event: Value,
    pub hash: String,
    pub target_id: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionTelemetryTarget {
    pub target_id: String,
    pub target_name: String,
    pub authority: String,
    pub last_pull_at: Option<String>,
    pub last_pull_error: Option<String>,
    pub active: Vec<RustionTelemetrySession>,
    pub history: Vec<RustionTelemetrySession>,
    pub stats: RustionTelemetryStats,
    pub recent_audit: Vec<RustionAuditEntry>,
}

fn session_from_value(v: &Value) -> RustionTelemetrySession {
    let obj = v.as_object().cloned().unwrap_or_default();
    RustionTelemetrySession {
        session_id: s(&obj, "session_id"),
        authority: s(&obj, "authority"),
        protocol: s(&obj, "protocol"),
        target_host: s(&obj, "target_host"),
        target_port: obj
            .get("target_port")
            .and_then(|v| v.as_u64())
            .map(|n| n as u16)
            .unwrap_or(0),
        target_user: s(&obj, "target_user"),
        operator_vault_user: s(&obj, "operator_vault_user"),
        operator_src_ip: s(&obj, "operator_src_ip"),
        correlation_id: s(&obj, "correlation_id"),
        opened_at: s(&obj, "opened_at"),
        expires_at: s(&obj, "expires_at"),
        renewals_used: obj
            .get("renewals_used")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(0),
        max_renewals: obj
            .get("max_renewals")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(0),
        killed_at: obj
            .get("killed_at")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

fn target_from_value(v: &Value) -> RustionTelemetryTarget {
    let obj = v.as_object().cloned().unwrap_or_default();
    let active = obj
        .get("active")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().map(session_from_value).collect())
        .unwrap_or_default();
    let history = obj
        .get("history")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().map(session_from_value).collect())
        .unwrap_or_default();
    let stats_v = obj.get("stats").cloned().unwrap_or(Value::Null);
    let stats_obj = stats_v.as_object().cloned().unwrap_or_default();
    let stats = RustionTelemetryStats {
        active: u64_field(&stats_obj, "active"),
        total: u64_field(&stats_obj, "total"),
        total_duration_secs: u64_field(&stats_obj, "total_duration_secs"),
        top_targets: stats_obj
            .get("top_targets")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|pair| {
                        let p = pair.as_array()?;
                        Some((
                            p.first()?.as_str()?.to_string(),
                            p.get(1)?.as_u64().unwrap_or(0),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        top_operators: stats_obj
            .get("top_operators")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|pair| {
                        let p = pair.as_array()?;
                        Some((
                            p.first()?.as_str()?.to_string(),
                            p.get(1)?.as_u64().unwrap_or(0),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    let recent_audit = obj
        .get("recent_audit")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().map(audit_entry_from_value).collect())
        .unwrap_or_default();
    RustionTelemetryTarget {
        target_id: s(&obj, "target_id"),
        target_name: s(&obj, "target_name"),
        authority: s(&obj, "authority"),
        last_pull_at: obj
            .get("last_pull_at")
            .and_then(|v| v.as_str())
            .map(String::from),
        last_pull_error: obj
            .get("last_pull_error")
            .and_then(|v| v.as_str())
            .map(String::from),
        active,
        history,
        stats,
        recent_audit,
    }
}

fn audit_entry_from_value(v: &Value) -> RustionAuditEntry {
    let obj = v.as_object().cloned().unwrap_or_default();
    RustionAuditEntry {
        sequence: u64_field(&obj, "sequence"),
        timestamp: s(&obj, "timestamp"),
        actor: s(&obj, "actor"),
        session_id: obj
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        source_addr: obj
            .get("source_addr")
            .and_then(|v| v.as_str())
            .map(String::from),
        event: obj.get("event").cloned().unwrap_or(Value::Null),
        hash: s(&obj, "hash"),
        target_id: s(&obj, "target_id"),
    }
}

#[tauri::command]
pub async fn rustion_telemetry_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<RustionTelemetryTarget>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}telemetry"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(target_from_value).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_telemetry_poll(
    state: State<'_, AppState>,
) -> CmdResult<Vec<RustionTelemetryTarget>> {
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}telemetry/poll"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(target_from_value).collect())
        .unwrap_or_default())
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
