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
    /// Convenience boolean mirror — true iff `tls_pinned_cert_pem`
    /// is non-empty on the server.
    pub tls_pinned: bool,
    /// PEM-encoded leaf cert pinned for outbound HTTPS to this
    /// Rustion (empty when no pin is configured).
    pub tls_pinned_cert_pem: String,
    /// Phase 9.3 — discovered SSH proxy listener dial host. Empty
    /// when the bastion's `ssh_advertise` is unset or bound to an
    /// unspecified address; Connect falls back to the host portion of
    /// `endpoint` in that case.
    #[serde(default)]
    pub ssh_listener_host: String,
    #[serde(default)]
    pub ssh_listener_port: u16,
    #[serde(default)]
    pub rdp_listener_host: String,
    #[serde(default)]
    pub rdp_listener_port: u16,
    /// ISO-8601 timestamp of the last successful listener-info pull.
    #[serde(default)]
    pub listeners_synced_at: String,
    /// Discovered OpenSSH host-key fingerprint (`SHA256:…`) the SSH
    /// dialler pins. Empty when the bastion advertised none.
    #[serde(default)]
    pub ssh_host_key_fingerprint: String,
    /// Discovered TLS leaf digest (`sha256:…`) the RDP dialler pins.
    /// Empty when the bastion advertised none.
    #[serde(default)]
    pub rdp_tls_pin_sha256: String,
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
    /// Phase-2 ML-DSA-65 sibling role. Required alongside `pki_role`
    /// (the Ed25519 half) for `master/issue` to succeed — the rustion
    /// engine mints both halves of the hybrid keypair through the PKI
    /// engine. Optional on the wire so older GUIs that pre-date the
    /// hybrid binding still round-trip cleanly.
    #[serde(default)]
    pub pki_role_pqc: String,
    pub issuer_ref: String,
    pub algorithm: String,
    pub default_ttl_secs: u64,
    pub rotate_grace_secs: u64,
    /// `X-Rustion-Authority` this deployment presents, and the record
    /// name the bastion pins the master pubkey under. Optional on the
    /// wire so a GUI predating the field still round-trips; the engine
    /// reports the effective value (`bastion-vault` by default).
    #[serde(default)]
    pub authority_name: String,
    pub current_serial: String,
    pub current_not_after: String,
    pub updated_at: String,
    pub configured: bool,
}

#[derive(Serialize, Default)]
pub struct RustionMasterIssueResult {
    pub serial: String,
    pub not_after: String,
    pub algorithm: String,
}

#[derive(Serialize, Default)]
pub struct RustionMasterPubkey {
    pub authority_name: String,
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
    /// Optional pinned TLS leaf cert (PEM). Empty preserves the
    /// existing value on update; the sentinel `"-"` clears it.
    #[serde(default)]
    pub tls_pinned_cert_pem: String,
}

fn default_enabled() -> bool {
    true
}

#[tauri::command]
pub async fn rustion_target_list(state: State<'_, AppState>) -> CmdResult<Vec<RustionTargetSummary>> {
    let resp = make_request(&state, Operation::List, format!("{RUSTION_MOUNT}targets/"), None).await?;
    let keys: Vec<String> = resp
        .as_ref()
        .and_then(|r| r.data.as_ref())
        .and_then(|d| d.get("keys"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
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
pub async fn rustion_target_read(state: State<'_, AppState>, id: String) -> CmdResult<RustionTargetSummary> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}targets/{id}"), None).await?;
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
    body.insert("public_key_ed25519".into(), Value::String(input.public_key_ed25519));
    body.insert("public_key_mldsa65".into(), Value::String(input.public_key_mldsa65));
    body.insert("kem_public_key".into(), Value::String(input.kem_public_key));
    body.insert("description".into(), Value::String(input.description));
    body.insert("tags".into(), Value::Array(input.tags.into_iter().map(Value::String).collect()));
    body.insert("enabled".into(), Value::Bool(input.enabled));
    body.insert("default_recording_dir".into(), Value::String(input.default_recording_dir));
    body.insert("tls_pinned_cert_pem".into(), Value::String(input.tls_pinned_cert_pem));

    let path = match id {
        Some(id) => format!("{RUSTION_MOUNT}targets/{id}"),
        None => format!("{RUSTION_MOUNT}targets/"),
    };
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(target_summary_from_map(&data))
}

/// Phase 9.3 — pull listener-info from a Rustion bastion and persist
/// it on the BV target record. Calls `POST rustion/targets/<id>/listeners/refresh`
/// which in turn hits the bastion's `GET /v1/listeners`. Returns the
/// updated target summary so the GUI can refresh the row without a
/// follow-up read.
#[tauri::command]
pub async fn rustion_target_refresh_listeners(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<RustionTargetSummary> {
    let resp =
        make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}targets/{id}/listeners/refresh"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(target_summary_from_map(&data))
}

#[tauri::command]
pub async fn rustion_target_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("{RUSTION_MOUNT}targets/{id}"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_target_health_all(state: State<'_, AppState>) -> CmdResult<Vec<RustionTargetHealth>> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}targets/health"), None).await?;
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
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}master/config"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(master_config_from_map(&data))
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
    if !input.pki_role_pqc.is_empty() {
        body.insert("pki_role_pqc".into(), Value::String(input.pki_role_pqc));
    }
    if !input.issuer_ref.is_empty() {
        body.insert("issuer_ref".into(), Value::String(input.issuer_ref));
    }
    // Empty means "leave unchanged" on the engine side too — the GUI has
    // no separate "reset to default" affordance, and clearing would only
    // restore the default the operator already has.
    if !input.authority_name.is_empty() {
        body.insert("authority_name".into(), Value::String(input.authority_name));
    }
    if input.default_ttl_secs > 0 {
        body.insert("default_ttl_secs".into(), Value::Number(input.default_ttl_secs.into()));
    }
    if input.rotate_grace_secs > 0 {
        body.insert("rotate_grace_secs".into(), Value::Number(input.rotate_grace_secs.into()));
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}master/config"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(master_config_from_map(&data))
}

/// Mint the hybrid Ed25519 + ML-DSA-65 master keypair through the
/// configured PKI engine. Mirrors the CLI's `bvault rustion master
/// issue` — both sides hit `rustion/master/issue`. Used by the
/// Bootstrap Master wizard in the GUI.
#[tauri::command]
pub async fn rustion_master_issue(state: State<'_, AppState>) -> CmdResult<RustionMasterIssueResult> {
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}master/issue"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionMasterIssueResult {
        serial: s(&data, "serial"),
        not_after: s(&data, "not_after"),
        algorithm: s(&data, "algorithm"),
    })
}

fn master_config_from_map(data: &Map<String, Value>) -> RustionMasterConfig {
    RustionMasterConfig {
        pki_mount: s(data, "pki_mount"),
        pki_role: s(data, "pki_role"),
        pki_role_pqc: s(data, "pki_role_pqc"),
        issuer_ref: s(data, "issuer_ref"),
        algorithm: s(data, "algorithm"),
        default_ttl_secs: u64_field(data, "default_ttl_secs"),
        rotate_grace_secs: u64_field(data, "rotate_grace_secs"),
        authority_name: s(data, "authority_name"),
        current_serial: s(data, "current_serial"),
        current_not_after: s(data, "current_not_after"),
        updated_at: s(data, "updated_at"),
        configured: data.get("configured").and_then(|v| v.as_bool()).unwrap_or(false),
    }
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
    body.insert("target_protocol".into(), Value::String(request.target_protocol));
    if let Some(pin) = request.target_hostkey_pin {
        body.insert("target_hostkey_pin".into(), Value::String(pin));
    }
    body.insert("credential_kind".into(), Value::String(request.credential_kind));
    body.insert("credential_username".into(), Value::String(request.credential_username));
    body.insert("credential_material".into(), Value::String(request.credential_material_b64));
    body.insert("ttl_secs".into(), Value::Number(request.ttl_secs.into()));
    body.insert("max_renewals".into(), Value::Number(request.max_renewals.into()));
    body.insert("recording".into(), Value::String(request.recording));
    if let Some(list) = request.bastions {
        body.insert("bastions".into(), Value::Array(list.into_iter().map(Value::String).collect()));
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
        body.insert("asset_group_ids".into(), Value::Array(ags.into_iter().map(Value::String).collect()));
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}session/open"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let tried = data
        .get("bastion_candidates_tried")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(RustionSessionOpenResult {
        session_id: s(&data, "session_id"),
        host: s(&data, "host"),
        port: data.get("port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()).unwrap_or(0),
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
    body.insert("correlation_id".into(), Value::String(request.correlation_id));
    body.insert("extend_secs".into(), Value::Number(request.extend_secs.into()));
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}session/renew"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionSessionRenewResult {
        session_id: s(&data, "session_id"),
        expires_at: s(&data, "expires_at"),
        renewals_used: data.get("renewals_used").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        max_renewals: data.get("max_renewals").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
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
    body.insert("correlation_id".into(), Value::String(request.correlation_id));
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}session/kill"), Some(body)).await?;
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

    // Phase 8.6 — keystroke-transcript summary. Counters and flags
    // only; the transcript lives behind
    // `rustion_recording_keystrokes`, which is gated with playback
    // and audited separately.
    /// `""` (not indexed yet) | `indexed` | `not-enabled` |
    /// `digest-mismatch` | `failed`. `""` and `not-enabled` are
    /// different states and the UI must not collapse them.
    pub keystroke_state: String,
    /// The artifact header's `keystroke_metadata`. `false` means the
    /// feature was off on that bastion, **not** that nobody typed.
    pub keystroke_metadata: bool,
    pub keystroke_text: bool,
    pub keystroke_chars: u64,
    pub keystroke_runs: u64,
    pub keystroke_redacted_runs: u64,
    /// `exact` | `approximate` | `none` | `unknown`.
    pub keystroke_decoding: String,
    pub keystroke_rebuilt: bool,
    pub keystroke_complete: bool,
    pub keystroke_indexed_at: String,
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
        keystroke_state: s(data, "keystroke_state"),
        keystroke_metadata: b(data, "keystroke_metadata"),
        keystroke_text: b(data, "keystroke_text"),
        keystroke_chars: u64_field(data, "keystroke_chars"),
        keystroke_runs: u64_field(data, "keystroke_runs"),
        keystroke_redacted_runs: u64_field(data, "keystroke_redacted_runs"),
        keystroke_decoding: s(data, "keystroke_decoding"),
        keystroke_rebuilt: b(data, "keystroke_rebuilt"),
        keystroke_complete: b(data, "keystroke_complete"),
        keystroke_indexed_at: s(data, "keystroke_indexed_at"),
    }
}

#[tauri::command]
pub async fn rustion_recordings_list(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}recordings"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("recordings")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_recording_read(
    state: State<'_, AppState>,
    recording_id: String,
) -> CmdResult<RustionRecordingEntry> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}recordings/{recording_id}"), None).await?;
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
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}recordings/pull"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(recording_from_map(&data))
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionReconcileReport {
    pub found: u64,
    pub imported: u64,
    pub skipped_existing: u64,
}

/// Actively reconcile the recordings index against one or all enrolled
/// bastions' `/v1/recordings` list. Empty `bastion_id` sweeps them all.
#[tauri::command]
pub async fn rustion_recordings_reconcile(
    state: State<'_, AppState>,
    bastion_id: Option<String>,
) -> CmdResult<RustionReconcileReport> {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(bastion_id.unwrap_or_default()));
    let resp =
        make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}recordings/reconcile"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let num = |k: &str| -> u64 { data.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
    Ok(RustionReconcileReport {
        found: num("found"),
        imported: num("imported"),
        skipped_existing: num("skipped_existing"),
    })
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
    body.insert("recording_id".into(), Value::String(input.recording_id));
    body.insert("sha256_mismatch".into(), Value::Bool(input.sha256_mismatch));
    make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}recordings/replay-log"), Some(body)).await?;
    Ok(())
}

/// Phase 8.3 — open a full-screen replay window. Spawns a separate
/// Tauri WebviewWindow pointed at the SessionReplayWindow route. The
/// new window calls `rustion_recording_blob` itself; we don't pass
/// the bytes via the spawn channel because they can be many MB.
///
/// `at_ms` is the Phase 8.6 seek offset in ms, set from a
/// keystroke-search hit's `t` so the operator lands on the moment the
/// text was typed. A **numeric offset only**: the searched-for text
/// never travels in this URL, and neither does any transcript content.
#[tauri::command]
pub async fn rustion_open_replay_window(
    app: tauri::AppHandle,
    recording_id: String,
    at_ms: Option<u64>,
) -> CmdResult<()> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
    if recording_id.is_empty() {
        return Err(crate::error::CommandError::from("recording_id is required".to_string()));
    }
    let window_label = format!("replay-{}", sanitize_label(&recording_id));
    // If a window for this recording is already open, focus it
    // instead of duplicating.
    if let Some(existing) = app.get_webview_window(&window_label) {
        let _ = existing.set_focus();
        return Ok(());
    }
    let at = match at_ms {
        Some(ms) if ms > 0 => format!("&at={ms}"),
        _ => String::new(),
    };
    let url =
        format!("index.html#/session-replay?recording={}{at}", urlencoding::encode(&recording_id));
    WebviewWindowBuilder::new(&app, &window_label, WebviewUrl::App(url.into()))
        .title(format!("BastionVault — Replay {recording_id}"))
        .inner_size(1200.0, 800.0)
        .resizable(true)
        .build()
        .map_err(|e| crate::error::CommandError::from(format!("spawn replay window: {e}")))?;
    Ok(())
}

fn sanitize_label(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect()
}

#[tauri::command]
pub async fn rustion_recording_blob(
    state: State<'_, AppState>,
    recording_id: String,
) -> CmdResult<RustionRecordingBlob> {
    let resp =
        make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}recordings/{recording_id}/blob"), None).await?;
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
pub async fn rustion_policy_global_read(state: State<'_, AppState>) -> CmdResult<RustionPolicyTier> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}policy/global"), None).await?;
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
pub async fn rustion_policy_global_write(state: State<'_, AppState>, input: RustionPolicyTier) -> CmdResult<()> {
    let mut body = Map::new();
    if !input.transport.is_empty() {
        body.insert("transport".into(), Value::String(input.transport));
    }
    body.insert("bastions".into(), Value::Array(input.bastions.into_iter().map(Value::String).collect()));
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/global"), Some(body)).await?;
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
pub async fn rustion_bastion_group_list(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}bastion-groups"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_bastion_group_read(state: State<'_, AppState>, name: String) -> CmdResult<RustionBastionGroup> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}bastion-groups/{name}"), None).await?;
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
    body.insert("members".into(), Value::Array(input.members.into_iter().map(Value::String).collect()));
    body.insert("selection".into(), Value::String(input.selection));
    body.insert("description".into(), Value::String(input.description));
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}bastion-groups"), Some(body)).await?;
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
    body.insert("members".into(), Value::Array(input.members.into_iter().map(Value::String).collect()));
    body.insert("selection".into(), Value::String(input.selection));
    body.insert("description".into(), Value::String(input.description));
    let resp =
        make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}bastion-groups/{name}"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(group_from_map(&data))
}

#[tauri::command]
pub async fn rustion_bastion_group_delete(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("{RUSTION_MOUNT}bastion-groups/{name}"), None).await?;
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
pub async fn rustion_policy_type_read(state: State<'_, AppState>, type_name: String) -> CmdResult<RustionTypePolicy> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}policy/type/{type_name}"), None).await?;
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
    body.insert("bastions".into(), Value::Array(input.bastions.into_iter().map(Value::String).collect()));
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/type/{type_name}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_policy_type_delete(state: State<'_, AppState>, type_name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("{RUSTION_MOUNT}policy/type/{type_name}"), None).await?;
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
    let resp =
        make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}policy/asset-group/{asset_group_id}"), None)
            .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionAssetGroupPolicy {
        priority: data.get("priority").and_then(|v| v.as_i64()).map(|n| n as i32).unwrap_or(0),
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
    body.insert("bastions".into(), Value::Array(input.bastions.into_iter().map(Value::String).collect()));
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(input.lock));
    make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/asset-group/{asset_group_id}"), Some(body))
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn rustion_policy_resource_read(
    state: State<'_, AppState>,
    resource_id: String,
) -> CmdResult<RustionPolicyTier> {
    let resp =
        make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}policy/resource/{resource_id}"), None).await?;
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
    body.insert("bastions".into(), Value::Array(input.bastions.into_iter().map(Value::String).collect()));
    if !input.bastion_group.is_empty() {
        body.insert("bastion_group".into(), Value::String(input.bastion_group));
    }
    if !input.recording.is_empty() {
        body.insert("recording".into(), Value::String(input.recording));
    }
    body.insert("lock".into(), Value::Bool(false));
    make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/resource/{resource_id}"), Some(body)).await?;
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
    let resp =
        make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/force-rustion"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionForceRustionResult {
        current_transport: s(&data, "current_transport"),
        current_lock: data.get("current_lock").and_then(|v| v.as_bool()).unwrap_or(false),
        proposed_transport: s(&data, "proposed_transport"),
        proposed_lock: data.get("proposed_lock").and_then(|v| v.as_bool()).unwrap_or(false),
        applied: data.get("applied").and_then(|v| v.as_bool()).unwrap_or(false),
        note: s(&data, "note"),
    })
}

// ─── Phase 7.4: effective-policy resolver ────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionPolicyEffectiveRequest {
    #[serde(default)]
    pub resource_id: String,
    #[serde(default)]
    pub resource_type: String,
    #[serde(default)]
    pub asset_group_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionEffectivePolicy {
    /// `direct | rustion-preferred | rustion-required`.
    pub transport: String,
    pub transport_source: String,
    /// Bastion ids the resolver would pick. Already expanded from
    /// `bastion_group` when applicable, so the caller doesn't need to
    /// fan out separately.
    pub bastions: Vec<String>,
    pub bastion_group: String,
    pub bastions_source: String,
    pub recording: String,
    pub recording_source: String,
    pub locked_by: Vec<String>,
    /// Present when a lower tier tried to weaken a locked higher tier.
    /// session/open would refuse with 403 in this case; callers should
    /// surface this verbatim and refuse to dial.
    pub lock_violation: Option<RustionLockViolation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionLockViolation {
    pub locking_tier: String,
    pub field: String,
    pub detail: String,
}

#[tauri::command]
pub async fn rustion_policy_effective(
    state: State<'_, AppState>,
    request: RustionPolicyEffectiveRequest,
) -> CmdResult<RustionEffectivePolicy> {
    let mut body = Map::new();
    if !request.resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(request.resource_id));
    }
    if !request.resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(request.resource_type));
    }
    if !request.asset_group_ids.is_empty() {
        body.insert(
            "asset_group_ids".into(),
            Value::Array(request.asset_group_ids.into_iter().map(Value::String).collect()),
        );
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}policy/effective"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let lock_violation = data.get("lock_violation").and_then(|v| match v {
        Value::Object(m) => Some(RustionLockViolation {
            locking_tier: s(m, "locking_tier"),
            field: s(m, "field"),
            detail: s(m, "detail"),
        }),
        _ => None,
    });
    Ok(RustionEffectivePolicy {
        transport: s(&data, "transport"),
        transport_source: s(&data, "transport_source"),
        bastions: data
            .get("bastions")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bastion_group: s(&data, "bastion_group"),
        bastions_source: s(&data, "bastions_source"),
        recording: s(&data, "recording"),
        recording_source: s(&data, "recording_source"),
        locked_by: data
            .get("locked_by")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        lock_violation,
    })
}

// ─── Phase 9.3: dispatcher preview ───────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionDispatcherCandidate {
    pub id: String,
    pub name: String,
    /// `up | degraded | down | unknown`.
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionDispatcherDropped {
    pub id: String,
    pub name: String,
    /// `disabled | not-registered | not-up:<status>`.
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionDispatcherPreview {
    /// `ordered-fallback | random-pool | group`.
    pub mode: String,
    /// Group name when `mode == "group"`, else empty.
    pub group_name: String,
    /// Which policy tier supplied the bastion list.
    pub source_tier: String,
    /// Healthy candidates in the order the next Connect would try them.
    pub candidates: Vec<RustionDispatcherCandidate>,
    /// Targets the dispatcher skipped, with the reason.
    pub dropped: Vec<RustionDispatcherDropped>,
}

#[tauri::command]
pub async fn rustion_dispatcher_preview(
    state: State<'_, AppState>,
    request: RustionPolicyEffectiveRequest,
) -> CmdResult<RustionDispatcherPreview> {
    let mut body = Map::new();
    if !request.resource_id.is_empty() {
        body.insert("resource_id".into(), Value::String(request.resource_id));
    }
    if !request.resource_type.is_empty() {
        body.insert("resource_type".into(), Value::String(request.resource_type));
    }
    if !request.asset_group_ids.is_empty() {
        body.insert(
            "asset_group_ids".into(),
            Value::Array(request.asset_group_ids.into_iter().map(Value::String).collect()),
        );
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}dispatcher/preview"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let candidates = data
        .get("candidates")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_object())
                .map(|m| RustionDispatcherCandidate { id: s(m, "id"), name: s(m, "name"), status: s(m, "status") })
                .collect()
        })
        .unwrap_or_default();
    let dropped = data
        .get("dropped")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_object())
                .map(|m| RustionDispatcherDropped { id: s(m, "id"), name: s(m, "name"), reason: s(m, "reason") })
                .collect()
        })
        .unwrap_or_default();
    Ok(RustionDispatcherPreview {
        mode: s(&data, "mode"),
        group_name: s(&data, "group_name"),
        source_tier: s(&data, "source_tier"),
        candidates,
        dropped,
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
        target_port: obj.get("target_port").and_then(|v| v.as_u64()).map(|n| n as u16).unwrap_or(0),
        target_user: s(&obj, "target_user"),
        operator_vault_user: s(&obj, "operator_vault_user"),
        operator_src_ip: s(&obj, "operator_src_ip"),
        correlation_id: s(&obj, "correlation_id"),
        opened_at: s(&obj, "opened_at"),
        expires_at: s(&obj, "expires_at"),
        renewals_used: obj.get("renewals_used").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        max_renewals: obj.get("max_renewals").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        killed_at: obj.get("killed_at").and_then(|v| v.as_str()).map(String::from),
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
                        Some((p.first()?.as_str()?.to_string(), p.get(1)?.as_u64().unwrap_or(0)))
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
                        Some((p.first()?.as_str()?.to_string(), p.get(1)?.as_u64().unwrap_or(0)))
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
        last_pull_at: obj.get("last_pull_at").and_then(|v| v.as_str()).map(String::from),
        last_pull_error: obj.get("last_pull_error").and_then(|v| v.as_str()).map(String::from),
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
        session_id: obj.get("session_id").and_then(|v| v.as_str()).map(String::from),
        source_addr: obj.get("source_addr").and_then(|v| v.as_str()).map(String::from),
        event: obj.get("event").cloned().unwrap_or(Value::Null),
        hash: s(&obj, "hash"),
        target_id: s(&obj, "target_id"),
    }
}

#[tauri::command]
pub async fn rustion_telemetry_list(state: State<'_, AppState>) -> CmdResult<Vec<RustionTelemetryTarget>> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}telemetry"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(target_from_value).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn rustion_telemetry_poll(state: State<'_, AppState>) -> CmdResult<Vec<RustionTelemetryTarget>> {
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}telemetry/poll"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(data
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(target_from_value).collect())
        .unwrap_or_default())
}

// ─── Phase 9.1: deployment_id ───────────────────────────────────

#[tauri::command]
pub async fn rustion_deployment_id_read(state: State<'_, AppState>) -> CmdResult<String> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}deployment-id"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(s(&data, "deployment_id"))
}

#[tauri::command]
pub async fn rustion_master_pubkey_export(state: State<'_, AppState>) -> CmdResult<RustionMasterPubkey> {
    let resp = make_request(&state, Operation::Read, format!("{RUSTION_MOUNT}master/pubkey"), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionMasterPubkey {
        authority_name: s(&data, "authority_name"),
        algorithm: s(&data, "algorithm"),
        ed25519_pem: s(&data, "ed25519_pem"),
        mldsa65_pem: s(&data, "mldsa65_pem"),
        fingerprint: s(&data, "fingerprint"),
        current_serial: s(&data, "current_serial"),
        current_not_after: s(&data, "current_not_after"),
        issued: data.get("issued").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

// ─── Phase 8.6: keystroke transcripts ──────────────────────────────

/// One keystroke run as the transcript records it.
///
/// `text` is `None` exactly when `redacted` is true. Nothing in the
/// GUI reconstructs a redacted run — it is rendered as withheld, with
/// its rule and its character count.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeRun {
    /// Elapsed ms of the run's first keystroke — the player's seek
    /// offset.
    pub t: u64,
    pub d: u64,
    pub n: u64,
    pub text: Option<String>,
    pub redacted: bool,
    /// `known_secret` | `masked_field` | `deny_pattern` |
    /// `credential_pair`, on a redacted run.
    pub reason: String,
    /// The `field_epoch` correlation **hint**. Not a field identity —
    /// a pass-through RDP proxy cannot see the remote UI's focus — so
    /// the UI must not label it "field".
    pub epoch: u32,
    pub composed: bool,
    pub approximate: bool,
    pub truncated: bool,
}

fn keystroke_run_from_value(v: &Value) -> RustionKeystrokeRun {
    let Some(o) = v.as_object() else {
        return RustionKeystrokeRun::default();
    };
    let redacted = o.get("redacted").and_then(|v| v.as_bool()).unwrap_or(false);
    RustionKeystrokeRun {
        t: o.get("t").and_then(|v| v.as_u64()).unwrap_or(0),
        d: o.get("d").and_then(|v| v.as_u64()).unwrap_or(0),
        n: o.get("n").and_then(|v| v.as_u64()).unwrap_or(0),
        // A redacted run's text is dropped here too, so a malformed
        // upstream payload cannot put withheld text on screen.
        text: if redacted {
            None
        } else {
            o.get("text").and_then(|v| v.as_str()).map(String::from)
        },
        redacted,
        reason: o.get("reason").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        epoch: o.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        composed: o.get("composed").and_then(|v| v.as_bool()).unwrap_or(false),
        approximate: o.get("approximate").and_then(|v| v.as_bool()).unwrap_or(false),
        truncated: o.get("truncated").and_then(|v| v.as_bool()).unwrap_or(false),
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeCensus {
    pub keys_total: u64,
    pub chars_decoded: u64,
    pub unicode_events: u64,
    pub named_keys: u64,
    pub composed: u64,
    pub undecodable_scancodes: u64,
    pub redacted_runs: u64,
    pub redacted_chars: u64,
    pub slowpath_input_pdus: u64,
    pub truncated_runs: u64,
}

/// One recording's transcript, or the reason there is none.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeTranscript {
    pub recording_id: String,
    pub session_id: String,
    pub format: String,
    /// `not-indexed` | `indexed` | `not-enabled` | `digest-mismatch`
    /// | `failed`. Three of these mean "no transcript" for different
    /// reasons and the UI renders each differently.
    pub state: String,
    /// The artifact header's `keystroke_metadata`.
    pub keystroke_metadata: bool,
    pub format_version: u32,
    /// The bound on how far out of order a keystroke record may
    /// appear. The player buffers by this before anchoring runs.
    pub max_reorder_ms: u64,
    /// `trailer-footer` | `text-record-scan`.
    pub source: String,
    /// False for a rebuilt trailer or a scanned fallback — both are
    /// missing the session's final unclosed run.
    pub complete: bool,
    pub trailer_version: u32,
    pub rebuilt: bool,
    /// `exact` | `approximate` | `none` | `unknown`. Anything other
    /// than `exact` must show a caveat.
    pub text_decoding: String,
    pub keyboard_layout: String,
    pub keyboard_layout_source: String,
    pub runs: Vec<RustionKeystrokeRun>,
    pub census: RustionKeystrokeCensus,
    pub chars_indexed: u64,
    pub indexed_at: String,
    pub warnings: Vec<String>,
    /// Server-supplied statement that upstream redaction is
    /// best-effort. Rendered verbatim; never suppressed.
    pub redaction_disclaimer: String,
}

/// Read one recording's `.rdp-rec` version-4 keystroke transcript.
///
/// Gated on the server with recording *playback*, not with metadata
/// reads, and audited as `recording.transcript.accessed`.
#[tauri::command]
pub async fn rustion_recording_keystrokes(
    state: State<'_, AppState>,
    recording_id: String,
) -> CmdResult<RustionKeystrokeTranscript> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{RUSTION_MOUNT}recordings/{recording_id}/keystrokes"),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let census = data
        .get("census")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let cn = |k: &str| -> u64 { census.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
    Ok(RustionKeystrokeTranscript {
        recording_id: s(&data, "recording_id"),
        session_id: s(&data, "session_id"),
        format: s(&data, "format"),
        state: s(&data, "state"),
        keystroke_metadata: b(&data, "keystroke_metadata"),
        format_version: u32_field(&data, "format_version"),
        max_reorder_ms: u64_field(&data, "max_reorder_ms"),
        source: s(&data, "source"),
        complete: b(&data, "complete"),
        trailer_version: u32_field(&data, "trailer_version"),
        rebuilt: b(&data, "rebuilt"),
        text_decoding: s(&data, "text_decoding"),
        keyboard_layout: s(&data, "keyboard_layout"),
        keyboard_layout_source: s(&data, "keyboard_layout_source"),
        runs: data
            .get("runs")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().map(keystroke_run_from_value).collect())
            .unwrap_or_default(),
        census: RustionKeystrokeCensus {
            keys_total: cn("keys_total"),
            chars_decoded: cn("chars_decoded"),
            unicode_events: cn("unicode_events"),
            named_keys: cn("named_keys"),
            composed: cn("composed"),
            undecodable_scancodes: cn("undecodable_scancodes"),
            redacted_runs: cn("redacted_runs"),
            redacted_chars: cn("redacted_chars"),
            slowpath_input_pdus: cn("slowpath_input_pdus"),
            truncated_runs: cn("truncated_runs"),
        },
        chars_indexed: u64_field(&data, "chars_indexed"),
        indexed_at: s(&data, "indexed_at"),
        warnings: data
            .get("warnings")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        redaction_disclaimer: s(&data, "redaction_disclaimer"),
    })
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeIndexReport {
    /// Single-recording form.
    pub recording_id: String,
    pub status: String,
    pub detail: String,
    pub runs: u64,
    pub redacted_runs: u64,
    pub chars_indexed: u64,
    pub text_decoding: String,
    pub rebuilt: bool,
    pub source: String,
    /// Sweep form.
    pub considered: u64,
    pub indexed: u64,
    pub not_enabled: u64,
    pub unchanged: u64,
    pub failed: u64,
    pub remaining: u64,
}

/// Build or refresh the keystroke-transcript index.
///
/// With a `recordingId`, indexes that one. Without, sweeps the
/// recordings that have no current transcript — each one costs a full
/// artifact fetch from its bastion, so the server caps the batch and
/// reports what is left.
#[tauri::command]
pub async fn rustion_keystrokes_index(
    state: State<'_, AppState>,
    recording_id: Option<String>,
    force: Option<bool>,
) -> CmdResult<RustionKeystrokeIndexReport> {
    let mut body = Map::new();
    body.insert("recording_id".into(), Value::String(recording_id.unwrap_or_default()));
    body.insert("force".into(), Value::Bool(force.unwrap_or(false)));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}recordings/keystrokes/index"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionKeystrokeIndexReport {
        recording_id: s(&data, "recording_id"),
        status: s(&data, "status"),
        detail: s(&data, "detail"),
        runs: u64_field(&data, "runs"),
        redacted_runs: u64_field(&data, "redacted_runs"),
        chars_indexed: u64_field(&data, "chars_indexed"),
        text_decoding: s(&data, "text_decoding"),
        rebuilt: b(&data, "rebuilt"),
        source: s(&data, "source"),
        considered: u64_field(&data, "considered"),
        indexed: u64_field(&data, "indexed"),
        not_enabled: u64_field(&data, "not_enabled"),
        unchanged: u64_field(&data, "unchanged"),
        failed: u64_field(&data, "failed"),
        remaining: u64_field(&data, "remaining"),
    })
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeHit {
    pub recording_id: String,
    pub session_id: String,
    pub target_host: String,
    pub target_user: String,
    pub authority: String,
    pub bastion_id: String,
    pub started_at: String,
    pub run_index: u64,
    /// Seek offset into the recording, in ms.
    pub t_ms: u64,
    pub d_ms: u64,
    pub n: u64,
    pub epoch: u32,
    pub excerpt: String,
    pub approximate: bool,
    pub text_decoding: String,
    pub rebuilt: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustionKeystrokeSearchReport {
    pub scanned: u64,
    /// Recordings with no transcript index. A negative result does
    /// **not** speak for these, and the UI has to say so.
    pub unindexed: u64,
    pub truncated: bool,
    pub hits: Vec<RustionKeystrokeHit>,
    pub redaction_disclaimer: String,
}

/// Search indexed transcripts for typed text.
///
/// The query travels in the request body — never a URL, a query
/// string or a log line. The server matches per run over non-redacted
/// text, so a hit cannot come from a withheld run.
#[tauri::command]
pub async fn rustion_keystroke_search(
    state: State<'_, AppState>,
    query: String,
    limit: Option<u64>,
) -> CmdResult<RustionKeystrokeSearchReport> {
    let mut body = Map::new();
    body.insert("query".into(), Value::String(query));
    body.insert("limit".into(), Value::Number(limit.unwrap_or(0).into()));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{RUSTION_MOUNT}recordings/keystroke-search"),
        Some(body),
    )
    .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let hits = data
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_object())
                .map(|o| {
                    let gs = |k: &str| -> String {
                        o.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string()
                    };
                    let gn = |k: &str| -> u64 { o.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
                    let gb = |k: &str| -> bool {
                        o.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
                    };
                    RustionKeystrokeHit {
                        recording_id: gs("recording_id"),
                        session_id: gs("session_id"),
                        target_host: gs("target_host"),
                        target_user: gs("target_user"),
                        authority: gs("authority"),
                        bastion_id: gs("bastion_id"),
                        started_at: gs("started_at"),
                        run_index: gn("run_index"),
                        t_ms: gn("t_ms"),
                        d_ms: gn("d_ms"),
                        n: gn("n"),
                        epoch: gn("epoch") as u32,
                        excerpt: gs("excerpt"),
                        approximate: gb("approximate"),
                        text_decoding: gs("text_decoding"),
                        rebuilt: gb("rebuilt"),
                        complete: gb("complete"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(RustionKeystrokeSearchReport {
        scanned: u64_field(&data, "scanned"),
        unindexed: u64_field(&data, "unindexed"),
        truncated: b(&data, "truncated"),
        hits,
        redaction_disclaimer: s(&data, "redaction_disclaimer"),
    })
}

// ─── helpers ───────────────────────────────────────────────────────

fn s(data: &Map<String, Value>, key: &str) -> String {
    data.get(key).and_then(|v| v.as_str()).map(String::from).unwrap_or_default()
}

fn u32_field(data: &Map<String, Value>, key: &str) -> u32 {
    data.get(key).and_then(|v| v.as_u64()).and_then(|n| u32::try_from(n).ok()).unwrap_or(0)
}

fn u64_field(data: &Map<String, Value>, key: &str) -> u64 {
    data.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn b(data: &Map<String, Value>, key: &str) -> bool {
    data.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn target_summary_from_map(data: &Map<String, Value>) -> RustionTargetSummary {
    let (ed25519, mldsa65) = data
        .get("public_key")
        .and_then(|v| v.as_object())
        .map(|pk| {
            (
                pk.get("ed25519").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                pk.get("mldsa65").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let tags = data
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    RustionTargetSummary {
        id: s(data, "id"),
        name: s(data, "name"),
        endpoint: s(data, "endpoint"),
        fingerprint: s(data, "fingerprint"),
        description: s(data, "description"),
        tags,
        enabled: data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
        default_recording_dir: s(data, "default_recording_dir"),
        created_at: s(data, "created_at"),
        updated_at: s(data, "updated_at"),
        public_key_ed25519: ed25519,
        public_key_mldsa65: mldsa65,
        kem_public_key: s(data, "kem_public_key"),
        tls_pinned: data.get("tls_pinned").and_then(|v| v.as_bool()).unwrap_or(false),
        tls_pinned_cert_pem: s(data, "tls_pinned_cert_pem"),
        ssh_listener_host: s(data, "ssh_listener_host"),
        ssh_listener_port: data
            .get("ssh_listener_port")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0),
        rdp_listener_host: s(data, "rdp_listener_host"),
        rdp_listener_port: data
            .get("rdp_listener_port")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0),
        listeners_synced_at: s(data, "listeners_synced_at"),
        ssh_host_key_fingerprint: s(data, "ssh_host_key_fingerprint"),
        rdp_tls_pin_sha256: s(data, "rdp_tls_pin_sha256"),
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
        enabled: data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
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

// ─── Phase 9.2: attest + deenrol ────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionAttestOutcome {
    pub status: String, // "ok" | "err"
    pub bastion_id: String,
    pub correlation_id: String,
    pub attested_at: String,
    pub expires_at: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionAttestResult {
    pub attempted: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub results: Vec<RustionAttestOutcome>,
}

#[tauri::command]
pub async fn rustion_authority_attest(
    state: State<'_, AppState>,
    bastion_id: Option<String>,
) -> CmdResult<RustionAttestResult> {
    let mut body = Map::new();
    if let Some(id) = bastion_id {
        body.insert("bastion_id".into(), Value::String(id));
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}authority/attest"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();

    let results: Vec<RustionAttestOutcome> = data
        .get("results")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_object())
                .map(|o| {
                    let status = s(o, "status");
                    RustionAttestOutcome {
                        status: status.clone(),
                        bastion_id: s(o, "bastion_id"),
                        correlation_id: s(o, "correlation_id"),
                        attested_at: s(o, "attested_at"),
                        expires_at: s(o, "expires_at"),
                        error: s(o, "error"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(RustionAttestResult {
        attempted: data.get("attempted").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        succeeded: data.get("succeeded").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        failed: data.get("failed").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(0),
        results,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustionDeenrolResult {
    pub bastion_id: String,
    pub correlation_id: String,
    pub reason: String,
}

#[tauri::command]
pub async fn rustion_target_deenrol(
    state: State<'_, AppState>,
    bastion_id: String,
    reason: Option<String>,
) -> CmdResult<RustionDeenrolResult> {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(bastion_id));
    if let Some(r) = reason {
        body.insert("reason".into(), Value::String(r));
    }
    let resp = make_request(&state, Operation::Write, format!("{RUSTION_MOUNT}target/deenrol"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(RustionDeenrolResult {
        bastion_id: s(&data, "bastion_id"),
        correlation_id: s(&data, "correlation_id"),
        reason: s(&data, "reason"),
    })
}
