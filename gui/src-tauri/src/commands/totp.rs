//! Tauri commands bridging the desktop GUI to the TOTP Secret Engine.
//!
//! Same `make_request` thin-wrapper pattern as `commands/ssh.rs` and
//! `commands/pki.rs`. The mount path is parameterised so an operator
//! who mounted at `totp-prod/` rather than `totp/` can drive both
//! from the same UI.
//!
//! Phase 4 surface only — the engine itself ships Phases 1-3 (HOTP/TOTP
//! crypto, generate + provider modes, replay protection, QR rendering);
//! this file is the GUI's view of it.

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<bastion_vault::logical::Response>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = operation;
    req.path = path;
    req.client_token = token;
    req.body = body;

    core.handle_request(&mut req).await.map_err(CommandError::from)
}

fn mount_prefix(mount: &str) -> String {
    let trimmed = mount.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "totp".to_string()
    } else {
        trimmed.to_string()
    }
}

fn data_to_map(resp: Option<bastion_vault::logical::Response>) -> Map<String, Value> {
    resp.and_then(|r| r.data).unwrap_or_default()
}

fn val_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn val_u64(map: &Map<String, Value>, key: &str) -> u64 {
    map.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn val_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

// ── Mount lifecycle ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct TotpMountInfo {
    pub path: String,
}

#[tauri::command]
pub async fn totp_list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<TotpMountInfo>> {
    let resp = make_request(&state, Operation::Read, "sys/mounts".into(), None).await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    for (path, info) in map.iter() {
        if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
            if t == "totp" {
                out.push(TotpMountInfo { path: path.clone() });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[tauri::command]
pub async fn totp_enable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let mount_path = path.trim().trim_end_matches('/').to_string();
    if mount_path.is_empty() {
        return Err("mount path required".into());
    }
    let mut body = Map::new();
    body.insert("type".into(), Value::String("totp".into()));
    let api_path = format!("sys/mounts/{mount_path}/");
    make_request(&state, Operation::Write, api_path, Some(body)).await?;
    Ok(())
}

// ── Keys ──────────────────────────────────────────────────────────

/// Metadata returned by `GET /v1/totp/keys/:name`. The seed is never
/// re-disclosed here — operators saw it once at create time.
#[derive(Serialize, Default)]
pub struct TotpKeyInfo {
    pub generate: bool,
    pub issuer: String,
    pub account_name: String,
    pub algorithm: String,
    pub digits: u64,
    pub period: u64,
    pub skew: u64,
    pub replay_check: bool,
}

#[tauri::command]
pub async fn totp_list_keys(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let path = format!("{}/keys", mount_prefix(&mount));
    let resp = make_request(&state, Operation::List, path, None).await?;
    let map = data_to_map(resp);
    let keys = map
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(keys)
}

#[tauri::command]
pub async fn totp_read_key(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<TotpKeyInfo> {
    let path = format!("{}/keys/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);
    Ok(TotpKeyInfo {
        generate: val_bool(&map, "generate"),
        issuer: val_str(&map, "issuer"),
        account_name: val_str(&map, "account_name"),
        algorithm: val_str(&map, "algorithm"),
        digits: val_u64(&map, "digits"),
        period: val_u64(&map, "period"),
        skew: val_u64(&map, "skew"),
        replay_check: val_bool(&map, "replay_check"),
    })
}

/// Create-key request. `generate=true` ignores `key`/`url`; the
/// engine draws a fresh seed and returns it once.
/// `generate=false` + (`key` xor `url`) imports an existing seed.
#[derive(Deserialize)]
pub struct TotpCreateKeyRequest {
    pub mount: String,
    pub name: String,
    pub generate: bool,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u64>,
    pub period: Option<u64>,
    pub skew: Option<u64>,
    pub key_size: Option<u64>,
    pub qr_size: Option<u64>,
    pub exported: Option<bool>,
    pub replay_check: Option<bool>,
    pub key: Option<String>,
    pub url: Option<String>,
}

/// Engine response from `POST /v1/totp/keys/:name`. `key` / `url` /
/// `barcode` are present only on a generate-mode + exported create
/// (one-shot disclosure). On every other call those fields are empty.
#[derive(Serialize, Default)]
pub struct TotpCreateKeyResult {
    pub name: String,
    pub generate: bool,
    pub key: String,
    pub url: String,
    /// Base64-encoded PNG. Empty if `qr_size = 0` or provider-mode.
    pub barcode: String,
}

#[tauri::command]
pub async fn totp_create_key(
    state: State<'_, AppState>,
    request: TotpCreateKeyRequest,
) -> CmdResult<TotpCreateKeyResult> {
    let path = format!("{}/keys/{}", mount_prefix(&request.mount), request.name);

    let mut body = Map::new();
    body.insert("generate".into(), Value::Bool(request.generate));

    let push_str = |body: &mut Map<String, Value>, k: &str, v: &Option<String>| {
        if let Some(s) = v.as_ref().filter(|s| !s.is_empty()) {
            body.insert(k.into(), Value::String(s.clone()));
        }
    };
    let push_u = |body: &mut Map<String, Value>, k: &str, v: Option<u64>| {
        if let Some(n) = v {
            body.insert(k.into(), Value::Number(n.into()));
        }
    };

    push_str(&mut body, "issuer", &request.issuer);
    push_str(&mut body, "account_name", &request.account_name);
    push_str(&mut body, "algorithm", &request.algorithm);
    push_u(&mut body, "digits", request.digits);
    push_u(&mut body, "period", request.period);
    push_u(&mut body, "skew", request.skew);
    push_u(&mut body, "key_size", request.key_size);
    push_u(&mut body, "qr_size", request.qr_size);
    if let Some(e) = request.exported {
        body.insert("exported".into(), Value::Bool(e));
    }
    if let Some(r) = request.replay_check {
        body.insert("replay_check".into(), Value::Bool(r));
    }
    push_str(&mut body, "key", &request.key);
    push_str(&mut body, "url", &request.url);

    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(TotpCreateKeyResult {
        name: val_str(&map, "name"),
        generate: val_bool(&map, "generate"),
        key: val_str(&map, "key"),
        url: val_str(&map, "url"),
        barcode: val_str(&map, "barcode"),
    })
}

#[tauri::command]
pub async fn totp_delete_key(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let path = format!("{}/keys/{}", mount_prefix(&mount), name);
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

// ── Code endpoint ─────────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct TotpCodeResult {
    pub code: String,
}

/// `GET /v1/totp/code/:name` — generate-mode current code.
#[tauri::command]
pub async fn totp_get_code(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<TotpCodeResult> {
    let path = format!("{}/code/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);
    Ok(TotpCodeResult {
        code: val_str(&map, "code"),
    })
}

#[derive(Serialize, Default)]
pub struct TotpValidateResult {
    pub valid: bool,
}

/// `POST /v1/totp/code/:name` — provider-mode validate.
#[tauri::command]
pub async fn totp_validate_code(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    code: String,
) -> CmdResult<TotpValidateResult> {
    let path = format!("{}/code/{}", mount_prefix(&mount), name);
    let mut body = Map::new();
    body.insert("code".into(), Value::String(code));
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(TotpValidateResult {
        valid: val_bool(&map, "valid"),
    })
}
