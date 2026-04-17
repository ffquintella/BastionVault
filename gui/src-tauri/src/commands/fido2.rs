use bastion_vault::logical::{Operation, Request};
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

pub(crate) async fn make_request(
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

    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)
}

// ── Config ─────────────────────────────────────────────────────────
// Now stored within the userpass mount at auth/userpass/fido2/config

#[derive(Serialize)]
pub struct Fido2Config {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

#[tauri::command]
pub async fn fido2_config_read(state: State<'_, AppState>) -> CmdResult<Option<Fido2Config>> {
    let resp = make_request(&state, Operation::Read, "auth/userpass/fido2/config".into(), None).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(Some(Fido2Config {
                rp_id: data.and_then(|d| d.get("rp_id")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                rp_origin: data.and_then(|d| d.get("rp_origin")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                rp_name: data.and_then(|d| d.get("rp_name")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
            }))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn fido2_config_write(
    state: State<'_, AppState>,
    rp_id: String,
    rp_origin: String,
    rp_name: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("rp_id".into(), Value::String(rp_id));
    body.insert("rp_origin".into(), Value::String(rp_origin));
    body.insert("rp_name".into(), Value::String(rp_name));

    make_request(&state, Operation::Write, "auth/userpass/fido2/config".into(), Some(body)).await?;
    Ok(())
}

// ── Registration ───────────────────────────────────────────────────
// Now within userpass: auth/userpass/fido2/register/*

#[derive(Serialize)]
pub struct Fido2ChallengeResponse {
    pub data: Value,
}

#[tauri::command]
pub async fn fido2_register_begin(
    state: State<'_, AppState>,
    username: String,
) -> CmdResult<Fido2ChallengeResponse> {
    let mut body = Map::new();
    body.insert("username".into(), Value::String(username));

    let resp = make_request(
        &state,
        Operation::Write,
        "auth/userpass/fido2/register/begin".into(),
        Some(body),
    ).await?;

    match resp {
        Some(r) => {
            let data = r.data.map(Value::Object).unwrap_or(Value::Null);
            Ok(Fido2ChallengeResponse { data })
        }
        None => Err("Failed to start registration".into()),
    }
}

#[tauri::command]
pub async fn fido2_register_complete(
    state: State<'_, AppState>,
    username: String,
    credential: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("username".into(), Value::String(username));
    body.insert("credential".into(), Value::String(credential));

    make_request(
        &state,
        Operation::Write,
        "auth/userpass/fido2/register/complete".into(),
        Some(body),
    ).await?;
    Ok(())
}

// ── Login ──────────────────────────────────────────────────────────
// Now within userpass: auth/userpass/fido2/login/*

#[derive(Serialize)]
pub struct Fido2LoginResponse {
    pub token: String,
    pub policies: Vec<String>,
}

#[tauri::command]
pub async fn fido2_login_begin(
    state: State<'_, AppState>,
    username: String,
) -> CmdResult<Fido2ChallengeResponse> {
    let mut body = Map::new();
    body.insert("username".into(), Value::String(username));

    let resp = make_request(
        &state,
        Operation::Write,
        "auth/userpass/fido2/login/begin".into(),
        Some(body),
    ).await?;

    match resp {
        Some(r) => {
            let data = r.data.map(Value::Object).unwrap_or(Value::Null);
            Ok(Fido2ChallengeResponse { data })
        }
        None => Err("Failed to start authentication".into()),
    }
}

#[tauri::command]
pub async fn fido2_login_complete(
    state: State<'_, AppState>,
    username: String,
    credential: String,
) -> CmdResult<Fido2LoginResponse> {
    let mut body = Map::new();
    body.insert("username".into(), Value::String(username));
    body.insert("credential".into(), Value::String(credential));

    let resp = make_request(
        &state,
        Operation::Write,
        "auth/userpass/fido2/login/complete".into(),
        Some(body),
    ).await?;

    match resp {
        Some(r) => {
            if let Some(auth) = r.auth {
                let token = auth.client_token.clone();
                Ok(Fido2LoginResponse {
                    token,
                    policies: auth.policies.clone(),
                })
            } else {
                Err("FIDO2 authentication failed: no auth in response".into())
            }
        }
        None => Err("FIDO2 authentication failed".into()),
    }
}

// ── Credentials (per-user FIDO2 info) ─────────────────────────────
// Now within userpass: auth/userpass/users/{username}/fido2

#[derive(Serialize)]
pub struct Fido2CredentialInfo {
    pub username: String,
    pub registered_keys: u64,
    pub fido2_enabled: bool,
}

#[tauri::command]
pub async fn fido2_list_credentials(
    state: State<'_, AppState>,
    username: String,
) -> CmdResult<Option<Fido2CredentialInfo>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("auth/userpass/users/{username}/fido2"),
        None,
    ).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(Some(Fido2CredentialInfo {
                username: data.and_then(|d| d.get("username")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                registered_keys: data.and_then(|d| d.get("registered_keys")).and_then(|v| v.as_u64()).unwrap_or(0),
                fido2_enabled: data.and_then(|d| d.get("fido2_enabled")).and_then(|v| v.as_bool()).unwrap_or(false),
            }))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn fido2_delete_credential(
    state: State<'_, AppState>,
    username: String,
) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("auth/userpass/users/{username}/fido2"),
        None,
    ).await?;
    Ok(())
}
