use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::{make_request, make_request_root};

#[derive(Serialize)]
pub struct UserListResult {
    pub users: Vec<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub policies: Vec<String>,
}

#[tauri::command]
pub async fn list_users(
    state: State<'_, AppState>,
    mount_path: String,
) -> CmdResult<UserListResult> {
    let path = format!("auth/{mount_path}users/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let users: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(UserListResult { users });
                }
            }
            Ok(UserListResult { users: vec![] })
        }
        None => Ok(UserListResult { users: vec![] }),
    }
}

#[tauri::command]
pub async fn get_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<UserInfo> {
    let path = format!("auth/{mount_path}users/{username}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let policies = r
                .data
                .as_ref()
                .and_then(|d| d.get("policies"))
                .map(|v| match v {
                    // Array of strings (from token_policies serialization)
                    Value::Array(arr) => arr
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect(),
                    // Comma-separated string
                    Value::String(s) => s
                        .split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect(),
                    _ => vec![],
                })
                .unwrap_or_default();
            Ok(UserInfo {
                username,
                policies,
            })
        }
        None => Err("User not found".into()),
    }
}

#[tauri::command]
pub async fn create_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    password: String,
    policies: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    let mut body = Map::new();
    body.insert("password".to_string(), Value::String(password));
    if !policies.is_empty() {
        body.insert("policies".to_string(), Value::String(policies));
    }

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn update_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    password: String,
    policies: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    let mut body = Map::new();
    if !password.is_empty() {
        body.insert("password".to_string(), Value::String(password));
    }
    body.insert("policies".to_string(), Value::String(policies));

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

/// A principal's per-OS default resource accounts (Resource Connect). Empty
/// login-name fields mean "unconfigured" for that OS family. The Windows RDP
/// password is never returned as plaintext on this admin path — only
/// `has_windows_password` reports whether one is stored.
#[derive(Serialize, Default)]
pub struct DefaultAccountResult {
    pub linux: String,
    pub macos: String,
    pub windows: String,
    pub has_windows_password: bool,
}

fn default_account_path(mount_path: &str, username: &str) -> String {
    // Mirror the ns-assignment shape: `<mount>` carries its trailing slash so
    // the sys route splits `mount` from `name` on the first slash after it.
    format!("sys/identity/default-account/{mount_path}{username}")
}

fn account_field(data: &Option<&Map<String, Value>>, key: &str) -> String {
    data.and_then(|d| d.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn account_bool(data: &Option<&Map<String, Value>>, key: &str) -> bool {
    data.and_then(|d| d.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[tauri::command]
pub async fn get_default_account(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<DefaultAccountResult> {
    let resp = make_request_root(
        &state,
        Operation::Read,
        default_account_path(&mount_path, &username),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data);
    let data_ref = data.as_ref();
    Ok(DefaultAccountResult {
        linux: account_field(&data_ref, "linux"),
        macos: account_field(&data_ref, "macos"),
        windows: account_field(&data_ref, "windows"),
        has_windows_password: account_bool(&data_ref, "has_windows_password"),
    })
}

/// The *calling* operator's own default accounts, resolved server-side from the
/// request token. Used by the Connect flow to decide whether to prompt for the
/// RDP password. The stored password itself is intentionally **not** surfaced
/// to the frontend — only `has_windows_password` — even though the underlying
/// `self` endpoint reveals it to the host (the connect path consumes it
/// directly in Rust).
#[tauri::command]
pub async fn get_default_account_self(
    state: State<'_, AppState>,
) -> CmdResult<DefaultAccountResult> {
    let resp = make_request(
        &state,
        Operation::Read,
        "sys/identity/default-account/self".to_string(),
        None,
    )
    .await?;
    let data = resp.and_then(|r| r.data);
    let data_ref = data.as_ref();
    Ok(DefaultAccountResult {
        linux: account_field(&data_ref, "linux"),
        macos: account_field(&data_ref, "macos"),
        windows: account_field(&data_ref, "windows"),
        has_windows_password: account_bool(&data_ref, "has_windows_password"),
    })
}

#[tauri::command]
pub async fn set_default_account(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    linux: String,
    macos: String,
    windows: String,
    // `None` keeps the stored password untouched; `Some("")` clears it;
    // `Some(pw)` sets a new one. The GUI sends `None` unless the admin typed a
    // new password or asked to clear it.
    windows_password: Option<String>,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("linux".to_string(), Value::String(linux));
    body.insert("macos".to_string(), Value::String(macos));
    body.insert("windows".to_string(), Value::String(windows));
    if let Some(pw) = windows_password {
        body.insert("windows_password".to_string(), Value::String(pw));
    }
    make_request_root(
        &state,
        Operation::Write,
        default_account_path(&mount_path, &username),
        Some(body),
    )
    .await?;
    Ok(())
}
