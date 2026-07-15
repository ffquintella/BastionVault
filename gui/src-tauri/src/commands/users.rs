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
    /// Admin enable/disable switch.
    pub disabled: bool,
    /// Whether the account is currently locked out (server-computed).
    pub locked: bool,
    /// Consecutive failed password attempts since the last success/unlock.
    pub failed_login_count: u64,
    /// Whether a TOTP second factor is required for this user.
    pub totp_mfa_enabled: bool,
    /// TOTP engine mount bound for MFA (empty = global default).
    pub totp_mount: String,
    /// TOTP key name bound for MFA.
    pub totp_key: String,
}

/// Mount-level lockout policy (mirrors `config/lockout`).
#[derive(Serialize, serde::Deserialize)]
pub struct LockoutConfigDto {
    pub enabled: bool,
    pub max_failed_attempts: u64,
    pub lockout_duration_secs: u64,
}

/// Mount-level TOTP MFA policy (mirrors `config/mfa`).
#[derive(Serialize, serde::Deserialize)]
pub struct MfaConfigDto {
    pub enabled: bool,
    pub default_mount: String,
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
            let data = r.data.as_ref();
            let get_bool = |k: &str| {
                data.and_then(|d| d.get(k)).and_then(|v| v.as_bool()).unwrap_or(false)
            };
            let get_str = |k: &str| {
                data.and_then(|d| d.get(k)).and_then(|v| v.as_str()).unwrap_or("").to_string()
            };
            let failed_login_count = data
                .and_then(|d| d.get("failed_login_count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            Ok(UserInfo {
                username,
                policies,
                disabled: get_bool("disabled"),
                locked: get_bool("locked"),
                failed_login_count,
                totp_mfa_enabled: get_bool("totp_mfa_enabled"),
                totp_mount: get_str("totp_mount"),
                totp_key: get_str("totp_key"),
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
#[allow(clippy::too_many_arguments)]
pub async fn update_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    password: String,
    policies: String,
    // Account-state and MFA fields. `None` leaves the stored value untouched
    // so an unrelated update (e.g. a policy change) never resets a flag.
    disabled: Option<bool>,
    totp_mfa_enabled: Option<bool>,
    totp_mount: Option<String>,
    totp_key: Option<String>,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    let mut body = Map::new();
    if !password.is_empty() {
        body.insert("password".to_string(), Value::String(password));
    }
    body.insert("policies".to_string(), Value::String(policies));
    if let Some(v) = disabled {
        body.insert("disabled".to_string(), Value::Bool(v));
    }
    if let Some(v) = totp_mfa_enabled {
        body.insert("totp_mfa_enabled".to_string(), Value::Bool(v));
    }
    if let Some(v) = totp_mount {
        body.insert("totp_mount".to_string(), Value::String(v));
    }
    if let Some(v) = totp_key {
        body.insert("totp_key".to_string(), Value::String(v));
    }

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn unlock_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}/unlock");
    make_request(&state, Operation::Write, path, Some(Map::new())).await?;
    Ok(())
}

#[tauri::command]
pub async fn get_lockout_config(
    state: State<'_, AppState>,
    mount_path: String,
) -> CmdResult<LockoutConfigDto> {
    let path = format!("auth/{mount_path}config/lockout");
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let data = resp.and_then(|r| r.data).map(Value::Object).unwrap_or(Value::Null);
    Ok(serde_json::from_value(data)
        .unwrap_or(LockoutConfigDto { enabled: true, max_failed_attempts: 5, lockout_duration_secs: 900 }))
}

#[tauri::command]
pub async fn set_lockout_config(
    state: State<'_, AppState>,
    mount_path: String,
    enabled: bool,
    max_failed_attempts: u64,
    lockout_duration_secs: u64,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}config/lockout");
    let mut body = Map::new();
    body.insert("enabled".to_string(), Value::Bool(enabled));
    body.insert("max_failed_attempts".to_string(), Value::Number(max_failed_attempts.into()));
    body.insert("lockout_duration_secs".to_string(), Value::Number(lockout_duration_secs.into()));
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn get_mfa_config(
    state: State<'_, AppState>,
    mount_path: String,
) -> CmdResult<MfaConfigDto> {
    let path = format!("auth/{mount_path}config/mfa");
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let data = resp.and_then(|r| r.data).map(Value::Object).unwrap_or(Value::Null);
    Ok(serde_json::from_value(data)
        .unwrap_or(MfaConfigDto { enabled: false, default_mount: "totp/".to_string() }))
}

#[tauri::command]
pub async fn set_mfa_config(
    state: State<'_, AppState>,
    mount_path: String,
    enabled: bool,
    default_mount: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}config/mfa");
    let mut body = Map::new();
    body.insert("enabled".to_string(), Value::Bool(enabled));
    if !default_mount.is_empty() {
        body.insert("default_mount".to_string(), Value::String(default_mount));
    }
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
