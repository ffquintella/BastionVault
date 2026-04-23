use std::path::PathBuf;

use bastion_vault::api::{client::TLSConfigBuilder, Client};
use serde::Serialize;
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::preferences::Preferences;
use crate::state::{AppState, RemoteProfile, VaultMode};

#[tauri::command]
pub async fn get_mode(state: State<'_, AppState>) -> CmdResult<VaultMode> {
    Ok(state.mode.lock().await.clone())
}

#[tauri::command]
pub async fn set_mode(state: State<'_, AppState>, mode: VaultMode) -> CmdResult<()> {
    *state.mode.lock().await = mode;
    Ok(())
}

#[tauri::command]
pub async fn is_vault_initialized() -> CmdResult<bool> {
    crate::embedded::is_initialized()
}

/// Get the current remote profile (if in remote mode).
#[tauri::command]
pub async fn get_remote_profile(state: State<'_, AppState>) -> CmdResult<Option<RemoteProfile>> {
    Ok(state.remote_profile.lock().await.clone())
}

/// Connect to a remote BastionVault server.
#[tauri::command]
pub async fn connect_remote(
    state: State<'_, AppState>,
    profile: RemoteProfile,
) -> CmdResult<()> {
    let mut client_builder = Client::new()
        .with_addr(&profile.address);

    // Configure TLS if the address is HTTPS.
    if profile.address.starts_with("https://") {
        let mut tls_builder = TLSConfigBuilder::new()
            .with_insecure(profile.tls_skip_verify);

        if let Some(ca_path) = &profile.ca_cert_path {
            if !ca_path.is_empty() {
                tls_builder = tls_builder
                    .with_server_ca_path(&PathBuf::from(ca_path))
                    .map_err(|e| CommandError::from(format!("CA cert error: {e}")))?;
            }
        }

        if let (Some(cert_path), Some(key_path)) = (&profile.client_cert_path, &profile.client_key_path) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                tls_builder = tls_builder
                    .with_client_cert_path(&PathBuf::from(cert_path), &PathBuf::from(key_path))
                    .map_err(|e| CommandError::from(format!("Client cert error: {e}")))?;
            }
        }

        let tls_config = tls_builder.build()
            .map_err(|e| CommandError::from(format!("TLS config error: {e}")))?;

        client_builder = client_builder.with_tls_config(tls_config);
    }

    let client = client_builder.build();

    // Test the connection by checking health.
    let health = client.sys().health()
        .map_err(|e| CommandError::from(format!("Connection failed: {e}")))?;

    if health.response_status == 0 {
        return Err("Connection failed: no response from server".into());
    }

    *state.mode.lock().await = VaultMode::Remote;
    *state.remote_client.lock().await = Some(client);
    *state.remote_profile.lock().await = Some(profile);
    // Clear embedded vault if switching from embedded.
    *state.vault.lock().await = None;

    Ok(())
}

/// Disconnect from remote server and reset to embedded mode.
#[tauri::command]
pub async fn disconnect_remote(state: State<'_, AppState>) -> CmdResult<()> {
    *state.mode.lock().await = VaultMode::Embedded;
    *state.remote_client.lock().await = None;
    *state.remote_profile.lock().await = None;
    *state.token.lock().await = None;
    Ok(())
}

#[derive(Serialize)]
pub struct RemoteStatus {
    pub connected: bool,
    pub address: String,
    pub initialized: bool,
    pub sealed: bool,
}

/// Get the status of the remote connection.
#[tauri::command]
pub async fn get_remote_status(state: State<'_, AppState>) -> CmdResult<RemoteStatus> {
    let client_guard = state.remote_client.lock().await;
    let profile_guard = state.remote_profile.lock().await;

    match (client_guard.as_ref(), profile_guard.as_ref()) {
        (Some(client), Some(profile)) => {
            match client.sys().health() {
                Ok(resp) => {
                    let data = resp.response_data;
                    let initialized = data.as_ref()
                        .and_then(|d| d.get("initialized"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let sealed = data.as_ref()
                        .and_then(|d| d.get("sealed"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    Ok(RemoteStatus {
                        connected: true,
                        address: profile.address.clone(),
                        initialized,
                        sealed,
                    })
                }
                Err(_) => Ok(RemoteStatus {
                    connected: false,
                    address: profile.address.clone(),
                    initialized: false,
                    sealed: true,
                }),
            }
        }
        _ => Ok(RemoteStatus {
            connected: false,
            address: String::new(),
            initialized: false,
            sealed: true,
        }),
    }
}

/// Login to a remote vault with a token.
///
/// Validates the token against the remote server via
/// `auth/token/lookup-self` before storing it. Without this,
/// a wrong token string gets saved into state and the user sees
/// "Permission denied" toasts from every subsequent page fetch;
/// this way an invalid token surfaces as an immediate "Invalid
/// token" error on the login page.
#[tauri::command]
pub async fn remote_login_token(
    state: State<'_, AppState>,
    token: String,
) -> CmdResult<()> {
    let client_guard = state.remote_client.lock().await;
    let client = client_guard.as_ref().ok_or("Not connected to remote server")?;

    // `token/lookup-self` is a GET that any valid token can call
    // against its own metadata. The client takes a token via
    // `with_token`; on an invalid token the request errors out and
    // we surface that as "Invalid token" without storing anything.
    let endpoint = format!("{}/auth/token/lookup-self", client.api_prefix());
    let bound = client.clone().with_token(&token);
    bound
        .request_read(endpoint)
        .map_err(|e| {
            let msg = format!("{e}");
            if msg.to_ascii_lowercase().contains("permission denied")
                || msg.to_ascii_lowercase().contains("invalid")
                || msg.to_ascii_lowercase().contains("forbidden")
            {
                CommandError::from("Invalid token")
            } else {
                CommandError::from(format!("Token validation failed: {e}"))
            }
        })?;

    drop(client_guard);
    *state.token.lock().await = Some(token);
    Ok(())
}

/// Login to a remote vault with username/password.
#[tauri::command]
pub async fn remote_login_userpass(
    state: State<'_, AppState>,
    username: String,
    password: String,
) -> CmdResult<crate::commands::auth::LoginResponse> {
    let client_guard = state.remote_client.lock().await;
    let client = client_guard.as_ref().ok_or("Not connected to remote server")?;

    let data = serde_json::json!({ "password": password });
    let resp = client
        .request_write(
            format!("{}/auth/userpass/login/{username}", client.api_prefix()),
            data.as_object().cloned(),
        )
        .map_err(|e| CommandError::from(format!("Login failed: {e}")))?;

    let response_data = resp.response_data.ok_or("No response data")?;

    let token = response_data
        .get("auth")
        .and_then(|a| a.get("client_token"))
        .and_then(|t| t.as_str())
        .ok_or("No token in response")?
        .to_string();

    let policies: Vec<String> = response_data
        .get("auth")
        .and_then(|a| a.get("policies"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    drop(client_guard);
    *state.token.lock().await = Some(token.clone());

    Ok(crate::commands::auth::LoginResponse { token, policies })
}

#[tauri::command]
pub async fn load_preferences() -> CmdResult<Preferences> {
    crate::preferences::load()
}

/// Legacy-shape save for callers that still think in mode + single
/// remote_profile terms. Folds into the multi-vault list:
///   * Embedded / no profile → ensures a default Local entry exists
///     and flips `last_used_id` to it.
///   * Remote with profile → upserts a Remote vault by matching
///     address; flips `last_used_id` to it.
///
/// New-shape callers (the redesigned ConnectPage) use the explicit
/// `add_vault_profile` + `set_last_used_vault` commands instead.
#[tauri::command]
pub async fn save_preferences(mode: VaultMode, remote_profile: Option<RemoteProfile>) -> CmdResult<()> {
    use crate::preferences::{short_id, VaultProfile, VaultSpec};

    let mut prefs = crate::preferences::load().unwrap_or_default();
    match mode {
        VaultMode::Embedded => {
            // Find any existing Local profile; otherwise create one.
            let existing_id = prefs
                .vaults
                .iter()
                .find(|v| matches!(v.spec, VaultSpec::Local { .. }))
                .map(|v| v.id.clone());
            let id = existing_id.unwrap_or_else(|| {
                let id = short_id();
                prefs.vaults.push(VaultProfile {
                    id: id.clone(),
                    name: "Local Vault".to_string(),
                    spec: VaultSpec::Local {
                        data_dir: None,
                        storage_kind: "file".to_string(),
                    },
                });
                id
            });
            prefs.last_used_id = Some(id);
        }
        VaultMode::Remote => {
            let Some(profile) = remote_profile else {
                return Err("save_preferences(Remote) requires a profile".into());
            };
            // Upsert by matching address — the legacy caller provides
            // no stable id.
            let existing = prefs
                .vaults
                .iter()
                .position(|v| matches!(&v.spec, VaultSpec::Remote { profile: p } if p.address == profile.address));
            let id = if let Some(idx) = existing {
                prefs.vaults[idx].spec = VaultSpec::Remote { profile: profile.clone() };
                prefs.vaults[idx].name = profile.name.clone();
                prefs.vaults[idx].id.clone()
            } else {
                let id = short_id();
                prefs.vaults.push(VaultProfile {
                    id: id.clone(),
                    name: if profile.name.is_empty() {
                        "Remote Vault".to_string()
                    } else {
                        profile.name.clone()
                    },
                    spec: VaultSpec::Remote { profile },
                });
                id
            };
            prefs.last_used_id = Some(id);
        }
    }
    crate::preferences::save(&prefs)
}

#[tauri::command]
pub async fn get_password_policy() -> CmdResult<crate::preferences::PasswordPolicy> {
    Ok(crate::preferences::load().unwrap_or_default().password_policy)
}

#[tauri::command]
pub async fn set_password_policy(
    policy: crate::preferences::PasswordPolicy,
) -> CmdResult<()> {
    let mut prefs = crate::preferences::load().unwrap_or_default();
    prefs.password_policy = policy;
    crate::preferences::save(&prefs)
}
