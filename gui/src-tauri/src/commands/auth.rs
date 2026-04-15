use serde::Serialize;
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub policies: Vec<String>,
}

#[tauri::command]
pub async fn login_token(state: State<'_, AppState>, token: String) -> CmdResult<LoginResponse> {
    let vault_guard = state.vault.lock().await;
    let _vault = vault_guard.as_ref().ok_or("Vault not open")?;

    // Store the token in state. Actual validation happens on each API call.
    drop(vault_guard);
    *state.token.lock().await = Some(token.clone());

    Ok(LoginResponse {
        token,
        policies: vec!["root".to_string()],
    })
}

#[tauri::command]
pub async fn login_userpass(
    state: State<'_, AppState>,
    username: String,
    password: String,
) -> CmdResult<LoginResponse> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    // Build a login request through the vault's internal request handling.
    use bastion_vault::logical::{Operation, Request};
    use serde_json::{Map, Value};

    let mut body = Map::new();
    body.insert("password".to_string(), Value::String(password));

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = format!("auth/userpass/login/{username}");
    req.body = Some(body);

    let resp = core.handle_request(&mut req).await
        .map_err(|e| crate::error::CommandError::from(e))?;

    match resp {
        Some(r) => {
            if let Some(auth) = r.auth {
                let token = auth.client_token.clone();
                drop(vault_guard);
                *state.token.lock().await = Some(token.clone());
                Ok(LoginResponse {
                    token,
                    policies: auth.policies.clone(),
                })
            } else {
                Err("Login failed: no auth in response".into())
            }
        }
        None => Err("Login failed: empty response".into()),
    }
}

#[tauri::command]
pub async fn get_current_token(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    Ok(state.token.lock().await.clone())
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    *state.token.lock().await = None;
    Ok(())
}
