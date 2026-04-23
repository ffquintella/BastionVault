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
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    // Validate the token up-front by calling `auth/token/lookup-self`
    // with it. This is the Vault-compatible "introspect my own token"
    // endpoint — any valid token can read its own metadata, an
    // invalid one gets `ErrPermissionDenied` / `ErrResponse`. Doing
    // the round-trip here turns a wrong token into an immediate
    // "Invalid token" login failure instead of letting the user
    // navigate to a page and get a confusing "Permission denied"
    // toast on the first data fetch.
    //
    // The response also carries the token's `policies`, which we
    // surface to the UI so role-gated routes (Admin sections, etc.)
    // render correctly from the moment of login rather than waiting
    // on a follow-up fetch.
    use bastion_vault::logical::{Operation, Request};

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = "auth/token/lookup-self".to_string();
    req.client_token = token.clone();

    let resp = core
        .handle_request(&mut req)
        .await
        .map_err(|e| {
            // Surface a more operator-friendly message than the raw
            // vault error for the common case — "permission denied"
            // on lookup-self means the token string didn't match
            // anything known, not that policy blocked the introspect.
            let msg = format!("{e}");
            if msg.to_ascii_lowercase().contains("permission denied")
                || msg.to_ascii_lowercase().contains("invalid")
            {
                crate::error::CommandError::from("Invalid token")
            } else {
                crate::error::CommandError::from(e)
            }
        })?
        .ok_or_else(|| crate::error::CommandError::from("Invalid token"))?;

    // Extract policies from the response data. The shape is
    // `{data: {policies: [...], ...}}`. Missing/empty policies is
    // unusual but not fatal — we fall back to the default-policy
    // list so the UI still renders, and any policy-gated operation
    // will still be blocked server-side by ACL anyway.
    let policies: Vec<String> = resp
        .data
        .as_ref()
        .and_then(|d| d.get("policies"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["default".to_string()]);

    drop(vault_guard);
    *state.token.lock().await = Some(token.clone());

    Ok(LoginResponse { token, policies })
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
