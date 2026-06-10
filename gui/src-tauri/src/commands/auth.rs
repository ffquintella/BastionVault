use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::dispatch_with_token;

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub policies: Vec<String>,
}

#[tauri::command]
pub async fn login_token(state: State<'_, AppState>, token: String) -> CmdResult<LoginResponse> {
    // Validate the token up-front by calling `auth/token/lookup-self`
    // with it. This is the Vault-compatible "introspect my own token"
    // endpoint — any valid token can read its own metadata, an
    // invalid one gets a "permission denied" / "invalid" error. Doing
    // the round-trip here turns a wrong token into an immediate
    // "Invalid token" login failure instead of letting the user
    // navigate to a page and get a confusing "Permission denied"
    // toast on the first data fetch.
    //
    // The response also carries the token's `policies`, which we
    // surface to the UI so role-gated routes (Admin sections, etc.)
    // render correctly from the moment of login rather than waiting
    // on a follow-up fetch.
    let resp = dispatch_with_token(
        &state,
        Operation::Read,
        "auth/token/lookup-self".to_string(),
        None,
        &token,
    )
    .await
    .map_err(|e| {
        // Surface a more operator-friendly message than the raw
        // vault error for the common case — "permission denied"
        // on lookup-self means the token string didn't match
        // anything known, not that policy blocked the introspect.
        let msg = e.to_string().to_ascii_lowercase();
        if msg.contains("permission denied") || msg.contains("invalid") {
            crate::error::CommandError::from("Invalid token")
        } else {
            e
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

    *state.token.lock().await = Some(token.clone());

    Ok(LoginResponse { token, policies })
}

#[tauri::command]
pub async fn login_userpass(
    state: State<'_, AppState>,
    username: String,
    password: String,
) -> CmdResult<LoginResponse> {
    let mut body = Map::new();
    body.insert("password".to_string(), Value::String(password));

    // The username is a URI path segment. Trim accidental surrounding
    // whitespace (a stray space/newline from paste or autofill would
    // otherwise build an invalid URI -> `InvalidUriChar`) and
    // percent-encode it so any legitimate special character can't break
    // URL construction.
    let username = urlencoding::encode(username.trim());

    // Login endpoints take no token. Pass an empty string; both
    // EmbeddedBackend (just stores it on the Request) and
    // RemoteBackend (skips the X-BastionVault-Token header for
    // /login paths) handle it correctly.
    let resp = dispatch_with_token(
        &state,
        Operation::Write,
        format!("auth/userpass/login/{username}"),
        Some(body),
        "",
    )
    .await?;

    match resp {
        Some(r) => {
            if let Some(auth) = r.auth {
                let token = auth
                    .get("client_token")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let policies = auth
                    .get("policies")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if token.is_empty() {
                    return Err("Login failed: no token in auth response".into());
                }
                *state.token.lock().await = Some(token.clone());
                Ok(LoginResponse { token, policies })
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
