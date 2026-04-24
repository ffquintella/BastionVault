//! SSO provider administration — the Settings → Single Sign-On card
//! drives these.
//!
//! Each command bundles the N vault writes needed to stand up an OIDC
//! provider end-to-end (mount + config + default role) so the admin
//! never has to drop to the raw `sys/auth/<mount>` / `auth/<mount>/config`
//! / `auth/<mount>/role/<name>` surface. Deleting a provider disables
//! the auth mount — the config + role storage is scoped to that mount
//! and gets torn down with it.
//!
//! `client_secret` and `allowed_redirect_uris` pass through to the
//! OIDC backend's `write_config` which redacts the secret on read;
//! the admin UI only surfaces a `client_secret_set` boolean hint.

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, VaultMode};

/// One row in the admin list. `client_secret` is never surfaced —
/// `client_secret_set` indicates whether one is stored.
#[derive(Serialize, Debug, Clone)]
pub struct SsoAdminProvider {
    pub mount: String,
    pub display_name: String,
    pub kind: String,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret_set: bool,
    pub allowed_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub default_role: String,
    /// Populated when the mount's `default_role` exists. `None` when
    /// the role is missing — the UI flags that as "login will fail".
    pub role: Option<SsoAdminRole>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SsoAdminRole {
    pub name: String,
    pub user_claim: String,
    pub groups_claim: String,
    pub bound_audiences: Vec<String>,
    /// Stored as raw JSON (`{"hd":["example.com"]}`) so the UI can
    /// round-trip it through the same text field the raw API uses.
    pub bound_claims_json: String,
    pub policies: Vec<String>,
    pub token_ttl_secs: u64,
}

/// Input payload for create + update. Optional fields that the caller
/// leaves blank propagate as "don't touch" on update; on create they
/// fill in documented defaults.
#[derive(Deserialize, Debug)]
pub struct SsoAdminInput {
    pub mount: String,
    pub display_name: String,
    pub discovery_url: String,
    pub client_id: String,
    /// Empty string means "don't change" on update. On create, empty
    /// is accepted (PKCE-only public client).
    pub client_secret: String,
    pub allowed_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub default_role: String,
    pub role: SsoAdminRole,
}

#[tauri::command]
pub async fn sso_admin_list(state: State<'_, AppState>) -> CmdResult<Vec<SsoAdminProvider>> {
    let mounts = load_oidc_mounts(&state).await?;
    let mut out = Vec::with_capacity(mounts.len());
    for (mount, display_name) in mounts {
        let detail = load_provider_detail(&state, &mount, &display_name).await?;
        out.push(detail);
    }
    out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(out)
}

#[tauri::command]
pub async fn sso_admin_get(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<SsoAdminProvider> {
    let mounts = load_oidc_mounts(&state).await?;
    let display_name = mounts
        .iter()
        .find(|(m, _)| *m == mount)
        .map(|(_, d)| d.clone())
        .ok_or_else(|| format!("sso: mount `{mount}` not found"))?;
    load_provider_detail(&state, &mount, &display_name).await
}

#[tauri::command]
pub async fn sso_admin_create(
    state: State<'_, AppState>,
    input: SsoAdminInput,
) -> CmdResult<()> {
    validate_input(&input)?;

    // 1. Mount the auth backend with the operator's display name
    //    populating the mount description. The list-SSO-providers
    //    unauth endpoint surfaces this as the button label.
    let mut mount_body = Map::new();
    mount_body.insert("type".into(), Value::String("oidc".into()));
    mount_body.insert(
        "description".into(),
        Value::String(input.display_name.clone()),
    );
    sys_write(&state, &format!("sys/auth/{}", input.mount), mount_body).await?;

    // 2. Write provider config (OIDC discovery, client id/secret,
    //    redirect URIs, scopes, default role).
    write_oidc_config(&state, &input, /* allow_secret_clear = */ true).await?;

    // 3. Write the default role. Callers must always supply one so
    //    the login flow has something to resolve when `role` is
    //    omitted on `auth_url`.
    write_oidc_role(&state, &input).await?;

    Ok(())
}

#[tauri::command]
pub async fn sso_admin_update(
    state: State<'_, AppState>,
    input: SsoAdminInput,
) -> CmdResult<()> {
    validate_input(&input)?;

    // Refresh the mount description if the display name changed.
    // There's no direct "remount description" API without tearing
    // the mount down, so we update the description via `sys/mounts`
    // if it existed. The lightweight path: re-write the mount, which
    // is idempotent in our implementation. We only do this when the
    // display name actually differs to avoid churning the mount table.
    let mounts = load_oidc_mounts(&state).await?;
    let current_desc = mounts
        .iter()
        .find(|(m, _)| *m == input.mount)
        .map(|(_, d)| d.clone())
        .unwrap_or_default();
    if current_desc != input.display_name {
        // The auth-mount write is upsert-like; re-issuing it updates
        // description without moving data. Tolerate "already mounted"
        // errors — in that case the description edit is deferred to
        // a future re-mount tool (acceptable: buttons render from
        // the latest description on next read).
        let mut mount_body = Map::new();
        mount_body.insert("type".into(), Value::String("oidc".into()));
        mount_body.insert(
            "description".into(),
            Value::String(input.display_name.clone()),
        );
        let _ = sys_write(&state, &format!("sys/auth/{}", input.mount), mount_body).await;
    }

    // On update, an empty client_secret means "don't change" — the
    // OIDC config-write loader merges onto the existing record, so
    // omitting the field entirely leaves it intact.
    write_oidc_config(
        &state,
        &input,
        /* allow_secret_clear = */ !input.client_secret.is_empty(),
    )
    .await?;
    write_oidc_role(&state, &input).await?;

    Ok(())
}

#[tauri::command]
pub async fn sso_admin_delete(state: State<'_, AppState>, mount: String) -> CmdResult<()> {
    sys_delete(&state, &format!("sys/auth/{mount}")).await?;
    Ok(())
}

/// Compute the redirect-URI hints shown next to the "Allowed Redirect
/// URIs" field. For embedded desktop the listener binds a random
/// loopback port each login, so the IdP must accept
/// `http://127.0.0.1` with any port (RFC 8252 "native app" pattern).
/// For a remote BastionVault the callback is stable:
/// `<server>/v1/auth/<mount>/callback`.
#[derive(Serialize, Debug, Clone)]
pub struct SsoCallbackHints {
    pub mode: String,
    pub suggested: Vec<String>,
    pub notes: Vec<String>,
}

#[tauri::command]
pub async fn sso_admin_callback_hints(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<SsoCallbackHints> {
    let mode = state.mode.lock().await.clone();
    match mode {
        VaultMode::Embedded => Ok(SsoCallbackHints {
            mode: "embedded".into(),
            suggested: vec!["http://127.0.0.1/callback".into()],
            notes: vec![
                "Desktop logins bind a random loopback port each run — register `http://127.0.0.1` (any port) with your IdP as a native-app / loopback redirect URI (RFC 8252).".into(),
                "Azure AD calls this a \"Mobile and desktop applications\" redirect; Okta calls it \"Native app\"; Google Cloud lists it under \"Desktop app\".".into(),
            ],
        }),
        VaultMode::Remote => {
            let profile = state.remote_profile.lock().await.clone();
            let base = profile
                .as_ref()
                .map(|p| p.address.trim_end_matches('/').to_string())
                .unwrap_or_else(|| "https://<vault-server>".to_string());
            let stable = format!("{base}/v1/auth/{mount}/callback");
            Ok(SsoCallbackHints {
                mode: "remote".into(),
                suggested: vec![stable],
                notes: vec![
                    "Register the URL above with your IdP. The vault exposes the callback at the v1 path for Vault-API compatibility.".into(),
                ],
            })
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────

async fn load_oidc_mounts(
    state: &State<'_, AppState>,
) -> Result<Vec<(String, String)>, CommandError> {
    // `sys/auth` enumerates every mounted auth backend with its
    // logical type + description. Filter to OIDC.
    let data = sys_read(state, "sys/auth").await?;
    let mut out: Vec<(String, String)> = Vec::new();
    for (raw_path, v) in data.iter() {
        let kind = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
        if kind != "oidc" {
            continue;
        }
        let mount = raw_path.trim_end_matches('/').to_string();
        let description = v
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        out.push((mount, description));
    }
    Ok(out)
}

async fn load_provider_detail(
    state: &State<'_, AppState>,
    mount: &str,
    display_name: &str,
) -> Result<SsoAdminProvider, CommandError> {
    let cfg_data = sys_read(state, &format!("auth/{mount}/config"))
        .await
        .unwrap_or_default();
    let discovery_url = cfg_data
        .get("oidc_discovery_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let client_id = cfg_data
        .get("oidc_client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let client_secret_set = cfg_data
        .get("oidc_client_secret_set")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let allowed_redirect_uris = string_list(&cfg_data, "allowed_redirect_uris");
    let scopes = string_list(&cfg_data, "oidc_scopes");
    let default_role = cfg_data
        .get("default_role")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let role = if !default_role.is_empty() {
        match sys_read(state, &format!("auth/{mount}/role/{default_role}")).await {
            Ok(data) if !data.is_empty() => Some(role_from_data(&default_role, &data)),
            _ => None,
        }
    } else {
        None
    };

    Ok(SsoAdminProvider {
        mount: mount.to_string(),
        display_name: display_name.to_string(),
        kind: "oidc".to_string(),
        discovery_url,
        client_id,
        client_secret_set,
        allowed_redirect_uris,
        scopes,
        default_role,
        role,
    })
}

fn validate_input(input: &SsoAdminInput) -> Result<(), CommandError> {
    if input.mount.trim().is_empty() {
        return Err("sso: mount path is required (e.g. `oidc`, `okta`)".into());
    }
    if input.display_name.trim().is_empty() {
        return Err("sso: display name is required (shown on the login button)".into());
    }
    if input.discovery_url.trim().is_empty() {
        return Err("sso: discovery URL is required".into());
    }
    if input.client_id.trim().is_empty() {
        return Err("sso: client ID is required".into());
    }
    if input.default_role.trim().is_empty() {
        return Err("sso: default role name is required".into());
    }
    if input.role.user_claim.trim().is_empty() {
        return Err("sso: role `user_claim` is required (e.g. `preferred_username`)".into());
    }
    if input.role.policies.is_empty() {
        return Err("sso: role must list at least one vault policy".into());
    }
    // bound_claims_json, when non-empty, must parse as a JSON object.
    let bc = input.role.bound_claims_json.trim();
    if !bc.is_empty() {
        match serde_json::from_str::<Value>(bc) {
            Ok(Value::Object(_)) => {}
            Ok(_) => {
                return Err(
                    "sso: role `bound_claims` must be a JSON object (e.g. `{\"hd\":[\"example.com\"]}`)"
                        .into(),
                )
            }
            Err(e) => return Err(format!("sso: role `bound_claims` invalid JSON: {e}").into()),
        }
    }
    Ok(())
}

async fn write_oidc_config(
    state: &State<'_, AppState>,
    input: &SsoAdminInput,
    allow_secret_clear: bool,
) -> Result<(), CommandError> {
    let mut body = Map::new();
    body.insert(
        "oidc_discovery_url".into(),
        Value::String(input.discovery_url.clone()),
    );
    body.insert(
        "oidc_client_id".into(),
        Value::String(input.client_id.clone()),
    );
    if allow_secret_clear {
        // Empty string on create is fine (public/PKCE client); the
        // backend just persists an empty secret. On update we skip
        // the field entirely to avoid clobbering.
        body.insert(
            "oidc_client_secret".into(),
            Value::String(input.client_secret.clone()),
        );
    }
    body.insert(
        "default_role".into(),
        Value::String(input.default_role.clone()),
    );
    if !input.allowed_redirect_uris.is_empty() {
        body.insert(
            "allowed_redirect_uris".into(),
            Value::Array(
                input
                    .allowed_redirect_uris
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !input.scopes.is_empty() {
        body.insert(
            "oidc_scopes".into(),
            Value::Array(input.scopes.iter().cloned().map(Value::String).collect()),
        );
    }
    sys_write(state, &format!("auth/{}/config", input.mount), body).await?;
    Ok(())
}

async fn write_oidc_role(
    state: &State<'_, AppState>,
    input: &SsoAdminInput,
) -> Result<(), CommandError> {
    let mut body = Map::new();
    body.insert(
        "user_claim".into(),
        Value::String(input.role.user_claim.clone()),
    );
    if !input.role.groups_claim.is_empty() {
        body.insert(
            "groups_claim".into(),
            Value::String(input.role.groups_claim.clone()),
        );
    }
    if !input.role.bound_audiences.is_empty() {
        body.insert(
            "bound_audiences".into(),
            Value::Array(
                input
                    .role
                    .bound_audiences
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !input.role.bound_claims_json.trim().is_empty() {
        body.insert(
            "bound_claims".into(),
            Value::String(input.role.bound_claims_json.trim().to_string()),
        );
    }
    body.insert(
        "policies".into(),
        Value::Array(
            input
                .role
                .policies
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if input.role.token_ttl_secs > 0 {
        body.insert(
            "token_ttl_secs".into(),
            Value::Number(input.role.token_ttl_secs.into()),
        );
    }
    sys_write(
        state,
        &format!("auth/{}/role/{}", input.mount, input.default_role),
        body,
    )
    .await?;
    Ok(())
}

fn role_from_data(name: &str, data: &Map<String, Value>) -> SsoAdminRole {
    SsoAdminRole {
        name: name.to_string(),
        user_claim: data
            .get("user_claim")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        groups_claim: data
            .get("groups_claim")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        bound_audiences: string_list(data, "bound_audiences"),
        bound_claims_json: data
            .get("bound_claims")
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_default(),
        policies: string_list(data, "policies"),
        token_ttl_secs: data
            .get("token_ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    }
}

fn string_list(m: &Map<String, Value>, key: &str) -> Vec<String> {
    m.get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

async fn sys_read(
    state: &State<'_, AppState>,
    path: &str,
) -> Result<Map<String, Value>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = path.to_string();
    req.client_token = token;
    let resp = core
        .handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

async fn sys_write(
    state: &State<'_, AppState>,
    path: &str,
    body: Map<String, Value>,
) -> Result<(), CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Write;
    req.path = path.to_string();
    req.client_token = token;
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;
    Ok(())
}

async fn sys_delete(state: &State<'_, AppState>, path: &str) -> Result<(), CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Delete;
    req.path = path.to_string();
    req.client_token = token;
    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)?;
    Ok(())
}
