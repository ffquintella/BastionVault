//! SSO provider administration — the Settings → Single Sign-On card
//! drives these.
//!
//! Each command bundles the N vault writes needed to stand up a
//! federation provider end-to-end (mount + config + default role)
//! so the admin never has to drop to the raw `sys/auth/<mount>` /
//! `auth/<mount>/config` / `auth/<mount>/role/<name>` surface.
//! Deleting a provider disables the auth mount — the config + role
//! storage is scoped to that mount and gets torn down with it.
//!
//! Two provider kinds are supported today:
//!
//!   * `oidc` — OpenID Connect via `src/modules/credential/oidc/`.
//!     Carries discovery URL, client id / secret, scopes, redirect URIs.
//!   * `saml` — SAML 2.0 via `src/modules/credential/saml/`. Carries
//!     IdP metadata URL / inline XML / SSO URL + cert, SP entity id,
//!     ACS URL. Admin-supplied PEM cert is redacted on read.
//!
//! Per-kind config fields are disjoint enough that rather than
//! pretending they share a shape, `SsoAdminInput` carries the common
//! fields (mount, display name, default role) + a tagged `config`
//! union for the provider-specific fields.
//!
//! Secrets (OIDC `client_secret`, SAML `idp_cert`, SAML
//! `idp_metadata_xml`) pass through to the respective backend's
//! `write_config` which redacts on read; the admin UI only surfaces
//! boolean `_set` hints.

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, VaultMode};

// ── Shared shapes ──────────────────────────────────────────────────

/// One row in the admin list. `config` is a tagged union so the
/// frontend can render the right form / row summary without type
/// gymnastics. Kind is always one of the `SSO_KINDS` registered in
/// the sys backend (currently `"oidc"` / `"saml"`).
#[derive(Serialize, Debug, Clone)]
pub struct SsoAdminProvider {
    pub mount: String,
    pub display_name: String,
    pub kind: String,
    pub config: SsoProviderConfig,
    /// Role projection. `None` when the mount's `default_role`
    /// points at a role that was deleted out-of-band.
    pub role: Option<SsoAdminRole>,
    pub default_role: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SsoProviderConfig {
    Oidc(OidcAdminConfig),
    Saml(SamlAdminConfig),
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct OidcAdminConfig {
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret_set: bool,
    pub scopes: Vec<String>,
    pub allowed_redirect_uris: Vec<String>,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct SamlAdminConfig {
    pub entity_id: String,
    pub acs_url: String,
    pub idp_sso_url: String,
    pub idp_slo_url: String,
    pub idp_metadata_url: String,
    pub idp_metadata_xml_set: bool,
    pub idp_cert_set: bool,
    pub allowed_redirect_uris: Vec<String>,
}

/// Tagged-union role shape. OIDC roles key on claim names; SAML
/// roles key on attribute / subject matching.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SsoAdminRole {
    Oidc(OidcAdminRole),
    Saml(SamlAdminRole),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OidcAdminRole {
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SamlAdminRole {
    pub name: String,
    pub bound_subjects: Vec<String>,
    pub bound_subjects_type: String,
    /// Stored as raw JSON (`{"department":["eng","sre"]}`).
    pub bound_attributes_json: String,
    /// Stored as raw JSON mapping SAML attribute name → vault
    /// metadata key (`{"email":"mail"}`).
    pub attribute_mappings_json: String,
    pub groups_attribute: String,
    pub policies: Vec<String>,
    pub token_ttl_secs: u64,
}

/// Input payload for create + update. The `config` and `role` fields
/// are tagged unions; the caller picks the variant matching the
/// desired `kind`. Server-side validation rejects a mismatched pair.
#[derive(Deserialize, Debug)]
pub struct SsoAdminInput {
    pub mount: String,
    pub display_name: String,
    pub kind: String,
    pub config: SsoAdminInputConfig,
    pub default_role: String,
    pub role: SsoAdminRole,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SsoAdminInputConfig {
    Oidc(OidcAdminInputConfig),
    Saml(SamlAdminInputConfig),
}

#[derive(Deserialize, Debug, Default)]
pub struct OidcAdminInputConfig {
    pub discovery_url: String,
    pub client_id: String,
    /// Empty string means "don't change" on update. On create, empty
    /// is accepted (PKCE-only public client).
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub allowed_redirect_uris: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct SamlAdminInputConfig {
    pub entity_id: String,
    pub acs_url: String,
    pub idp_sso_url: String,
    pub idp_slo_url: String,
    pub idp_metadata_url: String,
    /// Empty on update means "don't change". On create, accepted
    /// when a metadata URL OR an SSO URL + cert pair is provided.
    pub idp_metadata_xml: String,
    /// Empty on update means "don't change".
    pub idp_cert: String,
    pub allowed_redirect_uris: Vec<String>,
}

// ── Callback-URL hints (shared) ────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
pub struct SsoCallbackHints {
    pub mode: String,
    pub suggested: Vec<String>,
    pub notes: Vec<String>,
}

// ── Commands ───────────────────────────────────────────────────────

#[tauri::command]
pub async fn sso_admin_list(state: State<'_, AppState>) -> CmdResult<Vec<SsoAdminProvider>> {
    let mounts = load_sso_mounts(&state).await?;
    let mut out = Vec::with_capacity(mounts.len());
    for (mount, kind, display_name) in mounts {
        let detail = load_provider_detail(&state, &mount, &kind, &display_name).await?;
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
    let mounts = load_sso_mounts(&state).await?;
    let found = mounts
        .iter()
        .find(|(m, _, _)| *m == mount)
        .cloned()
        .ok_or_else(|| format!("sso: mount `{mount}` not found"))?;
    load_provider_detail(&state, &found.0, &found.1, &found.2).await
}

#[tauri::command]
pub async fn sso_admin_create(
    state: State<'_, AppState>,
    input: SsoAdminInput,
) -> CmdResult<()> {
    validate_input(&input)?;

    // 1. Mount the auth backend with the operator's display name as
    //    the mount description. The unauth list-providers endpoint
    //    surfaces this as the login button label.
    let mut mount_body = Map::new();
    mount_body.insert("type".into(), Value::String(input.kind.clone()));
    mount_body.insert(
        "description".into(),
        Value::String(input.display_name.clone()),
    );
    sys_write(&state, &format!("sys/auth/{}", input.mount), mount_body).await?;

    // 2. Write provider config. On create we allow clearing secrets
    //    (empty-string = empty secret).
    write_provider_config(&state, &input, /* allow_secret_clear = */ true).await?;

    // 3. Write the default role so login has something to resolve.
    write_provider_role(&state, &input).await?;

    Ok(())
}

#[tauri::command]
pub async fn sso_admin_update(
    state: State<'_, AppState>,
    input: SsoAdminInput,
) -> CmdResult<()> {
    validate_input(&input)?;

    // Refresh the mount description if the display name changed.
    // There's no direct remount-description API without rebuilding
    // the mount; re-issuing the mount write is our idempotent path.
    // Tolerate errors — the buttons will still render from the
    // latest description on next read.
    let mounts = load_sso_mounts(&state).await?;
    let current_desc = mounts
        .iter()
        .find(|(m, _, _)| *m == input.mount)
        .map(|(_, _, d)| d.clone())
        .unwrap_or_default();
    if current_desc != input.display_name {
        let mut mount_body = Map::new();
        mount_body.insert("type".into(), Value::String(input.kind.clone()));
        mount_body.insert(
            "description".into(),
            Value::String(input.display_name.clone()),
        );
        let _ = sys_write(&state, &format!("sys/auth/{}", input.mount), mount_body).await;
    }

    // On update, empty secret strings mean "leave existing value
    // intact" — the backend's write_config merges onto the existing
    // record when the field is absent, so we skip the field.
    write_provider_config(&state, &input, /* allow_secret_clear = */ false).await?;
    write_provider_role(&state, &input).await?;

    Ok(())
}

#[tauri::command]
pub async fn sso_admin_delete(state: State<'_, AppState>, mount: String) -> CmdResult<()> {
    sys_delete(&state, &format!("sys/auth/{mount}")).await?;
    Ok(())
}

/// Kind-aware redirect-URL hints. OIDC desktop binds a random
/// loopback port per login; SAML assertions can only POST back to
/// the configured ACS URL, so for SAML the stable URL is the
/// `<vault>/v1/auth/<mount>/callback` form in both modes.
#[tauri::command]
pub async fn sso_admin_callback_hints(
    state: State<'_, AppState>,
    mount: String,
    kind: String,
) -> CmdResult<SsoCallbackHints> {
    let mode = state.mode.lock().await.clone();
    let remote_base = match &mode {
        VaultMode::Remote => state
            .remote_profile
            .lock()
            .await
            .as_ref()
            .map(|p| p.address.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://<vault-server>".to_string()),
        VaultMode::Embedded => "https://<vault-server>".to_string(),
    };

    match (kind.as_str(), &mode) {
        ("oidc", VaultMode::Embedded) => Ok(SsoCallbackHints {
            mode: "embedded".into(),
            suggested: vec!["http://127.0.0.1/callback".into()],
            notes: vec![
                "Desktop OIDC logins bind a random loopback port each run — register `http://127.0.0.1` (any port) with your IdP as a native-app / loopback redirect URI (RFC 8252).".into(),
                "Azure AD calls this a \"Mobile and desktop applications\" redirect; Okta calls it \"Native app\"; Google Cloud lists it under \"Desktop app\".".into(),
            ],
        }),
        ("oidc", VaultMode::Remote) => {
            let stable = format!("{remote_base}/v1/auth/{mount}/callback");
            Ok(SsoCallbackHints {
                mode: "remote".into(),
                suggested: vec![stable],
                notes: vec![
                    "Register the URL above with your IdP. The vault exposes the callback at the v1 path for Vault-API compatibility.".into(),
                ],
            })
        }
        ("saml", _) => {
            // SAML's Assertion Consumer Service URL has to be stable
            // — the IdP POSTs signed assertions there. Desktop mode
            // has no useful alternative because the flow terminates
            // server-side, not at a loopback listener.
            let stable = format!("{remote_base}/v1/auth/{mount}/callback");
            let mut notes = vec![
                "SAML IdPs POST the signed assertion to a fixed Assertion Consumer Service (ACS) URL. The value above is what you paste into the IdP's SP configuration AND into the `acs_url` field here.".into(),
            ];
            if matches!(mode, VaultMode::Embedded) {
                notes.push(
                    "This is an embedded (desktop) vault; SAML typically requires a publicly-reachable ACS URL. For production SAML use a remote BastionVault deployment.".into(),
                );
            }
            Ok(SsoCallbackHints {
                mode: if matches!(mode, VaultMode::Embedded) {
                    "embedded"
                } else {
                    "remote"
                }
                .into(),
                suggested: vec![stable],
                notes,
            })
        }
        (other, _) => Err(format!("sso: unknown kind `{other}`").into()),
    }
}

// ── helpers ────────────────────────────────────────────────────────

async fn load_sso_mounts(
    state: &State<'_, AppState>,
) -> Result<Vec<(String, String, String)>, CommandError> {
    // Returns `(mount, kind, description)` tuples for every mounted
    // SSO-capable auth backend.
    let data = sys_read(state, "sys/auth").await?;
    let mut out: Vec<(String, String, String)> = Vec::new();
    for (raw_path, v) in data.iter() {
        let kind = v
            .get("type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if kind != "oidc" && kind != "saml" {
            continue;
        }
        let mount = raw_path.trim_end_matches('/').to_string();
        let description = v
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        out.push((mount, kind, description));
    }
    Ok(out)
}

async fn load_provider_detail(
    state: &State<'_, AppState>,
    mount: &str,
    kind: &str,
    display_name: &str,
) -> Result<SsoAdminProvider, CommandError> {
    match kind {
        "oidc" => load_oidc_detail(state, mount, display_name).await,
        "saml" => load_saml_detail(state, mount, display_name).await,
        other => Err(format!("sso: unsupported kind `{other}`").into()),
    }
}

async fn load_oidc_detail(
    state: &State<'_, AppState>,
    mount: &str,
    display_name: &str,
) -> Result<SsoAdminProvider, CommandError> {
    let cfg_data = sys_read(state, &format!("auth/{mount}/config"))
        .await
        .unwrap_or_default();
    let config = OidcAdminConfig {
        discovery_url: str_field(&cfg_data, "oidc_discovery_url"),
        client_id: str_field(&cfg_data, "oidc_client_id"),
        client_secret_set: cfg_data
            .get("oidc_client_secret_set")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        scopes: string_list(&cfg_data, "oidc_scopes"),
        allowed_redirect_uris: string_list(&cfg_data, "allowed_redirect_uris"),
    };
    let default_role = str_field(&cfg_data, "default_role");
    let role = if !default_role.is_empty() {
        match sys_read(state, &format!("auth/{mount}/role/{default_role}")).await {
            Ok(d) if !d.is_empty() => Some(SsoAdminRole::Oidc(oidc_role_from_data(
                &default_role,
                &d,
            ))),
            _ => None,
        }
    } else {
        None
    };
    Ok(SsoAdminProvider {
        mount: mount.to_string(),
        display_name: display_name.to_string(),
        kind: "oidc".into(),
        config: SsoProviderConfig::Oidc(config),
        default_role,
        role,
    })
}

async fn load_saml_detail(
    state: &State<'_, AppState>,
    mount: &str,
    display_name: &str,
) -> Result<SsoAdminProvider, CommandError> {
    let cfg_data = sys_read(state, &format!("auth/{mount}/config"))
        .await
        .unwrap_or_default();
    let config = SamlAdminConfig {
        entity_id: str_field(&cfg_data, "entity_id"),
        acs_url: str_field(&cfg_data, "acs_url"),
        idp_sso_url: str_field(&cfg_data, "idp_sso_url"),
        idp_slo_url: str_field(&cfg_data, "idp_slo_url"),
        idp_metadata_url: str_field(&cfg_data, "idp_metadata_url"),
        idp_metadata_xml_set: cfg_data
            .get("idp_metadata_xml_set")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        idp_cert_set: cfg_data
            .get("idp_cert_set")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        allowed_redirect_uris: string_list(&cfg_data, "allowed_redirect_uris"),
    };
    let default_role = str_field(&cfg_data, "default_role");
    let role = if !default_role.is_empty() {
        match sys_read(state, &format!("auth/{mount}/role/{default_role}")).await {
            Ok(d) if !d.is_empty() => Some(SsoAdminRole::Saml(saml_role_from_data(
                &default_role,
                &d,
            ))),
            _ => None,
        }
    } else {
        None
    };
    Ok(SsoAdminProvider {
        mount: mount.to_string(),
        display_name: display_name.to_string(),
        kind: "saml".into(),
        config: SsoProviderConfig::Saml(config),
        default_role,
        role,
    })
}

fn validate_input(input: &SsoAdminInput) -> Result<(), CommandError> {
    if input.mount.trim().is_empty() {
        return Err("sso: mount path is required".into());
    }
    if input.display_name.trim().is_empty() {
        return Err("sso: display name is required (shown on the login button)".into());
    }
    if input.default_role.trim().is_empty() {
        return Err("sso: default role name is required".into());
    }
    // Kind must match the config + role variants.
    match (
        input.kind.as_str(),
        &input.config,
        &input.role,
    ) {
        ("oidc", SsoAdminInputConfig::Oidc(cfg), SsoAdminRole::Oidc(role)) => {
            if cfg.discovery_url.trim().is_empty() {
                return Err("sso: OIDC discovery URL is required".into());
            }
            if cfg.client_id.trim().is_empty() {
                return Err("sso: OIDC client ID is required".into());
            }
            if role.user_claim.trim().is_empty() {
                return Err("sso: OIDC role `user_claim` is required (e.g. `preferred_username`)".into());
            }
            if role.policies.is_empty() {
                return Err("sso: OIDC role must list at least one vault policy".into());
            }
            let bc = role.bound_claims_json.trim();
            if !bc.is_empty() {
                match serde_json::from_str::<Value>(bc) {
                    Ok(Value::Object(_)) => {}
                    Ok(_) => return Err(
                        "sso: OIDC `bound_claims` must be a JSON object (e.g. `{\"hd\":[\"example.com\"]}`)".into(),
                    ),
                    Err(e) => return Err(format!("sso: OIDC `bound_claims` invalid JSON: {e}").into()),
                }
            }
        }
        ("saml", SsoAdminInputConfig::Saml(cfg), SsoAdminRole::Saml(role)) => {
            if cfg.entity_id.trim().is_empty() {
                return Err("sso: SAML SP `entity_id` is required".into());
            }
            if cfg.acs_url.trim().is_empty() {
                return Err("sso: SAML `acs_url` (ACS URL) is required".into());
            }
            let has_metadata = !cfg.idp_metadata_url.trim().is_empty()
                || !cfg.idp_metadata_xml.trim().is_empty();
            let has_manual =
                !cfg.idp_sso_url.trim().is_empty() && !cfg.idp_cert.trim().is_empty();
            if !has_metadata && !has_manual {
                return Err(
                    "sso: SAML requires either `idp_metadata_url` / `idp_metadata_xml` OR both `idp_sso_url` and `idp_cert`".into(),
                );
            }
            if role.policies.is_empty() {
                return Err("sso: SAML role must list at least one vault policy".into());
            }
            for (field, raw) in [
                ("bound_attributes", role.bound_attributes_json.trim()),
                ("attribute_mappings", role.attribute_mappings_json.trim()),
            ] {
                if raw.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(raw) {
                    Ok(Value::Object(_)) => {}
                    Ok(_) => {
                        return Err(
                            format!("sso: SAML `{field}` must be a JSON object").into(),
                        )
                    }
                    Err(e) => {
                        return Err(format!("sso: SAML `{field}` invalid JSON: {e}").into())
                    }
                }
            }
        }
        (kind, _, _) => {
            return Err(format!(
                "sso: input kind `{kind}` does not match the supplied config/role shape"
            )
            .into())
        }
    }
    Ok(())
}

async fn write_provider_config(
    state: &State<'_, AppState>,
    input: &SsoAdminInput,
    allow_secret_clear: bool,
) -> Result<(), CommandError> {
    match &input.config {
        SsoAdminInputConfig::Oidc(cfg) => {
            let mut body = Map::new();
            body.insert(
                "oidc_discovery_url".into(),
                Value::String(cfg.discovery_url.clone()),
            );
            body.insert(
                "oidc_client_id".into(),
                Value::String(cfg.client_id.clone()),
            );
            // Empty-on-update preserves existing secret (backend
            // merges onto prior config). Empty-on-create persists
            // an empty secret (public / PKCE client).
            if allow_secret_clear || !cfg.client_secret.is_empty() {
                body.insert(
                    "oidc_client_secret".into(),
                    Value::String(cfg.client_secret.clone()),
                );
            }
            body.insert(
                "default_role".into(),
                Value::String(input.default_role.clone()),
            );
            if !cfg.allowed_redirect_uris.is_empty() {
                body.insert(
                    "allowed_redirect_uris".into(),
                    Value::Array(
                        cfg.allowed_redirect_uris
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                );
            }
            if !cfg.scopes.is_empty() {
                body.insert(
                    "oidc_scopes".into(),
                    Value::Array(cfg.scopes.iter().cloned().map(Value::String).collect()),
                );
            }
            sys_write(state, &format!("auth/{}/config", input.mount), body).await?;
        }
        SsoAdminInputConfig::Saml(cfg) => {
            let mut body = Map::new();
            body.insert("entity_id".into(), Value::String(cfg.entity_id.clone()));
            body.insert("acs_url".into(), Value::String(cfg.acs_url.clone()));
            if !cfg.idp_sso_url.is_empty() {
                body.insert(
                    "idp_sso_url".into(),
                    Value::String(cfg.idp_sso_url.clone()),
                );
            }
            if !cfg.idp_slo_url.is_empty() {
                body.insert(
                    "idp_slo_url".into(),
                    Value::String(cfg.idp_slo_url.clone()),
                );
            }
            if !cfg.idp_metadata_url.is_empty() {
                body.insert(
                    "idp_metadata_url".into(),
                    Value::String(cfg.idp_metadata_url.clone()),
                );
            }
            if allow_secret_clear || !cfg.idp_metadata_xml.is_empty() {
                body.insert(
                    "idp_metadata_xml".into(),
                    Value::String(cfg.idp_metadata_xml.clone()),
                );
            }
            if allow_secret_clear || !cfg.idp_cert.is_empty() {
                body.insert("idp_cert".into(), Value::String(cfg.idp_cert.clone()));
            }
            body.insert(
                "default_role".into(),
                Value::String(input.default_role.clone()),
            );
            if !cfg.allowed_redirect_uris.is_empty() {
                body.insert(
                    "allowed_redirect_uris".into(),
                    Value::Array(
                        cfg.allowed_redirect_uris
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                );
            }
            sys_write(state, &format!("auth/{}/config", input.mount), body).await?;
        }
    }
    Ok(())
}

async fn write_provider_role(
    state: &State<'_, AppState>,
    input: &SsoAdminInput,
) -> Result<(), CommandError> {
    match &input.role {
        SsoAdminRole::Oidc(role) => {
            let mut body = Map::new();
            body.insert("user_claim".into(), Value::String(role.user_claim.clone()));
            if !role.groups_claim.is_empty() {
                body.insert(
                    "groups_claim".into(),
                    Value::String(role.groups_claim.clone()),
                );
            }
            if !role.bound_audiences.is_empty() {
                body.insert(
                    "bound_audiences".into(),
                    Value::Array(
                        role.bound_audiences
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                );
            }
            if !role.bound_claims_json.trim().is_empty() {
                body.insert(
                    "bound_claims".into(),
                    Value::String(role.bound_claims_json.trim().to_string()),
                );
            }
            body.insert(
                "policies".into(),
                Value::Array(
                    role.policies.iter().cloned().map(Value::String).collect(),
                ),
            );
            if role.token_ttl_secs > 0 {
                body.insert(
                    "token_ttl_secs".into(),
                    Value::Number(role.token_ttl_secs.into()),
                );
            }
            sys_write(
                state,
                &format!("auth/{}/role/{}", input.mount, input.default_role),
                body,
            )
            .await?;
        }
        SsoAdminRole::Saml(role) => {
            let mut body = Map::new();
            if !role.bound_subjects.is_empty() {
                body.insert(
                    "bound_subjects".into(),
                    Value::Array(
                        role.bound_subjects
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                );
            }
            if !role.bound_subjects_type.is_empty() {
                body.insert(
                    "bound_subjects_type".into(),
                    Value::String(role.bound_subjects_type.clone()),
                );
            }
            if !role.bound_attributes_json.trim().is_empty() {
                body.insert(
                    "bound_attributes".into(),
                    Value::String(role.bound_attributes_json.trim().to_string()),
                );
            }
            if !role.attribute_mappings_json.trim().is_empty() {
                body.insert(
                    "attribute_mappings".into(),
                    Value::String(role.attribute_mappings_json.trim().to_string()),
                );
            }
            if !role.groups_attribute.is_empty() {
                body.insert(
                    "groups_attribute".into(),
                    Value::String(role.groups_attribute.clone()),
                );
            }
            body.insert(
                "policies".into(),
                Value::Array(
                    role.policies.iter().cloned().map(Value::String).collect(),
                ),
            );
            if role.token_ttl_secs > 0 {
                body.insert(
                    "token_ttl_secs".into(),
                    Value::Number(role.token_ttl_secs.into()),
                );
            }
            sys_write(
                state,
                &format!("auth/{}/role/{}", input.mount, input.default_role),
                body,
            )
            .await?;
        }
    }
    Ok(())
}

fn oidc_role_from_data(name: &str, data: &Map<String, Value>) -> OidcAdminRole {
    OidcAdminRole {
        name: name.to_string(),
        user_claim: str_field(data, "user_claim"),
        groups_claim: str_field(data, "groups_claim"),
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

fn saml_role_from_data(name: &str, data: &Map<String, Value>) -> SamlAdminRole {
    SamlAdminRole {
        name: name.to_string(),
        bound_subjects: string_list(data, "bound_subjects"),
        bound_subjects_type: str_field(data, "bound_subjects_type"),
        bound_attributes_json: data
            .get("bound_attributes")
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_default(),
        attribute_mappings_json: data
            .get("attribute_mappings")
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_default(),
        groups_attribute: str_field(data, "groups_attribute"),
        policies: string_list(data, "policies"),
        token_ttl_secs: data
            .get("token_ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    }
}

fn str_field(m: &Map<String, Value>, key: &str) -> String {
    m.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
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
