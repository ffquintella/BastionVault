//! Tauri commands for the Identity Provider admin page (T52 Phase 7; routes
//! in `docs/api.md`). The engine answers `/v2` only, from the root namespace
//! only: every path is an absolute `/v2/idp/...` (sent verbatim by the remote
//! backend; the embedded one reads the version from it, see `backend.rs`) and
//! goes through [`make_request_root`]. Paths come from fixed templates (the
//! enums are the route allowlist; a caller's name is one validated segment).
//! One-time secrets and write-only keys pass through as data, never logged.

use bv_client::{JsonResponse, Operation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use super::make_request_root;
use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

/// Mount path of the engine, as `docs/api.md` documents it.
const MOUNT: &str = "idp";
/// The engine answers `v2` only; see the module docs.
const PREFIX: &str = "/v2/idp";
/// Longest name accepted as a path segment. The engine's own limits are
/// tighter; this only keeps an absurd value out of a request line.
const MAX_SEGMENT_LEN: usize = 256;

/// Data plus the warnings the engine attached (cleartext transports, a
/// secret shown once, listeners reconciled asynchronously). The page shows
/// the warnings; dropping them would hide exactly the notices that matter.
#[derive(Serialize, Default)]
pub struct IdpResponse {
    pub data: Value,
    pub warnings: Vec<String>,
}

impl From<Option<JsonResponse>> for IdpResponse {
    fn from(resp: Option<JsonResponse>) -> Self {
        match resp {
            Some(r) => IdpResponse { data: r.data.map(Value::Object).unwrap_or(Value::Null), warnings: r.warnings },
            None => IdpResponse::default(),
        }
    }
}

/// A `LIST` answer: the keys and the engine's per-key summary.
#[derive(Serialize, Default)]
pub struct IdpList {
    pub keys: Vec<String>,
    pub key_info: Map<String, Value>,
}

/// The settings documents, one per provider plus the allocator's.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdpSettings {
    Core,
    Ssh,
    Radius,
    Oidc,
    Saml,
    Ldap,
}

impl IdpSettings {
    fn path(self) -> &'static str {
        match self {
            IdpSettings::Core => "config",
            IdpSettings::Ssh => "ssh/config",
            IdpSettings::Radius => "radius/config",
            IdpSettings::Oidc => "oidc/config",
            IdpSettings::Saml => "saml/config",
            IdpSettings::Ldap => "ldap/config",
        }
    }
}

/// The named records the page lists, reads, writes and deletes.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdpKind {
    Identity,
    Environment,
    RadiusClient,
    RadiusProfile,
    OidcClient,
    SamlSp,
    LdapClient,
}

impl IdpKind {
    fn collection(self) -> &'static str {
        match self {
            IdpKind::Identity => "identities",
            IdpKind::Environment => "environments",
            IdpKind::RadiusClient => "radius/clients",
            IdpKind::RadiusProfile => "radius/profiles",
            IdpKind::OidcClient => "oidc/clients",
            IdpKind::SamlSp => "saml/sps",
            IdpKind::LdapClient => "ldap/clients",
        }
    }

    /// `DELETE` on an identity is the `removed` transition. The page reaches
    /// it only through [`idp_set_identity_state`], whose confirmation names
    /// the identity and the consequence, so the generic delete refuses it.
    fn deletable(self) -> bool {
        !matches!(self, IdpKind::Identity)
    }
}

/// The two signing key rings with a rotate route.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdpKeyRing {
    Oidc,
    Saml,
}

impl IdpKeyRing {
    fn path(self) -> &'static str {
        match self {
            IdpKeyRing::Oidc => "oidc/keys",
            IdpKeyRing::Saml => "saml/keys",
        }
    }
}

/// Lifecycle targets of `identities/{entity_id}/state`.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdpIdentityState {
    Active,
    Disabled,
    Removed,
}

impl IdpIdentityState {
    fn as_str(self) -> &'static str {
        match self {
            IdpIdentityState::Active => "active",
            IdpIdentityState::Disabled => "disabled",
            IdpIdentityState::Removed => "removed",
        }
    }
}

/// One caller-supplied path segment. The engine validates names itself; this
/// only guarantees the value stays inside the segment the template gives it
/// (no `/`, no `.`/`..`, nothing a URL or the router would reinterpret).
fn segment(what: &str, value: &str) -> Result<String, CommandError> {
    let bad = value.is_empty()
        || value.len() > MAX_SEGMENT_LEN
        || value == "."
        || value == ".."
        || value.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#' | '%'));
    if bad {
        return Err(format!("invalid {what}: expected a single name without '/', '?', '#', '%' or whitespace").into());
    }
    Ok(value.to_string())
}

fn path(rest: &str) -> String {
    format!("{PREFIX}/{rest}")
}

fn opt_string(body: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
        body.insert(key.into(), Value::String(v));
    }
}

async fn call(
    state: &State<'_, AppState>,
    operation: Operation,
    rest: &str,
    body: Option<Map<String, Value>>,
) -> CmdResult<IdpResponse> {
    Ok(make_request_root(state, operation, path(rest), body).await?.into())
}

/// Mount the engine at `idp/` in the root namespace (`sys/mounts/idp`,
/// `type = idp`). The page offers it when the probe finds no mount.
#[tauri::command]
pub async fn idp_enable_mount(state: State<'_, AppState>) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("type".into(), Value::String(MOUNT.into()));
    body.insert("description".into(), Value::String("Identity provider (workforce identities)".into()));
    make_request_root(&state, Operation::Write, format!("sys/mounts/{MOUNT}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn idp_read_settings(state: State<'_, AppState>, settings: IdpSettings) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, settings.path(), None).await
}

/// Write a settings document. The engine applies only the fields present, so
/// the page sends what changed and a write-only key only when one was typed.
#[tauri::command]
pub async fn idp_write_settings(
    state: State<'_, AppState>,
    settings: IdpSettings,
    body: Map<String, Value>,
) -> CmdResult<IdpResponse> {
    call(&state, Operation::Write, settings.path(), Some(body)).await
}

#[tauri::command]
pub async fn idp_list(state: State<'_, AppState>, kind: IdpKind) -> CmdResult<IdpList> {
    let resp = make_request_root(&state, Operation::List, path(kind.collection()), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let keys = data
        .get("keys")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let key_info = match data.get("key_info") {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    Ok(IdpList { keys, key_info })
}

#[tauri::command]
pub async fn idp_read(state: State<'_, AppState>, kind: IdpKind, name: String) -> CmdResult<IdpResponse> {
    let name = segment("name", &name)?;
    call(&state, Operation::Read, &format!("{}/{name}", kind.collection()), None).await
}

#[tauri::command]
pub async fn idp_write(
    state: State<'_, AppState>,
    kind: IdpKind,
    name: String,
    body: Map<String, Value>,
) -> CmdResult<IdpResponse> {
    let name = segment("name", &name)?;
    call(&state, Operation::Write, &format!("{}/{name}", kind.collection()), Some(body)).await
}

#[tauri::command]
pub async fn idp_delete(state: State<'_, AppState>, kind: IdpKind, name: String) -> CmdResult<IdpResponse> {
    if !kind.deletable() {
        return Err("an identity is removed through its state, not deleted".into());
    }
    let name = segment("name", &name)?;
    call(&state, Operation::Delete, &format!("{}/{name}", kind.collection()), None).await
}

/// `active -> disabled -> removed`, `disabled -> active`. The response
/// carries `revoked_certificates` and `deny_feed_version`.
#[tauri::command]
pub async fn idp_set_identity_state(
    state: State<'_, AppState>,
    entity_id: String,
    target: IdpIdentityState,
    reason: Option<String>,
) -> CmdResult<IdpResponse> {
    let entity_id = segment("entity id", &entity_id)?;
    let mut body = Map::new();
    body.insert("state".into(), Value::String(target.as_str().into()));
    opt_string(&mut body, "reason", reason);
    call(&state, Operation::Write, &format!("identities/{entity_id}/state"), Some(body)).await
}

#[tauri::command]
pub async fn idp_list_entitlements(state: State<'_, AppState>, entity_id: String) -> CmdResult<IdpResponse> {
    let entity_id = segment("entity id", &entity_id)?;
    call(&state, Operation::Read, &format!("entitlements/{entity_id}"), None).await
}

#[tauri::command]
pub async fn idp_write_entitlement(
    state: State<'_, AppState>,
    entity_id: String,
    environment: String,
    body: Map<String, Value>,
) -> CmdResult<IdpResponse> {
    let entity_id = segment("entity id", &entity_id)?;
    let environment = segment("environment", &environment)?;
    call(&state, Operation::Write, &format!("entitlements/{entity_id}/{environment}"), Some(body)).await
}

#[tauri::command]
pub async fn idp_revoke_entitlement(
    state: State<'_, AppState>,
    entity_id: String,
    environment: String,
) -> CmdResult<IdpResponse> {
    let entity_id = segment("entity id", &entity_id)?;
    let environment = segment("environment", &environment)?;
    call(&state, Operation::Delete, &format!("entitlements/{entity_id}/{environment}"), None).await
}

/// The public half of a key ring: kid, state, certificate. Never a private key.
#[tauri::command]
pub async fn idp_read_keys(state: State<'_, AppState>, ring: IdpKeyRing) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, ring.path(), None).await
}

#[tauri::command]
pub async fn idp_rotate_keys(
    state: State<'_, AppState>,
    ring: IdpKeyRing,
    overlap: Option<String>,
) -> CmdResult<IdpResponse> {
    let mut body = Map::new();
    opt_string(&mut body, "overlap", overlap);
    call(&state, Operation::Write, &format!("{}/rotate", ring.path()), Some(body)).await
}

#[tauri::command]
pub async fn idp_ssh_krl(state: State<'_, AppState>) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, "ssh/krl", None).await
}

#[tauri::command]
pub async fn idp_deny_feed(state: State<'_, AppState>) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, "deny-feed", None).await
}

/// The deny feed's verification key. The engine never returns the signing
/// half, and there is no route that would.
#[tauri::command]
pub async fn idp_deny_feed_key(state: State<'_, AppState>) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, "deny-feed/key", None).await
}

#[tauri::command]
pub async fn idp_saml_metadata(state: State<'_, AppState>) -> CmdResult<IdpResponse> {
    call(&state, Operation::Read, "saml/metadata", None).await
}

/// Self-service: signs the caller's own public key with the signed-in
/// session's token. A token without an entity (the root token) is refused
/// by the engine with 403; that refusal is returned as is.
#[tauri::command]
pub async fn idp_ssh_sign(
    state: State<'_, AppState>,
    environment: String,
    public_key: String,
    ttl: Option<String>,
    roles: Option<Vec<String>>,
) -> CmdResult<IdpResponse> {
    let environment = segment("environment", &environment)?;
    let mut body = Map::new();
    body.insert("public_key".into(), Value::String(public_key));
    opt_string(&mut body, "ttl", ttl);
    if let Some(roles) = roles.filter(|r| !r.is_empty()) {
        body.insert("roles".into(), Value::from(roles));
    }
    call(&state, Operation::Write, &format!("ssh/sign/{environment}"), Some(body)).await
}

/// Self-service: a one-time RADIUS passcode for the caller's own identity.
#[tauri::command]
pub async fn idp_radius_passcode(
    state: State<'_, AppState>,
    environment: String,
    ttl: Option<String>,
    roles: Option<Vec<String>>,
) -> CmdResult<IdpResponse> {
    let environment = segment("environment", &environment)?;
    let mut body = Map::new();
    opt_string(&mut body, "ttl", ttl);
    if let Some(roles) = roles.filter(|r| !r.is_empty()) {
        body.insert("roles".into(), Value::from(roles));
    }
    call(&state, Operation::Write, &format!("radius/passcode/{environment}"), Some(body)).await
}

/// Self-service: a one-time LDAP bind passcode for the caller's own identity.
#[tauri::command]
pub async fn idp_ldap_passcode(
    state: State<'_, AppState>,
    environment: String,
    ttl: Option<String>,
) -> CmdResult<IdpResponse> {
    let environment = segment("environment", &environment)?;
    let mut body = Map::new();
    opt_string(&mut body, "ttl", ttl);
    call(&state, Operation::Write, &format!("ldap/passcode/{environment}"), Some(body)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_is_an_absolute_v2_idp_path() {
        for s in [
            IdpSettings::Core,
            IdpSettings::Ssh,
            IdpSettings::Radius,
            IdpSettings::Oidc,
            IdpSettings::Saml,
            IdpSettings::Ldap,
        ] {
            assert!(path(s.path()).starts_with("/v2/idp/"), "{s:?}");
        }
        assert_eq!(path(IdpKind::RadiusProfile.collection()), "/v2/idp/radius/profiles");
        assert_eq!(path(&format!("{}/rotate", IdpKeyRing::Saml.path())), "/v2/idp/saml/keys/rotate");
    }

    #[test]
    fn a_name_stays_one_segment() {
        assert_eq!(segment("name", "fw-01").unwrap(), "fw-01");
        assert_eq!(segment("name", "0b8c3f2e-6a1d-4c7e-9f00-1234567890ab").unwrap().len(), 36);
        for bad in ["", ".", "..", "a/b", "../config", "a?b=c", "a#b", "a%2fb", "a b", "a\nb", "a\\b"] {
            assert!(segment("name", bad).is_err(), "{bad:?} must be refused");
        }
        assert!(segment("name", &"a".repeat(MAX_SEGMENT_LEN + 1)).is_err());
    }

    #[test]
    fn identities_are_not_deleted_through_the_generic_route() {
        assert!(!IdpKind::Identity.deletable());
        assert!(IdpKind::Environment.deletable());
        assert!(IdpKind::LdapClient.deletable());
    }

    #[test]
    fn unknown_kinds_and_states_do_not_deserialize() {
        assert!(serde_json::from_str::<IdpKind>("\"radius_client\"").is_ok());
        assert!(serde_json::from_str::<IdpKind>("\"sys\"").is_err());
        assert!(serde_json::from_str::<IdpIdentityState>("\"removed\"").is_ok());
        assert!(serde_json::from_str::<IdpIdentityState>("\"deleted\"").is_err());
        assert!(serde_json::from_str::<IdpSettings>("\"deny_feed\"").is_err());
    }
}
