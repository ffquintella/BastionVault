//! Launch sessions (features/identity-provider.md, T545): a single-use OP
//! login a host mints with the operator's vault token and plants as a
//! cookie in a browser it controls, so the browser-facing authorization
//! endpoint can authenticate a redirect from a relying party without a
//! vault token. Gated at mint (provider `oidc-launch-session`) and again
//! when the code is minted (`oidc-authorize`).

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{
    bounded, check_request, enabled, events, internal, issue_code, lookup_client, refuse_with,
    store::{LaunchSession, OidcConfig},
    AuthorizeRequest, Authorized, OidcDeps, Refusal, AUTHORIZE_PROVIDER,
};
use crate::{
    entitlement::gate::IssueRequest,
    logical::Request,
    provider::federation::{random_id, sha256_hex},
};

/// The provider name the gate records when a launch session is minted.
pub const LAUNCH_PROVIDER: &str = "oidc-launch-session";
/// The cookie the host plants. `__Host-`: the browser keeps it only if it
/// is `Secure`, host-only (no `Domain`) and `Path=/`.
pub const COOKIE_NAME: &str = "__Host-bv-idp-launch";
pub const COOKIE_PATH: &str = "/";
/// `Lax`: sent on the relying party's top-level redirect to the OP, never
/// on a cross-site subrequest or POST. `Strict` would drop it on exactly
/// that redirect.
pub const COOKIE_SAME_SITE: &str = "Lax";
pub const DEFAULT_TTL_SECS: u64 = 120;
pub const MIN_TTL_SECS: u64 = 10;
pub const MAX_TTL_SECS: u64 = 300;
/// A launch id is base64url: at least 128 bits, at most 128 characters.
const MIN_LAUNCH_ID_LEN: usize = 22;
const MAX_LAUNCH_ID_LEN: usize = 128;

const STAGE_MINT: &str = "launch-session";
const STAGE_CONSUME: &str = "launch-session-authorize";

#[derive(Default)]
pub struct LaunchRequest {
    pub client_id: String,
    /// The host's launch id; sensitive (it names an in-flight launch), so
    /// only its SHA-256 is stored or audited.
    pub launch_id: Zeroizing<String>,
    /// A subset of the entitled roles; `None` means all of them.
    pub roles: Option<Vec<String>>,
    pub ttl_secs: Option<u64>,
}

pub struct LaunchIssued {
    /// The cookie value, returned once.
    pub secret: Zeroizing<String>,
    pub session_id: String,
    pub client_id: String,
    pub environment: String,
    pub roles: Vec<String>,
    pub launch_id_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub max_age_secs: u64,
    /// Where the relying party sends the browser (discovery's value).
    pub authorization_endpoint: String,
    /// The origin the cookie must be planted for: the endpoint's.
    pub cookie_origin: String,
}

/// The browser's authorization request plus the cookie it carried. Any
/// `roles` in `authorize` is ignored: the session's roles are asked for.
#[derive(Default)]
pub struct BrowserAuthorizeRequest {
    pub launch_session: Zeroizing<String>,
    pub authorize: AuthorizeRequest,
}

fn valid_launch_id(id: &str) -> bool {
    (MIN_LAUNCH_ID_LEN..=MAX_LAUNCH_ID_LEN).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn session_fields(s: &LaunchSession) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("session_id".into(), s.session_id.clone().into());
    m.insert("launch_id_sha256".into(), s.launch_id_sha256.clone().into());
    m
}

// ─── Mint ───────────────────────────────────────────────────────────

/// Mint a launch session for the caller's own identity and one client.
/// Checks run in order: launch id, lifetime, client, then the gate;
/// nothing is stored before the gate allows.
#[maybe_async::maybe_async]
pub(crate) async fn mint(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &LaunchRequest,
    entity_id: &str,
    caller_namespace: &str,
    http: Option<&Request>,
    now: DateTime<Utc>,
) -> Result<LaunchIssued, Refusal> {
    let mut extra = Map::new();
    match mint_inner(deps, cfg, ask, entity_id, caller_namespace, http, now, &mut extra).await {
        Ok(ok) => Ok(ok),
        Err(r) => Err(refuse_with(deps, STAGE_MINT, r, &ask.client_id, Some(entity_id), extra, http).await),
    }
}

// The eighth argument is the refusal's audit context, filled in as checks pass.
#[allow(clippy::too_many_arguments)]
#[maybe_async::maybe_async]
async fn mint_inner(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &LaunchRequest,
    entity_id: &str,
    caller_namespace: &str,
    http: Option<&Request>,
    now: DateTime<Utc>,
    extra: &mut Map<String, Value>,
) -> Result<LaunchIssued, Refusal> {
    let cfg = enabled(cfg)?;
    if !valid_launch_id(&ask.launch_id) {
        return Err(Refusal::InvalidRequest("malformed_launch_id"));
    }
    let launch_id_sha256 = sha256_hex(ask.launch_id.as_bytes());
    extra.insert("launch_id_sha256".into(), launch_id_sha256.clone().into());
    let ttl_secs = ask.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
        return Err(Refusal::InvalidRequest("invalid_ttl"));
    }
    let client = lookup_client(deps.store, &ask.client_id).await?;
    let authorization_endpoint = cfg.authorization_endpoint();
    let cookie_origin = url::Url::parse(&authorization_endpoint)
        .map(|u| u.origin().ascii_serialization())
        .map_err(|_| Refusal::Internal)?;

    let gate_ask = IssueRequest {
        entity_id: entity_id.to_string(),
        environment: client.environment.clone(),
        roles: ask.roles.clone(),
        caller_namespace: caller_namespace.to_string(),
        provider: LAUNCH_PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&gate_ask, http).await.map_err(|d| Refusal::Denied(d.reason))?;

    let rec = LaunchSession {
        version: crate::posix::model::RECORD_VERSION,
        session_id: random_id(),
        client_id: client.client_id.clone(),
        entity_id: grant.entity_id.clone(),
        environment: grant.environment.clone(),
        roles: grant.roles.clone(),
        launch_id_sha256,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(i64::try_from(ttl_secs).unwrap_or(0)),
    };
    let secret = deps.store.mint_launch_session(&rec, now).await.map_err(|e| internal("launch session", &e))?;
    *extra = session_fields(&rec);

    let mut fields = session_fields(&rec);
    fields.insert("decision".into(), "mint".into());
    fields.insert("provider".into(), LAUNCH_PROVIDER.into());
    fields.insert("client_id".into(), rec.client_id.clone().into());
    fields.insert("entity_id".into(), rec.entity_id.clone().into());
    fields.insert("environment".into(), rec.environment.clone().into());
    fields.insert("roles".into(), Value::from(rec.roles.clone()));
    fields.insert("expires_at".into(), rec.expires_at.timestamp().into());
    // A login credential nobody can attribute is not returned.
    if let Err(e) = deps.audit.record(events::LAUNCH_SESSION, fields, http).await {
        log::error!(target: "idp", "{}: audit refused the event, refusing: {e}", events::LAUNCH_SESSION);
        return Err(Refusal::Internal);
    }
    Ok(LaunchIssued {
        secret,
        session_id: rec.session_id,
        client_id: rec.client_id,
        environment: rec.environment,
        roles: rec.roles,
        launch_id_sha256: rec.launch_id_sha256,
        expires_at: rec.expires_at,
        max_age_secs: ttl_secs,
        authorization_endpoint,
        cookie_origin,
    })
}

// ─── Browser authorization ──────────────────────────────────────────

/// Consume the browser's launch session and mint a code for its identity.
/// The session is taken first, so it is gone whatever happens next; then
/// expiry, client and environment binding, the same request checks as
/// `authorize`, and the gate. Nothing is ever redirected on a refusal.
#[maybe_async::maybe_async]
pub(crate) async fn authorize(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &BrowserAuthorizeRequest,
    http: Option<&Request>,
    now: DateTime<Utc>,
) -> Result<Authorized, Refusal> {
    let mut seen: Option<LaunchSession> = None;
    match authorize_inner(deps, cfg, ask, http, now, &mut seen).await {
        Ok(ok) => Ok(ok),
        Err(r) => {
            let extra = seen.as_ref().map(session_fields).unwrap_or_default();
            let entity = seen.as_ref().map(|s| s.entity_id.as_str());
            Err(refuse_with(deps, STAGE_CONSUME, r, &ask.authorize.client_id, entity, extra, http).await)
        }
    }
}

#[maybe_async::maybe_async]
async fn authorize_inner(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &BrowserAuthorizeRequest,
    http: Option<&Request>,
    now: DateTime<Utc>,
    seen: &mut Option<LaunchSession>,
) -> Result<Authorized, Refusal> {
    let cfg = enabled(cfg)?;
    if ask.launch_session.is_empty() {
        return Err(Refusal::LoginRequired("launch_session_missing"));
    }
    let session = match deps.store.take_launch_session(&ask.launch_session).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Refusal::LoginRequired("unknown_or_used_launch_session")),
        Err(e) => return Err(internal("launch session", &e)),
    };
    *seen = Some(session.clone());
    if session.expires_at <= now {
        return Err(Refusal::LoginRequired("launch_session_expired"));
    }
    let client = lookup_client(deps.store, &ask.authorize.client_id).await?;
    // A client deleted and re-created under the same id in another
    // environment is a different relying party.
    if session.client_id != client.client_id || session.environment != client.environment {
        return Err(Refusal::LoginRequired("launch_session_client_mismatch"));
    }
    let checked = check_request(&client, &ask.authorize)?;

    // Asked again: a disable, a removal or a revoked role since the mint
    // denies here. Clients are root-administered, like the idp mount.
    let gate_ask = IssueRequest {
        entity_id: session.entity_id.clone(),
        environment: session.environment.clone(),
        roles: Some(session.roles.clone()),
        caller_namespace: String::new(),
        provider: AUTHORIZE_PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&gate_ask, http).await.map_err(|d| Refusal::Denied(d.reason))?;
    let ok = issue_code(deps, cfg, &client, &ask.authorize, checked, grant, now).await?;

    let mut fields = session_fields(&session);
    fields.insert("decision".into(), "consume".into());
    fields.insert("provider".into(), AUTHORIZE_PROVIDER.into());
    fields.insert("client_id".into(), client.client_id.clone().into());
    fields.insert("entity_id".into(), session.entity_id.clone().into());
    fields.insert("environment".into(), ok.environment.clone().into());
    fields.insert("roles".into(), Value::from(ok.roles.clone()));
    fields.insert("redirect_uri".into(), bounded(&ask.authorize.redirect_uri).into());
    fields.insert("code_expires_at".into(), ok.expires_at.timestamp().into());
    // A code nobody can attribute is not handed to the browser.
    if let Err(e) = deps.audit.record(events::LAUNCH_SESSION_CONSUMED, fields, http).await {
        log::error!(target: "idp", "{}: audit refused the event, refusing: {e}", events::LAUNCH_SESSION_CONSUMED);
        return Err(Refusal::Internal);
    }
    Ok(ok)
}
