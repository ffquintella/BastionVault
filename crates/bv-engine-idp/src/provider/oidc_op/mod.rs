//! The OpenID Provider (features/identity-provider.md §3d): code flow with
//! PKCE S256 only, confidential clients (`client_secret_post`), RS256 ID
//! tokens; no implicit/hybrid flow, refresh token or userinfo. The vault
//! already knows the human: `authorize` is self-service with their token
//! (gate provider `oidc-authorize`); `token` is the RP's unauthenticated
//! call, gated again (provider `oidc`) so a disable in between denies.

pub mod jwt;
pub mod store;
#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    federation::{ct_eq, keys::KeyRing, random_id, sha256_hex, validate_echo, FederationAudit},
    Authorizer,
};
use crate::{
    entitlement::gate::{DenyReason, IssueDenied, IssueRequest, MAX_EVENT_ARG_LEN},
    errors::RvError,
    logical::Request,
};
use store::{AuthCode, OidcConfig, OidcStore};

/// The provider name the gate records when a code is minted.
pub const AUTHORIZE_PROVIDER: &str = "oidc-authorize";
/// The provider name the gate records when a token is issued.
pub const PROVIDER: &str = "oidc";

pub mod events {
    /// An ID token was issued (audit event; carries the `jti`, never the token).
    pub const TOKEN: &str = "idp.oidc.token";
    /// An authorize or token request was refused (audit event).
    pub const REFUSED: &str = "idp.oidc.refused";
}

pub const SCOPES_SUPPORTED: &[&str] = &["openid", "profile", "groups"];
pub const CLAIMS_SUPPORTED: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "azp",
    "exp",
    "iat",
    "jti",
    "nonce",
    "preferred_username",
    "name",
    "uid",
    "gid",
    "roles",
    "groups",
    "environment",
];
const MAX_STATE_LEN: usize = 512;
const MAX_NONCE_LEN: usize = 256;
const MAX_SCOPE_LEN: usize = 512;

/// Why a request was refused. Nothing is ever redirected on a refusal: the
/// caller gets the error, so an unregistered URI is never a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotEnabled,
    InvalidRequest(&'static str),
    InvalidClient,
    InvalidRedirectUri,
    UnsupportedResponseType,
    InvalidScope,
    UnsupportedGrantType,
    InvalidGrant(&'static str),
    Denied(DenyReason),
    Internal,
}

impl Refusal {
    /// The OAuth 2.0 / OIDC error code.
    pub fn error_code(self) -> &'static str {
        match self {
            Self::NotEnabled | Self::Internal => "server_error",
            Self::InvalidRequest(_) | Self::InvalidRedirectUri => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::Denied(_) => "access_denied",
        }
    }

    /// The audit reason.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotEnabled => "not_enabled",
            Self::InvalidRequest(r) | Self::InvalidGrant(r) => r,
            Self::InvalidClient => "invalid_client",
            Self::InvalidRedirectUri => "redirect_uri_mismatch",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::Denied(_) => "issue_denied",
            Self::Internal => "internal_error",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Self::NotEnabled => 404,
            Self::InvalidClient => 401,
            Self::Denied(reason) => match RvError::from(IssueDenied { reason }) {
                RvError::ErrResponseStatus(s, _) => s,
                _ => 403,
            },
            Self::Internal => 500,
            _ => 400,
        }
    }
}

impl From<Refusal> for RvError {
    fn from(r: Refusal) -> Self {
        let detail = match r {
            Refusal::Denied(d) => format!("identity issuance denied: {}", d.as_str()),
            other => other.reason().replace('_', " "),
        };
        RvError::ErrResponseStatus(r.status(), format!("{}: {detail}", r.error_code()))
    }
}

/// What the flows read and where they record. The gate is the only
/// [`Authorizer`] outside tests.
pub(crate) struct OidcDeps<'a> {
    pub authorizer: &'a dyn Authorizer,
    pub store: &'a OidcStore,
    pub audit: &'a dyn FederationAudit,
}

fn bounded(v: &str) -> String {
    v.chars().take(MAX_EVENT_ARG_LEN).collect()
}

#[maybe_async::maybe_async]
async fn refuse(
    deps: &OidcDeps<'_>,
    stage: &str,
    refusal: Refusal,
    client_id: &str,
    entity_id: Option<&str>,
    http: Option<&Request>,
) -> Refusal {
    let mut m = Map::new();
    m.insert("decision".into(), "refuse".into());
    m.insert("stage".into(), stage.into());
    m.insert("reason".into(), refusal.reason().into());
    if let Refusal::Denied(d) = refusal {
        m.insert("gate_reason".into(), d.as_str().into());
    }
    m.insert("provider".into(), PROVIDER.into());
    m.insert("client_id".into(), bounded(client_id).into());
    m.insert("entity_id".into(), entity_id.map(bounded).into());
    if let Err(e) = deps.audit.record(events::REFUSED, m, http).await {
        log::error!(target: "idp", "{}: audit refused the event: {e}", events::REFUSED);
    }
    refusal
}

fn enabled(cfg: Option<&OidcConfig>) -> Result<&OidcConfig, Refusal> {
    cfg.filter(|c| c.enabled).ok_or(Refusal::NotEnabled)
}

fn internal(what: &str, e: &RvError) -> Refusal {
    log::error!(target: "idp", "{}: cannot read or write the {what}: {e}", events::REFUSED);
    Refusal::Internal
}

/// A client id that is not even a valid name is an unknown client.
#[maybe_async::maybe_async]
async fn lookup_client(store: &OidcStore, client_id: &str) -> Result<store::OidcClient, Refusal> {
    if crate::provider::radius::store::validate_name("client", client_id).is_err() {
        return Err(Refusal::InvalidClient);
    }
    match store.get_client(client_id).await {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(Refusal::InvalidClient),
        Err(e) => Err(internal("client", &e)),
    }
}

/// `scope` must name `openid`; unknown scopes are dropped (RFC 6749 §3.3).
fn granted_scopes(scope: &str) -> Result<Vec<String>, Refusal> {
    if scope.len() > MAX_SCOPE_LEN || !scope.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\') {
        return Err(Refusal::InvalidScope);
    }
    let asked: Vec<&str> = scope.split(' ').filter(|s| !s.is_empty()).collect();
    if !asked.contains(&"openid") {
        return Err(Refusal::InvalidScope);
    }
    Ok(SCOPES_SUPPORTED.iter().filter(|s| asked.contains(s)).map(|s| s.to_string()).collect())
}

/// RFC 7636: the base64url of a SHA-256, 43 characters.
fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC 7636 §4.1: 43-128 unreserved characters.
fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

pub fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
    B64URL.encode(Sha256::digest(verifier.as_bytes()))
}

// ─── Authorization ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// A subset of the entitled roles; `None` means all of them.
    pub roles: Option<Vec<String>>,
}

pub struct Authorized {
    pub code: Zeroizing<String>,
    /// The registered `redirect_uri` with `code` and `state` added.
    pub redirect_to: Zeroizing<String>,
    pub state: Option<String>,
    pub client_id: String,
    pub environment: String,
    pub roles: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

/// Mint a single-use code for the caller's own identity. Checks run in
/// order: client, exact `redirect_uri`, response type, scope, PKCE, then
/// the gate; nothing is stored before the gate allows.
#[maybe_async::maybe_async]
pub(crate) async fn authorize(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &AuthorizeRequest,
    entity_id: &str,
    caller_namespace: &str,
    http: Option<&Request>,
    now: DateTime<Utc>,
) -> Result<Authorized, Refusal> {
    match authorize_inner(deps, cfg, ask, entity_id, caller_namespace, http, now).await {
        Ok(ok) => Ok(ok),
        Err(r) => Err(refuse(deps, "authorize", r, &ask.client_id, Some(entity_id), http).await),
    }
}

#[maybe_async::maybe_async]
async fn authorize_inner(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &AuthorizeRequest,
    entity_id: &str,
    caller_namespace: &str,
    http: Option<&Request>,
    now: DateTime<Utc>,
) -> Result<Authorized, Refusal> {
    let cfg = enabled(cfg)?;
    let client = lookup_client(deps.store, &ask.client_id).await?;
    // Byte-for-byte match against the registration: no prefix, no
    // normalisation, so no other URI can receive a code.
    if !client.redirect_uris.iter().any(|u| u == &ask.redirect_uri) {
        return Err(Refusal::InvalidRedirectUri);
    }
    if ask.response_type != "code" {
        return Err(Refusal::UnsupportedResponseType);
    }
    let scope = granted_scopes(&ask.scope)?;
    for (field, value, max) in [("state", &ask.state, MAX_STATE_LEN), ("nonce", &ask.nonce, MAX_NONCE_LEN)] {
        if let Some(v) = value {
            validate_echo(field, v, max).map_err(|_| Refusal::InvalidRequest("malformed_state_or_nonce"))?;
        }
    }
    let challenge = ask.code_challenge.as_deref().ok_or(Refusal::InvalidRequest("pkce_required"))?;
    if ask.code_challenge_method.as_deref() != Some("S256") {
        return Err(Refusal::InvalidRequest("pkce_s256_required"));
    }
    if !valid_challenge(challenge) {
        return Err(Refusal::InvalidRequest("malformed_code_challenge"));
    }

    let gate_ask = IssueRequest {
        entity_id: entity_id.to_string(),
        environment: client.environment.clone(),
        roles: ask.roles.clone(),
        caller_namespace: caller_namespace.to_string(),
        provider: AUTHORIZE_PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&gate_ask, http).await.map_err(|d| Refusal::Denied(d.reason))?;

    let ttl = chrono::Duration::seconds(i64::try_from(cfg.code_ttl_secs).unwrap_or(60));
    let rec = AuthCode {
        version: crate::posix::model::RECORD_VERSION,
        client_id: client.client_id.clone(),
        entity_id: grant.entity_id.clone(),
        environment: grant.environment.clone(),
        roles: grant.roles.clone(),
        redirect_uri: ask.redirect_uri.clone(),
        code_challenge: challenge.to_string(),
        nonce: ask.nonce.clone(),
        scope,
        created_at: now,
        expires_at: now + ttl,
    };
    let code = deps.store.mint_code(&rec, now).await.map_err(|e| internal("code", &e))?;
    // The registered string itself, never a re-serialisation of it, plus
    // the form-encoded parameters (registered URIs carry no fragment).
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("code", &code);
    if let Some(state) = &ask.state {
        params.append_pair("state", state);
    }
    let separator = if ask.redirect_uri.contains('?') { '&' } else { '?' };
    let redirect_to =
        Zeroizing::new(format!("{}{separator}{}", client_redirect(&client, &ask.redirect_uri)?, params.finish()));
    Ok(Authorized {
        code,
        redirect_to,
        state: ask.state.clone(),
        client_id: client.client_id.clone(),
        environment: grant.environment,
        roles: grant.roles,
        expires_at: rec.expires_at,
    })
}

/// The client's own registered copy of `uri` (exact match), so the
/// redirect is built from stored data, not from the request.
fn client_redirect<'a>(client: &'a store::OidcClient, uri: &str) -> Result<&'a str, Refusal> {
    client.redirect_uris.iter().find(|u| *u == uri).map(String::as_str).ok_or(Refusal::InvalidRedirectUri)
}

// ─── Token ──────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Zeroizing<String>,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub code_verifier: Zeroizing<String>,
}

pub struct Issued {
    pub id_token: Zeroizing<String>,
    pub access_token: Zeroizing<String>,
    pub expires_in: u64,
    pub scope: String,
    pub kid: String,
    pub jti: String,
}

/// Redeem a code. The client authenticates first, so a stranger cannot
/// burn codes; from then on the code is consumed whatever the outcome.
#[maybe_async::maybe_async]
pub(crate) async fn token(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &TokenRequest,
    http: Option<&Request>,
    now: DateTime<Utc>,
) -> Result<Issued, Refusal> {
    let mut entity: Option<String> = None;
    match token_inner(deps, cfg, ask, http, now, &mut entity).await {
        Ok(ok) => Ok(ok),
        Err(r) => Err(refuse(deps, "token", r, &ask.client_id, entity.as_deref(), http).await),
    }
}

#[maybe_async::maybe_async]
async fn token_inner(
    deps: &OidcDeps<'_>,
    cfg: Option<&OidcConfig>,
    ask: &TokenRequest,
    http: Option<&Request>,
    now: DateTime<Utc>,
    entity: &mut Option<String>,
) -> Result<Issued, Refusal> {
    let cfg = enabled(cfg)?;
    if ask.grant_type != "authorization_code" {
        return Err(Refusal::UnsupportedGrantType);
    }
    let client = lookup_client(deps.store, &ask.client_id).await?;
    let presented = sha256_hex(ask.client_secret.as_bytes());
    if ask.client_secret.is_empty() || !ct_eq(presented.as_bytes(), client.secret_sha256.as_bytes()) {
        return Err(Refusal::InvalidClient);
    }
    let code = match deps.store.take_code(&ask.code).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(Refusal::InvalidGrant("unknown_or_used_code")),
        Err(e) => return Err(internal("code", &e)),
    };
    *entity = Some(code.entity_id.clone());
    if code.expires_at <= now {
        return Err(Refusal::InvalidGrant("code_expired"));
    }
    if code.client_id != client.client_id || code.environment != client.environment {
        return Err(Refusal::InvalidGrant("code_client_mismatch"));
    }
    if code.redirect_uri != ask.redirect_uri {
        return Err(Refusal::InvalidGrant("redirect_uri_mismatch"));
    }
    let verifier = ask.code_verifier.as_str();
    if !valid_verifier(verifier) || !ct_eq(s256(verifier).as_bytes(), code.code_challenge.as_bytes()) {
        return Err(Refusal::InvalidGrant("pkce_verification_failed"));
    }

    // Asked again: a disable, a removal or a revoked role since the code
    // was minted denies here.
    let gate_ask = IssueRequest {
        entity_id: code.entity_id.clone(),
        environment: code.environment.clone(),
        roles: Some(code.roles.clone()),
        // Clients are root-administered objects, like the idp mount.
        caller_namespace: String::new(),
        provider: PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&gate_ask, http).await.map_err(|d| Refusal::Denied(d.reason))?;

    let ring = deps.store.keys.ensure(now).await.map_err(|e| internal("signing key", &e))?;
    let key = ring.current().map_err(|e| internal("signing key", &e.into()))?;
    let ttl = cfg.id_token_ttl_secs;
    let (iat, exp) = (now.timestamp(), now.timestamp() + i64::try_from(ttl).unwrap_or(300));
    let jti = random_id();

    let mut claims = Map::new();
    claims.insert("iss".into(), cfg.issuer.clone().into());
    claims.insert("sub".into(), grant.entity_id.clone().into());
    claims.insert("aud".into(), client.client_id.clone().into());
    claims.insert("azp".into(), client.client_id.clone().into());
    claims.insert("iat".into(), iat.into());
    claims.insert("exp".into(), exp.into());
    claims.insert("jti".into(), jti.clone().into());
    if let Some(nonce) = &code.nonce {
        claims.insert("nonce".into(), nonce.clone().into());
    }
    claims.insert("preferred_username".into(), grant.login.clone().into());
    if !grant.display_name.is_empty() {
        claims.insert("name".into(), grant.display_name.clone().into());
    }
    claims.insert("uid".into(), grant.uid.into());
    claims.insert("gid".into(), grant.primary_gid.into());
    claims.insert("roles".into(), Value::from(grant.roles.clone()));
    claims.insert("groups".into(), Value::from(grant.roles.clone()));
    claims.insert("environment".into(), grant.environment.clone().into());
    let id_token = jwt::encode_rs256(key, "JWT", &claims).map_err(|e| internal("id token", &e))?;

    let mut at = Map::new();
    at.insert("iss".into(), cfg.issuer.clone().into());
    at.insert("sub".into(), grant.entity_id.clone().into());
    at.insert("aud".into(), client.client_id.clone().into());
    at.insert("client_id".into(), client.client_id.clone().into());
    at.insert("scope".into(), code.scope.join(" ").into());
    at.insert("iat".into(), iat.into());
    at.insert("exp".into(), exp.into());
    at.insert("jti".into(), random_id().into());
    let access_token = jwt::encode_rs256(key, "at+jwt", &at).map_err(|e| internal("access token", &e))?;

    let mut fields = Map::new();
    fields.insert("decision".into(), "issue".into());
    fields.insert("provider".into(), PROVIDER.into());
    fields.insert("client_id".into(), client.client_id.clone().into());
    fields.insert("entity_id".into(), grant.entity_id.clone().into());
    fields.insert("login".into(), grant.login.clone().into());
    fields.insert("uid".into(), grant.uid.into());
    fields.insert("environment".into(), grant.environment.clone().into());
    fields.insert("roles".into(), Value::from(grant.roles.clone()));
    fields.insert("kid".into(), key.kid.clone().into());
    fields.insert("jti".into(), jti.clone().into());
    fields.insert("expires_at".into(), exp.into());
    // A token nobody can attribute is not returned.
    if let Err(e) = deps.audit.record(events::TOKEN, fields, http).await {
        log::error!(target: "idp", "{}: audit refused the event, refusing: {e}", events::TOKEN);
        return Err(Refusal::Internal);
    }
    Ok(Issued {
        id_token: Zeroizing::new(id_token),
        access_token: Zeroizing::new(access_token),
        expires_in: ttl,
        scope: code.scope.join(" "),
        kid: key.kid.clone(),
        jti,
    })
}

// ─── Discovery and keys ─────────────────────────────────────────────

/// The discovery document (OpenID Connect Discovery 1.0 §3).
pub fn discovery(cfg: &OidcConfig) -> Map<String, Value> {
    let list = |items: &[&str]| Value::from(items.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut m = Map::new();
    m.insert("issuer".into(), cfg.issuer.clone().into());
    m.insert("authorization_endpoint".into(), cfg.authorization_endpoint().into());
    m.insert("token_endpoint".into(), format!("{}/token", cfg.issuer).into());
    m.insert("jwks_uri".into(), format!("{}/jwks", cfg.issuer).into());
    m.insert("response_types_supported".into(), list(&["code"]));
    m.insert("response_modes_supported".into(), list(&["query"]));
    m.insert("grant_types_supported".into(), list(&["authorization_code"]));
    m.insert("subject_types_supported".into(), list(&["public"]));
    m.insert("id_token_signing_alg_values_supported".into(), list(&["RS256"]));
    m.insert("token_endpoint_auth_methods_supported".into(), list(&["client_secret_post"]));
    m.insert("code_challenge_methods_supported".into(), list(&["S256"]));
    m.insert("scopes_supported".into(), list(SCOPES_SUPPORTED));
    m.insert("claims_supported".into(), list(CLAIMS_SUPPORTED));
    m.insert("claims_parameter_supported".into(), false.into());
    m.insert("request_parameter_supported".into(), false.into());
    m.insert("request_uri_parameter_supported".into(), false.into());
    m
}

/// The JWKS: the current key, then retired keys still in their overlap.
pub fn jwks(ring: &KeyRing, now: DateTime<Utc>) -> Result<Map<String, Value>, RvError> {
    let keys = ring.published(now).into_iter().map(|k| Value::Object(k.public_jwk())).collect();
    Ok(Map::from_iter([("keys".to_string(), Value::Array(keys))]))
}
