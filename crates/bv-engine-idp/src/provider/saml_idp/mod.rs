//! The SAML 2.0 IdP (features/identity-provider.md §3c). The vault already
//! knows the human; `sso` answers an SP's AuthnRequest and `initiate` sends
//! an unsolicited response to an SP that allows it, both self-service and
//! gated (provider `saml`). Responses go only to a registered ACS URL, are
//! HTTP-POST, carry one assertion signed with RSA-SHA256 over exclusive C14N.

pub mod request;
pub mod store;
#[cfg(test)]
mod tests;
pub mod xml;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{
    federation::{random_id, validate_echo, FederationAudit},
    Authorizer,
};
use crate::{
    entitlement::gate::{DenyReason, IssueDenied, IssueRequest, MAX_EVENT_ARG_LEN},
    errors::RvError,
    logical::Request,
};
use request::{AuthnRequest, Binding};
use store::{SamlConfig, SamlStore, ServiceProvider, MAX_REQUEST_MAX_AGE_SECS};

/// The provider name the gate records.
pub const PROVIDER: &str = "saml";
/// Clock skew tolerated on an AuthnRequest's `IssueInstant`.
pub const CLOCK_SKEW_SECS: i64 = 60;
/// SAML bindings §3.4.3: RelayState is at most 80 bytes.
pub const MAX_RELAY_STATE_LEN: usize = 80;
const MAX_REQUEST_ID_LEN: usize = 256;

pub mod events {
    /// A signed response was issued (audit event; IDs only, never the XML).
    pub const RESPONSE: &str = "idp.saml.response";
    /// An SSO or initiate request was refused (audit event).
    pub const REFUSED: &str = "idp.saml.refused";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotEnabled,
    MalformedRequest(&'static str),
    UnknownServiceProvider,
    AcsMismatch,
    DestinationMismatch,
    RequestExpired,
    Replay,
    Unsupported(&'static str),
    IdpInitiatedNotAllowed,
    InvalidRelayState,
    Denied(DenyReason),
    Internal,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotEnabled => "not_enabled",
            Self::MalformedRequest(r) | Self::Unsupported(r) => r,
            Self::UnknownServiceProvider => "unknown_service_provider",
            Self::AcsMismatch => "acs_url_mismatch",
            Self::DestinationMismatch => "destination_mismatch",
            Self::RequestExpired => "request_expired",
            Self::Replay => "request_replayed",
            Self::IdpInitiatedNotAllowed => "idp_initiated_not_allowed",
            Self::InvalidRelayState => "invalid_relay_state",
            Self::Denied(_) => "issue_denied",
            Self::Internal => "internal_error",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Self::NotEnabled | Self::UnknownServiceProvider => 404,
            Self::IdpInitiatedNotAllowed => 403,
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
        RvError::ErrResponseStatus(r.status(), format!("saml: {detail}"))
    }
}

pub(crate) struct SamlDeps<'a> {
    pub authorizer: &'a dyn Authorizer,
    pub store: &'a SamlStore,
    pub audit: &'a dyn FederationAudit,
}

/// Who asks, as the gate needs it.
pub struct Caller<'a> {
    pub entity_id: &'a str,
    pub namespace: &'a str,
    pub http: Option<&'a Request>,
}

/// A response ready for the HTTP-POST binding.
pub struct SamlIssued {
    /// The `SAMLResponse` form value: the signed Response, base64.
    pub saml_response: Zeroizing<String>,
    pub acs_url: String,
    pub relay_state: Option<String>,
    pub service_provider: String,
    pub response_id: String,
    pub assertion_id: String,
    pub not_on_or_after: DateTime<Utc>,
}

pub struct SsoInput {
    pub saml_request: String,
    pub binding: Binding,
    pub relay_state: Option<String>,
    /// A subset of the entitled roles; `None` means all of them.
    pub roles: Option<Vec<String>>,
}

fn bounded(v: &str) -> String {
    v.chars().take(MAX_EVENT_ARG_LEN).collect()
}

fn enabled(cfg: Option<&SamlConfig>) -> Result<&SamlConfig, Refusal> {
    cfg.filter(|c| c.enabled).ok_or(Refusal::NotEnabled)
}

fn internal(what: &str, e: &RvError) -> Refusal {
    log::error!(target: "idp", "{}: cannot read or write the {what}: {e}", events::REFUSED);
    Refusal::Internal
}

#[maybe_async::maybe_async]
async fn refuse(deps: &SamlDeps<'_>, stage: &str, refusal: Refusal, sp: Option<&str>, caller: &Caller<'_>) -> Refusal {
    let mut m = Map::new();
    m.insert("decision".into(), "refuse".into());
    m.insert("stage".into(), stage.into());
    m.insert("reason".into(), refusal.reason().into());
    if let Refusal::Denied(d) = refusal {
        m.insert("gate_reason".into(), d.as_str().into());
    }
    m.insert("provider".into(), PROVIDER.into());
    m.insert("service_provider".into(), sp.map(bounded).into());
    m.insert("entity_id".into(), bounded(caller.entity_id).into());
    if let Err(e) = deps.audit.record(events::REFUSED, m, caller.http).await {
        log::error!(target: "idp", "{}: audit refused the event: {e}", events::REFUSED);
    }
    refusal
}

fn check_relay_state(relay_state: Option<&String>) -> Result<(), Refusal> {
    match relay_state {
        Some(rs) => validate_echo("relay_state", rs, MAX_RELAY_STATE_LEN).map_err(|_| Refusal::InvalidRelayState),
        None => Ok(()),
    }
}

/// An XML `ID`: an NCName-like token, bounded.
fn valid_request_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_REQUEST_ID_LEN
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
}

/// Answer an SP-initiated AuthnRequest for the caller's own identity.
#[maybe_async::maybe_async]
pub(crate) async fn sso(
    deps: &SamlDeps<'_>,
    cfg: Option<&SamlConfig>,
    input: &SsoInput,
    caller: &Caller<'_>,
    now: DateTime<Utc>,
) -> Result<SamlIssued, Refusal> {
    let mut sp_name: Option<String> = None;
    match sso_inner(deps, cfg, input, caller, now, &mut sp_name).await {
        Ok(ok) => Ok(ok),
        Err(r) => Err(refuse(deps, "sso", r, sp_name.as_deref(), caller).await),
    }
}

#[maybe_async::maybe_async]
async fn sso_inner(
    deps: &SamlDeps<'_>,
    cfg: Option<&SamlConfig>,
    input: &SsoInput,
    caller: &Caller<'_>,
    now: DateTime<Utc>,
    sp_name: &mut Option<String>,
) -> Result<SamlIssued, Refusal> {
    let cfg = enabled(cfg)?;
    check_relay_state(input.relay_state.as_ref())?;
    let xml = request::decode(&input.saml_request, input.binding).map_err(Refusal::MalformedRequest)?;
    let req: AuthnRequest = request::parse(&xml).map_err(Refusal::MalformedRequest)?;
    if req.version != "2.0" {
        return Err(Refusal::MalformedRequest("unsupported_version"));
    }
    if !valid_request_id(&req.id) {
        return Err(Refusal::MalformedRequest("malformed_request_id"));
    }
    let issued_at = DateTime::parse_from_rfc3339(&req.issue_instant)
        .map_err(|_| Refusal::MalformedRequest("malformed_issue_instant"))?
        .with_timezone(&Utc);
    let skew = chrono::Duration::seconds(CLOCK_SKEW_SECS);
    let max_age = chrono::Duration::seconds(i64::try_from(cfg.request_max_age_secs).unwrap_or(300));
    if issued_at > now + skew || issued_at + max_age + skew < now {
        return Err(Refusal::RequestExpired);
    }
    let sp = match deps.store.sp_for_entity(&req.issuer).await {
        Ok(Some(sp)) => sp,
        Ok(None) => return Err(Refusal::UnknownServiceProvider),
        Err(e) => return Err(internal("service provider", &e)),
    };
    *sp_name = Some(sp.name.clone());
    if req.destination.as_ref().is_some_and(|d| d != &cfg.sso_url) {
        return Err(Refusal::DestinationMismatch);
    }
    if req.acs_index.is_some() {
        return Err(Refusal::Unsupported("acs_index_unsupported"));
    }
    if req.protocol_binding.as_ref().is_some_and(|b| b != xml::BINDING_POST) {
        return Err(Refusal::Unsupported("binding_unsupported"));
    }
    if req.force_authn {
        return Err(Refusal::Unsupported("force_authn_unsupported"));
    }
    // Exact match against the registration; the default is the first one.
    let acs_url = match &req.acs_url {
        Some(url) if sp.acs_urls.contains(url) => url.clone(),
        Some(_) => return Err(Refusal::AcsMismatch),
        None => sp.acs_urls[0].clone(),
    };
    // Keyed on the request alone (not on the configured max age), so a
    // replay is caught whatever the configuration says later.
    let ceiling = chrono::Duration::seconds(i64::try_from(MAX_REQUEST_MAX_AGE_SECS).unwrap_or(900));
    match deps.store.record_request(&sp.name, &req.id, issued_at + ceiling + skew, now).await {
        Ok(true) => {}
        Ok(false) => return Err(Refusal::Replay),
        Err(e) => return Err(internal("replay cache", &e)),
    }
    issue(deps, cfg, &sp, &acs_url, Some(&req.id), input.roles.clone(), input.relay_state.clone(), caller, now).await
}

/// An unsolicited response to `sp_name`'s default ACS URL, for an SP that
/// allows IdP-initiated SSO.
#[maybe_async::maybe_async]
pub(crate) async fn initiate(
    deps: &SamlDeps<'_>,
    cfg: Option<&SamlConfig>,
    sp_name: &str,
    relay_state: Option<String>,
    roles: Option<Vec<String>>,
    caller: &Caller<'_>,
    now: DateTime<Utc>,
) -> Result<SamlIssued, Refusal> {
    match initiate_inner(deps, cfg, sp_name, relay_state, roles, caller, now).await {
        Ok(ok) => Ok(ok),
        Err(r) => Err(refuse(deps, "initiate", r, Some(sp_name), caller).await),
    }
}

#[maybe_async::maybe_async]
async fn initiate_inner(
    deps: &SamlDeps<'_>,
    cfg: Option<&SamlConfig>,
    sp_name: &str,
    relay_state: Option<String>,
    roles: Option<Vec<String>>,
    caller: &Caller<'_>,
    now: DateTime<Utc>,
) -> Result<SamlIssued, Refusal> {
    let cfg = enabled(cfg)?;
    check_relay_state(relay_state.as_ref())?;
    if crate::provider::radius::store::validate_name("service provider", sp_name).is_err() {
        return Err(Refusal::UnknownServiceProvider);
    }
    let sp = match deps.store.get_sp(sp_name).await {
        Ok(Some(sp)) => sp,
        Ok(None) => return Err(Refusal::UnknownServiceProvider),
        Err(e) => return Err(internal("service provider", &e)),
    };
    if !sp.allow_idp_initiated {
        return Err(Refusal::IdpInitiatedNotAllowed);
    }
    let acs_url = sp.acs_urls[0].clone();
    issue(deps, cfg, &sp, &acs_url, None, roles, relay_state, caller, now).await
}

/// Gate, build, sign, record. A response nobody can attribute is not
/// returned.
#[allow(clippy::too_many_arguments)]
#[maybe_async::maybe_async]
async fn issue(
    deps: &SamlDeps<'_>,
    cfg: &SamlConfig,
    sp: &ServiceProvider,
    acs_url: &str,
    in_response_to: Option<&str>,
    roles: Option<Vec<String>>,
    relay_state: Option<String>,
    caller: &Caller<'_>,
    now: DateTime<Utc>,
) -> Result<SamlIssued, Refusal> {
    let ask = IssueRequest {
        entity_id: caller.entity_id.to_string(),
        environment: sp.environment.clone(),
        roles,
        caller_namespace: caller.namespace.to_string(),
        provider: PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&ask, caller.http).await.map_err(|d| Refusal::Denied(d.reason))?;

    let ring = deps.store.keys.ensure(now).await.map_err(|e| internal("signing key", &e))?;
    let key = ring.current().map_err(|e| internal("signing key", &e.into()))?;
    let not_on_or_after = now + chrono::Duration::seconds(i64::try_from(cfg.assertion_ttl_secs).unwrap_or(300));
    let (response_id, assertion_id) = (random_id(), random_id());
    let mut attributes = vec![
        ("login", vec![grant.login.clone()]),
        ("uid", vec![grant.uid.to_string()]),
        ("gid", vec![grant.primary_gid.to_string()]),
        ("roles", grant.roles.clone()),
        ("groups", grant.roles.clone()),
        ("environment", vec![grant.environment.clone()]),
    ];
    if !grant.display_name.is_empty() {
        attributes.push(("display_name", vec![grant.display_name.clone()]));
    }
    let input = xml::AssertionInput {
        idp_entity_id: &cfg.entity_id,
        sp_entity_id: &sp.entity_id,
        acs_url,
        in_response_to,
        name_id: &grant.login,
        attributes,
        response_id: &response_id,
        assertion_id: &assertion_id,
        issue_instant: now,
        not_on_or_after,
    };
    let response = xml::signed_response(&input, key).map_err(|e| internal("response", &e))?;

    let mut fields = Map::new();
    fields.insert("decision".into(), "issue".into());
    fields.insert("provider".into(), PROVIDER.into());
    fields.insert("initiated_by".into(), if in_response_to.is_some() { "sp" } else { "idp" }.into());
    fields.insert("service_provider".into(), sp.name.clone().into());
    fields.insert("acs_url".into(), acs_url.into());
    fields.insert("entity_id".into(), grant.entity_id.clone().into());
    fields.insert("login".into(), grant.login.clone().into());
    fields.insert("uid".into(), grant.uid.into());
    fields.insert("environment".into(), grant.environment.clone().into());
    fields.insert("roles".into(), Value::from(grant.roles.clone()));
    fields.insert("kid".into(), key.kid.clone().into());
    fields.insert("response_id".into(), response_id.clone().into());
    fields.insert("assertion_id".into(), assertion_id.clone().into());
    fields.insert("in_response_to".into(), in_response_to.map(bounded).into());
    fields.insert("not_on_or_after".into(), not_on_or_after.to_rfc3339().into());
    if let Err(e) = deps.audit.record(events::RESPONSE, fields, caller.http).await {
        log::error!(target: "idp", "{}: audit refused the event, refusing: {e}", events::RESPONSE);
        return Err(Refusal::Internal);
    }
    Ok(SamlIssued {
        saml_response: Zeroizing::new(B64.encode(response.as_bytes())),
        acs_url: acs_url.to_string(),
        relay_state,
        service_provider: sp.name.clone(),
        response_id,
        assertion_id,
        not_on_or_after,
    })
}
