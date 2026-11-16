//! The RADIUS provider (features/identity-provider.md §3b). RadSec is the
//! default transport, UDP opt-in. The human proves identity to the vault and
//! mints a one-time passcode for one environment; the NAS sends it as
//! User-Password. Accept needs a known NAS, a valid Message-Authenticator,
//! the login's passcode for the NAS's environment, a gate allow and profile
//! attributes. Anything else is a Reject, or a silent discard where RFC 2865
//! and RFC 3579 require one. Every outcome is audited.

pub mod packet;
#[cfg(not(feature = "sync_handler"))]
pub mod server;
pub mod store;
#[cfg(test)]
mod tests;
pub mod tls;
pub mod vendor;

use std::{net::IpAddr, sync::Arc};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::Authorizer;
use crate::{
    entitlement::gate::{DenyReason, IssueRequest},
    errors::RvError,
    kernel_api::VaultCtx,
    posix::{model::validate_login, store::PosixStore},
};

use packet::{attr, code, MessageAuthCheck, PacketError};
use store::{RadiusClient, RadiusStore};

/// The provider name the gate records for an Access-Request.
pub const PROVIDER: &str = "radius";
/// The provider name the gate records when a passcode is minted.
pub const PASSCODE_PROVIDER: &str = "radius-passcode";

pub mod events {
    /// An Access-Accept was sent (audit event).
    pub const ACCEPT: &str = "idp.radius.accept";
    /// An Access-Reject was sent, or a request was discarded (audit event).
    pub const REJECT: &str = "idp.radius.reject";
}

/// Why a request was not accepted. The first group is discarded without a
/// reply (RFC 2865 §3, RFC 3579 §3.2); the rest get an Access-Reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed(PacketError),
    NotAccessRequest,
    UnknownClient,
    NoMessageAuthenticator,
    BadMessageAuthenticator,
    RateLimited,
    Busy,
    BadRequest,
    UnsupportedAuthentication,
    UnknownLogin,
    BadPasscode,
    PasscodeExpired,
    EnvironmentMismatch,
    ProfileUnavailable,
    Denied(DenyReason),
    NoAttributes,
    Internal,
}

impl Refusal {
    pub fn is_discard(self) -> bool {
        matches!(
            self,
            Self::Malformed(_)
                | Self::NotAccessRequest
                | Self::UnknownClient
                | Self::NoMessageAuthenticator
                | Self::BadMessageAuthenticator
                | Self::RateLimited
                | Self::Busy
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::NotAccessRequest => "not_access_request",
            Self::UnknownClient => "unknown_client",
            Self::NoMessageAuthenticator => "no_message_authenticator",
            Self::BadMessageAuthenticator => "bad_message_authenticator",
            Self::RateLimited => "rate_limited",
            Self::Busy => "busy",
            Self::BadRequest => "bad_request",
            Self::UnsupportedAuthentication => "unsupported_authentication",
            Self::UnknownLogin => "unknown_login",
            Self::BadPasscode => "bad_passcode",
            Self::PasscodeExpired => "passcode_expired",
            Self::EnvironmentMismatch => "environment_mismatch",
            Self::ProfileUnavailable => "profile_unavailable",
            Self::Denied(_) => "issue_denied",
            Self::NoAttributes => "no_attributes",
            Self::Internal => "internal_error",
        }
    }
}

/// Where `idp.radius.accept` / `idp.radius.reject` go.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait RadiusAudit: Send + Sync {
    async fn record(&self, name: &'static str, fields: Map<String, Value>) -> Result<(), RvError>;
}

/// The audit path the gate uses: a `security` log line plus a broker event
/// when a device is enabled.
pub struct BrokerRadiusAudit {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl RadiusAudit for BrokerRadiusAudit {
    async fn record(&self, name: &'static str, fields: Map<String, Value>) -> Result<(), RvError> {
        log::info!(target: "security", "{name} {}", Value::Object(fields.clone()));
        let Some(broker) = self.ctx.audit_broker() else {
            return Ok(());
        };
        if !broker.has_devices() {
            return Ok(());
        }
        let mut entry = bv_audit::AuditEntry::event(name, fields, None, broker.hmac_key());
        broker.log(&mut entry).await
    }
}

/// What the decision reads. The gate is the only [`Authorizer`] outside
/// tests.
pub(crate) struct RadiusDeps<'a> {
    pub authorizer: &'a dyn Authorizer,
    pub posix: &'a PosixStore,
    pub radius: &'a RadiusStore,
    pub audit: &'a dyn RadiusAudit,
}

/// One request from one NAS.
pub struct Exchange<'a> {
    pub client: &'a RadiusClient,
    pub peer: IpAddr,
    pub packet: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    pub environment: String,
    pub roles: Vec<String>,
    pub attributes: Vec<String>,
}

/// The reply to send (none for a discard) and why.
#[derive(Debug, Clone)]
pub struct Answer {
    pub reply: Option<Vec<u8>>,
    pub outcome: Result<Accepted, Refusal>,
}

/// What an audit event says about the request, filled in as it is learnt.
#[derive(Default)]
struct Seen {
    user_name: Option<String>,
    entity_id: Option<String>,
}

fn event_fields(
    decision: &str,
    refusal: Option<Refusal>,
    client: Option<&RadiusClient>,
    transport: &str,
    peer: IpAddr,
    seen: &Seen,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("decision".into(), decision.into());
    m.insert("reason".into(), refusal.map(Refusal::as_str).into());
    if let Some(Refusal::Denied(d)) = refusal {
        m.insert("gate_reason".into(), d.as_str().into());
    }
    if let Some(Refusal::Malformed(e)) = refusal {
        m.insert("packet_error".into(), e.as_str().into());
    }
    m.insert("provider".into(), PROVIDER.into());
    m.insert("transport".into(), transport.into());
    m.insert("peer".into(), peer.to_string().into());
    m.insert("client".into(), client.map(|c| c.name.clone()).into());
    m.insert("environment".into(), client.map(|c| c.environment.clone()).into());
    // Only a value that passed the login rules; the password never appears.
    m.insert("user_name".into(), seen.user_name.clone().into());
    m.insert("entity_id".into(), seen.entity_id.clone().into());
    m
}

/// Record a request refused before it could be attributed to a NAS (no
/// client record). Best effort; the caller bounds how often it is called.
#[maybe_async::maybe_async]
pub(crate) async fn audit_unattributed(audit: &dyn RadiusAudit, transport: &str, peer: IpAddr, refusal: Refusal) {
    let fields = event_fields("discard", Some(refusal), None, transport, peer, &Seen::default());
    if let Err(e) = audit.record(events::REJECT, fields).await {
        log::error!(target: "idp", "{}: audit refused the event: {e}", events::REJECT);
    }
}

fn reject_reply(identifier: u8, request_authenticator: &[u8; 16], secret: &[u8]) -> Option<Vec<u8>> {
    packet::encode_response(code::ACCESS_REJECT, identifier, request_authenticator, &[], secret).ok()
}

/// Answer one packet from a known NAS. An Access-Accept comes from one path
/// only, after the gate allowed and the accept event was recorded.
#[maybe_async::maybe_async]
pub(crate) async fn answer(deps: &RadiusDeps<'_>, ex: &Exchange<'_>, now: DateTime<Utc>) -> Answer {
    let transport = ex.client.transport.as_str();
    let mut seen = Seen::default();
    let refuse = |decision: &str, refusal: Refusal, reply: Option<Vec<u8>>, seen: &Seen| {
        let fields = event_fields(decision, Some(refusal), Some(ex.client), transport, ex.peer, seen);
        (Answer { reply, outcome: Err(refusal) }, fields)
    };

    let (answer, fields) = 'decide: {
        let Some(secret) = ex.client.shared_secret() else {
            break 'decide refuse("discard", Refusal::UnknownClient, None, &seen);
        };
        let p = match packet::parse(ex.packet) {
            Ok(p) => p,
            Err(e) => break 'decide refuse("discard", Refusal::Malformed(e), None, &seen),
        };
        if p.code != code::ACCESS_REQUEST {
            break 'decide refuse("discard", Refusal::NotAccessRequest, None, &seen);
        }
        let ma_refusal = match packet::check_message_authenticator(&p, &secret) {
            MessageAuthCheck::Valid => None,
            MessageAuthCheck::Missing => Some(Refusal::NoMessageAuthenticator),
            MessageAuthCheck::Invalid => Some(Refusal::BadMessageAuthenticator),
            MessageAuthCheck::Duplicate | MessageAuthCheck::Malformed => {
                Some(Refusal::Malformed(PacketError::BadAttribute))
            }
        };
        if let Some(refusal) = ma_refusal {
            break 'decide refuse("discard", refusal, None, &seen);
        }

        // The NAS is proven: from here every refusal is a signed Access-Reject.
        let reject = |refusal: Refusal, seen: &Seen| {
            refuse("reject", refusal, reject_reply(p.identifier, &p.authenticator, &secret), seen)
        };
        let (accepted, attrs) = match authorize_verified(deps, ex.client, &p, &secret, now, &mut seen).await {
            Ok(ok) => ok,
            Err(refusal) => break 'decide reject(refusal, &seen),
        };
        let encoded = packet::encode_response(code::ACCESS_ACCEPT, p.identifier, &p.authenticator, &attrs, &secret);
        let reply = match encoded {
            Ok(reply) => reply,
            Err(e) => {
                log::error!(target: "idp", "{}: cannot encode the Access-Accept: {}", events::REJECT, e.as_str());
                break 'decide reject(Refusal::Internal, &seen);
            }
        };
        let mut fields = event_fields("accept", None, Some(ex.client), transport, ex.peer, &seen);
        fields.insert("uid".into(), accepted.uid.into());
        fields.insert("roles".into(), Value::from(accepted.roles.clone()));
        fields.insert("attributes".into(), Value::from(accepted.attributes.clone()));
        // An Accept nobody can attribute to a NAS is not sent.
        if let Err(e) = deps.audit.record(events::ACCEPT, fields).await {
            log::error!(target: "idp", "{}: audit refused the event, rejecting: {e}", events::ACCEPT);
            break 'decide reject(Refusal::Internal, &seen);
        }
        log::info!(
            target: "security",
            "idp.radius.accept: client={} environment={} login={} uid={} roles={}",
            ex.client.name,
            accepted.environment,
            accepted.login,
            accepted.uid,
            accepted.roles.join(",")
        );
        return Answer { reply: Some(reply), outcome: Ok(accepted) };
    };
    if let Err(e) = deps.audit.record(events::REJECT, fields).await {
        log::error!(target: "idp", "{}: audit refused the event: {e}", events::REJECT);
    }
    answer
}

/// Everything after the Message-Authenticator check: the accepted identity
/// and the reply attributes, or why not.
#[maybe_async::maybe_async]
async fn authorize_verified(
    deps: &RadiusDeps<'_>,
    client: &RadiusClient,
    p: &packet::Packet<'_>,
    secret: &[u8],
    now: DateTime<Utc>,
    seen: &mut Seen,
) -> Result<(Accepted, Vec<(u8, Vec<u8>)>), Refusal> {
    if p.count(attr::CHAP_PASSWORD) > 0 || p.count(attr::EAP_MESSAGE) > 0 || p.count(attr::STATE) > 0 {
        return Err(Refusal::UnsupportedAuthentication);
    }
    let user = p.single(attr::USER_NAME).map_err(|_| Refusal::BadRequest)?.ok_or(Refusal::BadRequest)?;
    let hidden = p.single(attr::USER_PASSWORD).map_err(|_| Refusal::BadRequest)?.ok_or(Refusal::BadRequest)?;
    let login = std::str::from_utf8(user).map_err(|_| Refusal::UnknownLogin)?;
    if validate_login(login).is_err() {
        return Err(Refusal::UnknownLogin);
    }
    seen.user_name = Some(login.to_string());
    let password = packet::unhide_password(hidden, secret, &p.authenticator).map_err(|_| Refusal::BadRequest)?;

    let entity_id = match deps.posix.entity_for_login(login).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(Refusal::UnknownLogin),
        Err(e) => return Err(internal("login index", &e)),
    };
    seen.entity_id = Some(entity_id.clone());
    if !store::is_passcode_format(&password) {
        return Err(Refusal::BadPasscode);
    }
    let passcode = match deps.radius.consume_passcode(&entity_id, &password).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return Err(Refusal::BadPasscode),
        Err(e) => return Err(internal("passcode", &e)),
    };
    drop(password);
    if passcode.expires_at <= now {
        return Err(Refusal::PasscodeExpired);
    }
    if passcode.entity_id != entity_id || passcode.login != login {
        log::error!(target: "idp", "{}: passcode under entity_id={entity_id} names another identity", events::REJECT);
        return Err(Refusal::Internal);
    }
    if passcode.environment != client.environment {
        return Err(Refusal::EnvironmentMismatch);
    }
    let profile = match deps.radius.get_profile(&client.profile).await {
        Ok(Some(profile)) if profile.environment == client.environment => profile,
        Ok(_) => return Err(Refusal::ProfileUnavailable),
        Err(e) => return Err(internal("profile", &e)),
    };

    // The gate decides, and records `idp.issue` / `idp.issue-denied`.
    let ask = IssueRequest {
        entity_id: entity_id.clone(),
        environment: client.environment.clone(),
        roles: passcode.roles.clone(),
        // NAS clients are root-administered objects, like the idp mount.
        caller_namespace: String::new(),
        provider: PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&ask, None).await.map_err(|d| Refusal::Denied(d.reason))?;

    let chosen = profile.attributes_for(&grant.roles);
    if chosen.is_empty() {
        return Err(Refusal::NoAttributes);
    }
    let mut attrs = Vec::with_capacity(chosen.len());
    let mut names = Vec::with_capacity(chosen.len());
    for a in chosen {
        attrs.push((attr::VENDOR_SPECIFIC, a.encode().map_err(|_| Refusal::Internal)?));
        names.push(a.attribute.clone());
    }
    let accepted = Accepted {
        entity_id: grant.entity_id,
        login: grant.login,
        uid: grant.uid,
        environment: grant.environment,
        roles: grant.roles,
        attributes: names,
    };
    Ok((accepted, attrs))
}

fn internal(what: &str, e: &RvError) -> Refusal {
    log::error!(target: "idp", "{}: cannot read the {what}: {e}", events::REJECT);
    Refusal::Internal
}

/// What the listeners are bound to right now, for `v2/idp/radius/config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerStatus {
    pub radsec: Option<std::net::SocketAddr>,
    pub udp: Option<std::net::SocketAddr>,
    pub last_error: Option<String>,
}

impl ListenerStatus {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("radsec".into(), self.radsec.map(|a| a.to_string()).into());
        m.insert("udp".into(), self.udp.map(|a| a.to_string()).into());
        m.insert("last_error".into(), self.last_error.clone().into());
        Value::Object(m)
    }
}

/// The listeners' handle, shared by the module and the backend. The
/// supervisor (`server`) is started once per process from
/// `Module::start_background`; a config or client write asks it to
/// reconcile at once instead of at its next tick.
#[derive(Default)]
pub struct RadiusRuntime {
    pub(crate) notify: tokio::sync::Notify,
    pub(crate) started: std::sync::atomic::AtomicBool,
    pub(crate) status: std::sync::Mutex<ListenerStatus>,
}

impl RadiusRuntime {
    pub fn reconcile_soon(&self) {
        self.notify.notify_one();
    }

    pub fn status(&self) -> ListenerStatus {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }
}
