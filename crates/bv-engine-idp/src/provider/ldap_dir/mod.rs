//! The LDAP-compatible directory (features/identity-provider.md §3e): a
//! read-only LDAPv3 projection of the workforce store. A client is known by
//! its pinned TLS certificate (or, opted in, its address over cleartext)
//! and bound to one environment; it sees only identities the gate would
//! issue to there. A bind is a live gate check on a one-time passcode;
//! every write operation is refused. Every refusal is audited.

pub mod ber;
pub mod directory;
pub mod dn;
pub mod filter;
pub mod proto;
#[cfg(not(feature = "sync_handler"))]
pub mod server;
pub mod store;
#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::Authorizer;
use crate::{
    entitlement::gate::{DenyReason, IssueDenied, IssueGate, IssueGrant, IssueRequest},
    errors::RvError,
    kernel_api::VaultCtx,
    posix::{
        model::{validate_login, IdentityState, WorkforceIdentity},
        store::PosixStore,
    },
    provider::radius::store::is_passcode_format,
};

use directory::{supplementary_group_name, Entry, Layout, Person};
use dn::Dn;
use proto::{tag, BindAuth, BindRequest, Message, Op, ResultCode, Scope, SearchRequest, OID_STARTTLS};
use store::{LdapClient, LdapConfig, LdapStore};

/// The provider name the gate records for a bind.
pub const PROVIDER: &str = "ldap";
/// The provider name the gate records when a bind passcode is minted.
pub const PASSCODE_PROVIDER: &str = "ldap-passcode";
/// Longest caller-supplied string an audit event carries.
const MAX_EVENT_ARG_LEN: usize = 128;

pub mod events {
    /// A bind succeeded or was refused (audit event).
    pub const BIND: &str = "idp.ldap.bind";
    /// A search was answered or refused (audit event).
    pub const SEARCH: &str = "idp.ldap.search";
    /// Anything else refused: write operations, unknown clients, cleartext
    /// without opt-in, malformed PDUs, rate limits (audit event).
    pub const REFUSED: &str = "idp.ldap.refused";
}

/// Where `idp.ldap.*` events go.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait DirectoryAudit: Send + Sync {
    async fn record(&self, name: &'static str, fields: Map<String, Value>) -> Result<(), RvError>;
}

/// The gate's audit path: a `security` log line plus a broker event when a
/// device is enabled.
pub struct BrokerDirectoryAudit {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl DirectoryAudit for BrokerDirectoryAudit {
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

/// Which identities a client may see: the gate's own decision, not
/// recorded per entry (the search is audited as one event). Implemented by
/// [`IssueGate`] only, outside tests.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait DirectoryView: Send + Sync {
    async fn view(&self, req: &IssueRequest) -> Result<IssueGrant, IssueDenied>;
}

#[maybe_async::maybe_async]
impl DirectoryView for IssueGate {
    async fn view(&self, req: &IssueRequest) -> Result<IssueGrant, IssueDenied> {
        self.evaluate_unrecorded(req).await
    }
}

/// What a request reads. The gate is the only authorizer and view outside
/// tests.
pub(crate) struct LdapDeps<'a> {
    pub authorizer: &'a dyn Authorizer,
    pub view: &'a dyn DirectoryView,
    pub posix: &'a PosixStore,
    pub ldap: &'a LdapStore,
    pub audit: &'a dyn DirectoryAudit,
}

/// How a session's client was recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognised {
    Certificate(String),
    Address(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Ldaps,
    StartTls,
    Plain,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ldaps => "ldaps",
            Self::StartTls => "starttls",
            Self::Plain => "plain",
        }
    }

    pub fn is_tls(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

/// The bind state. It is recorded, never consulted: what a session sees
/// is decided by its client alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Anonymous,
    External,
    User(String),
}

/// One connection, once its client is recognised.
#[derive(Debug, Clone)]
pub struct Session {
    pub client: String,
    pub recognised: Recognised,
    pub channel: Channel,
    pub peer: IpAddr,
    pub bound: Bound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    Continue,
    Close,
}

/// The PDUs to send, in order, and whether the connection then closes.
pub struct Served {
    pub pdus: Vec<Vec<u8>>,
    pub after: After,
}

fn cut(value: &str) -> String {
    if value.chars().count() <= MAX_EVENT_ARG_LEN {
        return value.to_string();
    }
    let mut s: String = value.chars().take(MAX_EVENT_ARG_LEN).collect();
    s.push('…');
    s
}

fn session_fields(session: &Session, environment: Option<&str>, operation: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("provider".into(), PROVIDER.into());
    m.insert("client".into(), session.client.clone().into());
    m.insert("environment".into(), environment.map(str::to_string).into());
    m.insert("transport".into(), session.channel.as_str().into());
    m.insert("peer".into(), session.peer.to_string().into());
    m.insert("operation".into(), operation.into());
    m
}

#[maybe_async::maybe_async]
async fn record(audit: &dyn DirectoryAudit, name: &'static str, fields: Map<String, Value>) {
    if let Err(e) = audit.record(name, fields).await {
        log::error!(target: "idp", "{name}: audit refused the event: {e}");
    }
}

/// Record a refusal no client record vouches for. Best effort; the caller
/// bounds how often it is called.
#[maybe_async::maybe_async]
pub(crate) async fn audit_unattributed(audit: &dyn DirectoryAudit, transport: &str, peer: IpAddr, reason: &str) {
    let mut m = Map::new();
    m.insert("provider".into(), PROVIDER.into());
    m.insert("decision".into(), "refused".into());
    m.insert("reason".into(), reason.into());
    m.insert("client".into(), Value::Null);
    m.insert("transport".into(), transport.into());
    m.insert("peer".into(), peer.to_string().into());
    record(audit, events::REFUSED, m).await;
}

/// The client and configuration a session runs under, read live for every
/// operation: a deleted client, a re-pinned certificate, a disabled
/// directory or a withdrawn cleartext opt-in take effect at once.
#[maybe_async::maybe_async]
async fn current(deps: &LdapDeps<'_>, session: &Session) -> Result<(LdapClient, LdapConfig), &'static str> {
    let cfg = match deps.ldap.config().await {
        Ok(Some(cfg)) if cfg.enabled => cfg,
        Ok(_) => return Err("directory_disabled"),
        Err(e) => {
            log::error!(target: "idp", "{}: cannot read the config: {e}", events::REFUSED);
            return Err("internal_error");
        }
    };
    if session.channel == Channel::Plain && !cfg.plaintext_enabled {
        return Err("plaintext_disabled");
    }
    let client = match deps.ldap.get_client(&session.client).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err("unknown_client"),
        Err(e) => {
            log::error!(target: "idp", "{}: cannot read client {}: {e}", events::REFUSED, session.client);
            return Err("internal_error");
        }
    };
    let still = match (&session.recognised, client.transport) {
        (Recognised::Certificate(fp), store::Transport::Tls) => client.cert_sha256.as_deref() == Some(fp),
        (Recognised::Address(ip), store::Transport::Plain) => client.address == Some(ip.to_string()),
        _ => false,
    };
    if !still {
        return Err("unknown_client");
    }
    Ok((client, cfg))
}

/// Answer one message on an admitted session.
#[maybe_async::maybe_async]
pub(crate) async fn serve(deps: &LdapDeps<'_>, session: &mut Session, msg: Message, now: DateTime<Utc>) -> Served {
    let (client, cfg) = match current(deps, session).await {
        Ok(v) => v,
        Err(reason) => {
            let mut f = session_fields(session, None, msg.op.name());
            f.insert("decision".into(), "refused".into());
            f.insert("reason".into(), reason.into());
            record(deps.audit, events::REFUSED, f).await;
            let mut pdus: Vec<Vec<u8>> =
                proto::refusal(msg.id, &msg.op, ResultCode::Unavailable, "the directory is unavailable to this client")
                    .into_iter()
                    .collect();
            pdus.push(proto::notice_of_disconnection(ResultCode::Unavailable, "the directory is unavailable"));
            return Served { pdus, after: After::Close };
        }
    };
    let env = client.environment.clone();
    let refuse = |code: ResultCode, reason: &str, message: &str, detail: Option<(&str, String)>| {
        let mut f = session_fields(session, Some(&env), msg.op.name());
        f.insert("decision".into(), "refused".into());
        f.insert("reason".into(), reason.into());
        if let Some((k, v)) = detail {
            f.insert(k.into(), v.into());
        }
        (proto::refusal(msg.id, &msg.op, code, message), f)
    };
    let refused =
        if let Some(control) = msg.critical_controls.first().filter(|_| !matches!(msg.op, Op::Unbind | Op::Abandon)) {
            Some(refuse(
                ResultCode::UnavailableCriticalExtension,
                "unsupported_critical_control",
                "no control is supported",
                Some(("control", cut(control))),
            ))
        } else {
            match &msg.op {
                Op::Write(_) => {
                    Some(refuse(ResultCode::UnwillingToPerform, "write_refused", "the directory is read-only", None))
                }
                // The listener upgrades when it can; reaching here means it cannot.
                Op::Extended { oid } if oid == OID_STARTTLS && session.channel.is_tls() => {
                    Some(refuse(ResultCode::OperationsError, "starttls_refused", "TLS is already established", None))
                }
                Op::Extended { oid } if oid == OID_STARTTLS => {
                    Some(refuse(ResultCode::Unavailable, "starttls_not_configured", "StartTLS is not configured", None))
                }
                Op::Extended { oid } => Some(refuse(
                    ResultCode::ProtocolError,
                    "unsupported_extended_operation",
                    "extended operation not supported",
                    Some(("oid", cut(oid))),
                )),
                _ => None,
            }
        };
    if let Some((pdu, fields)) = refused {
        record(deps.audit, events::REFUSED, fields).await;
        return Served { pdus: pdu.into_iter().collect(), after: After::Continue };
    }
    match msg.op {
        Op::Unbind => Served { pdus: Vec::new(), after: After::Close },
        Op::Abandon => Served { pdus: Vec::new(), after: After::Continue },
        Op::Bind(b) => bind(deps, session, &client, &cfg, msg.id, b, now).await,
        Op::Search(s) => {
            let limit = match s.time_limit {
                0 => cfg.time_limit_secs,
                n => cfg.time_limit_secs.min(n.unsigned_abs()),
            };
            let deadline = Instant::now() + Duration::from_secs(u64::from(limit));
            search(deps, session, &client, &cfg, msg.id, &s, deadline).await
        }
        Op::Write(_) | Op::Extended { .. } => unreachable_refused(msg.id),
    }
}

/// Handled above; kept total without a panic.
fn unreachable_refused(id: i32) -> Served {
    let pdu = proto::extended_response(id, ResultCode::OperationsError, "", None);
    Served { pdus: vec![pdu], after: After::Close }
}

// ─── Bind ───────────────────────────────────────────────────────────

#[derive(Default)]
struct BindSeen {
    method: &'static str,
    mechanism: Option<String>,
    login: Option<String>,
    entity_id: Option<String>,
    gate_reason: Option<&'static str>,
    uid: Option<u32>,
}

fn internal(what: &str, e: &RvError) -> (ResultCode, &'static str) {
    log::error!(target: "idp", "{}: cannot read the {what}: {e}", events::BIND);
    // Not `unavailable`: a client that sees it may fall back to cached
    // credentials. Every refused bind is invalidCredentials or stricter.
    (ResultCode::InvalidCredentials, "internal_error")
}

/// The bind decision. A successful simple bind needs a one-time passcode
/// minted for this client's environment and a gate allow, now.
#[maybe_async::maybe_async]
async fn decide_bind(
    deps: &LdapDeps<'_>,
    session: &Session,
    client: &LdapClient,
    layout: &Layout,
    b: &BindRequest,
    now: DateTime<Utc>,
    seen: &mut BindSeen,
) -> Result<Bound, (ResultCode, &'static str)> {
    if b.version != 3 {
        return Err((ResultCode::ProtocolError, "unsupported_version"));
    }
    let password = match &b.auth {
        BindAuth::Unsupported => {
            seen.method = "unsupported";
            return Err((ResultCode::AuthMethodNotSupported, "unsupported_method"));
        }
        BindAuth::Sasl { mechanism, credentials } => {
            seen.method = "sasl";
            seen.mechanism = Some(cut(mechanism));
            if !mechanism.eq_ignore_ascii_case("EXTERNAL") {
                return Err((ResultCode::AuthMethodNotSupported, "unsupported_mechanism"));
            }
            if !session.channel.is_tls() {
                return Err((ResultCode::InappropriateAuthentication, "external_without_tls"));
            }
            // The certificate is the identity; no other authorisation id.
            if !b.name.is_empty() || credentials.as_ref().is_some_and(|c| !c.is_empty()) {
                return Err((ResultCode::InvalidCredentials, "authzid_refused"));
            }
            return Ok(Bound::External);
        }
        BindAuth::Simple(password) => password,
    };
    seen.method = "simple";
    match (b.name.trim().is_empty(), password.is_empty()) {
        (true, true) => {
            seen.method = "anonymous";
            return Err((ResultCode::InappropriateAuthentication, "anonymous_bind"));
        }
        (false, true) => {
            // RFC 4513 §5.1.2: an unauthenticated bind must never succeed.
            seen.method = "unauthenticated";
            return Err((ResultCode::UnwillingToPerform, "unauthenticated_bind"));
        }
        (true, false) => return Err((ResultCode::InvalidCredentials, "bad_dn")),
        (false, false) => {}
    }
    let login = Dn::parse(&b.name)
        .ok()
        .and_then(|dn| layout.login_for_dn(&dn))
        .filter(|l| validate_login(l).is_ok())
        .ok_or((ResultCode::InvalidCredentials, "bad_dn"))?;
    seen.login = Some(login.clone());
    if !is_passcode_format(password) {
        return Err((ResultCode::InvalidCredentials, "bad_passcode"));
    }
    let entity_id = match deps.posix.entity_for_login(&login).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err((ResultCode::InvalidCredentials, "unknown_login")),
        Err(e) => return Err(internal("login index", &e)),
    };
    seen.entity_id = Some(entity_id.clone());
    let passcode = match deps.ldap.consume_passcode(&entity_id, password).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return Err((ResultCode::InvalidCredentials, "bad_passcode")),
        Err(e) => return Err(internal("passcode", &e)),
    };
    if passcode.expires_at <= now {
        return Err((ResultCode::InvalidCredentials, "passcode_expired"));
    }
    if passcode.entity_id != entity_id || passcode.login != login {
        log::error!(target: "idp", "{}: passcode under entity_id={entity_id} names another identity", events::BIND);
        return Err((ResultCode::InvalidCredentials, "internal_error"));
    }
    if passcode.environment != client.environment {
        return Err((ResultCode::InvalidCredentials, "environment_mismatch"));
    }
    // The gate decides, live, and records `idp.issue` / `idp.issue-denied`.
    let ask = IssueRequest {
        entity_id,
        environment: client.environment.clone(),
        roles: passcode.roles.clone(),
        // Directory clients are root-administered, like the idp mount.
        caller_namespace: String::new(),
        provider: PROVIDER.to_string(),
    };
    let grant = deps.authorizer.check(&ask, None).await.map_err(|d| {
        seen.gate_reason = Some(d.reason.as_str());
        (ResultCode::InvalidCredentials, "issue_denied")
    })?;
    seen.uid = Some(grant.uid);
    Ok(Bound::User(grant.login))
}

#[maybe_async::maybe_async]
async fn bind(
    deps: &LdapDeps<'_>,
    session: &mut Session,
    client: &LdapClient,
    cfg: &LdapConfig,
    id: i32,
    b: BindRequest,
    now: DateTime<Utc>,
) -> Served {
    // RFC 4511 §4.2.1: a bind starts from the anonymous state.
    session.bound = Bound::Anonymous;
    let mut seen = BindSeen::default();
    let decided = match cfg.layout() {
        Ok(layout) => decide_bind(deps, session, client, &layout, &b, now, &mut seen).await,
        Err(e) => {
            log::error!(target: "idp", "{}: stored base_dn is unusable: {e}", events::BIND);
            Err((ResultCode::InvalidCredentials, "internal_error"))
        }
    };
    drop(b);
    let mut f = session_fields(session, Some(&client.environment), "bind");
    f.insert("method".into(), seen.method.into());
    f.insert("mechanism".into(), seen.mechanism.clone().into());
    // Only a value that passed the login rules; never the password.
    f.insert("login".into(), seen.login.clone().into());
    f.insert("entity_id".into(), seen.entity_id.clone().into());
    let (code, message) = match decided {
        Ok(bound) => {
            f.insert("decision".into(), "success".into());
            f.insert("reason".into(), Value::Null);
            f.insert("uid".into(), seen.uid.into());
            // A bind nobody can attribute does not succeed.
            match deps.audit.record(events::BIND, f).await {
                Ok(()) => {
                    session.bound = bound;
                    (ResultCode::Success, "")
                }
                Err(e) => {
                    log::error!(target: "idp", "{}: audit refused the event, refusing the bind: {e}", events::BIND);
                    (ResultCode::InvalidCredentials, "invalid credentials")
                }
            }
        }
        Err((code, reason)) => {
            f.insert("decision".into(), "refused".into());
            f.insert("reason".into(), reason.into());
            f.insert("gate_reason".into(), seen.gate_reason.into());
            record(deps.audit, events::BIND, f).await;
            let message = match code {
                ResultCode::InappropriateAuthentication | ResultCode::UnwillingToPerform => {
                    "bind with a passcode, or with SASL EXTERNAL over TLS"
                }
                ResultCode::AuthMethodNotSupported => "only simple binds and SASL EXTERNAL are supported",
                ResultCode::ProtocolError => "only LDAPv3 is supported",
                _ => "invalid credentials",
            };
            (code, message)
        }
    };
    Served { pdus: vec![proto::result(id, tag::BIND_RESPONSE, code, "", message)], after: After::Continue }
}

// ─── Search ─────────────────────────────────────────────────────────

/// Why a search stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    Size,
    Time,
    /// The client's environment cannot be served (retired, namespace gone).
    Environment(DenyReason),
    Unavailable,
    NoSuchObject,
    InvalidDn,
}

/// The gate's decision per identity, asked at most once per search.
struct Visibility<'a> {
    view: &'a dyn DirectoryView,
    environment: &'a str,
    memo: HashMap<String, Option<IssueGrant>>,
    hidden: usize,
    deadline: Instant,
}

#[maybe_async::maybe_async]
impl Visibility<'_> {
    async fn grant(&mut self, entity_id: &str) -> Result<Option<IssueGrant>, Halt> {
        if let Some(known) = self.memo.get(entity_id) {
            return Ok(known.clone());
        }
        if Instant::now() >= self.deadline {
            return Err(Halt::Time);
        }
        let ask = IssueRequest {
            entity_id: entity_id.to_string(),
            environment: self.environment.to_string(),
            roles: None,
            caller_namespace: String::new(),
            provider: PROVIDER.to_string(),
        };
        let seen = match self.view.view(&ask).await {
            Ok(g) => Some(g),
            // Every reason is named, so a new one needs a decision here.
            Err(d) => match d.reason {
                DenyReason::NoIdentity
                | DenyReason::IdentityDisabled
                | DenyReason::IdentityRemoved
                | DenyReason::NotEntitled
                | DenyReason::EntitlementExpired
                | DenyReason::RoleNotEntitled
                | DenyReason::UnknownRole => {
                    self.hidden += 1;
                    None
                }
                DenyReason::UnknownEnvironment
                | DenyReason::EnvironmentRetired
                | DenyReason::NamespaceMissing
                | DenyReason::NamespaceReplaced
                | DenyReason::NamespaceMismatch => return Err(Halt::Environment(d.reason)),
                DenyReason::InvalidRequest
                | DenyReason::StoreUnavailable
                | DenyReason::StoreError
                | DenyReason::NamespaceUnavailable
                | DenyReason::AuditFailed => {
                    log::error!(target: "idp", "{}: visibility of {entity_id}: {}", events::SEARCH, d.reason.as_str());
                    return Err(Halt::Unavailable);
                }
            },
        };
        self.memo.insert(entity_id.to_string(), seen.clone());
        Ok(seen)
    }
}

/// What a search returns before encoding.
pub(crate) struct SearchOutcome {
    pub entries: Vec<Entry>,
    pub code: ResultCode,
    pub hidden: usize,
}

struct Found<'a> {
    filter: &'a filter::Filter,
    base: Dn,
    scope: Scope,
    cap: usize,
    entries: Vec<Entry>,
    base_found: bool,
}

impl Found<'_> {
    fn in_scope(&self, dn: &Dn) -> bool {
        match self.scope {
            Scope::Base => *dn == self.base,
            Scope::One => dn.parent().as_ref() == Some(&self.base),
            Scope::Sub => dn.within(&self.base),
        }
    }

    /// Whether a child of `parent` can be in scope.
    fn touches(&self, parent: &Dn) -> bool {
        let base_parent = self.base.parent();
        match self.scope {
            Scope::Base => base_parent.as_ref() == Some(parent),
            Scope::One => self.base == *parent,
            Scope::Sub => parent.within(&self.base) || base_parent.as_ref() == Some(parent),
        }
    }

    /// Whether a provisional entry needs its visibility asked: it may match,
    /// or it is the base, whose existence decides noSuchObject.
    fn worth_asking(&self, e: &Entry) -> bool {
        e.dn == self.base || (self.in_scope(&e.dn) && self.filter.evaluate(e) == Some(true))
    }

    fn offer(&mut self, e: Entry) -> Result<(), Halt> {
        if e.dn == self.base {
            self.base_found = true;
        }
        if !self.in_scope(&e.dn) || self.filter.evaluate(&e) != Some(true) {
            return Ok(());
        }
        if self.entries.len() >= self.cap {
            return Err(Halt::Size);
        }
        self.entries.push(e);
        Ok(())
    }
}

#[maybe_async::maybe_async]
async fn identity_by_login(posix: &PosixStore, raw: &[u8]) -> Result<Vec<WorkforceIdentity>, Halt> {
    let Some(login) = std::str::from_utf8(raw).ok().map(str::to_ascii_lowercase) else {
        return Ok(Vec::new());
    };
    if validate_login(&login).is_err() {
        return Ok(Vec::new());
    }
    let unavailable = |e: RvError| {
        log::error!(target: "idp", "{}: cannot read the identity store: {e}", events::SEARCH);
        Halt::Unavailable
    };
    let Some(entity_id) = posix.entity_for_login(&login).await.map_err(unavailable)? else {
        return Ok(Vec::new());
    };
    Ok(posix.get_identity(&entity_id).await.map_err(unavailable)?.into_iter().collect())
}

#[maybe_async::maybe_async]
async fn all_identities(posix: &PosixStore) -> Result<Vec<WorkforceIdentity>, Halt> {
    posix.list_identities().await.map_err(|e| {
        log::error!(target: "idp", "{}: cannot list the identity store: {e}", events::SEARCH);
        Halt::Unavailable
    })
}

fn active_by_login(mut ids: Vec<WorkforceIdentity>) -> Vec<WorkforceIdentity> {
    ids.retain(|i| i.state == IdentityState::Active);
    ids.sort_by(|a, b| a.login.cmp(&b.login));
    ids
}

#[maybe_async::maybe_async]
async fn collect(
    posix: &PosixStore,
    layout: &Layout,
    vis: &mut Visibility<'_>,
    found: &mut Found<'_>,
) -> Result<(), Halt> {
    for e in layout.structural() {
        found.offer(e)?;
    }
    let (people, groups) = (layout.people(), layout.groups());
    if found.touches(&people) {
        let base_is_person = found.base.parent().as_ref() == Some(&people);
        let candidates = match (base_is_person, found.base.leaf(), found.filter.uid_hint()) {
            (true, Some(("uid", login)), _) => identity_by_login(posix, login.as_bytes()).await?,
            (true, _, _) => Vec::new(),
            (false, _, Some(login)) => identity_by_login(posix, login).await?,
            (false, _, None) => all_identities(posix).await?,
        };
        for ident in active_by_login(candidates) {
            if !found.worth_asking(&layout.person(&Person::from(&ident))) {
                continue;
            }
            if let Some(g) = vis.grant(&ident.entity_id).await? {
                found.offer(layout.person(&Person::from(&g)))?;
            }
        }
    }
    if found.touches(&groups) {
        let everyone = all_identities(posix).await?;
        let private: HashSet<u32> = everyone.iter().map(|i| i.primary_gid).collect();
        let active = active_by_login(everyone);
        for ident in &active {
            if !found.worth_asking(&layout.private_group(&Person::from(ident))) {
                continue;
            }
            if let Some(g) = vis.grant(&ident.entity_id).await? {
                found.offer(layout.private_group(&Person::from(&g)))?;
            }
        }
        let mut holders: BTreeMap<u32, Vec<&WorkforceIdentity>> = BTreeMap::new();
        for ident in &active {
            for gid in &ident.gids {
                if private.contains(gid) {
                    // Phase 1 refuses this; never serve two groups per gid.
                    log::warn!(target: "idp", "{}: gid {gid} is also a primary gid; not served", events::SEARCH);
                    continue;
                }
                holders.entry(*gid).or_default().push(ident);
            }
        }
        for (gid, members) in holders {
            let dn = groups.child("cn", &supplementary_group_name(gid));
            if dn != found.base && !found.in_scope(&dn) {
                continue;
            }
            let mut logins = Vec::new();
            for m in members {
                if let Some(g) = vis.grant(&m.entity_id).await? {
                    if g.gids.contains(&gid) {
                        logins.push(g.login);
                    }
                }
            }
            if !logins.is_empty() {
                logins.sort();
                found.offer(layout.supplementary_group(gid, logins))?;
            }
        }
    }
    if !found.base_found {
        return Err(Halt::NoSuchObject);
    }
    Ok(())
}

/// Evaluate a search for a client of `environment`. Pure apart from the
/// reads; the caller encodes and audits.
#[maybe_async::maybe_async]
pub(crate) async fn run_search(
    posix: &PosixStore,
    view: &dyn DirectoryView,
    environment: &str,
    cfg: &LdapConfig,
    req: &SearchRequest,
    tls: bool,
    deadline: Instant,
) -> SearchOutcome {
    let mut vis = Visibility { view, environment, memo: HashMap::new(), hidden: 0, deadline };
    let cap = match req.size_limit {
        0 => cfg.size_limit as usize,
        n => (n.unsigned_abs() as usize).min(cfg.size_limit as usize),
    };
    let halted: Result<Vec<Entry>, (Halt, Vec<Entry>)> = 'search: {
        let layout = match cfg.layout() {
            Ok(l) => l,
            Err(e) => {
                log::error!(target: "idp", "{}: stored base_dn is unusable: {e}", events::SEARCH);
                break 'search Err((Halt::Unavailable, Vec::new()));
            }
        };
        let Ok(parsed) = Dn::parse(&req.base) else {
            break 'search Err((Halt::InvalidDn, Vec::new()));
        };
        let (base, scope) = match (parsed.is_root(), req.scope) {
            (true, Scope::Base) => {
                let dse = layout.root_dse(tls, cfg.ldap_listen.is_some() && cfg.has_tls());
                let mut entries = Vec::new();
                if req.filter.evaluate(&dse) == Some(true) && cap > 0 {
                    entries.push(dse);
                }
                return SearchOutcome { entries, code: ResultCode::Success, hidden: 0 };
            }
            (true, Scope::One) => (layout.base.clone(), Scope::Base),
            (true, Scope::Sub) => (layout.base.clone(), Scope::Sub),
            (false, scope) => (parsed, scope),
        };
        if !base.within(&layout.base) {
            break 'search Err((Halt::NoSuchObject, Vec::new()));
        }
        let mut found = Found { filter: &req.filter, base, scope, cap, entries: Vec::new(), base_found: false };
        let r = collect(posix, &layout, &mut vis, &mut found).await;
        let entries = std::mem::take(&mut found.entries);
        match r {
            Ok(()) => Ok(entries),
            Err(h) => Err((h, entries)),
        }
    };
    let hidden = vis.hidden;
    match halted {
        Ok(entries) => SearchOutcome { entries, code: ResultCode::Success, hidden },
        Err((halt, entries)) => {
            let (code, keep) = match halt {
                Halt::Size => (ResultCode::SizeLimitExceeded, true),
                Halt::Time => (ResultCode::TimeLimitExceeded, true),
                Halt::Environment(_) => (ResultCode::InsufficientAccessRights, false),
                Halt::Unavailable => (ResultCode::Unavailable, false),
                Halt::NoSuchObject => (ResultCode::NoSuchObject, false),
                Halt::InvalidDn => (ResultCode::InvalidDnSyntax, false),
            };
            SearchOutcome { entries: if keep { entries } else { Vec::new() }, code, hidden }
        }
    }
}

fn search_message(code: ResultCode) -> &'static str {
    match code {
        ResultCode::Success => "",
        ResultCode::SizeLimitExceeded => "size limit exceeded",
        ResultCode::TimeLimitExceeded => "time limit exceeded",
        ResultCode::InsufficientAccessRights => "this client's environment cannot be served",
        ResultCode::NoSuchObject => "no such object",
        ResultCode::InvalidDnSyntax => "invalid DN",
        _ => "the directory is unavailable",
    }
}

#[maybe_async::maybe_async]
async fn search(
    deps: &LdapDeps<'_>,
    session: &Session,
    client: &LdapClient,
    cfg: &LdapConfig,
    id: i32,
    req: &SearchRequest,
    deadline: Instant,
) -> Served {
    let outcome =
        run_search(deps.posix, deps.view, &client.environment, cfg, req, session.channel.is_tls(), deadline).await;
    let mut pdus: Vec<Vec<u8>> = outcome
        .entries
        .iter()
        .map(|e| proto::search_entry(id, &e.dn.to_string(), &e.select(&req.attributes), req.types_only))
        .collect();
    let mut f = session_fields(session, Some(&client.environment), "search");
    let disclosed = !pdus.is_empty();
    f.insert("decision".into(), if outcome.code == ResultCode::Success { "allow" } else { "refused" }.into());
    f.insert("result".into(), outcome.code.as_str().into());
    let base = Dn::parse(&req.base).map(|d| cut(&d.to_string())).unwrap_or_else(|_| "<invalid>".into());
    f.insert("base".into(), base.into());
    f.insert("scope".into(), req.scope.as_str().into());
    f.insert("entries".into(), outcome.entries.len().into());
    f.insert("hidden".into(), outcome.hidden.into());
    // Entries nobody can attribute are not disclosed.
    if let Err(e) = deps.audit.record(events::SEARCH, f).await {
        log::error!(target: "idp", "{}: audit refused the event: {e}", events::SEARCH);
        if disclosed {
            let done = proto::result(id, tag::SEARCH_RESULT_DONE, ResultCode::Unavailable, "", "audit unavailable");
            return Served { pdus: vec![done], after: After::Continue };
        }
    }
    pdus.push(proto::result(id, tag::SEARCH_RESULT_DONE, outcome.code, "", search_message(outcome.code)));
    Served { pdus, after: After::Continue }
}

/// What the listeners are bound to right now, for `v2/idp/ldap/config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerStatus {
    pub ldaps: Option<std::net::SocketAddr>,
    pub ldap: Option<std::net::SocketAddr>,
    pub last_error: Option<String>,
}

impl ListenerStatus {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ldaps".into(), self.ldaps.map(|a| a.to_string()).into());
        m.insert("ldap".into(), self.ldap.map(|a| a.to_string()).into());
        m.insert("last_error".into(), self.last_error.clone().into());
        Value::Object(m)
    }
}

/// The listeners' handle, shared by the module and the backend; started
/// once from `Module::start_background`, as the RADIUS supervisor is.
#[derive(Default)]
pub struct LdapRuntime {
    pub(crate) notify: tokio::sync::Notify,
    pub(crate) started: std::sync::atomic::AtomicBool,
    pub(crate) status: std::sync::Mutex<ListenerStatus>,
}

impl LdapRuntime {
    pub fn reconcile_soon(&self) {
        self.notify.notify_one();
    }

    pub fn status(&self) -> ListenerStatus {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }
}
