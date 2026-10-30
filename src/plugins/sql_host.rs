//! ABI 1.4 caller-bound host calls for the SQL browser
//! (features/sql-browser.md §9.2, §5.4). Each is evaluated against the caller
//! of the invocation in flight and is refused outside one.
//!
//! Check order, the same for every call: manifest capability (`forbidden`),
//! invocation caller (`no_invocation`), core, admin grant (`not_granted`),
//! strict parameters (`bad_request`), then the call's own rules.

use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::invocation::InvocationCaller;
use super::manifest::{PluginManifest, ResourceCredentialKind};
use super::sql_grants::{self, SqlGrantKind};
use crate::{
    audit::AuditEntry,
    errors::RvError,
    kernel_api::{
        namespace::namespace_header_from_map,
        policy::{canonical_resource, PolicyGate, SqlCapability, SqlCheck, SqlPurpose, SqlTarget, SqlVerdict},
        VaultCtx,
    },
    logical::Request,
};

/// Error codes of these calls, as sent in `host_reply.error` (`code` or
/// `code: detail`). The detail never carries a credential or a token.
pub mod codes {
    pub const FORBIDDEN: &str = "forbidden";
    pub const NO_INVOCATION: &str = "no_invocation";
    pub const NO_CORE: &str = "no core";
    pub const NOT_GRANTED: &str = "not_granted";
    pub const BAD_REQUEST: &str = "bad_request";
    pub const NO_SQL_PRIVILEGE: &str = "no_sql_privilege";
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_AVAILABLE: &str = "not_available";
    pub const REFUSED: &str = "refused";
    pub const INTERNAL: &str = "internal";
}

/// The host-call methods this module serves.
pub const METHODS: [&str; 4] =
    ["resource_sql_target", "resource_sql_authorize", "resource_sql_credential", "connect_ticket_redeem"];

/// The audit event of a credential release (§11).
pub const RELEASE_EVENT: &str = "resource-credential-release";

const MAX_PROFILE_LEN: usize = 128;
const MAX_SESSION_REF_LEN: usize = 128;
const MAX_TICKET_LEN: usize = 256;

fn err(code: &str, detail: impl std::fmt::Display) -> String {
    format!("{code}: {detail}")
}

// ── the resource-engine seam ────────────────────────────────────────────

/// A database endpoint, `host:port`. The resource engine's parser: the
/// profile's endpoint and the secret's binding are read by the same code.
pub use crate::modules::resource::sql_profile::SqlEndpoint;
/// The step-up action's canonical form and its redemption: the resource
/// engine owns the ticket store, so the action binding is decided there.
use crate::modules::resource::connect_mfa::{canonical_sql_action, redeem_sql_action_ticket};

/// What the host needs to decide one release (§5.4), read by the resource
/// engine. Zeroized on drop.
pub struct SqlReleaseMaterial {
    /// The profile's stored `protocol`.
    pub protocol: String,
    /// The endpoint the plugin will dial, resolved from the profile.
    pub endpoint: SqlEndpoint,
    /// The effective Connect transport and the tier that set it.
    pub transport: String,
    pub transport_source: String,
    /// The stored secret serving the profile.
    pub secret_id: String,
    /// The secret's reserved `sql_endpoint` value, as stored.
    pub sql_endpoint: Option<Value>,
    pub username: String,
    pub password: Zeroizing<String>,
    /// The profile's `sql.require_mfa`: the release then needs a ticket
    /// redeemed for this profile by the same invocation.
    pub require_mfa: bool,
}

/// The resource engine's half of `resource_sql_target` and
/// `resource_sql_credential`. Production installs
/// [`super::sql_resource::ResourceEngineSqlSource`] at assembly; a host
/// without one uses [`UnavailableSqlSource`], which refuses explicitly.
pub trait SqlResourceSource: Send + Sync {
    /// Engine, endpoint fields and the strictly parsed `sql` profiles.
    fn sql_target<'a>(&'a self, core: &'a dyn VaultCtx, namespace: &'a str, resource: &'a str) -> SqlFuture<'a, Value>;

    /// One `sql` profile with its credential. Refuses a profile that does not
    /// parse strictly or does not belong to the resource.
    fn sql_release_material<'a>(
        &'a self,
        core: &'a dyn VaultCtx,
        namespace: &'a str,
        resource: &'a str,
        profile: &'a str,
    ) -> SqlFuture<'a, SqlReleaseMaterial>;
}

/// What a [`SqlResourceSource`] returns.
pub type SqlFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, RvError>> + Send + 'a>>;

/// The seam's default: no SQL protocol on this server yet.
pub struct UnavailableSqlSource;

fn unavailable() -> RvError {
    RvError::ErrResponseStatus(
        501,
        "the resource engine's `sql` protocol is not available on this server yet".to_string(),
    )
}

impl SqlResourceSource for UnavailableSqlSource {
    fn sql_target<'a>(&'a self, _: &'a dyn VaultCtx, _: &'a str, _: &'a str) -> SqlFuture<'a, Value> {
        Box::pin(async { Err(unavailable()) })
    }
    fn sql_release_material<'a>(
        &'a self,
        _: &'a dyn VaultCtx,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> SqlFuture<'a, SqlReleaseMaterial> {
        Box::pin(async { Err(unavailable()) })
    }
}

static SQL_SOURCE: OnceLock<Arc<dyn SqlResourceSource>> = OnceLock::new();

/// Install the resource engine's implementation. First call wins.
pub fn set_sql_resource_source(source: Arc<dyn SqlResourceSource>) {
    let _ = SQL_SOURCE.set(source);
}

fn sql_resource_source() -> Arc<dyn SqlResourceSource> {
    SQL_SOURCE.get().cloned().unwrap_or_else(|| Arc::new(UnavailableSqlSource))
}

// ── release rules (§5.4 rules 3–5) ──────────────────────────────────────

/// Why a release was refused once the material was read. Rules 1–2 (grant,
/// caller privilege) are checked before the material is read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// Rule 3: the profile's protocol is not `sql`.
    ProfileNotSql,
    /// Rule 4: the effective transport is `rustion-required`.
    RustionRequired { source: String },
    /// Rule 4: a transport this host does not know (fail closed).
    TransportUnknown,
    /// Rule 5: the secret names no endpoint it may be sent to.
    EndpointUnbound,
    /// Rule 5: the secret's `sql_endpoint` does not parse.
    EndpointInvalid,
    /// Rule 5: the profile's endpoint is not one the secret names.
    EndpointMismatch,
    /// `sql.require_mfa`: no connect ticket was redeemed for this profile
    /// in this invocation (§8.3).
    MfaRequired,
}

impl ReleaseRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            ReleaseRefusal::ProfileNotSql => "profile_not_sql",
            ReleaseRefusal::RustionRequired { .. } => "rustion_required",
            ReleaseRefusal::TransportUnknown => "transport_unknown",
            ReleaseRefusal::EndpointUnbound => "endpoint_unbound",
            ReleaseRefusal::EndpointInvalid => "endpoint_invalid",
            ReleaseRefusal::EndpointMismatch => "endpoint_mismatch",
            ReleaseRefusal::MfaRequired => "mfa_required",
        }
    }

    fn message(&self) -> String {
        match self {
            ReleaseRefusal::ProfileNotSql => "the connection profile is not a `sql` profile".into(),
            ReleaseRefusal::RustionRequired { source } => {
                format!("the resource's Connect transport is `rustion-required` (set by {source}); SQL sessions are refused")
            }
            ReleaseRefusal::TransportUnknown => "the resource's Connect transport is not recognised".into(),
            ReleaseRefusal::EndpointUnbound => {
                "the credential is not bound to an endpoint; bind it (`sql_endpoint`) before the SQL browser may use it"
                    .into()
            }
            ReleaseRefusal::EndpointInvalid => "the credential's `sql_endpoint` is malformed".into(),
            ReleaseRefusal::EndpointMismatch => {
                "the profile's endpoint is not one the credential is bound to (`sql_endpoint`)".into()
            }
            ReleaseRefusal::MfaRequired => "the profile requires MFA re-validation: redeem the operator's connect \
                                            ticket (`connect_ticket_redeem`) in the same invocation first"
                .into(),
        }
    }
}

/// Endpoints a secret's `sql_endpoint` names: `"host:port"` or a list of
/// them. Absent or empty is unbound; any malformed entry invalidates all.
pub fn bound_endpoints(value: Option<&Value>) -> Result<Vec<SqlEndpoint>, ReleaseRefusal> {
    use crate::modules::resource::sql_profile::{bound_endpoints as parse_binding, BindingError};
    parse_binding(value).map_err(|e| match e {
        BindingError::Unbound => ReleaseRefusal::EndpointUnbound,
        BindingError::Invalid => ReleaseRefusal::EndpointInvalid,
    })
}

/// Rules 3–5 over the material. Pure, so the testkit can mirror it.
pub fn check_release(m: &SqlReleaseMaterial) -> Result<(), ReleaseRefusal> {
    if m.protocol != "sql" {
        return Err(ReleaseRefusal::ProfileNotSql);
    }
    match m.transport.as_str() {
        "direct" | "rustion-preferred" => {}
        "rustion-required" => return Err(ReleaseRefusal::RustionRequired { source: m.transport_source.clone() }),
        _ => return Err(ReleaseRefusal::TransportUnknown),
    }
    let bound = bound_endpoints(m.sql_endpoint.as_ref())?;
    if bound.iter().any(|b| b.matches(&m.endpoint)) {
        Ok(())
    } else {
        Err(ReleaseRefusal::EndpointMismatch)
    }
}

// ── parameters ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetParams {
    resource: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeParams {
    resource: String,
    checks: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialParams {
    resource: String,
    profile: String,
    session_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketParams {
    resource: String,
    profile: String,
    ticket: String,
    #[serde(default)]
    action: Option<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(params: &Value) -> Result<T, String> {
    serde_json::from_value(params.clone()).map_err(|e| err(codes::BAD_REQUEST, e))
}

fn resource_name(raw: &str) -> Result<String, String> {
    canonical_resource(raw).map_err(|_| err(codes::BAD_REQUEST, "invalid resource name"))
}

fn bounded_text(field: &str, s: &str, max: usize) -> Result<(), String> {
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(err(codes::BAD_REQUEST, format!("`{field}` must be 1-{max} printable characters")));
    }
    Ok(())
}

/// One check of `resource_sql_authorize`:
/// `{"capability": "sql_select", "target": "server" | {"catalog","schema","object"}}`.
pub fn parse_check(v: &Value) -> Result<SqlCheck, String> {
    let bad = |m: &str| err(codes::BAD_REQUEST, m);
    let o = v.as_object().ok_or_else(|| bad("a check must be an object"))?;
    if o.keys().any(|k| k != "capability" && k != "target") {
        return Err(bad("a check has only `capability` and `target`"));
    }
    let cap = o.get("capability").and_then(Value::as_str).ok_or_else(|| bad("a check needs `capability`"))?;
    let capability = SqlCapability::parse(cap).ok_or_else(|| bad("unknown SQL capability"))?;
    let target = match o.get("target") {
        Some(Value::String(s)) if s == "server" => SqlTarget::Server,
        Some(Value::Object(t)) => {
            if t.len() != 3 {
                return Err(bad("an object target has exactly `catalog`, `schema` and `object`"));
            }
            let f = |k: &str| t.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| bad("bad target"));
            SqlTarget::Object { catalog: f("catalog")?, schema: f("schema")?, object: f("object")? }
        }
        _ => return Err(bad("`target` is \"server\" or {catalog, schema, object}")),
    };
    Ok(SqlCheck { capability, target })
}

fn verdict_json(v: &SqlVerdict) -> Value {
    let target = match &v.target {
        SqlTarget::Server => json!("server"),
        SqlTarget::Object { catalog, schema, object } => {
            json!({"catalog": catalog, "schema": schema, "object": object})
        }
    };
    json!({
        "capability": v.capability.as_str(),
        "target": target,
        "path": v.path,
        "allowed": v.allowed,
        "denied_by_deny": v.denied_by_deny,
    })
}

// ── shared steps ────────────────────────────────────────────────────────

/// Map a kernel error to a reply code. Client errors keep their message;
/// anything else is logged and answered `internal`.
fn kernel_error(method: &str, e: RvError) -> String {
    match e {
        RvError::ErrResponseStatus(400, m) => err(codes::BAD_REQUEST, m),
        RvError::ErrResponseStatus(401 | 403 | 409 | 422, m) => err(codes::REFUSED, m),
        RvError::ErrResponseStatus(404, m) => err(codes::NOT_FOUND, m),
        RvError::ErrResponseStatus(501 | 503, m) => err(codes::NOT_AVAILABLE, m),
        other => {
            log::warn!(target: "plugin", "host call {method} failed: {other}");
            codes::INTERNAL.to_string()
        }
    }
}

/// The namespace the caller's request addresses (`""` = root). A named
/// namespace that does not resolve is an error, never root.
async fn caller_namespace(core: &dyn VaultCtx, req: &Request) -> Result<String, String> {
    let raw = req.namespace_path.clone().or_else(|| namespace_header_from_map(req.headers.as_ref())).unwrap_or_default();
    let raw = raw.trim().trim_matches('/');
    if raw.is_empty() {
        return Ok(String::new());
    }
    let registry = core.namespaces().ok_or_else(|| err(codes::NOT_AVAILABLE, "no namespace registry"))?;
    match registry.resolve(raw).await {
        Ok(Some(ns)) => Ok(ns.path),
        Ok(None) => Err(err(codes::BAD_REQUEST, "unknown namespace")),
        Err(e) => Err(kernel_error("namespace", e)),
    }
}

/// Rule 2: the caller holds at least one SQL capability on
/// `…/sql/server`. Returns the names held. A `Display` probe answers the
/// common case without writing anything; a refusal is re-evaluated under
/// `Enforce` so every refused check lands in the denial store, and that
/// second answer decides.
async fn require_any_sql_privilege(
    gate: &dyn PolicyGate,
    req: &Request,
    plugin: &str,
    resource: &str,
    method: &str,
) -> Result<Vec<&'static str>, String> {
    let checks: Vec<SqlCheck> =
        SqlCapability::ALL.iter().map(|c| SqlCheck { capability: *c, target: SqlTarget::Server }).collect();
    let held = |vs: &[SqlVerdict]| vs.iter().filter(|v| v.allowed).map(|v| v.capability.as_str()).collect::<Vec<_>>();
    let shown = gate.sql_privileges(req, SqlPurpose::Display, resource, &checks).await.map_err(|e| kernel_error(method, e))?;
    if !held(&shown).is_empty() {
        return Ok(held(&shown));
    }
    let enforced = gate
        .sql_privileges(req, SqlPurpose::Enforce { plugin }, resource, &checks)
        .await
        .map_err(|e| kernel_error(method, e))?;
    let names = held(&enforced);
    if names.is_empty() {
        return Err(err(codes::NO_SQL_PRIVILEGE, "the caller holds no SQL privilege on this resource"));
    }
    Ok(names)
}

/// Steps 1–4 of every call: capability, caller, core, live grant.
async fn preflight<'a>(
    manifest: &PluginManifest,
    core: Option<&'a Arc<dyn VaultCtx>>,
    caller: Option<&'a InvocationCaller>,
    kind: SqlGrantKind,
) -> Result<(&'a Arc<dyn VaultCtx>, &'a InvocationCaller), String> {
    if !kind.requested_by(manifest) {
        return Err(codes::FORBIDDEN.to_string());
    }
    let caller = caller.ok_or_else(|| codes::NO_INVOCATION.to_string())?;
    let core = core.ok_or_else(|| codes::NO_CORE.to_string())?;
    if !sql_grants::is_live(core.barrier().as_storage(), kind, manifest).await {
        return Err(err(codes::NOT_GRANTED, format!("the `{}` grant is absent or voided", kind.segment())));
    }
    Ok((core, caller))
}

fn policy_gate(core: &dyn VaultCtx) -> Result<Arc<dyn PolicyGate>, String> {
    core.policy().ok_or_else(|| err(codes::NOT_AVAILABLE, "no policy gate"))
}

// ── dispatch ────────────────────────────────────────────────────────────

/// Serve one of [`METHODS`]. `caller` is the invocation in flight, or
/// `None` outside one.
pub async fn handle(
    manifest: &PluginManifest,
    core: Option<&Arc<dyn VaultCtx>>,
    method: &str,
    params: &Value,
    caller: Option<&InvocationCaller>,
) -> Result<Value, String> {
    match method {
        "resource_sql_target" => sql_target(manifest, core, params, caller, sql_resource_source().as_ref()).await,
        "resource_sql_authorize" => sql_authorize(manifest, core, params, caller).await,
        "resource_sql_credential" => {
            sql_credential(manifest, core, params, caller, sql_resource_source().as_ref()).await
        }
        "connect_ticket_redeem" => ticket_redeem(manifest, core, params, caller).await,
        _ => Err("unknown_method".to_string()),
    }
}

async fn sql_target(
    manifest: &PluginManifest,
    core: Option<&Arc<dyn VaultCtx>>,
    params: &Value,
    caller: Option<&InvocationCaller>,
    source: &dyn SqlResourceSource,
) -> Result<Value, String> {
    let (core, caller) = preflight(manifest, core, caller, SqlGrantKind::SqlGate).await?;
    let p: TargetParams = parse(params)?;
    let resource = resource_name(&p.resource)?;
    let req = caller.request();
    let gate = policy_gate(core.as_ref())?;
    let held = require_any_sql_privilege(gate.as_ref(), req, &manifest.name, &resource, "resource_sql_target").await?;
    let ns = caller_namespace(core.as_ref(), req).await?;
    let target =
        source.sql_target(core.as_ref(), &ns, &resource).await.map_err(|e| kernel_error("resource_sql_target", e))?;
    Ok(json!({ "namespace": ns, "resource": resource, "privileges": held, "target": target }))
}

async fn sql_authorize(
    manifest: &PluginManifest,
    core: Option<&Arc<dyn VaultCtx>>,
    params: &Value,
    caller: Option<&InvocationCaller>,
) -> Result<Value, String> {
    let (core, caller) = preflight(manifest, core, caller, SqlGrantKind::SqlGate).await?;
    let p: AuthorizeParams = parse(params)?;
    let resource = resource_name(&p.resource)?;
    if p.checks.len() > crate::kernel_api::policy::SQL_MAX_CHECKS {
        return Err(err(codes::BAD_REQUEST, "too many checks in one batch"));
    }
    let checks = p.checks.iter().map(parse_check).collect::<Result<Vec<_>, _>>()?;
    let gate = policy_gate(core.as_ref())?;
    let verdicts = gate
        .sql_privileges(caller.request(), SqlPurpose::Enforce { plugin: &manifest.name }, &resource, &checks)
        .await
        .map_err(|e| kernel_error("resource_sql_authorize", e))?;
    Ok(json!({ "resource": resource, "verdicts": verdicts.iter().map(verdict_json).collect::<Vec<_>>() }))
}

async fn sql_credential(
    manifest: &PluginManifest,
    core: Option<&Arc<dyn VaultCtx>>,
    params: &Value,
    caller: Option<&InvocationCaller>,
    source: &dyn SqlResourceSource,
) -> Result<Value, String> {
    if !manifest.capabilities.requests_resource_credentials(ResourceCredentialKind::Sql) {
        return Err(codes::FORBIDDEN.to_string());
    }
    let caller = caller.ok_or_else(|| codes::NO_INVOCATION.to_string())?;
    let core = core.ok_or_else(|| codes::NO_CORE.to_string())?;
    let mut audit = ReleaseAudit::new(manifest, params);
    let result = release(manifest, core, params, caller, source, &mut audit).await;
    audit.emit(core.as_ref(), caller, &result).await;
    result
}

async fn release(
    manifest: &PluginManifest,
    core: &Arc<dyn VaultCtx>,
    params: &Value,
    caller: &InvocationCaller,
    source: &dyn SqlResourceSource,
    audit: &mut ReleaseAudit,
) -> Result<Value, String> {
    let kind = SqlGrantKind::ResourceCredentials;
    if !sql_grants::is_live(core.barrier().as_storage(), kind, manifest).await {
        return Err(err(codes::NOT_GRANTED, "the `resource-credentials` grant is absent or voided"));
    }
    let p: CredentialParams = parse(params)?;
    let resource = resource_name(&p.resource)?;
    bounded_text("profile", &p.profile, MAX_PROFILE_LEN)?;
    bounded_text("session_ref", &p.session_ref, MAX_SESSION_REF_LEN)?;
    let req = caller.request();
    let gate = policy_gate(core.as_ref())?;
    require_any_sql_privilege(gate.as_ref(), req, &manifest.name, &resource, "resource_sql_credential").await?;
    let ns = caller_namespace(core.as_ref(), req).await?;
    let material = source
        .sql_release_material(core.as_ref(), &ns, &resource, &p.profile)
        .await
        .map_err(|e| kernel_error("resource_sql_credential", e))?;
    audit.secret_id = material.secret_id.clone();
    let refuse = |r: ReleaseRefusal, audit: &mut ReleaseAudit| {
        audit.reason = r.reason().to_string();
        err(codes::REFUSED, format!("{}: {}", r.reason(), r.message()))
    };
    check_release(&material).map_err(|r| refuse(r, audit))?;
    // Last, so a refusal the operator can fix (binding, transport) does not
    // spend the redemption.
    if material.require_mfa && !caller.take_mfa_redemption(&ns, &resource, &p.profile) {
        return Err(refuse(ReleaseRefusal::MfaRequired, audit));
    }
    // Moved, not copied: the reply is the credential's only other home, and
    // the writer zeroizes it once sent.
    let SqlReleaseMaterial { username, password, endpoint, secret_id, .. } = material;
    let mut reply = Map::new();
    reply.insert("resource".into(), json!(resource));
    reply.insert("profile".into(), json!(p.profile));
    reply.insert("secret_id".into(), json!(secret_id));
    reply.insert("endpoint".into(), json!(endpoint.to_string()));
    reply.insert("username".into(), json!(username));
    reply.insert("password".into(), Value::String(String::from(password.as_str())));
    Ok(Value::Object(reply))
}

async fn ticket_redeem(
    manifest: &PluginManifest,
    core: Option<&Arc<dyn VaultCtx>>,
    params: &Value,
    caller: Option<&InvocationCaller>,
) -> Result<Value, String> {
    let (core, caller) = preflight(manifest, core, caller, SqlGrantKind::SqlGate).await?;
    let p: TicketParams = parse(params)?;
    let resource = resource_name(&p.resource)?;
    bounded_text("profile", &p.profile, MAX_PROFILE_LEN)?;
    bounded_text("ticket", &p.ticket, MAX_TICKET_LEN)?;
    // Per-action step-up (§8.3, T126): a ticket bound to the canonical
    // action, never a connect ticket. Parsed before any privilege read, so
    // a malformed action costs nothing. An empty string is malformed, not
    // "no action": absent and `null` are the only connect forms.
    let action = match p.action.as_deref() {
        None => None,
        Some(a) => Some(canonical_sql_action(a).map_err(|m| err(codes::BAD_REQUEST, m))?),
    };
    let req = caller.request();
    let gate = policy_gate(core.as_ref())?;
    require_any_sql_privilege(gate.as_ref(), req, &manifest.name, &resource, "connect_ticket_redeem").await?;
    let ns = caller_namespace(core.as_ref(), req).await?;
    if let Some(action) = action {
        // Always burns a ticket bound to this exact action. It records no
        // MFA redemption, so it can never unlock a `require_mfa` release.
        let record =
            redeem_sql_action_ticket(core.as_ref(), req, &resource, &p.profile, p.ticket.as_str(), &action)
                .await
                .map_err(|e| kernel_error("connect_ticket_redeem", e))?;
        return Ok(json!({ "redeemed": true, "method": record.method, "action": action }));
    }
    let mfa = core.connect_mfa().ok_or_else(|| err(codes::NOT_AVAILABLE, "no connect-MFA gate"))?;
    let ns_prefix = if ns.is_empty() { String::new() } else { format!("{ns}/") };
    match mfa.enforce(req, &ns_prefix, &resource, &p.profile, Some(p.ticket.as_str())).await {
        Ok(Some(g)) => {
            // What `resource_sql_credential` checks for an MFA-gated profile.
            caller.record_mfa_redemption(&ns, &resource, &p.profile);
            Ok(json!({ "redeemed": true, "method": g.method }))
        }
        Ok(None) => Ok(json!({ "redeemed": false })),
        Err(e) => Err(kernel_error("connect_ticket_redeem", e)),
    }
}

// ── release audit ───────────────────────────────────────────────────────

/// The audit reason of a refusal: a stable second code when the error
/// carries one (`refused: dynamic_not_available: …`), else its first.
fn refusal_reason(e: &str) -> &str {
    let mut parts = e.splitn(3, ": ");
    let first = parts.next().unwrap_or("");
    match parts.next() {
        Some(second) if !second.is_empty() && second.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => second,
        _ => first,
    }
}

/// The `resource-credential-release` entry: actor (stamped from the
/// caller), namespace, resource, profile, secret id, plugin, session
/// reference and outcome. Never the value.
struct ReleaseAudit {
    plugin: String,
    resource: String,
    profile: String,
    session_ref: String,
    secret_id: String,
    reason: String,
}

impl ReleaseAudit {
    fn new(manifest: &PluginManifest, params: &Value) -> Self {
        let s = |k: &str| {
            params.get(k).and_then(Value::as_str).map(|v| v.chars().take(MAX_SESSION_REF_LEN).collect()).unwrap_or_default()
        };
        Self {
            plugin: manifest.name.clone(),
            resource: s("resource"),
            profile: s("profile"),
            session_ref: s("session_ref"),
            secret_id: String::new(),
            reason: String::new(),
        }
    }

    fn data(&self, result: &Result<Value, String>) -> Map<String, Value> {
        let mut d = Map::new();
        d.insert("plugin".into(), json!(self.plugin));
        d.insert("resource".into(), json!(self.resource));
        d.insert("profile".into(), json!(self.profile));
        d.insert("session_ref".into(), json!(self.session_ref));
        d.insert("secret_id".into(), json!(self.secret_id));
        match result {
            Ok(_) => {
                d.insert("outcome".into(), json!("released"));
            }
            Err(e) => {
                d.insert("outcome".into(), json!("refused"));
                let code = if self.reason.is_empty() { refusal_reason(e) } else { self.reason.as_str() };
                d.insert("reason".into(), json!(code));
            }
        }
        d
    }

    async fn emit(&self, core: &dyn VaultCtx, caller: &InvocationCaller, result: &Result<Value, String>) {
        let Some(broker) = core.audit_broker() else {
            return;
        };
        if !broker.has_devices() {
            return;
        }
        let mut entry = AuditEntry::event(RELEASE_EVENT, self.data(result), Some(caller.request()), broker.hmac_key());
        if let Err(e) = broker.log(&mut entry).await {
            log::warn!(target: "security", "{RELEASE_EVENT} audit failed for plugin `{}`: {e}", self.plugin);
        }
    }
}

#[cfg(test)]
mod tests;
