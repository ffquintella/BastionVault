//! Web Application Connect, `form` login mode — the server half
//! (`features/web-application-connect.md` §3, §6, §11; T96 Phase 2).
//!
//! Four endpoints on the resource mount, all `Write`, all under `v2/`:
//!
//! | path | does |
//! |---|---|
//! | `v2/connect/web/launch` | authorise like `connect/authorize`, enforce the exposure policy, resolve the credential server-side, return the launch bundle |
//! | `v2/connect/web/totp`   | one fresh TOTP code per TOTP step of an in-flight launch |
//! | `v2/connect/web/result` | record the recipe outcome, once |
//! | `v2/connect/web/close`  | record the session end, check an LDAP library account back in; idempotent |
//!
//! ## Whose authority resolves the credential
//!
//! * `secret` — a secret **on this resource**, read under the server's own
//!   authority. The `connect` grant on the resource is the authorization, as
//!   on `rustion/v2/session/open`: a connect-only operator launches without
//!   ever holding `read` on the secret.
//! * `ldap`, `default-account` — objects **outside** the resource. A stored
//!   profile names them, and anyone who may edit a resource may edit its
//!   profiles, so resolving them under server authority would let a resource
//!   editor check out any library account in the namespace. They are therefore
//!   dispatched through the full request pipeline **as the caller**, exactly
//!   as the desktop host does on the direct path today, and the LDAP engine's
//!   own ACL and check-in ownership apply.
//!
//! ## What leaves the server
//!
//! Only what the recipe fills: the bundle carries `username`, `password` and
//! the current TOTP code only when a step (or heuristic mode) uses them. The
//! TOTP seed never leaves; neither does a `default-account`'s stored Windows
//! password. The bundle travels in the response body of an authenticated
//! request, which the audit pipeline records HMAC-redacted.
//!
//! ## Audit
//!
//! `target: "audit"` lines `connect.web.launch` / `totp` / `result` / `close`
//! / `refused` / `reaped`, next to the pipeline's own (redacted) request
//! record. They carry names, hashes and enum values only: never a credential,
//! a TOTP code, a raw `launch_id`, or any URL.

pub mod exposure;
pub mod launch_store;
pub mod profile;
pub mod recipe;
pub mod totp;
pub mod transport;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use self::exposure::{ExposurePolicy, ExposureRefusal, WebExposure};
use self::launch_store::{
    launch_id_hash, CallerIdentity, CheckInState, LaunchError, LaunchGuard, LdapCheckIn, LdapCheckout, TotpSource,
    WebLaunchRecord, WebLaunchStore, LAUNCH_RECORD_VERSION, LOGIN_WINDOW_SECS,
};
use self::profile::{parse_launch_profile, WebCredentialSource, WebLaunchProfile};
use crate::connect_mfa::{caller_namespace, find_profile};
use crate::kernel_api::{identity::caller_audit_actor, VaultCtx};
use crate::{
    errors::RvError,
    logical::{connection::Connection, Backend, Operation, Request, Response},
    SECRET_PREFIX,
};

// ── Refusals ───────────────────────────────────────────────────────

/// One refusal: an HTTP status, a stable machine-readable `code` (the error
/// prefix the host matches on, and the `reason` of the audit line) and an
/// operator-facing message. When the refusal came from another layer (the
/// connect grant, the MFA ticket store, storage) that error is passed through
/// unchanged.
#[derive(Debug)]
pub struct WebRefusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    inner: Option<RvError>,
}

impl WebRefusal {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), inner: None }
    }

    fn wrap(code: &'static str, e: RvError) -> Self {
        let status = match &e {
            RvError::ErrResponseStatus(s, _) => *s,
            RvError::ErrPermissionDenied => 403,
            _ => 500,
        };
        Self { status, code, message: String::new(), inner: Some(e) }
    }

    fn into_rv(self) -> RvError {
        match self.inner {
            Some(e) => e,
            None => RvError::ErrResponseStatus(self.status, format!("{}: {}", self.code, self.message)),
        }
    }
}

impl From<LaunchError> for WebRefusal {
    fn from(e: LaunchError) -> Self {
        match e {
            LaunchError::Storage(inner) => Self::wrap("storage_error", inner),
            other => Self::new(other.status(), other.code(), other.to_string()),
        }
    }
}

impl From<ExposureRefusal> for WebRefusal {
    fn from(e: ExposureRefusal) -> Self {
        Self::new(e.status(), e.code(), e.to_string())
    }
}

// ── Audit lines ────────────────────────────────────────────────────

/// What a refusal line can say about the call. Filled in as the handler
/// learns it; operator-controlled strings are `{:?}`-quoted so none can break
/// the line.
#[derive(Default)]
struct AuditCtx {
    op: &'static str,
    principal: String,
    namespace: String,
    resource: String,
    profile: String,
    launch_id_hash: String,
}

impl AuditCtx {
    fn new(op: &'static str) -> Self {
        Self { op, ..Default::default() }
    }

    fn refused(&self, r: &WebRefusal) {
        log::info!(target: "audit", "{}", refused_line(self, r));
    }
}

fn refused_line(a: &AuditCtx, r: &WebRefusal) -> String {
    format!(
        "connect.web.refused op={} reason={} status={} principal={:?} namespace={:?} resource={:?} \
         profile={:?} launch_id_hash={}",
        a.op, r.code, r.status, a.principal, a.namespace, a.resource, a.profile, a.launch_id_hash
    )
}

/// The `connect.web.launch` fields of §11. Holds no credential by
/// construction.
struct LaunchAudit<'a> {
    principal: &'a str,
    namespace: &'a str,
    resource: &'a str,
    profile: &'a str,
    login_mode: &'a str,
    exposure: &'a str,
    exposure_cap: &'a str,
    credential_source: &'a str,
    recipe_hash: &'a str,
    heuristic: bool,
    mfa: &'a str,
    /// The effective Rustion transport the launch passed (`none` when
    /// Rustion is not mounted).
    transport: &'a str,
    released: &'a str,
    launch_id_hash: &'a str,
}

fn launch_line(a: &LaunchAudit<'_>) -> String {
    format!(
        "connect.web.launch principal={:?} namespace={:?} resource={:?} profile={:?} login_mode={} \
         exposure={} exposure_cap={} credential_source={} recipe_hash={} heuristic={} mfa={} \
         transport={} released={} launch_id_hash={}",
        a.principal,
        a.namespace,
        a.resource,
        a.profile,
        a.login_mode,
        a.exposure,
        a.exposure_cap,
        a.credential_source,
        a.recipe_hash,
        a.heuristic,
        a.mfa,
        a.transport,
        a.released,
        a.launch_id_hash
    )
}

// ── Small helpers ──────────────────────────────────────────────────

fn rfc3339_ms(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms).map(|d| d.to_rfc3339()).unwrap_or_default()
}

/// A non-empty string field of a secret / sub-response, copied into a
/// `Zeroizing` buffer.
fn take_field(data: &Map<String, Value>, key: &str) -> Option<Zeroizing<String>> {
    data.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(|s| Zeroizing::new(s.to_string()))
}

/// Scrub every string in a credential-bearing map before it is dropped.
fn zeroize_map(data: &mut Map<String, Value>) {
    for (_, v) in data.iter_mut() {
        match v {
            Value::String(s) => s.zeroize(),
            Value::Object(m) => zeroize_map(m),
            _ => {}
        }
    }
}

/// The calling principal as `(auth mount, name)`. Unlike the connect-MFA
/// ticket (userpass only, since only userpass carries a second factor) any
/// authenticated principal may launch an ungated profile, so the name falls
/// back to the entity id / display name the audit trail already uses.
fn web_caller(req: &Request) -> Result<(String, String), WebRefusal> {
    let auth = req.auth.as_ref().ok_or_else(|| WebRefusal::new(401, "no_caller", "no authenticated caller"))?;
    let mount = auth.metadata.get("mount_path").cloned().unwrap_or_default();
    let name = match auth.metadata.get("username").filter(|u| !u.is_empty()) {
        Some(u) => u.to_lowercase(),
        None => caller_audit_actor(req),
    };
    if name.is_empty() {
        return Err(WebRefusal::new(403, "no_principal", "the caller has no principal a launch can be bound to"));
    }
    Ok((mount, name))
}

fn string_field(req: &Request, key: &str) -> Option<String> {
    req.get_data(key).ok().and_then(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty())
}

fn launch_id_field(req: &Request) -> Result<String, WebRefusal> {
    string_field(req, "launch_id").ok_or_else(|| WebRefusal::new(400, "invalid_request", "`launch_id` is required"))
}

fn step_field(req: &Request, required: bool) -> Result<Option<u32>, WebRefusal> {
    let bad = || WebRefusal::new(400, "invalid_request", "`step` must be a non-negative integer recipe step index");
    let v = match req.get_data("step") {
        Ok(v) => v,
        Err(RvError::ErrRequestFieldInvalid) => return Err(bad()),
        Err(_) if !required => return Ok(None),
        Err(_) => return Err(WebRefusal::new(400, "invalid_request", "`step` is required")),
    };
    let n = match &v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    n.and_then(|n| u32::try_from(n).ok()).map(Some).ok_or_else(bad)
}

// ── Pipeline dispatch as the caller ────────────────────────────────

/// Dispatches a sub-request through the **full** request pipeline (token
/// lookup, ACL, audit) carrying the caller's own token. Used for the
/// credential sources the resource's `connect` grant does not cover.
struct CallerDispatch {
    core: Arc<dyn VaultCtx>,
    client_token: String,
    namespace_path: Option<String>,
    connection: Option<Connection>,
    /// `""` or `"<ns>/"`, prefixed onto logical-mount paths.
    ns_prefix: String,
}

impl CallerDispatch {
    fn new(core: Arc<dyn VaultCtx>, req: &Request, namespace: &str) -> Self {
        Self {
            core,
            client_token: req.client_token.clone(),
            namespace_path: req.namespace_path.clone(),
            connection: req.connection.clone(),
            ns_prefix: if namespace.is_empty() { String::new() } else { format!("{namespace}/") },
        }
    }
}

#[maybe_async::maybe_async]
impl CallerDispatch {
    /// `path` is complete: logical-mount paths already carry `ns_prefix`.
    /// Request headers are deliberately not copied — a response-wrapping
    /// header on the launch must not wrap the check-out response.
    async fn call(
        &self,
        op: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Map<String, Value>>, RvError> {
        let mut sub = Request::new(path);
        sub.operation = op;
        sub.client_token = self.client_token.clone();
        sub.namespace_path = self.namespace_path.clone();
        sub.connection = self.connection.clone();
        sub.body = body;
        Ok(self.core.handle_request(&mut sub).await?.and_then(|r| r.data))
    }
}

#[maybe_async::maybe_async]
impl LdapCheckIn for CallerDispatch {
    async fn check_in(&self, c: &LdapCheckout) -> Result<(), RvError> {
        let mut body = Map::new();
        // `account`, not the lease id: it is the field the LDAP engine's
        // check-in keys on, and naming it means a caller holding two
        // check-outs in one set still releases the right one.
        body.insert("account".into(), Value::String(c.account.clone()));
        let path = format!("{}{}library/{}/check-in", self.ns_prefix, c.mount, c.library_set);
        self.call(Operation::Write, &path, Some(body)).await.map(|_| ())
    }
}

// ── Credential resolution ──────────────────────────────────────────

#[derive(Default)]
struct ResolvedCredential {
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    totp: Option<totp::TotpCode>,
    totp_source: Option<TotpSource>,
    ldap: Option<LdapCheckout>,
}

impl ResolvedCredential {
    /// The parts being released, for the audit line: names only.
    fn released(&self) -> String {
        let parts: Vec<&str> = [
            self.username.is_some().then_some("username"),
            self.password.is_some().then_some("password"),
            self.totp.is_some().then_some("totp"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "nothing".into()
        } else {
            parts.join(",")
        }
    }
}

fn unavailable(message: impl Into<String>) -> WebRefusal {
    WebRefusal::new(422, "credential_unavailable", message)
}

/// Apply the recipe's demand to one resolved value: an explicit recipe that
/// fills it must get it; heuristic mode takes it if present; anything the
/// recipe does not fill is dropped here, never released.
fn demand(
    wanted: bool,
    heuristic: bool,
    value: Option<Zeroizing<String>>,
    what: &str,
) -> Result<Option<Zeroizing<String>>, WebRefusal> {
    match (wanted, value) {
        (false, _) => Ok(None),
        (true, Some(v)) => Ok(Some(v)),
        (true, None) if heuristic => Ok(None),
        (true, None) => Err(unavailable(format!("the credential source supplies no {what}, which the recipe fills"))),
    }
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    async fn read_resource_secret(
        &self,
        req: &mut Request,
        resource: &str,
        secret_id: &str,
    ) -> Result<Map<String, Value>, WebRefusal> {
        let entry = req
            .storage_get(&format!("{SECRET_PREFIX}{resource}/{secret_id}"))
            .await
            .map_err(|e| WebRefusal::wrap("storage_error", e))?
            .ok_or_else(|| {
                WebRefusal::new(
                    404,
                    "credential_unavailable",
                    format!("secret `{secret_id}` not found on this resource"),
                )
            })?;
        let raw = Zeroizing::new(entry.value);
        serde_json::from_slice(&raw).map_err(|_| unavailable(format!("secret `{secret_id}` is not a JSON object")))
    }

    async fn resolve_web_credential(
        &self,
        req: &mut Request,
        caller: &CallerDispatch,
        resource: &str,
        meta: &Map<String, Value>,
        profile: &WebLaunchProfile,
        now_secs: u64,
    ) -> Result<ResolvedCredential, WebRefusal> {
        let needs = &profile.needs;
        let user = caller_audit_actor(req);
        match &profile.source {
            WebCredentialSource::Secret { secret_id, fields, totp: params } => {
                let mut data = self.read_resource_secret(req, resource, secret_id).await?;
                let username = take_field(&data, &fields.username);
                let password = take_field(&data, &fields.password);
                let seed = if needs.totp { take_field(&data, &fields.totp_seed) } else { None };
                zeroize_map(&mut data);
                log::info!(
                    target: "security",
                    "resource-connect-web-resolve: user={user:?} resource={resource:?} source=secret key={secret_id:?}"
                );

                let mut out = ResolvedCredential {
                    username: demand(needs.username, needs.heuristic, username, "username")?,
                    password: demand(needs.password, needs.heuristic, password, "password")?,
                    ..Default::default()
                };
                match seed {
                    Some(seed) => {
                        let key = totp::decode_seed(&seed).map_err(|m| {
                            unavailable(format!("secret `{secret_id}` field `{}`: {m}", fields.totp_seed))
                        })?;
                        out.totp = Some(totp::code_at(&key, *params, now_secs));
                        out.totp_source = Some(TotpSource {
                            secret_id: secret_id.clone(),
                            seed_field: fields.totp_seed.clone(),
                            params: *params,
                            refresh_steps: needs.totp_steps.clone(),
                            refreshed_steps: Vec::new(),
                        });
                    }
                    None if needs.totp && !needs.heuristic => {
                        return Err(WebRefusal::new(
                            422,
                            "totp_not_configured",
                            format!(
                                "the recipe fills `totp`, but secret `{secret_id}` has no `{}` field",
                                fields.totp_seed
                            ),
                        ))
                    }
                    None => {}
                }
                if needs.heuristic && out.username.is_none() && out.password.is_none() {
                    return Err(unavailable(format!("secret `{secret_id}` has neither a username nor a password")));
                }
                Ok(out)
            }

            WebCredentialSource::LdapStaticRole { mount, role } => {
                let path = format!("{}{mount}static-cred/{role}", caller.ns_prefix);
                let mut data = caller
                    .call(Operation::Read, &path, None)
                    .await
                    .map_err(|e| WebRefusal::wrap("credential_unavailable", e))?
                    .ok_or_else(|| unavailable(format!("LDAP static role `{role}` returned no credential")))?;
                let username = take_field(&data, "username");
                let password = take_field(&data, "password");
                zeroize_map(&mut data);
                log::info!(
                    target: "security",
                    "resource-connect-web-resolve: user={user:?} resource={resource:?} source=ldap static_role={role:?}"
                );
                Ok(ResolvedCredential {
                    username: demand(needs.username, needs.heuristic, username, "username")?,
                    password: demand(needs.password, needs.heuristic, password, "password")?,
                    ..Default::default()
                })
            }

            WebCredentialSource::LdapLibrarySet { mount, set } => {
                let path = format!("{}{mount}library/{set}/check-out", caller.ns_prefix);
                let mut data = caller
                    .call(Operation::Write, &path, Some(Map::new()))
                    .await
                    .map_err(|e| WebRefusal::wrap("credential_unavailable", e))?
                    .unwrap_or_default();
                let account = take_field(&data, "service_account_name");
                let password = take_field(&data, "password");
                let lease_id = take_field(&data, "lease_id");
                zeroize_map(&mut data);
                let (Some(account), Some(password), Some(lease_id)) = (account, password, lease_id) else {
                    return Err(unavailable(format!("LDAP library `{set}` check-out returned an incomplete response")));
                };
                let checkout = LdapCheckout {
                    mount: mount.clone(),
                    library_set: set.clone(),
                    account: account.to_string(),
                    lease_id: lease_id.to_string(),
                    checked_in: false,
                };
                log::info!(
                    target: "security",
                    "resource-connect-web-resolve: user={user:?} resource={resource:?} source=ldap library_set={set:?} account={:?}",
                    checkout.account
                );
                let username = demand(needs.username, needs.heuristic, Some(account), "username");
                let password = demand(needs.password, needs.heuristic, Some(password), "password");
                Ok(ResolvedCredential {
                    // `demand` cannot fail when the value is present.
                    username: username?,
                    password: password?,
                    ldap: Some(checkout),
                    ..Default::default()
                })
            }

            WebCredentialSource::DefaultAccount => {
                if !needs.username {
                    return Ok(ResolvedCredential::default());
                }
                let mut data = caller
                    .call(Operation::Read, "sys/identity/default-account/self", None)
                    .await
                    .map_err(|e| WebRefusal::wrap("credential_unavailable", e))?
                    .unwrap_or_default();
                // The same OS-family mapping as SSH: windows / macos, else linux.
                let family = match meta.get("os_type").and_then(Value::as_str).unwrap_or_default() {
                    "windows" => "windows",
                    "macos" => "macos",
                    _ => "linux",
                };
                let username = data
                    .get(family)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Zeroizing::new(s.to_string()));
                // Also scrubs the stored Windows password, which is never released here.
                zeroize_map(&mut data);
                let username = username.ok_or_else(|| {
                    unavailable(format!(
                        "you have no default {family} account configured (Users → Edit User → Default Resource Account)"
                    ))
                })?;
                Ok(ResolvedCredential { username: Some(username), ..Default::default() })
            }
        }
    }

    /// The resource's entry in `config/types`, if its type was ever saved.
    async fn resource_type_def(
        &self,
        req: &mut Request,
        meta: &Map<String, Value>,
    ) -> Result<Option<Value>, WebRefusal> {
        let rtype = meta.get("type").and_then(Value::as_str).unwrap_or_default();
        if rtype.is_empty() {
            return Ok(None);
        }
        let Some(entry) = req.storage_get("config/types").await.map_err(|e| WebRefusal::wrap("storage_error", e))?
        else {
            return Ok(None);
        };
        let types: Map<String, Value> = serde_json::from_slice(&entry.value).map_err(|_| {
            WebRefusal::new(
                422,
                "exposure_policy_invalid",
                "the stored resource type configuration is not a JSON object",
            )
        })?;
        Ok(types.get(rtype).cloned())
    }

    /// The resource's effective Rustion transport policy, from Rustion's own
    /// resolver (`rustion/policy/effective` — the call the host makes, and the
    /// four-tier resolution `rustion/v2/session/open` applies).
    ///
    /// Dispatched through the router, i.e. under the server's authority, the
    /// way `session/open` reads its policy store: the caller's own grant on
    /// the resolver endpoint must not decide whether a restriction on them is
    /// applied. The caller's `auth` and namespace ride along, so the
    /// resolver's per-resource gate and tenant qualification still see the
    /// caller — who has already passed the connect grant on this resource.
    ///
    /// No `rustion/` mount means no Rustion policy can exist (its tiers live
    /// in that mount's store), which reads as "no policy". Every other failure
    /// — the store unreadable, a tier record undecodable, an asset-group
    /// lookup error, a verdict this server cannot parse — refuses.
    async fn effective_transport(
        &self,
        req: &Request,
        resource: &str,
        meta: &Map<String, Value>,
    ) -> Result<transport::TransportVerdict, WebRefusal> {
        // Unlike `resolve_login_class`, an index error is not "no groups": an
        // asset-group tier can be the one that requires Rustion.
        let asset_groups = match self.core.resource_groups() {
            Some(index) => index
                .groups_for_resource(resource)
                .await
                .map_err(|e| transport::unavailable(format!("asset-group lookup failed: {e}")))?,
            None => Vec::new(),
        };

        let mut body = Map::new();
        body.insert("resource_id".into(), Value::String(resource.to_string()));
        if let Some(t) = meta.get("type").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            body.insert("resource_type".into(), Value::String(t.to_string()));
        }
        if !asset_groups.is_empty() {
            body.insert("asset_group_ids".into(), Value::Array(asset_groups.into_iter().map(Value::String).collect()));
        }

        // `rustion/` is deployment-global and header-scoped: never prefixed
        // with the caller's namespace.
        let mut sub = Request::new("rustion/policy/effective");
        sub.operation = Operation::Write;
        sub.auth = req.auth.clone();
        sub.client_token = req.client_token.clone();
        sub.namespace_path = req.namespace_path.clone();
        sub.body = Some(body);
        match self.core.router().handle_request(&mut sub).await {
            Ok(resp) => {
                let data =
                    resp.and_then(|r| r.data).ok_or_else(|| transport::unavailable("the resolver returned nothing"))?;
                transport::evaluate(&data)
            }
            Err(RvError::ErrRouterMountNotFound) => Ok(transport::TransportVerdict::NoRustion),
            Err(e) => Err(transport::unavailable(e.to_string())),
        }
    }

    async fn caller_identity(&self, req: &Request, audit: &mut AuditCtx) -> Result<CallerIdentity, WebRefusal> {
        let (mount, principal) = web_caller(req)?;
        audit.principal = format!("{mount}{principal}");
        let namespace = caller_namespace(&self.core, req).await.map_err(|e| WebRefusal::wrap("namespace", e))?;
        audit.namespace = namespace.clone();
        Ok(CallerIdentity { mount, principal, namespace })
    }

    // ── launch ─────────────────────────────────────────────────────

    /// `POST resources/v2/connect/web/launch`.
    pub async fn handle_connect_web_launch(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = AuditCtx::new("launch");
        match self.web_launch(req, &mut audit).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(r) => {
                audit.refused(&r);
                Err(r.into_rv())
            }
        }
    }

    async fn web_launch(&self, req: &mut Request, audit: &mut AuditCtx) -> Result<Map<String, Value>, WebRefusal> {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let caller = self.caller_identity(req, audit).await?;

        // (1) The connect grant, then the stored record — the same front half
        // as `connect/authorize`.
        let (resource, profile_id, meta) = self.connect_target_record(req).await.map_err(|e| {
            let code = if matches!(e, RvError::ErrPermissionDenied) { "connect_denied" } else { "invalid_request" };
            WebRefusal::wrap(code, e)
        })?;
        audit.resource = resource.clone();
        audit.profile = profile_id.clone();
        let meta =
            meta.ok_or_else(|| WebRefusal::new(404, "resource_not_found", format!("resource `{resource}` not found")))?;
        let profile_value = find_profile(&meta, &profile_id).ok_or_else(|| {
            WebRefusal::new(
                404,
                "profile_not_found",
                format!("profile `{profile_id}` not found on resource `{resource}`"),
            )
        })?;

        // (2) Every static check: protocol, login mode, transport, recipe,
        // origins, source/recipe compatibility.
        let profile = parse_launch_profile(&profile_value)?;

        // (3) The host's copy of the recipe must be the stored one.
        let supplied = string_field(req, "recipe_hash").ok_or_else(|| {
            WebRefusal::new(400, "recipe_hash_required", "`recipe_hash` is required for a form-mode launch")
        })?;
        if supplied != profile.recipe_hash {
            return Err(WebRefusal::new(
                409,
                "recipe_hash_mismatch",
                "the profile's recipe changed since the host loaded it; reload the profile and launch again",
            ));
        }

        // (4) Exposure cap and heuristic policy (§6), at both tiers.
        let type_def = self.resource_type_def(req, &meta).await?;
        let policy = ExposurePolicy::from_tiers(type_def.as_ref(), &meta)?;
        let required = WebExposure::Dom;
        let cap = policy.check(required, profile.needs.heuristic, profile.allow_insecure_http)?;

        // (4b) The Rustion transport tier. A form launch is always local, so
        // `rustion-required` (or a lock violation) refuses here — before the
        // ticket is burnt and before any credential is read — never a local
        // fallback.
        let transport = self.effective_transport(req, &resource, &meta).await?;

        // (5) Connect-time MFA. Only now, so a profile that fails a static
        // or policy check never costs the operator their ticket.
        let mfa_method = if profile.require_mfa {
            let ticket = self
                .redeem_connect_ticket(req, &resource, &profile_id)
                .await
                .map_err(|e| WebRefusal::wrap("mfa", e))?;
            Some(ticket.method)
        } else {
            None
        };

        let store = WebLaunchStore::new(self.core.as_ref());
        match store.tidy(now_ms).await {
            Ok(reaped) => {
                for r in reaped {
                    log::info!(
                        target: "audit",
                        "connect.web.reaped launch_id_hash={} ldap_checkin={}",
                        r.launch_id_hash,
                        if r.ldap_pending { "pending" } else { "not_pending" }
                    );
                }
            }
            // Hygiene only: every follow-up call enforces its own window.
            Err(e) => log::warn!("connect.web: launch-record tidy failed: {e}"),
        }

        // (6) Resolve the credential.
        let dispatch = CallerDispatch::new(self.core.clone(), req, &caller.namespace);
        let mut cred = self
            .resolve_web_credential(req, &dispatch, &resource, &meta, &profile, now.timestamp().max(0) as u64)
            .await?;

        // (7) Persist the launch. On failure, give back an LDAP account that
        // was just checked out rather than leaving it to its lease.
        let record = WebLaunchRecord {
            v: LAUNCH_RECORD_VERSION,
            caller: caller.clone(),
            resource: resource.clone(),
            profile_id: profile_id.clone(),
            recipe_hash: profile.recipe_hash.clone(),
            login_mode: "form".into(),
            exposure: required.as_str().into(),
            credential_kind: profile.source.kind().into(),
            mfa_method: mfa_method.clone(),
            issued_at_ms: now_ms,
            login_expires_at_ms: now_ms + LOGIN_WINDOW_SECS * 1000,
            step_count: profile.needs.step_count,
            totp: cred.totp_source.take(),
            ldap: cred.ldap.clone(),
            result: None,
            closed_at_ms: None,
        };
        let launch_id = match store.create(&record).await {
            Ok(id) => id,
            Err(e) => {
                if let Some(c) = &cred.ldap {
                    if let Err(ce) = dispatch.check_in(c).await {
                        log::warn!(
                            target: "audit",
                            "connect.web.launch_rollback ldap_checkin=failed resource={resource:?} account={:?}: {ce}",
                            c.account
                        );
                    }
                }
                return Err(WebRefusal::wrap("storage_error", e));
            }
        };
        audit.launch_id_hash = launch_id_hash(&launch_id);

        let released = cred.released();
        log::info!(
            target: "audit",
            "{}",
            launch_line(&LaunchAudit {
                principal: &audit.principal,
                namespace: &caller.namespace,
                resource: &resource,
                profile: &profile_id,
                login_mode: "form",
                exposure: required.as_str(),
                exposure_cap: cap.as_str(),
                credential_source: profile.source.kind(),
                recipe_hash: &profile.recipe_hash,
                heuristic: profile.needs.heuristic,
                mfa: mfa_method.as_deref().unwrap_or("none"),
                transport: transport.as_str(),
                released: &released,
                launch_id_hash: &audit.launch_id_hash,
            })
        );

        // (8) The bundle.
        let mut credential = Map::new();
        if let Some(u) = &cred.username {
            credential.insert("username".into(), Value::String(u.to_string()));
        }
        if let Some(p) = &cred.password {
            credential.insert("password".into(), Value::String(p.to_string()));
        }
        let mut refresh_steps = Vec::new();
        if let Some(t) = &cred.totp {
            credential.insert("totp".into(), Value::String(t.code.to_string()));
            credential.insert("totp_valid_until".into(), Value::String(rfc3339_ms(t.valid_until as i64 * 1000)));
            refresh_steps = record.totp.as_ref().map(|s| s.refresh_steps.clone()).unwrap_or_default();
        }

        let mut data = Map::new();
        data.insert("launch_id".into(), Value::String(launch_id));
        data.insert("expires_at".into(), Value::String(rfc3339_ms(record.login_expires_at_ms)));
        data.insert("resource".into(), Value::String(resource));
        data.insert("profile_id".into(), Value::String(profile_id));
        data.insert("login_mode".into(), Value::String("form".into()));
        data.insert("exposure".into(), Value::String(required.as_str().into()));
        data.insert("exposure_cap".into(), Value::String(cap.as_str().into()));
        data.insert("recipe_hash".into(), Value::String(profile.recipe_hash.clone()));
        data.insert("heuristic".into(), Value::Bool(profile.needs.heuristic));
        data.insert("credential_source".into(), Value::String(profile.source.kind().into()));
        data.insert("credential".into(), Value::Object(credential));
        data.insert("totp_refresh_steps".into(), Value::Array(refresh_steps.into_iter().map(Value::from).collect()));
        data.insert("mfa_method".into(), mfa_method.map(Value::String).unwrap_or(Value::Null));
        Ok(data)
    }

    // ── totp ───────────────────────────────────────────────────────

    /// `POST resources/v2/connect/web/totp`.
    pub async fn handle_connect_web_totp(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = AuditCtx::new("totp");
        match self.web_totp(req, &mut audit).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(r) => {
                audit.refused(&r);
                Err(r.into_rv())
            }
        }
    }

    async fn web_totp(&self, req: &mut Request, audit: &mut AuditCtx) -> Result<Map<String, Value>, WebRefusal> {
        let now = Utc::now();
        let caller = self.caller_identity(req, audit).await?;
        let launch_id = launch_id_field(req)?;
        audit.launch_id_hash = launch_id_hash(&launch_id);
        let step = step_field(req, true)?.unwrap_or_default();

        let _guard = LaunchGuard::acquire(&launch_id)?;
        let store = WebLaunchStore::new(self.core.as_ref());
        let (key, mut record) = store.load(&launch_id, &caller).await?;
        audit.resource = record.resource.clone();
        audit.profile = record.profile_id.clone();
        let source = record.take_totp_refresh(step, now.timestamp_millis())?;

        // A code is credential-derived: a connect grant revoked since the
        // launch stops it.
        self.require_connect_grant(req, &record.resource).await.map_err(|e| WebRefusal::wrap("connect_denied", e))?;

        let mut data = self.read_resource_secret(req, &record.resource, &source.secret_id).await?;
        let seed = take_field(&data, &source.seed_field);
        zeroize_map(&mut data);
        let seed = seed.ok_or_else(|| {
            WebRefusal::new(409, "totp_not_configured", "the TOTP seed is no longer present in the launch's secret")
        })?;
        let key_bytes = totp::decode_seed(&seed).map_err(unavailable)?;
        let code = totp::code_at(&key_bytes, source.params, now.timestamp().max(0) as u64);

        // Only persisted once the code exists, so a failed read does not
        // spend the step.
        store.save(&key, &record).await.map_err(|e| WebRefusal::wrap("storage_error", e))?;
        log::info!(target: "audit", "connect.web.totp launch_id_hash={} step={step}", audit.launch_id_hash);

        let remaining: Vec<Value> = record
            .totp
            .as_ref()
            .map(|t| {
                t.refresh_steps.iter().filter(|s| !t.refreshed_steps.contains(s)).map(|s| Value::from(*s)).collect()
            })
            .unwrap_or_default();
        let mut out = Map::new();
        out.insert("totp".into(), Value::String(code.code.to_string()));
        out.insert("totp_valid_until".into(), Value::String(rfc3339_ms(code.valid_until as i64 * 1000)));
        out.insert("step".into(), Value::from(step));
        out.insert("totp_refresh_steps".into(), Value::Array(remaining));
        Ok(out)
    }

    // ── result ─────────────────────────────────────────────────────

    /// `POST resources/v2/connect/web/result`.
    pub async fn handle_connect_web_result(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = AuditCtx::new("result");
        match self.web_result(req, &mut audit).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(r) => {
                audit.refused(&r);
                Err(r.into_rv())
            }
        }
    }

    async fn web_result(&self, req: &mut Request, audit: &mut AuditCtx) -> Result<Map<String, Value>, WebRefusal> {
        let caller = self.caller_identity(req, audit).await?;
        let launch_id = launch_id_field(req)?;
        audit.launch_id_hash = launch_id_hash(&launch_id);
        let outcome = string_field(req, "outcome")
            .ok_or_else(|| WebRefusal::new(400, "invalid_request", "`outcome` is required"))?;
        let step = step_field(req, false)?;

        let _guard = LaunchGuard::acquire(&launch_id)?;
        let store = WebLaunchStore::new(self.core.as_ref());
        let (key, mut record) = store.load(&launch_id, &caller).await?;
        audit.resource = record.resource.clone();
        audit.profile = record.profile_id.clone();
        let newly = record.record_result(&outcome, step, Utc::now().timestamp_millis())?;
        if newly {
            store.save(&key, &record).await.map_err(|e| WebRefusal::wrap("storage_error", e))?;
            log::info!(
                target: "audit",
                "connect.web.result launch_id_hash={} outcome={outcome} step={}",
                audit.launch_id_hash,
                step.map(|s| s.to_string()).unwrap_or_else(|| "none".into())
            );
        }

        let mut out = Map::new();
        out.insert("recorded".into(), Value::Bool(true));
        out.insert("already_recorded".into(), Value::Bool(!newly));
        out.insert("outcome".into(), Value::String(outcome));
        Ok(out)
    }

    // ── close ──────────────────────────────────────────────────────

    /// `POST resources/v2/connect/web/close`.
    pub async fn handle_connect_web_close(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = AuditCtx::new("close");
        match self.web_close(req, &mut audit).await {
            Ok(data) => Ok(Some(Response::data_response(Some(data)))),
            Err(r) => {
                audit.refused(&r);
                Err(r.into_rv())
            }
        }
    }

    async fn web_close(&self, req: &mut Request, audit: &mut AuditCtx) -> Result<Map<String, Value>, WebRefusal> {
        let caller = self.caller_identity(req, audit).await?;
        let launch_id = launch_id_field(req)?;
        audit.launch_id_hash = launch_id_hash(&launch_id);

        let store = WebLaunchStore::new(self.core.as_ref());
        let dispatch = CallerDispatch::new(self.core.clone(), req, &caller.namespace);
        let report = store.close(&launch_id, &caller, Utc::now().timestamp_millis(), &dispatch).await?;
        audit.resource = report.resource.clone();
        audit.profile = report.profile_id.clone();
        log::info!(
            target: "audit",
            "connect.web.close launch_id_hash={} duration_ms={} ldap_checkin={} already_closed={}",
            audit.launch_id_hash,
            report.duration_ms,
            report.ldap_checkin.as_str(),
            report.already_closed
        );

        if report.ldap_checkin == CheckInState::Failed {
            return Err(WebRefusal::new(
                502,
                "ldap_checkin_failed",
                format!(
                    "the session is closed, but checking the LDAP account back in failed ({}); call close \
                     again to retry — otherwise the account is released when its LDAP lease expires",
                    report.checkin_error.unwrap_or_default()
                ),
            ));
        }

        let mut out = Map::new();
        out.insert("closed".into(), Value::Bool(true));
        out.insert("already_closed".into(), Value::Bool(report.already_closed));
        out.insert("duration_ms".into(), Value::from(report.duration_ms));
        out.insert("ldap_checkin".into(), Value::String(report.ldap_checkin.as_str().into()));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::Auth;

    #[test]
    fn audit_lines_carry_names_and_hashes_only() {
        let line = launch_line(&LaunchAudit {
            principal: "userpass/alice",
            namespace: "",
            resource: "fw01",
            profile: "p_web",
            login_mode: "form",
            exposure: "dom",
            exposure_cap: "dom",
            credential_source: "secret",
            recipe_hash: "sha256:ab",
            heuristic: false,
            mfa: "totp",
            transport: "rustion-preferred",
            released: "username,password,totp",
            launch_id_hash: "cd",
        });
        assert!(line.starts_with("connect.web.launch "));
        for k in [
            "principal=",
            "namespace=",
            "resource=",
            "profile=",
            "login_mode=form",
            "exposure=dom",
            "credential_source=secret",
            "recipe_hash=sha256:ab",
            "mfa=totp",
            "transport=rustion-preferred",
            "launch_id_hash=cd",
        ] {
            assert!(line.contains(k), "{k} missing from {line}");
        }
        // `released` names the parts; it is not the values.
        assert!(line.contains("released=username,password,totp"));
        assert!(!line.contains("://"), "no URL ever reaches an audit line");

        // Operator-controlled names are quoted, so one cannot forge a field.
        let mut a = AuditCtx::new("launch");
        a.resource = "fw01 reason=ok\nconnect.web.launch".into();
        let r = WebRefusal::new(403, "exposure_cap_exceeded", "x");
        let line = refused_line(&a, &r);
        assert!(!line.contains('\n'));
        assert!(line.contains("reason=exposure_cap_exceeded"));
        assert!(line.contains(r#"resource="fw01 reason=ok\nconnect.web.launch""#));
    }

    #[test]
    fn released_lists_parts_never_values() {
        let c = ResolvedCredential {
            username: Some(Zeroizing::new("alice".into())),
            password: Some(Zeroizing::new("hunter2".into())),
            ..Default::default()
        };
        assert_eq!(c.released(), "username,password");
        assert_eq!(ResolvedCredential::default().released(), "nothing");
    }

    #[test]
    fn demand_releases_only_what_the_recipe_fills() {
        let v = || Some(Zeroizing::new("x".to_string()));
        assert!(demand(false, false, v(), "password").unwrap().is_none(), "unfilled ⇒ dropped");
        assert!(demand(true, false, v(), "password").unwrap().is_some());
        assert_eq!(demand(true, false, None, "password").unwrap_err().code, "credential_unavailable");
        assert!(demand(true, true, None, "password").unwrap().is_none(), "heuristic takes what exists");
    }

    #[test]
    fn web_caller_binds_any_authenticated_principal() {
        let mut req = Request::new("resources/v2/connect/web/launch");
        assert_eq!(web_caller(&req).unwrap_err().code, "no_caller");

        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert("username".into(), "Alice".into());
        req.auth = Some(auth);
        assert_eq!(web_caller(&req).unwrap(), ("userpass/".to_string(), "alice".to_string()));

        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "oidc/".into());
        auth.metadata.insert("entity_id".into(), "ent-1".into());
        req.auth = Some(auth);
        assert_eq!(web_caller(&req).unwrap(), ("oidc/".to_string(), "ent-1".to_string()));

        req.auth = Some(Auth::default());
        assert_eq!(web_caller(&req).unwrap_err().code, "no_principal");
    }

    #[test]
    fn zeroize_map_scrubs_nested_strings() {
        let mut m: Map<String, Value> =
            serde_json::from_value(serde_json::json!({ "password": "hunter2", "nested": { "seed": "abc" }, "n": 1 }))
                .unwrap();
        zeroize_map(&mut m);
        assert_eq!(m["password"], Value::String(String::new()));
        assert_eq!(m["nested"]["seed"], Value::String(String::new()));
    }
}
