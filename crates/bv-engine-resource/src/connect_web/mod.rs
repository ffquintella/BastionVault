//! Web Application Connect, `form` and `http-auth` login modes — the server
//! half (`features/web-application-connect.md` §3, §6, §7, §11; T96 Phases 2
//! and 3).
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
//! * `provider` — one of the **caller's own** accounts in an approved
//!   credential-provider plugin (`features/self-accounts.md`), released through
//!   `PluginHost` with the caller attested from the token and the target set
//!   to this profile's fill origins. A resource editor cannot reach anyone
//!   else's accounts this way: the provider stores per entity, and its target
//!   binding is matched against the origins the server computed. A TOTP code
//!   from a provider seed is computed once, at launch; `totp` refreshes are
//!   not offered for it, because the seed is not kept anywhere server-side.
//!
//! ## What leaves the server
//!
//! Only what the login uses. `form`: the bundle carries `username`,
//! `password` and the current TOTP code only when a step (or heuristic mode)
//! uses them. `http-auth`: exactly a username and a password — the host hands
//! them to the webview's native challenge handler, never to the page — and
//! no TOTP, no recipe hash. The TOTP seed never leaves; neither does a
//! `default-account`'s stored Windows password. The bundle travels in the
//! response body of an authenticated request, which the audit pipeline
//! records HMAC-redacted.
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
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use self::exposure::{ExposurePolicy, ExposureRefusal, WebExposure};
use self::launch_store::{
    launch_id_hash, CallerIdentity, CheckInState, FillScope, LaunchError, LaunchGuard, LdapCheckIn, LdapCheckout,
    TotpSource, WebLaunchRecord, WebLaunchStore, LAUNCH_RECORD_VERSION, LOGIN_WINDOW_SECS, TIDY_THROTTLE,
};
use self::profile::{parse_launch_profile, LaunchLogin, WebCredentialSource, WebLaunchProfile};
use self::recipe::RecipeNeeds;
use self::totp::TotpParams;
use crate::connect_mfa::{caller_namespace, find_profile};
use crate::connect_provider::{account_id_field, audit_reason, ProviderAudit, ProviderLaunch};
use crate::kernel_api::{
    identity::caller_audit_actor,
    provider::{provider_resource, reason, ProviderNeeds, ProviderTarget, ReleasedCredential, ReleasedSecret},
    VaultCtx,
};
use crate::{
    errors::RvError,
    logical::{connection::Connection, Backend, Operation, Request, Response},
    storage::Storage,
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

    pub(crate) fn into_rv(self) -> RvError {
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
    /// The provider a `provider` source names (`None` for every other source).
    provider: Option<&'a str>,
    recipe_hash: &'a str,
    heuristic: bool,
    mfa: &'a str,
    /// The effective Rustion transport the launch passed (`none` when
    /// Rustion is not mounted).
    transport: &'a str,
    /// The origins the credential may be filled on (origins only, never paths).
    fill_origins: &'a [String],
    released: &'a str,
    launch_id_hash: &'a str,
}

fn launch_line(a: &LaunchAudit<'_>) -> String {
    format!(
        "connect.web.launch principal={:?} namespace={:?} resource={:?} profile={:?} login_mode={} \
         exposure={} exposure_cap={} credential_source={} provider={} recipe_hash={} heuristic={} mfa={} \
         transport={} fill_origins={:?} released={} launch_id_hash={}",
        a.principal,
        a.namespace,
        a.resource,
        a.profile,
        a.login_mode,
        a.exposure,
        a.exposure_cap,
        a.credential_source,
        a.provider.map(|p| format!("{p:?}")).unwrap_or_else(|| "none".into()),
        a.recipe_hash,
        a.heuristic,
        a.mfa,
        a.transport,
        a.fill_origins,
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

/// Scrub every string in a credential-bearing map — nested objects and
/// arrays included — before it is dropped.
fn zeroize_map(data: &mut Map<String, Value>) {
    for (_, v) in data.iter_mut() {
        zeroize_value(v);
    }
}

fn zeroize_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Object(m) => zeroize_map(m),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        _ => {}
    }
}

/// The calling principal a launch is bound to, as `(auth mount, name)`.
///
/// Any authenticated principal may launch an ungated profile (only the
/// connect-MFA ticket is userpass-only), so the name is the first of:
///
///   1. `username` on a known auth mount — the binding the MFA ticket uses;
///   2. `entity:<entity_id>`;
///   3. `token:<hex sha256(client token)>` — this token store has no
///      accessor, and a hash of a 256-bit token is the non-reversible
///      equivalent (it binds a root token, which has no entity, to itself);
///   4. `name:<display_name>`, only on a known auth mount.
///
/// A bare display name with no mount is never a binding. The prefixes keep
/// one kind of name from colliding with another.
fn web_caller(req: &Request) -> Result<(String, String), WebRefusal> {
    let auth = req.auth.as_ref().ok_or_else(|| WebRefusal::new(401, "no_caller", "no authenticated caller"))?;
    let meta = |k: &str| auth.metadata.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
    let mount = meta("mount_path").unwrap_or_default().to_string();
    if !mount.is_empty() {
        if let Some(u) = meta("username") {
            return Ok((mount, u.to_lowercase()));
        }
    }
    if let Some(entity) = meta("entity_id") {
        return Ok((mount, format!("entity:{entity}")));
    }
    if !req.client_token.is_empty() {
        return Ok((mount, format!("token:{}", hex::encode(Sha256::digest(req.client_token.as_bytes())))));
    }
    if !mount.is_empty() && !auth.display_name.trim().is_empty() {
        return Ok((mount, format!("name:{}", auth.display_name.trim())));
    }
    Err(WebRefusal::new(403, "no_principal", "the caller has no principal a launch can be bound to"))
}

/// The principal as an audit line shows it: a token binding is shortened so
/// the line does not carry a full token hash.
fn audit_principal(mount: &str, principal: &str) -> String {
    match principal.strip_prefix("token:") {
        Some(h) => format!("{mount}token:{}", &h[..h.len().min(16)]),
        None => format!("{mount}{principal}"),
    }
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

// ── The launch bundle ──────────────────────────────────────────────

/// What a `launch` response is built from. The credential is borrowed; the
/// response map is the only copy that leaves.
struct BundleParts<'a> {
    launch_id: String,
    expires_at_ms: i64,
    resource: String,
    profile_id: String,
    profile: &'a WebLaunchProfile,
    /// The level the launch was recorded at (`launched_exposure`).
    exposure: WebExposure,
    cap: WebExposure,
    fill_scope: &'a FillScope,
    cred: &'a ResolvedCredential,
    totp_refresh_steps: Vec<u32>,
    mfa_method: Option<String>,
}

/// The `launch` response (docs/api.md, *Web Connect*).
///
/// * `form`: `recipe_hash`, `heuristic`, and the credential parts the recipe
///   fills, including the current TOTP code and its window.
/// * `http-auth`: no `recipe_hash` (there is no recipe), `heuristic: false`,
///   `totp_refresh_steps: []`, and a credential of `username` and `password`
///   only — a TOTP code is never put in an http-auth bundle, whatever the
///   resolved credential holds. `fill_scope` is the set of origins whose
///   challenges the host may answer.
fn launch_bundle(b: BundleParts<'_>) -> Result<Map<String, Value>, WebRefusal> {
    let form = matches!(b.profile.login, LaunchLogin::Form { .. });
    let mut credential = Map::new();
    if let Some(u) = &b.cred.username {
        credential.insert("username".into(), Value::String(u.to_string()));
    }
    if let Some(p) = &b.cred.password {
        credential.insert("password".into(), Value::String(p.to_string()));
    }
    let mut refresh_steps = Vec::new();
    if let (true, Some(t)) = (form, &b.cred.totp) {
        credential.insert("totp".into(), Value::String(t.code.to_string()));
        credential.insert("totp_valid_until".into(), Value::String(rfc3339_ms(t.valid_until as i64 * 1000)));
        refresh_steps = b.totp_refresh_steps;
    }

    let mut data = Map::new();
    data.insert("launch_id".into(), Value::String(b.launch_id));
    data.insert("expires_at".into(), Value::String(rfc3339_ms(b.expires_at_ms)));
    data.insert("resource".into(), Value::String(b.resource));
    data.insert("profile_id".into(), Value::String(b.profile_id));
    data.insert("login_mode".into(), Value::String(b.profile.login_mode().into()));
    data.insert("exposure".into(), Value::String(b.exposure.as_str().into()));
    data.insert("exposure_cap".into(), Value::String(b.cap.as_str().into()));
    if let Some(hash) = b.profile.recipe_hash() {
        data.insert("recipe_hash".into(), Value::String(hash.to_string()));
    }
    data.insert("heuristic".into(), Value::Bool(form && b.profile.needs.heuristic));
    // The authoritative scope: the host fills (form) or answers challenges
    // (http-auth) only on these origins and starts at this URL, whatever its
    // own copy of the profile says.
    data.insert(
        "fill_scope".into(),
        serde_json::to_value(b.fill_scope).map_err(|e| WebRefusal::wrap("storage_error", e.into()))?,
    );
    data.insert("credential_source".into(), Value::String(b.profile.source.kind().into()));
    data.insert("credential".into(), Value::Object(credential));
    data.insert("totp_refresh_steps".into(), Value::Array(refresh_steps.into_iter().map(Value::from).collect()));
    data.insert("mfa_method".into(), b.mfa_method.map(Value::String).unwrap_or(Value::Null));
    Ok(data)
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

/// The `logical_type` an `ldap` source's mount must have.
const LDAP_LOGICAL_TYPE: &str = "openldap";

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

/// A credential checked as far as it can be **before** the MFA ticket is
/// redeemed, so a launch that fails for a reason the operator can fix does
/// not cost them their ticket.
///
/// * `secret` and `default-account` are resolved completely here: one read of
///   this resource's own storage, or of the caller's own default-account
///   record. Neither has a side effect, and nothing reaches the response until
///   `release_web_credential` runs, after the ticket.
/// * `ldap` is only pre-checked: the mount exists in the caller's namespace,
///   is untainted and is an LDAP engine. Reading a static credential and
///   checking a library account out stay after the ticket — a check-out
///   rotates a password — so their failures still spend it.
enum PreparedCredential {
    Ready {
        username: Option<Zeroizing<String>>,
        password: Option<Zeroizing<String>>,
        totp: Option<(Zeroizing<Vec<u8>>, TotpSource)>,
        /// How the security log names the source.
        source_detail: String,
    },
    LdapStaticRole {
        mount: String,
        role: String,
    },
    LdapLibrarySet {
        mount: String,
        set: String,
    },
    /// Everything but the release itself is checked: the account id is
    /// present, the caller has an identity entity, and the provider is live
    /// and declares `web`. The release runs after the ticket.
    Provider {
        launch: ProviderLaunch,
        account_id: String,
        needs: ProviderNeeds,
        totp: TotpParams,
    },
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
        (true, None) => Err(unavailable(format!("the credential source supplies no {what}, which this login needs"))),
    }
}

/// What a recipe needs, as a provider's `needs`. Heuristic mode takes a TOTP
/// only "if the source has it", which a provider cannot answer before the
/// release (asking for one the account lacks is refused), so a heuristic
/// launch asks for none. An explicit recipe asks for exactly what it fills.
fn provider_needs(needs: &RecipeNeeds) -> ProviderNeeds {
    ProviderNeeds { password: needs.password, totp: needs.totp && !needs.heuristic }
}

/// Turn a provider's release into the parts the recipe fills: the released
/// username is authoritative; an SSH key is refused (a web login cannot use
/// one, and the host's shape check already refuses it for `web`); a TOTP
/// seed becomes the code for `now_secs` and is dropped.
fn provider_credential(
    released: ReleasedCredential,
    needs: &RecipeNeeds,
    params: TotpParams,
    now_secs: u64,
) -> Result<ResolvedCredential, WebRefusal> {
    let ReleasedCredential { username, secret, .. } = released;
    let (password, seed) = match secret {
        ReleasedSecret::Password { password, totp_seed } => (password, totp_seed),
        ReleasedSecret::SshKey { .. } => {
            return Err(unavailable("the credential provider released an SSH key, which a web login cannot use"))
        }
    };
    let username = demand(needs.username, needs.heuristic, Some(Zeroizing::new(username)), "username")?;
    let password = demand(needs.password, needs.heuristic, Some(password), "password")?;
    let totp = match seed {
        Some(seed) if needs.totp => {
            let key = totp::decode_seed(&seed).map_err(|m| unavailable(format!("the provider's TOTP seed: {m}")))?;
            Some(totp::code_at(&key, params, now_secs))
        }
        _ if needs.totp && !needs.heuristic => {
            return Err(WebRefusal::new(
                422,
                "totp_not_configured",
                "the recipe fills `totp`, but the credential provider released no TOTP seed",
            ))
        }
        _ => None,
    };
    Ok(ResolvedCredential { username, password, totp, totp_source: None, ldap: None })
}

/// A provider-path error as a launch refusal: the reason code becomes the
/// refusal's `code`, and the error itself is passed through.
fn provider_refusal(e: RvError) -> WebRefusal {
    WebRefusal::wrap(audit_reason(&e), e)
}

/// A complete LDAP library check-out: `(account, password, lease_id)`.
type Checkout = (Zeroizing<String>, Zeroizing<String>, Zeroizing<String>);

/// Split a check-out response. `Err(Some(account))` is an incomplete response
/// that still checked `account` out: it must be checked back in before the
/// launch is refused, or the account stays leased to nobody.
fn parse_checkout(data: &Map<String, Value>) -> Result<Checkout, Option<Zeroizing<String>>> {
    match (take_field(data, "service_account_name"), take_field(data, "password"), take_field(data, "lease_id")) {
        (Some(account), Some(password), Some(lease_id)) => Ok((account, password, lease_id)),
        (account, _, _) => Err(account),
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

    /// The mount an `ldap` source names must exist in the caller's namespace,
    /// be untainted and be an LDAP engine. Read off the mount table; nothing
    /// is sent to the engine.
    fn require_ldap_mount(&self, ns_prefix: &str, mount: &str) -> Result<(), WebRefusal> {
        let path = format!("{ns_prefix}{mount}");
        let missing = || unavailable(format!("no LDAP engine is mounted at `{mount}`"));
        let router = self.core.router();
        if router.matching_mount(&path).map_err(|e| WebRefusal::wrap("storage_error", e))? != path {
            return Err(missing());
        }
        let entry = router
            .matching_mount_entry(&path)
            .map_err(|e| WebRefusal::wrap("storage_error", e))?
            .ok_or_else(missing)?;
        let entry =
            entry.read().map_err(|_| WebRefusal::new(500, "storage_error", "the mount table lock is poisoned"))?;
        if entry.tainted || entry.logical_type != LDAP_LOGICAL_TYPE {
            return Err(missing());
        }
        Ok(())
    }

    /// Pre-ticket half of resolution; see [`PreparedCredential`].
    async fn prepare_web_credential(
        &self,
        req: &mut Request,
        caller: &CallerDispatch,
        resource: &str,
        meta: &Map<String, Value>,
        profile: &WebLaunchProfile,
    ) -> Result<PreparedCredential, WebRefusal> {
        let needs = &profile.needs;
        match &profile.source {
            WebCredentialSource::Secret { secret_id, fields, totp: params } => {
                let mut data = self.read_resource_secret(req, resource, secret_id).await?;
                let username = take_field(&data, &fields.username);
                let password = take_field(&data, &fields.password);
                let seed = if needs.totp { take_field(&data, &fields.totp_seed) } else { None };
                zeroize_map(&mut data);

                let username = demand(needs.username, needs.heuristic, username, "username")?;
                let password = demand(needs.password, needs.heuristic, password, "password")?;
                let totp = match seed {
                    Some(seed) => {
                        let key = totp::decode_seed(&seed).map_err(|m| {
                            unavailable(format!("secret `{secret_id}` field `{}`: {m}", fields.totp_seed))
                        })?;
                        let source = TotpSource {
                            secret_id: secret_id.clone(),
                            seed_field: fields.totp_seed.clone(),
                            params: *params,
                            refresh_steps: needs.totp_steps.clone(),
                            refreshed_steps: Vec::new(),
                        };
                        Some((key, source))
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
                    None => None,
                };
                if needs.heuristic && username.is_none() && password.is_none() {
                    return Err(unavailable(format!("secret `{secret_id}` has neither a username nor a password")));
                }
                Ok(PreparedCredential::Ready {
                    username,
                    password,
                    totp,
                    source_detail: format!("source=secret key={secret_id:?}"),
                })
            }

            WebCredentialSource::LdapStaticRole { mount, role } => {
                self.require_ldap_mount(&caller.ns_prefix, mount)?;
                Ok(PreparedCredential::LdapStaticRole { mount: mount.clone(), role: role.clone() })
            }

            WebCredentialSource::LdapLibrarySet { mount, set } => {
                self.require_ldap_mount(&caller.ns_prefix, mount)?;
                Ok(PreparedCredential::LdapLibrarySet { mount: mount.clone(), set: set.clone() })
            }

            WebCredentialSource::DefaultAccount => {
                let source_detail = "source=default-account".to_string();
                if !needs.username {
                    return Ok(PreparedCredential::Ready { username: None, password: None, totp: None, source_detail });
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
                Ok(PreparedCredential::Ready { username: Some(username), password: None, totp: None, source_detail })
            }

            WebCredentialSource::Provider { provider, totp: params } => {
                let account_id = account_id_field(req).map_err(provider_refusal)?.ok_or_else(|| {
                    WebRefusal::new(
                        400,
                        reason::INVALID_REQUEST,
                        "`provider_account_id` is required for a provider profile: the account the operator \
                         picked from `resources/v2/connect/provider/candidates`",
                    )
                })?;
                let resource_desc =
                    provider_resource(meta).map_err(|m| WebRefusal::new(422, "invalid_profile", m))?;
                // The fill scope the server just checked, start origin first:
                // every origin the recipe may fill must match the account.
                let target = ProviderTarget::Origins { origins: profile.origins.clone() };
                let launch = self
                    .provider_launch(req, provider, "web", resource_desc, target)
                    .await
                    .map_err(provider_refusal)?;
                Ok(PreparedCredential::Provider {
                    launch,
                    account_id,
                    needs: provider_needs(needs),
                    totp: *params,
                })
            }
        }
    }

    /// Post-ticket half of resolution: compute the TOTP code, read an LDAP
    /// static credential, check a library account out, or ask a credential
    /// provider for the picked account. `mfa_verified` is true only when this
    /// launch redeemed a connect MFA ticket; `provider_audit` is the
    /// `connect.provider.release` line a provider source writes.
    // Eight distinct inputs of one release step, each used by at least one
    // source arm; a parameter struct would only rename them.
    #[allow(clippy::too_many_arguments)]
    async fn release_web_credential(
        &self,
        prepared: PreparedCredential,
        caller: &CallerDispatch,
        user: &str,
        resource: &str,
        needs: &RecipeNeeds,
        now_secs: u64,
        mfa_verified: bool,
        mut provider_audit: ProviderAudit,
    ) -> Result<ResolvedCredential, WebRefusal> {
        match prepared {
            PreparedCredential::Provider { launch, account_id, needs: provider_needs, totp: params } => {
                provider_audit.protocol = launch.protocol.into();
                provider_audit.provider = launch.provider.clone();
                provider_audit.account_id = account_id.clone();
                let released = match self
                    .release_provider(&launch, &account_id, provider_needs, mfa_verified, "web")
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        let r = provider_refusal(e);
                        provider_audit.denied(r.code);
                        return Err(r);
                    }
                };
                let login = released.username.clone();
                match provider_credential(released, needs, params, now_secs) {
                    Ok(c) => {
                        provider_audit.released(&login);
                        log::info!(
                            target: "security",
                            "resource-connect-web-resolve: user={user:?} resource={resource:?} source=provider \
                             provider={:?} account_id={account_id:?}",
                            launch.provider
                        );
                        Ok(c)
                    }
                    Err(r) => {
                        provider_audit.denied(reason::BAD_PROVIDER_OUTPUT);
                        Err(r)
                    }
                }
            }

            PreparedCredential::Ready { username, password, totp, source_detail } => {
                log::info!(
                    target: "security",
                    "resource-connect-web-resolve: user={user:?} resource={resource:?} {source_detail}"
                );
                let (code, totp_source) = match totp {
                    Some((key, source)) => (Some(totp::code_at(&key, source.params, now_secs)), Some(source)),
                    None => (None, None),
                };
                Ok(ResolvedCredential { username, password, totp: code, totp_source, ldap: None })
            }

            PreparedCredential::LdapStaticRole { mount, role } => {
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

            PreparedCredential::LdapLibrarySet { mount, set } => {
                let path = format!("{}{mount}library/{set}/check-out", caller.ns_prefix);
                let mut data = caller
                    .call(Operation::Write, &path, Some(Map::new()))
                    .await
                    .map_err(|e| WebRefusal::wrap("credential_unavailable", e))?
                    .unwrap_or_default();
                let parsed = parse_checkout(&data);
                zeroize_map(&mut data);
                let (account, password, lease_id) = match parsed {
                    Ok(c) => c,
                    Err(account) => {
                        // Checked out but unusable: give the account back now
                        // rather than leaving it leased until its TTL.
                        if let Some(account) = account {
                            let c = LdapCheckout {
                                mount: mount.clone(),
                                library_set: set.clone(),
                                account: account.to_string(),
                                lease_id: String::new(),
                                checked_in: false,
                            };
                            match caller.check_in(&c).await {
                                Ok(()) => log::info!(
                                    target: "audit",
                                    "connect.web.launch_rollback ldap_checkin=done resource={resource:?} account={:?}",
                                    c.account
                                ),
                                Err(e) => log::warn!(
                                    target: "audit",
                                    "connect.web.launch_rollback ldap_checkin=failed resource={resource:?} account={:?}: {e}",
                                    c.account
                                ),
                            }
                        }
                        return Err(unavailable(format!(
                            "LDAP library `{set}` check-out returned an incomplete response"
                        )));
                    }
                };
                let checkout = LdapCheckout {
                    mount,
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
                // `demand` cannot fail when the value is present.
                let username = demand(needs.username, needs.heuristic, Some(account), "username")?;
                let password = demand(needs.password, needs.heuristic, Some(password), "password")?;
                Ok(ResolvedCredential { username, password, ldap: Some(checkout), ..Default::default() })
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
    /// The resolver being unreachable (`ErrRouterMountNotFound`: `rustion/`
    /// unmounted, or tainted mid-unmount / remount) proves nothing, because
    /// Rustion keeps its tiers in the system view, not in the mount, and they
    /// survive an unmount. That case is allowed only when the system view's
    /// `rustion/policy/` prefix holds no record at all; otherwise — and on any
    /// other failure (the store unreadable, a tier record undecodable, an
    /// asset-group lookup error, a verdict this server cannot parse) — the
    /// launch is refused.
    pub(crate) async fn effective_transport(
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
            Err(RvError::ErrRouterMountNotFound) => self.prove_no_rustion_policy().await,
            Err(e) => Err(transport::unavailable(e.to_string())),
        }
    }

    /// With the resolver unreachable, allow only on proof that no Rustion
    /// policy record exists.
    async fn prove_no_rustion_policy(&self) -> Result<transport::TransportVerdict, WebRefusal> {
        let sys = self.core.system_view().ok_or_else(|| transport::unavailable("the vault is sealed"))?;
        let records = sys.list(transport::RUSTION_POLICY_PREFIX).await.map_err(|e| {
            transport::unavailable(format!(
                "the rustion/ mount is unavailable and its policy records cannot be listed: {e}"
            ))
        })?;
        if records.is_empty() {
            Ok(transport::TransportVerdict::NoRustion)
        } else {
            Err(transport::unavailable(
                "the rustion/ mount is unavailable (unmounted, or tainted mid-unmount or remount) while Rustion \
                 policy records exist, so the policy cannot be evaluated",
            ))
        }
    }

    async fn caller_identity(&self, req: &Request, audit: &mut AuditCtx) -> Result<CallerIdentity, WebRefusal> {
        let (mount, principal) = web_caller(req)?;
        audit.principal = audit_principal(&mount, &principal);
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

        // (3) A form launch's host copy of the recipe must be the stored one.
        // An http-auth profile has no recipe: a host that sends a hash for one
        // believes it is launching something else, so that is refused too.
        match (profile.recipe_hash(), string_field(req, "recipe_hash")) {
            (Some(_), None) => {
                return Err(WebRefusal::new(
                    400,
                    "recipe_hash_required",
                    "`recipe_hash` is required for a form-mode launch",
                ))
            }
            (Some(stored), Some(supplied)) if supplied != stored => {
                return Err(WebRefusal::new(
                    409,
                    "recipe_hash_mismatch",
                    "the profile's recipe changed since the host loaded it; reload the profile and launch again",
                ))
            }
            (None, Some(_)) => {
                return Err(WebRefusal::new(
                    400,
                    "recipe_hash_unexpected",
                    "this is an http-auth profile, which has no recipe, so its launch carries no `recipe_hash`; \
                     reload the profile and launch again",
                ))
            }
            (Some(_), Some(_)) | (None, None) => {}
        }

        // (4) Exposure cap and heuristic policy (§6), at both tiers. `form`
        // needs `dom`, `http-auth` `handler`; `allow_insecure_http` is
        // refused below a `dom` cap, and a launch that allows it is recorded
        // as `dom` whatever its mode.
        let type_def = self.resource_type_def(req, &meta).await?;
        let policy = ExposurePolicy::from_tiers(type_def.as_ref(), &meta)?;
        let cap = policy.check(profile.required_exposure(), profile.needs.heuristic, profile.allow_insecure_http)?;
        let exposure = profile.launched_exposure();

        // (4b) The Rustion transport tier. A web launch is always local, so
        // `rustion-required` (or a lock violation) refuses here — before the
        // ticket is burnt and before any credential is read — never a local
        // fallback.
        let transport = self.effective_transport(req, &resource, &meta).await?;

        // (4c) Every credential check that can run before the ticket does:
        // `secret` and `default-account` are resolved here (no side effects,
        // nothing released yet); `ldap` gets its mount checked.
        // A `provider` source writes its own `connect.provider.release` line
        // for every outcome from here on, next to `connect.web.*`.
        let mut provider_audit = ProviderAudit::new("release", "web", req);
        provider_audit.resource = resource.clone();
        provider_audit.profile_id = profile_id.clone();
        provider_audit.protocol = "web".into();
        provider_audit.provider = profile.source.provider().unwrap_or_default().to_string();
        provider_audit.account_id = account_id_field(req).ok().flatten().unwrap_or_default();
        let is_provider = profile.source.provider().is_some();

        let dispatch = CallerDispatch::new(self.core.clone(), req, &caller.namespace);
        let prepared = match self.prepare_web_credential(req, &dispatch, &resource, &meta, &profile).await {
            Ok(p) => p,
            Err(r) => {
                if is_provider {
                    provider_audit.denied(r.code);
                }
                return Err(r);
            }
        };

        // (5) Connect-time MFA. Only now, so a profile that fails a static,
        // policy or credential pre-check never costs the operator their
        // ticket. What can still fail after it: the LDAP static-credential
        // read or library check-out, the provider release, and persisting the
        // launch.
        let mfa_method = if profile.require_mfa {
            let ticket = match self.redeem_connect_ticket(req, &resource, &profile_id).await {
                Ok(t) => t,
                Err(e) => {
                    if is_provider {
                        provider_audit.denied(reason::MFA_REQUIRED);
                    }
                    return Err(WebRefusal::wrap("mfa", e));
                }
            };
            Some(ticket.method)
        } else {
            None
        };

        // (6) Release: the TOTP code for `now`, the LDAP read / check-out, or
        // the provider release (attested as MFA-verified only when this launch
        // redeemed a ticket).
        let user = caller_audit_actor(req);
        let mut cred = self
            .release_web_credential(
                prepared,
                &dispatch,
                &user,
                &resource,
                &profile.needs,
                now.timestamp().max(0) as u64,
                mfa_method.is_some(),
                provider_audit,
            )
            .await?;

        // (7) Persist the launch, with its fill scope. On failure, give back
        // an LDAP account that was just checked out rather than leaving it to
        // its lease.
        let fill_scope = FillScope {
            start_url: profile.start_url.clone(),
            origins: profile.origins.clone(),
            allow_insecure_http: profile.allow_insecure_http,
        };
        let record = WebLaunchRecord {
            v: LAUNCH_RECORD_VERSION,
            caller: caller.clone(),
            resource: resource.clone(),
            profile_id: profile_id.clone(),
            // `""` for http-auth, which has no recipe.
            recipe_hash: profile.recipe_hash().unwrap_or_default().to_string(),
            login_mode: profile.login_mode().into(),
            exposure: exposure.as_str().into(),
            credential_kind: profile.source.kind().into(),
            mfa_method: mfa_method.clone(),
            issued_at_ms: now_ms,
            login_expires_at_ms: now_ms + LOGIN_WINDOW_SECS * 1000,
            step_count: profile.needs.step_count,
            totp: cred.totp_source.take(),
            ldap: cred.ldap.clone(),
            result: None,
            closed_at_ms: None,
            fill_scope: Some(fill_scope.clone()),
        };
        let store = WebLaunchStore::new(self.core.as_ref());
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
                login_mode: profile.login_mode(),
                exposure: exposure.as_str(),
                exposure_cap: cap.as_str(),
                credential_source: profile.source.kind(),
                provider: profile.source.provider(),
                recipe_hash: profile.recipe_hash().unwrap_or("none"),
                heuristic: profile.needs.heuristic,
                mfa: mfa_method.as_deref().unwrap_or("none"),
                transport: transport.as_str(),
                fill_origins: &fill_scope.origins,
                released: &released,
                launch_id_hash: &audit.launch_id_hash,
            })
        );

        // (7b) Reap expired records — at most once a minute per process, after
        // the launch is persisted, and never a reason to fail it.
        if TIDY_THROTTLE.claim(now_ms) {
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
                Err(e) => log::warn!("connect.web: launch-record tidy failed: {e}"),
            }
        }

        // (8) The bundle.
        let refresh_steps = record.totp.as_ref().map(|t| t.refresh_steps.clone()).unwrap_or_default();
        launch_bundle(BundleParts {
            launch_id,
            expires_at_ms: record.login_expires_at_ms,
            resource,
            profile_id,
            profile: &profile,
            exposure,
            cap,
            fill_scope: &fill_scope,
            cred: &cred,
            totp_refresh_steps: refresh_steps,
            mfa_method,
        })
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
            provider: None,
            recipe_hash: "sha256:ab",
            heuristic: false,
            mfa: "totp",
            transport: "rustion-preferred",
            fill_origins: &["https://fw01.example.com".to_string()],
            released: "username,password,totp",
            launch_id_hash: "cd",
        });
        assert!(line.starts_with("connect.web.launch "));
        assert!(line.contains(" provider=none "));
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
        // Origins appear (§11 allows them); paths and queries never do.
        assert!(line.contains(r#"fill_origins=["https://fw01.example.com"]"#));
        assert_eq!(line.matches("://").count(), 1, "the only URL-like text is the origin: {line}");

        // Operator-controlled names are quoted, so one cannot forge a field.
        let mut a = AuditCtx::new("launch");
        a.resource = "fw01 reason=ok\nconnect.web.launch".into();
        let r = WebRefusal::new(403, "exposure_cap_exceeded", "x");
        let line = refused_line(&a, &r);
        assert!(!line.contains('\n'));
        assert!(line.contains("reason=exposure_cap_exceeded"));
        assert!(line.contains(r#"resource="fw01 reason=ok\nconnect.web.launch""#));

        // A provider launch names the provider (quoted) and, like every other
        // source, the parts released — never their values. The line is built
        // from names only: the released credential is not an input to it.
        let line = launch_line(&LaunchAudit {
            principal: "userpass/alice",
            namespace: "",
            resource: "fw01",
            profile: "p_web",
            login_mode: "form",
            exposure: "dom",
            exposure_cap: "dom",
            credential_source: "provider",
            provider: Some("self-accounts"),
            recipe_hash: "sha256:ab",
            heuristic: false,
            mfa: "totp",
            transport: "direct",
            fill_origins: &["https://fw01.example.com".to_string()],
            released: "username,password",
            launch_id_hash: "cd",
        });
        assert!(line.contains(r#"credential_source=provider provider="self-accounts" "#), "{line}");
        assert!(line.contains("released=username,password "));
    }

    #[test]
    fn a_provider_release_fills_only_what_the_recipe_asks() {
        let released = |seed: Option<&str>| ReleasedCredential {
            username: "felipe".into(),
            domain: Some("CORP".into()),
            secret: ReleasedSecret::Password {
                password: Zeroizing::new("hunter2-S3CRET".into()),
                totp_seed: seed.map(|s| Zeroizing::new(s.to_string())),
            },
        };
        let explicit = |username, password, totp| RecipeNeeds {
            heuristic: false,
            username,
            password,
            totp,
            totp_steps: if totp { vec![1] } else { vec![] },
            step_count: 2,
        };

        // Username + password: the domain is not a web fill.
        let c = provider_credential(released(None), &explicit(true, true, false), TotpParams::default(), 59).unwrap();
        assert_eq!(c.username.as_deref().map(String::as_str), Some("felipe"));
        assert_eq!(c.password.as_deref().map(String::as_str), Some("hunter2-S3CRET"));
        assert!(c.totp.is_none() && c.totp_source.is_none());

        // A recipe that fills only the username gets no password.
        let c = provider_credential(released(None), &explicit(true, false, false), TotpParams::default(), 59).unwrap();
        assert!(c.password.is_none());
        assert_eq!(c.released(), "username");

        // A seed becomes the code for `now`, and no refresh source is kept.
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let c = provider_credential(released(Some(seed)), &explicit(true, true, true), TotpParams::default(), 59)
            .unwrap();
        assert_eq!(c.totp.unwrap().code.as_str(), "287082", "RFC 6238 SHA1 vector at t=59, 6 digits");
        assert!(c.totp_source.is_none());

        // A recipe that fills `totp` with no seed released is refused.
        let r = provider_credential(released(None), &explicit(true, true, true), TotpParams::default(), 59).err().unwrap();
        assert_eq!(r.code, "totp_not_configured");

        // An SSH key is never a web credential.
        let key = ReleasedCredential {
            username: "u".into(),
            domain: None,
            secret: ReleasedSecret::SshKey { private_key: Zeroizing::new("k".into()) },
        };
        assert_eq!(
            provider_credential(key, &explicit(true, true, false), TotpParams::default(), 59).err().unwrap().code,
            "credential_unavailable"
        );
    }

    #[test]
    fn provider_needs_never_ask_a_heuristic_launch_for_a_totp() {
        let heuristic = RecipeNeeds {
            heuristic: true,
            username: true,
            password: true,
            totp: true,
            totp_steps: vec![0],
            step_count: 1,
        };
        assert_eq!(provider_needs(&heuristic), ProviderNeeds { password: true, totp: false });
        let explicit = RecipeNeeds { heuristic: false, ..heuristic.clone() };
        assert_eq!(provider_needs(&explicit), ProviderNeeds { password: true, totp: true });
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

        // No username: the entity id, before anything else.
        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "oidc/".into());
        auth.metadata.insert("entity_id".into(), "ent-1".into());
        auth.display_name = "oidc-alice".into();
        req.auth = Some(auth);
        assert_eq!(web_caller(&req).unwrap(), ("oidc/".to_string(), "entity:ent-1".to_string()));

        // A username with no mount does not bind by name.
        let mut auth = Auth::default();
        auth.metadata.insert("username".into(), "alice".into());
        auth.metadata.insert("entity_id".into(), "ent-2".into());
        req.auth = Some(auth);
        assert_eq!(web_caller(&req).unwrap().1, "entity:ent-2");

        // No entity (a root token): the token, by hash — never the display name.
        let mut auth = Auth::default();
        auth.display_name = "root".into();
        req.auth = Some(auth);
        req.client_token = "s.roottoken".into();
        let (mount, principal) = web_caller(&req).unwrap();
        assert_eq!(mount, "");
        assert_eq!(principal, format!("token:{}", hex::encode(Sha256::digest(b"s.roottoken"))));
        assert!(!principal.contains("s.roottoken"));
        assert_eq!(audit_principal(&mount, &principal).len(), "token:".len() + 16);

        // A display name binds only on a known mount, and never alone.
        req.client_token.clear();
        assert_eq!(web_caller(&req).unwrap_err().code, "no_principal", "empty mount + display name");
        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "cert/".into());
        auth.display_name = "web-ops".into();
        req.auth = Some(auth);
        assert_eq!(web_caller(&req).unwrap(), ("cert/".to_string(), "name:web-ops".to_string()));

        req.auth = Some(Auth::default());
        assert_eq!(web_caller(&req).unwrap_err().code, "no_principal");
    }

    #[test]
    fn an_incomplete_checkout_names_the_account_to_give_back() {
        let full = serde_json::json!({ "service_account_name": "svc-1", "password": "p", "lease_id": "l" });
        let (a, p, l) = parse_checkout(full.as_object().unwrap()).ok().unwrap();
        assert_eq!((a.as_str(), p.as_str(), l.as_str()), ("svc-1", "p", "l"));

        for (body, account) in [
            (serde_json::json!({ "service_account_name": "svc-1", "password": "p" }), Some("svc-1")),
            (serde_json::json!({ "service_account_name": "svc-1", "lease_id": "l" }), Some("svc-1")),
            (serde_json::json!({ "password": "p", "lease_id": "l" }), None),
            (serde_json::json!({}), None),
        ] {
            let got = parse_checkout(body.as_object().unwrap()).err().unwrap();
            assert_eq!(got.as_deref().map(String::as_str), account, "{body}");
        }
    }

    #[test]
    fn zeroize_map_scrubs_nested_strings() {
        let mut m: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "password": "hunter2", "nested": { "seed": "abc" }, "n": 1,
            "codes": ["123456", { "k": "v" }, ["deep"]]
        }))
        .unwrap();
        zeroize_map(&mut m);
        assert_eq!(m["password"], Value::String(String::new()));
        assert_eq!(m["nested"]["seed"], Value::String(String::new()));
        assert_eq!(m["codes"], serde_json::json!(["", { "k": "" }, [""]]));
    }
    fn bundle_for(profile: &Value, cred: &ResolvedCredential) -> Map<String, Value> {
        let profile = parse_launch_profile(profile).unwrap();
        let fill_scope = FillScope {
            start_url: profile.start_url.clone(),
            origins: profile.origins.clone(),
            allow_insecure_http: profile.allow_insecure_http,
        };
        launch_bundle(BundleParts {
            launch_id: "id".into(),
            expires_at_ms: 0,
            resource: "fw01".into(),
            profile_id: "p".into(),
            profile: &profile,
            exposure: profile.launched_exposure(),
            cap: WebExposure::Dom,
            fill_scope: &fill_scope,
            cred,
            totp_refresh_steps: vec![1],
            mfa_method: None,
        })
        .unwrap()
    }

    fn full_credential() -> ResolvedCredential {
        ResolvedCredential {
            username: Some(Zeroizing::new("admin".into())),
            password: Some(Zeroizing::new("hunter2".into())),
            totp: Some(totp::code_at(b"12345678901234567890", totp::TotpParams::default(), 59)),
            ..Default::default()
        }
    }

    #[test]
    fn an_http_auth_bundle_carries_username_and_password_only() {
        let profile = serde_json::json!({
            "id": "p", "name": "p", "protocol": "web",
            "credential_source": { "kind": "secret", "secret_id": "admin" },
            "web": { "start_url": "https://bmc.example.com/", "login_mode": "http-auth" }
        });
        let b = bundle_for(&profile, &full_credential());
        assert_eq!(b["login_mode"], Value::String("http-auth".into()));
        assert_eq!(b["exposure"], Value::String("handler".into()));
        assert!(!b.contains_key("recipe_hash"), "an http-auth launch has no recipe");
        assert_eq!(b["heuristic"], Value::Bool(false));
        assert_eq!(b["totp_refresh_steps"], serde_json::json!([]));
        // Even a resolved TOTP code never reaches an http-auth bundle.
        let cred = b["credential"].as_object().unwrap();
        let mut keys: Vec<&str> = cred.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["password", "username"]);
        assert_eq!(
            b["fill_scope"],
            serde_json::json!({ "start_url": "https://bmc.example.com/", "origins": ["https://bmc.example.com"],
                                 "allow_insecure_http": false })
        );

        // Plain http allowed: reported as `dom`, never `handler`.
        let mut insecure = profile.clone();
        insecure["web"]["start_url"] = Value::String("http://bmc.example.com/".into());
        insecure["web"]["allow_insecure_http"] = Value::Bool(true);
        assert_eq!(bundle_for(&insecure, &full_credential())["exposure"], Value::String("dom".into()));
    }

    #[test]
    fn a_form_bundle_keeps_its_recipe_hash_and_totp() {
        let profile = serde_json::json!({
            "id": "p", "name": "p", "protocol": "web",
            "credential_source": { "kind": "secret", "secret_id": "admin" },
            "web": { "start_url": "https://fw01.example.com/login", "login_mode": "form",
                     "recipe": { "version": 1, "steps": [ { "when_url": "https://fw01.example.com/*",
                       "actions": [ { "fill": "#otp", "value": "totp" } ] } ],
                       "success_when": { "url": "https://fw01.example.com/ng/*" } } }
        });
        let b = bundle_for(&profile, &full_credential());
        assert_eq!(b["login_mode"], Value::String("form".into()));
        assert_eq!(b["exposure"], Value::String("dom".into()));
        assert!(b["recipe_hash"].as_str().unwrap().starts_with("sha256:"));
        assert!(b["credential"].as_object().unwrap().contains_key("totp"));
        assert_eq!(b["totp_refresh_steps"], serde_json::json!([1]));
    }
}
