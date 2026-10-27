//! MCP Access (`features/mcp-access.md`, Phase 2): the `sys/mcp/*` app
//! registry and the `mcp/token` exchange. See that spec's § 2-4.
// source: features/mcp-access.md §2-4 (storage layout, accessor scheme,
// and why the reverse index is a separate top-level prefix from the app
// record are working notes, not separate decisions -- see the doc itself).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    errors::RvError,
    logical::{
        field::FieldTrait, is_open_world_mcp_tool, Auth, McpBinding, McpBindingKind, McpOperatorRef, Request, Response,
        ENTITY_ID_META, SPIFFE_ID_META, USERNAME_META,
    },
    modules::auth::AuthModule,
    modules::policy::PolicyModule,
    storage::StorageEntry,
};

use super::SystemBackend;
use crate::kernel_api::{
    mcp_events::TranscriptAccessed,
    mcp_transcripts::{parse_transcript_id, TranscriptError, TranscriptStore},
};

/// A transcript store failure as an operator-facing error: a malformed id is
/// the caller's (400), an unreadable record or a storage failure the
/// vault's (500), each naming why.
fn transcript_error(e: TranscriptError) -> RvError {
    match e {
        TranscriptError::InvalidId(_) | TranscriptError::Invalid(_) => {
            crate::bv_error_response_status!(400, "{}", e)
        }
        TranscriptError::Unreadable { .. } | TranscriptError::Storage(_) => {
            crate::bv_error_response_status!(500, "{}", e)
        }
    }
}

/// RFC3339 of a transcript id's nanosecond half.
fn nanos_rfc3339(nanos: u128) -> String {
    i64::try_from(nanos).map(|n| chrono::DateTime::from_timestamp_nanos(n).to_rfc3339()).unwrap_or_default()
}

pub const MCP_CONFIG_KEY: &str = "mcp/config";
pub const MCP_APP_PREFIX: &str = "mcp/apps/";
pub const MCP_APP_TOKEN_PREFIX: &str = "mcp/app-tokens/";

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `accessor` = `hex(blake3(token_id))`: a stable, non-secret handle
/// computable from the id but not reversible to it. Not a general
/// `TokenStore` accessor system -- this codebase has none; see the module
/// doc.
fn token_accessor(id: &str) -> String {
    blake3::hash(id.as_bytes()).to_hex().to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachineWaiver {
    pub reason: String,
    pub granted_by: String,
    pub granted_at: u64,
    pub expires_at: u64,
}

impl MachineWaiver {
    pub fn is_active(&self) -> bool {
        self.expires_at > now_secs()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpApp {
    #[serde(default = "default_version")]
    pub version: u32,
    pub name: String,
    pub approle_role: String,
    #[serde(default)]
    pub entity_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    #[serde(default)]
    pub path_scope: Vec<String>,
    #[serde(default)]
    pub reveal_allowed: bool,
    #[serde(default)]
    pub destructive_allowed: bool,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default)]
    pub machine_waiver: Option<MachineWaiver>,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: u64,
}

fn default_version() -> u32 {
    1
}
fn default_ttl_secs() -> u64 {
    3600
}
fn default_max_ttl_secs() -> u64 {
    86400
}
fn default_waiver_max_days() -> u32 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRuntimeConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
    #[serde(default = "default_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_waiver_max_days")]
    pub waiver_max_days: u32,
    #[serde(default)]
    pub catalogue_pin: Option<String>,
    /// The runtime "big red button" for brokered sessions
    /// (`features/mcp-brokered-sessions.md` §11): every session call needs
    /// it on, as well as the server config's `mcp.brokered_sessions`.
    /// `#[serde(default)]`: a record written before the field existed reads
    /// as off.
    #[serde(default)]
    pub brokered_sessions_enabled: bool,
    /// The runtime destination allow-list (§12). `None` (`null`) means the
    /// server config's list applies, or the built-in default when that sets
    /// none; a list replaces it, and an empty list allows no destination.
    /// Validated on write: every entry parses as a CIDR.
    #[serde(default)]
    pub brokered_sessions_allowed_target_cidrs: Option<Vec<String>>,
}

impl Default for McpRuntimeConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            default_ttl_secs: default_ttl_secs(),
            max_ttl_secs: default_max_ttl_secs(),
            waiver_max_days: default_waiver_max_days(),
            catalogue_pin: None,
            brokered_sessions_enabled: false,
            brokered_sessions_allowed_target_cidrs: None,
        }
    }
}

/// A request field read without `get_data`'s per-type coercion, which has no
/// way to say "present and `null`" — the reset value of
/// `brokered_sessions_allowed_target_cidrs`.
fn raw_request_field<'a>(req: &'a Request, key: &str) -> Option<&'a Value> {
    req.data.as_ref().and_then(|d| d.get(key)).or_else(|| req.body.as_ref().and_then(|b| b.get(key)))
}

/// `brokered_sessions_enabled`: a JSON boolean, or the strings `"true"` /
/// `"false"` the CLI's `key=value` form sends. Anything else is refused
/// rather than read as "off" or left unchanged.
fn parse_runtime_switch(value: &Value) -> Result<bool, RvError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(crate::bv_error_response_status!(400, "brokered_sessions_enabled must be a boolean")),
    }
}

/// `brokered_sessions_allowed_target_cidrs`: `null` resets to the server
/// config's value; a JSON array of strings, or one comma-separated string
/// (the CLI's form, `""` being the empty list), replaces it. Returns the new
/// value and the overlap warnings. Every entry must parse, or the write is
/// refused naming the entry.
fn parse_runtime_target_cidrs(value: &Value) -> Result<(Option<Vec<String>>, Vec<String>), RvError> {
    let entries: Vec<String> = match value {
        Value::Null => return Ok((None, Vec::new())),
        Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_str().map(|s| s.trim().to_string()).ok_or_else(|| {
                    crate::bv_error_response_status!(
                        400,
                        "brokered_sessions_allowed_target_cidrs entries must be strings"
                    )
                })
            })
            .collect::<Result<_, _>>()?,
        Value::String(s) if s.trim().is_empty() => Vec::new(),
        Value::String(s) => s.split(',').map(|e| e.trim().to_string()).collect(),
        _ => {
            return Err(crate::bv_error_response_status!(
                400,
                "brokered_sessions_allowed_target_cidrs must be a list of CIDRs, a comma-separated string, or null"
            ))
        }
    };
    let parsed = bv_utils::destination_policy::parse_target_cidrs(&entries)
        .map_err(|e| crate::bv_error_response_status!(400, "brokered_sessions_{}", e))?;
    Ok((Some(entries), parsed.warnings))
}

/// The reverse-index entry stored under `mcp/app-tokens/<name>/<accessor>`.
/// Barrier-encrypted like every other storage entry, reachable only
/// through the same ACL that reaches `sys/mcp/apps/*` -- so keeping the
/// raw `id` here (needed to call `TokenStore::revoke`) does not widen what
/// any API caller can read; every response handed back to a caller carries
/// the accessor hash only, never this entry's `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTokenIndexEntry {
    pub id: String,
    /// The index directory this entry lives under: an app name for an app
    /// token, `pairing_<id>` for a pairing token (`_` is not legal in an app
    /// name, so the two can never collide).
    pub app_name: String,
    pub client_name: String,
    pub client_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// `"app"` or `"pairing"`. Absent on entries written before pairing mode
    /// existed, which are all app tokens.
    #[serde(default = "default_token_kind")]
    pub kind: String,
    /// The namespace the token is bound to (`""` = root). `None` on entries
    /// written before MCP tokens carried a binding: those tokens are
    /// root-bound (`features/mcp-namespace-selection.md`).
    #[serde(default)]
    pub namespace: Option<String>,
}

/// Where a pairing's last exchange was bound, stored under
/// `mcp/pairing-namespaces/<id>` so the next exchange can tell that the
/// pairing moved and record it (`mcp.pairing.namespace_changed`). One small
/// record per pairing, deleted with the pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPairingNamespace {
    #[serde(default = "default_version")]
    pub version: u32,
    pub namespace: String,
    pub recorded_at: u64,
}

pub const MCP_PAIRING_NAMESPACE_PREFIX: &str = "mcp/pairing-namespaces/";

/// The stable refusal for an MCP token whose namespace cannot be used: a
/// binding that does not normalize, a namespace that was deleted or that the
/// vault cannot resolve. Never answered by falling back to root.
pub const MCP_NAMESPACE_UNAVAILABLE: &str = "mcp_namespace_unavailable";

/// The stable refusal for a narrowed exchange whose policies do not exist
/// in the target namespace (T457 Phase 2).
pub const MCP_POLICY_NOT_IN_NAMESPACE: &str = "mcp_policy_not_in_namespace";

fn default_token_kind() -> String {
    "app".to_string()
}

const PAIRING_INDEX_PREFIX: &str = "pairing_";

fn pairing_index_dir(pairing_id: &str) -> String {
    format!("{PAIRING_INDEX_PREFIX}{pairing_id}")
}

/// A pairing id is minted by the local MCP server; bound it to something
/// that is safe to use as a storage path segment and cannot collide with an
/// app's index directory.
fn valid_pairing_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

const MAX_PAIRING_LIST_LEN: usize = 64;
const MAX_PAIRING_STR_LEN: usize = 256;

fn pairing_str_list(p: &Map<String, Value>, key: &str) -> Result<Vec<String>, RvError> {
    let Some(value) = p.get(key) else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| crate::bv_error_response!("pairing.{} must be an array of strings", key))?;
    if arr.len() > MAX_PAIRING_LIST_LEN {
        return Err(crate::bv_error_response!("pairing.{} has too many entries", key));
    }
    arr.iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= MAX_PAIRING_STR_LEN)
                .map(str::to_string)
                .ok_or_else(|| crate::bv_error_response!("pairing.{} entries must be non-empty strings", key))
        })
        .collect()
}

fn pairing_str(p: &Map<String, Value>, key: &str, required: bool) -> Result<String, RvError> {
    match p.get(key).and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.len() <= MAX_PAIRING_STR_LEN => Ok(s.to_string()),
        Some(s) if s.is_empty() && !required => Ok(String::new()),
        None if !required => Ok(String::new()),
        _ => Err(crate::bv_error_response!("pairing.{} is required", key)),
    }
}

/// An optional boolean in the pairing grant, read strictly: absent or `null`
/// is `None`, anything that is not a boolean is refused rather than read as
/// "off" — a security switch must not have a typo-shaped default.
fn pairing_opt_bool(p: &Map<String, Value>, key: &str) -> Result<Option<bool>, RvError> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(crate::bv_error_response!("pairing.{} must be a boolean", key)),
    }
}

/// The brokered-session half of a pairing grant
/// (`features/mcp-brokered-sessions.md` §9), re-checked here although the
/// local gatekeeper's `normalize_grant` enforces the same rules, because the
/// exchange body is the only thing the vault actually sees:
///
/// * `confirm_connect` can never be turned off: an explicit `false` is
///   refused whether or not `connect_allowed` is set;
/// * `connect_allowed` requires `confirm_connect = true` in the body — absent
///   is refused, not defaulted, so a gatekeeper that does not know about
///   confirmation cannot obtain a session grant;
/// * a session tool in the allow-list requires `connect_allowed`.
///
/// Returns the granted `connect_allowed`.
fn check_pairing_connect_grant(pairing: &Map<String, Value>, tool_allowlist: &[String]) -> Result<bool, RvError> {
    let connect_allowed = pairing_opt_bool(pairing, "connect_allowed")?.unwrap_or(false);
    let confirm_connect = pairing_opt_bool(pairing, "confirm_connect")?;
    if confirm_connect == Some(false) {
        return Err(crate::bv_error_response!(
            "pairing.confirm_connect cannot be false: every brokered session call is confirmed by the operator, and that is not configurable"
        ));
    }
    if connect_allowed && confirm_connect != Some(true) {
        return Err(crate::bv_error_response!(
            "pairing.connect_allowed requires pairing.confirm_connect = true: every brokered session call is confirmed by the operator"
        ));
    }
    if let Some(tool) = tool_allowlist.iter().find(|t| is_open_world_mcp_tool(t)) {
        if !connect_allowed {
            return Err(crate::bv_error_response!(
                "pairing.tool_allowlist names the session tool {:?}, which requires pairing.connect_allowed = true",
                tool
            ));
        }
    }
    Ok(connect_allowed)
}

/// The operator record a pairing binding carries (`McpBinding::operator`),
/// copied from the exchanging session's own auth metadata. The namespace is
/// normalized exactly as a connect MFA ticket's `namespace` binding is, so a
/// later ticket redemption compares like with like; a namespace binding that
/// does not normalize is refused rather than recorded in a form nothing could
/// match.
fn operator_ref_from_auth(auth: &Auth) -> Result<McpOperatorRef, RvError> {
    let meta = |key: &str| auth.metadata.get(key).cloned().unwrap_or_default();
    let (ns_path, _child_visible) = crate::kernel_api::namespace::binding_from_metadata(&auth.metadata);
    let namespace = crate::kernel_api::namespace::normalize_path(&ns_path).map_err(|_| {
        crate::bv_error_response_status!(
            403,
            "mcp_pairing_requires_operator_session: the session's namespace binding is malformed"
        )
    })?;
    Ok(McpOperatorRef {
        entity_id: meta(ENTITY_ID_META),
        username: meta(USERNAME_META),
        mount_path: meta("mount_path"),
        namespace,
    })
}

/// The token store binds an MCP token from the parent's stored entry, and
/// the exchange resolved the same binding; both must agree. A disagreement
/// is a bug: the token is revoked and the exchange refused, never answered
/// with either value.
#[maybe_async::maybe_async]
async fn check_minted_namespace(
    token_store: &crate::modules::auth::token_store::TokenStore,
    minted: &Auth,
    expected: &str,
) -> Result<(), RvError> {
    let bound =
        crate::kernel_api::namespace::bound_namespace(&minted.metadata).unwrap_or_else(|_| "<malformed>".into());
    if bound == expected {
        return Ok(());
    }
    token_store.revoke(&minted.client_token).await?;
    Err(namespace_unavailable(&format!("the minted token was bound to {bound:?}, not {expected:?}")))
}

fn namespace_unavailable(why: &str) -> RvError {
    crate::bv_error_response_status!(
        403,
        "{}: {}; refusing rather than binding the MCP token to root",
        MCP_NAMESPACE_UNAVAILABLE,
        why
    )
}

/// The namespace an MCP token minted for `auth` will be bound to: the
/// exchanging session's own stored binding, canonical, and still resolvable
/// now (`features/mcp-namespace-selection.md` Phase 1). Never read from a
/// header, the body or a tool argument. Root needs no lookup.
#[maybe_async::maybe_async]
async fn exchange_namespace(core: &crate::core::Core, auth: &Auth) -> Result<String, RvError> {
    use crate::modules::namespace::{NamespaceModule, NAMESPACE_MODULE_NAME};
    let ns = crate::kernel_api::namespace::bound_namespace(&auth.metadata)
        .map_err(|_| namespace_unavailable("the session's namespace binding is malformed"))?;
    if ns.is_empty() {
        return Ok(ns);
    }
    let store =
        core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME).and_then(|m| m.store()).ok_or_else(
            || namespace_unavailable(&format!("namespace {ns:?} cannot be resolved: no namespace store")),
        )?;
    match store.get_by_path(&ns).await {
        Ok(Some(found)) => Ok(found.path),
        Ok(None) => Err(namespace_unavailable(&format!("namespace {ns:?} no longer exists"))),
        Err(e) => Err(namespace_unavailable(&format!("namespace {ns:?} could not be resolved ({e})"))),
    }
}

fn namespace_not_permitted(why: &str) -> RvError {
    crate::bv_error_response_status!(
        403,
        "{}: {}; no MCP token is minted for another namespace instead",
        crate::modules::auth::token_store::MCP_NAMESPACE_NOT_PERMITTED,
        why
    )
}

/// The namespace a pairing exchange asked to narrow its token to (T457
/// Phase 2): well-formed, covered by `token_may_operate` over the session's
/// stored binding, then resolved. Permission is judged before existence, so
/// a refusal says nothing about namespaces the session cannot reach.
#[maybe_async::maybe_async]
async fn narrowing_target(
    core: &crate::core::Core,
    auth: &Auth,
    raw: &str,
) -> Result<crate::modules::auth::token_store::McpNamespaceTarget, RvError> {
    use crate::modules::auth::token_store::McpNamespaceTarget;
    use crate::modules::namespace::{token_binding, NamespaceModule, NAMESPACE_MODULE_NAME};
    let requested = crate::kernel_api::namespace::normalize_path(raw)
        .map_err(|_| namespace_not_permitted(&format!("{raw:?} is not a well-formed namespace path")))?;
    let session = crate::kernel_api::namespace::bound_namespace(&auth.metadata)
        .map_err(|_| namespace_unavailable("the session's namespace binding is malformed"))?;
    // The stored binding first; failing that, the explicit namespace
    // assignment every other request honours (the route the GUI's namespace
    // picker takes). A store error is not "no assignment": it is reported as
    // unavailable, never as a refusal claiming the session lacks reach.
    let (_, child_visible) = token_binding::binding_from_metadata(&auth.metadata);
    let by_binding = token_binding::token_may_operate(&session, child_visible, &requested);
    if !by_binding {
        let assigned = token_binding::token_operable_checked(core, auth, &requested)
            .await
            .map_err(|e| namespace_unavailable(&format!("the namespace assignment could not be read ({e})")))?;
        if !assigned {
            let reach = if child_visible { "its own namespace and its descendants" } else { "only its own namespace" };
            return Err(namespace_not_permitted(&format!(
                "the session is bound to {session:?} and may narrow to {reach} or to a namespace assigned to it, not {requested:?}"
            )));
        }
    }
    let assignment_granted = !by_binding;
    if requested.is_empty() {
        return Ok(McpNamespaceTarget { path: String::new(), id: String::new(), assignment_granted });
    }
    let store =
        core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME).and_then(|m| m.store()).ok_or_else(
            || namespace_unavailable(&format!("namespace {requested:?} cannot be resolved: no namespace store")),
        )?;
    match store.get_by_path(&requested).await {
        Ok(Some(found)) => Ok(McpNamespaceTarget { path: found.path, id: found.uuid, assignment_granted }),
        Ok(None) => Err(namespace_unavailable(&format!("namespace {requested:?} does not exist"))),
        Err(e) => Err(namespace_unavailable(&format!("namespace {requested:?} could not be resolved ({e})"))),
    }
}

/// The namespaces the exchanging session may operate in right now -- its
/// binding or an explicit assignment, the answer `sys/namespaces-self` gives
/// it -- sorted and capped. Recorded on the binding of a pairing that carries
/// `bv_policy_read` ([`McpBinding::policy_namespaces`]). A store error fails
/// the exchange: a shorter list would silently narrow what was approved.
#[maybe_async::maybe_async]
async fn issuer_operable_namespaces(core: &crate::core::Core, auth: &Auth) -> Result<Vec<String>, RvError> {
    use crate::modules::namespace::{token_binding, NamespaceModule, NAMESPACE_MODULE_NAME};
    let store = core
        .module_manager()
        .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        .and_then(|m| m.store())
        .ok_or_else(|| namespace_unavailable("the namespace store is not available to list the issuer's namespaces"))?;
    let mut operable = Vec::new();
    for ns in store.list_all().await? {
        if token_binding::token_operable_checked(core, auth, &ns.path).await? {
            operable.push(ns.path);
        }
    }
    operable.sort();
    operable.truncate(crate::logical::MCP_POLICY_NAMESPACES_MAX);
    Ok(operable)
}

/// The optional `namespace` of an exchange body: `None` when absent, the raw
/// string otherwise. Any other shape is refused rather than ignored.
fn requested_namespace(req: &Request) -> Result<Option<String>, RvError> {
    match req.get_data("namespace") {
        Ok(Value::String(raw)) => Ok(Some(raw)),
        Err(RvError::ErrRequestFieldNotFound | RvError::ErrRequestNoData) => Ok(None),
        Ok(_) | Err(_) => Err(crate::bv_error_response_status!(400, "`namespace` must be a namespace path string")),
    }
}

/// The first open-world tool in an app's allow-list, if any. Network-mode
/// apps never open brokered sessions — a permanent exclusion
/// (`features/mcp-brokered-sessions.md` §1), not a v1 limit — so a record
/// carrying one is refused on write and cannot be exchanged.
fn app_open_world_tool(app: &McpApp) -> Option<&str> {
    app.tool_allowlist.iter().map(|t| t.trim()).find(|t| is_open_world_mcp_tool(t))
}

fn app_open_world_refusal(app_name: &str, tool: &str) -> RvError {
    crate::bv_error_response_status!(
        400,
        "mcp_connect_requires_local_operator: MCP app {:?} lists the session tool {:?}; network-mode apps never open brokered sessions, \
         because there is no operator to confirm each call. Remove it from the app's tool_allowlist; sessions are available to local pairings only",
        app_name,
        tool
    )
}

async fn get_app(req: &Request, name: &str) -> Result<Option<McpApp>, RvError> {
    match req.storage_get(&format!("{MCP_APP_PREFIX}{name}")).await? {
        Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
        None => Ok(None),
    }
}

async fn put_app(req: &Request, app: &McpApp) -> Result<(), RvError> {
    let entry = StorageEntry::new(&format!("{MCP_APP_PREFIX}{}", app.name), app)?;
    req.storage_put(&entry).await
}

async fn index_token(req: &Request, entry: &McpTokenIndexEntry) -> Result<(), RvError> {
    let key = format!("{MCP_APP_TOKEN_PREFIX}{}/{}", entry.app_name, token_accessor(&entry.id));
    let storage_entry = StorageEntry::new(&key, entry)?;
    req.storage_put(&storage_entry).await
}

#[maybe_async::maybe_async]
impl SystemBackend {
    pub async fn handle_mcp_config_read(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = match req.storage_get(MCP_CONFIG_KEY).await? {
            Some(entry) => serde_json::from_slice(&entry.value)?,
            None => McpRuntimeConfig::default(),
        };
        Ok(Some(Response::data_response(Some(self.mcp_config_response(&cfg)?))))
    }

    /// The stored runtime record plus what is actually in force for brokered
    /// sessions once the server config is folded in: the effective
    /// destination list and the layer it came from (`runtime`, `hcl` or
    /// `default`), the server config's static switch and protocols, and the
    /// always-denied classes no list can re-allow. The derived keys are
    /// read-only; a write ignores them.
    fn mcp_config_response(&self, cfg: &McpRuntimeConfig) -> Result<Map<String, Value>, RvError> {
        let mut data = serde_json::to_value(cfg)?.as_object().cloned().unwrap_or_default();
        let server = &self.core.mcp_brokered_sessions;
        let (effective, source) = bv_utils::destination_policy::effective_target_cidr_entries(
            cfg.brokered_sessions_allowed_target_cidrs.as_deref(),
            server.allowed_target_cidrs.as_deref(),
        );
        data.insert("brokered_sessions_effective_target_cidrs".into(), serde_json::to_value(effective)?);
        data.insert("brokered_sessions_target_cidrs_source".into(), Value::String(source.as_str().to_string()));
        data.insert("brokered_sessions_server_enabled".into(), Value::Bool(server.enabled));
        data.insert("brokered_sessions_server_protocols".into(), serde_json::to_value(&server.protocols)?);
        data.insert(
            "brokered_sessions_always_denied".into(),
            Value::Array(
                bv_utils::destination_policy::AlwaysDenied::ALL
                    .iter()
                    .map(|c| Value::String(c.as_str().to_string()))
                    .collect(),
            ),
        );
        Ok(data)
    }

    pub async fn handle_mcp_config_write(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut cfg = match req.storage_get(MCP_CONFIG_KEY).await? {
            Some(entry) => serde_json::from_slice(&entry.value)?,
            None => McpRuntimeConfig::default(),
        };
        if let Ok(v) = req.get_data("default_ttl_secs") {
            if let Some(n) = v.as_u64() {
                cfg.default_ttl_secs = n;
            }
        }
        if let Ok(v) = req.get_data("max_ttl_secs") {
            if let Some(n) = v.as_u64() {
                cfg.max_ttl_secs = n;
            }
        }
        if let Ok(v) = req.get_data("waiver_max_days") {
            if let Some(n) = v.as_u64() {
                cfg.waiver_max_days = n as u32;
            }
        }
        if let Ok(v) = req.get_data("catalogue_pin") {
            cfg.catalogue_pin = v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
        }

        // Brokered sessions (`features/mcp-brokered-sessions.md` §11-12).
        // Parsed before anything is stored, so an invalid entry leaves the
        // stored record untouched.
        let previous_enabled = cfg.brokered_sessions_enabled;
        let previous_cidrs = cfg.brokered_sessions_allowed_target_cidrs.clone();
        let mut warnings = Vec::new();
        let enabled_given = raw_request_field(req, "brokered_sessions_enabled").cloned();
        let cidrs_given = raw_request_field(req, "brokered_sessions_allowed_target_cidrs").cloned();
        if let Some(v) = &enabled_given {
            cfg.brokered_sessions_enabled = parse_runtime_switch(v)?;
        }
        if let Some(v) = &cidrs_given {
            let (cidrs, overlap_warnings) = parse_runtime_target_cidrs(v)?;
            cfg.brokered_sessions_allowed_target_cidrs = cidrs;
            warnings = overlap_warnings;
        }

        let entry = StorageEntry::new(MCP_CONFIG_KEY, &cfg)?;
        req.storage_put(&entry).await?;

        if enabled_given.is_some() || cidrs_given.is_some() {
            // `mcp.config.updated`, with both the old and the new values: the
            // standard audit entry for this request carries the new ones
            // only, and HMACs them.
            let by = req
                .auth
                .as_ref()
                .map(|a| a.display_name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "(unknown)".to_string());
            log::info!(
                target: "security",
                "mcp.config.updated by {}: brokered_sessions_enabled {} -> {}, brokered_sessions_allowed_target_cidrs {:?} -> {:?}",
                by,
                previous_enabled,
                cfg.brokered_sessions_enabled,
                previous_cidrs,
                cfg.brokered_sessions_allowed_target_cidrs
            );
            for w in &warnings {
                log::warn!(target: "security", "mcp.config.updated: {w}");
            }
        }

        let mut resp = Response::data_response(Some(self.mcp_config_response(&cfg)?));
        for w in warnings {
            resp.add_warning(&w);
        }
        Ok(Some(resp))
    }

    pub async fn handle_mcp_apps_list(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let names = req.storage_list(MCP_APP_PREFIX).await?;
        Ok(Some(Response::list_response(&names)))
    }

    pub async fn handle_mcp_app_read(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        match get_app(req, &name).await? {
            Some(app) => Ok(Some(Response::data_response(serde_json::to_value(app)?.as_object().cloned()))),
            None => Err(crate::bv_error_response_status!(404, &format!("no such MCP app: {name:?}"))),
        }
    }

    /// Create-or-update, mirroring `namespaces/(?P<path>.+)`'s Write
    /// semantics: no PATCH in this request model, so Write to an existing
    /// name updates it and Write to a new name creates it.
    pub async fn handle_mcp_app_write(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(crate::bv_error_response!("app name must match [a-z0-9-]+"));
        }

        let existing = get_app(req, &name).await?;
        let caller = req.client_token.clone();
        let now = now_secs();
        let mut app = existing.clone().unwrap_or(McpApp {
            version: 1,
            name: name.clone(),
            approle_role: String::new(),
            entity_id: String::new(),
            description: String::new(),
            tool_allowlist: Vec::new(),
            path_scope: Vec::new(),
            reveal_allowed: false,
            destructive_allowed: false,
            ttl_secs: default_ttl_secs(),
            machine_waiver: None,
            created_by: caller.clone(),
            created_at: now,
            updated_by: caller.clone(),
            updated_at: now,
        });

        if let Ok(v) = req.get_data("approle_role") {
            if let Some(s) = v.as_str() {
                app.approle_role = s.to_string();
            }
        }
        if let Ok(v) = req.get_data("entity_id") {
            if let Some(s) = v.as_str() {
                app.entity_id = s.to_string();
            }
        }
        if let Ok(v) = req.get_data("description") {
            if let Some(s) = v.as_str() {
                app.description = s.to_string();
            }
        }
        if let Ok(v) = req.get_data("tool_allowlist") {
            if let Some(list) = v.as_comma_string_slice() {
                app.tool_allowlist = list;
            }
        }
        if let Ok(v) = req.get_data("path_scope") {
            if let Some(list) = v.as_comma_string_slice() {
                app.path_scope = list;
            }
        }
        if let Ok(v) = req.get_data("reveal_allowed") {
            if let Some(b) = v.as_bool() {
                app.reveal_allowed = b;
            }
        }
        if let Ok(v) = req.get_data("destructive_allowed") {
            if let Some(b) = v.as_bool() {
                app.destructive_allowed = b;
            }
        }
        if let Ok(v) = req.get_data("ttl_secs") {
            if let Some(n) = v.as_u64() {
                app.ttl_secs = n.min(86400);
            }
        }
        app.updated_by = caller;
        app.updated_at = now;

        if app.approle_role.is_empty() {
            return Err(crate::bv_error_response!("approle_role is required"));
        }
        // Checked on the record as it would be stored, not only on the
        // request's `tool_allowlist`: an update to a record that already
        // carries a session tool (written before this rule existed) is
        // refused too, until the tool is removed.
        if let Some(tool) = app_open_world_tool(&app) {
            return Err(app_open_world_refusal(&app.name, tool));
        }

        put_app(req, &app).await?;
        Ok(Some(Response::data_response(serde_json::to_value(app)?.as_object().cloned())))
    }

    /// Deletes the app record and revokes every outstanding token it
    /// issued, via the `mcp/app-tokens/<name>/` reverse index -- see the
    /// module doc for why this index exists (the spec's own claim that
    /// this "reuses `ferrogate revoke`" does not hold: that path is not
    /// wired to the lease manager yet).
    pub async fn handle_mcp_app_delete(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };

        let index_prefix = format!("{MCP_APP_TOKEN_PREFIX}{name}/");
        let accessors = req.storage_list(&index_prefix).await?;
        for accessor in &accessors {
            let key = format!("{index_prefix}{accessor}");
            if let Some(entry) = req.storage_get(&key).await? {
                let indexed: McpTokenIndexEntry = serde_json::from_slice(&entry.value)?;
                // A failed revoke must leave the index entry in place and surface:
                // swallowing it would report success for a token that still works,
                // and delete the only record a retry could find it by.
                token_store.revoke(&indexed.id).await?;
            }
            req.storage_delete(&key).await?;
        }
        req.storage_delete(&format!("{MCP_APP_PREFIX}{name}")).await?;
        Ok(None)
    }

    /// `root_paths` cannot express "sudo on this one sub-path but not its
    /// CRUD sibling" (the variable segment is in the middle -- see the
    /// comment in `system/mod.rs` next to `root_paths`), so this and
    /// [`Self::handle_mcp_app_waiver_delete`] check `root_privs` directly.
    async fn require_sudo(&self, req: &Request) -> Result<(), RvError> {
        let auth = req.auth.clone().ok_or(RvError::ErrPermissionDenied)?;
        let policy_module = self.get_module::<PolicyModule>("policy")?;
        let acl = policy_module
            .policy_store
            .load()
            .new_acl_for_request(&auth.policies, None, &auth, req.namespace_path.as_deref())
            .await?;
        let mut probe = Request::new(req.path.clone());
        probe.operation = req.operation;
        probe.auth = Some(auth);
        if acl.allow_operation(&probe, true)?.root_privs {
            Ok(())
        } else {
            Err(RvError::ErrPermissionDenied)
        }
    }

    pub async fn handle_mcp_app_waiver_write(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.require_sudo(req).await?;
        let name = req.get_data_as_str("name")?;
        let Some(mut app) = get_app(req, &name).await? else {
            return Err(crate::bv_error_response_status!(404, &format!("no such MCP app: {name:?}")));
        };
        let reason = req.get_data_as_str("reason").unwrap_or_default();
        if reason.is_empty() {
            return Err(crate::bv_error_response!("reason is required to grant a machine-identity waiver"));
        }
        let requested_days = req.get_data("expires_in_days")?.as_u64().unwrap_or(0);
        if requested_days == 0 || requested_days > default_waiver_max_days() as u64 {
            return Err(crate::bv_error_response!("expires_in_days is required and must be <= 90"));
        }
        let now = now_secs();
        app.machine_waiver = Some(MachineWaiver {
            reason,
            granted_by: req.client_token.clone(),
            granted_at: now,
            expires_at: now + requested_days * 86400,
        });
        put_app(req, &app).await?;
        Ok(Some(Response::data_response(serde_json::to_value(&app)?.as_object().cloned())))
    }

    pub async fn handle_mcp_app_waiver_delete(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.require_sudo(req).await?;
        let name = req.get_data_as_str("name")?;
        let Some(mut app) = get_app(req, &name).await? else {
            return Err(crate::bv_error_response_status!(404, &format!("no such MCP app: {name:?}")));
        };
        app.machine_waiver = None;
        put_app(req, &app).await?;

        // Tokens minted under the waiver must not outlive it: revoke every
        // outstanding token of this app that carries a waiver expiry. Tokens
        // minted without one (the app was not waived when they were issued)
        // are untouched.
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let index_prefix = format!("{MCP_APP_TOKEN_PREFIX}{name}/");
        for accessor in req.storage_list(&index_prefix).await? {
            let key = format!("{index_prefix}{accessor}");
            let Some(entry) = req.storage_get(&key).await? else { continue };
            let indexed: McpTokenIndexEntry = serde_json::from_slice(&entry.value)?;
            let waived = token_store
                .lookup(&indexed.id)
                .await?
                .and_then(|te| te.mcp_binding)
                .is_some_and(|b| b.waived_until.is_some());
            if waived {
                token_store.revoke(&indexed.id).await?;
                req.storage_delete(&key).await?;
            }
        }
        Ok(None)
    }

    pub async fn handle_mcp_tokens_list(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Enumerate the token index itself, not the app registry, so pairing
        // tokens (which have no app record) are listed alongside app tokens.
        let index_dirs = req.storage_list(MCP_APP_TOKEN_PREFIX).await?;
        let mut rows: Vec<Value> = Vec::new();
        for name in index_dirs.iter().map(|n| n.trim_end_matches('/').to_string()) {
            let prefix = format!("{MCP_APP_TOKEN_PREFIX}{name}/");
            for accessor in req.storage_list(&prefix).await.unwrap_or_default() {
                if let Some(entry) = req.storage_get(&format!("{prefix}{accessor}")).await? {
                    if let Ok(indexed) = serde_json::from_slice::<McpTokenIndexEntry>(&entry.value) {
                        rows.push(serde_json::json!({
                            "accessor": accessor,
                            "kind": indexed.kind,
                            "app": indexed.app_name,
                            "client_name": indexed.client_name,
                            "client_version": indexed.client_version,
                            "issued_at": indexed.issued_at,
                            "expires_at": indexed.expires_at,
                            // `null` for a token minted before MCP tokens
                            // carried a binding (root-bound).
                            "namespace": indexed.namespace,
                        }));
                    }
                }
            }
        }
        let mut data = Map::new();
        data.insert("tokens".to_string(), Value::Array(rows));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_mcp_token_delete(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let accessor = req.get_data_as_str("accessor")?;
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let index_dirs = req.storage_list(MCP_APP_TOKEN_PREFIX).await?;
        for name in index_dirs.iter().map(|n| n.trim_end_matches('/').to_string()) {
            let key = format!("{MCP_APP_TOKEN_PREFIX}{name}/{accessor}");
            if let Some(entry) = req.storage_get(&key).await? {
                let indexed: McpTokenIndexEntry = serde_json::from_slice(&entry.value)?;
                // A failed revoke must leave the index entry in place and surface:
                // swallowing it would report success for a token that still works,
                // and delete the only record a retry could find it by.
                token_store.revoke(&indexed.id).await?;
                req.storage_delete(&key).await?;
                return Ok(None);
            }
        }
        Err(crate::bv_error_response_status!(404, &format!("no such MCP token: {accessor:?}")))
    }

    /// The `mcp/token` exchange (spec §4), routed normally at
    /// `sys/mcp/token` (public HTTP path stays `/v2/mcp/token`; Phase 3
    /// maps one to the other). Routed rather than called directly, since
    /// `pre_route` already ran check 1 (`check_token` + ACL "update") and
    /// populated `req.auth`/`req.storage` -- see the module doc.
    /// `catalogue_hash` travels in the body (`bv-kernel` cannot depend on
    /// `bv-mcp`). Two mutually exclusive modes: `app` (network, an
    /// `sys/mcp/apps/<name>` record) and `pairing` (local, the operator's own
    /// session narrowed by a per-client grant the operator approved).
    pub async fn handle_mcp_token_exchange(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let auth = req.auth.clone().ok_or(RvError::ErrPermissionDenied)?;
        if auth.mcp_binding.is_some() {
            return Err(crate::bv_error_response!("an MCP-bound token cannot itself exchange for another"));
        }
        if auth.policies.iter().any(|p| p == "root") {
            return Err(crate::bv_error_response!("mcp/token may not be exchanged from a root token"));
        }
        let caller_token = req.client_token.clone();
        let app_name = req.get_data_as_str("app").ok().filter(|s| !s.is_empty());
        let pairing = req.get_data("pairing").ok().and_then(|v| v.as_object().cloned());
        let requested_policies =
            req.get_data("policies").ok().and_then(|v| v.as_comma_string_slice()).unwrap_or_default();
        let requested_ttl_secs = req.get_data("ttl_secs").ok().and_then(|v| v.as_u64());
        let catalogue_hash = req.get_data_as_str("catalogue_hash").unwrap_or_default();
        let namespace = requested_namespace(req)?;

        match (app_name, pairing) {
            (Some(_), Some(_)) => Err(crate::bv_error_response!("`app` and `pairing` are mutually exclusive")),
            (None, None) => Err(crate::bv_error_response!("one of `app` or `pairing` is required")),
            // An app token is bound where its AppRole login is; narrowing is
            // a pairing (operator) decision. Refused, never ignored.
            (Some(_), None) if namespace.is_some() => Err(crate::bv_error_response_status!(
                400,
                "`namespace` applies to pairing exchanges only; an app token is bound to its AppRole login's namespace"
            )),
            (Some(app_name), None) => {
                self.exchange_app(
                    req,
                    &auth,
                    caller_token,
                    app_name,
                    requested_policies,
                    requested_ttl_secs,
                    catalogue_hash,
                )
                .await
            }
            (None, Some(pairing)) => {
                self.exchange_pairing(
                    req,
                    &auth,
                    caller_token,
                    pairing,
                    requested_policies,
                    requested_ttl_secs,
                    catalogue_hash,
                    namespace,
                )
                .await
            }
        }
    }

    /// Pairing mode (spec §4 step 3): the caller must be an operator session
    /// (an entity-bound login that is neither an AppRole nor a machine
    /// token), and the minted token's rights are the caller's policies
    /// narrowed by the pairing grant — `mint_mcp_token` enforces the subset
    /// rule. No machine-identity requirement: the operator is the attested
    /// party here, present at a TTY or GUI when they approved the pairing.
    #[allow(clippy::too_many_arguments)]
    async fn exchange_pairing(
        &self,
        req: &mut Request,
        auth: &Auth,
        caller_token: String,
        pairing: Map<String, Value>,
        requested_policies: Vec<String>,
        requested_ttl_secs: Option<u64>,
        catalogue_hash: String,
        requested_namespace: Option<String>,
    ) -> Result<Option<Response>, RvError> {
        // A human login stamps `entity_id` and/or `username`; tokens issued
        // before entity resolution was wired through login carry only the
        // latter. AppRole (`role_name`) and machine (`spiffe_id`) tokens are
        // excluded either way.
        let has_human_identity = [ENTITY_ID_META, USERNAME_META]
            .iter()
            .any(|k| auth.metadata.get(*k).is_some_and(|s| !s.is_empty()));
        let is_operator_session = has_human_identity
            && !auth.metadata.contains_key("role_name")
            && auth.metadata.get(SPIFFE_ID_META).is_none_or(|s| s.is_empty());
        if !is_operator_session {
            return Err(crate::bv_error_response_status!(
                403,
                "mcp_pairing_requires_operator_session: pairing needs an entity-bound user login, not an AppRole or machine token"
            ));
        }

        let id = pairing_str(&pairing, "id", true)?;
        if !valid_pairing_id(&id) {
            return Err(crate::bv_error_response!("pairing.id must match [a-z0-9-]{1,64}"));
        }
        let client_name = pairing_str(&pairing, "client_name", true)?;
        let client_version = pairing_str(&pairing, "client_version", false)?;
        let tool_allowlist = pairing_str_list(&pairing, "tool_allowlist")?;
        if let Some(bad) = tool_allowlist.iter().find(|t| !valid_tool_name(t)) {
            return Err(crate::bv_error_response!("pairing.tool_allowlist has an invalid tool name: {:?}", bad));
        }
        let path_scope = pairing_str_list(&pairing, "path_scope")?;
        let reveal_allowed = pairing.get("reveal_allowed").and_then(Value::as_bool).unwrap_or(false);
        let destructive_allowed = pairing.get("destructive_allowed").and_then(Value::as_bool).unwrap_or(false);
        let pairing_ttl = pairing.get("ttl_secs").and_then(Value::as_u64);
        // `features/mcp-brokered-sessions.md` §9. `connect_allowed` may sit
        // beside `reveal_allowed` (owner decision): such a grant holds the
        // whole lethal trifecta, and per-call confirmation is what bounds it.
        let connect_allowed = check_pairing_connect_grant(&pairing, &tool_allowlist)?;
        let mut operator = operator_ref_from_auth(auth)?;
        // Follow the operator's session (T457): the token is bound where the
        // exchanging session is, or where it asked to narrow to (Phase 2),
        // and a move from the previous exchange is audited before minting.
        let session_namespace = exchange_namespace(self.core.as_ref(), auth).await?;
        let target = match requested_namespace.as_deref() {
            Some(raw) => Some(narrowing_target(self.core.as_ref(), auth, raw).await?),
            None => None,
        };
        let namespace = target.as_ref().map_or(session_namespace, |t| t.path.clone());
        if target.is_some() {
            self.check_policies_resolve_in(auth, &requested_policies, &namespace).await?;
            // The operator's MFA ticket must be bound where this token's
            // calls run (`connect_mfa`): the narrowed namespace, which the
            // session may operate in.
            operator.namespace.clone_from(&namespace);
        }
        let record_namespace = self.note_pairing_namespace(req, &id, &client_name, &namespace, &operator).await?;

        let ttl_secs = requested_ttl_secs.or(pairing_ttl).unwrap_or(28_800).clamp(1, 86_400);
        // Only a pairing that lists `bv_policy_read` records where it may
        // read; nothing else consults the list.
        let policy_namespaces = if tool_allowlist.iter().any(|t| t == "bv_policy_read") {
            issuer_operable_namespaces(self.core.as_ref(), auth).await?
        } else {
            Vec::new()
        };
        let binding = McpBinding {
            policy_namespaces,
            kind: McpBindingKind::Pairing(id.clone()),
            catalogue_hash,
            tool_allowlist,
            path_scope,
            reveal_allowed,
            destructive_allowed,
            client_name: client_name.clone(),
            client_version: client_version.clone(),
            waived_until: None,
            connect_allowed,
            // Not configurable (§9): every pairing binding minted from now on
            // carries it, so no reader can ever find a pairing binding that
            // skips the operator.
            confirm_connect: true,
            operator: Some(operator),
        };
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let minted = token_store
            .mint_mcp_token(
                &caller_token,
                &requested_policies,
                ttl_secs,
                format!("mcp-pairing-{id}"),
                binding,
                target.as_ref(),
            )
            .await?;
        check_minted_namespace(&token_store, &minted, &namespace).await?;

        index_token(
            req,
            &McpTokenIndexEntry {
                id: minted.client_token.clone(),
                app_name: pairing_index_dir(&id),
                client_name,
                client_version,
                issued_at: now_secs(),
                expires_at: now_secs() + ttl_secs,
                kind: "pairing".to_string(),
                namespace: Some(namespace.clone()),
            },
        )
        .await?;
        if record_namespace {
            let record = McpPairingNamespace { version: 1, namespace: namespace.clone(), recorded_at: now_secs() };
            req.storage_put(&StorageEntry::new(&format!("{MCP_PAIRING_NAMESPACE_PREFIX}{id}"), &record)?).await?;
        }

        let mut data = Map::new();
        data.insert(
            "auth".to_string(),
            serde_json::json!({
                "client_token": minted.client_token,
                "accessor": token_accessor(&minted.client_token),
                "policies": minted.policies,
                "lease_duration": ttl_secs,
                "metadata": { "mcp_kind": "pairing", "mcp_name": id, "namespace": namespace },
            }),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    /// T457 Phase 2: every policy the narrowed token would carry (the
    /// requested set, else the session's) must exist in `namespace`'s store,
    /// or the token's grants would evaluate to nothing there.
    async fn check_policies_resolve_in(
        &self,
        auth: &Auth,
        requested_policies: &[String],
        namespace: &str,
    ) -> Result<(), RvError> {
        let mut names = if requested_policies.is_empty() { auth.policies.clone() } else { requested_policies.to_vec() };
        crate::utils::policy::sanitize_policies(&mut names, false);
        let policy_module = self.get_module::<PolicyModule>("policy")?;
        let missing = policy_module.policy_store.load().unresolved_in_namespace(&names, namespace).await?;
        if missing.is_empty() {
            return Ok(());
        }
        Err(crate::bv_error_response_status!(
            400,
            "{}: {} {:?} {} not exist in namespace {:?}; create {} there or request policies that do",
            MCP_POLICY_NOT_IN_NAMESPACE,
            if missing.len() == 1 { "policy" } else { "policies" },
            missing,
            if missing.len() == 1 { "does" } else { "do" },
            namespace,
            if missing.len() == 1 { "it" } else { "them" }
        ))
    }

    /// Compares the pairing's previous exchange with this one's `namespace`
    /// and, when they differ, emits `mcp.pairing.namespace_changed`. Fails
    /// closed: an event an enabled audit device cannot take refuses the
    /// exchange. Returns whether the pairing's namespace record needs writing.
    async fn note_pairing_namespace(
        &self,
        req: &Request,
        id: &str,
        client_name: &str,
        namespace: &str,
        operator: &McpOperatorRef,
    ) -> Result<bool, RvError> {
        let previous = match req.storage_get(&format!("{MCP_PAIRING_NAMESPACE_PREFIX}{id}")).await? {
            Some(entry) => Some(serde_json::from_slice::<McpPairingNamespace>(&entry.value)?.namespace),
            // No record: a first exchange, or tokens minted before MCP tokens
            // carried a binding -- every one of which was root-bound.
            None => {
                let index = format!("{MCP_APP_TOKEN_PREFIX}{}/", pairing_index_dir(id));
                (!req.storage_list(&index).await?.is_empty()).then(String::new)
            }
        };
        if let Some(previous) = previous.as_deref().filter(|p| *p != namespace) {
            let event = crate::kernel_api::mcp_events::PairingNamespaceChanged {
                pairing_id: id.to_string(),
                client_name: client_name.to_string(),
                previous_namespace: previous.to_string(),
                namespace: namespace.to_string(),
                operator: Some(operator.clone()),
            };
            crate::kernel_api::mcp_events::emit(self.core.as_ref(), &event, Some(req)).await?;
        }
        Ok(previous.as_deref() != Some(namespace))
    }

    /// Revokes every outstanding token minted for one pairing id, via the
    /// same reverse index app deletion uses. The local MCP server holds the
    /// token only in memory, so a separate `bvault mcp pairings revoke`
    /// process has no token to revoke by accessor — it revokes by pairing id.
    pub async fn handle_mcp_pairing_delete(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.get_data_as_str("id")?;
        if !valid_pairing_id(&id) {
            return Err(crate::bv_error_response!("pairing id must match [a-z0-9-]{1,64}"));
        }
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let index_prefix = format!("{MCP_APP_TOKEN_PREFIX}{}/", pairing_index_dir(&id));
        let accessors = req.storage_list(&index_prefix).await?;
        for accessor in &accessors {
            let key = format!("{index_prefix}{accessor}");
            if let Some(entry) = req.storage_get(&key).await? {
                let indexed: McpTokenIndexEntry = serde_json::from_slice(&entry.value)?;
                // A failed revoke must leave the index entry in place and surface:
                // swallowing it would report success for a token that still works,
                // and delete the only record a retry could find it by.
                token_store.revoke(&indexed.id).await?;
            }
            req.storage_delete(&key).await?;
        }
        req.storage_delete(&format!("{MCP_PAIRING_NAMESPACE_PREFIX}{id}")).await?;
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange_app(
        &self,
        req: &mut Request,
        auth: &Auth,
        caller_token: String,
        app_name: String,
        requested_policies: Vec<String>,
        requested_ttl_secs: Option<u64>,
        catalogue_hash: String,
    ) -> Result<Option<Response>, RvError> {
        // Check 2 (app mode): the app exists; the caller was minted by
        // `auth/approle` for exactly `approle_role`; spiffe_id or an
        // unexpired machine_waiver.
        let Some(app) = get_app(req, &app_name).await? else {
            return Err(crate::bv_error_response_status!(404, &format!("no such MCP app: {app_name:?}")));
        };
        let role_name = auth.metadata.get("role_name").cloned().unwrap_or_default();
        if role_name != app.approle_role {
            return Err(RvError::ErrPermissionDenied);
        }
        // A record written before `sys/mcp/apps` refused session tools may
        // still carry one. Refuse to mint from it rather than mint a token
        // whose allow-list names a tool the dispatcher would refuse anyway:
        // the operator learns at exchange, with the fix named.
        if let Some(tool) = app_open_world_tool(&app) {
            return Err(app_open_world_refusal(&app.name, tool));
        }
        let has_spiffe = auth.metadata.get(SPIFFE_ID_META).is_some_and(|s| !s.is_empty());
        let waived = app.machine_waiver.as_ref().is_some_and(MachineWaiver::is_active);
        if !has_spiffe && !waived {
            return Err(crate::bv_error_response_status!(
                403,
                "mcp_machine_identity_required: no machine attestation and no active waiver"
            ));
        }

        // The app's token is bound where its AppRole login is, as a pairing's
        // is where the operator's session is (T457); never widened to root.
        let namespace = exchange_namespace(self.core.as_ref(), auth).await?;

        // Check 4: effective policies = caller ∩ requested, never a
        // superset (mint_mcp_token enforces the subset rule again).
        let ttl_secs = requested_ttl_secs.unwrap_or(app.ttl_secs).min(app.ttl_secs).min(86400);
        let binding = McpBinding {
            policy_namespaces: Vec::new(),
            kind: McpBindingKind::App(app.name.clone()),
            catalogue_hash,
            tool_allowlist: app.tool_allowlist.clone(),
            path_scope: app.path_scope.clone(),
            reveal_allowed: app.reveal_allowed,
            destructive_allowed: app.destructive_allowed,
            client_name: String::new(),
            client_version: String::new(),
            waived_until: app.machine_waiver.as_ref().map(|w| w.expires_at),
            // Network-mode apps never open sessions (permanent, §1): there is
            // no human to confirm a call or complete MFA.
            connect_allowed: false,
            confirm_connect: false,
            operator: None,
        };
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let minted = token_store
            .mint_mcp_token(
                &caller_token,
                &requested_policies,
                ttl_secs,
                format!("mcp-app-{}", app.name),
                binding,
                None,
            )
            .await?;
        check_minted_namespace(&token_store, &minted, &namespace).await?;

        index_token(
            req,
            &McpTokenIndexEntry {
                id: minted.client_token.clone(),
                app_name: app.name.clone(),
                client_name: String::new(),
                client_version: String::new(),
                issued_at: now_secs(),
                expires_at: now_secs() + ttl_secs,
                kind: "app".to_string(),
                namespace: Some(namespace.clone()),
            },
        )
        .await?;

        // Not `Response.auth`: `TokenStore::post_route`'s generic
        // "any response carrying `.auth` mints a token" path only accepts
        // it from an `auth/token/*` path or an unauth login path (see its
        // own guard) -- and this handler has *already* minted and
        // persisted the token directly via `mint_mcp_token`. Shaped as
        // spec §4's documented `{"auth": {...}}` response body, just
        // carried through `data` instead of the field of the same name.
        let mut data = Map::new();
        data.insert(
            "auth".to_string(),
            serde_json::json!({
                "client_token": minted.client_token,
                "accessor": token_accessor(&minted.client_token),
                "policies": minted.policies,
                "lease_duration": ttl_secs,
                "metadata": { "mcp_kind": "app", "mcp_name": app.name, "namespace": namespace },
            }),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `LIST v2/sys/mcp/transcripts` — every MCP session transcript id,
    /// newest first, with the instant and session id each id encodes. Keys
    /// only: no transcript is decrypted. Needs `list` and `sudo`
    /// (`root_paths`), and emits `mcp.transcript.accessed`; if that event
    /// cannot be written to an enabled audit device the listing is refused.
    pub async fn handle_mcp_transcripts_list(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = TranscriptStore::from_ctx(self.core.as_ref())?;
        let ids = store.list().await.map_err(transcript_error)?;
        let event = TranscriptAccessed {
            operation: "list".into(),
            transcript_id: None,
            listed: Some(ids.len() as u64),
            found: true,
        };
        crate::kernel_api::mcp_events::emit(self.core.as_ref(), &event, Some(req)).await?;

        let mut key_info = Map::new();
        for id in &ids {
            if let Some(parsed) = parse_transcript_id(id) {
                key_info.insert(
                    id.clone(),
                    serde_json::json!({
                        "recorded_at": nanos_rfc3339(parsed.nanos),
                        "session_id": parsed.session_id,
                    }),
                );
            }
        }
        let mut data = Map::new();
        data.insert("keys".into(), serde_json::to_value(&ids)?);
        data.insert("key_info".into(), Value::Object(key_info));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `GET v2/sys/mcp/transcripts/{id}` — one transcript: who and what (the
    /// summary) and the session record (command and credential-scrubbed
    /// output). Needs `read` and `sudo` (`root_paths`). Every attempt emits
    /// `mcp.transcript.accessed`, found or not, before anything is returned;
    /// if that event cannot be written to an enabled audit device the read is
    /// refused. A record that does not decode is a 500 naming why — never
    /// skipped or returned in part.
    pub async fn handle_mcp_transcript_read(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req.get_data_as_str("id")?;
        let parsed = parse_transcript_id(&id);
        let read = match parsed {
            None => Err(TranscriptError::InvalidId(crate::kernel_api::mcp_events::bounded_arg(&id))),
            Some(_) => match TranscriptStore::from_ctx(self.core.as_ref()) {
                Ok(store) => store.read(&id).await,
                Err(e) => Err(TranscriptError::from(e)),
            },
        };
        let event = TranscriptAccessed {
            operation: "read".into(),
            transcript_id: Some(crate::kernel_api::mcp_events::bounded_arg(&id)),
            listed: None,
            found: matches!(read, Ok(Some(_))),
        };
        crate::kernel_api::mcp_events::emit(self.core.as_ref(), &event, Some(req)).await?;

        let transcript = match read {
            Ok(Some(t)) => t,
            Ok(None) => return Err(crate::bv_error_response_status!(404, "no MCP session transcript {:?}", id)),
            Err(e) => return Err(transcript_error(e)),
        };
        let recorded_at = parsed.map(|p| nanos_rfc3339(p.nanos)).unwrap_or_default();
        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("recorded_at".into(), Value::String(recorded_at));
        data.insert("version".into(), Value::from(crate::kernel_api::mcp_transcripts::TRANSCRIPT_RECORD_VERSION));
        data.insert("protocol".into(), Value::String(transcript.body.protocol().to_string()));
        data.insert("summary".into(), serde_json::to_value(&transcript.summary)?);
        data.insert("body".into(), serde_json::to_value(&transcript.body)?);
        Ok(Some(Response::data_response(Some(data))))
    }
}

#[cfg(test)]
mod brokered_session_tests {
    use super::*;
    use serde_json::json;

    fn grant(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn tools(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn connect_grant_rules() {
        let none = tools(&["bv_kv_read"]);
        let ssh = tools(&["bv_kv_read", "bv_resource_ssh_exec"]);
        // Absent: no connect, and that is fine.
        assert!(!check_pairing_connect_grant(&grant(json!({})), &none).unwrap());
        // Granted with confirmation, beside reveal.
        let ok = grant(json!({ "connect_allowed": true, "confirm_connect": true, "reveal_allowed": true }));
        assert!(check_pairing_connect_grant(&ok, &ssh).unwrap());
        // confirm_connect absent, false, or mistyped.
        for (g, needle) in [
            (json!({ "connect_allowed": true }), "requires pairing.confirm_connect"),
            (json!({ "connect_allowed": true, "confirm_connect": null }), "requires pairing.confirm_connect"),
            (json!({ "connect_allowed": true, "confirm_connect": false }), "cannot be false"),
            (json!({ "confirm_connect": false }), "cannot be false"),
            (json!({ "connect_allowed": "true", "confirm_connect": true }), "must be a boolean"),
            (json!({ "connect_allowed": true, "confirm_connect": "true" }), "must be a boolean"),
        ] {
            let err = check_pairing_connect_grant(&grant(g.clone()), &none).unwrap_err().to_string();
            assert!(err.contains(needle), "{g}: {err}");
        }
        // A session tool without the grant.
        let err = check_pairing_connect_grant(&grant(json!({})), &ssh).unwrap_err().to_string();
        assert!(err.contains("bv_resource_ssh_exec") && err.contains("requires pairing.connect_allowed"), "{err}");
    }

    #[test]
    fn operator_ref_is_copied_from_the_session_metadata() {
        let mut auth = Auth::default();
        auth.metadata.insert(USERNAME_META.into(), "felipe".into());
        auth.metadata.insert(ENTITY_ID_META.into(), "e-1".into());
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert(crate::logical::NS_PATH_META.into(), "/tenant-a/".into());
        let op = operator_ref_from_auth(&auth).unwrap();
        assert_eq!(
            op,
            McpOperatorRef {
                entity_id: "e-1".into(),
                username: "felipe".into(),
                mount_path: "userpass/".into(),
                namespace: "tenant-a".into(),
            }
        );
        // Root namespace normalizes to "".
        auth.metadata.remove(crate::logical::NS_PATH_META);
        assert_eq!(operator_ref_from_auth(&auth).unwrap().namespace, "");
        // A namespace binding that does not normalize is refused.
        auth.metadata.insert(crate::logical::NS_PATH_META.into(), "a/../b".into());
        assert!(operator_ref_from_auth(&auth).is_err());
    }

    #[test]
    fn app_records_with_a_session_tool_are_found() {
        let app = |list: &[&str]| McpApp {
            version: 1,
            name: "a".into(),
            approle_role: "r".into(),
            entity_id: String::new(),
            description: String::new(),
            tool_allowlist: tools(list),
            path_scope: vec![],
            reveal_allowed: false,
            destructive_allowed: false,
            ttl_secs: 3600,
            machine_waiver: None,
            created_by: String::new(),
            created_at: 0,
            updated_by: String::new(),
            updated_at: 0,
        };
        assert_eq!(app_open_world_tool(&app(&["bv_kv_read"])), None);
        assert_eq!(
            app_open_world_tool(&app(&["bv_kv_read", " bv_resource_web_fetch "])),
            Some("bv_resource_web_fetch")
        );
        let err = app_open_world_refusal("a", "bv_resource_rdp_act").to_string();
        assert!(err.contains("mcp_connect_requires_local_operator") && err.contains("bv_resource_rdp_act"), "{err}");
    }

    /// T457 "Persisted formats": an index entry written before MCP tokens
    /// carried a binding has no namespace (its token is root-bound); a new
    /// one and the per-pairing record round-trip.
    #[test]
    fn token_index_entries_read_old_and_write_the_namespace() {
        let old = r#"{"id":"t","app_name":"pairing_p","client_name":"c","client_version":"1",
            "issued_at":1,"expires_at":2,"kind":"pairing"}"#;
        let entry: McpTokenIndexEntry = serde_json::from_str(old).unwrap();
        assert_eq!(entry.namespace, None);
        let new = McpTokenIndexEntry { namespace: Some("dti/esi".into()), ..entry };
        let back: McpTokenIndexEntry = serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
        assert_eq!(back.namespace.as_deref(), Some("dti/esi"));

        let record: McpPairingNamespace = serde_json::from_str(r#"{"namespace":"","recorded_at":5}"#).unwrap();
        assert_eq!((record.version, record.namespace.as_str()), (1, ""));
        let err = namespace_unavailable("namespace \"gone\" no longer exists").to_string();
        assert!(err.contains("mcp_namespace_unavailable: namespace \"gone\" no longer exists"), "{err}");
        assert!(err.contains("rather than binding the MCP token to root"), "{err}");
    }

    /// A runtime config record written before the brokered-session keys
    /// existed reads as "switch off, allow-list not overridden".
    #[test]
    fn an_old_runtime_config_reads_with_sessions_off() {
        let old =
            r#"{"version":1,"default_ttl_secs":3600,"max_ttl_secs":86400,"waiver_max_days":90,"catalogue_pin":null}"#;
        let cfg: McpRuntimeConfig = serde_json::from_str(old).unwrap();
        assert!(!cfg.brokered_sessions_enabled);
        assert_eq!(cfg.brokered_sessions_allowed_target_cidrs, None);
        let d = McpRuntimeConfig::default();
        assert!(!d.brokered_sessions_enabled && d.brokered_sessions_allowed_target_cidrs.is_none());
    }

    #[test]
    fn runtime_switch_and_list_parsing() {
        assert!(parse_runtime_switch(&json!(true)).unwrap());
        assert!(parse_runtime_switch(&json!("true")).unwrap());
        assert!(!parse_runtime_switch(&json!("false")).unwrap());
        for bad in [json!("yes"), json!(1), json!(null), json!(["true"])] {
            assert!(parse_runtime_switch(&bad).is_err(), "{bad}");
        }

        assert_eq!(parse_runtime_target_cidrs(&json!(null)).unwrap(), (None, vec![]));
        assert_eq!(parse_runtime_target_cidrs(&json!([])).unwrap(), (Some(vec![]), vec![]));
        assert_eq!(parse_runtime_target_cidrs(&json!("")).unwrap(), (Some(vec![]), vec![]));
        assert_eq!(
            parse_runtime_target_cidrs(&json!(" 10.0.0.0/8 ,fd00::/8")).unwrap().0,
            Some(vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()])
        );
        let (list, warnings) = parse_runtime_target_cidrs(&json!(["10.0.0.0/8", "::ffff:127.0.0.1/128"])).unwrap();
        assert_eq!(list.unwrap().len(), 2);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        for (bad, needle) in [
            (json!(["10.0.0.0/8", "bogus"]), "\"bogus\""),
            (json!(["10.0.0.1/8"]), "host bits"),
            (json!("10.0.0.0/8,,"), "empty"),
            (json!([1]), "must be strings"),
            (json!({ "a": 1 }), "must be a list"),
        ] {
            let err = parse_runtime_target_cidrs(&bad).unwrap_err().to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
    }
}
