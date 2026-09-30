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
        field::FieldTrait, Auth, McpBinding, McpBindingKind, Request, Response, ENTITY_ID_META, SPIFFE_ID_META,
        USERNAME_META,
    },
    modules::auth::AuthModule,
    modules::policy::PolicyModule,
    storage::StorageEntry,
};

use super::SystemBackend;

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
}

impl Default for McpRuntimeConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            default_ttl_secs: default_ttl_secs(),
            max_ttl_secs: default_max_ttl_secs(),
            waiver_max_days: default_waiver_max_days(),
            catalogue_pin: None,
        }
    }
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
}

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
        Ok(Some(Response::data_response(serde_json::to_value(cfg)?.as_object().cloned())))
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
        let entry = StorageEntry::new(MCP_CONFIG_KEY, &cfg)?;
        req.storage_put(&entry).await?;
        Ok(Some(Response::data_response(serde_json::to_value(cfg)?.as_object().cloned())))
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
                token_store.revoke(&indexed.id).await.ok();
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
                token_store.revoke(&indexed.id).await.ok();
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

        match (app_name, pairing) {
            (Some(_), Some(_)) => Err(crate::bv_error_response!("`app` and `pairing` are mutually exclusive")),
            (None, None) => Err(crate::bv_error_response!("one of `app` or `pairing` is required")),
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

        let ttl_secs = requested_ttl_secs.or(pairing_ttl).unwrap_or(28_800).clamp(1, 86_400);
        let binding = McpBinding {
            kind: McpBindingKind::Pairing(id.clone()),
            catalogue_hash,
            tool_allowlist,
            path_scope,
            reveal_allowed,
            destructive_allowed,
            client_name: client_name.clone(),
            client_version: client_version.clone(),
            waived_until: None,
        };
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let minted = token_store
            .mint_mcp_token(&caller_token, &requested_policies, ttl_secs, format!("mcp-pairing-{id}"), binding)
            .await?;

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
            },
        )
        .await?;

        let mut data = Map::new();
        data.insert(
            "auth".to_string(),
            serde_json::json!({
                "client_token": minted.client_token,
                "accessor": token_accessor(&minted.client_token),
                "policies": minted.policies,
                "lease_duration": ttl_secs,
                "metadata": { "mcp_kind": "pairing", "mcp_name": id },
            }),
        );
        Ok(Some(Response::data_response(Some(data))))
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
                token_store.revoke(&indexed.id).await.ok();
            }
            req.storage_delete(&key).await?;
        }
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
        let has_spiffe = auth.metadata.get(SPIFFE_ID_META).is_some_and(|s| !s.is_empty());
        let waived = app.machine_waiver.as_ref().is_some_and(MachineWaiver::is_active);
        if !has_spiffe && !waived {
            return Err(crate::bv_error_response_status!(
                403,
                "mcp_machine_identity_required: no machine attestation and no active waiver"
            ));
        }

        // Check 4: effective policies = caller ∩ requested, never a
        // superset (mint_mcp_token enforces the subset rule again).
        let ttl_secs = requested_ttl_secs.unwrap_or(app.ttl_secs).min(app.ttl_secs).min(86400);
        let binding = McpBinding {
            kind: McpBindingKind::App(app.name.clone()),
            catalogue_hash,
            tool_allowlist: app.tool_allowlist.clone(),
            path_scope: app.path_scope.clone(),
            reveal_allowed: app.reveal_allowed,
            destructive_allowed: app.destructive_allowed,
            client_name: String::new(),
            client_version: String::new(),
            waived_until: app.machine_waiver.as_ref().map(|w| w.expires_at),
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
            )
            .await?;

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
                "metadata": { "mcp_kind": "app", "mcp_name": app.name },
            }),
        );
        Ok(Some(Response::data_response(Some(data))))
    }
}
