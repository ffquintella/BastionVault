//! MCP Access (`features/mcp-access.md`, Phase 2): the `sys/mcp/*` app
//! registry and the `mcp/token` exchange. See that spec's § 2-4.
// source: features/mcp-access.md §2-4 (storage layout, accessor scheme,
// and why the reverse index is a separate top-level prefix from the app
// record are working notes, not separate decisions -- see the doc itself).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    errors::RvError,
    logical::{field::FieldTrait, McpBinding, McpBindingKind, Request, Response, SPIFFE_ID_META},
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
    pub app_name: String,
    pub client_name: String,
    pub client_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
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
        Ok(None)
    }

    pub async fn handle_mcp_tokens_list(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let app_names = req.storage_list(MCP_APP_PREFIX).await?;
        let mut rows: Vec<Value> = Vec::new();
        for name in app_names.iter().map(|n| n.trim_end_matches('/').to_string()) {
            let prefix = format!("{MCP_APP_TOKEN_PREFIX}{name}/");
            for accessor in req.storage_list(&prefix).await.unwrap_or_default() {
                if let Some(entry) = req.storage_get(&format!("{prefix}{accessor}")).await? {
                    if let Ok(indexed) = serde_json::from_slice::<McpTokenIndexEntry>(&entry.value) {
                        rows.push(serde_json::json!({
                            "accessor": accessor,
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
        let app_names = req.storage_list(MCP_APP_PREFIX).await?;
        for name in app_names.iter().map(|n| n.trim_end_matches('/').to_string()) {
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
    /// `bv-mcp`). Pairing mode (Phase 4/5) is not built.
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
        let app_name = req.get_data_as_str("app")?;
        let requested_policies =
            req.get_data("policies").ok().and_then(|v| v.as_comma_string_slice()).unwrap_or_default();
        let requested_ttl_secs = req.get_data("ttl_secs").ok().and_then(|v| v.as_u64());
        let catalogue_hash = req.get_data_as_str("catalogue_hash").unwrap_or_default();

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
