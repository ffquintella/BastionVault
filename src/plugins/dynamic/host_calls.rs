//! The three dynamic-secret host calls, shared by both runtimes.
//!
//! `bv.dynamic_*` (WASM) and the `dynamic_*` JSON-RPC methods (process) both
//! land here, so the gate is one piece of code. A call whose capability is
//! not in the manifest is refused, audited, and quarantines the plugin.

use std::{collections::BTreeMap, sync::Arc};

use bv_dynamic::{
    audit::{DynamicEventKind, DynamicSecretEvent, EventOrigin},
    records::{check_name, LeaseRequest},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    pool::{host_pool, target_key},
    session::{DynamicSession, DynamicVerb},
    state,
};
use crate::{
    kernel_api::{mcp_events::McpAuditEvent, VaultCtx},
    plugins::manifest::PluginManifest,
};

/// WASM return code: the capability is not in the manifest.
pub const DYNAMIC_FORBIDDEN: i32 = -2;
/// WASM return code: the request was malformed or refused on its merits.
pub const DYNAMIC_INVALID: i32 = -4;
/// WASM return code: the host could not serve it (pool exhausted, storage).
pub const DYNAMIC_UNAVAILABLE: i32 = -5;
/// WASM return code: called outside a dynamic-secret RPC.
pub const DYNAMIC_NO_SESSION: i32 = -8;
/// Pool slots one host-to-plugin call may hold at once.
pub const MAX_GRANTS_PER_CALL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicMethod {
    LeaseRegister,
    AuditEmit,
    PoolCheckout,
}

impl DynamicMethod {
    pub fn parse(method: &str) -> Option<Self> {
        Some(match method {
            "dynamic_lease_register" => Self::LeaseRegister,
            "dynamic_audit_emit" => Self::AuditEmit,
            "dynamic_pool_checkout" => Self::PoolCheckout,
            _ => return None,
        })
    }

    /// The manifest capability, which is also the method's name.
    pub fn capability(self) -> &'static str {
        match self {
            Self::LeaseRegister => "dynamic_lease_register",
            Self::AuditEmit => "dynamic_audit_emit",
            Self::PoolCheckout => "dynamic_pool_checkout",
        }
    }

    fn declared(self, manifest: &PluginManifest) -> bool {
        let caps = &manifest.capabilities;
        match self {
            Self::LeaseRegister => caps.dynamic_lease_register,
            Self::AuditEmit => caps.dynamic_audit_emit,
            Self::PoolCheckout => caps.dynamic_pool_checkout,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicCallError {
    Forbidden,
    NoSession,
    Invalid(String),
    Unavailable(String),
}

impl DynamicCallError {
    pub fn wasm_code(&self) -> i32 {
        match self {
            Self::Forbidden => DYNAMIC_FORBIDDEN,
            Self::NoSession => DYNAMIC_NO_SESSION,
            Self::Invalid(_) => DYNAMIC_INVALID,
            Self::Unavailable(_) => DYNAMIC_UNAVAILABLE,
        }
    }

    /// The `host_reply.error` a process plugin receives.
    pub fn process_error(&self) -> String {
        match self {
            Self::Forbidden => "forbidden".to_string(),
            Self::NoSession => "no_session".to_string(),
            Self::Invalid(m) => format!("invalid: {m}"),
            Self::Unavailable(m) => format!("unavailable: {m}"),
        }
    }
}

impl From<bv_dynamic::DynamicError> for DynamicCallError {
    fn from(e: bv_dynamic::DynamicError) -> Self {
        if e.status() >= 500 {
            Self::Unavailable(e.to_string())
        } else {
            Self::Invalid(e.to_string())
        }
    }
}

/// What a host call runs with.
pub struct HostCallContext<'a> {
    pub manifest: &'a PluginManifest,
    pub core: Option<&'a Arc<dyn VaultCtx>>,
    pub session: Option<&'a Arc<DynamicSession>>,
    /// `wasm` or `process`, for the refusal record.
    pub runtime: &'static str,
}

/// `plugin.capability_refused`: a plugin called a host capability its
/// manifest does not declare. Names the capability, never the request.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityRefusedEvent {
    pub plugin: String,
    pub version: String,
    pub capability: String,
    pub runtime: String,
    pub quarantined: bool,
}

impl McpAuditEvent for CapabilityRefusedEvent {
    const NAME: &'static str = "plugin.capability_refused";
}

/// Refuse `method` unless the manifest declares it. A refusal is logged,
/// audited and quarantines the plugin: a plugin probing for host calls it
/// did not ask for is misbehaving, and its mounts stop until re-registered.
pub async fn authorize(ctx: &HostCallContext<'_>, method: DynamicMethod) -> Result<(), DynamicCallError> {
    if method.declared(ctx.manifest) {
        // Then the session, before the request is read (the testkit's order).
        return ctx.session.map(|_| ()).ok_or(DynamicCallError::NoSession);
    }
    let name = &ctx.manifest.name;
    log::warn!(
        target: "plugin",
        "[{name}] refused {} ({}): not declared in the plugin manifest; quarantining the plugin",
        method.capability(),
        ctx.runtime,
    );
    if let Some(session) = ctx.session {
        session.mark_violation();
    }
    let mut quarantined = false;
    if let Some(core) = ctx.core {
        let reason = format!("called {} without declaring it in its manifest", method.capability());
        match crate::plugins::quarantine::quarantine_for(
            core.barrier().as_storage(),
            name,
            "",
            &ctx.manifest.version,
            &reason,
        )
        .await
        {
            Ok(()) => quarantined = true,
            Err(e) => log::error!(target: "plugin", "[{name}] could not record the quarantine marker: {e}"),
        }
        super::cache::invalidate_plugin(name);
        let event = CapabilityRefusedEvent {
            plugin: name.clone(),
            version: ctx.manifest.version.clone(),
            capability: method.capability().to_string(),
            runtime: ctx.runtime.to_string(),
            quarantined,
        };
        if let Err(e) = crate::kernel_api::mcp_events::emit(core.as_ref(), &event, None).await {
            log::warn!(target: "plugin", "[{name}] capability refusal was not written to the audit broker: {e}");
        }
    }
    Err(DynamicCallError::Forbidden)
}

/// [`authorize`], then serve the call.
pub async fn handle(
    ctx: &HostCallContext<'_>,
    method: DynamicMethod,
    params: &Value,
) -> Result<Value, DynamicCallError> {
    authorize(ctx, method).await?;
    dispatch(ctx, method, params).await
}

/// Serve an authorized call.
pub async fn dispatch(
    ctx: &HostCallContext<'_>,
    method: DynamicMethod,
    params: &Value,
) -> Result<Value, DynamicCallError> {
    let session = ctx.session.ok_or(DynamicCallError::NoSession)?;
    match method {
        DynamicMethod::LeaseRegister => lease_register(session, params),
        DynamicMethod::AuditEmit => audit_emit(ctx, session, params).await,
        DynamicMethod::PoolCheckout => pool_checkout(session, params).await,
    }
}

fn lease_register(session: &DynamicSession, params: &Value) -> Result<Value, DynamicCallError> {
    if session.verb != DynamicVerb::Generate {
        return Err(DynamicCallError::Invalid(
            "dynamic_lease_register is only valid while the host is generating a credential".into(),
        ));
    }
    let request = LeaseRequest::parse(params)?;
    session.set_lease_request(request).map_err(|m| DynamicCallError::Invalid(m.to_string()))?;
    Ok(json!({ "registered": true }))
}

/// What a plugin may say in its own `dynamic_secret` event. Everything else on
/// the event (lease, identity, actor, plugin build) the host stamps itself.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginAuditInput {
    event: DynamicEventKind,
    #[serde(default)]
    target_identity_type: Option<String>,
    #[serde(default)]
    detail: BTreeMap<String, String>,
}

async fn audit_emit(
    ctx: &HostCallContext<'_>,
    session: &DynamicSession,
    params: &Value,
) -> Result<Value, DynamicCallError> {
    let input: PluginAuditInput = serde_json::from_value(params.clone())
        .map_err(|e| DynamicCallError::Invalid(format!("dynamic_audit_emit request: {e}")))?;
    if input.event == DynamicEventKind::CacheHit {
        return Err(DynamicCallError::Invalid("cache_hit is the host's event, not a plugin's".into()));
    }
    if !session.admit_plugin_event() {
        return Err(DynamicCallError::Invalid("too many plugin events for one call".into()));
    }
    let m = ctx.manifest;
    let secrets = session.secrets();
    let mut event = DynamicSecretEvent::new(
        input.event,
        EventOrigin::Plugin,
        m.engine_type.as_deref().unwrap_or(""),
        &m.name,
        &m.version,
    );
    event.lease_id.clone_from(&session.lease_id);
    event.role.clone_from(&session.role);
    event.connection.clone_from(&session.connection);
    event.target_identity.clone_from(&session.target_identity);
    event.actor.clone_from(&session.actor);
    event.request_id.clone_from(&session.request_id);
    if let Some(kind) = input.target_identity_type.as_deref() {
        event = event.with_identity_type(kind, &secrets)?;
    }
    let event = event.with_detail(&input.detail, &secrets)?;
    super::emit_event(ctx.core.map(|c| c.as_ref()), &event).await;
    Ok(json!({ "emitted": true }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolCheckoutInput {
    connection: String,
}

async fn pool_checkout(session: &DynamicSession, params: &Value) -> Result<Value, DynamicCallError> {
    let input: PoolCheckoutInput = serde_json::from_value(params.clone())
        .map_err(|e| DynamicCallError::Invalid(format!("dynamic_pool_checkout request: {e}")))?;
    check_name("connection", &input.connection)?;
    // One call cannot starve the shared pool by hoarding slots.
    if session.held_grants() >= MAX_GRANTS_PER_CALL {
        return Err(DynamicCallError::Invalid(format!("at most {MAX_GRANTS_PER_CALL} pooled connections per call")));
    }
    let storage = session.storage.as_ref().ok_or(DynamicCallError::NoSession)?;
    let record = state::load_connection(storage.as_ref(), &input.connection)
        .await
        .map_err(|e| DynamicCallError::Unavailable(e.to_string()))?
        .ok_or_else(|| {
            DynamicCallError::Invalid(format!(
                "connection `{}` is not configured on this mount (write config/{} first)",
                input.connection, input.connection
            ))
        })?;
    let pool = host_pool();
    let key = target_key(&session.mount_id, &input.connection);
    pool.configure(&key, record.root_credential_version, record.tls_policy());
    let grant = pool.checkout(&key).await?;
    if !grant.tls.verifies() {
        log::warn!(
            "pooled connection to `{}` handed out with TLS certificate verification disabled \
             (insecure_skip_tls_verify); development only",
            input.connection
        );
    }
    let reply = json!({
        "connection": input.connection,
        "root_credential_version": grant.key().root_credential_version,
        "tls": grant.tls,
        "slot": grant.id,
        "max_connections": pool.max_size(),
    });
    session.hold_grant(grant);
    Ok(reply)
}
