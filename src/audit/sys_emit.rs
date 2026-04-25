//! Helper for emitting audit events from sys-level HTTP handlers.
//!
//! The standard audit pipeline runs inside `Core::handle_request`, which
//! the exchange / plugin / scheduled-export endpoints don't currently
//! traverse — they're direct actix handlers. This helper bridges the gap:
//! it resolves the actor identity from the bearer token, builds an
//! `AuditEntry` with the same redaction discipline as the in-pipeline
//! path, and fans it out through `Core::audit_broker`.
//!
//! Discipline:
//! - Always emits, even on failure paths (`error` flag carries the cause).
//! - Token is HMAC'd into a stable identity hash so two events from the
//!   same caller correlate without ever logging the raw token.
//! - When no audit broker is installed (e.g. tests, or the operator
//!   hasn't enabled any device yet), the emit is a no-op — same as the
//!   in-pipeline path's `broker.has_devices()` check.

use serde_json::{Map, Value};

use crate::{
    audit::{AuditBroker, AuditEntry},
    core::Core,
    errors::RvError,
    logical::{Auth, Operation, Request},
};

/// Best-effort token → display_name + policies resolution. Returns an
/// empty `Auth` when the token isn't recognised (e.g. anonymous request,
/// or the auth module isn't installed yet); the audit entry still goes
/// out with the HMAC'd token as the only correlation handle.
async fn resolve_auth(core: &Core, token: &str) -> Auth {
    if token.is_empty() {
        return Auth::default();
    }
    let Some(auth_module) = core
        .module_manager
        .get_module::<crate::modules::auth::AuthModule>("auth")
    else {
        return Auth::default();
    };
    let Some(token_store) = auth_module.token_store.load_full() else {
        return Auth::default();
    };
    match token_store.lookup(token).await {
        Ok(Some(te)) => Auth {
            client_token: token.to_string(),
            display_name: te.display_name,
            policies: te.policies.clone(),
            token_policies: te.policies,
            metadata: te.meta,
            ..Default::default()
        },
        _ => Auth::default(),
    }
}

/// Emit a single audit event for a sys-level operation outside the
/// `Core::handle_request` pipeline.
///
/// `path` is the logical operation path (e.g. `"sys/exchange/export"`);
/// `body` is the redacted-by-default request body (HMAC redaction is
/// applied by `AuditEntry::from_response` regardless of what we pass);
/// `error` is the human-readable error string when the operation
/// failed, or `None` on success.
///
/// Returns `Ok(())` even when the broker rejects the entry — audit-emit
/// errors must not turn a successful operation into a 500. The broker
/// itself logs at WARN when a device fails; that's the operator's
/// signal to investigate.
pub async fn emit_sys_audit(
    core: &Core,
    token: &str,
    path: &str,
    operation: Operation,
    body: Option<Map<String, Value>>,
    error: Option<&str>,
) {
    let broker_arc = core.audit_broker.load_full();
    let Some(broker) = broker_arc else {
        return;
    };
    if !broker.has_devices() {
        return;
    }

    let auth = resolve_auth(core, token).await;
    let mut req = Request::default();
    req.client_token = token.to_string();
    req.path = path.to_string();
    req.operation = operation;
    req.body = body;
    req.auth = Some(auth.clone());
    req.name = auth.display_name;

    let mut entry = AuditEntry::from_response(&req, &None, error, broker.hmac_key(), false);
    log_or_warn(&broker, &mut entry).await;
}

/// Same as `emit_sys_audit` but for operations that produce a
/// well-formed response payload the auditor should see (with the same
/// HMAC-redaction discipline). Use when the response body has
/// non-secret fields the operator wants visible — e.g. a schedule id,
/// a plugin name, the count of items applied.
pub async fn emit_sys_audit_with_response(
    core: &Core,
    token: &str,
    path: &str,
    operation: Operation,
    body: Option<Map<String, Value>>,
    response_data: Option<Map<String, Value>>,
    error: Option<&str>,
) {
    let broker_arc = core.audit_broker.load_full();
    let Some(broker) = broker_arc else {
        return;
    };
    if !broker.has_devices() {
        return;
    }

    let auth = resolve_auth(core, token).await;
    let mut req = Request::default();
    req.client_token = token.to_string();
    req.path = path.to_string();
    req.operation = operation;
    req.body = body;
    req.auth = Some(auth.clone());
    req.name = auth.display_name;

    let resp = response_data.map(|d| crate::logical::Response {
        data: Some(d),
        ..Default::default()
    });

    let mut entry = AuditEntry::from_response(&req, &resp, error, broker.hmac_key(), false);
    log_or_warn(&broker, &mut entry).await;
}

async fn log_or_warn(broker: &AuditBroker, entry: &mut AuditEntry) {
    if let Err(e) = broker.log(entry).await {
        log::warn!("audit emit failed: {e}");
    }
}

/// Hint helper for callers: convert any `Result<_, RvError>` outcome
/// into the (success, error_string) pair `emit_sys_audit` wants.
pub fn outcome_for<T>(r: &Result<T, RvError>) -> Option<String> {
    match r {
        Ok(_) => None,
        Err(e) => Some(format!("{e}")),
    }
}
