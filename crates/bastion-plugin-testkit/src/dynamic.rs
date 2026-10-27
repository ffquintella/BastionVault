//! Mock of the ABI 1.5 dynamic-secret host calls (`dynamic_lease_register`,
//! `dynamic_audit_emit`, `dynamic_pool_checkout`), shared by the WASM and
//! process harnesses. Same gate order as the host: an undeclared capability
//! is refused (and recorded as a violation) before anything else is read.

use std::collections::BTreeSet;

use serde_json::{json, Value};

/// Return code: the capability is not in the manifest.
pub const DYNAMIC_FORBIDDEN: i32 = -2;
/// Return code: malformed or refused on its merits.
pub const DYNAMIC_INVALID: i32 = -4;
/// Return code: the host could not serve it (pool exhausted, storage). The
/// mock never answers it; it is named so tests can match the server's.
pub const DYNAMIC_UNAVAILABLE: i32 = -5;
/// Return code: called outside a dynamic-secret RPC.
pub const DYNAMIC_NO_SESSION: i32 = -8;

const EVENT_KINDS: [&str; 5] = ["generate", "renew", "revoke", "revoke_failed", "rotate_root"];

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DynamicCaps {
    pub(crate) lease_register: bool,
    pub(crate) audit_emit: bool,
    pub(crate) pool_checkout: bool,
}

#[derive(Debug, Default)]
pub(crate) struct DynamicState {
    /// The envelope `op` of the dynamic RPC being served, if any.
    pub(crate) session: Option<String>,
    pub(crate) lease_in_session: bool,
    pub(crate) leases: Vec<Value>,
    pub(crate) events: Vec<Value>,
    pub(crate) violations: Vec<String>,
    pub(crate) connections: BTreeSet<String>,
    pub(crate) next_slot: u64,
}

pub(crate) fn is_dynamic_method(method: &str) -> bool {
    matches!(method, "dynamic_lease_register" | "dynamic_audit_emit" | "dynamic_pool_checkout")
}

fn invalid(msg: impl Into<String>) -> (i32, String) {
    (DYNAMIC_INVALID, msg.into())
}

/// The capability gate, then the session check; nothing is read before.
pub(crate) fn gate(caps: DynamicCaps, state: &mut DynamicState, method: &str) -> Result<(), (i32, String)> {
    let declared = match method {
        "dynamic_lease_register" => caps.lease_register,
        "dynamic_audit_emit" => caps.audit_emit,
        "dynamic_pool_checkout" => caps.pool_checkout,
        _ => return Err(invalid("unknown dynamic method")),
    };
    if !declared {
        state.violations.push(method.to_string());
        return Err((DYNAMIC_FORBIDDEN, "forbidden".into()));
    }
    if state.session.is_none() {
        return Err((DYNAMIC_NO_SESSION, "no_session".into()));
    }
    Ok(())
}

/// [`gate`], then serve the call against the mock state.
pub(crate) fn call(
    caps: DynamicCaps,
    state: &mut DynamicState,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    gate(caps, state, method)?;
    serve(state, method, params)
}

/// Serve a call that passed [`gate`].
pub(crate) fn serve(state: &mut DynamicState, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    let session = state.session.clone().unwrap_or_default();
    let obj = params.as_object().cloned().unwrap_or_default();
    match method {
        "dynamic_lease_register" => {
            if session != "dynamic.generate" {
                return Err(invalid("dynamic_lease_register is only valid while generating a credential"));
            }
            if state.lease_in_session {
                return Err(invalid("dynamic_lease_register was already called for this credential"));
            }
            if let Some(k) =
                obj.keys().find(|k| !["internal", "ttl_secs", "max_ttl_secs", "renewable"].contains(&k.as_str()))
            {
                return Err(invalid(format!("unknown field `{k}`")));
            }
            state.lease_in_session = true;
            state.leases.push(Value::Object(obj));
            Ok(json!({ "registered": true }))
        }
        "dynamic_audit_emit" => {
            let event = obj.get("event").and_then(Value::as_str).unwrap_or("");
            if !EVENT_KINDS.contains(&event) {
                return Err(invalid("event must be generate, renew, revoke, revoke_failed or rotate_root"));
            }
            if let Some(k) = obj.keys().find(|k| !["event", "target_identity_type", "detail"].contains(&k.as_str())) {
                return Err(invalid(format!("unknown field `{k}`")));
            }
            state.events.push(Value::Object(obj));
            Ok(json!({ "emitted": true }))
        }
        _ => {
            let connection = obj.get("connection").and_then(Value::as_str).unwrap_or("");
            if !state.connections.contains(connection) {
                return Err(invalid(format!("connection `{connection}` is not configured on this mount")));
            }
            state.next_slot += 1;
            Ok(json!({
                "connection": connection,
                "root_credential_version": 1,
                "tls": { "verify": true },
                "slot": state.next_slot,
                "max_connections": 8,
            }))
        }
    }
}

/// The `host_reply.error` a process plugin receives, as the server words it.
pub(crate) fn process_error((code, msg): (i32, String)) -> String {
    match code {
        DYNAMIC_FORBIDDEN => "forbidden".into(),
        DYNAMIC_NO_SESSION => "no_session".into(),
        DYNAMIC_UNAVAILABLE => format!("unavailable: {msg}"),
        _ => format!("invalid: {msg}"),
    }
}
