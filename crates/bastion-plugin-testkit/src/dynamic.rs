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
    /// Connector kinds the mock host executes for (`host_execute` in every
    /// grant). Empty, as for a host without connectors, unless configured.
    pub(crate) host_execute: BTreeSet<String>,
    /// Accepted host executions, without the root secret.
    pub(crate) executions: Vec<Value>,
    /// Per session: its envelope's `connection` and statement count, the
    /// slots it checked out, and whether its plan already ran.
    pub(crate) session_connection: Option<String>,
    pub(crate) session_statements: usize,
    pub(crate) session_slots: BTreeSet<u64>,
    pub(crate) executed_in_session: bool,
}

impl DynamicState {
    /// Start serving the dynamic RPC `envelope`.
    pub(crate) fn open_session(&mut self, envelope: &Value) {
        self.session = Some(envelope.get("op").and_then(Value::as_str).unwrap_or("").to_string());
        self.lease_in_session = false;
        self.session_connection = envelope.get("connection").and_then(Value::as_str).map(str::to_string);
        self.session_statements = envelope.get("statements").and_then(Value::as_array).map_or(0, Vec::len);
        self.session_slots.clear();
        self.executed_in_session = false;
    }
}

/// The ops whose statements the host rendered, and so may run for a plugin
/// (rotate-root: the host sets, verifies and, if need be, undoes the secret).
const PLANNED_OPS: [&str; 4] = ["dynamic.generate", "dynamic.renew", "dynamic.revoke", "dynamic.rotate_root"];
const CONNECTOR_FIELDS: [&str; 5] = ["kind", "url", "username", "password", "connect_timeout_secs"];

/// `dynamic_pool_checkout` with `execute`, refused in the server's order and
/// words (`src/plugins/dynamic/host_calls.rs`). Nothing runs: the mock records
/// the execution and answers with the envelope's statement count.
fn execute(state: &mut DynamicState, connection: &str, execute: &Value) -> Result<Value, (i32, String)> {
    let shape = || invalid("execute must be {slot, connector}");
    let obj = execute.as_object().ok_or_else(shape)?;
    if obj.keys().any(|k| k != "slot" && k != "connector") {
        return Err(shape());
    }
    let slot = obj.get("slot").and_then(Value::as_u64).ok_or_else(shape)?;
    let connector = obj.get("connector").and_then(Value::as_object).ok_or_else(shape)?;
    let text = |k: &str| connector.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    let well_formed = connector.keys().all(|k| CONNECTOR_FIELDS.contains(&k.as_str()))
        && ["kind", "url", "username", "password"].iter().all(|k| text(k).is_some());
    if !well_formed {
        return Err(invalid(
            "invalid connector: expected exactly kind, url, username, password and optionally connect_timeout_secs",
        ));
    }
    let kind = text("kind").unwrap_or_default();
    if state.session_connection.as_deref() != Some(connection) {
        return Err(invalid("host execution runs only on the connection this call's statements were rendered for"));
    }
    if !state.host_execute.contains(kind) {
        return Err(invalid(format!("this host has no `{kind}` connector")));
    }
    if !state.session_slots.contains(&slot) {
        return Err(invalid(format!("slot {slot} is not held by this call")));
    }
    let op = state.session.clone().unwrap_or_default();
    if !PLANNED_OPS.contains(&op.as_str()) || state.executed_in_session {
        return Err(invalid(format!("{op} has no host-rendered statements to execute, or they already ran")));
    }
    state.executed_in_session = true;
    state.executions.push(json!({
        "op": op, "connection": connection, "slot": slot, "kind": kind,
        "url": text("url"), "username": text("username"),
    }));
    if op == "dynamic.rotate_root" {
        return Ok(json!({ "executed": 1, "identity_absent": false, "rotated": true }));
    }
    Ok(json!({ "executed": state.session_statements, "identity_absent": false }))
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
            if let Some(exec) = obj.get("execute") {
                return execute(state, connection, exec);
            }
            if !state.connections.contains(connection) {
                return Err(invalid(format!("connection `{connection}` is not configured on this mount")));
            }
            state.next_slot += 1;
            state.session_slots.insert(state.next_slot);
            Ok(json!({
                "connection": connection,
                "root_credential_version": 1,
                "tls": { "verify": true },
                "slot": state.next_slot,
                "max_connections": 8,
                "host_execute": state.host_execute.iter().collect::<Vec<_>>(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const CAPS: DynamicCaps = DynamicCaps { lease_register: true, audit_emit: true, pool_checkout: true };

    fn state(kinds: &[&str]) -> DynamicState {
        DynamicState {
            connections: ["prod".to_string()].into(),
            host_execute: kinds.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        }
    }

    fn exec(slot: Value, kind: &str) -> Value {
        json!({ "connection": "prod", "execute": { "slot": slot, "connector": {
            "kind": kind, "url": "postgres://db/app", "username": "vault", "password": "root-secret" } } })
    }

    #[test]
    fn host_execution_mirrors_the_servers_rules() {
        let mut st = state(&["postgres"]);
        st.open_session(&json!({ "op": "dynamic.generate", "connection": "prod", "statements": ["a", "b"] }));
        let grant = call(CAPS, &mut st, "dynamic_pool_checkout", &json!({ "connection": "prod" })).unwrap();
        assert_eq!(grant["host_execute"], json!(["postgres"]));
        let slot = grant["slot"].clone();

        let refused =
            |st: &mut DynamicState, params: Value| call(CAPS, st, "dynamic_pool_checkout", &params).unwrap_err().1;
        assert!(refused(&mut st, exec(json!(99), "postgres")).contains("not held"));
        assert!(refused(&mut st, exec(slot.clone(), "mysql")).contains("no `mysql` connector"));
        let mut smuggled = exec(slot.clone(), "postgres");
        smuggled["execute"]["statements"] = json!(["DROP DATABASE app"]);
        assert!(refused(&mut st, smuggled).contains("execute must be"));
        let mut other = exec(slot.clone(), "postgres");
        other["connection"] = json!("other");
        assert!(refused(&mut st, other).contains("rendered for"));

        let done = call(CAPS, &mut st, "dynamic_pool_checkout", &exec(slot.clone(), "postgres")).unwrap();
        assert_eq!(done, json!({ "executed": 2, "identity_absent": false }));
        assert!(refused(&mut st, exec(slot, "postgres")).contains("already ran"), "once per call");
        assert_eq!(st.executions.len(), 1);
        assert!(!st.executions[0].to_string().contains("root-secret"), "the root secret is not recorded");

        st.open_session(&json!({ "op": "dynamic.rotate_root", "connection": "prod" }));
        let slot =
            call(CAPS, &mut st, "dynamic_pool_checkout", &json!({ "connection": "prod" })).unwrap()["slot"].clone();
        let rotated = call(CAPS, &mut st, "dynamic_pool_checkout", &exec(slot, "postgres")).unwrap();
        assert_eq!(rotated["rotated"], true, "the host rotates the root itself");

        // A proxied call has no plan.
        st.open_session(&json!({ "op": "read", "connection": "prod" }));
        let slot =
            call(CAPS, &mut st, "dynamic_pool_checkout", &json!({ "connection": "prod" })).unwrap()["slot"].clone();
        assert!(refused(&mut st, exec(slot, "postgres")).contains("no host-rendered statements"));

        let mut plain = state(&[]);
        plain.open_session(&json!({ "op": "dynamic.generate", "connection": "prod" }));
        let grant = call(CAPS, &mut plain, "dynamic_pool_checkout", &json!({ "connection": "prod" })).unwrap();
        assert_eq!(grant["host_execute"], json!([]), "a host without connectors grants none");
    }
}
