//! An in-memory host for unit tests (feature `testing`). Same rules, in the
//! same order, as the server and `bastion-plugin-testkit`: an undeclared
//! capability is refused and recorded before anything else, a dynamic call
//! needs a dynamic RPC, and a lease is accepted once, in `dynamic.generate`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    backend::DynamicCredentialBackend,
    dispatch::{dispatch, Reply},
    host::{DynamicMethod, HostCalls},
    DynamicError,
};

#[derive(Debug, Default)]
pub struct MockHost {
    pub lease_register: bool,
    pub audit_emit: bool,
    pub pool_checkout: bool,
    /// Connections the host has a record for (written `config/<name>`).
    pub connections: BTreeSet<String>,
    /// The `tls` block every grant carries.
    pub tls: Option<Value>,
    pub storage: BTreeMap<String, Vec<u8>>,
    /// Accepted `dynamic_lease_register` requests.
    pub leases: Vec<Value>,
    pub events: Vec<Value>,
    pub violations: Vec<String>,
    /// Every host call made, in order (method names).
    pub calls: Vec<String>,
    /// Make the next call of this method fail with this host error string.
    pub fail_next: Option<(DynamicMethod, String)>,
    /// Make every `storage_put` fail (`internal`), as a broken barrier would.
    pub fail_storage_put: bool,
    /// Connector kinds the host executes for (`host_execute` in each grant).
    /// Empty by default: a host that does not, so the plugin dials itself.
    pub host_execute: BTreeSet<String>,
    /// Accepted host executions: op, connection, slot, kind, url, username
    /// (never the root secret).
    pub executions: Vec<Value>,
    /// The answer to the next host execution (default: the statement count).
    pub execution_reply: Option<Value>,
    /// Refuse the next host execution with this host error string.
    pub fail_execution: Option<String>,
    session: Option<String>,
    session_connection: Option<String>,
    session_statements: usize,
    session_slots: BTreeSet<u64>,
    executed_in_session: bool,
    lease_in_session: bool,
    next_slot: u64,
}

impl MockHost {
    /// A host granting all three dynamic capabilities.
    pub fn granting_all() -> Self {
        Self { lease_register: true, audit_emit: true, pool_checkout: true, ..Default::default() }
    }

    pub fn with_connection(mut self, name: &str) -> Self {
        self.connections.insert(name.to_string());
        self
    }

    /// A host with a connector of `kind`: it runs the call's statements.
    pub fn executing(mut self, kind: &str) -> Self {
        self.host_execute.insert(kind.to_string());
        self
    }

    /// `execute` on a held slot, refused as the server refuses it.
    fn execute(&mut self, method: DynamicMethod, connection: &str, exec: &Value) -> Result<Value, DynamicError> {
        let shape = || refused(method, "invalid: execute must be {slot, connector}");
        let obj = exec.as_object().ok_or_else(shape)?;
        if obj.keys().any(|k| k != "slot" && k != "connector") {
            return Err(shape());
        }
        let slot = obj.get("slot").and_then(Value::as_u64).ok_or_else(shape)?;
        let connector = obj.get("connector").and_then(Value::as_object).ok_or_else(shape)?;
        let text = |k: &str| connector.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
        let allowed = ["kind", "url", "username", "password", "connect_timeout_secs"];
        if connector.keys().any(|k| !allowed.contains(&k.as_str()))
            || ["kind", "url", "username", "password"].iter().any(|k| text(k).is_none())
        {
            return Err(refused(method, "invalid: invalid connector"));
        }
        let kind = text("kind").unwrap_or_default();
        if self.session_connection.as_deref() != Some(connection) {
            return Err(refused(method, "invalid: not the connection this call's statements were rendered for"));
        }
        if !self.host_execute.contains(&kind) {
            return Err(refused(method, &format!("invalid: this host has no `{kind}` connector")));
        }
        if !self.session_slots.contains(&slot) {
            return Err(refused(method, &format!("invalid: slot {slot} is not held by this call")));
        }
        let op = self.session.clone().unwrap_or_default();
        let planned = ["dynamic.generate", "dynamic.renew", "dynamic.revoke"].contains(&op.as_str());
        if !planned || self.executed_in_session {
            return Err(refused(method, &format!("invalid: {op} has no host-rendered statements to execute")));
        }
        self.executed_in_session = true;
        if let Some(err) = self.fail_execution.take() {
            return Err(refused(method, &err));
        }
        self.executions.push(json!({ "op": op, "connection": connection, "slot": slot, "kind": kind,
            "url": text("url"), "username": text("username") }));
        let default = json!({ "executed": self.session_statements, "identity_absent": false });
        Ok(self.execution_reply.take().unwrap_or(default))
    }

    fn declared(&self, method: DynamicMethod) -> bool {
        match method {
            DynamicMethod::LeaseRegister => self.lease_register,
            DynamicMethod::AuditEmit => self.audit_emit,
            DynamicMethod::PoolCheckout => self.pool_checkout,
        }
    }
}

fn refused(method: DynamicMethod, error: &str) -> DynamicError {
    DynamicError::from_process_reply(method.name(), error)
}

#[async_trait::async_trait(?Send)]
impl HostCalls for MockHost {
    async fn dynamic_call(&mut self, method: DynamicMethod, params: Value) -> Result<Value, DynamicError> {
        self.calls.push(method.name().to_string());
        if !self.declared(method) {
            self.violations.push(method.name().to_string());
            return Err(refused(method, "forbidden"));
        }
        let Some(session) = self.session.clone() else {
            return Err(refused(method, "no_session"));
        };
        if let Some((m, err)) = self.fail_next.take() {
            if m == method {
                return Err(refused(method, &err));
            }
            self.fail_next = Some((m, err));
        }
        let obj = params.as_object().cloned().unwrap_or_default();
        match method {
            DynamicMethod::LeaseRegister => {
                if session != "dynamic.generate" {
                    return Err(refused(method, "invalid: only valid while generating a credential"));
                }
                if self.lease_in_session {
                    return Err(refused(method, "invalid: already called for this credential"));
                }
                if let Some(k) =
                    obj.keys().find(|k| !["internal", "ttl_secs", "max_ttl_secs", "renewable"].contains(&k.as_str()))
                {
                    return Err(refused(method, &format!("invalid: unknown field `{k}`")));
                }
                self.lease_in_session = true;
                self.leases.push(Value::Object(obj));
                Ok(json!({ "registered": true }))
            }
            DynamicMethod::AuditEmit => {
                if let Some(k) = obj.keys().find(|k| !["event", "target_identity_type", "detail"].contains(&k.as_str()))
                {
                    return Err(refused(method, &format!("invalid: unknown field `{k}`")));
                }
                self.events.push(Value::Object(obj));
                Ok(json!({ "emitted": true }))
            }
            DynamicMethod::PoolCheckout => {
                let conn = obj.get("connection").and_then(Value::as_str).unwrap_or("").to_string();
                if let Some(exec) = obj.get("execute") {
                    return self.execute(method, &conn, exec);
                }
                if !self.connections.contains(&conn) {
                    return Err(refused(method, &format!("invalid: connection `{conn}` is not configured")));
                }
                self.next_slot += 1;
                self.session_slots.insert(self.next_slot);
                Ok(json!({
                    "connection": conn,
                    "root_credential_version": 1,
                    "tls": self.tls.clone().unwrap_or_else(|| json!({ "verify": true })),
                    "slot": self.next_slot,
                    "max_connections": 8,
                    "host_execute": self.host_execute.iter().collect::<Vec<_>>(),
                }))
            }
        }
    }

    async fn storage_get(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DynamicError> {
        self.calls.push("storage_get".into());
        Ok(self.storage.get(key).map(|v| Zeroizing::new(v.clone())))
    }

    async fn storage_put(&mut self, key: &str, value: &[u8]) -> Result<(), DynamicError> {
        self.calls.push("storage_put".into());
        if self.fail_storage_put {
            return Err(DynamicError::Unavailable("storage_put: host answered `internal`".into()));
        }
        self.storage.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn storage_delete(&mut self, key: &str) -> Result<(), DynamicError> {
        self.calls.push("storage_delete".into());
        self.storage.remove(key);
        Ok(())
    }

    async fn storage_list(&mut self, prefix: &str) -> Result<Vec<String>, DynamicError> {
        self.calls.push("storage_list".into());
        let full = format!("{}/", prefix.trim_end_matches('/'));
        let mut names = BTreeSet::new();
        for k in self.storage.keys() {
            if let Some(rest) = k.strip_prefix(&full) {
                match rest.split_once('/') {
                    Some((dir, _)) => names.insert(format!("{dir}/")),
                    None => names.insert(rest.to_string()),
                };
            }
        }
        Ok(names.into_iter().collect())
    }
}

/// One call through [`dispatch`] the way the host makes it: a `dynamic.*`
/// envelope opens a dynamic RPC for its duration. Returns the reply and the
/// diagnostic lines the plugin would have written to its host log.
pub async fn invoke<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    host: &mut MockHost,
    envelope: &Value,
) -> (Reply, Vec<String>) {
    let op = envelope.get("op").and_then(Value::as_str).unwrap_or("");
    host.session = op.starts_with("dynamic.").then(|| op.to_string());
    host.lease_in_session = false;
    host.session_connection = envelope.get("connection").and_then(Value::as_str).map(str::to_string);
    host.session_statements = envelope.get("statements").and_then(Value::as_array).map_or(0, Vec::len);
    host.session_slots.clear();
    host.executed_in_session = false;
    let input = Zeroizing::new(serde_json::to_vec(envelope).unwrap_or_default());
    let mut lines = Vec::new();
    let mut diag = |l: &str| lines.push(l.to_string());
    let reply = dispatch(backend, host, &input, &mut diag).await;
    host.session = None;
    (reply, lines)
}
