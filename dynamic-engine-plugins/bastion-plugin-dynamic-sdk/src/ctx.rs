//! [`DynamicCtx`]: what a backend may ask the host for during one call.
//!
//! A handle, not the host itself: the pool, the audit emitter and storage
//! are reachable; lease registration is not (the dispatcher does it once).
//! The context also remembers every secret of the call so error text that
//! leaves the plugin is redacted.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    audit::AuditEvent,
    connection::Connection,
    host::{DynamicMethod, HostCalls},
    lease::{LeaseSlot, LeaseTerms},
    pool::{HostConnector, HostExecution, PoolGrant},
    role::check_name,
    secret::{redact, SecretString},
    DynamicError,
};

/// Storage prefix of a backend's own records (`state/<key>`).
pub const STATE_PREFIX: &str = "state/";

pub struct DynamicCtx<'h> {
    host: &'h mut dyn HostCalls,
    diag: &'h mut dyn FnMut(&str),
    secrets: Vec<SecretString>,
    lease: LeaseSlot,
}

impl<'h> DynamicCtx<'h> {
    pub(crate) fn new(host: &'h mut dyn HostCalls, diag: &'h mut dyn FnMut(&str)) -> Self {
        Self { host, diag, secrets: Vec::new(), lease: LeaseSlot::default() }
    }

    /// Treat `secret` as credential material of this call: it is redacted
    /// from every error and refused in audit labels and lease blobs.
    pub fn remember_secret(&mut self, secret: &SecretString) {
        if !secret.is_empty() {
            self.secrets.push(secret.clone());
        }
    }

    pub(crate) fn secret_refs(&self) -> Vec<&str> {
        self.secrets.iter().map(SecretString::expose).collect()
    }

    /// `message` with this call's secrets replaced.
    pub fn redact(&self, message: &str) -> String {
        redact(message, &self.secret_refs())
    }

    /// A warning for the host log (process: stderr; WASM: `bv.log`). The
    /// text is redacted first; still, never pass request data here.
    pub fn warn(&mut self, message: &str) {
        let line = self.redact(message);
        (self.diag)(&line);
    }

    /// Check out a pooled connection slot for `connection`. Dial the target
    /// with the grant's TLS policy, exactly.
    pub async fn pool_checkout(&mut self, connection: &str) -> Result<PoolGrant, DynamicError> {
        check_name("connection", connection)?;
        let reply = self
            .host
            .dynamic_call(DynamicMethod::PoolCheckout, serde_json::json!({ "connection": connection }))
            .await?;
        serde_json::from_value(reply).map_err(|e| DynamicError::Protocol(format!("dynamic_pool_checkout reply: {e}")))
    }

    /// Have the host run this call's rendered statements on the slot of
    /// `grant`, dialling `connector` itself under the operator's TLS policy.
    /// Only when `grant.executes(connector.kind)`. The host runs what it
    /// rendered for this call, once; there is no way to pass a statement.
    /// A failure is the operation's failure: never retry by dialling.
    pub async fn host_execute(
        &mut self,
        grant: &PoolGrant,
        connector: &HostConnector,
    ) -> Result<HostExecution, DynamicError> {
        self.remember_secret(&connector.password);
        let mut params = serde_json::json!({
            "connection": grant.connection,
            "execute": { "slot": grant.slot, "connector": connector.to_params() },
        });
        let reply = self.host.dynamic_call(DynamicMethod::PoolCheckout, params.clone()).await;
        crate::secret::wipe_value(&mut params);
        serde_json::from_value(reply?).map_err(|_| DynamicError::Protocol("host execution reply".into()))
    }

    /// Emit a plugin `dynamic_secret` event; the host stamps the rest.
    pub async fn emit(&mut self, event: &AuditEvent) -> Result<(), DynamicError> {
        let params = event.to_params(&self.secret_refs())?;
        self.host.dynamic_call(DynamicMethod::AuditEmit, params).await.map(|_| ())
    }

    /// Persist `connection` (e.g. after `rotate-root` changed its secret).
    pub async fn save_connection(&mut self, connection: &Connection) -> Result<(), DynamicError> {
        check_name("connection", &connection.name)?;
        let bytes = connection.encode()?;
        self.host.storage_put(&format!("config/{}", connection.name), &bytes).await
    }

    /// Read a backend record at `state/<key>`.
    pub async fn state_get(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DynamicError> {
        check_name("state key", key)?;
        self.host.storage_get(&format!("{STATE_PREFIX}{key}")).await
    }

    pub async fn state_put(&mut self, key: &str, value: &[u8]) -> Result<(), DynamicError> {
        check_name("state key", key)?;
        self.host.storage_put(&format!("{STATE_PREFIX}{key}"), value).await
    }

    pub async fn state_delete(&mut self, key: &str) -> Result<(), DynamicError> {
        check_name("state key", key)?;
        self.host.storage_delete(&format!("{STATE_PREFIX}{key}")).await
    }

    pub async fn state_list(&mut self) -> Result<Vec<String>, DynamicError> {
        let keys = self.host.storage_list(STATE_PREFIX.trim_end_matches('/')).await?;
        Ok(keys.into_iter().filter(|k| !k.ends_with('/')).collect())
    }

    pub(crate) fn host(&mut self) -> &mut dyn HostCalls {
        &mut *self.host
    }

    /// Load `config/<name>`; its secrets join the call's redaction set.
    pub(crate) async fn load_connection(&mut self, name: &str) -> Result<Option<Connection>, DynamicError> {
        check_name("connection", name)?;
        let Some(bytes) = self.host.storage_get(&format!("config/{name}")).await? else {
            return Ok(None);
        };
        let conn = Connection::decode(name, &bytes)?;
        for s in conn.secret_values() {
            self.remember_secret(s);
        }
        Ok(Some(conn))
    }

    /// Register this call's lease: once, or refused.
    pub(crate) async fn register_lease(&mut self, terms: &LeaseTerms) -> Result<(), DynamicError> {
        let params = terms.to_params(&self.secret_refs())?;
        self.lease.claim()?;
        let reply: Value = self.host.dynamic_call(DynamicMethod::LeaseRegister, params).await?;
        if reply.get("registered").and_then(Value::as_bool) != Some(true) {
            return Err(DynamicError::Protocol("dynamic_lease_register did not confirm the registration".into()));
        }
        Ok(())
    }
}
