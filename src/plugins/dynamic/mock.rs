//! Test-only stand-in for a plugin binary, registered by plugin name.
//!
//! [`super::super::logical_backend::invoke_record`] consults it before picking
//! a runtime, so a mock plugin is driven through the real mount, lease
//! manager and dynamic host. Its host calls go through the process runtime's
//! `handle_host_call`, i.e. the same capability gate a real plugin meets.

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use dashmap::DashMap;
use serde_json::{json, Value};

use super::DynamicSession;
use crate::{
    errors::RvError,
    kernel_api::VaultCtx,
    plugins::{
        invocation::InvocationCaller,
        manifest::PluginManifest,
        runtime::{InvokeOutcome, InvokeOutput},
    },
};

/// What a mock plugin may call back into.
pub struct MockHost<'a> {
    manifest: &'a PluginManifest,
    core: Arc<dyn VaultCtx>,
    caller: Option<InvocationCaller>,
    session: Option<Arc<DynamicSession>>,
}

impl MockHost<'_> {
    /// The vault the mock runs in, for a mock that issues a request of its own.
    pub fn core(&self) -> &Arc<dyn VaultCtx> {
        &self.core
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let config = BTreeMap::new();
        crate::plugins::process_runtime::handle_host_call(
            self.manifest,
            Some(&self.core),
            &config,
            method,
            &params,
            self.caller.as_ref(),
            self.session.as_ref(),
        )
        .await
    }
}

#[async_trait::async_trait]
pub trait MockPlugin: Send + Sync {
    /// Answer one envelope; `Err((status, message))` is a plugin failure.
    async fn handle(&self, envelope: Value, host: &MockHost<'_>) -> Result<Value, (i32, String)>;
}

fn registry() -> &'static DashMap<String, Arc<dyn MockPlugin>> {
    static MOCKS: OnceLock<DashMap<String, Arc<dyn MockPlugin>>> = OnceLock::new();
    MOCKS.get_or_init(DashMap::new)
}

pub fn register(plugin_name: &str, plugin: Arc<dyn MockPlugin>) {
    registry().insert(plugin_name.to_string(), plugin);
}

pub fn unregister(plugin_name: &str) {
    registry().remove(plugin_name);
}

pub struct Registered(Arc<dyn MockPlugin>);

pub fn lookup(plugin_name: &str) -> Option<Registered> {
    registry().get(plugin_name).map(|e| Registered(e.value().clone()))
}

impl Registered {
    pub async fn invoke(
        &self,
        manifest: &PluginManifest,
        input: &[u8],
        core: Arc<dyn VaultCtx>,
        caller: Option<InvocationCaller>,
        session: Option<Arc<DynamicSession>>,
    ) -> Result<InvokeOutput, RvError> {
        let envelope: Value = serde_json::from_slice(input)?;
        let host = MockHost { manifest, core, caller, session };
        let (outcome, body) = match self.0.handle(envelope, &host).await {
            Ok(v) => (InvokeOutcome::Success, v),
            // A message that is a JSON object is the whole error body (a
            // plugin adding fields such as `root_stored`).
            Err((code, msg)) => {
                let body = serde_json::from_str::<Value>(&msg)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| json!({ "error": msg }));
                (InvokeOutcome::PluginError(code), body)
            }
        };
        Ok(InvokeOutput { outcome, response: serde_json::to_vec(&body)?, fuel_consumed: 0 })
    }
}
