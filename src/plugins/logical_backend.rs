//! Plugin-as-mount: a [`Backend`](crate::logical::Backend) that
//! routes every request operation through a registered plugin.
//!
//! ## Wiring
//!
//! When an operator mounts a path with `type = "plugin:<name>"`, the
//! [`MountsRouter`](crate::mount::MountsRouter) synthesises a factory
//! that constructs one of these backends bound to `<name>`. On every
//! request, this backend:
//!
//! 1. Resolves the active version of the plugin from the catalog.
//! 2. Loads the plugin's persisted `ConfigStore` (operator-set knobs).
//! 3. Wraps the request as a JSON envelope `{op, path, data}`.
//! 4. Dispatches to [`WasmRuntime`] or [`ProcessRuntime`] depending on
//!    `manifest.runtime`.
//! 5. Parses the plugin's response bytes as JSON `{data, warnings}`
//!    or `{error}` and translates back to a [`Response`].
//!
//! ## Envelope contract (v1)
//!
//! Host → plugin (input bytes are UTF-8 JSON):
//!
//! ```json
//! {"op": "read", "path": "users/alice", "data": {}}
//! ```
//!
//! `op ∈ {"read","write","delete","list","renew","revoke"}`. `path`
//! is the request path *relative to the mount* (the leading mount path
//! is already stripped by the router). `data` is the request body for
//! writes, an empty object otherwise.
//!
//! Plugin → host (response bytes, UTF-8 JSON):
//!
//! ```json
//! {"data": {...}, "warnings": ["..."]}
//! ```
//!
//! On error: a non-zero plugin status code, with the body either a
//! plain string (rendered as the error message) or a JSON object with
//! an `error` field.
//!
//! Plugins that don't want to handle every op return
//! `{"data": null}` or status `2` (treated as "not found"), surfaced
//! to the caller as `404`.

use std::any::Any;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::config::ConfigStore;
use super::manifest::{PluginManifest, RuntimeKind};
use super::process_runtime::ProcessRuntime;
use super::runtime::{InvokeOutcome, WasmRuntime};
use super::{PluginCatalog, PluginRecord};
use crate::context::Context;
use crate::core::Core;
use crate::errors::RvError;
use crate::logical::{Backend, Operation, Request, Response};

/// A `Backend` that routes every operation through a named plugin.
///
/// Created on-the-fly by the mounts router when an operator mounts a
/// path with `type = "plugin:<name>"`. One instance per mount, so
/// per-mount state (the storage view passed in `req.storage`) is
/// scoped to that mount; the plugin sees the same storage view a
/// built-in backend would.
pub struct PluginLogicalBackend {
    plugin_name: String,
    core: Arc<Core>,
}

impl PluginLogicalBackend {
    pub fn new(plugin_name: String, core: Arc<Core>) -> Self {
        Self { plugin_name, core }
    }
}

#[maybe_async::maybe_async]
impl Backend for PluginLogicalBackend {
    fn init(&mut self) -> Result<(), RvError> {
        Ok(())
    }

    fn setup(&self, _key: &str) -> Result<(), RvError> {
        Ok(())
    }

    fn cleanup(&self) -> Result<(), RvError> {
        Ok(())
    }

    fn get_unauth_paths(&self) -> Option<Arc<Vec<String>>> {
        None
    }

    fn get_root_paths(&self) -> Option<Arc<Vec<String>>> {
        None
    }

    fn get_ctx(&self) -> Option<Arc<Context>> {
        None
    }

    fn secret(&self, _key: &str) -> Option<&Arc<crate::logical::secret::Secret>> {
        None
    }

    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let storage = self.core.barrier.as_storage();
        let catalog = PluginCatalog::new();
        let record: PluginRecord = catalog
            .get(storage, &self.plugin_name)
            .await?
            .ok_or_else(|| {
                RvError::ErrOther(::anyhow::anyhow!(
                    "plugin {} is not registered (mount references a deleted plugin)",
                    self.plugin_name
                ))
            })?;

        let manifest = record.manifest;
        let binary = record.binary;

        let config_store = ConfigStore::new();
        let config = config_store
            .get(storage, &self.plugin_name)
            .await
            .unwrap_or_default();

        let envelope = build_envelope(req)?;
        let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| {
            RvError::ErrOther(::anyhow::anyhow!("envelope serialise failed: {e}"))
        })?;

        let output = match manifest.runtime {
            RuntimeKind::Wasm => {
                let runtime = WasmRuntime::new().map_err(|e| {
                    RvError::ErrOther(::anyhow::anyhow!("wasm runtime: {e:?}"))
                })?;
                runtime
                    .invoke_with_config(
                        &manifest,
                        &binary,
                        &envelope_bytes,
                        Some(self.core.clone()),
                        config,
                    )
                    .await
                    .map_err(|e| {
                        RvError::ErrOther(::anyhow::anyhow!(
                            "plugin {} (wasm) invoke failed: {e:?}",
                            self.plugin_name,
                        ))
                    })?
            }
            RuntimeKind::Process => {
                let runtime = ProcessRuntime::new();
                runtime
                    .invoke_with_config(
                        &manifest,
                        &binary,
                        &envelope_bytes,
                        Some(self.core.clone()),
                        config,
                    )
                    .await
                    .map_err(|e| {
                        RvError::ErrOther(::anyhow::anyhow!(
                            "plugin {} (process) invoke failed: {e:?}",
                            self.plugin_name,
                        ))
                    })?
            }
        };

        translate_response(&self.plugin_name, &manifest, &output)
    }
}

/// Build the host→plugin envelope from an inbound `Request`. The
/// `path` field is the request path *relative to the mount* — the
/// mounts router has already stripped the mount prefix.
fn build_envelope(req: &Request) -> Result<Value, RvError> {
    let op = match req.operation {
        Operation::Read => "read",
        Operation::Write => "write",
        Operation::Delete => "delete",
        Operation::List => "list",
        Operation::Renew => "renew",
        Operation::Revoke => "revoke",
        Operation::Help => "help",
        Operation::Rollback => "rollback",
    };
    let data = req.body.clone().unwrap_or_default();
    Ok(json!({
        "op": op,
        "path": req.path.clone(),
        "data": Value::Object(data),
    }))
}

/// Translate the plugin's response bytes into a `Response`. A
/// plugin that wants to emit a typed payload returns
/// `{"data": {...}, "warnings": [...]}`; one that wants to signal
/// "no value here" returns `{"data": null}` (rendered as `Ok(None)`).
/// On a non-zero plugin status, the body becomes the error message.
fn translate_response(
    plugin_name: &str,
    _manifest: &PluginManifest,
    output: &super::runtime::InvokeOutput,
) -> Result<Option<Response>, RvError> {
    if let InvokeOutcome::PluginError(code) = output.outcome {
        let msg = if let Ok(v) = serde_json::from_slice::<Value>(&output.response) {
            v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string()).unwrap_or_else(
                || String::from_utf8_lossy(&output.response).to_string(),
            )
        } else {
            String::from_utf8_lossy(&output.response).to_string()
        };
        return Err(RvError::ErrOther(::anyhow::anyhow!(
            "plugin {plugin_name} returned status {code}: {msg}"
        )));
    }

    if output.response.is_empty() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_slice(&output.response).map_err(|e| {
        RvError::ErrOther(::anyhow::anyhow!(
            "plugin {plugin_name} response is not valid JSON: {e}"
        ))
    })?;

    // {"data": null} → no value; the router surfaces 404.
    let data = match parsed.get("data") {
        Some(Value::Null) => return Ok(None),
        Some(Value::Object(m)) => Some(m.clone()),
        Some(_) => {
            return Err(RvError::ErrOther(::anyhow::anyhow!(
                "plugin {plugin_name} response.data is neither object nor null"
            )));
        }
        None => None,
    };
    let warnings = parsed
        .get("warnings")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(Some(Response {
        data,
        warnings,
        ..Default::default()
    }))
}

/// Trait-object factory closure compatible with
/// [`LogicalBackendNewFunc`](crate::core::LogicalBackendNewFunc). The
/// [`MountsRouter::get_backend`] hook returns one of these per
/// `plugin:<name>` lookup.
pub fn factory_for(plugin_name: String) -> Arc<crate::core::LogicalBackendNewFunc> {
    Arc::new(move |core: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
        let backend = PluginLogicalBackend::new(plugin_name.clone(), core);
        Ok(Arc::new(backend) as Arc<dyn Backend>)
    })
}

// `Any` impl so the mounts router can downcast if it ever needs to.
impl PluginLogicalBackend {
    #[allow(dead_code)]
    pub fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::Operation;
    use crate::plugins::runtime::{InvokeOutcome, InvokeOutput};

    fn manifest_for_test() -> PluginManifest {
        use crate::plugins::manifest::Capabilities;
        PluginManifest {
            name: "demo".into(),
            version: "0.1.0".into(),
            plugin_type: "secret-engine".into(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".into(),
            sha256: "0".repeat(64),
            size: 0,
            capabilities: Capabilities::default(),
            description: String::new(),
            config_schema: vec![],
        }
    }

    #[test]
    fn envelope_carries_op_and_path() {
        let mut req = Request::new("users/alice");
        req.operation = Operation::Read;
        let env = build_envelope(&req).unwrap();
        assert_eq!(env["op"], "read");
        assert_eq!(env["path"], "users/alice");
        assert_eq!(env["data"], serde_json::json!({}));
    }

    #[test]
    fn envelope_passes_body_for_writes() {
        let mut req = Request::new("kv/foo");
        req.operation = Operation::Write;
        let mut body = Map::new();
        body.insert("value".into(), Value::String("secret".into()));
        req.body = Some(body);
        let env = build_envelope(&req).unwrap();
        assert_eq!(env["op"], "write");
        assert_eq!(env["data"]["value"], "secret");
    }

    #[test]
    fn translate_data_object_round_trip() {
        let m = manifest_for_test();
        let body = serde_json::json!({"data": {"k": "v"}, "warnings": ["w1"]})
            .to_string()
            .into_bytes();
        let out = InvokeOutput {
            outcome: InvokeOutcome::Success,
            response: body,
            fuel_consumed: 0,
        };
        let resp = translate_response("demo", &m, &out).unwrap().expect("Some");
        assert_eq!(resp.data.unwrap()["k"], "v");
        assert_eq!(resp.warnings, vec!["w1".to_string()]);
    }

    #[test]
    fn translate_null_data_means_not_found() {
        let m = manifest_for_test();
        let body = serde_json::json!({"data": null}).to_string().into_bytes();
        let out = InvokeOutput {
            outcome: InvokeOutcome::Success,
            response: body,
            fuel_consumed: 0,
        };
        let resp = translate_response("demo", &m, &out).unwrap();
        assert!(resp.is_none(), "{{data: null}} must surface as Ok(None)");
    }

    #[test]
    fn translate_empty_response_is_none() {
        let m = manifest_for_test();
        let out = InvokeOutput {
            outcome: InvokeOutcome::Success,
            response: vec![],
            fuel_consumed: 0,
        };
        assert!(translate_response("demo", &m, &out).unwrap().is_none());
    }

    #[test]
    fn translate_plugin_error_with_json_body() {
        let m = manifest_for_test();
        let body = serde_json::json!({"error": "not allowed"}).to_string().into_bytes();
        let out = InvokeOutput {
            outcome: InvokeOutcome::PluginError(7),
            response: body,
            fuel_consumed: 0,
        };
        let err = translate_response("demo", &m, &out).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("status 7"), "{msg}");
        assert!(msg.contains("not allowed"), "{msg}");
    }

    #[test]
    fn translate_plugin_error_with_plain_string_body() {
        let m = manifest_for_test();
        let out = InvokeOutput {
            outcome: InvokeOutcome::PluginError(1),
            response: b"oops".to_vec(),
            fuel_consumed: 0,
        };
        let err = translate_response("demo", &m, &out).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("oops"), "{msg}");
    }

    #[test]
    fn translate_invalid_json_is_internal_error() {
        let m = manifest_for_test();
        let out = InvokeOutput {
            outcome: InvokeOutcome::Success,
            response: b"not-json".to_vec(),
            fuel_consumed: 0,
        };
        assert!(translate_response("demo", &m, &out).is_err());
    }

    #[test]
    fn factory_constructs_backend_for_any_name() {
        // Just exercise the factory closure — actually instantiating
        // a `Core` is heavy and covered by the integration tests.
        let f = factory_for("anything".into());
        assert!(Arc::strong_count(&f) >= 1);
    }
}
