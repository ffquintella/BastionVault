//! [`RemoteBackend`] — talks to a BastionVault HTTP server.
//!
//! Ported from `bastion_vault::api::client::Client` minus the chunks
//! the GUI never uses (the typed `sys` / `auth` / `secret` helpers).
//! The single dispatch method is [`Backend::handle`], which maps an
//! [`Operation`] to a HTTP method and parses the response body into
//! a [`JsonResponse`] for the GUI's command layer.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::Request;
use serde_json::{Map, Value};
use ureq::Agent;

use crate::{
    backend::Backend,
    error::ClientError,
    tls::ClientTlsConfig,
    types::{JsonResponse, Operation},
};

/// HTTP-backed implementation of [`Backend`].
///
/// Cheap to clone — internally just bumps an `Arc` on the
/// connection-pooled `ureq::Agent`. Per-request data (token, body)
/// is passed through `handle`; per-connection data (address, TLS,
/// API version) is set at construction time via
/// [`RemoteBackendBuilder`].
#[derive(Clone)]
pub struct RemoteBackend {
    inner: Arc<RemoteInner>,
}

struct RemoteInner {
    address: String,
    headers: HashMap<String, String>,
    api_version: u8,
    agent: Agent,
}

#[derive(Clone, Default)]
pub struct RemoteBackendBuilder {
    address: Option<String>,
    headers: HashMap<String, String>,
    api_version: Option<u8>,
    tls: Option<ClientTlsConfig>,
    timeout_connect: Option<Duration>,
    timeout_global: Option<Duration>,
}

impl RemoteBackendBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_address<S: Into<String>>(mut self, addr: S) -> Self {
        self.address = Some(addr.into());
        self
    }

    pub fn with_api_version(mut self, version: u8) -> Self {
        self.api_version = Some(version);
        self
    }

    pub fn with_header<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn with_tls_config(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_timeout_connect(mut self, d: Duration) -> Self {
        self.timeout_connect = Some(d);
        self
    }

    pub fn with_timeout_global(mut self, d: Duration) -> Self {
        self.timeout_global = Some(d);
        self
    }

    pub fn build(self) -> RemoteBackend {
        let mut config_builder = ureq::Agent::config_builder()
            .timeout_connect(Some(self.timeout_connect.unwrap_or(Duration::from_secs(10))))
            .timeout_global(Some(self.timeout_global.unwrap_or(Duration::from_secs(30))))
            .http_status_as_error(false)
            .allow_non_standard_methods(true);

        if let Some(tls) = &self.tls {
            config_builder = config_builder.tls_config(tls.tls_config.clone());
        }

        let agent = config_builder.build().new_agent();

        RemoteBackend {
            inner: Arc::new(RemoteInner {
                address: self.address.unwrap_or_else(|| "https://127.0.0.1:8200".to_string()),
                headers: self.headers,
                api_version: self.api_version.unwrap_or(1),
                agent,
            }),
        }
    }
}

impl RemoteBackend {
    pub fn builder() -> RemoteBackendBuilder {
        RemoteBackendBuilder::new()
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    fn api_prefix(&self) -> &'static str {
        match self.inner.api_version {
            2 => "/v2",
            _ => "/v1",
        }
    }

    fn build_url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.inner.address, path)
        } else {
            format!("{}/{}/{}", self.inner.address, self.api_prefix().trim_start_matches('/'), path)
        }
    }
}

#[async_trait]
impl Backend for RemoteBackend {
    async fn handle(
        &self,
        operation: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
        token: &str,
    ) -> Result<Option<JsonResponse>, ClientError> {
        let method = match operation {
            Operation::Read => "GET",
            Operation::Write => "POST",
            Operation::Delete => "DELETE",
            Operation::List => "LIST",
        };

        let url = self.build_url(path);
        let inner = Arc::clone(&self.inner);
        let body = body;
        let token = token.to_string();
        let path_owned = path.to_string();

        // ureq is sync. Park the call on a blocking thread so we
        // don't hold the executor while the network round-trips.
        let response_result = tokio::task::spawn_blocking(move || {
            let mut builder = Request::builder()
                .method(method)
                .uri(&url)
                .header("Accept", "application/json");

            if !path_owned.ends_with("/login") && !token.is_empty() {
                builder = builder.header("X-BastionVault-Token", &token);
            }
            for (k, v) in &inner.headers {
                builder = builder.header(k, v);
            }

            let result = if let Some(payload) = body {
                let bytes = serde_json::to_vec(&payload).map_err(ClientError::from)?;
                let req = builder
                    .header("Content-Type", "application/json")
                    .body(bytes)
                    .map_err(ClientError::from)?;
                inner.agent.run(req).map_err(ClientError::from)
            } else {
                let req = builder.body(()).map_err(ClientError::from)?;
                inner.agent.run(req).map_err(ClientError::from)
            };

            result.and_then(|mut response| {
                let status = response.status().as_u16();
                if status == 204 {
                    return Ok((status, Value::Null));
                }
                // Read raw bytes first — some server paths reply with
                // an empty body (notably error responses without an
                // `errors` envelope). serde_json::from_slice on `[]`
                // yields a confusing "EOF while parsing a value at
                // line 1 column 0" that masks the real status code,
                // so treat empty as Null and let the status branch
                // below produce a sensible message.
                let bytes = response
                    .body_mut()
                    .read_to_vec()
                    .map_err(ClientError::from)?;
                let json = if bytes.iter().all(|b| b.is_ascii_whitespace()) {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).map_err(ClientError::from)?
                };
                Ok((status, json))
            })
        })
        .await
        .map_err(|e| ClientError::backend(format!("join: {e}")))??;

        let (status, json) = response_result;

        if status == 204 {
            return Ok(None);
        }

        if (200..300).contains(&status) {
            // Server returns `null` body for some success cases —
            // treat as `None`. Otherwise pull out the well-known
            // top-level keys via JsonResponse::from_json.
            if json.is_null() {
                Ok(None)
            } else {
                Ok(Some(JsonResponse::from_json(json)))
            }
        } else {
            // Surface server-side errors with a best-effort message.
            // The HTTP API typically replies with `{"errors":[...]}`
            // so we pull that out when we can.
            let message = match &json {
                Value::Null => format!("HTTP {status} (no body)"),
                Value::Object(obj) => obj
                    .get("errors")
                    .and_then(|v| match v {
                        Value::Array(arr) => Some(
                            arr.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect::<Vec<_>>()
                                .join("; "),
                        ),
                        _ => None,
                    })
                    .or_else(|| obj.get("error").and_then(|v| v.as_str().map(String::from)))
                    .unwrap_or_else(|| json.to_string()),
                _ => json.to_string(),
            };
            Err(ClientError::server(status, message))
        }
    }

    async fn active_surfaces(
        &self,
        token: &str,
        etag: Option<&str>,
    ) -> Result<crate::backend::SurfaceFetch, ClientError> {
        self.fetch_active_surfaces(token, etag, false).await
    }

    async fn watch_active_surfaces(
        &self,
        token: &str,
        etag: Option<&str>,
    ) -> Result<crate::backend::SurfaceFetch, ClientError> {
        self.fetch_active_surfaces(token, etag, true).await
    }

    async fn fetch_asset(
        &self,
        plugin: &str,
        version: &str,
        sha256: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        self.do_fetch_asset(plugin, version, sha256, token).await
    }
}

impl RemoteBackend {
    async fn fetch_active_surfaces(
        &self,
        token: &str,
        etag: Option<&str>,
        watch: bool,
    ) -> Result<crate::backend::SurfaceFetch, ClientError> {
        // Trailing slash + leading slash hygiene matches `build_url`.
        let url = if watch {
            format!("{}?watch=1", self.build_url("sys/plugins/active-surfaces"))
        } else {
            self.build_url("sys/plugins/active-surfaces")
        };
        let inner = Arc::clone(&self.inner);
        let token = token.to_string();
        let etag = etag.map(|s| s.to_string());

        let (status, body, etag_header) = tokio::task::spawn_blocking(move || {
            let mut builder = Request::builder()
                .method("GET")
                .uri(&url)
                .header("Accept", "application/json");
            if !token.is_empty() {
                builder = builder.header("X-BastionVault-Token", &token);
            }
            for (k, v) in &inner.headers {
                builder = builder.header(k, v);
            }
            if let Some(tag) = &etag {
                builder = builder.header("If-None-Match", format!("\"{tag}\""));
            }
            let req = builder.body(()).map_err(ClientError::from)?;
            let mut resp = inner.agent.run(req).map_err(ClientError::from)?;
            let status = resp.status().as_u16();
            let etag_hdr = resp
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_string());
            let bytes = resp.body_mut().read_to_vec().map_err(ClientError::from)?;
            Ok::<_, ClientError>((status, bytes, etag_hdr))
        })
        .await
        .map_err(|e| ClientError::backend(format!("join: {e}")))??;

        if status == 304 {
            return Ok(crate::backend::SurfaceFetch::NotModified);
        }
        if !(200..300).contains(&status) {
            return Err(ClientError::server(status, format!("HTTP {status}")));
        }
        // Server wraps the bundle in `{"data": ActiveSurfaceBundle}`
        // to keep the response shape consistent with `response_json_ok`.
        let v: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).map_err(ClientError::from)?
        };
        let mut bundle: bv_plugin_surface::ActiveSurfaceBundle = match v {
            Value::Object(mut o) => match o.remove("data") {
                Some(d) => serde_json::from_value(d).map_err(ClientError::from)?,
                None => serde_json::from_value(Value::Object(o)).map_err(ClientError::from)?,
            },
            other => serde_json::from_value(other).map_err(ClientError::from)?,
        };
        // Prefer the server-supplied ETag header over the bundle's
        // self-computed one — they should match, but the header is
        // the wire-of-truth for cache-key purposes.
        if let Some(h) = etag_header {
            if !h.is_empty() {
                bundle.etag = h;
            }
        }
        Ok(crate::backend::SurfaceFetch::Bundle(bundle))
    }

    async fn do_fetch_asset(
        &self,
        plugin: &str,
        version: &str,
        sha256: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ClientError::backend(format!(
                "fetch_asset: sha256 `{sha256}` is not 64 hex chars"
            )));
        }
        let url = self.build_url(&format!(
            "sys/plugins/{plugin}/versions/{version}/asset/{sha256}"
        ));
        let inner = Arc::clone(&self.inner);
        let token = token.to_string();
        let sha = sha256.to_string();

        let (status, body) = tokio::task::spawn_blocking(move || {
            let mut builder = Request::builder()
                .method("GET")
                .uri(&url)
                .header("Accept", "application/octet-stream");
            if !token.is_empty() {
                builder = builder.header("X-BastionVault-Token", &token);
            }
            for (k, v) in &inner.headers {
                builder = builder.header(k, v);
            }
            let req = builder.body(()).map_err(ClientError::from)?;
            let mut resp = inner.agent.run(req).map_err(ClientError::from)?;
            let status = resp.status().as_u16();
            let bytes = resp.body_mut().read_to_vec().map_err(ClientError::from)?;
            Ok::<_, ClientError>((status, bytes))
        })
        .await
        .map_err(|e| ClientError::backend(format!("join: {e}")))??;

        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(ClientError::server(status, format!("HTTP {status}")));
        }
        // Re-verify the hash before handing bytes back. The server
        // already does this, but a defence-in-depth check here
        // catches MITM / proxy corruption that survives TLS (e.g. a
        // logging proxy that incorrectly rewrites bodies).
        let computed = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(&body);
            hex::encode(digest)
        };
        if computed != sha {
            return Err(ClientError::backend(format!(
                "fetch_asset: server returned bytes hashing to `{computed}` for asset `{sha}`"
            )));
        }
        Ok(Some(body))
    }
}
