//! Glue between the GUI's command layer and the `bv_client::Backend`
//! trait. Hosts the [`EmbeddedBackend`] adapter, plus helpers to
//! convert between server-side `bastion_vault::logical` types and the
//! JSON-only types the trait speaks.
//!
//! `EmbeddedBackend` is gated behind the `embedded_vault` Cargo
//! feature. When that feature is off, the GUI compiles without
//! `bastion_vault`, the embedded code path disappears entirely, and
//! the only thing the AppState can hold is a `RemoteBackend`.
//!
//! `RemoteBackend` itself lives in the `bv-client` crate and has no
//! `bastion_vault` dependency, so it's always available.

#[cfg(feature = "embedded_vault")]
mod embedded {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bastion_vault::BastionVault;
    use bv_client::{Backend, ClientError, JsonResponse, Operation};
    use serde_json::{Map, Value};

    /// Wraps an in-process `BastionVault` and exposes it through the
    /// `bv_client::Backend` trait. Construction is cheap — just an
    /// `Arc` clone — so the AppState can hand a fresh adapter out
    /// every time the embedded vault is (re)opened.
    pub struct EmbeddedBackend {
        vault: Arc<BastionVault>,
    }

    impl EmbeddedBackend {
        pub fn new(vault: Arc<BastionVault>) -> Self {
            Self { vault }
        }
    }

    impl EmbeddedBackend {
        async fn dispatch(
            &self,
            operation: Operation,
            path: &str,
            body: Option<Map<String, Value>>,
            token: &str,
            namespace: Option<&str>,
        ) -> Result<Option<JsonResponse>, ClientError> {
            use bastion_vault::logical::{split_path_query, Operation as ServerOp, Request};

            let core = self.vault.core.load();

            // The GUI glues an `?env=<name>` selector onto the path; the router
            // would otherwise absorb it into the secret name. Split it off and
            // seed `req.data` exactly like the HTTP entry boundary does, so the
            // ACL check and KV handler see `env` identically in both modes.
            let (clean_path, query_data) = split_path_query(path);

            let mut req = Request {
                operation: match operation {
                    Operation::Read => ServerOp::Read,
                    Operation::Write => ServerOp::Write,
                    Operation::Delete => ServerOp::Delete,
                    Operation::List => ServerOp::List,
                },
                path: clean_path,
                client_token: token.to_string(),
                body,
                data: query_data,
                ..Default::default()
            };
            // Multi-tenancy: carry the active namespace as the request header
            // the server resolver reads (case-insensitive). Root / empty omits.
            if let Some(ns) = namespace.map(str::trim).filter(|s| !s.is_empty()) {
                let mut h = std::collections::HashMap::new();
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
                req.headers = Some(h);
            }

            let resp = core
                .handle_request(&mut req)
                .await
                .map_err(|e| ClientError::backend(e.to_string()))?;

            Ok(resp.map(logical_response_to_json))
        }
    }

    #[async_trait]
    impl Backend for EmbeddedBackend {
        async fn handle(
            &self,
            operation: Operation,
            path: &str,
            body: Option<Map<String, Value>>,
            token: &str,
        ) -> Result<Option<JsonResponse>, ClientError> {
            self.dispatch(operation, path, body, token, None).await
        }

        async fn handle_with_namespace(
            &self,
            operation: Operation,
            path: &str,
            body: Option<Map<String, Value>>,
            token: &str,
            namespace: Option<&str>,
        ) -> Result<Option<JsonResponse>, ClientError> {
            self.dispatch(operation, path, body, token, namespace).await
        }
    }

    /// Map the server's full `logical::Response` to the JSON-only
    /// `JsonResponse` shape the trait speaks. Mirrors what the HTTP
    /// handler at `src/http/logical.rs::response_logical` writes onto
    /// the wire so the embedded path is observably equivalent.
    fn logical_response_to_json(resp: bastion_vault::logical::Response) -> JsonResponse {
        let mut out = JsonResponse {
            data: resp.data,
            ..Default::default()
        };
        if let Some(secret) = &resp.secret {
            out.lease_id = Some(secret.lease_id.clone());
            out.renewable = Some(secret.lease.renewable);
            out.lease_duration = Some(secret.lease.ttl.as_secs());
        }
        if let Some(auth) = resp.auth {
            // Serialize Auth as JSON so the GUI side never has to
            // know its concrete shape (and so we don't leak server
            // types through the trait).
            if let Ok(v) = serde_json::to_value(&auth) {
                out.auth = Some(v);
            }
        }
        out.warnings = resp.warnings;
        out.redirect = resp.redirect;
        out
    }
}

#[cfg(feature = "embedded_vault")]
pub use embedded::EmbeddedBackend;
