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
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use bastion_vault::{
        kernel_api::VaultCtx,
        modules::{auth::AuthModule, namespace::token_binding, policy::PolicyModule},
        mount::MountsRouter,
        plugins::PluginCatalog,
        BastionVault,
    };
    use bv_client::{Backend, ClientError, JsonResponse, Operation, SurfaceFetch};
    use bv_plugin_surface::ActiveSurfaceBundle;
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

            let resp = core.handle_request(&mut req).await.map_err(|e| ClientError::backend(e.to_string()))?;

            Ok(resp.map(logical_response_to_json))
        }

        async fn surface_mounts(&self, namespace: Option<&str>) -> Result<HashMap<String, String>, ClientError> {
            let core = self.vault.core.load_full();
            let namespace = namespace.map(str::trim).filter(|value| !value.is_empty());
            let router = if let Some(namespace) = namespace {
                let registry = core.namespaces().ok_or_else(|| {
                    ClientError::backend(format!("namespace support is unavailable; cannot resolve {namespace:?}"))
                })?;
                let resolved = registry
                    .resolve(namespace)
                    .await
                    .map_err(|error| ClientError::backend(error.to_string()))?
                    .ok_or_else(|| ClientError::backend(format!("no such namespace: {namespace:?}")))?;
                registry
                    .ensure_router(&resolved.uuid, &resolved.path)
                    .await
                    .map_err(|error| ClientError::backend(error.to_string()))?
            } else {
                core.mounts_router()
            };
            plugin_surface_mounts(&router).map_err(ClientError::backend)
        }

        async fn authorize_surface_read(&self, token: &str, namespace: Option<&str>) -> Result<(), ClientError> {
            const POLICY_PATH: &str = "sys/plugins/active-surfaces";

            let core = self.vault.core.load_full();
            let auth_module = core
                .module_manager
                .get_module::<AuthModule>("auth")
                .ok_or_else(|| ClientError::backend("auth module unavailable"))?;
            let token_store =
                auth_module.token_store.load_full().ok_or_else(|| ClientError::backend("token store unavailable"))?;
            // Tauri IPC has no client socket address. Passing the empty string
            // intentionally refuses CIDR-bound tokens rather than inventing a
            // loopback address, matching the other embedded privileged paths.
            let auth = token_store
                .check_token(POLICY_PATH, token, "", false)
                .await
                .map_err(|error| ClientError::backend(error.to_string()))?
                .ok_or_else(|| ClientError::backend("invalid or expired token"))?;
            let namespace = namespace.map(str::trim).filter(|value| !value.is_empty()).unwrap_or("");
            if !token_binding::token_operable_resolved(core.as_ref(), &auth, namespace).await {
                return Err(ClientError::backend("permission denied for active namespace"));
            }
            let policy_module = core
                .module_manager
                .get_module::<PolicyModule>("policy")
                .ok_or_else(|| ClientError::backend("policy module unavailable"))?;
            let policy_store = policy_module.policy_store.load_full();
            if !policy_store
                .can_operate(
                    &auth,
                    POLICY_PATH,
                    bastion_vault::logical::Operation::Read,
                    (!namespace.is_empty()).then_some(namespace),
                )
                .await
            {
                return Err(ClientError::backend(
                    "permission denied: caller lacks `read` on sys/plugins/active-surfaces",
                ));
            }
            Ok(())
        }

        async fn surface_bundle_authorized(&self, namespace: Option<&str>) -> Result<ActiveSurfaceBundle, ClientError> {
            let mounts = self.surface_mounts(namespace).await?;
            let core = self.vault.core.load_full();
            PluginCatalog::new()
                .aggregated_active_surfaces(core.barrier.as_storage(), |plugin| mounts.get(plugin).cloned())
                .await
                .map_err(|error| ClientError::backend(error.to_string()))
        }

        async fn fetch_surfaces(
            &self,
            token: &str,
            etag: Option<&str>,
            namespace: Option<&str>,
        ) -> Result<SurfaceFetch, ClientError> {
            self.authorize_surface_read(token, namespace).await?;
            let bundle = self.surface_bundle_authorized(namespace).await?;
            if etag == Some(bundle.etag.as_str()) {
                Ok(SurfaceFetch::NotModified)
            } else {
                Ok(SurfaceFetch::Bundle(bundle))
            }
        }

        async fn watch_surfaces(
            &self,
            token: &str,
            etag: Option<&str>,
            namespace: Option<&str>,
        ) -> Result<SurfaceFetch, ClientError> {
            // One authorization per watch request, before the bounded polling
            // loop, matching the remote HTTP handler's witness lifetime.
            self.authorize_surface_read(token, namespace).await?;
            let bundle = self.surface_bundle_authorized(namespace).await?;
            if etag != Some(bundle.etag.as_str()) {
                return Ok(SurfaceFetch::Bundle(bundle));
            }

            // Embedded mode has no HTTP long-poll handler to block this call,
            // so mirror the server's bounded polling semantics here. Returning
            // NotModified immediately would make the frontend watcher spin.
            let started = Instant::now();
            let max_wait = Duration::from_secs(25);
            let poll_interval = Duration::from_secs(2);
            while started.elapsed() < max_wait {
                tokio::time::sleep(poll_interval).await;
                let next = self.surface_bundle_authorized(namespace).await?;
                if etag != Some(next.etag.as_str()) {
                    return Ok(SurfaceFetch::Bundle(next));
                }
            }
            Ok(SurfaceFetch::NotModified)
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

        async fn active_surfaces(&self, token: &str, etag: Option<&str>) -> Result<SurfaceFetch, ClientError> {
            self.fetch_surfaces(token, etag, None).await
        }

        async fn active_surfaces_with_namespace(
            &self,
            token: &str,
            etag: Option<&str>,
            namespace: Option<&str>,
        ) -> Result<SurfaceFetch, ClientError> {
            self.fetch_surfaces(token, etag, namespace).await
        }

        async fn watch_active_surfaces(&self, token: &str, etag: Option<&str>) -> Result<SurfaceFetch, ClientError> {
            self.watch_surfaces(token, etag, None).await
        }

        async fn watch_active_surfaces_with_namespace(
            &self,
            token: &str,
            etag: Option<&str>,
            namespace: Option<&str>,
        ) -> Result<SurfaceFetch, ClientError> {
            self.watch_surfaces(token, etag, namespace).await
        }
    }

    fn plugin_surface_mounts(router: &MountsRouter) -> Result<HashMap<String, String>, String> {
        let entries = router.mounts.entries.read().map_err(|error| error.to_string())?;
        let mut mounts = HashMap::new();
        let mut ambiguous = HashSet::new();
        for entry in entries.values() {
            let entry = entry.read().map_err(|error| error.to_string())?;
            let Some(plugin) = entry.logical_type.strip_prefix("plugin:") else {
                continue;
            };
            if ambiguous.contains(plugin) {
                continue;
            }
            if mounts.insert(plugin.to_string(), entry.path.clone()).is_some() {
                mounts.remove(plugin);
                ambiguous.insert(plugin.to_string());
            }
        }
        Ok(mounts)
    }

    /// Map the server's full `logical::Response` to the JSON-only
    /// `JsonResponse` shape the trait speaks. Mirrors what the HTTP
    /// handler at `src/http/logical.rs::response_logical` writes onto
    /// the wire so the embedded path is observably equivalent.
    fn logical_response_to_json(resp: bastion_vault::logical::Response) -> JsonResponse {
        let mut out = JsonResponse { data: resp.data, ..Default::default() };
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

    #[cfg(test)]
    mod tests {
        use std::str::FromStr;
        use std::time::Duration;

        use bastion_vault::{
            core::SealConfig,
            modules::{
                auth::{token_store::TokenEntry, AuthModule},
                policy::{Policy, PolicyModule},
            },
            mount::MountEntry,
            plugins::{
                manifest::{Capabilities, SurfaceRef},
                verifier::write_accept_unsigned,
                PluginCatalog, PluginManifest, RuntimeKind,
            },
            test_utils::new_test_bastion_vault,
        };
        use bv_client::SurfaceFetch;
        use sha2::{Digest, Sha256};

        use super::*;

        fn sha256_hex(bytes: &[u8]) -> String {
            Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
        }

        async fn mounted_surface_backend() -> (EmbeddedBackend, String, String) {
            let vault = new_test_bastion_vault("embedded_surface_mount");
            let initialized = vault.init(&SealConfig { secret_shares: 1, secret_threshold: 1 }).await.unwrap();
            let shares = [initialized.secret_shares[0].as_slice()];
            assert!(vault.unseal(&shares).await.unwrap());
            let core = vault.core.load_full();
            let token = initialized.root_token.clone();
            let binary = wat::parse_str("(module (memory (export \"memory\") 1))").unwrap();
            let surface = serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "title": "Self accounts",
                "menus": [{
                    "id": "self-accounts.main",
                    "label": "My accounts",
                    "section": "secrets",
                    "route": "/plugin/self-accounts/accounts"
                }],
                "pages": [{
                    "route": "/plugin/self-accounts/accounts",
                    "title": "My accounts",
                    "components": [{
                        "kind": "table",
                        "id": "self-accounts.list",
                        "binding": { "op": "list", "path": "{mount}/accounts" },
                        "columns": [{ "field": "name", "label": "Name" }]
                    }]
                }]
            }))
            .unwrap();
            let manifest = PluginManifest {
                name: "self-accounts".into(),
                version: "0.1.1".into(),
                plugin_type: "secret-engine".into(),
                runtime: RuntimeKind::Wasm,
                abi_version: "1.0".into(),
                sha256: sha256_hex(&binary),
                size: binary.len() as u64,
                capabilities: Capabilities::default(),
                description: String::new(),
                config_schema: vec![],
                signature: String::new(),
                signing_key: String::new(),
                surface: Some(SurfaceRef {
                    schema_version: 1,
                    sha256: sha256_hex(&surface),
                    size: surface.len() as u64,
                }),
                client_assets: vec![],
            };
            write_accept_unsigned(core.barrier.as_storage(), true).await.unwrap();
            let catalog = PluginCatalog::new();
            catalog.put(core.barrier.as_storage(), &manifest, &binary).await.unwrap();
            catalog
                .put_surface(
                    core.barrier.as_storage(),
                    "self-accounts",
                    "0.1.1",
                    &surface,
                    &manifest.surface.as_ref().unwrap().sha256,
                )
                .await
                .unwrap();

            let backend = EmbeddedBackend::new(Arc::new(vault));
            let before_mount = match backend.active_surfaces_with_namespace(&token, None, None).await.unwrap() {
                SurfaceFetch::Bundle(bundle) => bundle,
                SurfaceFetch::NotModified => panic!("cold embedded fetch returned not-modified"),
            };
            assert_eq!(before_mount.entries.len(), 1);
            assert_eq!(before_mount.entries[0].mount, "");

            core.mount(&MountEntry {
                path: "self-accounts/".into(),
                logical_type: "plugin:self-accounts".into(),
                ..Default::default()
            })
            .await
            .unwrap();
            (backend, token, before_mount.etag)
        }

        #[tokio::test]
        async fn embedded_surface_watch_observes_a_new_plugin_mount() {
            let (backend, token, unmounted_etag) = mounted_surface_backend().await;

            let mounted = match backend
                .watch_active_surfaces_with_namespace(&token, Some(&unmounted_etag), None)
                .await
                .unwrap()
            {
                SurfaceFetch::Bundle(bundle) => bundle,
                SurfaceFetch::NotModified => panic!("mount change was hidden by the embedded surface watcher"),
            };
            assert_eq!(mounted.entries[0].mount, "self-accounts/");
            assert_ne!(mounted.etag, unmounted_etag);

            let unchanged = tokio::time::timeout(
                Duration::from_millis(20),
                backend.watch_active_surfaces_with_namespace(&token, Some(&mounted.etag), None),
            )
            .await;
            assert!(unchanged.is_err(), "unchanged embedded watches must not return immediately and busy-loop the GUI");
        }

        #[tokio::test]
        async fn embedded_surface_discovery_requires_an_authorized_token_and_namespace() {
            let (backend, root_token, _) = mounted_surface_backend().await;

            backend
                .active_surfaces_with_namespace(&root_token, None, None)
                .await
                .expect("the root token can discover root surfaces");
            backend
                .active_surfaces_with_namespace("", None, None)
                .await
                .expect_err("an empty token must not disclose the plugin catalog or mounts");

            let core = backend.vault.core.load_full();
            let policy_module = core.module_manager.get_module::<PolicyModule>("policy").unwrap();
            let policy_store = policy_module.policy_store.load_full();
            let mut policy =
                Policy::from_str(r#"path "sys/plugins/active-surfaces" { capabilities = ["read"] }"#).unwrap();
            policy.name = "surface-reader".into();
            policy_store.set_policy(policy).await.unwrap();
            let auth_module = core.module_manager.get_module::<AuthModule>("auth").unwrap();
            let token_store = auth_module.token_store.load_full().unwrap();
            let mut token = TokenEntry {
                policies: vec!["surface-reader".into()],
                display_name: "surface-reader".into(),
                ..Default::default()
            };
            token_store.create(&mut token).await.unwrap();

            backend
                .active_surfaces_with_namespace(&token.id, None, None)
                .await
                .expect("the scoped policy permits root surface discovery");
            backend
                .active_surfaces_with_namespace(&token.id, None, Some("tenant-a"))
                .await
                .expect_err("a root-bound token without child visibility must not inspect a child namespace");
        }
    }
}

#[cfg(feature = "embedded_vault")]
pub use embedded::EmbeddedBackend;
