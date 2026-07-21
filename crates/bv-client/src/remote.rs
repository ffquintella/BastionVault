//! [`RemoteBackend`] — talks to a BastionVault HTTP server.
//!
//! Ported from `bastion_vault::api::client::Client` minus the chunks
//! the GUI never uses (the typed `sys` / `auth` / `secret` helpers).
//! The single dispatch method is [`Backend::handle`], which maps an
//! [`Operation`] to a HTTP method and parses the response body into
//! a [`JsonResponse`] for the GUI's command layer.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use http::Request;
use serde_json::{Map, Value};
use ureq::Agent;

use crate::{
    backend::Backend,
    discovery::{self, DiscoveryConfig, SrvCandidate, SrvLookup, SystemResolver},
    error::{classify_node_failure, ClientError},
    health::{self, HealthConfig, Selected},
    tls::ClientTlsConfig,
    types::{JsonResponse, Operation},
};

#[cfg(test)]
mod builder_tests {
    use super::*;
    use crate::discovery::{SrvRecord};
    use async_trait::async_trait;

    struct FixedResolver(Vec<SrvRecord>);

    #[async_trait]
    impl SrvLookup for FixedResolver {
        async fn lookup_srv(&self, _label: &str) -> Result<Vec<SrvRecord>, ClientError> {
            Ok(self.0.clone())
        }
    }

    /// Cluster name → SRV → probes. We aim every candidate at a
    /// guaranteed-closed port (TCP/1) so the probes uniformly fail
    /// fast, producing `NoHealthyNode`. The point of the test is
    /// that the *plumbing* works: discovery runs, probes run, pick
    /// runs, and the right error variant comes out.
    #[tokio::test]
    async fn build_with_discovery_emits_no_healthy_node_when_all_probes_fail() {
        let resolver = FixedResolver(vec![SrvRecord {
            target: "127.0.0.1.".into(),
            port: 1,
            priority: 10,
            weight: 50,
        }]);
        let res = RemoteBackend::builder()
            .with_address("test.invalid")
            .with_health_config(HealthConfig {
                probe_timeout: std::time::Duration::from_millis(200),
                parallelism: 2,
                ..Default::default()
            })
            .build_with_discovery_using(&resolver)
            .await;
        match res {
            Err(ClientError::NoHealthyNode { cluster, .. }) => {
                assert_eq!(cluster, "test.invalid");
            }
            Err(other) => panic!("expected NoHealthyNode, got error: {other}"),
            Ok(_) => panic!("expected NoHealthyNode, got Ok"),
        }
    }

    /// `with_cluster_discovery(false)` opts out — we should get a
    /// fully-formed backend pointed at the literal input without
    /// any SRV traffic or probe overhead.
    #[tokio::test]
    async fn opt_out_path_skips_discovery_entirely() {
        struct PanicResolver;
        #[async_trait]
        impl SrvLookup for PanicResolver {
            async fn lookup_srv(&self, _label: &str) -> Result<Vec<SrvRecord>, ClientError> {
                panic!("resolver must not be called when cluster_discovery=false");
            }
        }
        let be = RemoteBackend::builder()
            .with_address("https://vault.example:9999")
            .with_cluster_discovery(false)
            .build_with_discovery_using(&PanicResolver)
            .await
            .expect("opt-out path should succeed without probing");
        assert_eq!(be.address().as_str(), "https://vault.example:9999");
        assert!(be.selected().is_none());
    }
}

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

/// The node the backend is *currently* dialing. Swappable at runtime
/// so the read-failover path (see [`RemoteInner::failover`]) can move a
/// session off a node that just went unavailable without forcing the
/// operator to reconnect. Guarded by an [`RwLock`]: request dispatch
/// takes a read lock to snapshot the address; failover takes a write
/// lock to swap it.
#[derive(Clone)]
struct ActiveNode {
    address: String,
    /// Discovery/selection metadata for the active node, if known.
    /// Carries enough info for log/UI surfacing of "Connected to
    /// <cluster> via <node>, leader, 12 ms". `None` for literal-URL
    /// constructions.
    selected: Option<Selected>,
}

/// Cached cluster topology that powers in-session read failover. Only
/// present when the backend was built with a multi-node candidate set
/// (`>= 2` candidates). Carries everything needed to re-probe and
/// re-pick a node *without* re-resolving SRV — the candidate list is
/// the part that is stable across a leader election; node health and
/// leadership are what we re-measure on failure.
struct Failover {
    /// Every node the cluster resolved to at connect time.
    candidates: Vec<SrvCandidate>,
    /// TLS material reused for the re-probe (same as the request path).
    tls: Option<ClientTlsConfig>,
    /// Probe timeouts/parallelism reused for the re-probe.
    health_cfg: HealthConfig,
    /// Serializes concurrent re-probes so a burst of failing requests
    /// triggers a single re-pick rather than a thundering herd. After
    /// acquiring it a caller re-checks the active address: if another
    /// task already moved us off the dead node, it reuses that pick.
    in_progress: tokio::sync::Mutex<()>,
}

struct RemoteInner {
    /// The node currently being dialed. See [`ActiveNode`].
    active: RwLock<ActiveNode>,
    headers: HashMap<String, String>,
    api_version: u8,
    agent: Agent,
    /// The original input the operator typed (cluster name or
    /// literal URL). Surfaced as `host` in `ClientError::NodeUnavailable`.
    input_label: String,
    /// Cached topology for in-session read failover. `None` disables
    /// failover (single-node / literal-URL backends — nothing to fail
    /// over to).
    failover: Option<Failover>,
}

#[derive(Clone, Default)]
pub struct RemoteBackendBuilder {
    address: Option<String>,
    headers: HashMap<String, String>,
    api_version: Option<u8>,
    tls: Option<ClientTlsConfig>,
    timeout_connect: Option<Duration>,
    timeout_global: Option<Duration>,
    /// `true` (default) enables SRV-based cluster discovery in
    /// `build_with_discovery`. When `false` (or when `build()` is
    /// used) discovery is bypassed and the address is treated as a
    /// literal URL.
    cluster_discovery: Option<bool>,
    discovery_config: Option<DiscoveryConfig>,
    health_config: Option<HealthConfig>,
    /// Cluster topology to enable in-session read failover. Set
    /// explicitly via [`Self::with_failover_candidates`] (the connect
    /// path, which discovers once and pins the node) or populated
    /// automatically by [`Self::build_with_discovery_using`].
    failover_candidates: Option<Vec<SrvCandidate>>,
    /// When `Some(true)`, honour the system proxy — the OS proxy (macOS
    /// System Settings, the Windows registry, GNOME) resolved via
    /// [`crate::sysproxy`], or the `ALL_PROXY` / `HTTPS_PROXY` /
    /// `HTTP_PROXY` environment variables, which take precedence. When
    /// `Some(false)` / `None` (the default) the proxy is explicitly
    /// cleared in `build()` so a stray proxy never silently reroutes
    /// traffic.
    use_system_proxy: Option<bool>,
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

    pub fn with_cluster_discovery(mut self, enabled: bool) -> Self {
        self.cluster_discovery = Some(enabled);
        self
    }

    pub fn with_discovery_config(mut self, cfg: DiscoveryConfig) -> Self {
        self.discovery_config = Some(cfg);
        self
    }

    pub fn with_health_config(mut self, cfg: HealthConfig) -> Self {
        self.health_config = Some(cfg);
        self
    }

    /// Supply the full cluster candidate set so the built backend can
    /// fail read-only requests over to another node in-session (see
    /// [`RemoteBackend`] docs). Used by the connect path, which runs
    /// discovery once to pick the node and then builds the production
    /// backend with discovery disabled (pinned URL) — passing the
    /// candidates here is what lets that pinned backend still recover
    /// from a node loss without a manual reconnect. Failover only
    /// engages when two or more candidates are supplied.
    pub fn with_failover_candidates(mut self, candidates: Vec<SrvCandidate>) -> Self {
        self.failover_candidates = Some(candidates);
        self
    }

    /// Enable or disable honouring the system proxy for the built backend.
    /// Defaults to disabled — see [`RemoteBackendBuilder::use_system_proxy`].
    pub fn with_system_proxy(mut self, enabled: bool) -> Self {
        self.use_system_proxy = Some(enabled);
        self
    }

    /// Run SRV discovery + `/sys/health` probing against the
    /// configured address and return a `RemoteBackend` pinned to
    /// the chosen node. The chosen node is frozen for the lifetime
    /// of the returned backend; transport failures on it surface as
    /// [`ClientError::NodeUnavailable`] and the caller is expected
    /// to call `build_with_discovery` again to pick a new one. This
    /// is the "Sticky session with failover-on-next-open" contract
    /// from the feature spec.
    ///
    /// When `with_cluster_discovery(false)` was set, or when the
    /// configured address is URL-shaped (`https://host:port`), this
    /// short-circuits and behaves exactly like [`Self::build`].
    pub async fn build_with_discovery(self) -> Result<RemoteBackend, ClientError> {
        let resolver = SystemResolver::new();
        self.build_with_discovery_using(&resolver).await
    }

    /// Variant of [`Self::build_with_discovery`] that takes an
    /// explicit resolver. Used by tests to inject a fake.
    pub async fn build_with_discovery_using(
        self,
        resolver: &dyn SrvLookup,
    ) -> Result<RemoteBackend, ClientError> {
        let input = self
            .address
            .clone()
            .unwrap_or_else(|| "https://127.0.0.1:8200".to_string());
        let discovery_enabled = self.cluster_discovery.unwrap_or(true);
        let discovery_cfg = self.discovery_config.clone().unwrap_or_default();
        let health_cfg = self.health_config.clone().unwrap_or_default();
        let tls_for_probe = self.tls.clone();

        if !discovery_enabled {
            // Operator opt-out: act exactly like the synchronous
            // builder, no SRV traffic, no health probes.
            let mut be = self.with_address(input.clone()).build();
            // Even in opt-out mode we record the input label for
            // NodeUnavailable surfacing.
            Arc::get_mut(&mut be.inner)
                .expect("freshly built RemoteBackend has unique Arc")
                .input_label = input;
            return Ok(be);
        }

        let resolved = discovery::resolve(&input, &discovery_cfg, resolver).await?;
        let candidates = resolved.into_candidates();
        if candidates.is_empty() {
            return Err(ClientError::no_healthy_node(input, "no candidates resolved"));
        }

        let probes = health::probe_all(&candidates, &health_cfg, tls_for_probe.as_ref()).await;
        let selected = health::pick(&probes).ok_or_else(|| {
            // Collect a compact diagnostic of what each probe found
            // so the operator's error toast isn't just "none."
            let reasons: Vec<String> = probes
                .iter()
                .map(|p| format!("{}={:?}", p.candidate.target, p.state))
                .collect();
            ClientError::no_healthy_node(&input, reasons.join(", "))
        })?;

        let address = selected.candidate.url();
        // Hand the full candidate set to the backend so it can fail
        // read-only requests over to another node in-session.
        let mut be = self
            .with_failover_candidates(candidates)
            .with_address(address)
            .build();
        // Stash the discovery/selection metadata after the fact
        // (the synchronous build path doesn't know about it).
        let inner = Arc::get_mut(&mut be.inner)
            .expect("freshly built RemoteBackend has unique Arc");
        inner
            .active
            .get_mut()
            .expect("freshly built RemoteBackend has un-poisoned lock")
            .selected = Some(selected);
        inner.input_label = input;
        Ok(be)
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

        // ureq picks up the system proxy from the environment (and the
        // Windows registry) by default; clear it unless the caller opted
        // in so vault traffic isn't silently rerouted through a stray
        // `HTTP(S)_PROXY`. When opted in, also resolve the OS-level proxy
        // ureq can't read on its own (macOS System Settings, GNOME).
        if !self.use_system_proxy.unwrap_or(false) {
            config_builder = config_builder.proxy(None);
        } else if let Some(uri) = crate::sysproxy::system_proxy_uri() {
            match ureq::Proxy::new(&uri) {
                Ok(p) => config_builder = config_builder.proxy(Some(p)),
                Err(e) => log::warn!("ignoring unparseable system proxy '{uri}': {e}"),
            }
        }

        let agent = config_builder.build().new_agent();

        // Strip trailing slashes so `build_url` never emits a double
        // slash when joining a leading-slash path (`https://host:port//v1/...`),
        // which mirrors the legacy `Client::with_addr` normalization and
        // keeps both clients dialing the same well-formed URLs.
        let address = self
            .address
            .map(|a| a.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://127.0.0.1:8200".to_string());
        let input_label = address.clone();
        // Enable in-session read failover only when there is somewhere
        // to fail over to (>= 2 candidates). Single-node / literal-URL
        // backends leave this `None`.
        let failover = self.failover_candidates.and_then(|candidates| {
            if candidates.len() >= 2 {
                Some(Failover {
                    candidates,
                    tls: self.tls.clone(),
                    health_cfg: self.health_config.clone().unwrap_or_default(),
                    in_progress: tokio::sync::Mutex::new(()),
                })
            } else {
                None
            }
        });
        RemoteBackend {
            inner: Arc::new(RemoteInner {
                active: RwLock::new(ActiveNode {
                    address,
                    selected: None,
                }),
                headers: self.headers,
                api_version: self.api_version.unwrap_or(1),
                agent,
                input_label,
                failover,
            }),
        }
    }
}

impl RemoteBackend {
    pub fn builder() -> RemoteBackendBuilder {
        RemoteBackendBuilder::new()
    }

    /// The URL of the node currently being dialed. Returns an owned
    /// `String` (rather than a borrow) because the active node can be
    /// swapped at runtime by the read-failover path.
    pub fn address(&self) -> String {
        self.inner
            .active
            .read()
            .expect("active-node lock poisoned")
            .address
            .clone()
    }

    /// The discovery result the *currently active* node was selected
    /// from, if any. `None` for backends built via
    /// [`RemoteBackendBuilder::build`] (the legacy literal-URL path);
    /// `Some` for backends built via
    /// [`RemoteBackendBuilder::build_with_discovery`]. Carries the
    /// chosen node + state + RTT for log/UI surfacing. Tracks failover:
    /// after a re-pick it reflects the node now in use.
    pub fn selected(&self) -> Option<Selected> {
        self.inner
            .active
            .read()
            .expect("active-node lock poisoned")
            .selected
            .clone()
    }

    /// Original input the operator typed (cluster name or literal
    /// URL). Used as the `host` field in `NodeUnavailable` so the
    /// error surfaces the operator-facing label rather than the
    /// internal IP we resolved to.
    pub fn input_label(&self) -> &str {
        &self.inner.input_label
    }

    fn api_prefix(&self) -> &'static str {
        match self.inner.api_version {
            2 => "/v2",
            _ => "/v1",
        }
    }

    /// Build a request URL against the node currently being dialed.
    fn build_url(&self, path: &str) -> String {
        self.build_url_with(&self.address(), path)
    }

    /// Build a request URL against an explicit node address. Used by
    /// the failover retry so it dials the freshly-picked node rather
    /// than re-reading the active address (which a racing request may
    /// already be swapping).
    fn build_url_with(&self, address: &str, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", address, path)
        } else {
            format!(
                "{}/{}/{}",
                address,
                self.api_prefix().trim_start_matches('/'),
                path
            )
        }
    }
}

impl RemoteBackend {
    /// Issue one request attempt against `address`. Transport-level
    /// failures and sealed-5xx responses are classified into
    /// [`ClientError::NodeUnavailable`] (see
    /// [`crate::error::classify_node_failure`]); everything else passes
    /// through. No retry / failover lives here — see [`Self::dispatch`].
    async fn attempt(
        &self,
        address: &str,
        operation: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
        token: &str,
        namespace: Option<&str>,
    ) -> Result<Option<JsonResponse>, ClientError> {
        let namespace = namespace
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let method = match operation {
            Operation::Read => "GET",
            Operation::Write => "POST",
            Operation::Delete => "DELETE",
            Operation::List => "LIST",
        };

        let url = self.build_url_with(address, path);
        let inner = Arc::clone(&self.inner);
        let token = token.to_string();
        let path_owned = path.to_string();

        // ureq is sync. Park the call on a blocking thread so we
        // don't hold the executor while the network round-trips.
        let host_for_err = inner.input_label.clone();
        let response_result = tokio::task::spawn_blocking(move || {
            let mut builder = Request::builder()
                .method(method)
                .uri(&url)
                .header("Accept", "application/json");

            if !path_owned.ends_with("/login") && !token.is_empty() {
                builder = builder.header("X-BastionVault-Token", &token);
            }
            if let Some(ns) = &namespace {
                builder = builder.header("X-BastionVault-Namespace", ns);
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
        .map_err(|e| ClientError::backend(format!("join: {e}")))?
        // Translate transport-level / sealed-shaped failures into
        // `NodeUnavailable` so the caller's sticky-session recovery
        // path can light up a "reconnect" UX instead of a generic
        // error toast. Non-node errors pass through unchanged.
        .map_err(|e| classify_node_failure(&host_for_err, e))?;

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
            Err(classify_node_failure(
                &host_for_err,
                ClientError::server(status, message),
            ))
        }
    }

    /// Dispatch a request with single-shot read failover.
    ///
    /// For idempotent operations ([`Operation::Read`] /
    /// [`Operation::List`]) on a cluster-aware backend, a
    /// [`ClientError::NodeUnavailable`] outcome triggers one re-probe +
    /// re-pick of a different healthy node followed by exactly one
    /// retry. This narrows the deliberate "sticky session" contract:
    ///
    /// * Writes / deletes are **never** auto-retried — a dropped
    ///   connection leaves the commit state ambiguous, so a silent
    ///   retry could double-apply. They keep the explicit-reconnect
    ///   contract and surface `NodeUnavailable` to the caller.
    /// * Single-node / literal-URL backends (`failover.is_none()`) have
    ///   nowhere to move, so they behave exactly as before.
    /// * Node-local streaming surfaces (active-surface watch, asset
    ///   fetch) are dispatched on their own paths and are intentionally
    ///   not covered here.
    async fn dispatch(
        &self,
        operation: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
        token: &str,
        namespace: Option<&str>,
    ) -> Result<Option<JsonResponse>, ClientError> {
        let address = self.address();

        // `body` is consumed by `attempt`; clone for the first try so
        // the original survives for a potential retry. The clone is a
        // small JSON map — negligible next to a network round-trip.
        let first = self
            .attempt(&address, operation, path, body.clone(), token, namespace)
            .await;

        let node_failed = matches!(&first, Err(e) if e.is_node_unavailable());
        if !node_failed || !Self::is_idempotent(operation) || self.inner.failover.is_none() {
            return first;
        }

        match self.try_failover(&address).await {
            Some(new_address) => {
                log::warn!(
                    "bv-client: node `{address}` unavailable on {operation:?} `{path}`; \
                     failing over to `{new_address}` and retrying once"
                );
                self.attempt(&new_address, operation, path, body, token, namespace)
                    .await
            }
            // No distinct healthy node — surface the original failure
            // so the caller's reconnect UX still lights up.
            None => first,
        }
    }

    /// Only side-effect-free operations are safe to transparently
    /// retry on another node.
    fn is_idempotent(op: Operation) -> bool {
        matches!(op, Operation::Read | Operation::List)
    }

    /// Re-probe the cached candidate set and swap the active node to
    /// the best healthy one that is *not* `failed_address`. Returns the
    /// new node URL, or `None` when no distinct healthy node exists (the
    /// caller then surfaces the original error).
    ///
    /// Serialized via the failover mutex so a burst of failing requests
    /// re-picks once; a caller that finds the active node already moved
    /// off `failed_address` reuses that pick without re-probing.
    async fn try_failover(&self, failed_address: &str) -> Option<String> {
        let fo = self.inner.failover.as_ref()?;
        let _guard = fo.in_progress.lock().await;

        // A concurrent failover may have already moved us off the dead
        // node while we waited for the lock — reuse its pick.
        let current = self.address();
        if current != failed_address {
            return Some(current);
        }

        let probes = health::probe_all(&fo.candidates, &fo.health_cfg, fo.tls.as_ref()).await;
        let alternates: Vec<_> = probes
            .into_iter()
            .filter(|p| p.candidate.url() != failed_address)
            .collect();
        let selected = health::pick(&alternates)?;
        let new_address = selected.candidate.url();
        if new_address == failed_address {
            return None;
        }

        *self
            .inner
            .active
            .write()
            .expect("active-node lock poisoned") = ActiveNode {
            address: new_address.clone(),
            selected: Some(selected),
        };
        Some(new_address)
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

#[cfg(test)]
mod failover_tests {
    use super::*;
    use crate::health::NodeState;

    fn cand(target: &str) -> SrvCandidate {
        SrvCandidate {
            target: target.to_string(),
            port: 5200,
            scheme: "https".to_string(),
            priority: 10,
            weight: 50,
        }
    }

    #[test]
    fn only_reads_and_lists_are_idempotent() {
        assert!(RemoteBackend::is_idempotent(Operation::Read));
        assert!(RemoteBackend::is_idempotent(Operation::List));
        assert!(!RemoteBackend::is_idempotent(Operation::Write));
        assert!(!RemoteBackend::is_idempotent(Operation::Delete));
    }

    #[test]
    fn failover_enabled_only_with_two_or_more_candidates() {
        // Two candidates → failover armed.
        let be = RemoteBackend::builder()
            .with_address("https://a.example:5200")
            .with_failover_candidates(vec![cand("a.example"), cand("b.example")])
            .build();
        assert!(
            be.inner.failover.is_some(),
            "two candidates should arm failover"
        );

        // One candidate → nothing to fail over to.
        let be = RemoteBackend::builder()
            .with_address("https://a.example:5200")
            .with_failover_candidates(vec![cand("a.example")])
            .build();
        assert!(
            be.inner.failover.is_none(),
            "single candidate must not arm failover"
        );

        // No candidates supplied (literal-URL / discovery-off path).
        let be = RemoteBackend::builder()
            .with_address("https://a.example:5200")
            .build();
        assert!(be.inner.failover.is_none());
    }

    #[test]
    fn active_node_swap_is_observable() {
        // Simulate the swap a successful `try_failover` performs and
        // confirm the public accessors track the new node.
        let be = RemoteBackend::builder()
            .with_address("https://a.example:5200")
            .with_failover_candidates(vec![cand("a.example"), cand("b.example")])
            .build();
        assert_eq!(be.address().as_str(), "https://a.example:5200");
        assert!(be.selected().is_none());

        let new = Selected {
            candidate: cand("b.example"),
            state: NodeState::ActiveLeader,
            rtt_ms: 12,
            cluster_id: Some("cid".into()),
            version: None,
        };
        *be.inner.active.write().unwrap() = ActiveNode {
            address: "https://b.example:5200".to_string(),
            selected: Some(new),
        };

        assert_eq!(be.address().as_str(), "https://b.example:5200");
        let sel = be.selected().expect("selected should follow the swap");
        assert_eq!(sel.candidate.target, "b.example");
        assert_eq!(sel.state, NodeState::ActiveLeader);
        // Request URLs now target the failed-over node.
        assert_eq!(
            be.build_url("sys/internal/ui/mounts"),
            "https://b.example:5200/v1/sys/internal/ui/mounts"
        );
    }

    #[test]
    fn build_url_with_honors_leading_slash_and_api_prefix() {
        let be = RemoteBackend::builder()
            .with_address("https://a.example:5200")
            .with_api_version(2)
            .build();
        // Relative path picks up the versioned prefix.
        assert_eq!(
            be.build_url_with("https://node:5200", "sys/health"),
            "https://node:5200/v2/sys/health"
        );
        // Absolute (leading-slash) path is used verbatim.
        assert_eq!(
            be.build_url_with("https://node:5200", "/v1/sys/health"),
            "https://node:5200/v1/sys/health"
        );
    }
}
