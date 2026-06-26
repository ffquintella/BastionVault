use std::{path::PathBuf, sync::Arc, time::Duration};

use bastion_vault::api::{client::TLSConfigBuilder, Client};
use bv_client::{
    discovery::{DiscoveryConfig, SrvCandidate},
    health::HealthConfig,
    tls::{ClientTlsConfig, TLSConfigBuilder as BvTLSConfigBuilder},
    RemoteBackend,
};
use serde::Serialize;
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::preferences::Preferences;
use crate::state::{AppState, RemoteProfile, SelectedNode, VaultMode};

#[tauri::command]
pub async fn get_mode(state: State<'_, AppState>) -> CmdResult<VaultMode> {
    Ok(state.mode.lock().await.clone())
}

#[tauri::command]
pub async fn set_mode(state: State<'_, AppState>, mode: VaultMode) -> CmdResult<()> {
    *state.mode.lock().await = mode;
    Ok(())
}

#[tauri::command]
pub async fn is_vault_initialized() -> CmdResult<bool> {
    crate::embedded::is_initialized()
}

/// Get the current remote profile (if in remote mode).
#[tauri::command]
pub async fn get_remote_profile(state: State<'_, AppState>) -> CmdResult<Option<RemoteProfile>> {
    Ok(state.remote_profile.lock().await.clone())
}

/// Connect to a remote BastionVault server.
///
/// When `profile.cluster_discovery` is `true` and the address isn't
/// already URL-shaped, this runs SRV-based cluster discovery
/// (`_bvault._tcp.<address>`) and probes each candidate's
/// `/v1/sys/health` to pick the best node. The chosen node is
/// frozen for the lifetime of this connection — if it fails mid
/// session, commands return `NodeUnavailable` and the operator is
/// expected to call `connect_remote` again to re-run discovery.
///
/// For literal URLs (`https://host:port`) or when discovery is
/// explicitly disabled, this short-circuits to the pre-discovery
/// behaviour and connects to the address as-is.
#[tauri::command]
pub async fn connect_remote(
    state: State<'_, AppState>,
    profile: RemoteProfile,
) -> CmdResult<()> {
    // Resolve the operator-typed address into a concrete URL the
    // legacy `Client` can dial. This is the only place discovery
    // runs — once we've picked a node, every legacy / bv-client
    // request goes through the same target.
    let tls_for_bv = build_bv_tls(&profile)?;
    let (effective_address, selected, failover_candidates, health_cfg) =
        resolve_remote_address(&profile, tls_for_bv.as_ref()).await?;

    // Legacy `Client`: point it at the chosen URL.
    let mut client_builder = Client::new().with_addr(&effective_address);
    if effective_address.starts_with("https://") {
        client_builder = client_builder.with_tls_config(build_legacy_tls(&profile)?);
    }
    let client = client_builder.build();

    // Test the connection by checking health.
    let health = client
        .sys()
        .health()
        .map_err(|e| CommandError::from(format!("Connection failed: {e}")))?;
    if health.response_status == 0 {
        return Err("Connection failed: no response from server".into());
    }

    // bv-client `RemoteBackend`: pin it to the SAME chosen URL with
    // discovery disabled. Re-running discovery here would either
    // duplicate the SRV traffic or risk picking a different node
    // than the legacy client, which would surface as confusing
    // mid-session inconsistencies.
    let mut bv_builder = RemoteBackend::builder()
        .with_address(&effective_address)
        .with_api_version(2)
        .with_cluster_discovery(false)
        .with_health_config(health_cfg);
    // Hand the discovered cluster topology to the pinned backend so it
    // can fail read-only requests over to another healthy node mid-
    // session (no-op for single-node / literal-URL profiles, where the
    // candidate set has fewer than two entries). The legacy `Client`
    // above stays pinned to the originally chosen node — only the
    // bv-client read path participates in failover, which keeps any
    // node-local state on the legacy client unambiguous.
    if !failover_candidates.is_empty() {
        bv_builder = bv_builder.with_failover_candidates(failover_candidates);
    }
    if let Some(tls) = tls_for_bv {
        bv_builder = bv_builder.with_tls_config(tls);
    }
    let remote_backend = bv_builder.build();

    *state.mode.lock().await = VaultMode::Remote;
    *state.remote_client.lock().await = Some(client);
    *state.remote_profile.lock().await = Some(profile);
    *state.selected_node.lock().await = selected;
    *state.backend.lock().await = Some(Arc::new(remote_backend));
    // Clear embedded vault if switching from embedded.
    *state.vault.lock().await = None;

    Ok(())
}

/// Run cluster discovery for `profile` and return everything the
/// connect path needs:
///
/// * the URL both the legacy `Client` and the bv-client
///   `RemoteBackend` should dial,
/// * a serialisable [`SelectedNode`] describing the pick (or `None`
///   when discovery short-circuited),
/// * the full candidate set, so the pinned production backend can fail
///   read-only requests over to another node without re-resolving SRV
///   (empty for the discovery-disabled / literal-URL paths), and
/// * the [`HealthConfig`] used for probing, reused for those failover
///   re-probes.
async fn resolve_remote_address(
    profile: &RemoteProfile,
    tls: Option<&ClientTlsConfig>,
) -> CmdResult<(String, Option<SelectedNode>, Vec<SrvCandidate>, HealthConfig)> {
    use bv_client::{
        discovery::{self, SystemResolver},
        health,
    };

    let mut health_cfg = HealthConfig::default();
    if let Some(ms) = profile.health_probe_timeout_ms {
        if ms > 0 {
            health_cfg.probe_timeout = Duration::from_millis(ms.into());
        }
    }

    // Two short-circuits: discovery disabled, or URL-shaped input.
    // The bv-client discovery layer already does the URL detection
    // for us — keep the check here at the connect command boundary
    // so the legacy `Client` skips its TLS branching predictably.
    // Neither path yields a candidate set, so failover stays off.
    if !profile.cluster_discovery || looks_like_url(&profile.address) {
        return Ok((profile.address.clone(), None, Vec::new(), health_cfg));
    }

    let mut discovery_cfg = DiscoveryConfig::default();
    if let Some(svc) = profile.discovery_srv_service.as_deref() {
        if !svc.is_empty() {
            discovery_cfg.srv_service = svc.to_string();
        }
    }

    // Drive bv-client's discovery → probe → pick pipeline directly so
    // we keep the resolved candidate list (a throwaway `RemoteBackend`
    // would discard it). The production backend is built later in
    // `connect_remote` with this address baked in and these candidates
    // wired in for failover.
    let resolver = SystemResolver::new();
    let resolved = discovery::resolve(&profile.address, &discovery_cfg, &resolver)
        .await
        .map_err(|e| CommandError::from(format!("Cluster discovery failed: {e}")))?;
    let candidates = resolved.into_candidates();
    if candidates.is_empty() {
        return Err(CommandError::from(format!(
            "Cluster discovery failed: no nodes resolved for `{}`",
            profile.address
        )));
    }

    let probes = health::probe_all(&candidates, &health_cfg, tls).await;
    let selected = health::pick(&probes).ok_or_else(|| {
        let reasons: Vec<String> = probes
            .iter()
            .map(|p| format!("{}={:?}", p.candidate.target, p.state))
            .collect();
        CommandError::from(format!(
            "Cluster discovery failed: no healthy node for `{}`: {}",
            profile.address,
            reasons.join(", ")
        ))
    })?;

    let address = selected.candidate.url();
    let selected_node = SelectedNode {
        cluster_label: profile.address.clone(),
        address: selected.candidate.url(),
        target: selected.candidate.target.clone(),
        port: selected.candidate.port,
        state: format!("{:?}", selected.state),
        rtt_ms: selected.rtt_ms,
        cluster_id: selected.cluster_id.clone(),
        version: selected.version.clone(),
    };
    Ok((address, Some(selected_node), candidates, health_cfg))
}

fn looks_like_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Per-node result of a cluster seal/unseal fan-out.
#[derive(Serialize, Clone)]
pub struct NodeSealResult {
    /// Concrete node URL the share was sent to.
    pub address: String,
    /// Post-submit seal state for this node, when the call succeeded.
    /// `None` means the call to this node errored.
    pub sealed: Option<bool>,
    /// Shamir share progress the node reported (shares entered so far).
    pub progress: Option<u64>,
    /// Threshold the node reported (shares required to cross).
    pub threshold: Option<u64>,
    /// Error string when the call to this node failed.
    pub error: Option<String>,
}

/// Enumerate the node URLs of the connected cluster. Mirrors the
/// operator CLI's `cluster_clients`: a literal-URL profile (or one with
/// discovery disabled) resolves to just the connected node; a bare
/// cluster name resolves via SRV to *every* node — including sealed /
/// unreachable ones, since those are exactly the nodes a seal/unseal
/// must reach.
async fn cluster_target_urls(profile: &RemoteProfile) -> CmdResult<Vec<String>> {
    use bv_client::discovery::{self, SystemResolver};

    if !profile.cluster_discovery || looks_like_url(&profile.address) {
        return Ok(vec![profile.address.clone()]);
    }

    let mut discovery_cfg = DiscoveryConfig::default();
    if let Some(svc) = profile
        .discovery_srv_service
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        discovery_cfg.srv_service = svc.to_string();
    }

    let resolver = SystemResolver::new();
    let resolved = discovery::resolve(&profile.address, &discovery_cfg, &resolver)
        .await
        .map_err(|e| CommandError::from(format!("Cluster discovery failed: {e}")))?;
    let urls: Vec<String> = resolved
        .into_candidates()
        .iter()
        .map(|c| c.url())
        .collect();
    if urls.is_empty() {
        return Err(CommandError::from(format!(
            "No nodes found for `{}`",
            profile.address
        )));
    }
    Ok(urls)
}

/// Build a fresh legacy `Client` aimed at a single node URL, attaching
/// TLS when the scheme calls for it. One client per node is how the
/// CLI fans seal/unseal out — `Client` is immutable once built, so a
/// per-node target means a per-node client.
fn client_for_node(profile: &RemoteProfile, url: &str) -> CmdResult<Client> {
    let mut builder = Client::new().with_addr(url);
    if url.starts_with("https://") {
        builder = builder.with_tls_config(build_legacy_tls(profile)?);
    }
    Ok(builder.build())
}

/// Send an unseal share to every node of the connected cluster.
///
/// Seal state is per-node (each node holds its own barrier), so the
/// same share must reach every node to bring them across the Shamir
/// threshold in lockstep — this is the GUI analogue of
/// `bvault operator unseal`'s cluster fan-out. `sys/unseal` is an
/// unauthenticated endpoint (a sealed vault can't authenticate anyone),
/// so the per-node clients carry no token. Per-node failures are
/// captured rather than aborting the sweep, so one unreachable node
/// doesn't strand the others mid-threshold.
pub(crate) async fn remote_unseal_fanout(
    profile: &RemoteProfile,
    key: &str,
) -> CmdResult<Vec<NodeSealResult>> {
    let urls = cluster_target_urls(profile).await?;
    let mut results = Vec::with_capacity(urls.len());
    for url in urls {
        let client = match client_for_node(profile, &url) {
            Ok(c) => c,
            Err(e) => {
                results.push(NodeSealResult {
                    address: url,
                    sealed: None,
                    progress: None,
                    threshold: None,
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        match client.sys().unseal(key) {
            Ok(resp) => {
                let body = resp.response_data.as_ref().and_then(|v| v.as_object());
                results.push(NodeSealResult {
                    address: url,
                    sealed: body
                        .and_then(|b| b.get("sealed"))
                        .and_then(|v| v.as_bool()),
                    progress: body
                        .and_then(|b| b.get("progress"))
                        .and_then(|v| v.as_u64()),
                    threshold: body.and_then(|b| b.get("t")).and_then(|v| v.as_u64()),
                    error: None,
                });
            }
            Err(e) => results.push(NodeSealResult {
                address: url,
                sealed: None,
                progress: None,
                threshold: None,
                error: Some(format!("sys/unseal failed: {e}")),
            }),
        }
    }
    Ok(results)
}

/// Send a seal command to every node of the connected cluster.
///
/// Seal state is per-node, so `bvault operator seal` fans the command
/// across the whole cluster — this is the GUI analogue. Unlike unseal,
/// `sys/seal` requires authorization (`update` on `sys/seal`), so each
/// per-node client carries the session token. Per-node failures are
/// captured rather than aborting the sweep, so one node that refuses
/// (e.g. a transient 403 or an unreachable peer) doesn't leave the
/// remaining nodes un-sealed.
pub(crate) async fn remote_seal_fanout(
    profile: &RemoteProfile,
    token: &str,
) -> CmdResult<Vec<NodeSealResult>> {
    let urls = cluster_target_urls(profile).await?;
    let mut results = Vec::with_capacity(urls.len());
    for url in urls {
        let client = match client_for_node(profile, &url) {
            Ok(c) => c.with_token(token),
            Err(e) => {
                results.push(NodeSealResult {
                    address: url,
                    sealed: None,
                    progress: None,
                    threshold: None,
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        match client.sys().seal() {
            // `sys/seal` answers 204 (or 200) on success; a 0 status is
            // the client's "no response from node" sentinel.
            Ok(resp) if resp.response_status == 0 => results.push(NodeSealResult {
                address: url,
                sealed: None,
                progress: None,
                threshold: None,
                error: Some("sys/seal failed: no response from node".to_string()),
            }),
            Ok(_) => results.push(NodeSealResult {
                address: url,
                sealed: Some(true),
                progress: None,
                threshold: None,
                error: None,
            }),
            Err(e) => results.push(NodeSealResult {
                address: url,
                sealed: None,
                progress: None,
                threshold: None,
                error: Some(format!("sys/seal failed: {e}")),
            }),
        }
    }
    Ok(results)
}

/// Build the bv-client TLS config matching the profile. Returns
/// `None` when the address scheme is plain HTTP (no TLS needed).
fn build_bv_tls(profile: &RemoteProfile) -> CmdResult<Option<ClientTlsConfig>> {
    // For literal URLs we can tell from the scheme; for cluster
    // names we don't know the scheme until discovery runs, so we
    // build TLS whenever any TLS material is configured OR the
    // input doesn't explicitly start with `http://`.
    let needs_tls = profile.address.starts_with("https://")
        || (!profile.address.starts_with("http://")
            && (profile.tls_skip_verify
                || profile.ca_cert_path.is_some()
                || profile.client_cert_path.is_some()));
    if !needs_tls {
        return Ok(None);
    }
    let mut b = BvTLSConfigBuilder::new().with_insecure(profile.tls_skip_verify);
    if let Some(p) = profile.ca_cert_path.as_deref().filter(|s| !s.is_empty()) {
        b = b
            .with_server_ca_path(&PathBuf::from(p))
            .map_err(|e| CommandError::from(format!("CA cert error: {e}")))?;
    }
    if let (Some(cp), Some(kp)) = (
        profile.client_cert_path.as_deref().filter(|s| !s.is_empty()),
        profile.client_key_path.as_deref().filter(|s| !s.is_empty()),
    ) {
        b = b
            .with_client_cert_path(&PathBuf::from(cp), &PathBuf::from(kp))
            .map_err(|e| CommandError::from(format!("Client cert error: {e}")))?;
    }
    let cfg = b
        .build()
        .map_err(|e| CommandError::from(format!("TLS config error: {e}")))?;
    Ok(Some(cfg))
}

fn build_legacy_tls(profile: &RemoteProfile) -> CmdResult<bastion_vault::api::client::TLSConfig> {
    let mut tls_builder = TLSConfigBuilder::new().with_insecure(profile.tls_skip_verify);
    if let Some(p) = profile.ca_cert_path.as_deref().filter(|s| !s.is_empty()) {
        tls_builder = tls_builder
            .with_server_ca_path(&PathBuf::from(p))
            .map_err(|e| CommandError::from(format!("CA cert error: {e}")))?;
    }
    if let (Some(cp), Some(kp)) = (
        profile.client_cert_path.as_deref().filter(|s| !s.is_empty()),
        profile.client_key_path.as_deref().filter(|s| !s.is_empty()),
    ) {
        tls_builder = tls_builder
            .with_client_cert_path(&PathBuf::from(cp), &PathBuf::from(kp))
            .map_err(|e| CommandError::from(format!("Client cert error: {e}")))?;
    }
    tls_builder
        .build()
        .map_err(|e| CommandError::from(format!("TLS config error: {e}")))
}

/// Disconnect from remote server and reset to embedded mode.
#[tauri::command]
pub async fn disconnect_remote(state: State<'_, AppState>) -> CmdResult<()> {
    *state.mode.lock().await = VaultMode::Embedded;
    *state.remote_client.lock().await = None;
    *state.remote_profile.lock().await = None;
    *state.selected_node.lock().await = None;
    *state.backend.lock().await = None;
    *state.token.lock().await = None;
    Ok(())
}

/// Cluster-discovery result for the live connection (if any).
/// Frontend uses this to render "Connected to <cluster> via <node>"
/// in the status bar.
#[tauri::command]
pub async fn get_selected_node(state: State<'_, AppState>) -> CmdResult<Option<SelectedNode>> {
    Ok(state.selected_node.lock().await.clone())
}

/// Run discovery + health probing for an address without storing
/// the result. Used by the Settings page's diagnostics panel
/// ("Cluster discovery") and by the operator's reconnect flow when
/// they want to see what the next pick would be before actually
/// switching.
#[tauri::command]
pub async fn cluster_discover(profile: RemoteProfile) -> CmdResult<ClusterDiagnostics> {
    use bv_client::discovery::{self, SystemResolver};
    use bv_client::health;

    let tls = build_bv_tls(&profile)?;
    let mut discovery_cfg = DiscoveryConfig::default();
    if let Some(svc) = profile.discovery_srv_service.as_deref().filter(|s| !s.is_empty()) {
        discovery_cfg.srv_service = svc.to_string();
    }
    let mut health_cfg = HealthConfig::default();
    if let Some(ms) = profile.health_probe_timeout_ms.filter(|m| *m > 0) {
        health_cfg.probe_timeout = Duration::from_millis(ms.into());
    }

    let resolver = SystemResolver::new();
    let resolved = discovery::resolve(&profile.address, &discovery_cfg, &resolver)
        .await
        .map_err(|e| CommandError::from(format!("Discovery failed: {e}")))?;
    let candidates: Vec<_> = resolved.into_candidates();
    let probes = health::probe_all(&candidates, &health_cfg, tls.as_ref()).await;
    let chosen = health::pick(&probes);

    let rows = probes
        .iter()
        .map(|p| ProbeRow {
            target: p.candidate.target.clone(),
            port: p.candidate.port,
            scheme: p.candidate.scheme.clone(),
            priority: p.candidate.priority,
            weight: p.candidate.weight,
            state: format!("{:?}", p.state),
            rtt_ms: p.rtt_ms,
            cluster_id: p.cluster_id.clone(),
            version: p.version.clone(),
        })
        .collect();

    Ok(ClusterDiagnostics {
        cluster_label: profile.address.clone(),
        chosen: chosen.map(|s| SelectedNode {
            cluster_label: profile.address.clone(),
            address: s.candidate.url(),
            target: s.candidate.target.clone(),
            port: s.candidate.port,
            state: format!("{:?}", s.state),
            rtt_ms: s.rtt_ms,
            cluster_id: s.cluster_id.clone(),
            version: s.version.clone(),
        }),
        candidates: rows,
    })
}

#[derive(Serialize)]
pub struct ClusterDiagnostics {
    pub cluster_label: String,
    pub chosen: Option<SelectedNode>,
    pub candidates: Vec<ProbeRow>,
}

#[derive(Serialize)]
pub struct ProbeRow {
    pub target: String,
    pub port: u16,
    pub scheme: String,
    pub priority: u16,
    pub weight: u16,
    pub state: String,
    pub rtt_ms: u32,
    pub cluster_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct RemoteStatus {
    pub connected: bool,
    pub address: String,
    pub initialized: bool,
    pub sealed: bool,
}

/// Get the status of the remote connection.
#[tauri::command]
pub async fn get_remote_status(state: State<'_, AppState>) -> CmdResult<RemoteStatus> {
    let client_guard = state.remote_client.lock().await;
    let profile_guard = state.remote_profile.lock().await;

    match (client_guard.as_ref(), profile_guard.as_ref()) {
        (Some(client), Some(profile)) => {
            match client.sys().health() {
                Ok(resp) => {
                    let data = resp.response_data;
                    let initialized = data.as_ref()
                        .and_then(|d| d.get("initialized"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let sealed = data.as_ref()
                        .and_then(|d| d.get("sealed"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    Ok(RemoteStatus {
                        connected: true,
                        address: profile.address.clone(),
                        initialized,
                        sealed,
                    })
                }
                Err(_) => Ok(RemoteStatus {
                    connected: false,
                    address: profile.address.clone(),
                    initialized: false,
                    sealed: true,
                }),
            }
        }
        _ => Ok(RemoteStatus {
            connected: false,
            address: String::new(),
            initialized: false,
            sealed: true,
        }),
    }
}

/// Login to a remote vault with a token.
///
/// Validates the token against the remote server via
/// `auth/token/lookup-self` before storing it. Without this,
/// a wrong token string gets saved into state and the user sees
/// "Permission denied" toasts from every subsequent page fetch;
/// this way an invalid token surfaces as an immediate "Invalid
/// token" error on the login page.
#[tauri::command]
pub async fn remote_login_token(
    state: State<'_, AppState>,
    token: String,
) -> CmdResult<crate::commands::auth::LoginResponse> {
    let client_guard = state.remote_client.lock().await;
    let client = client_guard.as_ref().ok_or("Not connected to remote server")?;

    // `token/lookup-self` is a GET that any valid token can call
    // against its own metadata. The client takes a token via
    // `with_token`; on an invalid token the request errors out and
    // we surface that as "Invalid token" without storing anything.
    let endpoint = format!("{}/auth/token/lookup-self", client.api_prefix());
    let bound = client.clone().with_token(&token);
    let resp = bound
        .request_read(endpoint)
        .map_err(|e| {
            let msg = format!("{e}");
            if msg.to_ascii_lowercase().contains("permission denied")
                || msg.to_ascii_lowercase().contains("invalid")
                || msg.to_ascii_lowercase().contains("forbidden")
            {
                CommandError::from("Invalid token")
            } else {
                CommandError::from(format!("Token validation failed: {e}"))
            }
        })?;

    // Extract policies so the UI can gate role-specific routes on the
    // first render — same shape as the embedded `login_token` path.
    let policies: Vec<String> = resp
        .response_data
        .as_ref()
        .and_then(|d| d.get("data").and_then(|x| x.get("policies")).or_else(|| d.get("policies")))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["default".to_string()]);

    // Record the token sign-in on the server's login-audit trail so it
    // surfaces on the Admin → Audit page alongside password / FIDO2 /
    // SSO logins. Mirrors the embedded `login_token` path; best-effort,
    // so a token whose policy lacks the grant still logs in cleanly. Done
    // before dropping the client guard since it reuses the bound client.
    let audit_endpoint = format!("{}/auth/token/audit-login", client.api_prefix());
    let _ = bound.request_write(audit_endpoint, None);

    drop(client_guard);
    *state.token.lock().await = Some(token.clone());
    Ok(crate::commands::auth::LoginResponse { token, policies })
}

/// Login to a remote vault with username/password.
#[tauri::command]
pub async fn remote_login_userpass(
    state: State<'_, AppState>,
    username: String,
    password: String,
) -> CmdResult<crate::commands::auth::LoginResponse> {
    let client_guard = state.remote_client.lock().await;
    let client = client_guard.as_ref().ok_or("Not connected to remote server")?;

    // Trim accidental surrounding whitespace (a stray space/newline from
    // paste or autofill would otherwise build an invalid URI ->
    // `InvalidUriChar`) and percent-encode the username path segment so any
    // legitimate special character can't break URL construction.
    let username = urlencoding::encode(username.trim());

    let data = serde_json::json!({ "password": password });
    let resp = client
        .request_write(
            format!("{}/auth/userpass/login/{username}", client.api_prefix()),
            data.as_object().cloned(),
        )
        .map_err(|e| CommandError::from(format!("Login failed: {e}")))?;

    let response_data = resp.response_data.ok_or("No response data")?;

    let token = response_data
        .get("auth")
        .and_then(|a| a.get("client_token"))
        .and_then(|t| t.as_str())
        .ok_or("No token in response")?
        .to_string();

    let policies: Vec<String> = response_data
        .get("auth")
        .and_then(|a| a.get("policies"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    drop(client_guard);
    *state.token.lock().await = Some(token.clone());

    Ok(crate::commands::auth::LoginResponse { token, policies })
}

#[tauri::command]
pub async fn load_preferences() -> CmdResult<Preferences> {
    crate::preferences::load()
}

/// Legacy-shape save for callers that still think in mode + single
/// remote_profile terms. Folds into the multi-vault list:
///   * Embedded / no profile → ensures a default Local entry exists
///     and flips `last_used_id` to it.
///   * Remote with profile → upserts a Remote vault by matching
///     address; flips `last_used_id` to it.
///
/// New-shape callers (the redesigned ConnectPage) use the explicit
/// `add_vault_profile` + `set_last_used_vault` commands instead.
#[tauri::command]
pub async fn save_preferences(mode: VaultMode, remote_profile: Option<RemoteProfile>) -> CmdResult<()> {
    use crate::preferences::{short_id, VaultProfile, VaultSpec};

    let mut prefs = crate::preferences::load().unwrap_or_default();
    match mode {
        VaultMode::Embedded => {
            // Find any existing Local profile; otherwise create one.
            let existing_id = prefs
                .vaults
                .iter()
                .find(|v| matches!(v.spec, VaultSpec::Local { .. }))
                .map(|v| v.id.clone());
            let id = existing_id.unwrap_or_else(|| {
                let id = short_id();
                prefs.vaults.push(VaultProfile {
                    id: id.clone(),
                    name: "Local Vault".to_string(),
                    spec: VaultSpec::Local {
                        data_dir: None,
                        storage_kind: "file".to_string(),
                    },
                });
                id
            });
            prefs.last_used_id = Some(id);
        }
        VaultMode::Remote => {
            let Some(profile) = remote_profile else {
                return Err("save_preferences(Remote) requires a profile".into());
            };
            // Upsert by matching address — the legacy caller provides
            // no stable id.
            let existing = prefs
                .vaults
                .iter()
                .position(|v| matches!(&v.spec, VaultSpec::Remote { profile: p } if p.address == profile.address));
            let id = if let Some(idx) = existing {
                prefs.vaults[idx].spec = VaultSpec::Remote { profile: profile.clone() };
                prefs.vaults[idx].name = profile.name.clone();
                prefs.vaults[idx].id.clone()
            } else {
                let id = short_id();
                prefs.vaults.push(VaultProfile {
                    id: id.clone(),
                    name: if profile.name.is_empty() {
                        "Remote Vault".to_string()
                    } else {
                        profile.name.clone()
                    },
                    spec: VaultSpec::Remote { profile },
                });
                id
            };
            prefs.last_used_id = Some(id);
        }
    }
    crate::preferences::save(&prefs)
}

#[tauri::command]
pub async fn get_password_policy() -> CmdResult<crate::preferences::PasswordPolicy> {
    Ok(crate::preferences::load().unwrap_or_default().password_policy)
}

#[tauri::command]
pub async fn set_password_policy(
    policy: crate::preferences::PasswordPolicy,
) -> CmdResult<()> {
    let mut prefs = crate::preferences::load().unwrap_or_default();
    prefs.password_policy = policy;
    crate::preferences::save(&prefs)
}
