use std::{collections::HashMap, sync::Arc};

use bastion_vault::BastionVault;
use bastion_vault::api::Client;
use bastion_vault::storage::physical::file::oauth::{
    ConsentSession, OAuthCredentials, OAuthProvider,
};
use bv_client::Backend;
use tokio::sync::Mutex;

/// In-flight OAuth consent session for a cloud storage target.
///
/// The session handle owns the bound loopback listener, the PKCE
/// verifier, and the CSRF state; the rest of the struct carries the
/// provider + creds + destination so the `complete_connect` command
/// has everything it needs without a re-lookup.
pub struct CloudSession {
    pub session: ConsentSession,
    pub provider: OAuthProvider,
    pub creds: OAuthCredentials,
    pub credentials_ref: String,
}

/// In-flight OIDC *login* session (distinct from `CloudSession`,
/// which is for configuring cloud storage targets).
///
/// The vault backend does most of the heavy lifting — PKCE, state,
/// discovery, JWKS verification — so all we hold on the GUI side is
/// the bound loopback listener + the mount name. The callback
/// handler on this side just grabs `code` + `state` off the query
/// string and POSTs them back through `auth/<mount>/callback`;
/// the vault returns a ready-to-use client token.
pub struct OidcLoginSession {
    pub listener: std::net::TcpListener,
    /// The redirect URI the vault's `auth_url` was composed with.
    /// Only kept here for debugging / future observability — the
    /// vault validates it at callback time, not the GUI. Marked
    /// `dead_code` for the current build.
    #[allow(dead_code)]
    pub redirect_uri: String,
    pub mount: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VaultMode {
    Embedded,
    Remote,
}

/// Connection profile for a remote BastionVault server.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RemoteProfile {
    pub name: String,
    pub address: String,
    pub tls_skip_verify: bool,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    /// Vault Cluster Client Discovery — when `true` (default) and
    /// `address` looks like a bare DNS name, `connect_remote` queries
    /// `_bvault._tcp.<address>` for SRV records and picks the best
    /// node via `/sys/health` scoring before connecting. URL-shaped
    /// addresses (`https://host:port`) always skip discovery. Set
    /// to `false` to force literal-address mode for diagnostics
    /// against a single node in an HA cluster.
    ///
    /// Optional in the serde shape so old preference files (which
    /// predate the field) deserialize cleanly to the default.
    #[serde(default = "default_cluster_discovery")]
    pub cluster_discovery: bool,
    /// Override for the SRV service label (defaults to
    /// `_bvault._tcp`). Empty / missing → keep the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_srv_service: Option<String>,
    /// Per-probe deadline in milliseconds (default 1500). 0 / missing
    /// → keep the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_probe_timeout_ms: Option<u32>,
    /// When `true`, the connect flow requires a successful FerroGate machine
    /// login (this host attested + operator-approved) BEFORE the user-login
    /// screen — so vault access needs machine identity AND a user credential.
    /// Optional/defaulted so old preference files load cleanly; defaults off
    /// to avoid locking operators out of vaults that don't use ferrogate.
    #[serde(default)]
    pub require_machine_identity: bool,
    /// MIA environment pinned to this server profile by the operator in the
    /// GUI's Server form. Selects which `mia-<env>.toml` the connect-time
    /// machine gate dials and takes precedence over the env the server
    /// advertises — the override for "this caller is not on the MIA's local
    /// allowlist" when the wrong MIA daemon would otherwise be asked. Empty /
    /// missing → use the server-advertised environment (default `mia.toml`).
    /// Optional/defaulted so old preference files load cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mia_environment: Option<String>,
}

fn default_cluster_discovery() -> bool {
    true
}

/// Serializable view of `bv_client::health::Selected` for the
/// frontend. Carries enough metadata to render the connected-node
/// indicator and to drive a `bvault cluster discover`-style
/// diagnostics row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelectedNode {
    /// Operator-facing label — the cluster name they originally
    /// typed (e.g. `vault.corp.example`).
    pub cluster_label: String,
    /// Concrete `scheme://target:port` the client is actually
    /// talking to.
    pub address: String,
    pub target: String,
    pub port: u16,
    /// `"ActiveLeader"`, `"Follower"`, `"Sealed"`, `"Uninitialized"`,
    /// or `"Unreachable: <reason>"`. Stringified so the frontend
    /// doesn't have to mirror the bv-client enum shape.
    pub state: String,
    pub rtt_ms: u32,
    pub cluster_id: Option<String>,
    pub version: Option<String>,
}

pub struct AppState {
    pub mode: Mutex<VaultMode>,
    /// Embedded vault instance (only set in Embedded mode).
    pub vault: Mutex<Option<Arc<BastionVault>>>,
    /// Remote API client (only set in Remote mode).
    pub remote_client: Mutex<Option<Client>>,
    /// Remote server profile (only set in Remote mode).
    pub remote_profile: Mutex<Option<RemoteProfile>>,
    /// Cluster-discovery result for the live remote connection.
    /// Populated by `connect_remote` when discovery ran (cluster
    /// name → SRV → health probes → pick). `None` when the operator
    /// used a literal URL or disabled discovery. Surfaced to the
    /// frontend via `get_remote_status` so the status bar can show
    /// "Connected to <cluster> via <node> (leader, 12 ms)".
    pub selected_node: Mutex<Option<SelectedNode>>,
    /// Trait-object backend used by migrated commands. Always populated
    /// to mirror whichever of `vault` / `remote_client` is active —
    /// embedded mode wraps `vault` in an `EmbeddedBackend`, remote mode
    /// wraps a `RemoteBackend`. New commands route through this; the
    /// legacy `vault` / `remote_client` fields above stay during the
    /// migration so unmigrated commands keep compiling.
    pub backend: Mutex<Option<Arc<dyn Backend>>>,
    /// Active auth token (used in both modes).
    pub token: Mutex<Option<String>>,
    /// Channel for receiving PIN input from the frontend during FIDO2 ceremonies.
    /// The status handler thread stores a sender here; the `fido2_submit_pin` command
    /// sends the user-entered PIN (or empty string for cancel) through it.
    pub pin_sender: std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>,
    /// Pending cloud-target OAuth consent sessions, keyed by an
    /// opaque session id handed back to the frontend. Removed on
    /// completion, timeout, or cancel — the underlying TCP listener
    /// is dropped with the session so no port leaks.
    pub cloud_sessions: std::sync::Mutex<HashMap<String, CloudSession>>,
    /// Pending OIDC login sessions. Same shape + lifecycle as
    /// `cloud_sessions` but distinct because the two flows collect
    /// different state (cloud-target = OAuth to a provider, OIDC =
    /// auth via the vault's `oidc` backend).
    pub oidc_sessions: std::sync::Mutex<HashMap<String, OidcLoginSession>>,
    /// Live Resource-Connect SSH/RDP sessions, keyed by the
    /// per-session token returned to the spawned WebviewWindow.
    /// Each entry owns the russh client + a control channel the
    /// session_input / session_resize / session_close commands
    /// use to drive the remote PTY.
    pub connect_sessions:
        tokio::sync::Mutex<HashMap<String, crate::session::SessionState>>,
    /// Phase 7.4: per-session Rustion bundle stashed when the Connect
    /// path routed through a bastion. Keyed by the same SSH/RDP
    /// session token in `connect_sessions`. Read by the spawned window
    /// via `session_rustion_info` to drive renew/kill UI; dropped
    /// alongside the session in `drop_session`.
    pub rustion_session_bundles:
        tokio::sync::Mutex<HashMap<String, RustionSessionBundle>>,
    /// Plugin Extensibility v1: per-vault on-disk surface cache.
    /// Resolved on first use from the Tauri app's cache directory
    /// (`<dirs::cache>/com.bastionvault.gui/plugins/<vault-id>/`).
    /// Cleared when the operator switches vaults.
    pub plugin_surface_cache: Mutex<Option<bv_client::SurfaceCache>>,
}

/// Persistent identity of a Rustion-mediated session, captured at
/// `session/open` time. The spawned SSH/RDP window queries this to
/// drive renew + kill against the same correlation_id Rustion bound
/// to the open envelope.
#[derive(Clone)]
pub struct RustionSessionBundle {
    pub session_id: String,
    pub bastion_id: String,
    pub bastion_name: String,
    pub correlation_id: String,
    pub expires_at: String,
    pub max_renewals: u32,
    /// `ssh` | `rdp` — surfaced in audit + the lifecycle UI.
    pub protocol: String,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(VaultMode::Embedded),
            vault: Mutex::new(None),
            remote_client: Mutex::new(None),
            remote_profile: Mutex::new(None),
            selected_node: Mutex::new(None),
            backend: Mutex::new(None),
            token: Mutex::new(None),
            pin_sender: std::sync::Mutex::new(None),
            cloud_sessions: std::sync::Mutex::new(HashMap::new()),
            oidc_sessions: std::sync::Mutex::new(HashMap::new()),
            connect_sessions: tokio::sync::Mutex::new(HashMap::new()),
            rustion_session_bundles: tokio::sync::Mutex::new(HashMap::new()),
            plugin_surface_cache: Mutex::new(None),
        }
    }
}
