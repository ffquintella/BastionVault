use std::{collections::HashMap, sync::Arc};

use bastion_vault::BastionVault;
use bastion_vault::api::Client;
use bastion_vault::storage::physical::file::oauth::{
    ConsentSession, OAuthCredentials, OAuthProvider,
};
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
}

pub struct AppState {
    pub mode: Mutex<VaultMode>,
    /// Embedded vault instance (only set in Embedded mode).
    pub vault: Mutex<Option<Arc<BastionVault>>>,
    /// Remote API client (only set in Remote mode).
    pub remote_client: Mutex<Option<Client>>,
    /// Remote server profile (only set in Remote mode).
    pub remote_profile: Mutex<Option<RemoteProfile>>,
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
}

impl AppState {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(VaultMode::Embedded),
            vault: Mutex::new(None),
            remote_client: Mutex::new(None),
            remote_profile: Mutex::new(None),
            token: Mutex::new(None),
            pin_sender: std::sync::Mutex::new(None),
            cloud_sessions: std::sync::Mutex::new(HashMap::new()),
            oidc_sessions: std::sync::Mutex::new(HashMap::new()),
            connect_sessions: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}
