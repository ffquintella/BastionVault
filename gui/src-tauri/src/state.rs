use std::sync::Arc;

use bastion_vault::BastionVault;
use bastion_vault::api::Client;
use tokio::sync::Mutex;

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
}

impl AppState {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(VaultMode::Embedded),
            vault: Mutex::new(None),
            remote_client: Mutex::new(None),
            remote_profile: Mutex::new(None),
            token: Mutex::new(None),
        }
    }
}
