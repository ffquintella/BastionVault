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
    /// Channel for receiving PIN input from the frontend during FIDO2 ceremonies.
    /// The status handler thread stores a sender here; the `fido2_submit_pin` command
    /// sends the user-entered PIN (or empty string for cancel) through it.
    pub pin_sender: std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>,
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
        }
    }
}
