//! Phase 9.3 — listener-info discovery.
//!
//! Calls Rustion's `GET /v1/listeners` over the pinned-TLS path and
//! returns the per-protocol dial coordinates. Used by the GUI Connect
//! resolver so it can dial the SSH/RDP proxies even when the
//! `session/open` echo leaks an unspecified bind address (the bastion
//! advertises `0.0.0.0:<port>` when `[control_plane].ssh_advertise` /
//! `rdp_advertise` are left empty in `rustion.toml`).
//!
//! Wire shape mirrors Rustion's `ListenersResponse`:
//! ```json
//! {
//!   "schema_version": 1,
//!   "ssh": { "advertised_host": "bastion.example.com",
//!            "port": 2222,
//!            "advertised": true },
//!   "rdp": { "advertised_host": "",  "port": 3389, "advertised": false }
//! }
//! ```
//!
//! `advertised_host` is **empty** when Rustion only knows its bind
//! address (`0.0.0.0` / `::`) — callers must fall back to the host
//! portion of `target.endpoint` for that protocol. `advertised: true`
//! is the one-shot flag that says "this host is safe to dial".

#![deny(unsafe_code)]

use std::time::Duration;

use serde::Deserialize;

use crate::errors::RvError;

use super::config::RustionTarget;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct ListenerInfo {
    #[serde(default)]
    pub advertised_host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub advertised: bool,
    /// Transport-identity pin the dialler verifies against. SSH: OpenSSH
    /// host-key fingerprint (`SHA256:<base64>`); RDP: TLS leaf cert digest
    /// (`sha256:<hex>`). Present from listener schema v2 onwards; empty
    /// (or absent, on a v1 bastion) means the bastion advertises no pin
    /// and the dialler keeps its unpinned TOFU behaviour.
    #[serde(default)]
    pub pin: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenersResponse {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub ssh: ListenerInfo,
    #[serde(default)]
    pub rdp: ListenerInfo,
}

/// Pull `GET /v1/listeners` from a target's control plane. No auth
/// header is required by Rustion (matches `/v1/health` posture); the
/// response carries no secrets and an attacker who can reach the
/// control plane can already port-scan the proxy ports.
pub async fn discover(target: &RustionTarget) -> Result<ListenersResponse, RvError> {
    let client = super::http::build_client_for(target, DISCOVERY_TIMEOUT)?;
    let url = format!("https://{}/v1/listeners", target.endpoint.trim_end_matches('/'));
    let resp =
        client.get(&url).send().await.map_err(|e| RvError::ErrString(format!("rustion listener discovery: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(RvError::ErrString(format!("rustion listener discovery: http {status}: {body}")));
    }
    resp.json::<ListenersResponse>()
        .await
        .map_err(|e| RvError::ErrString(format!("rustion listener discovery: decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::ListenersResponse;

    #[test]
    fn parses_v2_pins() {
        // Rustion listener schema v2: per-protocol `pin` present.
        let json = r#"{
            "schema_version": 2,
            "ssh": { "advertised_host": "bastion.example.com", "port": 2222,
                     "advertised": true, "pin": "SHA256:abc123" },
            "rdp": { "advertised_host": "bastion.example.com", "port": 3389,
                     "advertised": true, "pin": "sha256:deadbeef" }
        }"#;
        let r: ListenersResponse = serde_json::from_str(json).expect("decode v2");
        assert_eq!(r.schema_version, 2);
        assert_eq!(r.ssh.pin, "SHA256:abc123");
        assert_eq!(r.rdp.pin, "sha256:deadbeef");
    }

    #[test]
    fn v1_without_pin_defaults_empty() {
        // A pre-v2 Rustion omits `pin` entirely — must default to empty
        // (dialler then stays unpinned) rather than fail to decode.
        let json = r#"{
            "schema_version": 1,
            "ssh": { "advertised_host": "", "port": 2222, "advertised": false },
            "rdp": { "advertised_host": "", "port": 3389, "advertised": false }
        }"#;
        let r: ListenersResponse = serde_json::from_str(json).expect("decode v1");
        assert_eq!(r.schema_version, 1);
        assert!(r.ssh.pin.is_empty());
        assert!(r.rdp.pin.is_empty());
    }
}
