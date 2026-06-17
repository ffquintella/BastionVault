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
    let url = format!(
        "https://{}/v1/listeners",
        target.endpoint.trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| RvError::ErrString(format!("rustion listener discovery: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(RvError::ErrString(format!(
            "rustion listener discovery: http {status}: {body}"
        )));
    }
    resp.json::<ListenersResponse>()
        .await
        .map_err(|e| RvError::ErrString(format!("rustion listener discovery: decode: {e}")))
}
