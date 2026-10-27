//! The HSM link (features/hsm-pool-ha.md § "HSM link: gateway and relay"):
//! `yubihsm::Client -> Relay ==mTLS==> Gateway -> yubihsm-connector`.
//! Neither half parses YubiHSM commands (SCP03 is end to end), and nothing
//! here logs a request or response body.

#![forbid(unsafe_code)]

use std::time::Duration;

mod config;
mod gateway;
mod http;
mod ratelimit;
mod relay;
mod tls;

pub use config::{
    validate_client_id, ConnectorUrl, GatewayConfig, GatewayLimits, GatewaySettings, GatewayUrl, LinkTls, RelayConfig,
    RelayLimits,
};
pub use gateway::{Gateway, GatewayStats};
pub use relay::{Relay, RelayStats};

/// The connector's command endpoint (`POST`).
pub const CONNECTOR_API_PATH: &str = "/connector/api";
/// The connector's status page (`GET`, no body).
pub const CONNECTOR_STATUS_PATH: &str = "/connector/status";
/// Smallest command the connector accepts: a command byte and a 2-byte length.
pub const MIN_API_BODY_BYTES: usize = 3;
/// Largest command the connector accepts: the 3-byte header plus the device's
/// 3136-byte message buffer.
pub const MAX_API_BODY_BYTES: usize = 3139;
/// The gateway's bound on one connector exchange (connect, send, response).
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests per second per allowed client when the config does not say: a
/// node sends a handful per HSM operation, and 50 covers a cold start.
pub const DEFAULT_MAX_RPS_PER_CLIENT: u32 = 50;
