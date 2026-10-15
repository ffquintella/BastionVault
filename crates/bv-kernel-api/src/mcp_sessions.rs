//! What an MCP brokered-session executor needs from the vault around it
//! (`features/mcp-brokered-sessions.md` §11-12), and cannot see itself.
//!
//! The session handler is the resource engine's (`resources/v2/connect/agent/*`).
//! The switches and limits it enforces are the server's: the static
//! `mcp.brokered_sessions` block lives in the server config (`bv-core`, above
//! every engine), the runtime switch and destination list in
//! `sys/mcp/config` (`bv-kernel`), and the vault's own addresses in the
//! listener configuration. [`BrokeredSessionEnv`] is the one narrow window
//! onto all three, registered by the assembly layer.
//!
//! **Fail closed.** No registered environment means no brokered session: the
//! handler refuses with `mcp_brokered_sessions_disabled`, exactly as with the
//! switch off.

use bv_errors::RvError;
use bv_utils::destination_policy::{DestinationPolicy, TargetCidrSource, TargetCidrs};

/// The static half: the server config's `mcp.brokered_sessions`, already
/// validated at load (`bv-core`'s `BrokeredSessionsConfig::validate`), so
/// every bound here is inside its ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokeredSessionSettings {
    /// `mcp.brokered_sessions.enabled`, the server switch.
    pub enabled: bool,
    /// `mcp.brokered_sessions.protocols`: `ssh`, `web`, `rdp`.
    pub protocols: Vec<String>,
    /// Concurrent sessions on this node.
    pub max_concurrent: u32,
    /// Session calls per binding per minute, on this node.
    pub rate_per_binding_per_min: u32,
    /// Wall-clock budget of one SSH or web call, seconds, connect included.
    pub call_timeout_secs: u64,
    /// Bytes of output returned to the model per call.
    pub max_output_bytes: u64,
    /// The vault's egress addresses for a brokered certificate's
    /// `source-address` critical option. Empty: the option is omitted.
    pub ssh_cert_source_addresses: Vec<String>,
}

impl Default for BrokeredSessionSettings {
    /// Sessions off; the spec's default limits.
    fn default() -> Self {
        Self {
            enabled: false,
            protocols: Vec::new(),
            max_concurrent: 4,
            rate_per_binding_per_min: 6,
            call_timeout_secs: 20,
            max_output_bytes: 65_536,
            ssh_cert_source_addresses: Vec::new(),
        }
    }
}

impl BrokeredSessionSettings {
    /// Whether the server config lists `protocol`.
    pub fn allows_protocol(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }
}

/// The runtime half, read per call: `sys/mcp/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokeredSessionRuntime {
    /// `brokered_sessions_enabled`, the runtime "big red button".
    pub enabled: bool,
    /// The destination allow-list in force, unparsed: the runtime list, else
    /// the server config's, else the built-in default.
    pub allowed_target_cidrs: Vec<String>,
    /// Which layer `allowed_target_cidrs` came from.
    pub source: TargetCidrSource,
}

/// The vault around a session executor. Registered once per vault by the
/// assembly layer; see the module doc.
#[maybe_async::maybe_async]
pub trait BrokeredSessionEnv: Send + Sync {
    /// The server config's `mcp.brokered_sessions`.
    fn settings(&self) -> BrokeredSessionSettings;

    /// The runtime switch and destination list, read now. A session reads
    /// this before it dials and again every two seconds while it runs.
    async fn runtime(&self) -> Result<BrokeredSessionRuntime, RvError>;

    /// The policy one dial is checked against: `allowed`, the always-denied
    /// classes, the vault's own listener and cluster addresses, and every
    /// address of this host ([`DestinationPolicy::deny_host_addresses`]).
    /// The only constructor of a session's policy, so a test that needs a
    /// loopback target replaces this service rather than any setting.
    fn destination_policy(&self, allowed: TargetCidrs) -> DestinationPolicy;
}
