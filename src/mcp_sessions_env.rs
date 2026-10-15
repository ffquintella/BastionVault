//! The vault's [`BrokeredSessionEnv`]: what the MCP brokered-session handler
//! (`resources/v2/connect/agent/*`, in the resource engine) reads about the
//! server around it (`features/mcp-brokered-sessions.md` §11-12).
//!
//! Registered here, at the assembly point, because this is the only place
//! that holds all three sources at once: the server config's
//! `mcp.brokered_sessions` (on `Core`), the runtime `sys/mcp/config` record
//! (the system mount's storage), and the listener and cluster addresses the
//! destination policy denies whatever an operator lists.

use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Weak},
};

use bv_utils::destination_policy::{effective_target_cidr_entries, DestinationPolicy, TargetCidrs};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::{
        mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
        VaultCtx,
    },
    modules::system::mcp::{McpRuntimeConfig, MCP_CONFIG_KEY},
    storage::Storage,
};

/// The production environment. Holds the vault weakly: it lives in the
/// vault's own service registry, and a strong handle would keep the vault
/// alive through it.
pub struct VaultBrokeredSessionEnv {
    core: Weak<Core>,
    /// This vault's own configured addresses (IP-literal listeners and
    /// `api_addr`). Every address of the host is denied as well, at dial time
    /// (`DestinationPolicy::deny_host_addresses`), which covers a listener
    /// bound to an unspecified address.
    own_addresses: Vec<IpAddr>,
    /// The configured cluster nodes' addresses (hiqlite `nodes`).
    cluster_nodes: Vec<IpAddr>,
}

impl VaultBrokeredSessionEnv {
    pub fn new(core: &Arc<Core>, config: Option<&crate::config::Config>) -> Self {
        let (own_addresses, cluster_nodes) = config.map(configured_addresses).unwrap_or_default();
        Self { core: Arc::downgrade(core), own_addresses, cluster_nodes }
    }
}

/// The host part of `host:port`, `[v6]:port`, or a URL's authority.
fn host_of(addr: &str) -> &str {
    let addr = addr.split_once("://").map(|(_, rest)| rest).unwrap_or(addr);
    let authority = addr.split('/').next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or_default();
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// The listener and `api_addr` IP literals, and the hiqlite cluster nodes
/// (`"id:raft_host:raft_port:api_host:api_port"`), resolved once, at start.
/// A node name that does not resolve is logged and skipped: it cannot be
/// dialed by name either, since a session dials only checked addresses.
fn configured_addresses(config: &crate::config::Config) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut own: Vec<IpAddr> = Vec::new();
    let push = |list: &mut Vec<IpAddr>, ip: IpAddr| {
        if !ip.is_unspecified() && !list.contains(&ip) {
            list.push(ip);
        }
    };
    for listener in config.listener.values() {
        if let Ok(ip) = host_of(&listener.address).parse::<IpAddr>() {
            push(&mut own, ip);
        }
    }
    if let Ok(ip) = host_of(&config.api_addr).parse::<IpAddr>() {
        push(&mut own, ip);
    }
    let mut cluster: Vec<IpAddr> = Vec::new();
    for storage in config.storage.values() {
        let Some(nodes) = storage.config.get("nodes").and_then(|v| v.as_array()) else { continue };
        for node in nodes.iter().filter_map(|n| n.as_str()) {
            let parts: Vec<&str> = node.split(':').collect();
            for host in [parts.get(1), parts.get(3)].into_iter().flatten() {
                match host.parse::<IpAddr>() {
                    Ok(ip) => push(&mut cluster, ip),
                    Err(_) => match (*host, 0u16).to_socket_addrs() {
                        Ok(addrs) => addrs.for_each(|a| push(&mut cluster, a.ip())),
                        Err(e) => log::warn!(
                            "mcp.brokered_sessions: cluster node {host:?} does not resolve ({e}); it is not on the \
                             destination deny list"
                        ),
                    },
                }
            }
        }
    }
    (own, cluster)
}

#[maybe_async::maybe_async]
impl BrokeredSessionEnv for VaultBrokeredSessionEnv {
    fn settings(&self) -> BrokeredSessionSettings {
        let Some(core) = self.core.upgrade() else {
            return BrokeredSessionSettings::default();
        };
        let c = &core.mcp_brokered_sessions;
        BrokeredSessionSettings {
            enabled: c.enabled,
            protocols: c.protocols.clone(),
            max_concurrent: c.max_concurrent,
            rate_per_binding_per_min: c.rate_per_binding_per_min,
            call_timeout_secs: c.call_timeout_secs,
            max_output_bytes: c.max_output_bytes,
            ssh_cert_source_addresses: c.ssh.cert_source_addresses.clone(),
        }
    }

    async fn runtime(&self) -> Result<BrokeredSessionRuntime, RvError> {
        let core = self.core.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        // The runtime record lives in the system mount's own storage, where
        // `sys/mcp/config` reads and writes it.
        let view = VaultCtx::router(core.as_ref())
            .matching_view("sys/mcp/config")?
            .ok_or_else(|| crate::bv_error_string!("the system mount is not mounted"))?;
        let cfg: McpRuntimeConfig = match view.get(MCP_CONFIG_KEY).await? {
            Some(entry) => serde_json::from_slice(&entry.value)?,
            None => McpRuntimeConfig::default(),
        };
        let (allowed_target_cidrs, source) = effective_target_cidr_entries(
            cfg.brokered_sessions_allowed_target_cidrs.as_deref(),
            core.mcp_brokered_sessions.allowed_target_cidrs.as_deref(),
        );
        Ok(BrokeredSessionRuntime { enabled: cfg.brokered_sessions_enabled, allowed_target_cidrs, source })
    }

    fn destination_policy(&self, allowed: TargetCidrs) -> DestinationPolicy {
        DestinationPolicy::new(allowed, self.own_addresses.iter().copied(), self.cluster_nodes.iter().copied())
            .deny_host_addresses()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_read_from_every_address_form() {
        assert_eq!(host_of("127.0.0.1:8200"), "127.0.0.1");
        assert_eq!(host_of("http://10.0.0.5:8200/"), "10.0.0.5");
        assert_eq!(host_of("https://vault.example.com"), "vault.example.com");
        assert_eq!(host_of("[::1]:8200"), "::1");
        assert_eq!(host_of("https://[fd00::5]:8200/v1"), "fd00::5");
        assert_eq!(host_of("0.0.0.0:8200"), "0.0.0.0");
    }
}
