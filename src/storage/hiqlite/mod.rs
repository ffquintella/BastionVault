use std::{any::Any, borrow::Cow, collections::HashMap, net::ToSocketAddrs, path::Path};

use hiqlite::{Client, Node, NodeConfig, Param, tls::ServerTlsConfig};
use serde_json::Value;
use tokio::net::TcpListener;

use crate::{
    errors::RvError,
    storage::{Backend, BackendEntry},
};

/// Hiqlite WAL segment size. Must be larger than any single Raft log entry we
/// produce — hiqlite-wal panics rather than erroring when an entry exceeds the
/// segment size. We cap files at 32 MiB; 64 MiB here leaves room for the
/// encryption envelope and Raft framing.
const HIQLITE_WAL_SIZE: u32 = 64 * 1024 * 1024;

/// Conservative safe payload ceiling for a single `put`. Slightly below
/// `HIQLITE_WAL_SIZE` to account for Raft entry framing / serialization
/// overhead that wraps the raw value before it hits the WAL writer.
const MAX_PUT_VALUE_BYTES: usize = (HIQLITE_WAL_SIZE as usize) - 1024 * 1024;

/// Maximum age (ms) of a leader's last quorum acknowledgement before we treat
/// it as unhealthy.
///
/// openraft's `millis_since_quorum_ack` reports how long ago the leader last
/// heard back from a quorum. A leader that can no longer reach a quorum keeps
/// reporting itself as leader in its *local* cached metrics — so hiqlite's
/// `is_leader_db()` / `is_healthy_db()` (which only read that local state) stay
/// green — while every linearizable read fails the read-index confirmation with
/// a quorum-not-enough timeout. Treating such an isolated leader as unhealthy
/// makes `cluster-status` mean "can actually serve reads", not just "thinks it
/// is leader". The read path uses a 500ms read-index timeout, so 3s is several
/// heartbeat intervals of slack: wide enough to avoid false positives on a
/// healthy cluster, tight enough to flag a partitioned leader quickly.
const QUORUM_ACK_STALE_MS: u64 = 3_000;

fn map_hiqlite_error(e: hiqlite::Error) -> RvError {
    match &e {
        hiqlite::Error::CheckIsLeaderError(_) => {
            // A `CheckIsLeaderError` carries two distinct meanings that we must
            // not conflate:
            //   - `ForwardToLeader`: this node is not the leader (election in
            //     progress, or leadership lives elsewhere). hiqlite's
            //     `is_forward_to_leader()` returns `Some(..)` for this shape.
            //   - `QuorumNotEnough`: this node *is* the leader but could not
            //     confirm leadership with a quorum within the read-index
            //     timeout — e.g. its heartbeat `AppendEntries` to a peer keeps
            //     failing. `is_forward_to_leader()` returns `None` here.
            //
            // The quorum case is what an isolated leader hits on every
            // consistent read: the cluster still has a leader (this node), so
            // reporting "Cluster has no leader" sends operators chasing a
            // phantom election while the real fault is peer connectivity.
            // Surface it as the distinct `ErrClusterQuorumLost` instead.
            if e.is_forward_to_leader().is_some() {
                RvError::ErrClusterNoLeader
            } else {
                RvError::ErrClusterQuorumLost
            }
        }
        hiqlite::Error::LeaderChange(_) => RvError::ErrClusterNoLeader,
        hiqlite::Error::ClientWriteError(_) => {
            if e.is_forward_to_leader().is_some() {
                // hiqlite should auto-forward; if we get here, forward failed
                RvError::ErrClusterNoLeader
            } else {
                RvError::ErrCluster(e.to_string())
            }
        }
        hiqlite::Error::Connect(_) => RvError::ErrClusterUnhealthy,
        hiqlite::Error::Timeout(_) => RvError::ErrClusterUnhealthy,
        hiqlite::Error::RaftError(_) => RvError::ErrCluster(e.to_string()),
        hiqlite::Error::RaftErrorFatal(_) => RvError::ErrCluster(e.to_string()),
        _ => RvError::ErrCluster(e.to_string()),
    }
}

pub struct HiqliteBackend {
    client: Client,
    table: String,
    /// Hiqlite API address for management HTTP calls (e.g., "https://127.0.0.1:8100")
    api_addr: String,
    /// Shared API secret for hiqlite management endpoints
    secret_api: String,
    /// This node's ID
    node_id: u64,
    /// Whether TLS is enabled on the API channel (affects certificate verification for self-signed)
    tls_api_auto_certs: bool,
    /// Keeps the tokio runtime alive so hiqlite's background tasks (Raft, RPC servers) continue running.
    /// Without this, dropping the runtime kills all spawned tasks and the node becomes unreachable.
    _runtime: Option<tokio::runtime::Runtime>,
}

impl std::fmt::Debug for HiqliteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HiqliteBackend")
            .field("table", &self.table)
            .field("api_addr", &self.api_addr)
            .field("node_id", &self.node_id)
            .field("tls_api_auto_certs", &self.tls_api_auto_certs)
            .finish_non_exhaustive()
    }
}

struct VaultRow {
    vault_key: String,
    vault_value: Vec<u8>,
}

impl<'a, 'r> From<&'a mut hiqlite::Row<'r>> for VaultRow {
    fn from(row: &'a mut hiqlite::Row<'r>) -> Self {
        Self {
            vault_key: row.get("vault_key"),
            vault_value: row.get("vault_value"),
        }
    }
}

#[maybe_async::must_be_async]
impl Backend for HiqliteBackend {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let rows: Vec<VaultRow> = self
            .client
            .query_consistent_map(
                Cow::Owned(format!(
                    "SELECT vault_key, vault_value FROM {} WHERE vault_key LIKE ?",
                    self.table
                )),
                vec![Param::from(format!("{prefix}%"))],
            )
            .await
            .map_err(map_hiqlite_error)?;

        let mut keys: Vec<String> = Vec::new();
        for entry in rows.iter() {
            let key = entry.vault_key.trim_start_matches(prefix);
            match key.find('/') {
                Some(i) => {
                    let key = &key[0..i + 1];
                    if !keys.contains(&key.to_string()) {
                        keys.push(key.to_string());
                    }
                }
                None => {
                    keys.push(key.to_string());
                }
            }
        }
        Ok(keys)
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let result: Option<VaultRow> = self
            .client
            .query_consistent_map(
                Cow::Owned(format!(
                    "SELECT vault_key, vault_value FROM {} WHERE vault_key = ?",
                    self.table
                )),
                vec![Param::from(key)],
            )
            .await
            .map_err(map_hiqlite_error)?
            .into_iter()
            .next();

        match result {
            Some(row) => Ok(Some(BackendEntry {
                key: row.vault_key,
                value: row.vault_value,
            })),
            None => Ok(None),
        }
    }

    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        if entry.key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        // Reject oversized payloads before they reach hiqlite-wal, which
        // panics (not errors) on any entry larger than the WAL segment.
        if entry.value.len() > MAX_PUT_VALUE_BYTES {
            return Err(RvError::ErrString(format!(
                "storage put: value size {} exceeds raft log segment limit {}",
                entry.value.len(),
                MAX_PUT_VALUE_BYTES
            )));
        }

        self.client
            .execute(
                Cow::Owned(format!(
                    "INSERT OR REPLACE INTO {} (vault_key, vault_value) VALUES (?, ?)",
                    self.table
                )),
                vec![Param::from(entry.key.clone()), Param::from(entry.value.clone())],
            )
            .await
            .map_err(map_hiqlite_error)?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        self.client
            .execute(
                Cow::Owned(format!("DELETE FROM {} WHERE vault_key = ?", self.table)),
                vec![Param::from(key)],
            )
            .await
            .map_err(map_hiqlite_error)?;

        Ok(())
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        let lock = self
            .client
            .lock(Cow::Owned(lock_name.to_string()))
            .await
            .map_err(map_hiqlite_error)?;
        Ok(Box::new(lock))
    }
}

fn parse_nodes(nodes_val: &Value) -> Result<Vec<Node>, RvError> {
    let nodes_arr = nodes_val.as_array().ok_or(RvError::ErrPhysicalConfigItemMissing)?;
    let mut nodes = Vec::new();
    for node_val in nodes_arr {
        let s = node_val.as_str().ok_or(RvError::ErrPhysicalConfigItemMissing)?;
        // Format: "id:raft_host:raft_port:api_host:api_port"
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 5 {
            return Err(RvError::ErrPhysicalConfigItemMissing);
        }
        let id: u64 = parts[0].parse().map_err(|_| RvError::ErrPhysicalConfigItemMissing)?;
        let addr_raft = format!("{}:{}", parts[1], parts[2]);
        let addr_api = format!("{}:{}", parts[3], parts[4]);
        nodes.push(Node {
            id,
            addr_raft,
            addr_api,
        });
    }
    Ok(nodes)
}

/// Verify that `host:port` is bindable in the current network namespace.
///
/// hiqlite passes `listen_addr_*` straight to axum's `TcpListener::bind`. If the
/// host resolves to an address the netns does not own (typical when an operator
/// puts an external FQDN in `listen_addr_*` while running rootless under pasta),
/// the bind fails with `EADDRNOTAVAIL` and the error is swallowed deep in the
/// listener task — operations.log shows a confident "api external listening on
/// ..." line while no socket is actually open. Probe with a short-lived bind
/// here so we surface the misconfiguration with the real OS error.
async fn preflight_bind(label: &str, host: &str, port: u16) -> Result<(), RvError> {
    let socket_addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            RvError::ErrCluster(format!(
                "hiqlite {label} listener: cannot resolve listen address '{host}:{port}': {e}"
            ))
        })?
        .collect();
    if socket_addrs.is_empty() {
        return Err(RvError::ErrCluster(format!(
            "hiqlite {label} listener: listen address '{host}:{port}' resolved to zero socket \
             addresses"
        )));
    }
    for addr in &socket_addrs {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            RvError::ErrCluster(format!(
                "hiqlite {label} listener: bind({addr}) failed: {e}. The configured listen_addr \
                 '{host}' resolves to an address this process cannot bind. Use '0.0.0.0' (or an \
                 IP owned by this network namespace) for listen_addr_{label}."
            ))
        })?;
        drop(listener);
    }
    Ok(())
}

impl HiqliteBackend {
    async fn new_backend(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let data_dir = conf
            .get("data_dir")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let node_id = conf
            .get("node_id")
            .and_then(|v| v.as_u64())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let secret_raft = conf
            .get("secret_raft")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let secret_api = conf
            .get("secret_api")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let table = conf
            .get("table")
            .and_then(|v| v.as_str())
            .unwrap_or("vault")
            .to_string();

        // hiqlite expects listen_addr to be host-only (e.g. "0.0.0.0");
        // it appends the port from the node's addr_raft/addr_api fields via build_listen_addr().
        let listen_addr_api = conf
            .get("listen_addr_api")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let listen_addr_raft = conf
            .get("listen_addr_raft")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");

        let port_raft: u16 = conf
            .get("port_raft")
            .and_then(|v| v.as_u64())
            .unwrap_or(8210) as u16;

        let port_api: u16 = conf
            .get("port_api")
            .and_then(|v| v.as_u64())
            .unwrap_or(8220) as u16;

        let nodes = if let Some(nodes_val) = conf.get("nodes") {
            parse_nodes(nodes_val)?
        } else {
            vec![Node {
                id: node_id,
                addr_raft: format!("{listen_addr_raft}:{port_raft}"),
                addr_api: format!("{listen_addr_api}:{port_api}"),
            }]
        };

        // Parse TLS configuration for Raft and API channels.
        // By default, TLS is enabled with auto-generated self-signed certificates
        // (ServerTlsConfig::TlsAutoCertificates). Peer authentication is handled by
        // secret_raft/secret_api; TLS provides PQC-protected confidentiality.
        let tls_raft_disable = conf
            .get("tls_raft_disable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tls_api_disable = conf
            .get("tls_api_disable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // NOTE: hiqlite 0.13.1's `ServerTlsConfigCerts::new(key, cert)` takes the
        // private key first and the certificate second — an unusual ordering that
        // is easy to invert when reading the call site. Calling it positionally
        // with `(cert, key)` puts cert content in the key slot, which makes
        // `axum-server::tls_rustls::RustlsConfig::from_pem_file` fail with
        // `The private key file contained no keys` during Raft/API bootstrap and
        // the node crash-loops. Use struct-literal construction with named fields
        // so the cert/key mapping can never be silently swapped again.
        // When operators sign the Raft/API certs with a private CA that the
        // container's trust store does not know about, hiqlite's rustls client
        // rejects peers with `invalid peer certificate: UnknownIssuer`. Mutual
        // peer authenticity is already enforced by secret_raft/secret_api, so
        // we expose an explicit opt-in switch (`tls_*_no_verify = true`) to
        // skip chain verification while keeping TLS for confidentiality. The
        // server side still presents its configured cert; only the client-side
        // verification of the peer's cert is relaxed.
        let tls_raft_no_verify = conf
            .get("tls_raft_no_verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tls_api_no_verify = conf
            .get("tls_api_no_verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tls_raft = if tls_raft_disable {
            None
        } else if let (Some(cert), Some(key)) = (
            conf.get("tls_raft_cert").and_then(|v| v.as_str()),
            conf.get("tls_raft_key").and_then(|v| v.as_str()),
        ) {
            Some(ServerTlsConfig::Specific(hiqlite::tls::ServerTlsConfigCerts {
                key: key.to_string().into(),
                cert: cert.to_string().into(),
                danger_tls_no_verify: tls_raft_no_verify,
            }))
        } else {
            Some(ServerTlsConfig::TlsAutoCertificates)
        };

        let tls_api = if tls_api_disable {
            None
        } else if let (Some(cert), Some(key)) = (
            conf.get("tls_api_cert").and_then(|v| v.as_str()),
            conf.get("tls_api_key").and_then(|v| v.as_str()),
        ) {
            Some(ServerTlsConfig::Specific(hiqlite::tls::ServerTlsConfigCerts {
                key: key.to_string().into(),
                cert: cert.to_string().into(),
                danger_tls_no_verify: tls_api_no_verify,
            }))
        } else {
            Some(ServerTlsConfig::TlsAutoCertificates)
        };

        if tls_raft_no_verify {
            log::warn!(
                "hiqlite: tls_raft_no_verify=true — peer cert chain verification is DISABLED \
                 for the Raft channel; peer authenticity relies on secret_raft only"
            );
        }
        if tls_api_no_verify {
            log::warn!(
                "hiqlite: tls_api_no_verify=true — peer cert chain verification is DISABLED \
                 for the API channel; peer authenticity relies on secret_api only"
            );
        }

        let api_scheme = if tls_api.is_some() { "https" } else { "http" };
        // Skip ureq's chain verification for the management API client when either:
        //   - the API channel uses hiqlite's auto-generated self-signed certs, or
        //   - the operator opted into tls_api_no_verify (e.g. private CA not in trust store).
        // Peer authenticity is enforced by the X-API-SECRET challenge-response either way.
        let tls_api_auto_certs =
            matches!(tls_api, Some(ServerTlsConfig::TlsAutoCertificates)) || tls_api_no_verify;

        // hiqlite requires encryption keys for backup/cookie encryption
        let mut enc_keys = cryptr::EncKeys {
            enc_key_active: String::new(),
            enc_keys: Vec::new(),
        };
        enc_keys
            .append_new_random_with_id("bvault-default".to_string())
            .map_err(|e| RvError::ErrCluster(e.to_string()))?;

        let node_config = NodeConfig {
            node_id,
            nodes,
            data_dir: Cow::Owned(data_dir.to_string()),
            listen_addr_api: Cow::Owned(listen_addr_api.to_string()),
            listen_addr_raft: Cow::Owned(listen_addr_raft.to_string()),
            secret_raft: secret_raft.to_string(),
            secret_api: secret_api.to_string(),
            enc_keys,
            tls_raft,
            tls_api,
            // Hiqlite's WAL panics (not errors) if any single Raft log entry
            // exceeds the segment size — see hiqlite-wal writer.rs:194. Default
            // is 2 MiB, but we accept files up to MAX_FILE_BYTES (32 MiB) plus
            // encryption/JSON overhead. 64 MiB leaves headroom and keeps the
            // ceiling well above any single entry we generate.
            wal_size: HIQLITE_WAL_SIZE,
            ..Default::default()
        };

        // Install aws_lc_rs as the default rustls crypto provider BEFORE hiqlite starts.
        // This gives us X25519MLKEM768 hybrid post-quantum key exchange in TLS 1.3.
        // hiqlite tries to install ring's provider in start_node(), but first-install-wins
        // semantics mean it will silently no-op since aws_lc_rs is already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Pre-flight bind probe. hiqlite's internal listener tasks swallow bind()
        // errors and only log a misleading "listening on ..." line, so a misconfigured
        // listen_addr (e.g. an external hostname inside a rootless pasta netns that
        // resolves to an IP the netns does not own) silently produces a node that
        // never accepts WebSocket connections — the cluster appears alive but the
        // client loops on "Connection refused" forever. Probe both ports here so
        // we crash with EADDRNOTAVAIL before any cluster state is touched.
        preflight_bind("raft", listen_addr_raft, port_raft).await?;
        preflight_bind("api", listen_addr_api, port_api).await?;

        // Surface whether we are about to start with an empty WAL (fresh/pristine
        // cluster) or resume from existing on-disk state. If the data volume has
        // silently been wiped (e.g. a Quadlet volume regression), the operator
        // sees "pristine" on every restart instead of having to infer it from
        // raft-internal log lines.
        let wal_meta = Path::new(data_dir).join("logs").join("meta.hql");
        if wal_meta.exists() {
            log::info!(
                "hiqlite: resuming from existing WAL at {} (node_id={node_id})",
                wal_meta.display()
            );
        } else {
            log::warn!(
                "hiqlite: no WAL found at {} — starting node_id={node_id} with PRISTINE state. \
                 If this is not a first boot, the data volume may have been wiped.",
                wal_meta.display()
            );
        }

        let client = hiqlite::start_node(node_config)
            .await
            .map_err(map_hiqlite_error)?;

        // Create the vault table if it doesn't exist
        client
            .batch(Cow::Owned(format!(
                "CREATE TABLE IF NOT EXISTS {} (vault_key TEXT NOT NULL PRIMARY KEY, vault_value BLOB NOT NULL)",
                table
            )))
            .await
            .map_err(map_hiqlite_error)?;

        let api_addr = format!("{api_scheme}://{listen_addr_api}:{port_api}");

        Ok(HiqliteBackend {
            client,
            table,
            api_addr,
            secret_api: secret_api.to_string(),
            node_id,
            tls_api_auto_certs,
            _runtime: None,
        })
    }

    /// Returns a reference to the underlying hiqlite client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns true if this node is the current Raft leader.
    pub async fn is_leader(&self) -> bool {
        self.client.is_leader_db().await
    }

    /// Returns true if the Raft database cluster is healthy *and this node can
    /// actually serve consistent reads*.
    ///
    /// hiqlite's `is_healthy_db()` only inspects this node's locally cached Raft
    /// metrics (running state + a known leader). That is necessary but not
    /// sufficient: an isolated leader whose heartbeat `AppendEntries` to its
    /// peers keep failing still shows a healthy local state while every
    /// linearizable read fails the read-index quorum confirmation. We layer a
    /// quorum-freshness check on top so "healthy" reflects read-serving
    /// capability — see [`QUORUM_ACK_STALE_MS`].
    pub async fn is_healthy(&self) -> bool {
        if self.client.is_healthy_db().await.is_err() {
            return false;
        }

        match self.client.metrics_db().await {
            Ok(metrics) => {
                // Only the leader maintains `millis_since_quorum_ack`; for a
                // follower the base check above is sufficient.
                if metrics.current_leader == Some(metrics.id) {
                    matches!(
                        metrics.millis_since_quorum_ack,
                        Some(ms) if ms <= QUORUM_ACK_STALE_MS
                    )
                } else {
                    true
                }
            }
            Err(_) => false,
        }
    }

    /// Returns Raft cluster metrics as a JSON value.
    pub async fn cluster_metrics(&self) -> Result<Value, RvError> {
        let metrics = self.client.metrics_db().await.map_err(map_hiqlite_error)?;
        serde_json::to_value(metrics).map_err(|e| RvError::ErrCluster(e.to_string()))
    }

    /// Returns this node's ID.
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Remove a node from the Raft cluster. Must be called on the leader.
    /// If `stay_as_learner` is true, the node is demoted to learner instead of fully removed.
    pub fn remove_node(&self, target_node_id: u64, stay_as_learner: bool) -> Result<(), RvError> {
        let url = format!("{}/cluster/membership/db", self.api_addr);
        let body = serde_json::json!({
            "node_id": target_node_id,
            "stay_as_learner": stay_as_learner,
        });

        let mut agent_builder = ureq::Agent::config_builder();
        if self.tls_api_auto_certs {
            // Auto-generated self-signed certs require skipping certificate verification.
            // Peer authentication is handled by the X-API-SECRET challenge-response.
            agent_builder = agent_builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .disable_verification(true)
                    .build(),
            );
        }
        let agent = agent_builder.build().new_agent();
        let req = http::Request::builder()
            .method("DELETE")
            .uri(&url)
            .header("X-API-SECRET", &self.secret_api)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body).map_err(|e| RvError::ErrCluster(e.to_string()))?)
            .map_err(|e| RvError::ErrCluster(e.to_string()))?;

        let resp = agent.run(req).map_err(|e| RvError::ErrCluster(e.to_string()))?;
        let status = resp.status().as_u16();

        if (200..300).contains(&status) {
            Ok(())
        } else {
            let text = resp.into_body().read_to_string().unwrap_or_default();
            Err(RvError::ErrCluster(format!("remove_node failed (HTTP {status}): {text}")))
        }
    }

    /// Gracefully shut down this node and leave the cluster.
    pub async fn leave_cluster(&self) -> Result<(), RvError> {
        self.client.shutdown().await.map_err(map_hiqlite_error)
    }

    /// Trigger a leader step-down to initiate a new election. Must be called on the leader.
    pub fn trigger_failover(&self) -> Result<(), RvError> {
        let url = format!("{}/cluster/step_down/db", self.api_addr);

        let mut agent_builder = ureq::Agent::config_builder();
        if self.tls_api_auto_certs {
            agent_builder = agent_builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .disable_verification(true)
                    .build(),
            );
        }
        let agent = agent_builder.build().new_agent();
        let req = http::Request::builder()
            .method("POST")
            .uri(&url)
            .header("X-API-SECRET", &self.secret_api)
            .body(Vec::new())
            .map_err(|e| RvError::ErrCluster(e.to_string()))?;

        let resp = agent.run(req).map_err(|e| RvError::ErrCluster(e.to_string()))?;
        let status = resp.status().as_u16();

        if (200..300).contains(&status) {
            Ok(())
        } else {
            let text = resp.into_body().read_to_string().unwrap_or_default();
            Err(RvError::ErrCluster(format!("failover failed (HTTP {status}): {text}")))
        }
    }

    pub fn new(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        // hiqlite is async-only; use a dedicated runtime to bridge sync construction.
        // The runtime must be kept alive because hiqlite spawns long-running background
        // tasks (Raft consensus, RPC servers) that are killed if the runtime is dropped.
        let needs_own_runtime = tokio::runtime::Handle::try_current().is_ok();

        if needs_own_runtime {
            // An outer runtime exists (e.g. actix, or a current-thread runtime used
            // by `Server::main` to bridge async backend bootstrap). We must NOT
            // create or drop the inner Runtime on the calling thread, because:
            //   - `block_on` from inside an async context is forbidden.
            //   - Dropping a multi-threaded `Runtime` is also forbidden inside an
            //     async context — `Drop` synchronously waits on the blocking pool,
            //     which panics with "Cannot drop a runtime in a context where
            //     blocking is not allowed".
            // The previous version created `rt` here in the caller's frame and only
            // moved `block_on` to a scoped thread. That left the `rt` drop on the
            // error path (`?` unwind) running on the caller's async worker, which
            // panicked and masked the real underlying error (e.g. peer TLS handshake
            // failure during Raft bootstrap).
            //
            // The fix: own the entire runtime lifecycle on a dedicated OS thread.
            // On error, `rt` drops on that thread (safe). On success, ownership
            // moves into `backend._runtime` and the backend is sent back across the
            // join. The eventual backend drop is handled by `Drop for HiqliteBackend`,
            // which already detaches runtime shutdown onto its own OS thread.
            let conf = conf.clone();
            std::thread::scope(|s| {
                s.spawn(move || -> Result<Self, RvError> {
                    let rt = tokio::runtime::Runtime::new()?;
                    let mut backend =
                        rt.block_on(async { Self::new_backend(&conf).await })?;
                    backend._runtime = Some(rt);
                    Ok(backend)
                })
                .join()
                .map_err(|_| {
                    RvError::ErrCluster(
                        "HiqliteBackend init thread panicked".to_string(),
                    )
                })?
            })
        } else {
            let rt = tokio::runtime::Runtime::new()?;
            let mut backend = rt.block_on(async { Self::new_backend(conf).await })?;
            backend._runtime = Some(rt);
            Ok(backend)
        }
    }
}

impl Drop for HiqliteBackend {
    fn drop(&mut self) {
        // Graceful shutdown: must run the client's async shutdown while the
        // owned runtime is still alive, then drop the runtime. Both `block_on`
        // and dropping a `Runtime` are forbidden inside another runtime's
        // worker thread (panics with "Cannot drop a runtime in a context where
        // blocking is not allowed"), so when we own a runtime we move the
        // shutdown + drop onto a dedicated OS thread.
        if let Some(rt) = self._runtime.take() {
            let client = self.client.clone();
            let joiner = std::thread::spawn(move || {
                let _ = rt.block_on(async move { client.shutdown().await });
                // `rt` drops here, on a plain OS thread — safe to block.
            });
            // If we're not inside an async runtime, wait for graceful shutdown
            // so tests and CLI exits are deterministic. Inside a runtime we
            // must not block the worker, so we let the thread finish detached.
            if tokio::runtime::Handle::try_current().is_err() {
                let _ = joiner.join();
            }
        } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            handle.spawn(async move {
                let _ = client.shutdown().await;
            });
        }
    }
}

#[cfg(all(test, feature = "storage_hiqlite"))]
mod test {
    use std::{collections::HashMap, env, fs};

    use serde_json::Value;
    use serial_test::serial;

    use super::HiqliteBackend;
    use crate::storage::test::{test_backend_curd, test_backend_list_prefix};
    use crate::test_utils::TEST_DIR;

    /// Returns true if hiqlite integration tests should run.
    /// Set CARGO_TEST_HIQLITE=1 to enable (requires free ports 18100/18200).
    fn should_run() -> bool {
        env::var("CARGO_TEST_HIQLITE").map_or(false, |v| v == "1")
    }

    fn make_test_conf(test_name: &str) -> HashMap<String, Value> {
        let dir = env::temp_dir().join(*TEST_DIR).join(test_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("data_dir".to_string(), Value::String(dir.to_string_lossy().into_owned()));
        conf.insert("node_id".to_string(), Value::Number(1.into()));
        conf.insert("secret_raft".to_string(), Value::String("test_raft_secret_1234".to_string()));
        conf.insert("secret_api".to_string(), Value::String("test_api_secret_12345".to_string()));
        conf.insert("table".to_string(), Value::String("vault_test".to_string()));
        conf.insert("listen_addr_api".to_string(), Value::String("127.0.0.1".to_string()));
        conf.insert("listen_addr_raft".to_string(), Value::String("127.0.0.1".to_string()));
        conf.insert("port_api".to_string(), Value::Number(18100.into()));
        conf.insert("port_raft".to_string(), Value::Number(18200.into()));
        conf
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_backend() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_backend");
        let backend = HiqliteBackend::new(&conf);
        assert!(backend.is_ok(), "Failed to create backend: {:?}", backend.err());
        let backend = backend.unwrap();

        // Clear the test table
        let _ = backend
            .client()
            .batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test"))
            .await;

        test_backend_curd(&backend).await;

        // Clear again before prefix test
        let _ = backend
            .client()
            .batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test"))
            .await;

        test_backend_list_prefix(&backend).await;
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_cluster_health() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_cluster_health");
        let backend = HiqliteBackend::new(&conf);
        assert!(backend.is_ok(), "Failed to create backend: {:?}", backend.err());
        let backend = backend.unwrap();

        // Single-node cluster should be leader
        assert!(backend.is_leader().await, "Single-node should be leader");

        // Single-node cluster should be healthy
        assert!(backend.is_healthy().await, "Single-node should be healthy");

        // Cluster metrics should be available
        let metrics = backend.cluster_metrics().await;
        assert!(metrics.is_ok(), "Cluster metrics should be available: {:?}", metrics.err());

        // Node ID should match config
        assert_eq!(backend.node_id(), 1);
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_migrate_from_file() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        
        use crate::storage::{new_backend, migrate::migrate_backend, BackendEntry};

        // Create source file backend with test data
        let source_dir = env::temp_dir().join(*TEST_DIR).join("test_migrate_source");
        let _ = fs::remove_dir_all(&source_dir);
        fs::create_dir_all(&source_dir).unwrap();

        let mut source_conf: HashMap<String, Value> = HashMap::new();
        source_conf.insert("path".to_string(), Value::String(source_dir.to_string_lossy().into_owned()));
        let source = new_backend("file", &source_conf).unwrap();

        // Write test entries
        let entries = vec![
            BackendEntry { key: "core/test".to_string(), value: b"core_data".to_vec() },
            BackendEntry { key: "logical/mount1/secret".to_string(), value: b"secret_data".to_vec() },
            BackendEntry { key: "logical/mount1/nested/key".to_string(), value: b"nested_data".to_vec() },
        ];
        for entry in &entries {
            source.put(entry).await.unwrap();
        }

        // Create destination hiqlite backend
        let dest_conf = make_test_conf("test_migrate_dest");
        let dest = new_backend("hiqlite", &dest_conf).unwrap();

        // Clear destination
        let dest_any = dest.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite) = dest_any.downcast_ref::<HiqliteBackend>() {
            let _ = hiqlite.client().batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test")).await;
        }

        // Run migration
        let result = migrate_backend(&source, &dest).await.unwrap();
        assert_eq!(result.entries_copied, 3);
        assert_eq!(result.entries_skipped, 0);

        // Verify all entries exist in destination
        for entry in &entries {
            let got = dest.get(&entry.key).await.unwrap();
            assert!(got.is_some(), "Entry {} not found in destination", entry.key);
            assert_eq!(got.unwrap().value, entry.value);
        }
    }

    /// Regression test: dropping a HiqliteBackend that owns a tokio Runtime
    /// from inside an outer tokio runtime previously panicked with
    /// "Cannot drop a runtime in a context where blocking is not allowed".
    /// The fix moves shutdown + runtime drop onto a detached OS thread.
    #[serial]
    #[tokio::test]
    async fn test_hiqlite_backend_drop_inside_runtime() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        // Outer runtime is present, so `new()` takes the `needs_own_runtime`
        // path and stores a Runtime in `_runtime`.
        assert!(tokio::runtime::Handle::try_current().is_ok());

        let conf = make_test_conf("test_hiqlite_backend_drop_inside_runtime");
        let backend = HiqliteBackend::new(&conf).expect("backend creation failed");
        assert!(
            backend._runtime.is_some(),
            "backend should own a runtime when constructed inside an outer runtime",
        );

        // Drop here, inside the outer runtime. Must not panic.
        drop(backend);
    }

    /// Regression test: when `HiqliteBackend::new` is called from inside an
    /// outer tokio runtime and the inner backend construction *fails*, the
    /// previous implementation panicked while unwinding `?` because the
    /// locally-created `rt` was dropped on a tokio worker thread. The fix
    /// owns the entire runtime lifecycle on a dedicated OS thread, so the
    /// error must propagate as an `Err` — never as a panic.
    ///
    /// This test does NOT require the hiqlite integration env (`CARGO_TEST_HIQLITE=1`)
    /// because it deliberately drives `new()` to fail before any port binds.
    #[serial]
    #[tokio::test]
    async fn test_hiqlite_backend_new_error_inside_runtime_does_not_panic() {
        // We must be inside an outer runtime so `new()` takes the
        // `needs_own_runtime` path — the path that used to panic on drop.
        assert!(tokio::runtime::Handle::try_current().is_ok());

        // Empty config — `new_backend` will fail extracting required keys
        // (e.g. `data_dir`/`node_id`) and return an Err. The runtime created
        // inside `new()` must be dropped cleanly on that error path.
        let conf: HashMap<String, Value> = HashMap::new();
        let res = HiqliteBackend::new(&conf);
        assert!(res.is_err(), "expected Err from empty config, got Ok");
    }
}
