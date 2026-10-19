use std::{any::Any, borrow::Cow, collections::HashMap, net::ToSocketAddrs, path::Path};

use hiqlite::{Client, Node, NodeConfig, Param, tls::ServerTlsConfig};
use serde_json::Value;
use tokio::net::TcpListener;

use bv_errors::RvError;
use bv_sql_guard::{sql, SqlIdent};

use crate::{Backend, BackendEntry};

mod paging;

use paging::{prefix_upper_bound, ListPager, PageLimits, PageStart, ScanPager, PAGE_ROW_OVERHEAD_BYTES};

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

/// `LIKE` pattern matching every key under `prefix`, wildcards escaped.
fn like_prefix_pattern(prefix: &str) -> String {
    format!("{}%", bv_sql_guard::escape_like(prefix))
}

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
    table: SqlIdent,
    /// Hiqlite API address for management HTTP calls (e.g., "https://127.0.0.1:8100")
    api_addr: String,
    /// Shared API secret for hiqlite management endpoints
    secret_api: String,
    /// This node's ID
    node_id: u64,
    /// Every configured peer endpoint as `host:port` (both the Raft and the
    /// management-API address of every entry in `nodes`, this node included).
    /// Kept verbatim rather than pre-resolved because the documented config
    /// form allows hostnames (`"1:bv-1:8210:bv-1:8220"` — compose/k8s DNS),
    /// whose addresses change across peer restarts. Consumers resolve on
    /// demand; see the cluster-local disclosure gate in the root crate's
    /// `http::sys` (this crate sits below the HTTP layer and cannot name it).
    peer_addrs: Vec<String>,
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
    fn backend_kind(&self) -> &'static str {
        "hiqlite"
    }

    /// Immediate children of `prefix`, `dir/` entries de-duplicated, in
    /// ascending order. Reads keys only, in bounded pages — see
    /// [`paging`] for the bounds and why the pages are not a snapshot.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        self.list_paged(prefix, PageLimits::DEFAULT).await
    }

    /// Bulk subtree read: every row whose `vault_key` starts with `prefix`
    /// (optionally bounded below by `start_key`), in ascending key order.
    /// Replaces the recursive `list` + per-key `get` walk — the 1+N
    /// linearizable reads that made audit/history aggregation take
    /// seconds — with one consistent query per bounded page (see
    /// [`paging`]). `start_key` pushes the time-window lower bound into
    /// SQL so chronologically-keyed logs read only the recent tail.
    async fn scan(&self, prefix: &str, start_key: Option<&str>) -> Result<Vec<BackendEntry>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        self.scan_paged(prefix, start_key, PageLimits::DEFAULT).await
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let result: Option<VaultRow> = self
            .client
            .query_consistent_map(
                sql!("SELECT vault_key, vault_value FROM {} WHERE vault_key = ?", &self.table).into_cow(),
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
                sql!("INSERT OR REPLACE INTO {} (vault_key, vault_value) VALUES (?, ?)", &self.table).into_cow(),
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
                sql!("DELETE FROM {} WHERE vault_key = ?", &self.table).into_cow(),
                vec![Param::from(key)],
            )
            .await
            .map_err(map_hiqlite_error)?;

        Ok(())
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        let lock = self
            .client
            .lock(Cow::Owned(lock_name.to_string()))
            .await
            .map_err(map_hiqlite_error)?;
        Ok(Box::new(lock))
    }
}

/// Parameters of the page queries, in their `?N` order:
/// `?1` LIKE pattern, `?2` lower bound (`>=`), `?3` excluded key (`IS NOT`,
/// `NULL` for none), `?4` exclusive upper bound — only when the range has
/// one —, then per-row overhead, max candidate rows and byte budget.
fn page_params(like: &str, start: &PageStart, upper: Option<&str>, limits: PageLimits) -> Vec<Param> {
    let (from, exclude) = start.sql_bounds();
    let mut params = vec![Param::from(like), Param::from(from), exclude.map_or(Param::Null, Param::from)];
    if let Some(upper) = upper {
        params.push(Param::from(upper));
    }
    params.extend([Param::from(PAGE_ROW_OVERHEAD_BYTES), Param::from(limits.max_rows), Param::from(limits.max_bytes)]);
    params
}

fn page_row_error(e: hiqlite::Error) -> RvError {
    RvError::ErrString(format!("hiqlite paged read: unexpected row shape: {e}"))
}

/// Paged reads behind `list` and `scan`; the paging rules live in
/// [`paging`]. Each statement below is one page: the inner query picks at
/// most `max_rows` keys of the range after the cursor, the window adds the
/// running byte total, and the outer query keeps the rows that fit the
/// budget (the first row always does) plus one all-`NULL` cut marker when
/// the budget ended the page. The `ESCAPE`d `LIKE` is redundant with the
/// range and kept as a second, independent narrowing; Rust's prefix test
/// in the pagers stays authoritative.
impl HiqliteBackend {
    async fn list_paged(&self, prefix: &str, limits: PageLimits) -> Result<Vec<String>, RvError> {
        let like = like_prefix_pattern(prefix);
        let upper = prefix_upper_bound(prefix);
        let mut pager = ListPager::new(prefix, limits);
        while let Some(start) = pager.next_start().cloned() {
            let rows = self.query_list_page(&like, &start, upper.as_deref(), limits).await?;
            pager.accept(rows)?;
        }
        Ok(pager.finish())
    }

    async fn scan_paged(
        &self,
        prefix: &str,
        start_key: Option<&str>,
        limits: PageLimits,
    ) -> Result<Vec<BackendEntry>, RvError> {
        let like = like_prefix_pattern(prefix);
        let upper = prefix_upper_bound(prefix);
        let mut pager = ScanPager::new(prefix, start_key, limits);
        while let Some(start) = pager.next_start().cloned() {
            let rows = self.query_scan_page(&like, &start, upper.as_deref(), limits).await?;
            pager.accept(rows)?;
        }
        Ok(pager.finish())
    }

    /// One page of full keys; `None` is the cut marker.
    async fn query_list_page(
        &self,
        like: &str,
        start: &PageStart,
        upper: Option<&str>,
        limits: PageLimits,
    ) -> Result<Vec<Option<String>>, RvError> {
        let stmt = match upper {
            Some(_) => sql!(
                "WITH page AS ( \
                     SELECT vault_key, row_bytes, \
                            ROW_NUMBER() OVER w AS page_row, \
                            SUM(row_bytes) OVER w AS page_bytes \
                     FROM ( \
                         SELECT vault_key, length(CAST(vault_key AS BLOB)) + ?5 AS row_bytes \
                         FROM {} \
                         WHERE vault_key LIKE ?1 ESCAPE '\\' AND vault_key >= ?2 AND vault_key IS NOT ?3 \
                           AND vault_key < ?4 \
                         ORDER BY vault_key \
                         LIMIT ?6 \
                     ) \
                     WINDOW w AS (ORDER BY vault_key ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) \
                 ) \
                 SELECT CASE WHEN page_row = 1 OR page_bytes <= ?7 THEN vault_key END AS vault_key \
                 FROM page \
                 WHERE page_row <= 2 OR page_bytes - row_bytes <= ?7 \
                 ORDER BY page_row",
                &self.table
            ),
            None => sql!(
                "WITH page AS ( \
                     SELECT vault_key, row_bytes, \
                            ROW_NUMBER() OVER w AS page_row, \
                            SUM(row_bytes) OVER w AS page_bytes \
                     FROM ( \
                         SELECT vault_key, length(CAST(vault_key AS BLOB)) + ?4 AS row_bytes \
                         FROM {} \
                         WHERE vault_key LIKE ?1 ESCAPE '\\' AND vault_key >= ?2 AND vault_key IS NOT ?3 \
                         ORDER BY vault_key \
                         LIMIT ?5 \
                     ) \
                     WINDOW w AS (ORDER BY vault_key ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) \
                 ) \
                 SELECT CASE WHEN page_row = 1 OR page_bytes <= ?6 THEN vault_key END AS vault_key \
                 FROM page \
                 WHERE page_row <= 2 OR page_bytes - row_bytes <= ?6 \
                 ORDER BY page_row",
                &self.table
            ),
        };
        self.client
            .query_consistent(stmt.into_cow(), page_params(like, start, upper, limits))
            .await
            .map_err(map_hiqlite_error)?
            .into_iter()
            .map(|mut row| row.try_get::<Option<String>>("vault_key").map_err(page_row_error))
            .collect()
    }

    /// One page of entries; `None` is the cut marker.
    async fn query_scan_page(
        &self,
        like: &str,
        start: &PageStart,
        upper: Option<&str>,
        limits: PageLimits,
    ) -> Result<Vec<Option<BackendEntry>>, RvError> {
        let stmt = match upper {
            Some(_) => sql!(
                "WITH page AS ( \
                     SELECT vault_key, row_bytes, \
                            ROW_NUMBER() OVER w AS page_row, \
                            SUM(row_bytes) OVER w AS page_bytes \
                     FROM ( \
                         SELECT vault_key, \
                                length(CAST(vault_key AS BLOB)) + length(vault_value) + ?5 AS row_bytes \
                         FROM {} \
                         WHERE vault_key LIKE ?1 ESCAPE '\\' AND vault_key >= ?2 AND vault_key IS NOT ?3 \
                           AND vault_key < ?4 \
                         ORDER BY vault_key \
                         LIMIT ?6 \
                     ) \
                     WINDOW w AS (ORDER BY vault_key ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) \
                 ) \
                 SELECT CASE WHEN page.page_row = 1 OR page.page_bytes <= ?7 THEN t.vault_key END AS vault_key, \
                        CASE WHEN page.page_row = 1 OR page.page_bytes <= ?7 THEN t.vault_value END AS vault_value \
                 FROM page JOIN {} AS t ON t.vault_key = page.vault_key \
                 WHERE page.page_row <= 2 OR page.page_bytes - page.row_bytes <= ?7 \
                 ORDER BY page.page_row",
                &self.table,
                &self.table
            ),
            None => sql!(
                "WITH page AS ( \
                     SELECT vault_key, row_bytes, \
                            ROW_NUMBER() OVER w AS page_row, \
                            SUM(row_bytes) OVER w AS page_bytes \
                     FROM ( \
                         SELECT vault_key, \
                                length(CAST(vault_key AS BLOB)) + length(vault_value) + ?4 AS row_bytes \
                         FROM {} \
                         WHERE vault_key LIKE ?1 ESCAPE '\\' AND vault_key >= ?2 AND vault_key IS NOT ?3 \
                         ORDER BY vault_key \
                         LIMIT ?5 \
                     ) \
                     WINDOW w AS (ORDER BY vault_key ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) \
                 ) \
                 SELECT CASE WHEN page.page_row = 1 OR page.page_bytes <= ?6 THEN t.vault_key END AS vault_key, \
                        CASE WHEN page.page_row = 1 OR page.page_bytes <= ?6 THEN t.vault_value END AS vault_value \
                 FROM page JOIN {} AS t ON t.vault_key = page.vault_key \
                 WHERE page.page_row <= 2 OR page.page_bytes - page.row_bytes <= ?6 \
                 ORDER BY page.page_row",
                &self.table,
                &self.table
            ),
        };
        self.client
            .query_consistent(stmt.into_cow(), page_params(like, start, upper, limits))
            .await
            .map_err(map_hiqlite_error)?
            .into_iter()
            .map(|mut row| {
                let key = row.try_get::<Option<String>>("vault_key").map_err(page_row_error)?;
                let value = row.try_get::<Option<Vec<u8>>>("vault_value").map_err(page_row_error)?;
                match (key, value) {
                    (Some(key), Some(value)) => Ok(Some(BackendEntry { key, value })),
                    (None, None) => Ok(None),
                    _ => Err(RvError::ErrString(
                        "hiqlite paged read: row with a key but no value, or a value but no key".to_string(),
                    )),
                }
            })
            .collect()
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

        // Validated once, at the boundary: an invalid `table` is a startup
        // error, never a statement fragment. `client.batch(..)` executes
        // `;`-separated statements, so this value must not be able to
        // terminate one.
        let table = SqlIdent::new(conf.get("table").and_then(|v| v.as_str()).unwrap_or("vault"))
            .map_err(|e| {
                RvError::ErrString(format!("hiqlite storage: `table` is not a valid SQL identifier: {e}"))
            })?;

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

        // `NodeConfig::enc_keys` only exists under hiqlite's `s3`/`dashboard`
        // features, which we build without — the ephemeral key we used to
        // generate here only ever encrypted hiqlite's own S3 backups and
        // dashboard cookies, neither of which BastionVault uses.

        // Snapshot the peer endpoints before `nodes` is moved into NodeConfig.
        let peer_addrs: Vec<String> = nodes
            .iter()
            .flat_map(|n| [n.addr_raft.clone(), n.addr_api.clone()])
            .collect();

        let node_config = NodeConfig {
            node_id,
            nodes,
            data_dir: Cow::Owned(data_dir.to_string()),
            listen_addr_api: Cow::Owned(listen_addr_api.to_string()),
            listen_addr_raft: Cow::Owned(listen_addr_raft.to_string()),
            secret_raft: secret_raft.to_string(),
            secret_api: secret_api.to_string(),
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

        // Create the vault table if it doesn't exist. NB: `batch` executes
        // multiple `;`-separated statements — the identifier must stay a
        // `SqlIdent` and the statement must stay a `sql!` literal.
        client
            .batch(
                sql!(
                    "CREATE TABLE IF NOT EXISTS {} (vault_key TEXT NOT NULL PRIMARY KEY, vault_value BLOB NOT NULL)",
                    &table
                )
                .into_cow(),
            )
            .await
            .map_err(map_hiqlite_error)?;

        let api_addr = format!("{api_scheme}://{listen_addr_api}:{port_api}");

        Ok(HiqliteBackend {
            client,
            table,
            api_addr,
            secret_api: secret_api.to_string(),
            node_id,
            peer_addrs,
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

    /// Every configured cluster endpoint as `host:port`, this node included.
    /// Hostnames are returned unresolved — see [`HiqliteBackend::peer_addrs`].
    pub fn peer_addrs(&self) -> &[String] {
        &self.peer_addrs
    }

    /// Remove a node from the Raft cluster. Must be called on the leader.
    /// If `stay_as_learner` is true, the node is demoted to learner instead of fully removed.
    pub fn remove_node(&self, target_node_id: u64, stay_as_learner: bool) -> Result<(), RvError> {
        // NB: the {raft_type} path segment deserializes via serde into hiqlite's
        // RaftType enum, so the only valid values are "sqlite" / "cache" — "db"
        // fails Path extraction with a 400 before reaching the handler.
        let url = format!("{}/cluster/membership/sqlite", self.api_addr);
        let body = serde_json::json!({
            "node_id": target_node_id,
            "stay_as_learner": stay_as_learner,
        });

        // Report 4xx/5xx through our own status branch (with the response body)
        // instead of ureq's bare "http status: NNN" transport error.
        let mut agent_builder = ureq::Agent::config_builder().http_status_as_error(false);
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
    ///
    /// openraft 0.9 has no leader-side step-down API, so the step-down is
    /// driven from the other end: a follower's `/cluster/step_down` endpoint
    /// (a fork addition) makes that follower start an election with a higher
    /// term, which this leader observes and yields to. We resolve a follower
    /// voter from the current membership and POST there.
    pub async fn trigger_failover(&self) -> Result<(), RvError> {
        let metrics = self.client.metrics_db().await.map_err(map_hiqlite_error)?;
        let leader_id = metrics
            .current_leader
            .ok_or(RvError::ErrClusterNoLeader)?;
        if leader_id != self.node_id {
            return Err(RvError::ErrCluster(format!(
                "this node ({}) is not the leader ({leader_id}); run failover against the leader",
                self.node_id
            )));
        }

        let follower = metrics
            .membership_config
            .voter_ids()
            .filter(|id| *id != leader_id)
            .find_map(|id| metrics.membership_config.membership().get_node(&id))
            .ok_or_else(|| {
                RvError::ErrCluster(
                    "no follower voter available to take over leadership".to_string(),
                )
            })?;

        let scheme = self
            .api_addr
            .split_once("://")
            .map_or("http", |(scheme, _)| scheme);
        // "sqlite", not "db" — see the raft_type note in remove_node().
        let url = format!("{scheme}://{}/cluster/step_down/sqlite", follower.addr_api);

        // As in remove_node: keep 4xx/5xx as responses so the error carries the body.
        let mut agent_builder = ureq::Agent::config_builder().http_status_as_error(false);
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

    use super::{
        like_prefix_pattern, prefix_upper_bound, HiqliteBackend, PageLimits, ScanPager, VaultRow,
        PAGE_ROW_OVERHEAD_BYTES,
    };
    use bv_sql_guard::sql;
    use hiqlite::Param;
    use crate::test::{
        test_backend_curd, test_backend_list_prefix, test_backend_list_prefix_is_literal,
    };
    use crate::{Backend, BackendEntry};
    use crate::test_support::TEST_DIR;

    /// Returns true if hiqlite integration tests should run.
    /// Set CARGO_TEST_HIQLITE=1 to enable (requires free ports from 18100/18200 up).
    fn should_run() -> bool {
        env::var("CARGO_TEST_HIQLITE").map_or(false, |v| v == "1")
    }

    /// Each conf gets its own port pair: a dropped backend releases its
    /// listeners asynchronously (detached graceful shutdown), so consecutive
    /// tests reusing fixed ports race it and fail with "Address already in use"
    /// even under `#[serial]`.
    static NEXT_PORT_OFFSET: std::sync::atomic::AtomicU16 =
        std::sync::atomic::AtomicU16::new(0);

    fn make_test_conf(test_name: &str) -> HashMap<String, Value> {
        let dir = env::temp_dir().join(TEST_DIR).join(test_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let offset = NEXT_PORT_OFFSET.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("data_dir".to_string(), Value::String(dir.to_string_lossy().into_owned()));
        conf.insert("node_id".to_string(), Value::Number(1.into()));
        conf.insert("secret_raft".to_string(), Value::String("test_raft_secret_1234".to_string()));
        conf.insert("secret_api".to_string(), Value::String("test_api_secret_12345".to_string()));
        conf.insert("table".to_string(), Value::String("vault_test".to_string()));
        conf.insert("listen_addr_api".to_string(), Value::String("127.0.0.1".to_string()));
        conf.insert("listen_addr_raft".to_string(), Value::String("127.0.0.1".to_string()));
        conf.insert("port_api".to_string(), Value::Number((18100 + offset).into()));
        conf.insert("port_raft".to_string(), Value::Number((18200 + offset).into()));
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
            .batch(sql!("DELETE FROM vault_test").into_cow())
            .await;

        test_backend_curd(&backend).await;

        // Clear again before prefix test
        let _ = backend
            .client()
            .batch(sql!("DELETE FROM vault_test").into_cow())
            .await;

        test_backend_list_prefix(&backend).await;
    }

    /// Regression: `list`/`scan` must not leak a sibling subtree whose
    /// key merely *matches* the `LIKE` pattern.
    ///
    /// `_` is a single-character `LIKE` wildcard, and vault keys carry
    /// `_` routinely, so listing `secret/my_app/` used to also match
    /// `secret/myXapp/…`. Worse, the excess rows were not filtered:
    /// `trim_start_matches` is a no-op on a key that does not start with
    /// the prefix, so the foreign key came back verbatim.
    #[serial]
    #[tokio::test]
    async fn test_hiqlite_list_does_not_leak_like_wildcard_matches() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_like_wildcard");
        let backend = HiqliteBackend::new(&conf).expect("backend creation failed");
        let _ = backend
            .client()
            .batch(sql!("DELETE FROM vault_test").into_cow())
            .await;

        for key in [
            "secret/my_app/db",
            "secret/my_app/nested/token",
            // The impostor: matches `secret/my_app/%` only because `_`
            // is a wildcard.
            "secret/myXapp/db",
            // `%` is a wildcard too.
            "secret/my%app/db",
        ] {
            backend
                .put(&BackendEntry { key: key.to_string(), value: b"v".to_vec() })
                .await
                .unwrap();
        }

        // Cross-backend contract check on a clean table.
        test_backend_list_prefix_is_literal(&backend).await;

        let mut keys = backend.list("secret/my_app/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["db".to_string(), "nested/".to_string()]);

        let mut scanned: Vec<String> = backend
            .scan("secret/my_app/", None)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.key)
            .collect();
        scanned.sort();
        assert_eq!(
            scanned,
            vec![
                "secret/my_app/db".to_string(),
                "secret/my_app/nested/token".to_string()
            ]
        );

        // The `%`-bearing prefix is likewise treated literally, not as
        // "every key under secret/my".
        let keys = backend.list("secret/my%app/").await.unwrap();
        assert_eq!(keys, vec!["db".to_string()]);
    }

    /// The pre-pagination read: the single unbounded `LIKE` query `list`
    /// and `scan` used to run, kept here as the reference the paged reads
    /// must reproduce.
    async fn legacy_rows(backend: &HiqliteBackend, prefix: &str, start_key: Option<&str>) -> Vec<VaultRow> {
        let like = Param::from(like_prefix_pattern(prefix));
        match start_key {
            Some(start) => backend
                .client()
                .query_consistent_map(
                    sql!("SELECT vault_key, vault_value FROM vault_test WHERE vault_key LIKE ? ESCAPE '\\' AND vault_key >= ?")
                        .into_cow(),
                    vec![like, Param::from(start)],
                )
                .await
                .unwrap(),
            None => backend
                .client()
                .query_consistent_map(
                    sql!("SELECT vault_key, vault_value FROM vault_test WHERE vault_key LIKE ? ESCAPE '\\'").into_cow(),
                    vec![like],
                )
                .await
                .unwrap(),
        }
    }

    /// The pre-pagination `list` post-processing, verbatim in effect, sorted
    /// because the legacy query had no `ORDER BY`.
    async fn legacy_list(backend: &HiqliteBackend, prefix: &str) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for row in legacy_rows(backend, prefix, None).await {
            let Some(rest) = row.vault_key.strip_prefix(prefix) else { continue };
            match rest.find('/') {
                Some(i) => {
                    let child = rest[..=i].to_string();
                    if !keys.contains(&child) {
                        keys.push(child);
                    }
                }
                None => keys.push(rest.to_string()),
            }
        }
        keys.sort();
        keys
    }

    async fn legacy_scan(backend: &HiqliteBackend, prefix: &str, start_key: Option<&str>) -> Vec<BackendEntry> {
        let mut entries: Vec<BackendEntry> = legacy_rows(backend, prefix, start_key)
            .await
            .into_iter()
            .filter(|row| row.vault_key.starts_with(prefix))
            .map(|row| BackendEntry { key: row.vault_key, value: row.vault_value })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// Paged `list`/`scan` return exactly what the single unbounded query
    /// returned, on the real SQL, for page sizes from one row up to the
    /// production defaults — and no page outgrows its byte budget.
    #[serial]
    #[tokio::test]
    async fn test_hiqlite_paged_list_and_scan_match_unpaged() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_paged_list_scan");
        let backend = HiqliteBackend::new(&conf).expect("backend creation failed");
        let _ = backend.client().batch(sql!("DELETE FROM vault_test").into_cow()).await;

        let mut keys: Vec<(String, usize)> = Vec::new();
        // A chronologically keyed append log, values of uneven size, one
        // value larger than any test budget below.
        for i in 0..120usize {
            keys.push((format!("audit/{:020}", 1_000 + i), (i * 37) % 600));
        }
        keys.push(("audit/00000000000000099999".to_string(), 8 * 1024));
        // A tree: nested directories, a key equal to the listed prefix, a
        // key ending in '/', and siblings sorting right around `kv/`.
        for d in 0..4 {
            for i in 0..6 {
                keys.push((format!("kv/dir{d}/leaf{i}"), 16));
                keys.push((format!("kv/dir{d}/sub/deep{i}"), 16));
            }
            keys.push((format!("kv/leaf{d}"), 16));
        }
        for k in ["kv/", "kv/dir0/", "kv", "kv.", "kv0"] {
            keys.push((k.to_string(), 4));
        }
        // LIKE wildcards, the escape character, an ASCII-case variant that
        // SQLite's LIKE matches, and their impostors.
        for k in ["w/my_app/a", "w/my_app/b/c", "w/myXapp/a", "w/my%app/a", "w/myZZapp/a", r"w/my\app/a", "w/MY_APP/a"]
        {
            keys.push((k.to_string(), 4));
        }
        for k in ["u/é", "u/\u{D7FF}/x", "u/\u{E000}/y"] {
            keys.push((k.to_string(), 4));
        }
        for (key, len) in &keys {
            let value: Vec<u8> = (0..*len).map(|i| (i % 251) as u8).collect();
            backend.put(&BackendEntry { key: key.clone(), value }).await.unwrap();
        }

        let limit_sets = [
            PageLimits { max_rows: 1, max_bytes: 1 },
            PageLimits { max_rows: 3, max_bytes: 600 },
            PageLimits { max_rows: 7, max_bytes: 2048 },
            PageLimits::DEFAULT,
        ];

        for prefix in ["", "audit/", "kv/", "kv/dir1/", "kv/dir0/sub/", "w/", "w/my_app/", "w/my%app/", r"w/my\app/", "u/", "none/"] {
            let expected = legacy_list(&backend, prefix).await;
            assert_eq!(backend.list(prefix).await.unwrap(), expected, "list {prefix:?}");
            for limits in limit_sets {
                assert_eq!(backend.list_paged(prefix, limits).await.unwrap(), expected, "list {prefix:?} {limits:?}");
            }
        }
        assert_eq!(backend.list("w/my_app/").await.unwrap(), vec!["a".to_string(), "b/".to_string()]);

        let scans: &[(&str, Option<&str>)] = &[
            ("", None),
            ("audit/", None),
            ("audit/", Some("audit/00000000000000001050")),
            ("audit/", Some("audit/000000000000000010505")), // between two keys
            ("audit/", Some("a")),                              // below the prefix
            ("audit/", Some("audit0")),                         // above the range
            ("kv/", None),
            ("kv/", Some("kv/dir2/")),
            ("w/my_app/", None),
            ("w/my%app/", None),
            (r"w/my\app/", None),
            ("u/", None),
            ("none/", None),
        ];
        for (prefix, start) in scans {
            let expected = legacy_scan(&backend, prefix, *start).await;
            assert_eq!(backend.scan(prefix, *start).await.unwrap(), expected, "scan {prefix:?} {start:?}");
            for limits in limit_sets {
                assert_eq!(
                    backend.scan_paged(prefix, *start, limits).await.unwrap(),
                    expected,
                    "scan {prefix:?} {start:?} {limits:?}"
                );
            }
        }

        // Drive the scan pager by hand to see each real page: the byte
        // budget (not the row limit) splits it, the cut marker appears,
        // and no page carries more than max(budget, its first row).
        let limits = PageLimits { max_rows: 1_000, max_bytes: 2048 };
        let like = like_prefix_pattern("audit/");
        let upper = prefix_upper_bound("audit/");
        let mut pager = ScanPager::new("audit/", None, limits);
        let (mut pages, mut markers) = (0, 0);
        while let Some(start) = pager.next_start().cloned() {
            let rows = backend.query_scan_page(&like, &start, upper.as_deref(), limits).await.unwrap();
            markers += rows.iter().filter(|r| r.is_none()).count();
            let data: Vec<&BackendEntry> = rows.iter().flatten().collect();
            let bytes: i64 =
                data.iter().map(|e| (e.key.len() + e.value.len()) as i64 + PAGE_ROW_OVERHEAD_BYTES).sum();
            assert!(data.len() == 1 || bytes <= limits.max_bytes, "page of {} rows carries {bytes} bytes", data.len());
            pager.accept(rows).unwrap();
            pages += 1;
        }
        assert_eq!(pager.finish(), legacy_scan(&backend, "audit/", None).await);
        assert!(pages > 10 && markers > 0, "budget must split the scan: {pages} pages, {markers} cut markers");

        // Malformed input is still rejected before any query.
        assert!(backend.list("/audit/").await.is_err());
        assert!(backend.scan("/audit/", None).await.is_err());
    }

    #[test]
    fn test_escape_like_prefix_neutralizes_wildcards() {
        assert_eq!(like_prefix_pattern("secret/my_app/"), r"secret/my\_app/%");
        assert_eq!(like_prefix_pattern(""), "%");
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

    /// Regression test for the cluster-reporting bug fixed in 0.41.19: a
    /// live hiqlite node reported `storage_type: "file"`, `cluster: false`
    /// and (on a follower) `standby: false` to every operator surface,
    /// because the crates doing the reporting inferred the backend by
    /// downcast -- behind a feature they were not compiled with, and
    /// without peeling the read-cache decorator.
    ///
    /// Both halves are asserted here, on a real backend: the kind the
    /// backend reports about itself, and the cluster view taken through
    /// `crate::cluster`, bare and behind the cache decorator.
    #[serial]
    #[tokio::test]
    async fn test_hiqlite_reports_itself_as_a_cluster() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        use std::sync::Arc;

        let conf = make_test_conf("test_hiqlite_cluster_reporting");
        let backend: Arc<dyn Backend> = Arc::new(HiqliteBackend::new(&conf).unwrap());

        assert_eq!(backend.backend_kind(), "hiqlite", "the backend must name itself");

        let status = crate::cluster::status(backend.as_ref()).await.expect("a hiqlite backend is a cluster");
        assert_eq!(status.node_id, 1);
        assert!(status.is_leader, "single-node cluster is its own leader");
        assert!(status.healthy);
        assert!(status.raft_metrics.is_some(), "raft metrics must reach the operator surface");
        assert_eq!(crate::cluster::node_id(backend.as_ref()), Some(1));

        // Same answers behind the ciphertext read cache -- which is what
        // `Core::physical` is whenever `cache.secret_cache_ttl_secs > 0`.
        let cached: Arc<dyn Backend> = Arc::new(crate::cache::CachingBackend::new(backend, 16, 30).unwrap());
        assert_eq!(cached.backend_kind(), "hiqlite");
        let via_cache =
            crate::cluster::status(cached.as_ref()).await.expect("the cache decorator must not hide the cluster");
        assert_eq!(via_cache.node_id, 1);
        assert!(via_cache.is_leader);
        assert_eq!(crate::cluster::node_id(cached.as_ref()), Some(1));
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_migrate_from_file() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        
        use crate::{new_backend, migrate::migrate_backend, BackendEntry};

        // Create source file backend with test data
        let source_dir = env::temp_dir().join(TEST_DIR).join("test_migrate_source");
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
            let _ = hiqlite.client().batch(sql!("DELETE FROM vault_test").into_cow()).await;
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
