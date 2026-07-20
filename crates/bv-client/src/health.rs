//! Health screen + scoring for the discovery → connect pipeline.
//!
//! Given a candidate list from [`crate::discovery`], probe each
//! node's `/v1/sys/health` endpoint, classify the response into one
//! of [`NodeState`]'s buckets, and pick the best survivor according
//! to the rules from the feature spec:
//!
//! 1. SRV priority is a hard floor — never consider a lower-priority
//!    node when a higher-priority node is healthy.
//! 2. Within a priority bucket, prefer the active leader; followers
//!    are accepted but ranked below.
//! 3. Within the same (priority, state) bucket, prefer lower RTT.
//! 4. Within the same (priority, state, rtt) bucket, prefer higher
//!    SRV weight. We use a deterministic sort rather than RFC 2782
//!    weighted-random — operators want repeatable picks in tests and
//!    diagnostics, and weight tie-breaking only matters in practice
//!    when all earlier criteria are equal anyway.
//!
//! Probes are HTTP via `ureq` on a blocking thread pool — the rest
//! of the crate already commits to this style. Each probe runs with
//! its own short-timeout `Agent` so a slow node can't drag the whole
//! selection past the wall-clock budget.

use std::time::{Duration, Instant};

use http::Request;
use serde::Deserialize;
use ureq::Agent;

use crate::{
    discovery::SrvCandidate,
    tls::ClientTlsConfig,
};

/// Classified state of a single node. `ActiveLeader` and `Follower`
/// are the only states the selector will route to; the rest are
/// rejection reasons preserved for logging / diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeState {
    ActiveLeader,
    Follower,
    Sealed,
    Uninitialized,
    Unreachable(String),
}

impl NodeState {
    /// Lower rank wins. Used as the second sort key after SRV
    /// priority. `Unreachable` / `Sealed` / `Uninitialized` are not
    /// supposed to reach the sort path — they're filtered out — but
    /// we still return a sentinel so a bug in the filter is loud.
    fn rank(&self) -> u8 {
        match self {
            NodeState::ActiveLeader => 0,
            NodeState::Follower => 1,
            _ => 255,
        }
    }

    /// True for states the selector will route requests to.
    pub fn is_healthy(&self) -> bool {
        matches!(self, NodeState::ActiveLeader | NodeState::Follower)
    }
}

/// Subset of the Vault-compatible `/sys/health` JSON the classifier
/// inspects. `#[serde(default)]` keeps us resilient when a server
/// version omits one of the optional booleans.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HealthResponse {
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub sealed: bool,
    #[serde(default)]
    pub standby: bool,
    #[serde(default)]
    pub performance_standby: bool,
    pub cluster_id: Option<String>,
    pub version: Option<String>,
}

/// Pure mapping from a parsed health response to a [`NodeState`].
/// Lifted out of the probe so every row of the classification table
/// is easy to unit-test.
pub fn classify(resp: &HealthResponse) -> NodeState {
    if !resp.initialized {
        return NodeState::Uninitialized;
    }
    if resp.sealed {
        return NodeState::Sealed;
    }
    if resp.standby || resp.performance_standby {
        return NodeState::Follower;
    }
    NodeState::ActiveLeader
}

/// One probe result. Always present in the slice returned by
/// [`probe_all`], even for unreachable nodes — keeps the diagnostics
/// surface complete so a future `bvault cluster discover` (or the
/// GUI's diagnostics panel) can render every candidate's outcome.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub candidate: SrvCandidate,
    pub state: NodeState,
    /// Wall-clock RTT of the probe. `0` for unreachable / timed-out
    /// probes so a sort-by-rtt tiebreak never confuses them with a
    /// fast healthy node (they're filtered out first regardless).
    pub rtt_ms: u32,
    pub cluster_id: Option<String>,
    pub version: Option<String>,
}

/// What the caller wires into `RemoteBackend`. Carries enough info
/// for log/UI surfacing ("Connected to <cluster> via <node>, leader,
/// 12 ms").
#[derive(Debug, Clone)]
pub struct Selected {
    pub candidate: SrvCandidate,
    pub state: NodeState,
    pub rtt_ms: u32,
    pub cluster_id: Option<String>,
    pub version: Option<String>,
}

/// Knobs that shape the probe. Defaults match the feature spec.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Per-probe deadline. The selector waits up to this long for
    /// each candidate; slow nodes are classified `Unreachable` and
    /// skipped.
    pub probe_timeout: Duration,
    /// Maximum concurrent probes. Real clusters are small so the
    /// default just runs everything in parallel.
    pub parallelism: u8,
    /// When `true`, discovery health probes honour the system proxy (the
    /// `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` environment variables ureq
    /// reads by default). When `false` (the default) the proxy is explicitly
    /// cleared so probes take the same path as the data-plane client.
    pub use_system_proxy: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_millis(1500),
            parallelism: 4,
            use_system_proxy: false,
        }
    }
}

/// Probe every candidate concurrently. Returns one [`ProbeResult`]
/// per input candidate in the SAME ORDER (the caller can correlate
/// without juggling identifiers). Network/TLS/parse failures all
/// fold into `NodeState::Unreachable(reason)` — never an `Err` from
/// this function, so the selector always has a complete picture to
/// reason about.
pub async fn probe_all(
    candidates: &[SrvCandidate],
    cfg: &HealthConfig,
    tls: Option<&ClientTlsConfig>,
) -> Vec<ProbeResult> {
    let agent = build_probe_agent(cfg.probe_timeout, tls, cfg.use_system_proxy);
    let parallelism = cfg.parallelism.max(1) as usize;

    let mut handles: Vec<tokio::task::JoinHandle<(usize, ProbeResult)>> =
        Vec::with_capacity(candidates.len().min(parallelism));
    let mut iter = candidates.iter().cloned().enumerate();

    // Prime the first chunk.
    for _ in 0..parallelism {
        if let Some((idx, cand)) = iter.next() {
            let agent = agent.clone();
            handles.push(tokio::spawn(async move {
                (idx, probe_one(&agent, &cand).await)
            }));
        }
    }

    let mut results: Vec<(usize, ProbeResult)> = Vec::with_capacity(candidates.len());
    while !handles.is_empty() {
        // Drain in arrival order, then refill from the iterator. We
        // can't tokio::select! over a Vec, so a sequential await is
        // fine here — the futures themselves are running in parallel
        // via `tokio::spawn`. The select_all variant would shave a
        // few µs but adds a `futures-util` dep we don't otherwise
        // need.
        let h = handles.remove(0);
        let v = h.await.expect("probe future panicked");
        results.push(v);
        if let Some((idx, cand)) = iter.next() {
            let agent = agent.clone();
            handles.push(tokio::spawn(async move {
                (idx, probe_one(&agent, &cand).await)
            }));
        }
    }

    results.sort_by_key(|(idx, _)| *idx);
    results.into_iter().map(|(_, r)| r).collect()
}

fn build_probe_agent(
    timeout: Duration,
    tls: Option<&ClientTlsConfig>,
    use_system_proxy: bool,
) -> Agent {
    let mut cfg = ureq::Agent::config_builder()
        .timeout_connect(Some(timeout))
        .timeout_global(Some(timeout))
        .http_status_as_error(false);
    if let Some(t) = tls {
        cfg = cfg.tls_config(t.tls_config.clone());
    }
    // ureq picks up the system proxy from the environment by default; clear
    // it unless opted in so probes match the data-plane client's routing.
    if !use_system_proxy {
        cfg = cfg.proxy(None);
    }
    cfg.build().new_agent()
}

async fn probe_one(agent: &Agent, cand: &SrvCandidate) -> ProbeResult {
    let url = format!("{}/v1/sys/health", cand.url());
    let cand_for_thread = cand.clone();
    let agent = agent.clone();

    let join = tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let req = match Request::builder()
            .method("GET")
            .uri(&url)
            .header("Accept", "application/json")
            .body(())
        {
            Ok(r) => r,
            Err(e) => {
                return ProbeResult {
                    candidate: cand_for_thread,
                    state: NodeState::Unreachable(format!("request build: {e}")),
                    rtt_ms: 0,
                    cluster_id: None,
                    version: None,
                };
            }
        };
        let response = match agent.run(req) {
            Ok(r) => r,
            Err(e) => {
                return ProbeResult {
                    candidate: cand_for_thread,
                    state: NodeState::Unreachable(format!("transport: {e}")),
                    rtt_ms: rtt_ms_from(start),
                    cluster_id: None,
                    version: None,
                };
            }
        };
        let mut response = response;
        let status = response.status().as_u16();
        let bytes = match response.body_mut().read_to_vec() {
            Ok(b) => b,
            Err(e) => {
                return ProbeResult {
                    candidate: cand_for_thread,
                    state: NodeState::Unreachable(format!("body: {e}")),
                    rtt_ms: rtt_ms_from(start),
                    cluster_id: None,
                    version: None,
                };
            }
        };

        // /sys/health uses status codes to mirror the health state
        // (200 active, 429 standby, 472 perf-standby, 473 dr,
        // 501 uninit, 503 sealed). The body is authoritative for
        // our classifier — non-JSON success is still a probe
        // failure though.
        let parsed: HealthResponse = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return ProbeResult {
                    candidate: cand_for_thread,
                    state: NodeState::Unreachable(format!(
                        "parse health body (HTTP {status}): {e}"
                    )),
                    rtt_ms: rtt_ms_from(start),
                    cluster_id: None,
                    version: None,
                };
            }
        };

        let state = classify(&parsed);
        ProbeResult {
            candidate: cand_for_thread,
            state,
            rtt_ms: rtt_ms_from(start),
            cluster_id: parsed.cluster_id,
            version: parsed.version,
        }
    })
    .await;

    match join {
        Ok(r) => r,
        Err(e) => ProbeResult {
            candidate: cand.clone(),
            state: NodeState::Unreachable(format!("join: {e}")),
            rtt_ms: 0,
            cluster_id: None,
            version: None,
        },
    }
}

fn rtt_ms_from(start: Instant) -> u32 {
    start.elapsed().as_millis().min(u32::MAX as u128) as u32
}

/// Reject the minority cluster_id when the probed set disagrees.
/// Returns the dominant cluster_id (`None` if every node reported
/// `None`). Ties between two non-empty ids are broken in favor of
/// the one belonging to the highest-ranking probe (leader > follower,
/// lower priority bucket beats higher) so a stale follower from a
/// decommissioned cluster can't outvote a freshly-elected leader.
fn dominant_cluster_id(probes: &[&ProbeResult]) -> Option<String> {
    use std::collections::HashMap;
    let mut tally: HashMap<&str, (usize, u8, u16)> = HashMap::new();
    for p in probes {
        if let Some(id) = p.cluster_id.as_deref() {
            let entry = tally.entry(id).or_insert((0, 255, u16::MAX));
            entry.0 += 1;
            entry.1 = entry.1.min(p.state.rank());
            entry.2 = entry.2.min(p.candidate.priority);
        }
    }
    tally
        .into_iter()
        .max_by(|a, b| {
            a.1.0
                .cmp(&b.1.0)
                .then_with(|| b.1.1.cmp(&a.1.1))
                .then_with(|| b.1.2.cmp(&a.1.2))
        })
        .map(|(id, _)| id.to_string())
}

/// Pick the best probed node, or return `None` if nothing is
/// reachable + healthy. Pure function — no I/O — so tests can feed
/// it synthetic probe lists.
pub fn pick(probes: &[ProbeResult]) -> Option<Selected> {
    let healthy: Vec<&ProbeResult> = probes.iter().filter(|p| p.state.is_healthy()).collect();
    if healthy.is_empty() {
        return None;
    }

    // Hard SRV-priority floor.
    let min_priority = healthy.iter().map(|p| p.candidate.priority).min().unwrap();
    let bucket: Vec<&ProbeResult> = healthy
        .into_iter()
        .filter(|p| p.candidate.priority == min_priority)
        .collect();

    // Cluster_id sanity check.
    let dominant = dominant_cluster_id(&bucket);
    let in_dominant: Vec<&ProbeResult> = bucket
        .iter()
        .copied()
        .filter(|p| match (&dominant, &p.cluster_id) {
            (Some(d), Some(pid)) => d == pid,
            // No cluster_id reported → keep (older servers).
            (_, None) => true,
            // No dominant id (nobody had one) → keep everyone.
            (None, _) => true,
        })
        .collect();

    if in_dominant.is_empty() {
        return None;
    }

    let best = in_dominant
        .into_iter()
        .min_by(|a, b| {
            a.state
                .rank()
                .cmp(&b.state.rank())
                .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
                .then_with(|| b.candidate.weight.cmp(&a.candidate.weight))
        })?
        .clone();

    Some(Selected {
        candidate: best.candidate,
        state: best.state,
        rtt_ms: best.rtt_ms,
        cluster_id: best.cluster_id,
        version: best.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(target: &str, priority: u16, weight: u16) -> SrvCandidate {
        SrvCandidate {
            target: target.to_string(),
            port: 8200,
            scheme: "https".to_string(),
            priority,
            weight,
        }
    }

    fn probe(
        target: &str,
        priority: u16,
        weight: u16,
        state: NodeState,
        rtt_ms: u32,
        cluster_id: Option<&str>,
    ) -> ProbeResult {
        ProbeResult {
            candidate: cand(target, priority, weight),
            state,
            rtt_ms,
            cluster_id: cluster_id.map(String::from),
            version: None,
        }
    }

    #[test]
    fn classify_active_leader() {
        let r = HealthResponse { initialized: true, sealed: false, standby: false, performance_standby: false, ..Default::default() };
        assert_eq!(classify(&r), NodeState::ActiveLeader);
    }

    #[test]
    fn classify_follower_standby() {
        let r = HealthResponse { initialized: true, sealed: false, standby: true, performance_standby: false, ..Default::default() };
        assert_eq!(classify(&r), NodeState::Follower);
    }

    #[test]
    fn classify_follower_perf_standby() {
        let r = HealthResponse { initialized: true, sealed: false, standby: false, performance_standby: true, ..Default::default() };
        assert_eq!(classify(&r), NodeState::Follower);
    }

    #[test]
    fn classify_sealed() {
        let r = HealthResponse { initialized: true, sealed: true, ..Default::default() };
        assert_eq!(classify(&r), NodeState::Sealed);
    }

    #[test]
    fn classify_uninitialized() {
        let r = HealthResponse { initialized: false, ..Default::default() };
        assert_eq!(classify(&r), NodeState::Uninitialized);
    }

    #[test]
    fn pick_returns_none_when_all_unreachable() {
        let probes = vec![
            probe("a", 10, 50, NodeState::Unreachable("dns".into()), 0, None),
            probe("b", 10, 50, NodeState::Sealed, 0, None),
            probe("c", 10, 50, NodeState::Uninitialized, 0, None),
        ];
        assert!(pick(&probes).is_none());
    }

    #[test]
    fn pick_prefers_leader_over_follower() {
        let probes = vec![
            probe("a", 10, 50, NodeState::Follower, 5, Some("cid")),
            probe("b", 10, 50, NodeState::ActiveLeader, 20, Some("cid")),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.candidate.target, "b");
    }

    #[test]
    fn pick_respects_srv_priority_hard_floor() {
        // Higher-priority follower wins even when a lower-priority
        // leader is faster — priority is the hard floor.
        let probes = vec![
            probe("a", 10, 50, NodeState::Follower, 100, Some("cid")),
            probe("b", 20, 50, NodeState::ActiveLeader, 5, Some("cid")),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.candidate.target, "a");
    }

    #[test]
    fn pick_rtt_tiebreak_within_bucket() {
        let probes = vec![
            probe("slow", 10, 50, NodeState::Follower, 100, Some("cid")),
            probe("fast", 10, 50, NodeState::Follower, 10, Some("cid")),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.candidate.target, "fast");
    }

    #[test]
    fn pick_weight_breaks_final_tie() {
        let probes = vec![
            probe("light", 10, 10, NodeState::Follower, 5, Some("cid")),
            probe("heavy", 10, 90, NodeState::Follower, 5, Some("cid")),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.candidate.target, "heavy");
    }

    #[test]
    fn pick_drops_minority_cluster_id() {
        // Two nodes report cluster A, one reports cluster B. The
        // minority is dropped even though it's the fastest leader.
        let probes = vec![
            probe("a1", 10, 50, NodeState::Follower, 50, Some("cluster-A")),
            probe("a2", 10, 50, NodeState::Follower, 60, Some("cluster-A")),
            probe("rogue", 10, 50, NodeState::ActiveLeader, 5, Some("cluster-B")),
        ];
        let s = pick(&probes).unwrap();
        assert!(s.candidate.target.starts_with('a'));
        assert_eq!(s.cluster_id.as_deref(), Some("cluster-A"));
    }

    #[test]
    fn pick_tolerates_missing_cluster_id() {
        let probes = vec![
            probe("a", 10, 50, NodeState::ActiveLeader, 5, None),
            probe("b", 10, 50, NodeState::Follower, 5, None),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.candidate.target, "a");
    }

    #[test]
    fn dominant_cluster_id_ties_break_on_state() {
        // 1-vote for A from a leader, 1-vote for B from a follower
        // → A wins on state-rank tiebreak (leader beats follower).
        let probes = vec![
            probe("a", 10, 50, NodeState::ActiveLeader, 5, Some("A")),
            probe("b", 10, 50, NodeState::Follower, 5, Some("B")),
        ];
        let s = pick(&probes).unwrap();
        assert_eq!(s.cluster_id.as_deref(), Some("A"));
    }
}
