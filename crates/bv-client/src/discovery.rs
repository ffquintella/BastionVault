//! Cluster discovery — turn a single "cluster address" into the
//! ordered list of nodes the client should consider connecting to.
//!
//! Two paths:
//!
//! 1. **Literal URL** (`https://host:8200`, `http://10.0.0.5`, etc.):
//!    bypass DNS entirely and emit a single candidate. This preserves
//!    backwards compat with every existing `RemoteProfile.address`
//!    consumer.
//!
//! 2. **Cluster name** (`vault.corp.example`): query
//!    `_bvault._tcp.<name>` for SRV records. Each record contributes
//!    a candidate carrying the SRV `priority` + `weight` so the
//!    selector in [`crate::health`] can rank them. NXDOMAIN / empty
//!    answers fall back to literal-hostname resolution so a misconfig
//!    doesn't lock the client out.
//!
//! The [`SrvLookup`] trait keeps the resolver swappable for tests
//! without spinning up a real DNS server.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use crate::error::ClientError;

/// One concrete node the client might connect to. SRV-derived
/// candidates carry the record's priority/weight; literal-address
/// candidates carry `priority = 0` and `weight = 0` so they always
/// win an empty SRV ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvCandidate {
    /// Hostname used for both the wire connection AND TLS SNI / cert
    /// verification. SRV targets typically end with `.`; we strip the
    /// trailing dot before storing.
    pub target: String,
    pub port: u16,
    /// `"http"` or `"https"`. Derived from the input scheme hint or
    /// the discovery config default.
    pub scheme: String,
    pub priority: u16,
    pub weight: u16,
}

impl SrvCandidate {
    /// `scheme://target[:port]` — used as the request base URL and
    /// the source of TLS SNI. The port is included even when it's
    /// the scheme default so the host header is unambiguous.
    pub fn url(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.target, self.port)
    }
}

/// Knobs that shape the discovery query. Defaults match the feature
/// spec (`_bvault._tcp`, HTTPS, port 8200).
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// The DNS service label prefix. Becomes `<this>.<cluster-name>`
    /// at lookup time. Operators on non-standard deployments can
    /// override (e.g. `"_bvault-test._tcp"`).
    pub srv_service: String,
    /// Default wire scheme when the input carries no scheme hint.
    pub default_scheme: String,
    /// Port used for literal-hostname fallback when the input has no
    /// `:port`. SRV records always supply their own port.
    pub default_port: u16,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            srv_service: "_bvault._tcp".to_string(),
            default_scheme: "https".to_string(),
            default_port: 8200,
        }
    }
}

/// Minimal shape of an SRV record. We don't expose the full
/// `hickory_proto::rr::rdata::SRV` type so tests don't have to
/// construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// Resolver abstraction. Production code uses [`SystemResolver`];
/// unit tests provide an in-memory fake.
#[async_trait]
pub trait SrvLookup: Send + Sync {
    /// Returns SRV records for `label` (already in
    /// `_service._proto.name` form). An empty `Vec` and any
    /// resolver-level error both signal "no SRV answer" — the caller
    /// falls back to literal resolution either way.
    async fn lookup_srv(&self, label: &str) -> Result<Vec<SrvRecord>, ClientError>;
}

/// Resolver backed by the system DNS configuration.
pub struct SystemResolver {
    inner: Arc<TokioResolver>,
}

impl SystemResolver {
    /// Build a resolver using `/etc/resolv.conf` on Unix and the
    /// platform equivalent on Windows. Falls back to a sensible
    /// in-process default if the system file is unreadable rather
    /// than failing the connection outright.
    pub fn new() -> Self {
        let (cfg, opts) = hickory_resolver::system_conf::read_system_conf()
            .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
        let mut builder =
            TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
        *builder.options_mut() = opts;
        let resolver = builder
            .build()
            .expect("TokioRuntimeProvider build is infallible");
        Self { inner: Arc::new(resolver) }
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SrvLookup for SystemResolver {
    async fn lookup_srv(&self, label: &str) -> Result<Vec<SrvRecord>, ClientError> {
        match self.inner.srv_lookup(label).await {
            Ok(resp) => Ok(resp
                .answers()
                .iter()
                .filter_map(|rec| match &rec.data {
                    RData::SRV(srv) => Some(SrvRecord {
                        target: srv.target.to_utf8(),
                        port: srv.port,
                        priority: srv.priority,
                        weight: srv.weight,
                    }),
                    _ => None,
                })
                .collect()),
            // Treat resolver errors as "no SRV" — caller falls back
            // to literal. We deliberately do NOT propagate them: a
            // misconfigured DNS server shouldn't block a connection
            // to a deployment that doesn't use SRV at all.
            Err(_) => Ok(Vec::new()),
        }
    }
}

/// Result of resolving an input address. `Literal` means the caller
/// passed something URL-shaped and discovery short-circuited; `Cluster`
/// means SRV discovery produced one or more candidates.
#[derive(Debug, Clone)]
pub enum ResolvedAddress {
    Literal(SrvCandidate),
    Cluster {
        /// The bare cluster name (without scheme), useful for
        /// log/UI labels like `Connected to <cluster>`.
        name: String,
        candidates: Vec<SrvCandidate>,
    },
}

impl ResolvedAddress {
    pub fn candidates(&self) -> &[SrvCandidate] {
        match self {
            ResolvedAddress::Literal(c) => std::slice::from_ref(c),
            ResolvedAddress::Cluster { candidates, .. } => candidates,
        }
    }

    pub fn into_candidates(self) -> Vec<SrvCandidate> {
        match self {
            ResolvedAddress::Literal(c) => vec![c],
            ResolvedAddress::Cluster { candidates, .. } => candidates,
        }
    }
}

/// Parse the input into either a literal URL candidate or a cluster
/// name to feed to SRV lookup. Pure — no I/O.
///
/// Returns `Ok(Either::Literal)` when the input has a scheme prefix,
/// an explicit port, a path, or is an IP literal. Returns
/// `Ok(Either::Cluster(name))` for a bare DNS name.
fn parse_input(input: &str, cfg: &DiscoveryConfig) -> Result<ParsedInput, ClientError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ClientError::backend("discovery: empty address"));
    }

    // Strip scheme prefix and remember it as a hint.
    let (scheme_hint, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (Some("https".to_string()), r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (Some("http".to_string()), r)
    } else {
        (None, trimmed)
    };

    // Drop any path/query/fragment so we operate on `host[:port]`.
    let host_port = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_end_matches('/');
    if host_port.is_empty() {
        return Err(ClientError::backend(format!(
            "discovery: address `{input}` has no host"
        )));
    }

    // IPv6 literal `[::1]:8200` or `[::1]`.
    if let Some(after_bracket) = host_port.strip_prefix('[') {
        let close = after_bracket
            .find(']')
            .ok_or_else(|| ClientError::backend(format!("discovery: malformed IPv6 in `{input}`")))?;
        let host = &after_bracket[..close];
        let tail = &after_bracket[close + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| ClientError::backend(format!("discovery: bad port in `{input}`")))?
        } else {
            cfg.default_port
        };
        return Ok(ParsedInput::Literal(SrvCandidate {
            target: host.to_string(),
            port,
            scheme: scheme_hint.unwrap_or_else(|| cfg.default_scheme.clone()),
            priority: 0,
            weight: 0,
        }));
    }

    // Non-bracketed host[:port]. Exactly one `:` is OK, more is an error.
    let (host, port_opt) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    if host.contains(':') {
        return Err(ClientError::backend(format!(
            "discovery: ambiguous IPv6 in `{input}` — wrap in brackets",
        )));
    }

    // Force literal mode if the input was URL-shaped (scheme prefix,
    // explicit port, or an IP literal); otherwise treat as a bare
    // DNS name and offer it up for SRV lookup.
    let is_literal = scheme_hint.is_some() || port_opt.is_some() || is_ip_literal(host);
    if is_literal {
        let port = match port_opt {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| ClientError::backend(format!("discovery: bad port in `{input}`")))?,
            None => cfg.default_port,
        };
        Ok(ParsedInput::Literal(SrvCandidate {
            target: host.to_string(),
            port,
            scheme: scheme_hint.unwrap_or_else(|| cfg.default_scheme.clone()),
            priority: 0,
            weight: 0,
        }))
    } else {
        Ok(ParsedInput::Cluster {
            name: host.to_string(),
            scheme: scheme_hint.unwrap_or_else(|| cfg.default_scheme.clone()),
        })
    }
}

#[derive(Debug)]
enum ParsedInput {
    Literal(SrvCandidate),
    Cluster { name: String, scheme: String },
}

fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Main entry point. Decides literal vs SRV, runs the lookup if
/// needed, and orders candidates by SRV priority (lower = better).
pub async fn resolve(
    input: &str,
    cfg: &DiscoveryConfig,
    resolver: &dyn SrvLookup,
) -> Result<ResolvedAddress, ClientError> {
    match parse_input(input, cfg)? {
        ParsedInput::Literal(c) => Ok(ResolvedAddress::Literal(c)),
        ParsedInput::Cluster { name, scheme } => {
            // If the input already looks SRV-shaped (starts with `_`,
            // e.g. `_bvault._tcp.cluster.example` or
            // `_cofre-html._tcp.esi.fgv.br`), query it verbatim instead
            // of prepending `cfg.srv_service` — otherwise we'd build a
            // nonsense double-prefixed label like
            // `_bvault._tcp._cofre-html._tcp.esi.fgv.br`.
            let is_srv_shaped = name.starts_with('_');
            let label = if is_srv_shaped {
                name.clone()
            } else {
                format!("{}.{}", cfg.srv_service, name)
            };
            let records = resolver.lookup_srv(&label).await.unwrap_or_default();

            if records.is_empty() {
                // SRV NXDOMAIN / empty. For non-SRV-shaped input fall
                // back to literal hostname resolution with the default
                // port — the OS resolver will handle A/AAAA at TCP
                // connect time. For SRV-shaped input there is no
                // sensible fallback (underscore labels aren't valid
                // hostnames for `getaddrinfo`), so surface an empty
                // candidate list and let the caller report it.
                if is_srv_shaped {
                    return Ok(ResolvedAddress::Cluster {
                        name,
                        candidates: Vec::new(),
                    });
                }
                return Ok(ResolvedAddress::Cluster {
                    name: name.clone(),
                    candidates: vec![SrvCandidate {
                        target: name,
                        port: cfg.default_port,
                        scheme,
                        priority: 0,
                        weight: 0,
                    }],
                });
            }

            let mut candidates: Vec<SrvCandidate> = records
                .into_iter()
                .map(|r| SrvCandidate {
                    target: r.target.trim_end_matches('.').to_string(),
                    port: r.port,
                    scheme: scheme.clone(),
                    priority: r.priority,
                    weight: r.weight,
                })
                .collect();

            // SRV priority is the hard ordering. Within a priority
            // we leave weight as-is and let the health scorer apply
            // it after probing (weight is a tiebreaker among healthy
            // peers, not a discovery-time concern).
            candidates.sort_by_key(|c| c.priority);
            Ok(ResolvedAddress::Cluster { name, candidates })
        }
    }
}

/// Default per-cluster discovery deadline. Kept as a constant rather
/// than baked into `DiscoveryConfig` because it's a wall-clock budget
/// the caller owns — they wrap `resolve` in `tokio::time::timeout`
/// when they care about end-to-end latency bounds.
pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled fake resolver. The constructor takes a closure
    /// rather than a `HashMap` so individual tests can express
    /// "resolver errored", "empty answer", and "specific records"
    /// without ceremony.
    struct FakeResolver<F: Fn(&str) -> Result<Vec<SrvRecord>, ClientError> + Send + Sync> {
        f: F,
    }

    #[async_trait]
    impl<F: Fn(&str) -> Result<Vec<SrvRecord>, ClientError> + Send + Sync> SrvLookup
        for FakeResolver<F>
    {
        async fn lookup_srv(&self, label: &str) -> Result<Vec<SrvRecord>, ClientError> {
            (self.f)(label)
        }
    }

    fn cfg() -> DiscoveryConfig {
        DiscoveryConfig::default()
    }

    #[tokio::test]
    async fn literal_url_with_scheme_skips_srv() {
        let resolver = FakeResolver {
            f: |_| panic!("SRV lookup should not be invoked for URL inputs"),
        };
        let r = resolve("https://vault.example:9000", &cfg(), &resolver).await.unwrap();
        let cands = r.candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].target, "vault.example");
        assert_eq!(cands[0].port, 9000);
        assert_eq!(cands[0].scheme, "https");
    }

    #[tokio::test]
    async fn literal_url_with_explicit_port_skips_srv() {
        let resolver = FakeResolver {
            f: |_| panic!("SRV lookup should not be invoked"),
        };
        let r = resolve("vault.example:9000", &cfg(), &resolver).await.unwrap();
        assert!(matches!(r, ResolvedAddress::Literal(_)));
    }

    #[tokio::test]
    async fn ip_literal_is_treated_as_literal() {
        let resolver = FakeResolver {
            f: |_| panic!("SRV lookup should not be invoked for IPs"),
        };
        let r = resolve("10.0.0.5", &cfg(), &resolver).await.unwrap();
        let cands = r.into_candidates();
        assert_eq!(cands[0].target, "10.0.0.5");
        assert_eq!(cands[0].port, 8200);
    }

    #[tokio::test]
    async fn ipv6_literal_with_port_parses() {
        let resolver = FakeResolver { f: |_| Ok(vec![]) };
        let r = resolve("[::1]:8300", &cfg(), &resolver).await.unwrap();
        let cands = r.into_candidates();
        assert_eq!(cands[0].target, "::1");
        assert_eq!(cands[0].port, 8300);
    }

    #[tokio::test]
    async fn bare_name_with_no_srv_falls_back_to_literal() {
        // Empty Vec from the resolver = NXDOMAIN/empty. The caller
        // should still get a single candidate using the cluster name
        // as the hostname.
        let resolver = FakeResolver { f: |_| Ok(vec![]) };
        let r = resolve("vault.corp.example", &cfg(), &resolver).await.unwrap();
        let cands = r.into_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].target, "vault.corp.example");
        assert_eq!(cands[0].port, 8200);
        assert_eq!(cands[0].scheme, "https");
    }

    #[tokio::test]
    async fn srv_records_sorted_by_priority_ascending() {
        let resolver = FakeResolver {
            f: |label| {
                assert_eq!(label, "_bvault._tcp.vault.corp.example");
                Ok(vec![
                    SrvRecord { target: "c.corp.example.".into(), port: 8200, priority: 20, weight: 50 },
                    SrvRecord { target: "a.corp.example.".into(), port: 8200, priority: 10, weight: 50 },
                    SrvRecord { target: "b.corp.example.".into(), port: 8200, priority: 10, weight: 50 },
                ])
            },
        };
        let r = resolve("vault.corp.example", &cfg(), &resolver).await.unwrap();
        let cands = r.into_candidates();
        assert_eq!(cands.len(), 3);
        assert_eq!(cands[0].priority, 10);
        assert_eq!(cands[1].priority, 10);
        assert_eq!(cands[2].priority, 20);
        // Trailing dot is stripped.
        assert!(cands.iter().all(|c| !c.target.ends_with('.')));
    }

    #[tokio::test]
    async fn resolver_error_falls_back_to_literal() {
        // SRV lookup errors are not propagated — a broken DNS path
        // shouldn't lock the operator out of literal-address mode.
        let resolver = FakeResolver {
            f: |_| Err(ClientError::backend("simulated resolver outage")),
        };
        let r = resolve("vault.corp.example", &cfg(), &resolver).await.unwrap();
        assert_eq!(r.candidates().len(), 1);
    }

    #[tokio::test]
    async fn srv_shaped_input_queried_verbatim_no_prefix() {
        // Input that already starts with `_` is treated as a full SRV
        // FQDN — we must NOT prepend `cfg.srv_service` on top of it.
        let resolver = FakeResolver {
            f: |label| {
                assert_eq!(label, "_cofre-html._tcp.esi.fgv.br");
                Ok(vec![SrvRecord {
                    target: "node1.fgv.br.".into(),
                    port: 5200,
                    priority: 10,
                    weight: 50,
                }])
            },
        };
        let r = resolve("_cofre-html._tcp.esi.fgv.br", &cfg(), &resolver).await.unwrap();
        let cands = r.into_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].target, "node1.fgv.br");
        assert_eq!(cands[0].port, 5200);
    }

    #[tokio::test]
    async fn srv_shaped_input_with_no_records_yields_empty_no_bogus_literal() {
        // Underscore labels can't be resolved as A/AAAA, so the
        // bare-hostname fallback would just produce a guaranteed-broken
        // candidate. Return empty and let the caller surface the
        // "no candidates resolved" error instead.
        let resolver = FakeResolver { f: |_| Ok(vec![]) };
        let r = resolve("_bvault._tcp.missing.example", &cfg(), &resolver).await.unwrap();
        assert!(r.candidates().is_empty());
    }

    #[test]
    fn parse_input_rejects_empty() {
        let err = parse_input("", &cfg()).unwrap_err();
        assert!(err.to_string().contains("empty address"));
    }

    #[test]
    fn parse_input_rejects_unbracketed_ipv6() {
        let err = parse_input("::1:8200", &cfg()).unwrap_err();
        assert!(err.to_string().contains("ambiguous IPv6"));
    }

    #[test]
    fn parse_input_rejects_bad_port() {
        let err = parse_input("vault.example:abc", &cfg()).unwrap_err();
        assert!(err.to_string().contains("bad port"));
    }

    #[test]
    fn srv_candidate_url_includes_port() {
        let c = SrvCandidate {
            target: "node-1.corp".into(),
            port: 8200,
            scheme: "https".into(),
            priority: 10,
            weight: 50,
        };
        assert_eq!(c.url(), "https://node-1.corp:8200");
    }
}
