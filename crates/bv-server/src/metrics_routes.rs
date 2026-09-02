//! Prometheus scrape endpoint (`/metrics`) and its access gate.
//!
//! The registry of a secrets manager is operational telemetry about the
//! deployment — request volumes per path label, auth-failure and denial
//! counts, per-plugin invocation counts, FerroGate enrolment state, host
//! CPU/memory/disk. None of it is a secret, all of it is reconnaissance,
//! and the project's rule is that *every* endpoint is authorized,
//! including read-only ones. Three credentials are accepted, in the
//! order the gate tries them:
//!
//! 1. **A cluster-local socket peer** — loopback, or an IP in the
//!    configured `nodes` list — exactly the predicate that gates
//!    `sys/cluster-status`, and judged on the *socket* peer so no header
//!    can forge it. This is what keeps a node-local scrape (and a scrape
//!    of a **sealed** node, where no token can be validated because the
//!    barrier is shut) working with no credential plumbing. Operators
//!    who want strict token-only scraping set
//!    `metrics { allow_cluster_local = false }`.
//!
//! 2. **A source IP inside the operator-configured allowlist**
//!    (`metrics { allow_unauthenticated_cidrs = [...] }`), empty by
//!    default. For a scraper on a separate host that cannot hold a
//!    token. Matched against the trusted-proxy-aware client IP the
//!    logical handler and the DoS guard use, so a spoofed
//!    `X-Forwarded-For` cannot manufacture an allowlisted source unless
//!    the operator already trusts the proxy it came from.
//!
//! 3. **A vault token** carrying `read` on the logical path
//!    [`METRICS_ACL_PATH`] (`sys/metrics`). The credential for every
//!    remote scraper. Grant it with an ordinary ACL policy:
//!
//!    ```hcl
//!    path "sys/metrics" { capabilities = ["read"] }
//!    ```
//!
//!    Root tokens are allowed by the usual root short-circuit. The
//!    `default` policy does **not** grant it — deployment-wide telemetry
//!    is not something every authenticated principal should read, the
//!    same reasoning that keeps `sys/audit/events` out of `default`.
//!
//! Anything else is refused. When the [`MetricsAccess`] app data is not
//! registered at all, both IP allowances are off and a token is the only
//! way in — absence fails closed.

use std::{
    net::IpAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};

use actix_web::{
    web,
    HttpRequest,
    HttpResponse,
    http::{StatusCode},
};
use ipnetwork::IpNetwork;
use prometheus_client::encoding::text::encode;

use crate::{
    core::Core,
    errors::RvError,
    client_ip::{ClientIp, TrustedProxies},
        get_token_from_req, response_error, Connection,
    logical::{Operation, Request},
    metrics::manager::MetricsManager,
    modules::{auth::AuthModule, policy::PolicyModule},
};

/// Logical path the scrape endpoint authorizes against. It is not a
/// routable logical path — nothing is mounted there — it is the ACL
/// name operators write policy against.
pub const METRICS_ACL_PATH: &str = "sys/metrics";

/// Which unauthenticated scrapes this node permits.
///
/// Built once at startup from the `metrics { ... }` config block and
/// shared with every worker. [`Default`] is the strictest setting — no
/// IP allowance at all — so a missing registration fails closed rather
/// than inheriting the config default.
#[derive(Debug, Clone, Default)]
pub struct MetricsAccess {
    /// Waive the token for loopback and configured cluster-node peers.
    /// Config default is `true`; the struct default is `false`.
    allow_cluster_local: bool,
    /// Extra CIDRs that may scrape without a token.
    allow_cidrs: Vec<IpNetwork>,
}

impl MetricsAccess {
    /// Build from the config block. Returns the access policy plus the
    /// CIDR entries that failed to parse, so the caller can log them at
    /// startup without aborting the server — mirrors
    /// [`TrustedProxies::parse`]. A rejected entry is simply absent from
    /// the allowlist, which fails closed (that source then needs a
    /// token).
    pub fn parse(allow_cluster_local: bool, entries: &[String]) -> (Self, Vec<String>) {
        let mut allow_cidrs = Vec::new();
        let mut bad = Vec::new();
        for raw in entries {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            match IpNetwork::from_str(trimmed) {
                Ok(net) => allow_cidrs.push(net),
                Err(_) => bad.push(trimmed.to_string()),
            }
        }
        (Self { allow_cluster_local, allow_cidrs }, bad)
    }

    /// True when no scrape can succeed without a token.
    pub fn is_token_only(&self) -> bool {
        !self.allow_cluster_local && self.allow_cidrs.is_empty()
    }

    pub fn allow_cluster_local(&self) -> bool {
        self.allow_cluster_local
    }

    pub fn cidrs_allow(&self, ip: IpAddr) -> bool {
        self.allow_cidrs.iter().any(|c| c.contains(ip))
    }
}

pub async fn metrics_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
    metrics_manager: web::Data<Arc<RwLock<MetricsManager>>>,
) -> HttpResponse {
    if let Err(denial) = authorize_scrape(&req, core.get_ref()).await {
        return denial;
    }

    let m = metrics_manager.read().unwrap();
    let registry = m.registry.lock().unwrap();

    let mut buffer = String::new();
    if let Err(e) = encode(&mut buffer, &registry) {
        log::error!("Failed to encode metrics: {e}");
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().content_type("text/plain; version=0.0.4").body(buffer)
}

/// Decide whether this scrape may proceed. `Ok(())` authorizes it;
/// `Err(response)` is the fail-closed response to return verbatim.
async fn authorize_scrape(req: &HttpRequest, core: &Arc<Core>) -> Result<(), HttpResponse> {
    if allowlisted_source(req, core) {
        return Ok(());
    }

    let token = match get_token_from_req(req) {
        Ok(token) => token,
        Err(_) => {
            log::debug!("metrics scrape refused: no client token and source not allowlisted");
            return Err(deny("missing client token"));
        }
    };

    match token_grants_scrape(core, &token, &scrape_client_ip(req)).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            // A real token that lacks the grant. Worth surfacing: it is
            // the shape of a misconfigured scraper policy, and the caller
            // had to authenticate to get here, so it cannot be used to
            // flood the security log anonymously.
            log::warn!(
                target: "security",
                "metrics scrape denied: token lacks `read` on `{METRICS_ACL_PATH}`"
            );
            Err(deny("permission denied"))
        }
        Err(RvError::ErrBarrierSealed) => Err(response_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault is sealed: token-authorized scraping is unavailable until unseal; \
             use `metrics { allow_unauthenticated_cidrs = [...] }` to scrape a sealed node",
        )),
        Err(e) => {
            log::debug!("metrics scrape refused: {e}");
            Err(deny("permission denied"))
        }
    }
}

/// True when this request's origin waives the token requirement. False
/// whenever the access policy is unset or token-only, or the peer
/// address cannot be determined — all fail closed.
fn allowlisted_source(req: &HttpRequest, core: &Arc<Core>) -> bool {
    let Some(access) = req.app_data::<web::Data<MetricsAccess>>() else {
        return false;
    };
    if access.is_token_only() {
        return false;
    }

    // Prefer the socket peer captured by the on-connect hook; fall back to
    // actix's `peer_addr` when that hook did not run (test harness).
    let Some(socket_peer) = req
        .conn_data::<Connection>()
        .map(|c| c.peer)
        .or_else(|| req.peer_addr())
    else {
        return false;
    };

    // Cluster-local is judged on the raw socket peer, never on a derived
    // address: this branch waives authentication, so it must rest on
    // something no client can set in a header. Same rule, same predicate
    // as the `sys/cluster-status` disclosure gate.
    if access.allow_cluster_local()
        && crate::sys::ip_is_cluster_local(
            socket_peer.ip(),
            &crate::sys::cluster_peer_ips(core),
        )
    {
        return true;
    }

    // The operator-configured allowlist, in contrast, is matched on the
    // trusted-proxy-aware client IP, so an operator can name the actual
    // scraper host behind a reverse proxy they already trust rather than
    // having to allowlist the proxy (which would admit everything
    // arriving through it).
    let default_trusted;
    let trusted = match req.app_data::<web::Data<TrustedProxies>>() {
        Some(d) => d.get_ref(),
        None => {
            default_trusted = TrustedProxies::default();
            &default_trusted
        }
    };

    access.cidrs_allow(ClientIp::resolve(socket_peer, req, trusted).derived)
}

/// The trusted-proxy-aware client IP for a scrape, as a bare address string,
/// for matching a token's `token_bound_cidrs`.
///
/// `/metrics` is not a routed logical path, so there is no `Connection` on a
/// `Request` to read `client_ip()` off — this resolves the same address
/// `allowlisted_source` matches its operator allowlist against. Returns an
/// empty string when the peer cannot be determined, which `check_token`
/// treats as a refusal for any token that carries a binding.
fn scrape_client_ip(req: &HttpRequest) -> String {
    let Some(socket_peer) = req
        .conn_data::<Connection>()
        .map(|c| c.peer)
        .or_else(|| req.peer_addr())
    else {
        return String::new();
    };

    let default_trusted;
    let trusted = match req.app_data::<web::Data<TrustedProxies>>() {
        Some(d) => d.get_ref(),
        None => {
            default_trusted = TrustedProxies::default();
            &default_trusted
        }
    };

    ClientIp::resolve(socket_peer, req, trusted).derived.to_string()
}

/// Validate the token and evaluate the ACL for a read of
/// [`METRICS_ACL_PATH`]. Mirrors what the token store's `pre_route` and
/// the policy store's `post_auth` do for a routed request; `/metrics` is
/// not a routed logical path, so the two steps are performed here rather
/// than by going through `Core::handle_request`.
async fn token_grants_scrape(core: &Arc<Core>, token: &str, client_ip: &str) -> Result<bool, RvError> {
    let auth_module = core
        .module_manager()
        .get_module::<AuthModule>("auth")
        .ok_or(RvError::ErrPermissionDenied)?;
    let token_store = auth_module
        .token_store
        .load_full()
        .ok_or(RvError::ErrPermissionDenied)?;
    let Some(auth) = token_store.check_token(METRICS_ACL_PATH, token, client_ip).await? else {
        return Ok(false);
    };

    let policy_module = core
        .module_manager()
        .get_module::<PolicyModule>("policy")
        .ok_or(RvError::ErrPermissionDenied)?;
    let policy_store = policy_module.policy_store.load();
    // `None` for the request namespace: `/metrics` is not a routed logical
    // path and is never namespace-scoped, so no `{{request.namespace}}` rule
    // should contribute to the scrape verdict.
    let acl = policy_store
        .new_acl_for_request(&auth.policies, None, &auth, None)
        .await?;

    let mut probe = Request::new(METRICS_ACL_PATH);
    probe.operation = Operation::Read;
    probe.auth = Some(auth);

    Ok(acl.allow_operation(&probe, false)?.allowed)
}

fn deny(msg: &str) -> HttpResponse {
    response_error(StatusCode::FORBIDDEN, msg)
}

pub fn init_metrics_service(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/metrics").route(web::get().to(metrics_handler)));
}

#[cfg(test)]
mod test {
    use serde_json::{json, Value};

    use super::*;
    use crate::test_utils::TestHttpServer;

    /// Raw GET against the scrape endpoint. Unlike
    /// `TestHttpServer::request_prometheus`, `token: None` sends **no**
    /// token header at all — that is the case the gate exists for.
    fn scrape(server: &TestHttpServer, token: Option<&str>) -> u16 {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .new_agent();
        let mut builder = ::http::Request::builder()
            .method("GET")
            .uri(format!("{}/metrics", server.url_prefix));
        if let Some(token) = token {
            builder = builder.header("X-BastionVault-Token", token);
        }
        agent
            .run(builder.body(()).unwrap())
            .unwrap()
            .status()
            .as_u16()
    }

    /// `/metrics` is authorization-gated: an anonymous or unprivileged
    /// caller gets 403, and only a token carrying `read` on
    /// `sys/metrics` (or root) is served the registry. Regression cover
    /// for the endpoint having previously been world-readable.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_metrics_endpoint_requires_authorization() {
        let server = TestHttpServer::new_with_prometheus("test_metrics_authz", false).await;
        let root_token = server.root_token.clone();

        // No credential at all, and a forged one: both refused.
        assert_eq!(scrape(&server, None), 403);
        assert_eq!(scrape(&server, Some("")), 403);
        assert_eq!(scrape(&server, Some("not-a-real-token")), 403);

        // Root is served.
        assert_eq!(scrape(&server, Some(&root_token)), 200);

        // A token holding only the `default` policy is refused:
        // deployment-wide telemetry is not granted to every principal.
        let (status, resp) = server
            .request_prometheus(
                "POST",
                "v1/auth/token/create",
                json!({ "policies": ["default"] }).as_object().cloned(),
                Some(&root_token),
                None,
            )
            .unwrap();
        assert_eq!(status, 200);
        let body: Value = serde_json::from_str(resp["metrics"].as_str().unwrap()).unwrap();
        let plain_token = body["auth"]["client_token"].as_str().unwrap().to_string();
        assert_eq!(scrape(&server, Some(&plain_token)), 403);

        // Granting `read` on `sys/metrics` through an ordinary ACL
        // policy is what a scraper identity is supposed to look like.
        let (status, _) = server
            .request_prometheus(
                "POST",
                "v1/sys/policy/metrics-scraper",
                json!({ "policy": "path \"sys/metrics\" { capabilities = [\"read\"] }" })
                    .as_object()
                    .cloned(),
                Some(&root_token),
                None,
            )
            .unwrap();
        assert!(status == 200 || status == 204, "policy write returned {status}");

        let (status, resp) = server
            .request_prometheus(
                "POST",
                "v1/auth/token/create",
                json!({ "policies": ["metrics-scraper"] }).as_object().cloned(),
                Some(&root_token),
                None,
            )
            .unwrap();
        assert_eq!(status, 200);
        let body: Value = serde_json::from_str(resp["metrics"].as_str().unwrap()).unwrap();
        let scraper_token = body["auth"]["client_token"].as_str().unwrap().to_string();
        assert_eq!(scrape(&server, Some(&scraper_token)), 200);
    }

    /// The struct default is the strict one: when the app data is not
    /// registered at all, absence must not inherit the *config* default
    /// (which does waive the token for cluster-local peers).
    #[test]
    fn test_metrics_access_struct_default_is_token_only() {
        let access = MetricsAccess::default();
        assert!(access.is_token_only());
        assert!(!access.allow_cluster_local());
        assert!(!access.cidrs_allow("127.0.0.1".parse().unwrap()));
        assert!(!access.cidrs_allow("10.0.0.1".parse().unwrap()));
    }

    /// The shipped config default waives the token for cluster-local
    /// peers only — never for an arbitrary source.
    #[test]
    fn test_config_default_allows_cluster_local_only() {
        let cfg = crate::config::MetricsAccessConfig::default();
        assert!(cfg.allow_cluster_local);
        assert!(cfg.allow_unauthenticated_cidrs.is_empty());

        let (access, bad) =
            MetricsAccess::parse(cfg.allow_cluster_local, &cfg.allow_unauthenticated_cidrs);
        assert!(bad.is_empty());
        assert!(!access.is_token_only());
        assert!(access.allow_cluster_local());
        assert!(!access.cidrs_allow("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_metrics_access_matches_only_listed_cidrs() {
        let (access, bad) = MetricsAccess::parse(
            false,
            &[
                "127.0.0.1/32".to_string(),
                " 10.20.0.0/16 ".to_string(),
                "".to_string(),
                "::1/128".to_string(),
            ],
        );
        assert!(bad.is_empty());
        assert!(!access.is_token_only());
        assert!(!access.allow_cluster_local());

        assert!(access.cidrs_allow("127.0.0.1".parse().unwrap()));
        assert!(access.cidrs_allow("10.20.7.9".parse().unwrap()));
        assert!(access.cidrs_allow("::1".parse().unwrap()));

        assert!(!access.cidrs_allow("127.0.0.2".parse().unwrap()));
        assert!(!access.cidrs_allow("10.21.0.1".parse().unwrap()));
        assert!(!access.cidrs_allow("::2".parse().unwrap()));
    }

    /// The two IP allowances, exercised through the real request path.
    ///
    /// Cluster-local is judged on the socket peer, so a spoofed
    /// `X-Forwarded-For` must not reach it; the operator CIDR list is
    /// judged on the derived client IP, which only moves for a *trusted*
    /// proxy — an untrusted hop leaves the socket peer authoritative.
    #[test]
    fn test_allowlisted_source_paths() {
        use actix_web::test::TestRequest;

        let core = crate::test_utils::new_test_bastion_vault("test_metrics_allowlist_source")
            .core
            .load()
            .clone();

        let strict = web::Data::new(MetricsAccess::default());
        let (cluster_local, _) = MetricsAccess::parse(true, &[]);
        let cluster_local = web::Data::new(cluster_local);
        let (subnet, _) = MetricsAccess::parse(false, &["203.0.113.0/24".to_string()]);
        let subnet = web::Data::new(subnet);

        // Token-only: loopback gets no waiver.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .app_data(strict.clone())
            .to_http_request();
        assert!(!allowlisted_source(&req, &core));

        // No app data at all is the same as token-only.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .to_http_request();
        assert!(!allowlisted_source(&req, &core));

        // Cluster-local enabled: loopback is waived, a remote peer is not.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .app_data(cluster_local.clone())
            .to_http_request();
        assert!(allowlisted_source(&req, &core));

        let req = TestRequest::default()
            .peer_addr("198.51.100.7:5000".parse().unwrap())
            .app_data(cluster_local.clone())
            .to_http_request();
        assert!(!allowlisted_source(&req, &core));

        // ...and a forwarded-for header claiming loopback does not buy it.
        let req = TestRequest::default()
            .peer_addr("198.51.100.7:5000".parse().unwrap())
            .insert_header(("X-Forwarded-For", "127.0.0.1"))
            .app_data(cluster_local)
            .to_http_request();
        assert!(!allowlisted_source(&req, &core));

        // Operator CIDR list: in-range socket peer allowed, out-of-range
        // refused, and an untrusted `X-Forwarded-For` cannot fake it.
        let req = TestRequest::default()
            .peer_addr("203.0.113.9:5000".parse().unwrap())
            .app_data(subnet.clone())
            .to_http_request();
        assert!(allowlisted_source(&req, &core));

        let req = TestRequest::default()
            .peer_addr("198.51.100.7:5000".parse().unwrap())
            .insert_header(("X-Forwarded-For", "203.0.113.9"))
            .app_data(subnet)
            .to_http_request();
        assert!(!allowlisted_source(&req, &core));
    }

    /// A malformed entry must not silently widen the allowlist: it is
    /// reported to the caller and dropped, leaving the remaining entries
    /// authoritative.
    #[test]
    fn test_metrics_access_reports_bad_entries_and_fails_closed() {
        let (access, bad) =
            MetricsAccess::parse(false, &["not-a-cidr".to_string(), "192.0.2.0/24".to_string()]);
        assert_eq!(bad, vec!["not-a-cidr".to_string()]);
        assert!(access.cidrs_allow("192.0.2.10".parse().unwrap()));
        assert!(!access.cidrs_allow("198.51.100.10".parse().unwrap()));
    }
}
