//! Actix-web middleware that enforces the IP-based DoS guard.
//!
//! Wrapped as the **outermost** layer in the HTTP `App` (before logging and
//! metrics) so a banned IP is rejected as early and cheaply as possible. It
//! resolves the trusted-proxy-aware client IP exactly as the logical handler
//! does (`ClientIp::resolve`), consults the shared [`DosGuard`] held on `Core`,
//! and either passes the request through or short-circuits with
//! `429 Too Many Requests` + a `Retry-After` header.
//!
//! Modeled on `crate::metrics::middleware::metrics_midleware`.

use std::sync::Arc;

use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web::Data,
    Error, HttpResponse,
};

use crate::core::Core;
use crate::http::client_ip::{ClientIp, TrustedProxies};
use crate::http::Connection;

use super::guard::{is_exempt_path, BanInfo};

pub async fn dos_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody + 'static>>, Error> {
    // Health / seal-status / metrics are never rate-limited.
    let path = req.path().to_string();
    if is_exempt_path(&path) {
        return Ok(next.call(req).await?.map_into_left_body());
    }

    // The guard lives on Core; Core is always registered as app data. Without
    // it (should never happen) we fail open rather than blocking traffic.
    let Some(core) = req.app_data::<Data<Arc<Core>>>().map(|d| d.get_ref().clone()) else {
        return Ok(next.call(req).await?.map_into_left_body());
    };

    // Resolve the client IP the same way the logical handler does: honor the
    // configured trusted proxies. Prefer the connection's captured socket peer;
    // fall back to actix's `peer_addr` if the connect hook did not run (e.g.
    // under the test harness). If neither is available we cannot key the guard,
    // so we fail open.
    let socket_peer = req
        .conn_data::<Connection>()
        .map(|c| c.peer)
        .or_else(|| req.peer_addr());
    let Some(socket_peer) = socket_peer else {
        return Ok(next.call(req).await?.map_into_left_body());
    };
    let default_trusted;
    let trusted = match req.app_data::<Data<TrustedProxies>>() {
        Some(d) => d.get_ref(),
        None => {
            default_trusted = TrustedProxies::default();
            &default_trusted
        }
    };
    let client_ip = ClientIp::resolve(socket_peer, req.request(), trusted).derived;

    match core.dos_guard.check(client_ip, &path) {
        Ok(()) => Ok(next.call(req).await?.map_into_left_body()),
        Err(info) => {
            // Best-effort: audit exactly the transition into a ban, never every
            // blocked request (a flood would otherwise flood the audit log).
            if info.newly_banned {
                emit_ban_audit(&core, client_ip, &path, &info).await;
            }
            let resp = ban_response(&info);
            Ok(req.into_response(resp).map_into_right_body())
        }
    }
}

fn ban_response(info: &BanInfo) -> HttpResponse {
    HttpResponse::TooManyRequests()
        .insert_header((header::RETRY_AFTER, info.retry_after_secs))
        .json(serde_json::json!({
            "errors": [format!(
                "request temporarily blocked by DoS protection: {}", info.reason
            )],
        }))
}

async fn emit_ban_audit(core: &Core, ip: std::net::IpAddr, path: &str, info: &BanInfo) {
    let body = serde_json::json!({
        "client_ip": ip.to_string(),
        "path": path,
        "kind": info.kind,
        "reason": info.reason,
        "ban_secs": info.retry_after_secs,
    })
    .as_object()
    .cloned();
    crate::audit::sys_emit::emit_sys_audit(
        core,
        "",
        "sys/dos/ban-triggered",
        crate::logical::Operation::Write,
        body,
        Some("request blocked by DoS protection"),
    )
    .await;
}

#[cfg(all(test, not(feature = "sync_handler")))]
mod tests {
    use super::*;
    use crate::core::Core;
    use crate::dos::DosConfig;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse};

    fn test_core(cfg: DosConfig) -> Arc<Core> {
        let core = Core::default().wrap();
        core.dos_guard.set_config(cfg);
        core
    }

    #[actix_web::test]
    async fn flooding_ip_gets_429_but_exempt_path_never_does() {
        let cfg = DosConfig {
            enabled: true,
            window_secs: 60,
            max_requests: 3,
            auth_max_requests: 0,
            ban_secs: 300,
            refresh_secs: 30,
        };
        let core = test_core(cfg);
        let app = test::init_service(
            App::new()
                .wrap(from_fn(dos_middleware))
                .app_data(web::Data::new(core.clone()))
                .route("/v1/secret/data/x", web::get().to(|| async { HttpResponse::Ok().finish() }))
                .route("/v1/sys/health", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        // First 3 requests admitted, 4th (over max_requests=3) banned.
        for _ in 0..3 {
            let req = test::TestRequest::get()
                .uri("/v1/secret/data/x")
                .peer_addr("203.0.113.50:4444".parse().unwrap())
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status().as_u16(), 200);
        }
        let req = test::TestRequest::get()
            .uri("/v1/secret/data/x")
            .peer_addr("203.0.113.50:4444".parse().unwrap())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 429);
        assert!(resp.headers().contains_key("retry-after"));

        // A different IP is unaffected.
        let req = test::TestRequest::get()
            .uri("/v1/secret/data/x")
            .peer_addr("203.0.113.51:4444".parse().unwrap())
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

        // The exempt health path is never rate-limited, even from the banned IP.
        for _ in 0..20 {
            let req = test::TestRequest::get()
                .uri("/v1/sys/health")
                .peer_addr("203.0.113.50:4444".parse().unwrap())
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
        }
    }
}
