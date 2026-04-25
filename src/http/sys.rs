use std::sync::Arc;

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    core::{Core, SealConfig},
    errors::RvError,
    http::{
        //Connection,
        handle_request,
        request_auth,
        response_error,
        response_json_ok,
        response_ok,
    },
    logical::Operation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub cluster_healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatusResponse {
    pub storage_type: String,
    pub cluster: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_leader: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raft_metrics: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitRequest {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct InitResponse {
    pub keys: Vec<String>,
    pub root_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct UnsealRequest {
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatusResponse {
    pub sealed: bool,
    pub t: u8,
    pub n: u8,
    pub progress: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MountRequest {
    #[serde(rename = "type")]
    logical_type: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemountRequest {
    from: String,
    to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyRequest {
    #[serde(default)]
    name: String,
    policy: String,
}

#[maybe_async::maybe_async]
async fn response_seal_status(core: web::Data<Arc<Core>>) -> Result<HttpResponse, RvError> {
    let progress = core.unseal_progress();
    let sealed = core.sealed();
    let seal_config = core.seal_config().await?;

    let resp = SealStatusResponse { sealed, t: seal_config.secret_shares, n: seal_config.secret_threshold, progress };

    Ok(response_json_ok(None, resp))
}

async fn sys_init_get_request_handler(_req: HttpRequest, core: web::Data<Arc<Core>>) -> Result<HttpResponse, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    let inited = core.inited().await?;
    #[cfg(feature = "sync_handler")]
    let inited = core.inited()?;
    Ok(response_ok(
        None,
        Some(
            json!({
                "initialized": inited
            })
            .as_object()
            .unwrap(),
        ),
    ))
}

async fn sys_init_put_request_handler(
    _req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let payload = serde_json::from_slice::<InitRequest>(&body)?;
    body.clear();
    let seal_config = SealConfig { secret_shares: payload.secret_shares, secret_threshold: payload.secret_threshold };

    #[cfg(not(feature = "sync_handler"))]
    let result = core.init(&seal_config).await?;
    #[cfg(feature = "sync_handler")]
    let result = core.init(&seal_config)?;

    let resp = InitResponse {
        keys: result.secret_shares.iter().map(hex::encode).collect(),
        root_token: result.root_token.clone(),
    };

    Ok(response_json_ok(None, resp))
}

async fn sys_seal_status_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    {
        response_seal_status(core).await
    }
    #[cfg(feature = "sync_handler")]
    {
        response_seal_status(core)
    }
}

async fn sys_seal_request_handler(_req: HttpRequest, core: web::Data<Arc<Core>>) -> Result<HttpResponse, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    core.seal().await?;
    #[cfg(feature = "sync_handler")]
    core.seal()?;
    Ok(response_ok(None, None))
}

async fn sys_unseal_request_handler(
    _req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    // TODO
    let payload = serde_json::from_slice::<UnsealRequest>(&body)?;
    body.clear();
    let key: Zeroizing<Vec<u8>> = Zeroizing::new(hex::decode(payload.key.clone())?);

    #[cfg(not(feature = "sync_handler"))]
    {
        let _result = core.unseal(&key).await?;
        response_seal_status(core).await
    }

    #[cfg(feature = "sync_handler")]
    {
        let _result = core.unseal(&key)?;
        response_seal_status(core)
    }
}

async fn sys_list_mounts_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/mounts".to_string();
    r.operation = Operation::Read;

    handle_request(core, &mut r).await
}

/// GET `/sys/audit` — list enabled audit devices.
async fn sys_audit_list_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/audit".to_string();
    r.operation = Operation::Read;
    handle_request(core, &mut r).await
}

/// POST `/sys/audit/{path}` — enable a new audit device.
async fn sys_audit_enable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let device_path = path.into_inner();
    if device_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }
    let payload: serde_json::Map<String, serde_json::Value> = if body.is_empty() {
        serde_json::Map::new()
    } else {
        serde_json::from_slice(&body)?
    };
    body.clear();

    let mut r = request_auth(&req);
    r.path = format!("sys/audit/{device_path}");
    r.operation = Operation::Write;
    r.body = Some(payload);
    handle_request(core, &mut r).await
}

/// POST `/sys/cache/flush` — drop every in-memory cache layer
/// (policy / token / secret) and zeroize held payloads. Sudo-gated by
/// `root_paths` in the system backend definition.
async fn sys_cache_flush_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/cache/flush".to_string();
    r.operation = Operation::Write;
    handle_request(core, &mut r).await
}

/// POST `/sys/owner/backfill` — admin migration tool that stamps
/// `entity_id` as the owner of every currently-unowned target in the
/// request. Sudo-gated by `root_paths` in the system backend definition.
async fn sys_owner_backfill_request_handler(
    req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let payload: serde_json::Map<String, serde_json::Value> = if body.is_empty() {
        serde_json::Map::new()
    } else {
        serde_json::from_slice(&body)?
    };
    body.clear();

    let mut r = request_auth(&req);
    r.path = "sys/owner/backfill".to_string();
    r.operation = Operation::Write;
    r.body = Some(payload);
    handle_request(core, &mut r).await
}

/// DELETE `/sys/audit/{path}` — disable an audit device.
async fn sys_audit_disable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let device_path = path.into_inner();
    if device_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }
    let mut r = request_auth(&req);
    r.path = format!("sys/audit/{device_path}");
    r.operation = Operation::Delete;
    handle_request(core, &mut r).await
}

/// Unified admin audit trail. GET reads the aggregated log; optional
/// `from` / `to` / `limit` are accepted as query-string-style fields
/// via the request body so the same handler works over the internal
/// logical pipeline too (the Tauri command path).
async fn sys_audit_events_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/audit/events".to_string();
    r.operation = Operation::Read;

    // Parse query string (`?from=...&to=...&limit=...`) into the
    // request body so the logical handler's field-declaration-based
    // `req.get_data(...)` lookups resolve. We accept the values
    // verbatim — RFC3339 timestamps and integers don't need URL
    // decoding, and any clients that need arbitrary characters can
    // just POST a JSON body instead.
    if let Some(qs) = req.uri().query() {
        let mut body = serde_json::Map::new();
        for pair in qs.split('&') {
            let Some((k, v)) = pair.split_once('=') else { continue };
            if k == "limit" {
                if let Ok(n) = v.parse::<u64>() {
                    body.insert(k.into(), serde_json::Value::Number(n.into()));
                }
            } else {
                body.insert(k.into(), serde_json::Value::String(v.to_string()));
            }
        }
        if !body.is_empty() {
            r.body = Some(body);
        }
    }

    handle_request(core, &mut r).await
}

async fn sys_mount_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<MountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let mount_path = path.into_inner();
    if mount_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/mounts/".to_owned() + mount_path.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r).await
}

async fn sys_unmount_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mount_path = path.into_inner();
    if mount_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/mounts/".to_owned() + mount_path.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r).await
}

async fn sys_remount_request_handler(
    req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<RemountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();

    let mut r = request_auth(&req);
    r.path = "sys/remount".to_string();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r).await
}

async fn sys_list_auth_mounts_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/auth".to_string();
    r.operation = Operation::Read;

    handle_request(core, &mut r).await
}

async fn sys_auth_enable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<MountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let mount_path = path.into_inner();
    if mount_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/auth/".to_owned() + mount_path.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r).await
}

async fn sys_auth_disable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mount_path = path.into_inner();
    if mount_path.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/auth/".to_owned() + mount_path.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r).await
}

async fn sys_list_policy_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/policy".to_string();
    r.operation = Operation::List;

    handle_request(core, &mut r).await
}

async fn sys_read_policy_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let policy_name = name.into_inner();

    let mut r = request_auth(&req);
    r.path = "sys/policy/".to_owned() + policy_name.as_str();
    r.operation = Operation::Read;

    if policy_name.is_empty() {
        r.operation = Operation::List;
    }

    handle_request(core, &mut r).await
}

async fn sys_write_policy_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<PolicyRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let policy_name = name.into_inner();
    if policy_name.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/policy/".to_owned() + policy_name.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r).await
}

async fn sys_delete_policy_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let policy_name = name.into_inner();
    if policy_name.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/policy/".to_owned() + policy_name.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r).await
}

async fn sys_list_policies_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/policies/acl".to_string();
    r.operation = Operation::List;

    handle_request(core, &mut r).await
}

async fn sys_read_policies_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let policy_name = name.into_inner();

    let mut r = request_auth(&req);
    r.path = "sys/policies/acl/".to_owned() + policy_name.as_str();
    r.operation = Operation::Read;

    if policy_name.is_empty() {
        r.operation = Operation::List;
    }

    handle_request(core, &mut r).await
}

async fn sys_write_policies_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<PolicyRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let policy_name = name.into_inner();
    if policy_name.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/policies/acl/".to_owned() + policy_name.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r).await
}

async fn sys_delete_policies_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let policy_name = name.into_inner();
    if policy_name.is_empty() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/policies/acl/".to_owned() + policy_name.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r).await
}

async fn sys_get_internal_ui_mounts_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/internal/ui/mounts".to_string();
    r.operation = Operation::Read;

    handle_request(core, &mut r).await
}

async fn sys_get_internal_ui_mount_request_handler(
    req: HttpRequest,
    name: web::Path<String>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/internal/ui/mounts/".to_owned() + name.into_inner().as_str();
    r.operation = Operation::Read;

    handle_request(core, &mut r).await
}

async fn sys_health_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    #[cfg(not(feature = "sync_handler"))]
    let initialized = core.inited().await.unwrap_or(false);
    #[cfg(feature = "sync_handler")]
    let initialized = core.inited().unwrap_or(false);

    let sealed = core.sealed();

    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    let (standby, cluster_healthy) = {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite_backend) = backend_any.downcast_ref::<HiqliteBackend>() {
            (!hiqlite_backend.is_leader().await, hiqlite_backend.is_healthy().await)
        } else {
            (false, true)
        }
    };
    #[cfg(not(all(not(feature = "sync_handler"), feature = "storage_hiqlite")))]
    let (standby, cluster_healthy) = (false, true);

    let resp = HealthResponse { initialized, sealed, standby, cluster_healthy };

    let status = if !initialized {
        StatusCode::NOT_IMPLEMENTED
    } else if sealed || !cluster_healthy {
        StatusCode::SERVICE_UNAVAILABLE
    } else if standby {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::OK
    };

    Ok(HttpResponse::build(status).json(resp))
}

async fn sys_cluster_status_request_handler(
    req: HttpRequest,
    _core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let mut resp = ClusterStatusResponse {
        storage_type: "unknown".to_string(),
        cluster: false,
        node_id: None,
        is_leader: None,
        cluster_healthy: None,
        raft_metrics: None,
    };

    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = _core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite_backend) = backend_any.downcast_ref::<HiqliteBackend>() {
            resp.storage_type = "hiqlite".to_string();
            resp.cluster = true;
            resp.is_leader = Some(hiqlite_backend.is_leader().await);
            resp.cluster_healthy = Some(hiqlite_backend.is_healthy().await);
            resp.raft_metrics = hiqlite_backend.cluster_metrics().await.ok();
        }
    }

    if resp.storage_type == "unknown" {
        resp.storage_type = "file".to_string();
    }

    Ok(response_json_ok(None, resp))
}

async fn sys_cluster_remove_node_request_handler(
    req: HttpRequest,
    mut body: web::Bytes,
    _core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct RemoveNodeRequest {
        node_id: u64,
        #[serde(default)]
        stay_as_learner: bool,
    }

    let payload = serde_json::from_slice::<RemoveNodeRequest>(&body)?;
    body.clear();

    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = _core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite_backend) = backend_any.downcast_ref::<HiqliteBackend>() {
            hiqlite_backend.remove_node(payload.node_id, payload.stay_as_learner)?;
            return Ok(response_ok(None, None));
        }
    }

    let _ = payload;
    Ok(response_error(StatusCode::BAD_REQUEST, "cluster operations require hiqlite storage backend"))
}

async fn sys_cluster_leave_request_handler(
    req: HttpRequest,
    _core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = _core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite_backend) = backend_any.downcast_ref::<HiqliteBackend>() {
            hiqlite_backend.leave_cluster().await?;
            return Ok(response_ok(None, None));
        }
    }

    Ok(response_error(StatusCode::BAD_REQUEST, "cluster operations require hiqlite storage backend"))
}

async fn sys_cluster_failover_request_handler(
    req: HttpRequest,
    _core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    #[cfg(all(not(feature = "sync_handler"), feature = "storage_hiqlite"))]
    {
        use crate::storage::hiqlite::HiqliteBackend;
        let backend_any = _core.physical.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite_backend) = backend_any.downcast_ref::<HiqliteBackend>() {
            hiqlite_backend.trigger_failover()?;
            return Ok(response_ok(None, None));
        }
    }

    Ok(response_error(StatusCode::BAD_REQUEST, "cluster operations require hiqlite storage backend"))
}

async fn sys_backup_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let hmac_key = core.barrier.derive_hmac_key()?;
    let mut buf = Vec::new();

    crate::backup::create::create_backup(
        core.physical.as_ref(),
        &hmac_key,
        &mut buf,
        false,
    )
    .await?;

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("Content-Disposition", "attachment; filename=\"backup.bvbk\""))
        .body(buf))
}

async fn sys_restore_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let hmac_key = core.barrier.derive_hmac_key()?;
    let mut reader = std::io::Cursor::new(body.as_ref());

    let count = crate::backup::restore::restore_backup(
        core.physical.as_ref(),
        &hmac_key,
        &mut reader,
    )
    .await?;

    Ok(response_json_ok(None, serde_json::json!({ "entries_restored": count })))
}

async fn sys_export_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let path = req.match_info().get("path").unwrap_or("");
    // Split path into mount and prefix at the first '/' after removing leading slash
    let (mount, prefix) = if let Some(idx) = path.find('/') {
        let (m, p) = path.split_at(idx + 1);
        (m.to_string(), p.to_string())
    } else {
        (format!("{path}/"), String::new())
    };

    let export_data = crate::backup::export::export_secrets(
        core.barrier.as_storage(),
        &mount,
        &prefix,
    )
    .await?;

    Ok(response_json_ok(None, export_data))
}

/// Request body for `POST /v1/sys/exchange/export`.
#[derive(Debug, Deserialize)]
struct ExchangeExportRequest {
    #[serde(default = "default_format")]
    format: String,
    scope: crate::exchange::ScopeSpec,
    /// Required when `format = "bvx"`. Refused (with `allow_plaintext: false`)
    /// when `format = "json"` unless explicitly opted in.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    allow_plaintext: bool,
    #[serde(default)]
    comment: Option<String>,
}

fn default_format() -> String {
    "bvx".to_string()
}

/// `POST /v1/sys/exchange/export` — produce a `bvx.v1` JSON document
/// describing the requested scope; optionally wrap it in a password-encrypted
/// `.bvx` envelope. See `features/import-export-module.md`.
async fn sys_exchange_export_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let mut payload: ExchangeExportRequest =
        serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

    // Build the bvx.v1 document by walking barrier-decrypted storage.
    let exporter = crate::exchange::ExporterInfo::default();
    let document = crate::exchange::scope::export_to_document(
        core.barrier.as_storage(),
        exporter,
        payload.scope.clone(),
    )
    .await?;

    // Canonical JSON — sorted keys, no whitespace, deterministic across runs.
    let inner_bytes = crate::exchange::canonical::to_canonical_vec(&document)?;

    let (body_bytes, format_label) = match payload.format.as_str() {
        "json" => {
            if !payload.allow_plaintext {
                // Loud refusal: the default is encrypted. Operators who want
                // plaintext must opt in explicitly so the choice is auditable.
                return Ok(response_error(
                    StatusCode::BAD_REQUEST,
                    "plaintext export refused (set allow_plaintext: true to override)",
                ));
            }
            (inner_bytes, "json")
        }
        "bvx" => {
            let password = payload.password.as_deref().ok_or(RvError::ErrRequestInvalid)?;
            let bytes = crate::exchange::encrypt_bvx(
                &inner_bytes,
                password,
                "",
                payload.comment.clone(),
            )?;
            // Zeroise the password buffer in our local copy.
            if let Some(ref mut p) = payload.password {
                p.zeroize();
            }
            (bytes, "bvx")
        }
        _ => {
            return Ok(response_error(
                StatusCode::BAD_REQUEST,
                "format must be \"bvx\" or \"json\"",
            ));
        }
    };

    use base64::Engine;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);

    Ok(response_json_ok(
        None,
        json!({
            "format": format_label,
            "size_bytes": body_bytes.len(),
            "file_b64": body_b64,
        }),
    ))
}

/// Request body for `POST /v1/sys/exchange/import`.
#[derive(Debug, Deserialize)]
struct ExchangeImportRequest {
    /// Either the raw `bvx.v1` JSON document (when `format == "json"`) or
    /// the `.bvx` envelope JSON (when `format == "bvx"`). Sent as a UTF-8
    /// string to keep the payload schema simple.
    file: String,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    conflict_policy: crate::exchange::ConflictPolicy,
    #[serde(default)]
    allow_plaintext: bool,
}

/// `POST /v1/sys/exchange/import/preview` — decrypt + parse + classify.
/// Stores the parsed document keyed by an opaque token; the apply call
/// must present the same token within the configured TTL.
async fn sys_exchange_import_preview_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let mut payload: ExchangeImportRequest =
        serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

    let document_bytes = match payload.format.as_str() {
        "bvx" => {
            let password = payload.password.as_deref().ok_or(RvError::ErrRequestInvalid)?;
            let bytes = crate::exchange::decrypt_bvx(payload.file.as_bytes(), password)?;
            if let Some(ref mut p) = payload.password {
                p.zeroize();
            }
            bytes
        }
        "json" => {
            if !payload.allow_plaintext {
                return Ok(response_error(
                    StatusCode::BAD_REQUEST,
                    "plaintext import refused (set allow_plaintext: true to override)",
                ));
            }
            payload.file.as_bytes().to_vec()
        }
        _ => {
            return Ok(response_error(
                StatusCode::BAD_REQUEST,
                "format must be \"bvx\" or \"json\"",
            ));
        }
    };

    let document: crate::exchange::ExchangeDocument =
        serde_json::from_slice(&document_bytes).map_err(|_| RvError::ErrRequestInvalid)?;
    document.validate_schema_tag().map_err(|_| RvError::ErrRequestInvalid)?;

    // Classify each item against the destination *without* writing.
    let storage = core.barrier.as_storage();
    let mut new = 0u64;
    let mut identical = 0u64;
    let mut conflict = 0u64;
    let mut items: Vec<crate::exchange::PreviewClassificationItem> = Vec::with_capacity(document.items.kv.len());
    for kv in &document.items.kv {
        let mount = if kv.mount.ends_with('/') { kv.mount.clone() } else { format!("{}/", kv.mount) };
        let path = kv.path.strip_prefix('/').unwrap_or(&kv.path);
        let full_path = format!("{mount}{path}");
        let new_bytes = match &kv.value {
            serde_json::Value::Object(map) if map.len() == 1 && map.contains_key("_base64") => {
                if let Some(serde_json::Value::String(b64)) = map.get("_base64") {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(b64.as_bytes())
                        .map_err(|_| RvError::ErrRequestInvalid)?
                } else {
                    serde_json::to_vec(&kv.value)?
                }
            }
            _ => serde_json::to_vec(&kv.value)?,
        };
        let existing = storage.get(&full_path).await?;
        let classification = match &existing {
            None => {
                new += 1;
                crate::exchange::ImportClassification::New
            }
            Some(e) if e.value == new_bytes => {
                identical += 1;
                crate::exchange::ImportClassification::Identical
            }
            Some(_) => {
                conflict += 1;
                crate::exchange::ImportClassification::Conflict
            }
        };
        items.push(crate::exchange::PreviewClassificationItem {
            mount: kv.mount.clone(),
            path: kv.path.clone(),
            classification,
        });
    }

    // Owner binding: tokens are bound to the actor's display name. We
    // pull it from the auth context — empty string when unauthenticated
    // (the route is gated; root-token operators see "" too, which is
    // fine since the apply call comes from the same actor).
    let owner = req.headers()
        .get("X-BastionVault-Actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let token = core.exchange_preview_store.insert(document, owner);

    Ok(response_json_ok(
        None,
        json!({
            "token": token,
            "expires_in_secs": core.exchange_preview_store.ttl_secs(),
            "total": items.len() as u64,
            "new": new,
            "identical": identical,
            "conflict": conflict,
            "items": items,
        }),
    ))
}

/// `POST /v1/sys/exchange/import/apply` — consume a preview token and
/// write the items per the supplied conflict policy.
#[derive(Debug, Deserialize)]
struct ExchangeApplyRequest {
    token: String,
    #[serde(default)]
    conflict_policy: crate::exchange::ConflictPolicy,
}

async fn sys_exchange_import_apply_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let payload: ExchangeApplyRequest =
        serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

    let owner = req.headers()
        .get("X-BastionVault-Actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let document = core
        .exchange_preview_store
        .consume(&payload.token, &owner)?;

    let result = crate::exchange::scope::import_from_document(
        core.barrier.as_storage(),
        &document,
        payload.conflict_policy,
    )
    .await?;

    Ok(response_json_ok(
        None,
        json!({
            "written": result.written,
            "unchanged": result.unchanged,
            "skipped": result.skipped,
            "renamed": result.renamed,
            "items": result.items,
        }),
    ))
}

/// `POST /v1/sys/exchange/import` — single-shot import, kept for callers
/// (CLI scripts, automation pipelines) that don't want to round-trip a
/// preview token. The two-step flow above is the GUI default.
async fn sys_exchange_import_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let mut payload: ExchangeImportRequest =
        serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

    let document_bytes = match payload.format.as_str() {
        "bvx" => {
            let password = payload.password.as_deref().ok_or(RvError::ErrRequestInvalid)?;
            let bytes = crate::exchange::decrypt_bvx(payload.file.as_bytes(), password)?;
            if let Some(ref mut p) = payload.password {
                p.zeroize();
            }
            bytes
        }
        "json" => {
            if !payload.allow_plaintext {
                return Ok(response_error(
                    StatusCode::BAD_REQUEST,
                    "plaintext import refused (set allow_plaintext: true to override)",
                ));
            }
            payload.file.as_bytes().to_vec()
        }
        _ => {
            return Ok(response_error(
                StatusCode::BAD_REQUEST,
                "format must be \"bvx\" or \"json\"",
            ));
        }
    };

    let document: crate::exchange::ExchangeDocument =
        serde_json::from_slice(&document_bytes).map_err(|_| RvError::ErrRequestInvalid)?;

    let result = crate::exchange::scope::import_from_document(
        core.barrier.as_storage(),
        &document,
        payload.conflict_policy,
    )
    .await?;

    Ok(response_json_ok(
        None,
        json!({
            "written": result.written,
            "unchanged": result.unchanged,
            "skipped": result.skipped,
            "renamed": result.renamed,
            "items": result.items,
        }),
    ))
}

async fn sys_import_request_handler(
    req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let _auth = request_auth(&req);

    let mount = req.match_info().get("mount").unwrap_or("").to_string();
    let mount = if mount.ends_with('/') { mount } else { format!("{mount}/") };

    #[derive(serde::Deserialize)]
    struct ImportPayload {
        #[serde(default)]
        version: u32,
        #[serde(default)]
        entries: Vec<crate::backup::export::ExportEntry>,
        #[serde(default)]
        force: bool,
    }

    let payload: ImportPayload = serde_json::from_slice(&body)?;
    body.clear();

    let export_data = crate::backup::export::ExportData {
        version: payload.version.max(1),
        created_at: String::new(),
        mount: mount.clone(),
        prefix: String::new(),
        entries: payload.entries,
    };

    let result = crate::backup::import::import_secrets(
        core.barrier.as_storage(),
        &mount,
        &export_data,
        payload.force,
    )
    .await?;

    Ok(response_json_ok(
        None,
        serde_json::json!({
            "imported": result.imported,
            "skipped": result.skipped,
        }),
    ))
}

fn configure_sys_routes(scope: actix_web::Scope) -> actix_web::Scope {
    scope
        .service(
            web::resource("/init")
                .route(web::get().to(sys_init_get_request_handler))
                .route(web::post().to(sys_init_put_request_handler))
                .route(web::put().to(sys_init_put_request_handler)),
        )
        .service(web::resource("/seal-status").route(web::get().to(sys_seal_status_request_handler)))
        .service(web::resource("/health").route(web::get().to(sys_health_request_handler)))
        .service(web::resource("/cluster-status").route(web::get().to(sys_cluster_status_request_handler)))
        .service(web::resource("/cluster/remove-node").route(web::post().to(sys_cluster_remove_node_request_handler)))
        .service(web::resource("/cluster/leave").route(web::post().to(sys_cluster_leave_request_handler)))
        .service(web::resource("/cluster/failover").route(web::post().to(sys_cluster_failover_request_handler)))
        .service(web::resource("/backup").route(web::post().to(sys_backup_request_handler)))
        .service(web::resource("/restore").route(web::post().to(sys_restore_request_handler)))
        .service(web::resource("/export/{path:.*}").route(web::get().to(sys_export_request_handler)))
        .service(web::resource("/import/{mount:.*}").route(web::post().to(sys_import_request_handler)))
        .service(web::resource("/exchange/export").route(web::post().to(sys_exchange_export_request_handler)))
        .service(web::resource("/exchange/import").route(web::post().to(sys_exchange_import_request_handler)))
        .service(web::resource("/exchange/import/preview").route(web::post().to(sys_exchange_import_preview_handler)))
        .service(web::resource("/exchange/import/apply").route(web::post().to(sys_exchange_import_apply_handler)))
        .service(
            web::resource("/seal")
                .route(web::post().to(sys_seal_request_handler))
                .route(web::put().to(sys_seal_request_handler)),
        )
        .service(
            web::resource("/unseal")
                .route(web::post().to(sys_unseal_request_handler))
                .route(web::put().to(sys_unseal_request_handler)),
        )
        .service(web::resource("/mounts").route(web::get().to(sys_list_mounts_request_handler)))
        .service(
            web::resource("/mounts/{path:.*}")
                .route(web::get().to(sys_list_mounts_request_handler))
                .route(web::post().to(sys_mount_request_handler))
                .route(web::delete().to(sys_unmount_request_handler)),
        )
        .service(
            web::resource("/remount")
                .route(web::post().to(sys_remount_request_handler))
                .route(web::put().to(sys_remount_request_handler)),
        )
        .service(web::resource("/auth").route(web::get().to(sys_list_auth_mounts_request_handler)))
        .service(
            web::resource("/auth/{path:.*}")
                .route(web::get().to(sys_list_auth_mounts_request_handler))
                .route(web::post().to(sys_auth_enable_request_handler))
                .route(web::delete().to(sys_auth_disable_request_handler)),
        )
        .service(web::resource("/policy").route(web::get().to(sys_list_policy_request_handler)))
        .service(
            web::resource("/policy/{name:.*}")
                .route(web::get().to(sys_read_policy_request_handler))
                .route(web::post().to(sys_write_policy_request_handler))
                .route(web::delete().to(sys_delete_policy_request_handler)),
        )
        .service(web::resource("/policies/acl").route(web::get().to(sys_list_policies_request_handler)))
        .service(
            web::resource("/policies/acl/{name:.*}")
                .route(web::get().to(sys_read_policies_request_handler))
                .route(web::post().to(sys_write_policies_request_handler))
                .route(web::delete().to(sys_delete_policies_request_handler)),
        )
        .service(
            web::resource("/audit/events").route(web::get().to(sys_audit_events_request_handler)),
        )
        .service(web::resource("/audit").route(web::get().to(sys_audit_list_request_handler)))
        .service(
            web::resource("/audit/{path:.*}")
                .route(web::post().to(sys_audit_enable_request_handler))
                .route(web::delete().to(sys_audit_disable_request_handler)),
        )
        .service(
            web::resource("/cache/flush").route(web::post().to(sys_cache_flush_request_handler)),
        )
        .service(
            web::resource("/owner/backfill")
                .route(web::post().to(sys_owner_backfill_request_handler)),
        )
        .service(
            web::resource("/internal/ui/mounts").route(web::get().to(sys_get_internal_ui_mounts_request_handler)),
        )
        .service(
            web::resource("/internal/ui/mounts/{name:.*}")
                .route(web::get().to(sys_get_internal_ui_mount_request_handler)),
        )
}

pub fn init_sys_service(cfg: &mut web::ServiceConfig) {
    cfg.service(configure_sys_routes(web::scope("/v1/sys")));
    // Batch is a v2-only route per the project's forward-going HTTP API
    // rule. Register it under the v2 scope only. The body-size limit is
    // enforced by the per-route `PayloadConfig`; when `Config` is not
    // available (tests without a loaded config) the default 32 MiB
    // from actix + our handler-level size check applies.
    cfg.service(
        configure_sys_routes(web::scope("/v2/sys"))
            .service(
                web::resource("/batch")
                    .app_data(web::JsonConfig::default().limit(default_batch_body_limit()))
                    .route(web::post().to(crate::http::batch::sys_batch_v2_request_handler)),
            ),
    );
}

/// Body-size limit for the batch route when no `Config` extension is
/// present. Matches the documented default in `features/batch-operations.md`.
fn default_batch_body_limit() -> usize {
    32 * 1024 * 1024
}
