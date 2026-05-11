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

    // Idempotent: if the vault is already unsealed, swallow the
    // `ErrBarrierUnsealed` and just return current seal status (200).
    // Matches HashiCorp Vault's behavior — re-running `vault operator
    // unseal` against an already-open vault is a no-op, not a 400.
    #[cfg(not(feature = "sync_handler"))]
    {
        match core.unseal(&key).await {
            Ok(_) | Err(RvError::ErrBarrierUnsealed) => {}
            Err(e) => return Err(e),
        }
        response_seal_status(core).await
    }

    #[cfg(feature = "sync_handler")]
    {
        match core.unseal(&key) {
            Ok(_) | Err(RvError::ErrBarrierUnsealed) => {}
            Err(e) => return Err(e),
        }
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
/// Parse the bytes that will be audit-logged into a JSON map, when
/// possible. Audit redaction (HMAC-per-string-leaf) runs against this
/// map inside `AuditEntry::from_response`, so passwords, file_b64,
/// payloads, etc. are HMAC'd in the persisted entry without us having
/// to teach the audit layer anything about exchange/plugin schemas.
fn body_to_audit_map(body: &web::Bytes) -> Option<serde_json::Map<String, serde_json::Value>> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.as_object().cloned())
}

/// Capture the bits each sys-level handler needs for audit emit before
/// the request body is consumed by the work closure. Returned struct is
/// fed to `emit_sys_audit` after the work completes (success or
/// failure) so every operation produces exactly one audit entry.
struct SysAuditCtx {
    core: Arc<Core>,
    token: String,
    body_for_audit: Option<serde_json::Map<String, serde_json::Value>>,
}

impl SysAuditCtx {
    fn new(req: &HttpRequest, body: &web::Bytes, core: &web::Data<Arc<Core>>) -> Self {
        Self {
            core: core.get_ref().clone(),
            token: request_auth(req).client_token,
            body_for_audit: body_to_audit_map(body),
        }
    }

    /// Variant for handlers without a request body (GET / DELETE / list
    /// endpoints). The audit entry's `data` field will be empty.
    fn new_no_body(req: &HttpRequest, core: &web::Data<Arc<Core>>) -> Self {
        Self {
            core: core.get_ref().clone(),
            token: request_auth(req).client_token,
            body_for_audit: None,
        }
    }

    async fn finish(
        self,
        result: &Result<HttpResponse, RvError>,
        path: &str,
        op: Operation,
    ) {
        let err_str = result.as_ref().err().map(|e| format!("{e}"));
        crate::audit::emit_sys_audit(
            &self.core,
            &self.token,
            path,
            op,
            self.body_for_audit,
            err_str.as_deref(),
        )
        .await;
    }
}

async fn sys_exchange_export_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);

    let result: Result<HttpResponse, RvError> = (async move {
        let mut payload: ExchangeExportRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

    // Build the bvx.v1 document by walking barrier-decrypted storage.
    let exporter = crate::exchange::ExporterInfo::default();
    let core_arc = core.get_ref().clone();
    let mounts = crate::exchange::scope::MountIndex::from_core(&core_arc)?;
    let document = crate::exchange::scope::export_to_document(
        core.barrier.as_storage(),
        &mounts,
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
    })
    .await;
    audit.finish(&result, "sys/exchange/export", Operation::Write).await;
    result
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
    let audit = SysAuditCtx::new(&req, &body, &core);
    // Owner header is needed inside the work block but `req` is not moved
    // into the closure (we only own a few captures), so resolve it now.
    let owner_header = req
        .headers()
        .get("X-BastionVault-Actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let result: Result<HttpResponse, RvError> = (async move {
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

    // Owner binding: tokens are bound to the actor's display name; the
    // header was resolved before we moved into the async block.
    let preview_token = core.exchange_preview_store.insert(document, owner_header);

    Ok(response_json_ok(
        None,
        json!({
            "token": preview_token,
            "expires_in_secs": core.exchange_preview_store.ttl_secs(),
            "total": items.len() as u64,
            "new": new,
            "identical": identical,
            "conflict": conflict,
            "items": items,
        }),
    ))
    })
    .await;
    audit.finish(&result, "sys/exchange/import/preview", Operation::Write).await;
    result
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
    let audit = SysAuditCtx::new(&req, &body, &core);
    let owner_header = req
        .headers()
        .get("X-BastionVault-Actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let result: Result<HttpResponse, RvError> = (async move {
        let payload: ExchangeApplyRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

        let document = core
            .exchange_preview_store
            .consume(&payload.token, &owner_header)?;

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
    })
    .await;
    audit.finish(&result, "sys/exchange/import/apply", Operation::Write).await;
    result
}

// ── Plugins (Phase 1: WASM substrate) ─────────────────────────────────────
//
// Catalog CRUD plus an `invoke` endpoint that runs a registered plugin
// in a fresh wasmtime sandbox. ML-DSA signature verification, hot reload,
// and out-of-process runtime are deferred per
// `features/plugin-system.md`. CI must fail if either OpenSSL or
// `aws-lc-sys` becomes reachable through this code path.

#[derive(Debug, Deserialize)]
struct PluginRegisterRequest {
    manifest: crate::plugins::PluginManifest,
    /// Base64-encoded WASM binary. Operators upload the bytes inline
    /// rather than a path so the entire registration is one barrier-
    /// scoped transaction.
    binary_b64: String,
    /// Plugin Extensibility v1: base64-encoded `surface.json` bytes,
    /// when the manifest declares a surface. The catalog cross-checks
    /// the SHA-256 against `manifest.surface.sha256`.
    #[serde(default)]
    surface_b64: Option<String>,
    /// Plugin Extensibility v1: base64-encoded client assets (form
    /// hooks today). Each entry's `name` must match a corresponding
    /// `client_assets[]` entry in the manifest.
    #[serde(default)]
    client_assets_b64: Vec<PluginRegisterAsset>,
}

#[derive(Debug, Deserialize)]
struct PluginRegisterAsset {
    name: String,
    bytes_b64: String,
}

async fn sys_plugins_list_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        let manifests = catalog.list(core.barrier.as_storage()).await?;
        Ok(response_json_ok(None, json!({ "plugins": manifests })))
    })
    .await;
    audit.finish(&result, "sys/plugins", Operation::List).await;
    result
}

async fn sys_plugins_register_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let result: Result<HttpResponse, RvError> = (async move {
        use base64::Engine;
        let payload: PluginRegisterRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;
        let binary = base64::engine::general_purpose::STANDARD
            .decode(payload.binary_b64.as_bytes())
            .map_err(|_| RvError::ErrRequestInvalid)?;

        let catalog = crate::plugins::PluginCatalog::new();
        catalog.put(core.barrier.as_storage(), &payload.manifest, &binary).await?;

        // Plugin Extensibility v1: persist surface + assets when the
        // operator uploaded them. The catalog re-verifies hashes
        // against the manifest declarations, so a tampered upload
        // fails registration with a clear error rather than landing
        // a half-bad plugin.
        let surface_present = payload.manifest.surface.is_some();
        if let (Some(surface_b64), Some(surface_ref)) =
            (payload.surface_b64.as_ref(), payload.manifest.surface.as_ref())
        {
            let surface_bytes = base64::engine::general_purpose::STANDARD
                .decode(surface_b64.as_bytes())
                .map_err(|_| RvError::ErrRequestInvalid)?;
            catalog
                .put_surface(
                    core.barrier.as_storage(),
                    &payload.manifest.name,
                    &payload.manifest.version,
                    &surface_bytes,
                    &surface_ref.sha256,
                )
                .await?;
        } else if surface_present {
            return Err(RvError::ErrString(
                "manifest declares a surface but request omitted `surface_b64`".into(),
            ));
        }
        // Cross-check declared assets against uploaded ones.
        let declared: std::collections::BTreeMap<&str, &crate::plugins::manifest::ClientAssetRef> =
            payload
                .manifest
                .client_assets
                .iter()
                .map(|a| (a.name.as_str(), a))
                .collect();
        let uploaded: std::collections::BTreeMap<&str, &str> = payload
            .client_assets_b64
            .iter()
            .map(|a| (a.name.as_str(), a.bytes_b64.as_str()))
            .collect();
        for n in declared.keys() {
            if !uploaded.contains_key(n) {
                return Err(RvError::ErrString(format!(
                    "manifest declares client asset `{n}` but no matching upload was provided"
                )));
            }
        }
        for (n, b64) in &uploaded {
            let aref = declared.get(n).ok_or_else(|| {
                RvError::ErrString(format!("uploaded asset `{n}` not declared in manifest"))
            })?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| RvError::ErrRequestInvalid)?;
            if (bytes.len() as u64) != aref.size {
                return Err(RvError::ErrString(format!(
                    "asset `{n}` size {} does not match declared {}",
                    bytes.len(),
                    aref.size
                )));
            }
            catalog
                .put_asset(
                    core.barrier.as_storage(),
                    &payload.manifest.name,
                    &payload.manifest.version,
                    &bytes,
                    &aref.sha256,
                )
                .await?;
        }

        Ok(response_json_ok(None, json!({ "manifest": payload.manifest })))
    })
    .await;
    audit.finish(&result, "sys/plugins/register", Operation::Write).await;
    result
}

async fn sys_plugins_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        match catalog.get_manifest(core.barrier.as_storage(), &name).await? {
            Some(m) => Ok(response_json_ok(None, json!({ "manifest": m }))),
            None => Ok(response_error(StatusCode::NOT_FOUND, "plugin not found")),
        }
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_plugins_delete_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        catalog.delete(core.barrier.as_storage(), &name).await?;
        Ok(response_ok(None, None))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Delete).await;
    result
}

#[derive(Debug, Deserialize)]
struct PluginInvokeRequest {
    /// Base64-encoded request payload handed to the plugin. The plugin
    /// gets these bytes verbatim in its linear memory; what they mean
    /// is up to the plugin's contract with its caller.
    #[serde(default)]
    input_b64: String,
    /// Optional fuel override. Capped by the host's max budget regardless.
    #[serde(default)]
    fuel: Option<u64>,
}

async fn sys_plugins_versions_list_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/versions");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        let versions = catalog.list_versions(core.barrier.as_storage(), &name).await?;
        let active = catalog
            .get_active_version(core.barrier.as_storage(), &name)
            .await?;
        Ok(response_json_ok(
            None,
            json!({ "versions": versions, "active": active }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::List).await;
    result
}

async fn sys_plugins_versions_activate_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let version = req.match_info().get("version").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/versions/{version}/activate");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        catalog
            .set_active(core.barrier.as_storage(), &name, &version)
            .await?;
        // Activating a different version means the cached compiled
        // module for the previous binary is no longer the right thing
        // to invoke. Cheap insurance: invalidate.
        let cache = crate::plugins::ModuleCache::shared().map_err(|_| RvError::ErrUnknown)?;
        cache.invalidate(&name);
        Ok(response_json_ok(
            None,
            json!({ "name": name, "active": version }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

async fn sys_plugins_versions_delete_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let version = req.match_info().get("version").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/versions/{version}");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        catalog
            .delete_version(core.barrier.as_storage(), &name, &version)
            .await?;
        Ok(response_ok(None, None))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Delete).await;
    result
}

async fn sys_plugins_reload_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/reload");
    let result: Result<HttpResponse, RvError> = (async move {
        // Phase 5.6: drain-and-swap. Acquire the per-plugin reload
        // gate's *write* side, which blocks on every in-flight
        // invocation completing. Default drain timeout: 10s.
        let drain_timeout = std::time::Duration::from_secs(10);
        let _reload_guard = match crate::plugins::reload_lock::acquire_reload(&name, drain_timeout).await {
            Ok(g) => g,
            Err(e) => {
                return Ok(response_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("plugin_reloading: {e}"),
                ));
            }
        };

        // Re-fetch the active record + verify its sha256 against the
        // stored binary. This catches storage-side tampering before
        // the next invocation. After verification we drop the cached
        // compiled module so the next invoke recompiles fresh.
        let catalog = crate::plugins::PluginCatalog::new();
        let record = match catalog.get(core.barrier.as_storage(), &name).await? {
            Some(r) => r,
            None => return Ok(response_error(StatusCode::NOT_FOUND, "plugin not found")),
        };
        let cache = crate::plugins::ModuleCache::shared().map_err(|_| RvError::ErrUnknown)?;
        let evicted = cache.invalidate(&name);
        // Phase 5.3: also tear down any long-lived supervised child
        // so the new version doesn't share the previous version's
        // process. The next invoke respawns under the breaker.
        crate::plugins::process_supervisor::shutdown_for(&name).await;
        // The reload guard drops here; queued invocations resume
        // against the freshly-compiled module on next call.
        Ok(response_json_ok(
            None,
            json!({
                "name": name,
                "active_version": record.manifest.version,
                "sha256": record.manifest.sha256,
                "cache_entries_evicted": evicted,
                "drained_via": "reload_lock::acquire_reload (10s drain)",
            }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

async fn sys_plugins_config_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/config");
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        let manifest = match catalog
            .get_manifest(core.barrier.as_storage(), &name)
            .await?
        {
            Some(m) => m,
            None => return Ok(response_error(StatusCode::NOT_FOUND, "plugin not found")),
        };
        let store = crate::plugins::ConfigStore::new();
        let values = store
            .get_redacted(core.barrier.as_storage(), &manifest)
            .await?;
        Ok(response_json_ok(
            None,
            json!({
                "schema": manifest.config_schema,
                "values": values,
            }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

#[derive(Debug, Deserialize)]
struct PluginConfigPutRequest {
    values: std::collections::BTreeMap<String, String>,
}

async fn sys_plugins_config_put_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/config");
    let result: Result<HttpResponse, RvError> = (async move {
        let payload: PluginConfigPutRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;
        let catalog = crate::plugins::PluginCatalog::new();
        let manifest = match catalog
            .get_manifest(core.barrier.as_storage(), &name)
            .await?
        {
            Some(m) => m,
            None => return Ok(response_error(StatusCode::NOT_FOUND, "plugin not found")),
        };
        let store = crate::plugins::ConfigStore::new();
        store
            .put(core.barrier.as_storage(), &manifest, payload.values)
            .await?;
        Ok(response_ok(None, None))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

// ── Phase 5.2: publisher allowlist + accept_unsigned engine flag ──

#[derive(Debug, Deserialize)]
struct PublishersPutRequest {
    /// Map from publisher identifier → hex-encoded ML-DSA-65 public key.
    keys: std::collections::BTreeMap<String, String>,
}

async fn sys_plugins_publishers_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let audit_path = "sys/plugins/publishers".to_string();
    let result: Result<HttpResponse, RvError> = (async move {
        let allow =
            crate::plugins::verifier::PublisherAllowlist::load(core.barrier.as_storage()).await?;
        let unsigned =
            crate::plugins::verifier::read_accept_unsigned(core.barrier.as_storage()).await?;
        Ok(response_json_ok(
            None,
            json!({
                "publishers": allow.keys,
                "accept_unsigned": unsigned,
            }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_plugins_publishers_put_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let audit_path = "sys/plugins/publishers".to_string();
    let result: Result<HttpResponse, RvError> = (async move {
        let payload: PublishersPutRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;
        let allow = crate::plugins::verifier::PublisherAllowlist {
            keys: payload.keys,
        };
        allow.save(core.barrier.as_storage()).await?;
        Ok(response_json_ok(None, json!({ "ok": true })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

#[derive(Debug, Deserialize)]
struct AcceptUnsignedPutRequest {
    accept_unsigned: bool,
}

async fn sys_plugins_accept_unsigned_put_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let audit_path = "sys/plugins/accept_unsigned".to_string();
    let result: Result<HttpResponse, RvError> = (async move {
        let payload: AcceptUnsignedPutRequest =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;
        crate::plugins::verifier::write_accept_unsigned(
            core.barrier.as_storage(),
            payload.accept_unsigned,
        )
        .await?;
        if payload.accept_unsigned {
            log::warn!(
                "sys/plugins/accept_unsigned set to true — unsigned plugins will load (development mode)"
            );
        }
        Ok(response_json_ok(
            None,
            json!({ "accept_unsigned": payload.accept_unsigned }),
        ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

// ── Plugin Extensibility v1: surface + assets ────────────────────────

async fn sys_plugins_surface_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/surface");
    let if_none_match = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        match catalog.read_active_surface(core.barrier.as_storage(), &name).await? {
            None => Ok(response_error(StatusCode::NOT_FOUND, "no surface for this plugin")),
            Some((manifest, bytes)) => {
                // Hash is already verified by `read_active_surface`;
                // use the stored `surface.sha256` directly so we
                // don't re-hash on every fetch.
                let etag = manifest
                    .surface
                    .as_ref()
                    .map(|s| s.sha256.clone())
                    .unwrap_or_default();
                if if_none_match.as_deref() == Some(etag.as_str()) {
                    return Ok(HttpResponse::NotModified()
                        .insert_header(("ETag", format!("\"{etag}\"")))
                        .finish());
                }
                let parsed: bv_plugin_surface::SurfaceManifest =
                    serde_json::from_slice(&bytes).map_err(|_| RvError::ErrRequestInvalid)?;
                Ok(HttpResponse::Ok()
                    .insert_header(("ETag", format!("\"{etag}\"")))
                    .insert_header(("Cache-Control", "no-cache"))
                    .json(json!({
                        "data": {
                            "plugin": manifest.name,
                            "version": manifest.version,
                            "etag": etag,
                            "surface": parsed,
                        }
                    })))
            }
        }
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_plugins_active_surfaces_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let audit_path = "sys/plugins/active-surfaces".to_string();
    let if_none_match = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());

    // Plugin Extensibility v1 / Phase 5: `?watch=1` upgrades the
    // request to a long-poll. The handler keeps recomputing the
    // aggregated bundle every ~2 s; as soon as the ETag differs from
    // the operator-supplied `If-None-Match` (or after a 30 s timeout)
    // it returns. Cheaper than SSE/WS — fits the existing actix-web
    // plumbing — and a missed wakeup just means the GUI re-polls on
    // the next tick.
    let query = req.query_string();
    let watch_requested =
        query.split('&').any(|kv| matches!(kv, "watch=1" | "watch=true"));

    let result: Result<HttpResponse, RvError> = (async move {
        let catalog = crate::plugins::PluginCatalog::new();
        // Mount lookup is wired in Phase 1 with a placeholder (empty
        // string) — the GUI tolerates an empty mount because it only
        // resolves bindings client-side. A future Phase 1 follow-up
        // will inject the actual mount registry here.
        let mut bundle = catalog
            .aggregated_active_surfaces(core.barrier.as_storage(), |_| None)
            .await?;

        if watch_requested && if_none_match.as_deref() == Some(bundle.etag.as_str()) {
            // Long-poll loop. 25 s ceiling (leaves 5 s of slack
            // before the bv-client default 30 s `timeout_global`
            // fires), 2 s polling cadence. Deliberately conservative:
            // no Notify-channel wakeup wired on activate/delete yet,
            // so the worst case is a ~2 s lag between activation and
            // the GUI re-rendering.
            let started = std::time::Instant::now();
            let max_wait = std::time::Duration::from_secs(25);
            let poll_interval = std::time::Duration::from_millis(2000);
            while started.elapsed() < max_wait {
                tokio::time::sleep(poll_interval).await;
                let next = catalog
                    .aggregated_active_surfaces(core.barrier.as_storage(), |_| None)
                    .await?;
                if next.etag != bundle.etag {
                    bundle = next;
                    break;
                }
            }
        }

        if if_none_match.as_deref() == Some(bundle.etag.as_str()) {
            return Ok(HttpResponse::NotModified()
                .insert_header(("ETag", format!("\"{}\"", bundle.etag)))
                .finish());
        }
        Ok(HttpResponse::Ok()
            .insert_header(("ETag", format!("\"{}\"", bundle.etag)))
            .insert_header(("Cache-Control", "no-cache"))
            .json(json!({ "data": bundle })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_plugins_asset_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let version = req.match_info().get("version").unwrap_or("").to_string();
    let sha256 = req.match_info().get("sha256").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/{version}/asset/{sha256}");
    // Defence-in-depth: the regex on the route already constrains
    // shape, but reject anything that isn't lowercase hex of length
    // 64 here too.
    let valid_hash =
        sha256.len() == 64 && sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    let result: Result<HttpResponse, RvError> = (async move {
        if !valid_hash {
            return Ok(response_error(StatusCode::BAD_REQUEST, "asset sha256 must be 64 lowercase hex chars"));
        }
        let catalog = crate::plugins::PluginCatalog::new();
        match catalog
            .read_asset(core.barrier.as_storage(), &name, &version, &sha256)
            .await?
        {
            None => Ok(response_error(StatusCode::NOT_FOUND, "asset not found")),
            Some(bytes) => Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .insert_header(("ETag", format!("\"{sha256}\"")))
                .insert_header(("Cache-Control", "public, max-age=31536000, immutable"))
                .body(bytes)),
        }
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

// ── Phase 5.7: list quarantined plugins (recovery aid) ──

async fn sys_plugins_quarantine_list_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let audit_path = "sys/plugins/quarantine".to_string();
    let result: Result<HttpResponse, RvError> = (async move {
        let names = crate::plugins::quarantine::list(core.barrier.as_storage()).await?;
        let mut entries = serde_json::Map::new();
        for name in names {
            if let Some(rec) =
                crate::plugins::quarantine::lookup(core.barrier.as_storage(), &name).await?
            {
                entries.insert(name, serde_json::to_value(rec).unwrap_or(serde_json::Value::Null));
            }
        }
        Ok(response_json_ok(None, json!({ "quarantined": entries })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_plugins_invoke_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let name = req.match_info().get("name").unwrap_or("").to_string();
    let audit_path = format!("sys/plugins/{name}/invoke");

    let result: Result<HttpResponse, RvError> = (async move {
    use base64::Engine;
    let payload: PluginInvokeRequest = if body.is_empty() {
        PluginInvokeRequest { input_b64: String::new(), fuel: None }
    } else {
        serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?
    };
    let input = base64::engine::general_purpose::STANDARD
        .decode(payload.input_b64.as_bytes())
        .map_err(|_| RvError::ErrRequestInvalid)?;

    let catalog = crate::plugins::PluginCatalog::new();
    let record = match catalog.get(core.barrier.as_storage(), &name).await? {
        Some(r) => r,
        None => return Ok(response_error(StatusCode::NOT_FOUND, "plugin not found")),
    };

    // Load operator-supplied config (if any) before invoking — both
    // runtimes accept a config map and expose it to the plugin via
    // `bv.config_get`.
    let core_arc: Arc<Core> = Arc::clone(&*core);
    let config_store = crate::plugins::ConfigStore::new();
    let config = config_store
        .get(core_arc.barrier.as_storage(), &record.manifest.name)
        .await
        .unwrap_or_default();

    // Dispatch by manifest.runtime: WASM stays in the wasmtime sandbox,
    // Process spawns a subprocess and mediates host calls over JSON-RPC
    // on stdio. The output shape is identical regardless of runtime.
    let output = match record.manifest.runtime {
        crate::plugins::RuntimeKind::Wasm => {
            let fuel = payload
                .fuel
                .unwrap_or(crate::plugins::DEFAULT_FUEL)
                .min(crate::plugins::DEFAULT_FUEL.saturating_mul(10));
            let runtime = crate::plugins::WasmRuntime::with_budgets(
                fuel,
                crate::plugins::DEFAULT_MEMORY_BYTES,
            )
            .map_err(|_| RvError::ErrUnknown)?;
            runtime
                .invoke_with_config(&record.manifest, &record.binary, &input, Some(core_arc), config)
                .await
                .map_err(|e| {
                    log::warn!("plugin {} wasm invoke failed: {e}", record.manifest.name);
                    RvError::ErrRequestInvalid
                })?
        }
        crate::plugins::RuntimeKind::Process => {
            let runtime = crate::plugins::ProcessRuntime::new();
            runtime
                .invoke_with_config(&record.manifest, &record.binary, &input, Some(core_arc), config)
                .await
                .map_err(|e| {
                    log::warn!("plugin {} process invoke failed: {e}", record.manifest.name);
                    RvError::ErrRequestInvalid
                })?
        }
    };

    let (status, plugin_status) = match output.outcome {
        crate::plugins::InvokeOutcome::Success => ("success", 0),
        crate::plugins::InvokeOutcome::PluginError(s) => ("plugin_error", s),
    };
    Ok(response_json_ok(
        None,
        json!({
            "status": status,
            "plugin_status_code": plugin_status,
            "fuel_consumed": output.fuel_consumed,
            "response_b64": base64::engine::general_purpose::STANDARD.encode(&output.response),
        }),
    ))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

// ── Scheduled exports ─────────────────────────────────────────────────────
//
// CRUD over `core/scheduled_exports/schedules/*` plus run history. The
// scheduler tick loop is owned by `Core::post_unseal` (see
// `scheduled_exports::runner::start_scheduler`); these endpoints are the
// management surface. See `features/scheduled-exports.md`.

async fn sys_scheduled_exports_list_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let result: Result<HttpResponse, RvError> = (async move {
        let store = crate::scheduled_exports::ScheduleStore::new();
        let list = store.list(core.barrier.as_storage()).await?;
        Ok(response_json_ok(None, json!({ "schedules": list })))
    })
    .await;
    audit.finish(&result, "sys/scheduled-exports", Operation::List).await;
    result
}

async fn sys_scheduled_exports_create_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let result: Result<HttpResponse, RvError> = (async move {
        let input: crate::scheduled_exports::ScheduleInput =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

        use std::str::FromStr;
        cron::Schedule::from_str(&input.cron).map_err(|_| RvError::ErrRequestInvalid)?;

        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let sched = crate::scheduled_exports::Schedule {
            id: id.clone(),
            name: input.name,
            cron: input.cron,
            format: input.format,
            scope: input.scope,
            destination: input.destination,
            password_ref: input.password_ref,
            allow_plaintext: input.allow_plaintext,
            comment: input.comment,
            created_at: now.clone(),
            updated_at: now,
            enabled: input.enabled,
        };
        let store = crate::scheduled_exports::ScheduleStore::new();
        store.put(core.barrier.as_storage(), &sched).await?;
        Ok(response_json_ok(None, json!({ "schedule": sched })))
    })
    .await;
    audit.finish(&result, "sys/scheduled-exports/create", Operation::Write).await;
    result
}

async fn sys_scheduled_exports_get_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let audit_path = format!("sys/scheduled-exports/{id}");
    let result: Result<HttpResponse, RvError> = (async move {
        let store = crate::scheduled_exports::ScheduleStore::new();
        let sched = store.get(core.barrier.as_storage(), &id).await?;
        match sched {
            Some(s) => Ok(response_json_ok(None, json!({ "schedule": s }))),
            None => Ok(response_error(StatusCode::NOT_FOUND, "schedule not found")),
        }
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Read).await;
    result
}

async fn sys_scheduled_exports_update_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let audit_path = format!("sys/scheduled-exports/{id}");
    let result: Result<HttpResponse, RvError> = (async move {
        let input: crate::scheduled_exports::ScheduleInput =
            serde_json::from_slice(&body).map_err(|_| RvError::ErrRequestInvalid)?;

        use std::str::FromStr;
        cron::Schedule::from_str(&input.cron).map_err(|_| RvError::ErrRequestInvalid)?;

        let store = crate::scheduled_exports::ScheduleStore::new();
        let existing = store.get(core.barrier.as_storage(), &id).await?;
        let existing = match existing {
            Some(s) => s,
            None => return Ok(response_error(StatusCode::NOT_FOUND, "schedule not found")),
        };
        let sched = crate::scheduled_exports::Schedule {
            id: existing.id,
            name: input.name,
            cron: input.cron,
            format: input.format,
            scope: input.scope,
            destination: input.destination,
            password_ref: input.password_ref,
            allow_plaintext: input.allow_plaintext,
            comment: input.comment,
            created_at: existing.created_at,
            updated_at: chrono::Utc::now().to_rfc3339(),
            enabled: input.enabled,
        };
        store.put(core.barrier.as_storage(), &sched).await?;
        Ok(response_json_ok(None, json!({ "schedule": sched })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

async fn sys_scheduled_exports_delete_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let audit_path = format!("sys/scheduled-exports/{id}");
    let result: Result<HttpResponse, RvError> = (async move {
        let store = crate::scheduled_exports::ScheduleStore::new();
        store.delete(core.barrier.as_storage(), &id).await?;
        Ok(response_ok(None, None))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Delete).await;
    result
}

async fn sys_scheduled_exports_runs_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let audit_path = format!("sys/scheduled-exports/{id}/runs");
    let result: Result<HttpResponse, RvError> = (async move {
        let store = crate::scheduled_exports::ScheduleStore::new();
        let runs = store.list_runs(core.barrier.as_storage(), &id).await?;
        Ok(response_json_ok(None, json!({ "runs": runs })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::List).await;
    result
}

/// Trigger an immediate one-off run, separate from the cron cadence.
/// Useful for "test my schedule" workflows in the GUI.
async fn sys_scheduled_exports_run_now_handler(
    req: HttpRequest,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new_no_body(&req, &core);
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let audit_path = format!("sys/scheduled-exports/{id}/run-now");
    let result: Result<HttpResponse, RvError> = (async move {
        let store = crate::scheduled_exports::ScheduleStore::new();
        let sched = store.get(core.barrier.as_storage(), &id).await?
            .ok_or_else(|| RvError::ErrRequestInvalid)?;

    let core_arc = core.get_ref().clone();
    let outcome = crate::scheduled_exports::runner::run_once(&core_arc, &sched).await;
    let record = match outcome {
        Ok((bytes, dest)) => crate::scheduled_exports::RunRecord {
            schedule_id: sched.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            status: crate::scheduled_exports::RunStatus::Success,
            bytes_written: bytes,
            destination: dest,
            error: None,
        },
        Err(e) => crate::scheduled_exports::RunRecord {
            schedule_id: sched.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            status: crate::scheduled_exports::RunStatus::Failed,
            bytes_written: 0,
            destination: sched.destination.clone(),
            error: Some(format!("{e}")),
        },
    };
    let _ = store.append_run(core.barrier.as_storage(), &record).await;
    Ok(response_json_ok(None, json!({ "run": record })))
    })
    .await;
    audit.finish(&result, &audit_path, Operation::Write).await;
    result
}

/// `POST /v1/sys/exchange/import` — single-shot import, kept for callers
/// (CLI scripts, automation pipelines) that don't want to round-trip a
/// preview token. The two-step flow above is the GUI default.
async fn sys_exchange_import_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let audit = SysAuditCtx::new(&req, &body, &core);

    let result: Result<HttpResponse, RvError> = (async move {
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
    })
    .await;
    audit.finish(&result, "sys/exchange/import", Operation::Write).await;
    result
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
            web::resource("/scheduled-exports")
                .route(web::get().to(sys_scheduled_exports_list_handler))
                .route(web::post().to(sys_scheduled_exports_create_handler)),
        )
        .service(
            web::resource("/scheduled-exports/{id}")
                .route(web::get().to(sys_scheduled_exports_get_handler))
                .route(web::put().to(sys_scheduled_exports_update_handler))
                .route(web::delete().to(sys_scheduled_exports_delete_handler)),
        )
        .service(
            web::resource("/scheduled-exports/{id}/runs")
                .route(web::get().to(sys_scheduled_exports_runs_handler)),
        )
        .service(
            web::resource("/scheduled-exports/{id}/run-now")
                .route(web::post().to(sys_scheduled_exports_run_now_handler)),
        )
        .service(
            // Plugin registration uploads the manifest + binary (and
            // optionally a surface + client assets) inline as base64
            // inside one JSON body. A real `.bvplugin` is comfortably
            // bigger than actix's default 256 KiB `web::Bytes` limit;
            // without an explicit `PayloadConfig` the server resets
            // the connection mid-upload (Windows surfaces this as
            // `ConnectionAborted` / WSAECONNABORTED 10053). Use the
            // same 32 MiB ceiling logical and batch already settled
            // on so operators don't hit a different limit on a
            // different route.
            web::resource("/plugins")
                .app_data(web::PayloadConfig::default().limit(default_plugin_register_body_limit()))
                .route(web::get().to(sys_plugins_list_handler))
                .route(web::post().to(sys_plugins_register_handler)),
        )
        // Literal `/plugins/<word>` resources MUST be registered before
        // the `/plugins/{name}` wildcard — actix-web matches resources
        // in registration order, so a wildcard registered first would
        // swallow `publishers`, `accept_unsigned`, `quarantine`, and
        // `active-surfaces` and answer 404 "plugin not found".
        .service(
            web::resource("/plugins/publishers")
                .route(web::get().to(sys_plugins_publishers_get_handler))
                .route(web::put().to(sys_plugins_publishers_put_handler)),
        )
        .service(
            web::resource("/plugins/accept_unsigned")
                .route(web::put().to(sys_plugins_accept_unsigned_put_handler)),
        )
        .service(
            web::resource("/plugins/quarantine")
                .route(web::get().to(sys_plugins_quarantine_list_handler)),
        )
        .service(
            web::resource("/plugins/active-surfaces")
                .route(web::get().to(sys_plugins_active_surfaces_handler)),
        )
        .service(
            web::resource("/plugins/{name}")
                .route(web::get().to(sys_plugins_get_handler))
                .route(web::delete().to(sys_plugins_delete_handler)),
        )
        .service(
            // Plugin invocations carry their input inline as base64
            // inside the JSON body. Some plugins (e.g. `xca-import`)
            // legitimately receive multi-MiB blobs — an entire XCA
            // `.xdb` database — so we'd otherwise blow through actix's
            // 256 KiB `web::Bytes` default and the server would reset
            // the connection mid-upload (ureq surfaces this as
            // `BrokenPipe` / EPIPE on macOS, `ConnectionAborted` on
            // Windows). Reuse the 32 MiB ceiling already established
            // for registration / logical / batch.
            web::resource("/plugins/{name}/invoke")
                .app_data(web::PayloadConfig::default().limit(default_plugin_invoke_body_limit()))
                .route(web::post().to(sys_plugins_invoke_handler)),
        )
        .service(
            web::resource("/plugins/{name}/config")
                .route(web::get().to(sys_plugins_config_get_handler))
                .route(web::put().to(sys_plugins_config_put_handler)),
        )
        .service(
            web::resource("/plugins/{name}/reload")
                .route(web::post().to(sys_plugins_reload_handler)),
        )
        .service(
            web::resource("/plugins/{name}/versions")
                .route(web::get().to(sys_plugins_versions_list_handler)),
        )
        .service(
            web::resource("/plugins/{name}/versions/{version}/activate")
                .route(web::post().to(sys_plugins_versions_activate_handler)),
        )
        .service(
            web::resource("/plugins/{name}/versions/{version}")
                .route(web::delete().to(sys_plugins_versions_delete_handler)),
        )
        .service(
            web::resource("/plugins/{name}/surface")
                .route(web::get().to(sys_plugins_surface_get_handler)),
        )
        .service(
            web::resource("/plugins/{name}/versions/{version}/asset/{sha256}")
                .route(web::get().to(sys_plugins_asset_get_handler)),
        )
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

/// Body-size limit for `POST /v1/sys/plugins` (registration). Plugin
/// bundles routinely run a few MiB, so the actix default of 256 KiB
/// rejects most uploads mid-stream. 32 MiB matches the logical and
/// batch limits.
fn default_plugin_register_body_limit() -> usize {
    32 * 1024 * 1024
}

/// Body-size limit for `POST /v1/sys/plugins/{name}/invoke`. Plugin
/// inputs are shipped as base64-encoded JSON; some plugins (notably
/// `xca-import`) receive multi-MiB blobs inline, so the actix 256 KiB
/// `web::Bytes` default would reset the connection mid-upload. 32 MiB
/// matches the register / logical / batch limits.
fn default_plugin_invoke_body_limit() -> usize {
    32 * 1024 * 1024
}
