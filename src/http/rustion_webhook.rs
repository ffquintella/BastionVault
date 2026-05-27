//! Dedicated actix route for the Rustion `recording.ready` webhook.
//!
//! Rustion's `rustion-control-plane::webhook` deliverer POSTs the
//! **raw recording sidecar JSON** as the request body, with the
//! hybrid signature carried in the `X-Rustion-Signature` header
//! (`ed25519=<base64> mldsa65=<base64>`) and `Content-Type:
//! application/json`. It does NOT wrap the payload in the
//! `{bastion_id, signature, sidecar_json}` envelope the original
//! logical-backend handler expected, and it never embeds a per-bastion
//! id in the body (the sidecar's `authority` is shared across every
//! bastion enrolled under this BV).
//!
//! BV's logical-backend plumbing only exposes the *parsed* JSON body
//! and cannot recover the exact bytes the bastion signed (key order /
//! whitespace would differ on re-serialisation), nor read the
//! signature header. This dedicated actix route sits in front of the
//! `/v1` catch-all and verifies `sha256(raw body)` against the
//! pinned key directly off the wire.
//!
//! Bastion identification: the configured `recording_webhook_url`
//! should carry `?bastion_id=rt_…` so we can pick the exact pinned
//! key. When absent, we fall back to trying every enrolled target's
//! key until one verifies (the signature is the real authenticator).

use std::{collections::HashMap, sync::Arc};

use actix_web::{web, HttpRequest, HttpResponse};
use serde_json::{Map, Value};

use crate::{
    bv_error_response_status,
    core::Core,
    errors::RvError,
    http::response_json_ok,
    modules::rustion::{audit, recordings, store::RustionStore, webhook_verify},
};

const SIG_HEADER: &str = "X-Rustion-Signature";

pub fn init_rustion_webhook_service(cfg: &mut web::ServiceConfig) {
    // Registered before the `/v1/{path:.*}` logical catch-all (see
    // `http::init_service`) so this exact path wins. Any other path
    // falls through to the logical backend.
    cfg.service(
        web::resource("/v1/rustion/webhooks/recording-ready")
            .route(web::post().to(recording_ready)),
    );
}

async fn recording_ready(
    req: HttpRequest,
    body: web::Bytes,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    let sig = req
        .headers()
        .get(SIG_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    if sig.is_empty() {
        return Err(bv_error_response_status!(
            400,
            "X-Rustion-Signature header is required"
        ));
    }
    if body.is_empty() {
        return Err(bv_error_response_status!(400, "empty request body"));
    }

    // Optional bastion id hint from the query string.
    let bastion_hint = web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .ok()
        .and_then(|q| q.get("bastion_id").map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty());

    let targets = RustionStore::new(core.get_ref()).await?;

    // Resolve which enrolled target's pinned key verifies the payload.
    let bastion_id = match &bastion_hint {
        Some(bid) => {
            let target = targets.get_target(bid).await?.ok_or_else(|| {
                bv_error_response_status!(404, &format!("bastion `{bid}` not enrolled"))
            })?;
            webhook_verify::verify(
                &target.public_key.ed25519,
                &target.public_key.mldsa65,
                &sig,
                &body,
            )
            .map_err(|e| bv_error_response_status!(401, &format!("signature verify: {e}")))?;
            bid.clone()
        }
        None => {
            // No hint — the signature itself is the authenticator. Try
            // every enrolled target until one verifies.
            let mut matched = None;
            for t in targets.list_targets().await? {
                if webhook_verify::verify(
                    &t.public_key.ed25519,
                    &t.public_key.mldsa65,
                    &sig,
                    &body,
                )
                .is_ok()
                {
                    matched = Some(t.id);
                    break;
                }
            }
            matched.ok_or_else(|| {
                bv_error_response_status!(401, "signature did not match any enrolled bastion")
            })?
        }
    };

    // Parse the verified sidecar.
    let sidecar: Value = serde_json::from_slice(&body)
        .map_err(|e| bv_error_response_status!(400, &format!("sidecar parse: {e}")))?;
    let sd = sidecar
        .as_object()
        .ok_or_else(|| bv_error_response_status!(400, "sidecar must be a JSON object"))?;
    let s = |k: &str| -> String {
        sd.get(k).and_then(|v| v.as_str()).map(String::from).unwrap_or_default()
    };
    let u = |k: &str| -> u64 { sd.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
    let parse_iso = |k: &str| -> chrono::DateTime<chrono::Utc> {
        sd.get(k)
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now)
    };

    let recording_id = s("recording_id");
    if recording_id.is_empty() {
        return Err(bv_error_response_status!(400, "sidecar missing recording_id"));
    }

    let entry = recordings::RecordingEntry {
        recording_id: recording_id.clone(),
        session_id: s("session_id"),
        authority: s("authority"),
        format: s("format"),
        sha256: s("sha256"),
        size_bytes: u("size_bytes"),
        started_at: parse_iso("started_at"),
        finished_at: parse_iso("finished_at"),
        target_host: s("target_host"),
        target_user: s("target_user"),
        correlation_id: s("correlation_id"),
        bastion_id: bastion_id.clone(),
        received_at: chrono::Utc::now(),
        delivery_mode: "webhook".into(),
    };

    let store = recordings::RecordingsStore::new(core.get_ref()).await?;
    store.put(&entry).await?;
    // Clear the pending-recording marker so the 24h poller drops this
    // session from its sweep list.
    let _ = store.pending_remove(&entry.session_id).await;

    log::info!(
        "{}: recording_id={} session_id={} bastion={} correlation_id={}",
        audit::RECORDING_LINKED,
        entry.recording_id,
        entry.session_id,
        entry.bastion_id,
        entry.correlation_id
    );

    let mut data = Map::new();
    data.insert("recording_id".into(), Value::String(entry.recording_id));
    data.insert("delivery_mode".into(), Value::String(entry.delivery_mode));
    data.insert("received_at".into(), Value::String(entry.received_at.to_rfc3339()));
    Ok(response_json_ok(None, data))
}
