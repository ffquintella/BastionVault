//! Recordings index on the BV side — Phase 6.2 of
//! `features/rustion-integration.md`.
//!
//! When Rustion POSTs a signed `recording.ready` webhook, the handler
//! in `mod.rs` verifies the signature against the originating
//! bastion's pinned `RustionTarget.public_key` and then persists the
//! sidecar entry here.
//!
//! Storage layout: `rustion/recordings/<recording_id>` under the
//! system view. The recording_id is what the sidecar carried —
//! globally unique (it's derived from `sess_<32 hex>`).
//!
//! Phase 6.3 will add the 24h pull-fallback poller that walks the
//! audit chain for sessions whose `session.terminate` event has
//! landed but whose recordings have not, and pulls them via
//! `GET /v1/sessions/{sid}/recording` on the bastion side.

#![deny(unsafe_code)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::Core;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
use crate::bv_error_string;

const RECORDINGS_SUB_PATH: &str = "rustion/recordings/";

/// One recording entry. Mirrors `RecordingSidecar` on the Rustion
/// side plus the BV-only fields that record the chain-of-custody at
/// receive time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingEntry {
    pub recording_id: String,
    pub session_id: String,
    pub authority: String,
    pub format: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub target_host: String,
    pub target_user: String,
    pub correlation_id: String,
    /// Bastion id this recording came from. Used by the audit chain
    /// to identify *which* Rustion instance holds the artifact when
    /// the operator clicks "Open recording" later.
    pub bastion_id: String,
    /// ISO timestamp when BV received the webhook (NOT when the
    /// recording finished — those can drift). Used for the 24h
    /// fallback poller.
    pub received_at: DateTime<Utc>,
    /// `webhook` if BV received it via the signed webhook; `pull`
    /// once the 24h fallback poller lands in Phase 6.3.
    pub delivery_mode: String,
}

pub struct RecordingsStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl RecordingsStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(RECORDINGS_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    pub async fn list_ids(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn get(&self, recording_id: &str) -> Result<Option<RecordingEntry>, RvError> {
        let id = sanitize(recording_id)?;
        let Some(entry) = self.view.get(&id).await? else {
            return Ok(None);
        };
        let rec: RecordingEntry = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode recording {id}: {e}")))?;
        Ok(Some(rec))
    }

    pub async fn put(&self, rec: &RecordingEntry) -> Result<(), RvError> {
        let id = sanitize(&rec.recording_id)?;
        let value = serde_json::to_vec(rec)
            .map_err(|e| bv_error_string!(&format!("encode recording: {e}")))?;
        self.view.put(&StorageEntry { key: id, value }).await
    }
}

fn sanitize(id: &str) -> Result<String, RvError> {
    let t = id.trim();
    if t.is_empty() {
        return Err(bv_error_string!("recording id is required"));
    }
    if t.contains('/') || t.contains("..") {
        return Err(bv_error_string!("invalid recording id"));
    }
    Ok(t.to_string())
}

// ─── Phase 6.3: pull-fallback ───────────────────────────────────────

/// Pull a recording sidecar from a bastion's 24h pull-fallback
/// endpoint and persist it into the recordings index. Used when the
/// webhook delivery missed (no `recording.ready` arrived within the
/// expected window), and also exposed via a Tauri command so the
/// operator can force-refresh from the GUI.
///
/// Returns the freshly-stored entry. Phase 6.3.
#[maybe_async::maybe_async]
pub async fn pull_recording(
    targets: &super::store::RustionStore,
    recordings: &RecordingsStore,
    bastion_id: &str,
    session_id: &str,
) -> Result<RecordingEntry, RvError> {
    let target = targets
        .get_target(bastion_id)
        .await?
        .ok_or_else(|| bv_error_string!(&format!("bastion `{bastion_id}` not enrolled")))?;

    let url = format!(
        "https://{}/v1/sessions/{}/recording",
        target.endpoint.trim_end_matches('/'),
        session_id
    );
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| bv_error_string!(&format!("http client: {e}")))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| bv_error_string!(&format!("transport: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(bv_error_string!(&format!(
            "bastion returned HTTP {status}: {body}"
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| bv_error_string!(&format!("read body: {e}")))?;

    // Pull-fallback skips the signature check — the sidecar comes
    // over the bastion's TLS-pinned channel, not a third-party hop.
    // The webhook path retains hybrid-sig verification because
    // there's no transport-level guarantee about who sent the POST.
    let sidecar: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| bv_error_string!(&format!("sidecar parse: {e}")))?;
    let sd = sidecar.as_object().ok_or_else(|| {
        bv_error_string!("pull sidecar must be a JSON object")
    })?;
    let s = |k: &str| -> String {
        sd.get(k)
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default()
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
        return Err(bv_error_string!("pulled sidecar missing recording_id"));
    }
    let entry = RecordingEntry {
        recording_id,
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
        bastion_id: bastion_id.to_string(),
        received_at: chrono::Utc::now(),
        delivery_mode: "pull".into(),
    };
    recordings.put(&entry).await?;
    Ok(entry)
}
