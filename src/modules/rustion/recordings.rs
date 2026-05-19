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
