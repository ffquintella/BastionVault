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

use crate::kernel_api::VaultCtx;
use crate::errors::RvError;
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};
use crate::bv_error_string;

const RECORDINGS_SUB_PATH: &str = "rustion/recordings/";
/// Sub-view for the 24h fallback poller's "pending recordings"
/// tracker. Populated on `session.open` (so the poller knows BV is
/// expecting a recording from a specific bastion+session), and
/// emptied either when the webhook delivers OR when the poller's
/// pull-fallback succeeds. Phase 6.4.
const PENDING_SUB_PATH: &str = "rustion/recordings_pending/";

/// One recording entry. Mirrors `RecordingSidecar` on the Rustion
/// side plus the BV-only fields that record the chain-of-custody at
/// receive time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    // ─── Phase 8.6: keystroke-transcript summary ────────────────────
    //
    // The transcript itself lives in the cold
    // `rustion/recordings_keystrokes/<rid>` view (see
    // `keystroke_index`); only counters and flags live here, because
    // this record is read for every row of the Recordings page.
    //
    // Every field is `#[serde(default)]`: entries written before
    // Phase 8.6 decode with these at their zero value, which reads as
    // "no transcript index yet" — the read-old/write-new migration
    // this persisted format needs. An empty `keystroke_state` means
    // *not indexed*, which the UI must not render as "nothing was
    // typed".
    /// `""` (not indexed) | `indexed` | `not-enabled` |
    /// `digest-mismatch` | `failed`. See
    /// `keystroke_index::IndexStatus`.
    #[serde(default)]
    pub keystroke_state: String,
    /// Digest of the artifact the current keystroke verdict was
    /// derived from. When it stops matching `sha256` the index is
    /// stale and the sweep re-reads it.
    #[serde(default)]
    pub keystroke_artifact_sha256: String,
    /// The artifact header's `keystroke_metadata`. `false` means the
    /// feature was off on that bastion — **not** that nobody typed.
    #[serde(default)]
    pub keystroke_metadata: bool,
    /// A transcript with at least one non-redacted character exists.
    #[serde(default)]
    pub keystroke_text: bool,
    /// Non-redacted characters, i.e. what the search index covers.
    #[serde(default)]
    pub keystroke_chars: u64,
    #[serde(default)]
    pub keystroke_runs: u64,
    #[serde(default)]
    pub keystroke_redacted_runs: u64,
    /// `exact` | `approximate` | `none` | `unknown`. Anything but
    /// `exact` must be surfaced in the UI.
    #[serde(default)]
    pub keystroke_decoding: String,
    /// The bastion rebuilt the trailer after a crash: the session's
    /// final unclosed run is missing.
    #[serde(default)]
    pub keystroke_rebuilt: bool,
    /// False when the transcript is a rebuilt trailer or a `0x08`
    /// scan, both of which are incomplete by construction.
    #[serde(default)]
    pub keystroke_complete: bool,
    #[serde(default)]
    pub keystroke_indexed_at: Option<DateTime<Utc>>,
}

/// One "pending recording" entry — BV expects this recording to land
/// (either via webhook or via the 24h poller). The poller's task tick
/// walks this view, checks each pending entry's `expected_by` deadline,
/// and calls `pull_recording` if the deadline has passed without the
/// recording appearing in the main index.
///
/// Cleared either by webhook delivery (`handle_webhook_recording_ready`
/// removes the pending entry) or by a successful pull
/// (`pull_recording` calls `pending_remove`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRecording {
    pub session_id: String,
    pub bastion_id: String,
    pub authority: String,
    pub correlation_id: String,
    pub opened_at: DateTime<Utc>,
    /// When BV expects the recording to be available. Typically
    /// `session.opened_at + session.ttl_secs + 5 min` so the poller
    /// doesn't pull a session that's still active.
    pub expected_by: DateTime<Utc>,
}

pub struct RecordingsStore {
    view: Arc<BarrierView>,
    pending_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl RecordingsStore {
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(RECORDINGS_SUB_PATH));
        let pending_view = Arc::new(system_view.new_sub_view(PENDING_SUB_PATH));
        Ok(Arc::new(Self { view, pending_view }))
    }

    // ─── Pending recordings (Phase 6.4 cron) ────────────────────────

    pub async fn pending_list(&self) -> Result<Vec<PendingRecording>, RvError> {
        let mut out = Vec::new();
        let keys = self.pending_view.get_keys().await?;
        for k in keys {
            if let Some(entry) = self.pending_view.get(&k).await? {
                if let Ok(pr) = serde_json::from_slice::<PendingRecording>(&entry.value) {
                    out.push(pr);
                }
            }
        }
        Ok(out)
    }

    pub async fn pending_insert(&self, pr: &PendingRecording) -> Result<(), RvError> {
        let id = sanitize(&pr.session_id)?;
        let value = serde_json::to_vec(pr)
            .map_err(|e| bv_error_string!(&format!("encode pending recording: {e}")))?;
        self.pending_view.put(&StorageEntry { key: id, value }).await
    }

    pub async fn pending_remove(&self, session_id: &str) -> Result<(), RvError> {
        let id = sanitize(session_id)?;
        self.pending_view.delete(&id).await
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
    let client = super::http::build_client_for(&target, std::time::Duration::from_secs(10))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| bv_error_string!(&format!("transport: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        // Surface the upstream failure with a faithful status: a missing
        // recording on the bastion is a 404, any other upstream failure is
        // a 502 (the bastion is an upstream gateway from our perspective).
        // Without this, every upstream error collapsed into a generic 500.
        let mapped = if status == reqwest::StatusCode::NOT_FOUND {
            404
        } else {
            502
        };
        return Err(crate::bv_error_response_status!(
            mapped,
            &format!("bastion returned HTTP {status}: {body}")
        ));
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
        // Phase 8.6: a freshly-ingested recording has no transcript
        // index yet. The poller's sweep (or an explicit index call)
        // fills these in; leaving them at their zero value is the
        // "not indexed" state, distinct from "not enabled".
        ..Default::default()
    };
    recordings.put(&entry).await?;
    // Clear the pending-recording marker so the 24h poller doesn't
    // re-attempt this session.
    let _ = recordings.pending_remove(&entry.session_id).await;
    Ok(entry)
}

// ─── Phase 6.5: active reconcile (list-pull) ────────────────────────

/// Outcome of an active reconcile sweep against one bastion.
#[derive(Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub bastion_id: String,
    /// Recordings the bastion reported in its index.
    pub found: usize,
    /// New recordings ingested into the BV index this sweep.
    pub imported: usize,
    /// Recordings already present in the BV index, left untouched.
    pub skipped_existing: usize,
}

/// Actively pull a bastion's full recording index (`GET /v1/recordings`)
/// and ingest any recordings BV doesn't already hold.
///
/// This is the third recording-delivery path, complementing the
/// `recording.ready` webhook (push) and the per-session pull-fallback.
/// Unlike the per-session route — which resolves against Rustion's
/// live in-memory session table and so cannot serve terminated
/// sessions or survive a bastion restart — the list endpoint walks the
/// bastion's on-disk recording index, so reconcile recovers recordings
/// regardless of session lifecycle or missed webhooks.
///
/// Idempotent: recordings already in the index (matched by
/// `recording_id`) are skipped, so it is safe to run on a schedule or
/// on-demand from the GUI.
pub async fn reconcile_from_bastion(
    targets: &super::store::RustionStore,
    recordings: &RecordingsStore,
    authority: &str,
    bastion_id: &str,
) -> Result<ReconcileReport, RvError> {
    let target = targets
        .get_target(bastion_id)
        .await?
        .ok_or_else(|| bv_error_string!(&format!("bastion `{bastion_id}` not enrolled")))?;

    let url = format!(
        "https://{}/v1/recordings",
        target.endpoint.trim_end_matches('/')
    );
    let client = super::http::build_client_for(&target, std::time::Duration::from_secs(15))?;
    let resp = client
        .get(&url)
        .header("X-Rustion-Authority", authority)
        .send()
        .await
        .map_err(|e| bv_error_string!(&format!("transport: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let mapped = if status == reqwest::StatusCode::NOT_FOUND {
            404
        } else {
            502
        };
        return Err(crate::bv_error_response_status!(
            mapped,
            &format!("bastion returned HTTP {status}: {body}")
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| bv_error_string!(&format!("read body: {e}")))?;
    let parsed: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| bv_error_string!(&format!("recordings list parse: {e}")))?;
    let list = parsed
        .get("recordings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut report = ReconcileReport {
        bastion_id: bastion_id.to_string(),
        ..Default::default()
    };
    for item in &list {
        let Some(sd) = item.as_object() else {
            continue;
        };
        report.found += 1;
        let s = |k: &str| -> String {
            sd.get(k).and_then(|v| v.as_str()).map(String::from).unwrap_or_default()
        };
        let u = |k: &str| -> u64 { sd.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
        let parse_iso = |k: &str| -> DateTime<Utc> {
            sd.get(k)
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now)
        };
        let recording_id = s("recording_id");
        if recording_id.is_empty() {
            continue;
        }
        if recordings.get(&recording_id).await?.is_some() {
            report.skipped_existing += 1;
            continue;
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
            received_at: Utc::now(),
            delivery_mode: "reconcile".into(),
            ..Default::default()
        };
        recordings.put(&entry).await?;
        let _ = recordings.pending_remove(&entry.session_id).await;
        report.imported += 1;
    }
    Ok(report)
}

/// Phase 6.5: fetch the recording artifact bytes from the bastion's
/// `GET /v1/recordings/{rid}/blob` endpoint. Returns the raw bytes
/// + the format string from the `X-Recording-Format` header so the
/// caller (the GUI) can route to the right player.
///
/// **These bytes are unverified.** This function performs the transfer
/// and nothing else: the digest it returns is whatever the bastion
/// claimed (falling back to the sidecar's), and it is never checked
/// against the body. Every caller that hands the bytes onwards — to a
/// player, to a cache, to a derived index — must run them through
/// [`verify_artifact_digest`] first. [`fetch_blob_cached`] does;
/// `keystroke_index` does its own equivalent gate because it needs to
/// report a mismatch as an index *state* rather than as an error.
#[maybe_async::maybe_async]
pub async fn fetch_blob(
    targets: &super::store::RustionStore,
    recordings: &RecordingsStore,
    recording_id: &str,
) -> Result<(Vec<u8>, String, String), RvError> {
    let entry = recordings
        .get(recording_id)
        .await?
        .ok_or_else(|| bv_error_string!(&format!("recording `{recording_id}` not in index")))?;
    let target = targets
        .get_target(&entry.bastion_id)
        .await?
        .ok_or_else(|| {
            bv_error_string!(&format!("bastion `{}` not enrolled", entry.bastion_id))
        })?;

    let url = format!(
        "https://{}/v1/recordings/{}/blob",
        target.endpoint.trim_end_matches('/'),
        recording_id
    );
    let client = super::http::build_client_for(&target, std::time::Duration::from_secs(30))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| bv_error_string!(&format!("transport: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        // Surface the upstream failure with a faithful status: a missing
        // recording on the bastion is a 404, any other upstream failure is
        // a 502 (the bastion is an upstream gateway from our perspective).
        // Without this, every upstream error collapsed into a generic 500.
        let mapped = if status == reqwest::StatusCode::NOT_FOUND {
            404
        } else {
            502
        };
        return Err(crate::bv_error_response_status!(
            mapped,
            &format!("bastion returned HTTP {status}: {body}")
        ));
    }
    let format = resp
        .headers()
        .get("x-recording-format")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&entry.format)
        .to_string();
    let sha256 = resp
        .headers()
        .get("x-recording-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&entry.sha256)
        .to_string();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| bv_error_string!(&format!("read body: {e}")))?;
    Ok((bytes.to_vec(), format, sha256))
}

/// The digest an artifact is required to hash to, given what the index
/// entry and the response claim. `None` when nothing on record claims
/// one.
///
/// The sidecar's `sha256` wins whenever it is present. It arrived over
/// the signed `recording.ready` webhook — verified against the
/// originating bastion's pinned key before it was persisted — whereas
/// the `x-recording-sha256` header is supplied by the same party, in
/// the same response, as the bytes it describes, and so cannot vouch
/// for them on its own. Falling back to the header when the sidecar
/// disagrees would let the serving side choose which digest it is
/// checked against, which is the silent downgrade this gate exists to
/// prevent.
fn expected_artifact_digest<'a>(sidecar: &'a str, response: &'a str) -> Option<&'a str> {
    let sidecar = sidecar.trim();
    if !sidecar.is_empty() {
        return Some(sidecar);
    }
    let response = response.trim();
    if response.is_empty() {
        None
    } else {
        Some(response)
    }
}

/// Verify artifact bytes against the digest on record for that
/// recording. The gate the playback path runs before it serves or
/// caches anything, mirroring the one `keystroke_index` runs before it
/// persists derived text.
///
/// * `Ok(Some(digest))` — the bytes hash to the digest on record. The
///   returned value is the *computed* digest (lowercase hex), which is
///   what the vault then reports for the artifact: it is the only one
///   of the three candidate strings that is demonstrably a fact about
///   the bytes being served.
/// * `Ok(None)` — nothing on record claims a digest, so there is
///   nothing to check against. The bytes are served, and the caller is
///   told they are unverified rather than being left to assume
///   otherwise. This is the compatibility case: recordings whose
///   sidecar predates the digest, or landed without one, keep playing.
/// * `Err(..)` — the bytes contradict the digest on record. Nothing is
///   served and nothing is cached.
///
/// The mismatch is a **409**, deliberately not the 502 that a failed
/// upstream fetch produces. 502 says "the bastion could not answer,
/// try again"; this is deterministic — the same bytes will fail the
/// same way on every retry — and it is a different operator response
/// (go look at the artifact on the bastion) than an unreachable
/// bastion. The status is what lets those two be told apart without
/// parsing a message.
pub fn verify_artifact_digest(
    recording_id: &str,
    bytes: &[u8],
    sidecar_sha256: &str,
    response_sha256: &str,
) -> Result<Option<String>, RvError> {
    use sha2::{Digest, Sha256};

    let Some(expected) = expected_artifact_digest(sidecar_sha256, response_sha256) else {
        log::warn!(
            "rustion: recording `{recording_id}` has no digest on record ({} bytes); serving it \
             unverified — `digest_verified` is false on the response",
            bytes.len()
        );
        return Ok(None);
    };
    let got = hex::encode(Sha256::digest(bytes));
    if !got.eq_ignore_ascii_case(expected) {
        log::warn!(
            "{}: recording_id={recording_id} sha256_mismatch=true size_bytes={} served=false",
            crate::audit::RECORDING_ARTIFACT_REJECTED,
            bytes.len()
        );
        return Err(crate::bv_error_response_status!(
            409,
            &format!(
                "recording `{recording_id}`: artifact digest {}… does not match the recorded \
                 {}…; refusing to serve",
                &got[..got.len().min(12)],
                &expected[..expected.len().min(12)]
            )
        ));
    }
    Ok(Some(got))
}

/// Fetch a recording artifact through the [`BlobCache`], so a chunked
/// playback pays for one upstream fetch rather than one per chunk.
///
/// A cache miss delegates to [`fetch_blob`], runs the fetched bytes
/// through [`verify_artifact_digest`], and only then stores the
/// result; a hit returns the resident copy. Because the gate sits
/// *before* the insert, the cache holds no artifact that failed its
/// digest, and a chunked read — which serves from the cache for every
/// chunk after the first — cannot hand out corrupted bytes one slice
/// at a time. A cache hit is not re-hashed: re-verifying per chunk
/// would hash the whole artifact once per chunk, and the entry it
/// would be re-checking was already verified on the way in.
///
/// The format reported is the one that came with the artifact,
/// unchanged. The digest reported is the verified one when there was a
/// digest to verify against, and `digest_verified` on the returned
/// [`Artifact`] says which of those two happened — the vault never
/// reports a digest it computed itself as though it were an
/// independent attestation.
///
/// Concurrent misses for the same recording may both fetch; the second
/// insert simply replaces the first. Left as a benign race on purpose:
/// a player reads its chunks in order, so the window only opens when
/// two operators start the *same* recording within one fetch of each
/// other, and closing it would mean holding a lock across an await in
/// a module that also compiles under `sync_handler`.
///
/// [`BlobCache`]: crate::blob_cache::BlobCache
/// [`Artifact`]: crate::blob_cache::Artifact
#[maybe_async::maybe_async]
pub async fn fetch_blob_cached(
    targets: &super::store::RustionStore,
    recordings: &RecordingsStore,
    cache: &crate::blob_cache::BlobCache,
    recording_id: &str,
) -> Result<crate::blob_cache::Artifact, RvError> {
    if let Some(hit) = cache.get(recording_id) {
        log::debug!(
            "rustion: recording `{recording_id}` served from the blob cache ({} bytes)",
            hit.bytes.len()
        );
        return Ok(hit);
    }
    // The sidecar digest, read before the fetch so the check below is
    // against the chain-of-custody value rather than against whatever
    // the response carried. `fetch_blob` re-reads the same entry; one
    // extra decrypted read of a small record, once per cache miss, is
    // the price of not widening `fetch_blob`'s return type for the one
    // caller that needs both digests separately.
    let sidecar_sha256 = recordings
        .get(recording_id)
        .await?
        .map(|e| e.sha256)
        .unwrap_or_default();
    let (bytes, format, response_sha256) = fetch_blob(targets, recordings, recording_id).await?;
    // Into `Zeroizing` before the gate, so bytes that fail it are wiped
    // on the way out rather than left in the allocator.
    let bytes: crate::blob_cache::ArtifactBytes = Arc::new(zeroize::Zeroizing::new(bytes));
    let verified =
        verify_artifact_digest(recording_id, bytes.as_slice(), &sidecar_sha256, &response_sha256)?;
    let artifact = crate::blob_cache::Artifact {
        bytes,
        format,
        digest_verified: verified.is_some(),
        sha256: verified.unwrap_or(response_sha256),
    };
    cache.put(recording_id, &artifact);
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    /// Bytes that hash to the sidecar's digest pass, and what comes
    /// back is the *computed* digest in lowercase hex — not whichever
    /// of the input strings happened to be echoed.
    #[test]
    fn matching_bytes_verify_and_report_the_computed_digest() {
        let bytes = b"rdp-rec artifact";
        let digest = sha256_hex(bytes);
        let verified = verify_artifact_digest("rec_1", bytes, &digest, "")
            .expect("matching bytes verify");
        assert_eq!(verified.as_deref(), Some(digest.as_str()));

        // Sidecars have been seen carrying upper-case hex and stray
        // whitespace; neither is a mismatch.
        let shouty = format!("  {}  ", digest.to_uppercase());
        let verified = verify_artifact_digest("rec_1", bytes, &shouty, "")
            .expect("case and padding are not a mismatch");
        assert_eq!(
            verified.as_deref(),
            Some(digest.as_str()),
            "the reported digest is normalized to computed lowercase hex"
        );
    }

    /// The gate. Bytes that contradict the digest on record are refused
    /// outright — the caller gets an error, not the bytes with a
    /// warning attached.
    #[test]
    fn mismatching_bytes_are_refused_with_a_distinguishable_status() {
        let err = verify_artifact_digest("rec_1", b"tampered", &"ab".repeat(32), "")
            .expect_err("bytes that contradict the digest must not be served");
        // 409, not the 502 an unreachable bastion produces: a retry
        // cannot fix this, and an operator has to tell the two apart.
        let RvError::ErrResponseStatus(status, msg) = &err else {
            panic!("a digest mismatch must carry an HTTP status, got: {err:?}");
        };
        assert_eq!(
            *status, 409,
            "a digest mismatch must be distinguishable from an upstream fetch failure"
        );
        assert!(
            msg.contains("does not match the recorded"),
            "the message must name the failure, got: {msg}"
        );
        assert!(msg.contains("rec_1"), "the message must name the recording, got: {msg}");
    }

    /// The migration case, and the reason this is not simply "hard-fail
    /// always": a recording whose sidecar carries no digest keeps
    /// playing, and the response says the bytes were not verified
    /// rather than implying they were.
    #[test]
    fn an_artifact_with_no_digest_on_record_is_served_unverified() {
        let verified = verify_artifact_digest("rec_1", b"anything", "", "")
            .expect("nothing to check against is not a failure");
        assert!(verified.is_none(), "an unverifiable artifact reports no verified digest");

        // Whitespace-only is "no digest", not a digest that never matches.
        let verified = verify_artifact_digest("rec_1", b"anything", "   ", "  ")
            .expect("a blank digest is no digest");
        assert!(verified.is_none());
    }

    /// With no sidecar digest, the response header is still a digest
    /// and is still enforced — a bastion that contradicts its own
    /// header is caught even when BV has nothing of its own on record.
    #[test]
    fn the_response_digest_is_enforced_when_the_sidecar_has_none() {
        let bytes = b"rdp-rec artifact";
        let digest = sha256_hex(bytes);
        assert_eq!(
            verify_artifact_digest("rec_1", bytes, "", &digest).unwrap().as_deref(),
            Some(digest.as_str())
        );
        verify_artifact_digest("rec_1", bytes, "", &"cd".repeat(32))
            .expect_err("a response digest that the body contradicts is still a mismatch");
    }

    /// The sidecar wins, and there is no fallback to the response
    /// header when the two disagree. Otherwise the party serving the
    /// bytes would get to pick the digest it is checked against, which
    /// is the whole failure mode this gate exists for.
    #[test]
    fn the_sidecar_digest_wins_and_the_response_cannot_override_it() {
        let bytes = b"rdp-rec artifact";
        let sidecar = sha256_hex(bytes);

        // Sidecar right, header wrong: the bytes are the sidecar's, so
        // they are served, and the digest reported is the true one.
        let verified = verify_artifact_digest("rec_1", bytes, &sidecar, &"ef".repeat(32))
            .expect("bytes matching the sidecar are served");
        assert_eq!(verified.as_deref(), Some(sidecar.as_str()));

        // Header "right", sidecar wrong: refused. The bastion agreeing
        // with itself proves nothing.
        let other = sha256_hex(b"different bytes");
        verify_artifact_digest("rec_1", bytes, &other, &sidecar)
            .expect_err("a matching response header must not excuse a sidecar mismatch");

        assert_eq!(expected_artifact_digest("side", "resp"), Some("side"));
        assert_eq!(expected_artifact_digest(" ", "resp"), Some("resp"));
        assert_eq!(expected_artifact_digest("", ""), None);
    }

    /// A verified artifact keeps its verification state across the
    /// cache, so a chunk served from a hit reports what chunk 0
    /// reported. The cache is the only place these bytes are reachable
    /// from after the fetch, so this flag has to survive the round
    /// trip.
    #[test]
    fn the_cache_round_trips_the_verification_state() {
        let cache = crate::blob_cache::BlobCache::new();
        for verified in [true, false] {
            let art = crate::blob_cache::Artifact {
                bytes: Arc::new(zeroize::Zeroizing::new(vec![1u8; 32])),
                format: "rdp-rec".into(),
                sha256: "aa".repeat(32),
                digest_verified: verified,
            };
            cache.put("rec_1", &art);
            let hit = cache.get("rec_1").expect("cached");
            assert_eq!(hit.digest_verified, verified);
            assert_eq!(hit.sha256, art.sha256);
        }
    }

    /// A `RecordingEntry` written before Phase 8.6 must still decode.
    ///
    /// This is the read-old half of the read-old/write-new migration
    /// the keystroke fields introduce: every one of them is
    /// `#[serde(default)]`, and the zero values have to land on the
    /// *"not indexed yet"* reading rather than on "not enabled" or
    /// "nothing was typed". Those three states are distinguishable in
    /// the API and the GUI precisely because this default is `""`.
    #[test]
    fn a_pre_phase_8_6_entry_decodes_as_not_indexed() {
        let legacy = r#"{
            "recording_id": "rec_deadbeef",
            "session_id": "sess_deadbeef",
            "authority": "bastion-vault",
            "format": "rdp-rec",
            "sha256": "aa",
            "size_bytes": 4096,
            "started_at": "2026-01-02T03:04:05Z",
            "finished_at": "2026-01-02T03:14:05Z",
            "target_host": "evdc400",
            "target_user": "administrator",
            "correlation_id": "corr_1",
            "bastion_id": "rt_1",
            "received_at": "2026-01-02T03:15:00Z",
            "delivery_mode": "webhook"
        }"#;
        let entry: RecordingEntry = serde_json::from_str(legacy).expect("legacy entry decodes");
        assert_eq!(entry.recording_id, "rec_deadbeef");
        assert_eq!(entry.delivery_mode, "webhook");
        // `""` is "not indexed". It is deliberately not the string
        // `not-enabled`, which is a *verdict* about the artifact.
        assert_eq!(entry.keystroke_state, "");
        assert!(!entry.keystroke_metadata);
        assert!(!entry.keystroke_text);
        assert_eq!(entry.keystroke_chars, 0);
        assert_eq!(entry.keystroke_runs, 0);
        assert!(entry.keystroke_indexed_at.is_none());
        assert_eq!(entry.keystroke_artifact_sha256, "");
    }

    /// Write-new: a re-serialized entry carries the new fields, and
    /// the old fields are untouched in name and meaning.
    #[test]
    fn a_round_tripped_entry_keeps_both_generations_of_fields() {
        let now = Utc::now();
        let entry = RecordingEntry {
            recording_id: "rec_1".into(),
            session_id: "sess_1".into(),
            format: "rdp-rec".into(),
            sha256: "bb".repeat(32),
            started_at: now,
            finished_at: now,
            received_at: now,
            delivery_mode: "webhook".into(),
            keystroke_state: "indexed".into(),
            keystroke_artifact_sha256: "bb".repeat(32),
            keystroke_metadata: true,
            keystroke_text: true,
            keystroke_chars: 42,
            keystroke_runs: 5,
            keystroke_redacted_runs: 1,
            keystroke_decoding: "exact".into(),
            keystroke_complete: true,
            keystroke_indexed_at: Some(now),
            ..Default::default()
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RecordingEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.delivery_mode, "webhook");
        assert_eq!(back.keystroke_state, "indexed");
        assert_eq!(back.keystroke_chars, 42);
        assert_eq!(back.keystroke_redacted_runs, 1);
        assert!(back.keystroke_complete);
        // The hot entry holds counters, never the transcript itself.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("search_text").is_none());
        assert!(v.get("runs").is_none());
    }
}
