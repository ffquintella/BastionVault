//! Keystroke transcript index + search — Phase 8.6 of
//! `features/rustion-integration.md`.
//!
//! The transcript lives inside the `.rdp-rec` BastionVault already
//! pulls, covered by the sidecar `sha256` we already verify. This
//! module is what turns it into something an auditor can query:
//! "which session typed `net user /add`?"
//!
//! ## Storage shape, and why it is two views
//!
//! `rustion/recordings/<rid>` is a **hot** store: rendering the
//! Recordings page reads every entry in it. A transcript is the
//! largest and most sensitive thing in a recording, so it does not go
//! there. `RecordingEntry` gains only counters and flags — enough to
//! render a badge in the list — and the transcript itself lives in a
//! separate cold view, `rustion/recordings_keystrokes/<rid>`, read
//! only when an operator opens or searches a transcript.
//!
//! ## Why BastionVault stores the text at all
//!
//! Rustion's own search re-reads each candidate artifact's tail at
//! query time, which is bounded work per candidate. BastionVault
//! cannot: the bastion's `GET /v1/recordings/{rid}/blob` serves whole
//! files and honours no `Range`, so a query-time tail read would mean
//! downloading every candidate artifact in full. The derived
//! `search_text` is therefore persisted once, at index time, into the
//! barrier-encrypted store — and the access controls below exist
//! because of that decision, not in spite of it.
//!
//! ## Security posture
//!
//! * **Only non-redacted text is ever stored.** The value indexed is
//!   `rdp_keystrokes::Transcript::search_text`, which that module
//!   rebuilds from the runs whose `redacted` flag is false rather than
//!   trusting the producer's own field. A redacted run contributes
//!   nothing, so a substring hit can never be a hit on withheld text.
//! * **`text_applied` is never stored or indexed** — it is not even
//!   deserialized. See `rdp_keystrokes`.
//! * **The digest is verified before anything is persisted.** We are
//!   deriving durable state from bastion-supplied bytes, so the bytes
//!   have to match the sidecar's `sha256` first. A mismatch refuses to
//!   index and says so; it does not index best-effort.
//! * **A search query is user input and is treated as sensitive.** It
//!   is never logged, never echoed into an error, and never placed in
//!   a URL — which is why the search route is a `Write` with the query
//!   in the body, not a `Read` with it in the path.
//! * **Reading a transcript is its own audit event**, distinct from
//!   viewing the recording, and every event carries counts only.
//! * **Redaction upstream is best-effort.** Nothing here may present
//!   an unredacted transcript as verified free of secrets.

#![deny(unsafe_code)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bv_error_string;
use crate::errors::RvError;
use crate::kernel_api::VaultCtx;
use crate::rdp_keystrokes::{self, Census, Run};
use crate::recordings::{RecordingEntry, RecordingsStore};
use crate::storage::{barrier_view::BarrierView, Storage, StorageEntry};

/// Cold view holding one transcript per recording. Deliberately not
/// the recordings view — see the module header.
const KEYSTROKES_SUB_PATH: &str = "rustion/recordings_keystrokes/";

/// The only recording format that can carry a keystroke track.
pub const KEYSTROKE_FORMAT: &str = "rdp-rec";

/// Hard cap on how many recordings one search pass will open. A search
/// loads one cold entry at a time and keeps only the hits, but an
/// unbounded sweep over a large index is still a DoS surface on an
/// interactive endpoint.
pub const MAX_SEARCH_CANDIDATES: usize = 5_000;

/// Default and maximum number of hits returned by one search.
pub const DEFAULT_SEARCH_LIMIT: usize = 200;
pub const MAX_SEARCH_LIMIT: usize = 1_000;

/// Characters of surrounding run text returned either side of a match.
/// A hit needs enough context to be recognisable and no more.
pub const EXCERPT_CONTEXT_CHARS: usize = 60;

/// Recordings indexed per background sweep. Each one costs a full
/// artifact download from its bastion, so the sweep is deliberately
/// slow rather than a thundering herd after a restart.
pub const SWEEP_BATCH: usize = 8;

/// What an index attempt concluded. Every value is a state an operator
/// can act on; none of them is silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndexStatus {
    /// A transcript was read and stored.
    Indexed,
    /// The artifact says keystroke recording was not enabled for this
    /// session (version <= 3, or version 4 with
    /// `keystroke_metadata: false`). **Not** "nobody typed".
    NotEnabled,
    /// Not an `.rdp-rec`; no keystroke track is possible.
    SkippedFormat,
    /// Already indexed against this artifact digest.
    Unchanged,
    /// The fetched bytes did not match the sidecar's `sha256`. Nothing
    /// was stored.
    DigestMismatch,
    /// The artifact could not be fetched or read.
    Failed,
}

impl IndexStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Indexed => "indexed",
            Self::NotEnabled => "not-enabled",
            Self::SkippedFormat => "skipped-format",
            Self::Unchanged => "unchanged",
            Self::DigestMismatch => "digest-mismatch",
            Self::Failed => "failed",
        }
    }
}

/// The outcome of one recording's index attempt. Counts and states
/// only — no transcript text.
#[derive(Debug, Clone, Serialize)]
pub struct IndexReport {
    pub recording_id: String,
    pub status: IndexStatus,
    /// Operator-facing explanation. Never carries transcript text.
    pub detail: String,
    pub runs: u64,
    pub redacted_runs: u64,
    pub chars_indexed: u64,
    pub text_decoding: String,
    pub rebuilt: bool,
    pub complete: bool,
    pub source: String,
}

impl IndexReport {
    fn plain(recording_id: &str, status: IndexStatus, detail: impl Into<String>) -> Self {
        Self {
            recording_id: recording_id.to_string(),
            status,
            detail: detail.into(),
            runs: 0,
            redacted_runs: 0,
            chars_indexed: 0,
            text_decoding: String::new(),
            rebuilt: false,
            complete: false,
            source: String::new(),
        }
    }
}

/// Outcome of an index sweep over many recordings.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepReport {
    pub considered: usize,
    pub indexed: usize,
    pub not_enabled: usize,
    pub unchanged: usize,
    pub skipped_format: usize,
    pub failed: usize,
    /// Recordings left for the next pass because the batch cap was
    /// reached. Stated so the operator knows the sweep is not done.
    pub remaining: usize,
    pub reports: Vec<IndexReport>,
}

/// One recording's stored transcript. The cold record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeIndexEntry {
    pub recording_id: String,
    pub session_id: String,
    pub indexed_at: DateTime<Utc>,
    /// Digest of the artifact this transcript was read from. An index
    /// entry whose digest no longer matches the sidecar is stale and
    /// is re-read rather than served.
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    /// Container `version` from the artifact header.
    pub format_version: u32,
    /// Header `keystroke_metadata`.
    pub keystroke_metadata: bool,
    /// Header `max_reorder_ms` — the bound on how far out of order a
    /// keystroke record may appear. The player needs it.
    pub max_reorder_ms: u64,
    /// `trailer-footer` | `text-record-scan`.
    pub source: String,
    /// False for a rebuilt trailer and for a scanned fallback, both of
    /// which are missing the session's final unclosed run.
    pub complete: bool,
    pub trailer_version: u32,
    pub rebuilt: bool,
    /// `exact` | `approximate` | `none` | `unknown`. Anything but
    /// `exact` must be surfaced in the UI.
    pub text_decoding: String,
    pub keyboard_layout: Option<String>,
    pub keyboard_layout_source: Option<String>,
    pub runs: Vec<Run>,
    /// Newline join of the non-redacted runs. The only text stored.
    pub search_text: String,
    pub census: Census,
    pub chars_indexed: u64,
    /// Bytes of the artifact the parse examined. A trailer read is
    /// bounded by the trailer; a fallback scan is not.
    pub bytes_examined: u64,
    pub warnings: Vec<String>,
}

/// One search hit, anchored so the player can seek to it.
#[derive(Debug, Clone, Serialize)]
pub struct KeystrokeHit {
    pub recording_id: String,
    pub session_id: String,
    pub target_host: String,
    pub target_user: String,
    pub authority: String,
    pub bastion_id: String,
    pub started_at: DateTime<Utc>,
    /// Index into the transcript's `runs`.
    pub run_index: usize,
    /// Elapsed ms of the run's first keystroke — the player's seek
    /// offset.
    pub t_ms: u64,
    pub d_ms: u64,
    /// Character count of the run.
    pub n: u64,
    /// The `field_epoch` correlation hint. Not a field identity.
    pub epoch: u32,
    /// A bounded window of the matching run's text.
    pub excerpt: String,
    /// The run was decoded through a fallback layout.
    pub approximate: bool,
    /// Transcript-level caveats that apply to this hit.
    pub text_decoding: String,
    pub rebuilt: bool,
    pub complete: bool,
}

/// Aggregate result of a search. `scanned`, `unindexed` and
/// `truncated` are stated so an empty result is never mistaken for a
/// complete negative.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SearchReport {
    /// Recordings whose transcript was opened.
    pub scanned: usize,
    /// Recordings with no transcript index yet — a negative result
    /// does **not** cover these, and the operator has to be told.
    pub unindexed: usize,
    /// Hit list truncated at the limit or the candidate cap.
    pub truncated: bool,
    pub hits: Vec<KeystrokeHit>,
}

pub struct KeystrokeIndexStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl KeystrokeIndexStore {
    pub async fn new(core: &dyn VaultCtx) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        Ok(Arc::new(Self {
            view: Arc::new(system_view.new_sub_view(KEYSTROKES_SUB_PATH)),
        }))
    }

    pub async fn list_ids(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn get(&self, recording_id: &str) -> Result<Option<KeystrokeIndexEntry>, RvError> {
        let id = sanitize(recording_id)?;
        let Some(entry) = self.view.get(&id).await? else {
            return Ok(None);
        };
        // A cold entry that will not decode is treated as absent
        // rather than fatal: the recording is still viewable and the
        // index can be rebuilt. Log the shape, never the content.
        match serde_json::from_slice::<KeystrokeIndexEntry>(&entry.value) {
            Ok(e) => Ok(Some(e)),
            Err(e) => {
                log::warn!(
                    "rustion/keystrokes: stored transcript for {id} did not decode ({} bytes): {e}",
                    entry.value.len()
                );
                Ok(None)
            }
        }
    }

    pub async fn put(&self, entry: &KeystrokeIndexEntry) -> Result<(), RvError> {
        let id = sanitize(&entry.recording_id)?;
        let value = serde_json::to_vec(entry)
            .map_err(|e| bv_error_string!(&format!("encode keystroke index: {e}")))?;
        self.view.put(&StorageEntry { key: id, value }).await
    }

    pub async fn delete(&self, recording_id: &str) -> Result<(), RvError> {
        let id = sanitize(recording_id)?;
        self.view.delete(&id).await
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

// ─── Indexing ───────────────────────────────────────────────────────

/// Read one recording's keystroke transcript and store it.
///
/// Fetches the artifact from its bastion, **verifies the digest
/// against the sidecar**, reads the trailer by tail-seek (falling back
/// to the `0x08` scan when the trailer is unreadable), stores the cold
/// transcript and updates the hot recording entry's counters.
///
/// `force` re-reads an artifact whose digest already matches the
/// stored index — for when the parser itself has changed.
#[maybe_async::maybe_async]
pub async fn index_recording(
    targets: &crate::store::RustionStore,
    recordings: &RecordingsStore,
    keystrokes: &KeystrokeIndexStore,
    recording_id: &str,
    force: bool,
) -> Result<IndexReport, RvError> {
    let Some(mut entry) = recordings.get(recording_id).await? else {
        return Err(crate::bv_error_response_status!(
            404,
            &format!("recording `{recording_id}` not in index")
        ));
    };
    if entry.format != KEYSTROKE_FORMAT {
        return Ok(IndexReport::plain(
            recording_id,
            IndexStatus::SkippedFormat,
            format!(
                "format `{}` cannot carry a keystroke track; only `{KEYSTROKE_FORMAT}` can",
                entry.format
            ),
        ));
    }
    if !force {
        if let Some(existing) = keystrokes.get(recording_id).await? {
            if !existing.artifact_sha256.is_empty()
                && existing.artifact_sha256.eq_ignore_ascii_case(&entry.sha256)
            {
                return Ok(IndexReport {
                    recording_id: recording_id.to_string(),
                    status: IndexStatus::Unchanged,
                    detail: "already indexed against this artifact digest".into(),
                    runs: existing.runs.len() as u64,
                    redacted_runs: existing.runs.iter().filter(|r| r.redacted).count() as u64,
                    chars_indexed: existing.chars_indexed,
                    text_decoding: existing.text_decoding,
                    rebuilt: existing.rebuilt,
                    complete: existing.complete,
                    source: existing.source,
                });
            }
        }
        // `keystroke_state` is the hot record's memory of an earlier
        // "not enabled" verdict. Without it, every sweep would
        // re-download every version-3 artifact forever.
        if entry.keystroke_state == IndexStatus::NotEnabled.as_str()
            && !entry.sha256.is_empty()
            && entry
                .keystroke_artifact_sha256
                .eq_ignore_ascii_case(&entry.sha256)
        {
            return Ok(IndexReport::plain(
                recording_id,
                IndexStatus::NotEnabled,
                "keystroke recording was not enabled for this session (cached verdict)",
            ));
        }
    }

    let (bytes, _format, header_sha) =
        crate::recordings::fetch_blob(targets, recordings, recording_id).await?;

    // The digest gate. We are about to derive durable, searchable
    // state from bastion-supplied bytes, so those bytes have to be the
    // ones the chain of custody vouches for.
    let expected = if entry.sha256.trim().is_empty() {
        header_sha.trim().to_string()
    } else {
        entry.sha256.trim().to_string()
    };
    let got = hex::encode(Sha256::digest(&bytes));
    if !expected.is_empty() && !got.eq_ignore_ascii_case(&expected) {
        log::warn!(
            "{}: recording_id={recording_id} sha256_mismatch=true size_bytes={} indexed=false",
            crate::audit::RECORDING_TRANSCRIPT_INDEXED,
            bytes.len()
        );
        return Ok(IndexReport::plain(
            recording_id,
            IndexStatus::DigestMismatch,
            format!(
                "fetched artifact digest {}… does not match the sidecar's {}…; nothing indexed",
                &got[..got.len().min(12)],
                &expected[..expected.len().min(12)]
            ),
        ));
    }

    let header = rdp_keystrokes::header_and_start(&bytes)
        .map(|(h, _)| rdp_keystrokes::parse_keystroke_header(h))
        .unwrap_or_default();

    let transcript = match rdp_keystrokes::read_transcript(&bytes) {
        Ok(Some(t)) => t,
        Ok(None) => {
            // A real state: the feature was off, or the file predates
            // it. Remember the verdict so the sweep stops re-fetching
            // this artifact, and clear any stale transcript.
            let _ = keystrokes.delete(recording_id).await;
            clear_keystroke_fields(&mut entry, IndexStatus::NotEnabled, &got, &header);
            recordings.put(&entry).await?;
            return Ok(IndexReport::plain(
                recording_id,
                IndexStatus::NotEnabled,
                format!(
                    "keystroke recording was not enabled for this session \
                     (format version {}, keystroke_metadata false)",
                    header.version
                ),
            ));
        }
        Err(e) => return Ok(IndexReport::plain(recording_id, IndexStatus::Failed, e)),
    };

    let redacted_runs = transcript.runs.iter().filter(|r| r.redacted).count() as u64;
    let stored = KeystrokeIndexEntry {
        recording_id: recording_id.to_string(),
        session_id: entry.session_id.clone(),
        indexed_at: Utc::now(),
        artifact_sha256: got.clone(),
        artifact_size_bytes: bytes.len() as u64,
        format_version: header.version,
        keystroke_metadata: header.keystroke_metadata,
        max_reorder_ms: header.max_reorder_ms,
        source: transcript.source.as_str().to_string(),
        complete: transcript.complete,
        trailer_version: transcript.trailer_version,
        rebuilt: transcript.rebuilt,
        text_decoding: transcript.text_decoding.clone(),
        keyboard_layout: transcript
            .keyboard_layout
            .clone()
            .or_else(|| header.keyboard_layout.clone()),
        keyboard_layout_source: transcript
            .keyboard_layout_source
            .clone()
            .or_else(|| header.keyboard_layout_source.clone()),
        runs: transcript.runs,
        search_text: transcript.search_text,
        census: transcript.census,
        chars_indexed: transcript.chars_indexed,
        bytes_examined: transcript.bytes_examined as u64,
        warnings: transcript.warnings,
    };
    keystrokes.put(&stored).await?;

    entry.keystroke_state = IndexStatus::Indexed.as_str().to_string();
    entry.keystroke_artifact_sha256 = got;
    entry.keystroke_text = stored.chars_indexed > 0;
    entry.keystroke_chars = stored.chars_indexed;
    entry.keystroke_runs = stored.runs.len() as u64;
    entry.keystroke_redacted_runs = redacted_runs;
    entry.keystroke_decoding = stored.text_decoding.clone();
    entry.keystroke_rebuilt = stored.rebuilt;
    entry.keystroke_complete = stored.complete;
    entry.keystroke_metadata = stored.keystroke_metadata;
    entry.keystroke_indexed_at = Some(stored.indexed_at);
    recordings.put(&entry).await?;

    // Audit: metadata only. Not one character of typed text, redacted
    // or otherwise, appears in a log line.
    log::info!(
        "{}: recording_id={recording_id} session_id={} source={} runs={} redacted_runs={} \
         chars={} text_decoding={} rebuilt={} complete={}",
        crate::audit::RECORDING_TRANSCRIPT_INDEXED,
        stored.session_id,
        stored.source,
        stored.runs.len(),
        redacted_runs,
        stored.chars_indexed,
        stored.text_decoding,
        stored.rebuilt,
        stored.complete,
    );

    Ok(IndexReport {
        recording_id: recording_id.to_string(),
        status: IndexStatus::Indexed,
        detail: stored.warnings.join("; "),
        runs: stored.runs.len() as u64,
        redacted_runs,
        chars_indexed: stored.chars_indexed,
        text_decoding: stored.text_decoding,
        rebuilt: stored.rebuilt,
        complete: stored.complete,
        source: stored.source,
    })
}

/// Reset the hot entry's keystroke summary to a terminal non-transcript
/// verdict. Keeps the field list in one place so a future field cannot
/// be forgotten on this path.
fn clear_keystroke_fields(
    entry: &mut RecordingEntry,
    status: IndexStatus,
    artifact_sha256: &str,
    header: &rdp_keystrokes::KeystrokeHeader,
) {
    entry.keystroke_state = status.as_str().to_string();
    entry.keystroke_artifact_sha256 = artifact_sha256.to_string();
    entry.keystroke_text = false;
    entry.keystroke_chars = 0;
    entry.keystroke_runs = 0;
    entry.keystroke_redacted_runs = 0;
    entry.keystroke_decoding = String::new();
    entry.keystroke_rebuilt = false;
    entry.keystroke_complete = false;
    entry.keystroke_metadata = header.keystroke_metadata;
    entry.keystroke_indexed_at = Some(Utc::now());
}

/// Index every `.rdp-rec` recording that has no current transcript, up
/// to `batch` artifacts.
///
/// Bounded on purpose: each recording costs a full artifact download
/// from its bastion, because the bastion's blob endpoint serves whole
/// files. Called by the recording poller's tick and by the explicit
/// sweep endpoint.
#[maybe_async::maybe_async]
pub async fn index_sweep(
    targets: &crate::store::RustionStore,
    recordings: &RecordingsStore,
    keystrokes: &KeystrokeIndexStore,
    batch: usize,
) -> Result<SweepReport, RvError> {
    let mut report = SweepReport::default();
    let ids = recordings.list_ids().await?;
    let mut pending: Vec<String> = Vec::new();

    for id in ids {
        let Some(entry) = recordings.get(&id).await? else {
            continue;
        };
        if entry.format != KEYSTROKE_FORMAT {
            report.skipped_format += 1;
            continue;
        }
        report.considered += 1;
        // Up to date against the artifact digest we hold?
        let fresh = !entry.keystroke_state.is_empty()
            && !entry.sha256.is_empty()
            && entry
                .keystroke_artifact_sha256
                .eq_ignore_ascii_case(&entry.sha256);
        if fresh {
            if entry.keystroke_state == IndexStatus::NotEnabled.as_str() {
                report.not_enabled += 1;
            } else {
                report.unchanged += 1;
            }
            continue;
        }
        pending.push(id);
    }

    report.remaining = pending.len().saturating_sub(batch);
    for id in pending.into_iter().take(batch) {
        match index_recording(targets, recordings, keystrokes, &id, false).await {
            Ok(r) => {
                match r.status {
                    IndexStatus::Indexed => report.indexed += 1,
                    IndexStatus::NotEnabled => report.not_enabled += 1,
                    IndexStatus::Unchanged => report.unchanged += 1,
                    IndexStatus::SkippedFormat => report.skipped_format += 1,
                    IndexStatus::DigestMismatch | IndexStatus::Failed => report.failed += 1,
                }
                report.reports.push(r);
            }
            Err(e) => {
                report.failed += 1;
                report
                    .reports
                    .push(IndexReport::plain(&id, IndexStatus::Failed, format!("{e}")));
            }
        }
    }
    Ok(report)
}

// ─── Search ─────────────────────────────────────────────────────────

/// Search stored transcripts for typed text.
///
/// Matching is per-**run** and case-insensitive. A redacted run has no
/// text and is therefore structurally unmatchable — the guarantee that
/// a hit never comes from withheld content is the data model, not a
/// filter someone has to remember to apply. A query spanning the
/// newline between two runs does not match, which is correct: two
/// separate runs are not one typed string.
///
/// `candidates` restricts the sweep, which is how the caller applies
/// namespace scoping. `None` searches every indexed recording.
///
/// **The query is not logged.** Callers log that a search ran and how
/// many hits it produced.
#[maybe_async::maybe_async]
pub async fn search_transcripts(
    recordings: &RecordingsStore,
    keystrokes: &KeystrokeIndexStore,
    query: &str,
    limit: usize,
    candidates: Option<&std::collections::HashSet<String>>,
) -> Result<SearchReport, RvError> {
    let mut report = SearchReport::default();
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Err(bv_error_string!("a keystroke search needs a query"));
    }
    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);

    let ids = recordings.list_ids().await?;
    for rid in ids {
        if let Some(allowed) = candidates {
            if !allowed.contains(&rid) {
                continue;
            }
        }
        let Some(entry) = recordings.get(&rid).await? else {
            continue;
        };
        if entry.format != KEYSTROKE_FORMAT {
            continue;
        }
        if report.scanned >= MAX_SEARCH_CANDIDATES {
            report.truncated = true;
            break;
        }
        let Some(index) = keystrokes.get(&rid).await? else {
            // Never indexed, or indexed as "not enabled". Either way a
            // negative result does not speak for this recording.
            if entry.keystroke_state != IndexStatus::NotEnabled.as_str() {
                report.unindexed += 1;
            }
            continue;
        };
        report.scanned += 1;

        for (i, run) in index.runs.iter().enumerate() {
            let Some(text) = run.text.as_deref() else {
                continue; // redacted: no text to match, by design
            };
            let Some(at) = text.to_lowercase().find(&needle) else {
                continue;
            };
            if report.hits.len() >= limit {
                report.truncated = true;
                break;
            }
            report.hits.push(KeystrokeHit {
                recording_id: rid.clone(),
                session_id: entry.session_id.clone(),
                target_host: entry.target_host.clone(),
                target_user: entry.target_user.clone(),
                authority: entry.authority.clone(),
                bastion_id: entry.bastion_id.clone(),
                started_at: entry.started_at,
                run_index: i,
                t_ms: run.t,
                d_ms: run.d,
                n: run.n,
                epoch: run.epoch,
                excerpt: excerpt_around(text, at, needle.len()),
                approximate: run.approximate,
                text_decoding: index.text_decoding.clone(),
                rebuilt: index.rebuilt,
                complete: index.complete,
            });
        }
        if report.truncated {
            break;
        }
    }
    Ok(report)
}

/// A bounded window of run text around a byte offset, snapped to char
/// boundaries. Prefixed and/or suffixed with `…` when it was cut.
fn excerpt_around(text: &str, byte_at: usize, needle_len: usize) -> String {
    // Work in chars so a multi-byte layout (pt-BR `á`, `ç`) cannot be
    // split mid-character.
    let chars: Vec<char> = text.chars().collect();
    let at = byte_at.min(text.len());
    let char_at = text[..at].chars().count();
    let needle_chars = text[at..]
        .get(..needle_len.min(text.len() - at))
        .map(|s| s.chars().count())
        .unwrap_or(0);
    let start = char_at.saturating_sub(EXCERPT_CONTEXT_CHARS);
    let end = (char_at + needle_chars + EXCERPT_CONTEXT_CHARS).min(chars.len());
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.extend(&chars[start..end]);
    if end < chars.len() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp_keystrokes::TranscriptSource;

    fn run(t: u64, text: Option<&str>, redacted: bool) -> Run {
        Run {
            t,
            d: 100,
            n: text.map(|s| s.chars().count() as u64).unwrap_or(8),
            text: text.map(str::to_string),
            redacted,
            reason: redacted.then(|| "known_secret".to_string()),
            epoch: 1,
            composed: false,
            approximate: false,
            truncated: false,
        }
    }

    #[test]
    fn excerpt_is_bounded_and_marks_where_it_cut() {
        let long = "a".repeat(400) + "needle" + &"b".repeat(400);
        let at = long.find("needle").unwrap();
        let e = excerpt_around(&long, at, 6);
        assert!(e.starts_with('…') && e.ends_with('…'));
        assert!(e.contains("needle"));
        assert!(
            e.chars().count() <= 2 * EXCERPT_CONTEXT_CHARS + 6 + 2,
            "excerpt was {} chars",
            e.chars().count()
        );
    }

    #[test]
    fn excerpt_does_not_split_a_multibyte_character() {
        // pt-BR dead-key output is the realistic case here.
        let text = "senhá não é ótima";
        let at = text.find("não").unwrap();
        let e = excerpt_around(text, at, "não".len());
        assert_eq!(e, text, "short text should come back whole");
    }

    #[test]
    fn excerpt_of_a_short_run_is_the_whole_run() {
        assert_eq!(excerpt_around("dir[Enter]", 0, 3), "dir[Enter]");
    }

    #[test]
    fn a_redacted_run_carries_no_text_to_match() {
        // The structural guarantee: search matches `run.text`, and a
        // redacted run's is `None`. There is nothing to filter.
        let r = run(10, None, true);
        assert!(r.text.is_none());
        assert_eq!(r.reason.as_deref(), Some("known_secret"));
    }

    #[test]
    fn index_status_strings_are_stable() {
        // These land in a persisted `RecordingEntry` field and in the
        // GUI's switch statements; renaming one is a migration.
        assert_eq!(IndexStatus::Indexed.as_str(), "indexed");
        assert_eq!(IndexStatus::NotEnabled.as_str(), "not-enabled");
        assert_eq!(IndexStatus::SkippedFormat.as_str(), "skipped-format");
        assert_eq!(IndexStatus::Unchanged.as_str(), "unchanged");
        assert_eq!(IndexStatus::DigestMismatch.as_str(), "digest-mismatch");
        assert_eq!(IndexStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn transcript_source_strings_match_the_stored_field() {
        assert_eq!(TranscriptSource::TrailerFooter.as_str(), "trailer-footer");
        assert_eq!(TranscriptSource::TextRecordScan.as_str(), "text-record-scan");
    }

    #[test]
    fn a_stored_entry_round_trips_and_never_carries_text_applied() {
        let e = KeystrokeIndexEntry {
            recording_id: "rec_abc".into(),
            session_id: "sess_abc".into(),
            indexed_at: Utc::now(),
            artifact_sha256: "aa".repeat(32),
            artifact_size_bytes: 4096,
            format_version: 4,
            keystroke_metadata: true,
            max_reorder_ms: 2000,
            source: TranscriptSource::TrailerFooter.as_str().into(),
            complete: true,
            trailer_version: 1,
            rebuilt: false,
            text_decoding: "exact".into(),
            keyboard_layout: Some("0x00000416".into()),
            keyboard_layout_source: Some("client_core".into()),
            runs: vec![run(10, Some("dir[Enter]"), false), run(50, None, true)],
            search_text: "dir[Enter]".into(),
            census: Census {
                keys_total: 12,
                redacted_runs: 1,
                redacted_chars: 8,
                ..Census::default()
            },
            chars_indexed: 10,
            bytes_examined: 512,
            warnings: vec!["w".into()],
        };
        let json = serde_json::to_vec(&e).unwrap();
        let back: KeystrokeIndexEntry = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.search_text, "dir[Enter]");
        assert_eq!(back.runs.len(), 2);
        assert!(back.runs[1].redacted);
        assert_eq!(back.runs[1].text, None);
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(v.get("text_applied").is_none());
    }
}
