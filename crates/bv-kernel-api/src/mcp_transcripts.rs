//! Transcripts of MCP brokered sessions (`features/mcp-brokered-sessions.md`
//! §10 "Transcripts"): what an agent's session command was and what came
//! back, kept 30 days for an investigator.
//!
//! Here, in the kernel contract, because two tiers name the same store: the
//! resource engine records a session (the writer, [`TranscriptStore::record`])
//! and `bv-kernel` reads (`v2/sys/mcp/transcripts`) and prunes it (the audit
//! retention housekeeping). Neither may depend on the other.
//!
//! **Layout.** A flat store under the system view, [`MCP_TRANSCRIPTS_SUB_PATH`],
//! barrier-encrypted like every storage entry. One session is
//!
//! ```text
//! <20-digit nanos>-<session_id>        head: version, summary, chunk count, body length
//! <20-digit nanos>-<session_id>.1..n   body: the protocol record's JSON, split in chunks
//! ```
//!
//! The nanosecond prefix is what the retention job classifies, so a head and
//! its chunks expire together. Chunks are written first and the head last: a
//! head is only ever visible once its whole body is stored, and chunks left by
//! a failed write are invisible (nothing lists them) and expire on the same
//! rule. The head is small, so a listing can show what a transcript is without
//! decrypting its body.
//!
//! **What is stored.** The command verbatim and the output *after* the
//! session's own credential was scrubbed and *before* model sanitization, so
//! ANSI and other bytes survive for forensics. The writer scrubs every text
//! field itself, through the caller's [`TranscriptScrubber`], so the session
//! credential cannot reach a record even when a caller forgot to. A transcript
//! can still hold **other** secrets a command printed (`cat .env`): that is why
//! reading one needs `read`/`list` *and* `sudo`, every read is audited, and
//! records are pruned after [`TRANSCRIPT_RETENTION_DAYS`] whatever the
//! operator's audit retention says.
//!
//! **Versioning.** The head carries [`TRANSCRIPT_RECORD_VERSION`]. A reader
//! refuses a version it does not know, and every malformed record, by name,
//! instead of skipping it: a transcript an investigator cannot read must say
//! so.

use std::time::{SystemTime, UNIX_EPOCH};

use bv_errors::RvError;
use bv_logical::McpOperatorRef;
use bv_storage::{barrier_view::BarrierView, Storage, StorageEntry};
use serde::{Deserialize, Serialize};

use crate::ctx::VaultCtx;

/// System-view sub-path of the store. Named here once for the writer (the
/// resource engine), the reader and the pruner (`bv-kernel`).
pub const MCP_TRANSCRIPTS_SUB_PATH: &str = "mcp-session-transcripts/";

/// Fixed retention, decided 2026-10-14 by the owner. Not configurable: the
/// operator's audit retention can neither shorten nor lengthen it.
pub const TRANSCRIPT_RETENTION_DAYS: u32 = 30;

/// Current on-disk version of a transcript head (and of the body format it
/// describes).
pub const TRANSCRIPT_RECORD_VERSION: u32 = 1;

/// Body bytes per chunk entry. One storage entry is one Raft entry on
/// hiqlite; 1 MiB keeps a large transcript from becoming one large write.
pub const TRANSCRIPT_CHUNK_BYTES: usize = 1 << 20;

/// Largest body a transcript may have (32 chunks). Generous: two 1 MiB
/// streams JSON-escaped at worst six bytes per byte, plus redaction markers.
/// A larger record is refused, never truncated in silence.
pub const MAX_TRANSCRIPT_BODY_BYTES: usize = 32 << 20;

/// Most of one SSH stream a transcript keeps (`features/mcp-brokered-sessions.md`
/// §10: "up to 1 MiB per stream, beyond the model's copy").
pub const MAX_TRANSCRIPT_STREAM_BYTES: usize = 1 << 20;

/// Longest SSH command a transcript accepts: the session tool's own ceiling
/// (§11 "Limits"), which the dispatcher enforces before anything runs.
pub const MAX_TRANSCRIPT_COMMAND_BYTES: usize = 4096;

/// Longest web request path (with its query) a transcript accepts: the
/// web fetch tool's own ceiling, which the dispatcher enforces.
pub const MAX_TRANSCRIPT_WEB_PATH_BYTES: usize = 2048;

/// Longest redirect-hop path a transcript keeps. A server chooses these, so
/// the executor cuts a longer one (and says so) before it is recorded.
pub const MAX_TRANSCRIPT_HOP_PATH_BYTES: usize = 8192;

/// Most requests one web fetch makes (the first, five redirects, and a
/// challenge answer on each), and so most hops a transcript lists.
pub const MAX_TRANSCRIPT_WEB_HOPS: usize = 12;

/// Longest session id. Ids are `[a-z0-9_-]` (the spec's ids look like
/// `as_6f0c…`), so a transcript id is a single, dot-free storage key segment
/// and a chunk key cannot be named as an id.
pub const MAX_SESSION_ID_LEN: usize = 64;

/// Width of the nanosecond prefix, the same as every store the audit
/// retention job prunes.
const NANOS_WIDTH: usize = 20;

const MAX_TRANSCRIPT_CHUNKS: usize = MAX_TRANSCRIPT_BODY_BYTES / TRANSCRIPT_CHUNK_BYTES;

/// Why a transcript could not be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// Not a transcript id (`<20 digits>-<session id>`). Nothing was read.
    InvalidId(String),
    /// The record to write breaks a bound or carries a malformed field.
    Invalid(String),
    /// A stored record that does not decode: unknown version, missing chunk,
    /// length mismatch, malformed JSON.
    Unreadable { id: String, reason: String },
    /// The storage layer failed.
    Storage(String),
}

impl std::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId(id) => write!(f, "{id:?} is not a transcript id (<20-digit nanoseconds>-<session id>)"),
            Self::Invalid(reason) => write!(f, "transcript refused: {reason}"),
            Self::Unreadable { id, reason } => write!(f, "transcript {id} is unreadable: {reason}"),
            Self::Storage(e) => write!(f, "transcript storage failed: {e}"),
        }
    }
}

impl From<RvError> for TranscriptError {
    fn from(e: RvError) -> Self {
        Self::Storage(e.to_string())
    }
}

/// What the writer asks of the caller's credential scrubber: replace every
/// encoding of the session's own credential it knows, and say whether it
/// replaced anything. The resource engine adapts `bv_mcp::untrusted`'s
/// `CredentialScrubber` to it; a certificate login, which has no reusable
/// secret, passes [`NoCredential`].
///
/// `Sync`, so a `&dyn TranscriptScrubber` held across [`TranscriptStore::record`]'s
/// storage writes keeps the future `Send`: a session records its transcript
/// from its own spawned task.
pub trait TranscriptScrubber: Sync {
    fn scrub(&self, text: &str) -> (String, bool);
}

/// The scrubber for a session with no reusable credential.
pub struct NoCredential;

impl TranscriptScrubber for NoCredential {
    fn scrub(&self, text: &str) -> (String, bool) {
        (text.to_string(), false)
    }
}

/// Who and what a session was: everything an investigator needs to find a
/// transcript, nothing that is secret. Stored in the head, so listing it
/// decrypts no output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSummary {
    /// The session id the `connect.agent.*` events carry.
    pub session_id: String,
    /// The MCP tool, e.g. `bv_resource_ssh_exec`.
    pub tool: String,
    pub resource: String,
    pub profile_id: String,
    /// The operator who approved the pairing (`McpBinding::operator`).
    #[serde(default)]
    pub operator: Option<McpOperatorRef>,
    #[serde(default)]
    pub pairing_id: String,
    #[serde(default)]
    pub client_name: String,
    /// Whether the same binding could also reveal secrets (§1).
    #[serde(default)]
    pub binding_reveal_allowed: bool,
    /// How the operator's confirmation is known, e.g.
    /// `"asserted-by-local-host"` (§9).
    #[serde(default)]
    pub operator_confirmation: Option<String>,
    /// The MFA method when the profile was gated.
    #[serde(default)]
    pub mfa_method: Option<String>,
    /// Unix milliseconds.
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    /// Whether any field had the session credential scrubbed from it, by the
    /// executor or by the writer.
    #[serde(default)]
    pub credential_echo_redacted: bool,
}

/// One captured output stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptStream {
    /// Lossy UTF-8 of what was kept, credential-scrubbed, not sanitized.
    /// Empty for a stream reported as binary.
    pub text: String,
    /// Bytes the target sent on this stream, including any not kept.
    pub seen_bytes: u64,
    /// The stream exceeded [`MAX_TRANSCRIPT_STREAM_BYTES`] and `text` holds
    /// only its start.
    #[serde(default)]
    pub stored_truncated: bool,
    /// Byte offset at which the model's copy stopped, when it was truncated.
    #[serde(default)]
    pub model_truncated_at: Option<u64>,
    #[serde(default)]
    pub binary: bool,
}

/// An SSH `exec` session (§5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTranscript {
    /// The command, verbatim (credential-scrubbed).
    pub command: String,
    /// The `host:port` dialed.
    pub target: String,
    pub host_key_fingerprint: String,
    /// `certificate`, `password` or `stored-key`.
    pub login: String,
    #[serde(default)]
    pub cert_serial: Option<String>,
    #[serde(default)]
    pub exit_status: Option<u32>,
    #[serde(default)]
    pub exit_signal: Option<String>,
    #[serde(default)]
    pub timed_out: bool,
    /// Why the session was cut short (`token_revoked`, `kill_switch`,
    /// `timeout`, `executor_error`), when it was.
    #[serde(default)]
    pub aborted: Option<String>,
    pub stdout: TranscriptStream,
    pub stderr: TranscriptStream,
}

/// One request a web fetch sent (`features/mcp-brokered-sessions.md` §10:
/// "each redirect hop's path").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTranscriptHop {
    /// `https://host[:port]`.
    pub origin: String,
    /// The path with its query, as sent (credential- and session-scrubbed by
    /// the writer). At most [`MAX_TRANSCRIPT_HOP_PATH_BYTES`].
    pub path: String,
    /// The response status; `None` when no response arrived.
    #[serde(default)]
    pub status: Option<u16>,
    /// This request answered an HTTP authentication challenge with the
    /// profile's credential.
    #[serde(default)]
    pub answered_challenge: bool,
}

/// A web `GET`/`HEAD` fetch (§6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTranscript {
    /// `GET` or `HEAD`.
    pub method: String,
    /// The origin-relative path with its query, as the operator confirmed it.
    pub path: String,
    /// The profile's start origin the path was fetched from.
    pub origin: String,
    /// The `ip:port` the first request dialed.
    #[serde(default)]
    pub target: String,
    /// `open` or `http-auth`.
    pub login: String,
    /// How the server's certificate was trusted on the last request:
    /// `platform`, `pinned-leaf` or `pinned-issuer`.
    #[serde(default)]
    pub tls: Option<String>,
    /// Every request sent, in order.
    #[serde(default)]
    pub hops: Vec<WebTranscriptHop>,
    /// The final response's status; `None` when the fetch stopped before one.
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Raw body bytes read (at most the raw-read cap).
    #[serde(default)]
    pub body_bytes: u64,
    /// The raw body was longer than the raw-read cap.
    #[serde(default)]
    pub body_truncated: bool,
    /// The extracted response text (HTML reduced to text), credential-
    /// scrubbed, not sanitized; up to 1 MiB, with where the model's copy
    /// stopped.
    #[serde(default)]
    pub text: TranscriptStream,
    #[serde(default)]
    pub timed_out: bool,
    /// Why the session was cut short (`token_revoked`, `kill_switch`,
    /// `timeout`, `executor_error`), when it was.
    #[serde(default)]
    pub aborted: Option<String>,
    /// The refusal code that stopped the fetch after it had dialed (an
    /// off-origin redirect, a refused hop destination, a refused
    /// certificate), when one did.
    #[serde(default)]
    pub stopped: Option<String>,
}

/// The protocol-specific half of a transcript. RDP (Phase 3) adds a
/// variant; a reader refuses a variant it does not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum TranscriptBody {
    Ssh(SshTranscript),
    Web(WebTranscript),
}

impl TranscriptBody {
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Ssh(_) => "ssh",
            Self::Web(_) => "web",
        }
    }
}

/// One session's transcript, as recorded and as read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSessionTranscript {
    pub summary: TranscriptSummary,
    pub body: TranscriptBody,
}

/// The head entry, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptHead {
    pub version: u32,
    /// `ssh`, `web` or `rdp`; the body must say the same.
    pub protocol: String,
    pub summary: TranscriptSummary,
    /// Body chunk entries, `.1` to `.chunks`. At least one.
    pub chunks: u32,
    /// Total body length across the chunks.
    pub body_bytes: u64,
}

/// A transcript id's two halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptId<'a> {
    /// Nanoseconds since the epoch at which the transcript was recorded.
    pub nanos: u128,
    pub session_id: &'a str,
}

/// Is `session_id` acceptable as the second half of a transcript id?
pub fn valid_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= MAX_SESSION_ID_LEN
        && session_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Parse `<20 digits>-<session id>`. Anything else — a chunk key, a path, an
/// upper-case id — is `None`.
pub fn parse_transcript_id(id: &str) -> Option<TranscriptId<'_>> {
    let bytes = id.as_bytes();
    if bytes.len() < NANOS_WIDTH + 2 || bytes[NANOS_WIDTH] != b'-' {
        return None;
    }
    let (digits, rest) = id.split_at(NANOS_WIDTH);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let session_id = &rest[1..];
    if !valid_session_id(session_id) {
        return None;
    }
    Some(TranscriptId { nanos: digits.parse().ok()?, session_id })
}

/// The id a transcript recorded at `nanos` for `session_id` gets.
pub fn transcript_id(nanos: u128, session_id: &str) -> String {
    format!("{nanos:0width$}-{session_id}", width = NANOS_WIDTH)
}

fn chunk_key(id: &str, n: usize) -> String {
    format!("{id}.{n}")
}

fn now_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// Scrub every text field and check the bounds; the record to store.
fn prepare(
    mut transcript: McpSessionTranscript,
    scrubber: &dyn TranscriptScrubber,
) -> Result<McpSessionTranscript, TranscriptError> {
    let summary = &mut transcript.summary;
    if !valid_session_id(&summary.session_id) {
        return Err(TranscriptError::Invalid(format!(
            "session id {:?} must be 1-{MAX_SESSION_ID_LEN} characters of [a-z0-9_-]",
            summary.session_id
        )));
    }
    if summary.tool.is_empty() || summary.resource.is_empty() || summary.profile_id.is_empty() {
        return Err(TranscriptError::Invalid("tool, resource and profile_id are required".into()));
    }
    let mut redacted = false;
    let mut scrub = |text: &mut String| {
        let (clean, hit) = scrubber.scrub(text);
        *text = clean;
        redacted |= hit;
    };
    match &mut transcript.body {
        TranscriptBody::Ssh(ssh) => {
            if ssh.command.len() > MAX_TRANSCRIPT_COMMAND_BYTES {
                return Err(TranscriptError::Invalid(format!(
                    "the command is {} bytes; at most {MAX_TRANSCRIPT_COMMAND_BYTES}",
                    ssh.command.len()
                )));
            }
            for (name, stream) in [("stdout", &ssh.stdout), ("stderr", &ssh.stderr)] {
                if stream.text.len() > MAX_TRANSCRIPT_STREAM_BYTES {
                    return Err(TranscriptError::Invalid(format!(
                        "{name} holds {} bytes; a transcript keeps at most {MAX_TRANSCRIPT_STREAM_BYTES} per stream",
                        stream.text.len()
                    )));
                }
            }
            scrub(&mut ssh.command);
            scrub(&mut ssh.stdout.text);
            scrub(&mut ssh.stderr.text);
        }
        TranscriptBody::Web(web) => {
            if web.method != "GET" && web.method != "HEAD" {
                return Err(TranscriptError::Invalid(format!("web method {:?} is not GET or HEAD", web.method)));
            }
            if web.path.len() > MAX_TRANSCRIPT_WEB_PATH_BYTES {
                return Err(TranscriptError::Invalid(format!(
                    "the path is {} bytes; at most {MAX_TRANSCRIPT_WEB_PATH_BYTES}",
                    web.path.len()
                )));
            }
            if web.hops.len() > MAX_TRANSCRIPT_WEB_HOPS {
                return Err(TranscriptError::Invalid(format!(
                    "{} requests; a web transcript keeps at most {MAX_TRANSCRIPT_WEB_HOPS}",
                    web.hops.len()
                )));
            }
            if let Some(hop) = web.hops.iter().find(|h| h.path.len() > MAX_TRANSCRIPT_HOP_PATH_BYTES) {
                return Err(TranscriptError::Invalid(format!(
                    "a hop path is {} bytes; at most {MAX_TRANSCRIPT_HOP_PATH_BYTES}",
                    hop.path.len()
                )));
            }
            if web.text.text.len() > MAX_TRANSCRIPT_STREAM_BYTES {
                return Err(TranscriptError::Invalid(format!(
                    "the response text is {} bytes; a transcript keeps at most {MAX_TRANSCRIPT_STREAM_BYTES}",
                    web.text.text.len()
                )));
            }
            scrub(&mut web.path);
            for hop in &mut web.hops {
                scrub(&mut hop.path);
            }
            scrub(&mut web.text.text);
        }
    }
    transcript.summary.credential_echo_redacted |= redacted;
    Ok(transcript)
}

/// The storage entries for `transcript` recorded at `nanos`: the chunks, then
/// the head, in the order they must be written. Returns the transcript id.
pub fn encode(
    transcript: McpSessionTranscript,
    nanos: u128,
    scrubber: &dyn TranscriptScrubber,
) -> Result<(String, Vec<StorageEntry>), TranscriptError> {
    let transcript = prepare(transcript, scrubber)?;
    let id = transcript_id(nanos, &transcript.summary.session_id);
    let body = serde_json::to_vec(&transcript.body).map_err(|e| TranscriptError::Invalid(e.to_string()))?;
    if body.len() > MAX_TRANSCRIPT_BODY_BYTES {
        return Err(TranscriptError::Invalid(format!(
            "the record is {} bytes; at most {MAX_TRANSCRIPT_BODY_BYTES}",
            body.len()
        )));
    }
    let mut entries: Vec<StorageEntry> = body
        .chunks(TRANSCRIPT_CHUNK_BYTES)
        .enumerate()
        .map(|(i, chunk)| StorageEntry { key: chunk_key(&id, i + 1), value: chunk.to_vec() })
        .collect();
    let head = TranscriptHead {
        version: TRANSCRIPT_RECORD_VERSION,
        protocol: transcript.body.protocol().to_string(),
        summary: transcript.summary,
        chunks: entries.len() as u32,
        body_bytes: body.len() as u64,
    };
    let head = serde_json::to_vec(&head).map_err(|e| TranscriptError::Invalid(e.to_string()))?;
    entries.push(StorageEntry { key: id.clone(), value: head });
    Ok((id, entries))
}

/// Decode a head entry. An unknown version, a chunk count or length out of
/// bounds, or malformed JSON is unreadable.
pub fn decode_head(id: &str, bytes: &[u8]) -> Result<TranscriptHead, TranscriptError> {
    let unreadable = |reason: String| TranscriptError::Unreadable { id: id.to_string(), reason };
    // The version first, so a record from a newer build names its version
    // instead of failing on a field this build does not know.
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| unreadable(format!("the head is not JSON: {e}")))?;
    match raw.get("version").and_then(serde_json::Value::as_u64) {
        Some(v) if v == u64::from(TRANSCRIPT_RECORD_VERSION) => {}
        Some(v) => {
            return Err(unreadable(format!(
                "unsupported transcript version {v} (this build reads {TRANSCRIPT_RECORD_VERSION})"
            )))
        }
        None => return Err(unreadable("the head has no version".into())),
    }
    let head: TranscriptHead =
        serde_json::from_value(raw).map_err(|e| unreadable(format!("the head is malformed: {e}")))?;
    if head.chunks == 0 || head.chunks as usize > MAX_TRANSCRIPT_CHUNKS {
        return Err(unreadable(format!("the head names {} body chunks", head.chunks)));
    }
    if head.body_bytes > MAX_TRANSCRIPT_BODY_BYTES as u64 {
        return Err(unreadable(format!("the head names a {}-byte body", head.body_bytes)));
    }
    Ok(head)
}

/// Join a head with its chunks (in order, `.1` first) into the transcript.
/// A missing chunk, a length mismatch or a body that does not match the head
/// is unreadable.
pub fn assemble(
    id: &str,
    head: TranscriptHead,
    chunks: Vec<Option<Vec<u8>>>,
) -> Result<McpSessionTranscript, TranscriptError> {
    let unreadable = |reason: String| TranscriptError::Unreadable { id: id.to_string(), reason };
    if chunks.len() != head.chunks as usize {
        return Err(unreadable(format!("expected {} body chunks, got {}", head.chunks, chunks.len())));
    }
    let mut body = Vec::with_capacity(head.body_bytes as usize);
    for (i, chunk) in chunks.into_iter().enumerate() {
        match chunk {
            Some(bytes) => body.extend_from_slice(&bytes),
            None => return Err(unreadable(format!("body chunk {} is missing", i + 1))),
        }
    }
    if body.len() as u64 != head.body_bytes {
        return Err(unreadable(format!("the body is {} bytes; the head says {}", body.len(), head.body_bytes)));
    }
    let body: TranscriptBody =
        serde_json::from_slice(&body).map_err(|e| unreadable(format!("the body is malformed: {e}")))?;
    if body.protocol() != head.protocol {
        return Err(unreadable(format!("the head says protocol {:?}, the body {:?}", head.protocol, body.protocol())));
    }
    Ok(McpSessionTranscript { summary: head.summary, body })
}

/// The transcript store, over the system view.
pub struct TranscriptStore {
    view: BarrierView,
}

#[maybe_async::maybe_async]
impl TranscriptStore {
    /// The store of a running, unsealed vault.
    pub fn from_ctx(ctx: &dyn VaultCtx) -> Result<Self, RvError> {
        let system_view = ctx.system_view().ok_or(RvError::ErrBarrierSealed)?;
        Ok(Self::new(&system_view))
    }

    /// The store under `system_view`.
    pub fn new(system_view: &BarrierView) -> Self {
        Self { view: system_view.new_sub_view(MCP_TRANSCRIPTS_SUB_PATH) }
    }

    /// Record one session, now. Every text field is passed through
    /// `scrubber` first. Chunks are written before the head, so a failure
    /// leaves no visible transcript. Returns the transcript id, which the
    /// session's `connect.agent.*` event carries as `transcript_id`.
    pub async fn record(
        &self,
        transcript: McpSessionTranscript,
        scrubber: &dyn TranscriptScrubber,
    ) -> Result<String, TranscriptError> {
        self.record_at(transcript, now_nanos(), scrubber).await
    }

    /// [`Self::record`] at an explicit instant (nanoseconds since the epoch).
    pub async fn record_at(
        &self,
        transcript: McpSessionTranscript,
        nanos: u128,
        scrubber: &dyn TranscriptScrubber,
    ) -> Result<String, TranscriptError> {
        let (id, entries) = encode(transcript, nanos, scrubber)?;
        for entry in &entries {
            self.view.put(entry).await?;
        }
        Ok(id)
    }

    /// Every transcript id, newest first. Keys only: no record is read.
    pub async fn list(&self) -> Result<Vec<String>, TranscriptError> {
        let mut ids: Vec<String> =
            self.view.list("").await?.into_iter().filter(|k| parse_transcript_id(k).is_some()).collect();
        ids.sort_by(|a, b| b.cmp(a));
        Ok(ids)
    }

    /// The head of transcript `id` only: who and what, without the output.
    pub async fn read_head(&self, id: &str) -> Result<Option<TranscriptHead>, TranscriptError> {
        if parse_transcript_id(id).is_none() {
            return Err(TranscriptError::InvalidId(id.to_string()));
        }
        match self.view.get(id).await? {
            None => Ok(None),
            Some(entry) => decode_head(id, &entry.value).map(Some),
        }
    }

    /// Transcript `id`, whole. `None` when there is no such transcript.
    pub async fn read(&self, id: &str) -> Result<Option<McpSessionTranscript>, TranscriptError> {
        let Some(head) = self.read_head(id).await? else {
            return Ok(None);
        };
        let mut chunks = Vec::with_capacity(head.chunks as usize);
        for n in 1..=head.chunks as usize {
            chunks.push(self.view.get(&chunk_key(id, n)).await?.map(|e| e.value));
        }
        assemble(id, head, chunks).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replaces one secret, raw, the way the resource engine's scrubber does
    /// in every encoding.
    struct Replace(&'static str);
    impl TranscriptScrubber for Replace {
        fn scrub(&self, text: &str) -> (String, bool) {
            (text.replace(self.0, "<redacted:credential>"), text.contains(self.0))
        }
    }

    fn ssh(command: &str, stdout: &str) -> McpSessionTranscript {
        McpSessionTranscript {
            summary: TranscriptSummary {
                session_id: "as_0b1c-42".into(),
                tool: "bv_resource_ssh_exec".into(),
                resource: "web-01".into(),
                profile_id: "p_agent".into(),
                operator: Some(McpOperatorRef { username: "felipe".into(), ..Default::default() }),
                pairing_id: "pair-1".into(),
                client_name: "claude-code".into(),
                started_at_ms: 1_000,
                finished_at_ms: 1_250,
                ..Default::default()
            },
            body: TranscriptBody::Ssh(SshTranscript {
                command: command.into(),
                target: "10.0.0.9:22".into(),
                host_key_fingerprint: "SHA256:abc".into(),
                login: "password".into(),
                exit_status: Some(0),
                stdout: TranscriptStream { text: stdout.into(), seen_bytes: stdout.len() as u64, ..Default::default() },
                ..Default::default()
            }),
        }
    }

    fn round_trip(entries: &[StorageEntry], id: &str) -> Result<McpSessionTranscript, TranscriptError> {
        let get = |k: &str| entries.iter().find(|e| e.key == k).map(|e| e.value.clone());
        let head = decode_head(id, &get(id).unwrap())?;
        let chunks = (1..=head.chunks as usize).map(|n| get(&chunk_key(id, n))).collect();
        assemble(id, head, chunks)
    }

    #[test]
    fn ids_are_nanos_and_a_session_id_and_nothing_else() {
        let id = transcript_id(1_760_000_000_123_456_789, "as_0b1c-42");
        assert_eq!(id, "01760000000123456789-as_0b1c-42");
        let parsed = parse_transcript_id(&id).unwrap();
        assert_eq!((parsed.nanos, parsed.session_id), (1_760_000_000_123_456_789, "as_0b1c-42"));
        for bad in [
            "",
            "01760000000123456789",
            "01760000000123456789-",
            "01760000000123456789-0b1c-42.1",
            "01760000000123456789-ABC",
            "01760000000123456789-a/b",
            "0176000000012345678x-abc",
            "1760000000123456789-abc",
            "../01760000000123456789-abc",
        ] {
            assert!(parse_transcript_id(bad).is_none(), "{bad:?}");
        }
        assert!(!valid_session_id(&"a".repeat(MAX_SESSION_ID_LEN + 1)));
    }

    /// The command and both streams are scrubbed by the writer, chunks come
    /// before the head, and the record reads back equal.
    #[test]
    fn a_record_is_scrubbed_chunked_head_last_and_reads_back() {
        let (id, entries) =
            encode(ssh("echo hunter2 | sudo -S id", "[sudo] password: hunter2\nuid=0(root)\n"), 7, &Replace("hunter2"))
                .unwrap();
        assert_eq!(entries.last().unwrap().key, id, "the head is written last");
        assert!(entries.iter().all(|e| !String::from_utf8_lossy(&e.value).contains("hunter2")));
        let back = round_trip(&entries, &id).unwrap();
        assert!(back.summary.credential_echo_redacted);
        let TranscriptBody::Ssh(body) = &back.body else { panic!("an ssh transcript") };
        assert_eq!(body.command, "echo <redacted:credential> | sudo -S id");
        assert!(body.stdout.text.contains("uid=0(root)") && !body.stdout.text.contains("hunter2"));

        // A large body spans several chunks, each at most one chunk long.
        let big = "x".repeat(MAX_TRANSCRIPT_STREAM_BYTES);
        let (id, entries) = encode(ssh("seq 1 1000000", &big), 8, &NoCredential).unwrap();
        let chunks = entries.len() - 1;
        assert!(chunks >= 2, "{chunks}");
        assert!(entries[..chunks].iter().all(|e| e.value.len() <= TRANSCRIPT_CHUNK_BYTES));
        assert!(!round_trip(&entries, &id).unwrap().summary.credential_echo_redacted);
    }

    #[test]
    fn records_out_of_bounds_are_refused_not_truncated() {
        let long_command = "a".repeat(MAX_TRANSCRIPT_COMMAND_BYTES + 1);
        assert!(matches!(encode(ssh(&long_command, ""), 1, &NoCredential), Err(TranscriptError::Invalid(_))));
        let long_stream = "a".repeat(MAX_TRANSCRIPT_STREAM_BYTES + 1);
        assert!(matches!(encode(ssh("id", &long_stream), 1, &NoCredential), Err(TranscriptError::Invalid(_))));
        for session_id in ["", "UPPER", "a.b", "a/b"] {
            let mut t = ssh("id", "");
            t.summary.session_id = session_id.into();
            assert!(matches!(encode(t, 1, &NoCredential), Err(TranscriptError::Invalid(_))), "{session_id:?}");
        }
        let mut t = ssh("id", "");
        t.summary.resource.clear();
        assert!(matches!(encode(t, 1, &NoCredential), Err(TranscriptError::Invalid(_))));
    }

    /// The first version's on-disk form, pinned: a later build must keep
    /// reading it (read-old). Optional fields a later version adds must
    /// default when absent, as `operator`, `mfa_method` and the stream flags
    /// do here.
    #[test]
    fn a_version_1_record_as_first_written_still_reads() {
        let id = "01760000000000000000-s-1";
        let body = br#"{"protocol":"ssh","command":"uptime","target":"10.0.0.9:22","host_key_fingerprint":"SHA256:k","login":"certificate","stdout":{"text":" 10:00 up 3 days\n","seen_bytes":17},"stderr":{"text":"","seen_bytes":0}}"#;
        let head = format!(
            r#"{{"version":1,"protocol":"ssh","summary":{{"session_id":"s-1","tool":"bv_resource_ssh_exec","resource":"web-01","profile_id":"p","started_at_ms":1,"finished_at_ms":2}},"chunks":1,"body_bytes":{}}}"#,
            body.len()
        );
        let head = decode_head(id, head.as_bytes()).unwrap();
        let t = assemble(id, head, vec![Some(body.to_vec())]).unwrap();
        assert_eq!(t.summary.operator, None);
        assert!(!t.summary.credential_echo_redacted);
        let TranscriptBody::Ssh(ssh) = t.body else { panic!("an ssh transcript") };
        assert_eq!(ssh.command, "uptime");
        assert_eq!(ssh.exit_status, None);
        assert_eq!(ssh.stdout.model_truncated_at, None);
        assert!(!ssh.stdout.binary && !ssh.timed_out);
    }

    /// Every malformed record is refused by name, never skipped or patched.
    #[test]
    fn malformed_records_are_unreadable_with_a_reason() {
        let (id, entries) = encode(ssh("id", "uid=0\n"), 9, &NoCredential).unwrap();
        let head_bytes = entries.last().unwrap().value.clone();
        let chunk = entries[0].value.clone();
        let head = || decode_head(&id, &head_bytes).unwrap();
        let reason = |r: Result<McpSessionTranscript, TranscriptError>| match r {
            Err(TranscriptError::Unreadable { reason, .. }) => reason,
            other => panic!("expected unreadable, got {other:?}"),
        };
        let head_reason = |bytes: &[u8]| match decode_head(&id, bytes) {
            Err(TranscriptError::Unreadable { reason, .. }) => reason,
            other => panic!("expected unreadable, got {other:?}"),
        };

        assert!(head_reason(b"{garbage").contains("not JSON"));
        assert!(head_reason(br#"{"protocol":"ssh"}"#).contains("no version"));
        assert!(head_reason(br#"{"version":2,"anything":true}"#).contains("unsupported transcript version 2"));
        assert!(head_reason(br#"{"version":1,"protocol":"ssh"}"#).contains("malformed"));
        let mut zero: serde_json::Value = serde_json::from_slice(&head_bytes).unwrap();
        zero["chunks"] = 0.into();
        assert!(head_reason(&serde_json::to_vec(&zero).unwrap()).contains("0 body chunks"));
        zero["chunks"] = 1000.into();
        assert!(head_reason(&serde_json::to_vec(&zero).unwrap()).contains("1000 body chunks"));

        assert!(reason(assemble(&id, head(), vec![None])).contains("chunk 1 is missing"));
        assert!(reason(assemble(&id, head(), vec![])).contains("expected 1 body chunks"));
        assert!(reason(assemble(&id, head(), vec![Some(chunk[..chunk.len() - 1].to_vec())])).contains("the head says"));
        let mut not_json = chunk.clone();
        not_json[0] = b'#';
        assert!(reason(assemble(&id, head(), vec![Some(not_json)])).contains("malformed"));
        let mut other_protocol = head();
        other_protocol.protocol = "rdp".into();
        assert!(reason(assemble(&id, other_protocol, vec![Some(chunk.clone())])).contains("protocol"));
        let unknown_variant = br#"{"protocol":"telnet","command":"id"}"#.to_vec();
        let mut h = head();
        h.body_bytes = unknown_variant.len() as u64;
        assert!(reason(assemble(&id, h, vec![Some(unknown_variant)])).contains("malformed"));
    }

    fn web(path: &str, text: &str) -> McpSessionTranscript {
        let mut t = ssh("unused", "");
        t.summary.tool = "bv_resource_web_fetch".into();
        t.body = TranscriptBody::Web(WebTranscript {
            method: "GET".into(),
            path: path.into(),
            origin: "https://grafana.internal".into(),
            target: "10.0.0.9:443".into(),
            login: "http-auth".into(),
            tls: Some("platform".into()),
            hops: vec![
                WebTranscriptHop {
                    origin: "https://grafana.internal".into(),
                    path: path.into(),
                    status: Some(302),
                    answered_challenge: false,
                },
                WebTranscriptHop {
                    origin: "https://grafana.internal".into(),
                    path: "/login?next=hunter2".into(),
                    status: Some(200),
                    answered_challenge: true,
                },
            ],
            status: Some(200),
            content_type: Some("text/html".into()),
            body_bytes: text.len() as u64,
            text: TranscriptStream { text: text.into(), seen_bytes: text.len() as u64, ..Default::default() },
            ..Default::default()
        });
        t
    }

    /// A web record scrubs its path, every hop path and the page text, and
    /// reads back; out-of-bounds records are refused.
    #[test]
    fn a_web_record_is_scrubbed_bounded_and_reads_back() {
        let (id, entries) =
            encode(web("/api/health?token=hunter2", "Welcome hunter2\nDashboards"), 11, &Replace("hunter2")).unwrap();
        assert!(entries.iter().all(|e| !String::from_utf8_lossy(&e.value).contains("hunter2")));
        let back = round_trip(&entries, &id).unwrap();
        assert!(back.summary.credential_echo_redacted);
        let TranscriptBody::Web(body) = &back.body else { panic!("a web transcript") };
        assert_eq!(body.path, "/api/health?token=<redacted:credential>");
        assert_eq!(body.hops[1].path, "/login?next=<redacted:credential>");
        assert!(body.hops[1].answered_challenge);
        assert!(body.text.text.starts_with("Welcome <redacted:credential>"));
        assert_eq!(back.body.protocol(), "web");

        let long = format!("/{}", "a".repeat(MAX_TRANSCRIPT_WEB_PATH_BYTES));
        assert!(matches!(encode(web(&long, ""), 1, &NoCredential), Err(TranscriptError::Invalid(_))));
        let mut post = web("/", "");
        if let TranscriptBody::Web(w) = &mut post.body {
            w.method = "POST".into();
        }
        assert!(matches!(encode(post, 1, &NoCredential), Err(TranscriptError::Invalid(_))));
        let mut many = web("/", "");
        if let TranscriptBody::Web(w) = &mut many.body {
            w.hops = vec![WebTranscriptHop::default(); MAX_TRANSCRIPT_WEB_HOPS + 1];
        }
        assert!(matches!(encode(many, 1, &NoCredential), Err(TranscriptError::Invalid(_))));
    }
}
