//! `.rdp-rec` version-4 keystroke transcript reader — Phase 8.6 of
//! `features/rustion-integration.md`.
//!
//! Version 4 of Rustion's `.rdp-rec` container adds a searchable
//! keystroke track *inside the artifact BastionVault already pulls*.
//! There is no second file, no new endpoint and no new integrity
//! story: the recording sidecar's `sha256` already covers the whole
//! artifact, so the transcript inherits the existing chain of custody.
//! The authoritative specification is Rustion's
//! `docs/rdp-keystroke-metadata.md`.
//!
//! ## What this module reads
//!
//! Two record types, both additive — a version-3 consumer skips them
//! by `payload_len`, which is the container's forward-compatibility
//! contract:
//!
//! * `0x08` **text input**: `flags:u8`, `field_epoch:u32 LE`,
//!   `char_count:u16 LE`, `text_len:u16 LE`, `text` (UTF-8). The
//!   record's `timestamp_ms` is the run's **first** keystroke.
//! * `0x7F` **keystroke trailer**: the whole transcript as JSON,
//!   always the last record, ending in a self-locating 8-byte footer
//!   (`record_len:u32 LE` + `"RKTR"`).
//!
//! ## The fast path, and why it exists
//!
//! [`read_trailer`] reads the last 8 bytes, checks the magic, seeks
//! back `record_len` from EOF and parses exactly that one record. It
//! touches no graphics byte and its cost does not scale with the
//! artifact — [`Transcript::bytes_examined`] records what it actually
//! looked at so that property stays testable. **Do not scan the file
//! looking for the trailer**; that is the entire thing the footer is
//! there to avoid.
//!
//! [`read_transcript`] adds the degradation path: when the magic or
//! the JSON fails — a file truncated mid-trailer, or one whose
//! trailer was never written because the bastion crashed — it falls
//! back to [`scan_text_records`], which walks the `0x08` records and
//! yields every *completed* run. That is sound because a `0x08` is
//! only ever written after its run's redaction verdict, so everything
//! in a crashed file is already adjudicated; what is lost is the final
//! unclosed run, which is the safe direction to fail.
//!
//! ## Security rules this module enforces
//!
//! 1. **Redacted runs are never reconstructed.** A redacted run has
//!    no `0x02` scancode records and no per-key timestamps — the
//!    recorder drops both deliberately, because inter-keystroke
//!    timing is itself a password-recovery channel. Nothing here
//!    infers a redacted run's content from anything: not from
//!    neighbouring records, not from the framebuffer, not from its
//!    length. It is rendered as withheld, with its rule and its
//!    character count.
//! 2. **The indexable text is derived from `runs[]`, not trusted from
//!    `search_text`.** The producer's `search_text` is specified as
//!    the newline join of the *non-redacted* runs. We rebuild that
//!    join ourselves from the runs whose `redacted` flag is false, so
//!    a producer bug cannot put withheld text into a BastionVault
//!    index. When the two disagree we keep ours and record a warning
//!    — see [`Transcript::warnings`].
//! 3. **`text_applied` is not read.** The trailer carries a derived,
//!    lossy rendering with `[Backspace]`/`[Delete]` applied. It is
//!    explicitly not for indexing, so the server side does not
//!    deserialize it at all: the guarantee is structural rather than
//!    a rule someone has to remember. The GUI shows it as a labelled
//!    display-only pane from its own copy of the artifact.
//! 4. **No transcript text in logs or errors.** Every error and log
//!    line in this module carries offsets, lengths and counts only.
//!
//! ## Ordering
//!
//! From version 4 `timestamp_ms` is **not monotonic across records**:
//! `0x02` and `0x08` are buffered until their run closes, so they are
//! written after graphics records bearing later timestamps. The bound
//! is declared in the header as `max_reorder_ms`. Nothing in this
//! module assumes monotonicity, and the graphics path does not need
//! to change — `0x01`, `0x03`, `0x06` and `0x07` remain monotonic
//! among themselves.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// `event_type` of a version-4 text-input record.
pub const EVENT_TEXT_INPUT: u8 = 0x08;

/// `event_type` of the keystroke trailer.
pub const EVENT_KEYSTROKE_TRAILER: u8 = 0x7F;

/// Trailing magic of the trailer's self-locating footer.
pub const TRAILER_MAGIC: &[u8; 4] = b"RKTR";

/// `record_len:u32 LE` + `"RKTR"`.
pub const TRAILER_FOOTER_LEN: usize = 8;

/// `timestamp_ms:u64 LE` + `event_type:u8` + `payload_len:u32 LE`.
pub const RECORD_HEADER_LEN: usize = 13;

/// `0x08` fixed prefix: `flags:u8 field_epoch:u32 char_count:u16 text_len:u16`.
pub const TEXT_INPUT_PREFIX_LEN: usize = 9;

/// First container version that can carry a keystroke track.
pub const FIRST_KEYSTROKE_VERSION: u32 = 4;

// `0x08` `flags` bits.
pub const FLAG_REDACTED: u8 = 0x01;
pub const FLAG_COMPOSED: u8 = 0x02;
pub const FLAG_APPROXIMATE: u8 = 0x04;
pub const FLAG_RUN_END: u8 = 0x08;
pub const FLAG_TRUNCATED: u8 = 0x10;

/// Ceiling on the trailer record we are willing to parse. The footer's
/// `record_len` is attacker-influenced input (recording bytes come
/// from the bastion), and a JSON document this large is a malformed
/// file rather than a session transcript: 32 MiB of `search_text` is
/// roughly 32 million keystrokes.
pub const MAX_TRAILER_RECORD_BYTES: usize = 32 * 1024 * 1024;

/// Ceiling on how many `0x08` runs the fallback scan will accumulate.
/// Bounds the work and the allocation on a malformed artifact without
/// silently truncating a plausible one — the default per-run character
/// cap is 4096, so this is a multi-million-keystroke session.
pub const MAX_SCANNED_RUNS: usize = 200_000;

/// How the transcript was obtained. Surfaced to the operator, because
/// a scanned transcript is missing the session's final unclosed run
/// and carries no per-run durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranscriptSource {
    /// The `0x7F` trailer, located by the footer's tail-seek.
    TrailerFooter,
    /// Reconstructed by walking `0x08` records after the trailer
    /// could not be read.
    TextRecordScan,
}

impl TranscriptSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrailerFooter => "trailer-footer",
            Self::TextRecordScan => "text-record-scan",
        }
    }
}

/// Version-4 header fields. All additive; a version <= 3 header parses
/// to `keystroke_metadata: false`, which is exactly how those files
/// must read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystrokeHeader {
    /// Container `version`. `0` when the header carries no version.
    pub version: u32,
    /// Whether a keystroke track and trailer are present.
    ///
    /// **`false` does not mean nobody typed.** It means the feature
    /// was off on that bastion. A consumer must never render it as
    /// "no keyboard activity".
    pub keystroke_metadata: bool,
    /// Resolved Windows KLID as a hex string, or `None`.
    pub keyboard_layout: Option<String>,
    /// `client_core` | `config` | `fallback`.
    pub keyboard_layout_source: Option<String>,
    /// Bound on how far out of order a keystroke record may appear.
    /// `0` when `keystroke_metadata` is false.
    pub max_reorder_ms: u64,
}

/// One keystroke run.
///
/// `text` is `None` exactly when `redacted` is true — the recorder
/// withheld it and there is no path here that tries to recover it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// Elapsed ms of the run's first keystroke.
    #[serde(rename = "t")]
    pub t: u64,
    /// Run duration in ms. `0` on a scanned transcript, which has no
    /// duration to read.
    #[serde(rename = "d", default)]
    pub d: u64,
    /// Character count (Unicode scalar values). Retained for a
    /// redacted run: an auditor sees that N characters were withheld.
    #[serde(rename = "n", default)]
    pub n: u64,
    /// The typed text, with non-character keys as bracketed tokens
    /// (`[Enter]`, `[Ctrl+C]`, `[F5]`). `None` when redacted.
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub redacted: bool,
    /// `known_secret` | `masked_field` | `deny_pattern` |
    /// `credential_pair`. Present only on a redacted run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The `field_epoch` correlation **hint**. A pass-through RDP
    /// proxy has no access to the remote UI's focus, so this groups
    /// runs visually and must not be labelled "field" or relied on.
    #[serde(default)]
    pub epoch: u32,
    /// Run contains at least one dead-key composition.
    #[serde(default)]
    pub composed: bool,
    /// Decoded through a fallback keyboard layout — display as
    /// approximate.
    #[serde(default)]
    pub approximate: bool,
    /// Run hit the recorder's per-run character cap and was cut.
    #[serde(default)]
    pub truncated: bool,
}

/// The recorder's own account of what it dropped. Counts only; no
/// typed text ever appears here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Census {
    #[serde(default)]
    pub keys_total: u64,
    #[serde(default)]
    pub chars_decoded: u64,
    #[serde(default)]
    pub unicode_events: u64,
    #[serde(default)]
    pub named_keys: u64,
    #[serde(default)]
    pub composed: u64,
    #[serde(default)]
    pub undecodable_scancodes: u64,
    #[serde(default)]
    pub redacted_runs: u64,
    #[serde(default)]
    pub redacted_chars: u64,
    #[serde(default)]
    pub slowpath_input_pdus: u64,
    #[serde(default)]
    pub truncated_runs: u64,
}

/// The `0x7F` trailer's JSON payload, as the producer wrote it.
///
/// `text_applied` is deliberately **absent**: the trailer carries a
/// derived, lossy rendering with backspace applied, and it must not be
/// indexed. Not deserializing it makes that structural instead of a
/// convention (serde ignores unknown fields).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TrailerJson {
    #[serde(default)]
    pub trailer_version: u32,
    #[serde(default)]
    pub rebuilt: bool,
    #[serde(default)]
    pub keyboard_layout: Option<String>,
    #[serde(default)]
    pub keyboard_layout_source: Option<String>,
    /// `exact` | `approximate` | `none`. Anything other than `exact`
    /// must be surfaced in the UI.
    #[serde(default)]
    pub text_decoding: String,
    #[serde(default)]
    pub runs: Vec<Run>,
    /// The producer's own newline join of the non-redacted runs. Read
    /// for cross-checking only — [`Transcript::search_text`] is
    /// rebuilt from `runs[]`.
    #[serde(default)]
    pub search_text: String,
    #[serde(default)]
    pub census: Census,
}

/// A parsed keystroke transcript, ready to index or render.
#[derive(Debug, Clone, Serialize)]
pub struct Transcript {
    pub source: TranscriptSource,
    /// `true` only for a trailer that the live recorder wrote. False
    /// for a scanned fallback and for `rebuilt: true`, both of which
    /// are missing the session's final unclosed run and must not be
    /// presented as a complete transcript.
    pub complete: bool,
    pub trailer_version: u32,
    /// The trailer was reconstructed by the bastion after a crash
    /// rather than written live.
    pub rebuilt: bool,
    pub keyboard_layout: Option<String>,
    pub keyboard_layout_source: Option<String>,
    /// `exact` | `approximate` | `none` | `unknown` (a scanned
    /// transcript with no `APPROXIMATE` flag cannot tell which).
    pub text_decoding: String,
    pub runs: Vec<Run>,
    /// Newline join of every **non-redacted** run's text, rebuilt from
    /// `runs[]`. This is the only field a search index should hold; a
    /// substring hit against it can never be a hit on withheld text.
    pub search_text: String,
    pub census: Census,
    /// Non-redacted characters, i.e. what `search_text` covers.
    pub chars_indexed: u64,
    /// How many bytes of the artifact this parse actually looked at.
    /// The trailer fast path is bounded by the trailer's own size and
    /// does not scale with the artifact; the fallback scan does.
    pub bytes_examined: usize,
    /// Everything the operator should know that is not an outright
    /// failure: a `search_text` that disagreed with `runs[]`, a
    /// trailer version we do not know, a truncated tail.
    pub warnings: Vec<String>,
}

/// Why a trailer could not be read. Offsets and lengths only — never a
/// byte of transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrailerError {
    /// Shorter than the 8-byte footer.
    TooShort { len: usize },
    /// The last 4 bytes are not `RKTR`. The ordinary reading of this
    /// is "version <= 3, or `keystroke_metadata: false`" — not a
    /// corrupt file.
    NoMagic,
    /// `record_len` does not describe a record inside this file.
    BadRecordLen { record_len: usize, file_len: usize },
    /// The record `record_len` points at is not a `0x7F`.
    NotTrailerRecord { event_type: u8 },
    /// The record's `payload_len` disagrees with `record_len`.
    LengthMismatch { payload_len: usize, record_len: usize },
    /// The JSON is not UTF-8.
    NotUtf8,
    /// The JSON would not parse. Carries serde's message, which
    /// reports a line/column, not content.
    BadJson(String),
}

impl std::fmt::Display for TrailerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len } => write!(
                f,
                "artifact is {len} bytes, shorter than the {TRAILER_FOOTER_LEN}-byte keystroke-trailer footer"
            ),
            Self::NoMagic => write!(f, "no `RKTR` keystroke-trailer footer at end of file"),
            Self::BadRecordLen { record_len, file_len } => write!(
                f,
                "keystroke-trailer footer claims record_len={record_len}, which does not fit a {file_len}-byte artifact"
            ),
            Self::NotTrailerRecord { event_type } => write!(
                f,
                "record at EOF-record_len has event_type 0x{event_type:02x}, expected 0x{EVENT_KEYSTROKE_TRAILER:02x}"
            ),
            Self::LengthMismatch { payload_len, record_len } => write!(
                f,
                "keystroke trailer payload_len={payload_len} disagrees with footer record_len={record_len}"
            ),
            Self::NotUtf8 => write!(f, "keystroke trailer JSON is not valid UTF-8"),
            Self::BadJson(e) => write!(f, "keystroke trailer JSON did not parse: {e}"),
        }
    }
}

// ─── Header ─────────────────────────────────────────────────────────

/// Read the version-4 keystroke fields off a `.rdp-rec` JSON header.
///
/// A missing `keystroke_metadata` reads as `false`, which is how every
/// version <= 3 header reads — that is the whole compatibility story
/// and it needs no version gate to work.
pub fn parse_keystroke_header(header_json: &str) -> KeystrokeHeader {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(header_json) else {
        return KeystrokeHeader::default();
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => return KeystrokeHeader::default(),
    };
    KeystrokeHeader {
        version: obj.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        keystroke_metadata: obj
            .get("keystroke_metadata")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        keyboard_layout: obj
            .get("keyboard_layout")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        keyboard_layout_source: obj
            .get("keyboard_layout_source")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        max_reorder_ms: obj
            .get("max_reorder_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    }
}

/// Split a `.rdp-rec` into its JSON header line and the offset of the
/// first event record. Mirrors the graphics decoder's `parseHeader`.
pub fn header_and_start(bytes: &[u8]) -> Option<(&str, usize)> {
    if bytes.len() < 4 || &bytes[..4] != b"RREC" {
        return None;
    }
    let nl = bytes[4..].iter().position(|b| *b == b'\n')? + 4;
    let header = std::str::from_utf8(&bytes[4..nl]).ok()?;
    Some((header, nl + 1))
}

// ─── The trailer fast path ──────────────────────────────────────────

/// Locate and parse the `0x7F` trailer by seeking from EOF.
///
/// Reads the last 8 bytes, checks the magic, seeks back `record_len`
/// and parses that one record. **The cost is the trailer's size, not
/// the artifact's** — see [`Transcript::bytes_examined`].
pub fn read_trailer(bytes: &[u8]) -> Result<Transcript, TrailerError> {
    let file_len = bytes.len();
    if file_len < TRAILER_FOOTER_LEN {
        return Err(TrailerError::TooShort { len: file_len });
    }
    let footer = &bytes[file_len - TRAILER_FOOTER_LEN..];
    if &footer[4..8] != TRAILER_MAGIC {
        return Err(TrailerError::NoMagic);
    }
    let record_len = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]) as usize;

    // A trailer record is at minimum its 13-byte header plus a payload
    // big enough to hold the 8-byte footer it ends with.
    let min = RECORD_HEADER_LEN + TRAILER_FOOTER_LEN;
    if record_len < min || record_len > file_len || record_len > MAX_TRAILER_RECORD_BYTES {
        return Err(TrailerError::BadRecordLen { record_len, file_len });
    }
    let start = file_len - record_len;
    let event_type = bytes[start + 8];
    if event_type != EVENT_KEYSTROKE_TRAILER {
        return Err(TrailerError::NotTrailerRecord { event_type });
    }
    let payload_len = u32::from_le_bytes([
        bytes[start + 9],
        bytes[start + 10],
        bytes[start + 11],
        bytes[start + 12],
    ]) as usize;
    if payload_len != record_len - RECORD_HEADER_LEN {
        return Err(TrailerError::LengthMismatch { payload_len, record_len });
    }
    let json_len = payload_len - TRAILER_FOOTER_LEN;
    let json_bytes = &bytes[start + RECORD_HEADER_LEN..start + RECORD_HEADER_LEN + json_len];
    let json = std::str::from_utf8(json_bytes).map_err(|_| TrailerError::NotUtf8)?;
    let parsed: TrailerJson =
        serde_json::from_str(json).map_err(|e| TrailerError::BadJson(e.to_string()))?;

    Ok(transcript_from_trailer(parsed, TRAILER_FOOTER_LEN + record_len))
}

fn transcript_from_trailer(t: TrailerJson, bytes_examined: usize) -> Transcript {
    let mut warnings = Vec::new();
    if t.trailer_version != 1 {
        warnings.push(format!(
            "trailer_version {} is not the version 1 this reader was written against; \
             unknown fields were ignored",
            t.trailer_version
        ));
    }
    if t.rebuilt {
        warnings.push(
            "the bastion rebuilt this trailer after a crash rather than writing it live — \
             the session's final unclosed run is missing"
                .to_string(),
        );
    }
    if t.text_decoding != "exact" {
        warnings.push(format!(
            "text_decoding is `{}`, not `exact` — the transcript was not decoded through a \
             layout table matching the session's own keyboard layout",
            if t.text_decoding.is_empty() {
                "unset"
            } else {
                t.text_decoding.as_str()
            }
        ));
    }

    // Rule 2 in this module's header: the indexable text is *ours*,
    // rebuilt from the runs whose `redacted` flag is false, never the
    // producer's `search_text` taken on trust.
    let (search_text, chars_indexed) = derive_search_text(&t.runs);
    if t.search_text != search_text {
        warnings.push(format!(
            "the trailer's own search_text ({} bytes) differs from the newline join of its \
             non-redacted runs ({} bytes); indexing the join",
            t.search_text.len(),
            search_text.len()
        ));
    }

    Transcript {
        source: TranscriptSource::TrailerFooter,
        complete: !t.rebuilt,
        trailer_version: t.trailer_version,
        rebuilt: t.rebuilt,
        keyboard_layout: t.keyboard_layout,
        keyboard_layout_source: t.keyboard_layout_source,
        text_decoding: t.text_decoding,
        runs: t.runs,
        search_text,
        census: t.census,
        chars_indexed,
        bytes_examined,
        warnings,
    }
}

/// Newline-join every non-redacted run's text.
///
/// A redacted run contributes **nothing** — not even a placeholder —
/// so a substring hit against the result is never a hit on withheld
/// text. A run flagged `redacted` whose `text` is nevertheless
/// populated (a producer bug) is dropped, not indexed.
fn derive_search_text(runs: &[Run]) -> (String, u64) {
    let mut parts: Vec<&str> = Vec::new();
    let mut chars = 0u64;
    for r in runs {
        if r.redacted {
            continue;
        }
        if let Some(text) = r.text.as_deref() {
            parts.push(text);
            chars += text.chars().count() as u64;
        }
    }
    (parts.join("\n"), chars)
}

// ─── The degradation path ───────────────────────────────────────────

/// Walk the `0x08` records and rebuild whatever runs completed.
///
/// Used when the trailer is unreadable — a file truncated mid-trailer,
/// or one whose bastion died before writing it. Sound because a `0x08`
/// is only written after its run's redaction verdict, so every run
/// found here is already adjudicated. What is lost is the final
/// unclosed run and the per-run durations, which is why the result is
/// marked `complete: false`.
///
/// Unknown `event_type` values are skipped by `payload_len`, exactly
/// as the graphics path does.
pub fn scan_text_records(bytes: &[u8]) -> Transcript {
    let mut runs: Vec<Run> = Vec::new();
    let mut census = Census::default();
    let mut warnings = Vec::new();
    let mut any_approximate = false;
    let mut trailer_seen = false;

    let Some((_header, start)) = header_and_start(bytes) else {
        return Transcript {
            source: TranscriptSource::TextRecordScan,
            complete: false,
            trailer_version: 0,
            rebuilt: false,
            keyboard_layout: None,
            keyboard_layout_source: None,
            text_decoding: "unknown".into(),
            runs,
            search_text: String::new(),
            census,
            chars_indexed: 0,
            bytes_examined: bytes.len(),
            warnings: vec!["artifact has no readable `RREC` header".into()],
        };
    };

    // The run currently being accumulated across fragments. A run may
    // span several `0x08` records; only the one with `RUN_END` closes
    // it. An unterminated tail is dropped rather than guessed at.
    let mut open: Option<Run> = None;
    let mut pos = start;
    let mut hit_cap = false;

    while pos + RECORD_HEADER_LEN <= bytes.len() {
        let ts = u64::from_le_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let kind = bytes[pos + 8];
        let len = u32::from_le_bytes([
            bytes[pos + 9],
            bytes[pos + 10],
            bytes[pos + 11],
            bytes[pos + 12],
        ]) as usize;
        let data_start = pos + RECORD_HEADER_LEN;
        let Some(next) = data_start.checked_add(len) else {
            break;
        };
        if next > bytes.len() {
            warnings.push(format!(
                "artifact ends mid-record: {} trailing bytes do not form a complete record",
                bytes.len() - pos
            ));
            break;
        }
        if kind == EVENT_KEYSTROKE_TRAILER {
            trailer_seen = true;
        }
        if kind == EVENT_TEXT_INPUT {
            match parse_text_input(ts, &bytes[data_start..next]) {
                Some(frag) => {
                    if frag.approximate {
                        any_approximate = true;
                    }
                    let closed = frag.run_end;
                    let acc = open.get_or_insert_with(|| Run {
                        t: frag.timestamp_ms,
                        ..Run::default()
                    });
                    merge_fragment(acc, frag);
                    if closed {
                        if runs.len() >= MAX_SCANNED_RUNS {
                            hit_cap = true;
                            open = None;
                            break;
                        }
                        let run = open.take().unwrap_or_default();
                        if run.redacted {
                            census.redacted_runs += 1;
                            census.redacted_chars += run.n;
                        }
                        if run.composed {
                            census.composed += 1;
                        }
                        if run.truncated {
                            census.truncated_runs += 1;
                        }
                        if !run.redacted {
                            census.chars_decoded += run.n;
                        }
                        runs.push(run);
                    }
                }
                None => {
                    warnings.push(format!(
                        "skipped a malformed 0x08 text-input record ({len} payload bytes)"
                    ));
                }
            }
        }
        pos = next;
    }

    if open.is_some() {
        warnings.push(
            "the artifact's final keystroke run was never closed by a RUN_END record and was \
             dropped — an un-adjudicated run is not written out"
                .to_string(),
        );
    }
    if hit_cap {
        warnings.push(format!(
            "stopped after {MAX_SCANNED_RUNS} runs; the artifact declares more than this reader \
             will accumulate"
        ));
    }
    warnings.push(if trailer_seen {
        "the keystroke trailer could not be read, so this transcript was rebuilt by scanning \
         the 0x08 text-input records. It is missing per-run durations and any run the recorder \
         had not closed."
            .to_string()
    } else {
        "this artifact carries no keystroke trailer, so the transcript was rebuilt by scanning \
         the 0x08 text-input records. It is missing per-run durations and any run the recorder \
         had not closed."
            .to_string()
    });

    let (search_text, chars_indexed) = derive_search_text(&runs);
    Transcript {
        source: TranscriptSource::TextRecordScan,
        complete: false,
        trailer_version: 0,
        rebuilt: false,
        keyboard_layout: None,
        keyboard_layout_source: None,
        // A scan can prove "approximate" from a flag but can never
        // prove "exact" — the layout match is a fact only the trailer
        // carries. Say `unknown` rather than claim exactness.
        text_decoding: if any_approximate {
            "approximate".into()
        } else {
            "unknown".into()
        },
        runs,
        search_text,
        census,
        chars_indexed,
        bytes_examined: bytes.len(),
        warnings,
    }
}

struct TextInputFragment {
    timestamp_ms: u64,
    redacted: bool,
    composed: bool,
    approximate: bool,
    run_end: bool,
    truncated: bool,
    epoch: u32,
    char_count: u64,
    text: Option<String>,
}

/// Decode one `0x08` payload. `None` when the payload is too short for
/// its own declared fields — skipped and counted, never guessed at.
fn parse_text_input(timestamp_ms: u64, payload: &[u8]) -> Option<TextInputFragment> {
    if payload.len() < TEXT_INPUT_PREFIX_LEN {
        return None;
    }
    let flags = payload[0];
    let epoch = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let char_count = u16::from_le_bytes([payload[5], payload[6]]) as u64;
    let text_len = u16::from_le_bytes([payload[7], payload[8]]) as usize;
    if payload.len() < TEXT_INPUT_PREFIX_LEN + text_len {
        return None;
    }
    let redacted = flags & FLAG_REDACTED != 0;
    // A redacted record carries `text_len == 0` by specification. If a
    // producer bug puts bytes there anyway we drop them: this reader
    // does not surface text from a run the recorder said to withhold.
    let text = if redacted {
        None
    } else {
        Some(
            String::from_utf8_lossy(
                &payload[TEXT_INPUT_PREFIX_LEN..TEXT_INPUT_PREFIX_LEN + text_len],
            )
            .into_owned(),
        )
    };
    Some(TextInputFragment {
        timestamp_ms,
        redacted,
        composed: flags & FLAG_COMPOSED != 0,
        approximate: flags & FLAG_APPROXIMATE != 0,
        run_end: flags & FLAG_RUN_END != 0,
        truncated: flags & FLAG_TRUNCATED != 0,
        epoch,
        char_count,
        text,
    })
}

fn merge_fragment(acc: &mut Run, frag: TextInputFragment) {
    acc.n += frag.char_count;
    acc.epoch = frag.epoch;
    acc.composed |= frag.composed;
    acc.approximate |= frag.approximate;
    acc.truncated |= frag.truncated;
    if frag.redacted {
        // Redaction is a property of the whole run: once any fragment
        // says withheld, the run is withheld and whatever text earlier
        // fragments carried is discarded rather than half-published.
        acc.redacted = true;
        acc.text = None;
        if acc.reason.is_none() {
            // `0x08` carries no reason; the trailer does. Name the
            // gap instead of inventing a rule.
            acc.reason = Some("unknown".into());
        }
        return;
    }
    if acc.redacted {
        return;
    }
    if let Some(text) = frag.text {
        match acc.text.as_mut() {
            Some(existing) => existing.push_str(&text),
            None => acc.text = Some(text),
        }
    }
}

// ─── The path callers should use ────────────────────────────────────

/// Read a `.rdp-rec`'s keystroke transcript: trailer fast path, then
/// the `0x08` scan when the trailer cannot be read.
///
/// `Ok(None)` means the artifact genuinely carries no keystroke track
/// — a version <= 3 file, or a version-4 file recorded with
/// `keystroke_metadata: false`. That is a real state and the caller
/// must render it as "keystroke recording was not enabled for this
/// session", never as an empty transcript.
pub fn read_transcript(bytes: &[u8]) -> Result<Option<Transcript>, String> {
    let header = header_and_start(bytes)
        .map(|(h, _)| parse_keystroke_header(h))
        .unwrap_or_default();

    match read_trailer(bytes) {
        Ok(t) => Ok(Some(t)),
        Err(TrailerError::NoMagic) => {
            // No footer. Either there was never a keystroke track, or
            // the tail was lost. The header settles which.
            if !header.keystroke_metadata {
                return Ok(None);
            }
            Ok(Some(scan_text_records(bytes)))
        }
        Err(e) => {
            // A footer that is present but unusable is a damaged tail,
            // not an absent feature: fall back and say why.
            let mut t = scan_text_records(bytes);
            t.warnings.insert(0, e.to_string());
            Ok(Some(t))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixture builders ───────────────────────────────────────────

    fn record(ts: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ts.to_le_bytes());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn text_input(ts: u64, flags: u8, epoch: u32, char_count: u16, text: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(flags);
        p.extend_from_slice(&epoch.to_le_bytes());
        p.extend_from_slice(&char_count.to_le_bytes());
        p.extend_from_slice(&(text.len() as u16).to_le_bytes());
        p.extend_from_slice(text.as_bytes());
        record(ts, EVENT_TEXT_INPUT, &p)
    }

    /// Build a `0x7F` record with the self-locating footer, exactly as
    /// §5.3 of the spec lays it out.
    fn trailer_record(ts: u64, json: &str) -> Vec<u8> {
        let payload_len = json.len() + TRAILER_FOOTER_LEN;
        let record_len = RECORD_HEADER_LEN + payload_len;
        let mut out = Vec::new();
        out.extend_from_slice(&ts.to_le_bytes());
        out.push(EVENT_KEYSTROKE_TRAILER);
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
        out.extend_from_slice(json.as_bytes());
        out.extend_from_slice(&(record_len as u32).to_le_bytes());
        out.extend_from_slice(TRAILER_MAGIC);
        assert_eq!(out.len(), record_len);
        out
    }

    fn file(header: &str, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::from(*b"RREC");
        out.extend_from_slice(header.as_bytes());
        out.push(b'\n');
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    const V4_HEADER: &str = r#"{"version":4,"screen_width":1920,"screen_height":1080,"keystroke_metadata":true,"keyboard_layout":"0x00000416","keyboard_layout_source":"client_core","max_reorder_ms":2000}"#;

    const TRAILER_JSON: &str = r#"{"trailer_version":1,"rebuilt":false,"keyboard_layout":"0x00000416","keyboard_layout_source":"client_core","text_decoding":"exact","runs":[{"t":4120,"d":2310,"n":11,"text":"notepad.exe[Enter]","redacted":false,"epoch":3},{"t":20100,"d":1490,"n":14,"text":null,"redacted":true,"reason":"known_secret","epoch":4}],"search_text":"notepad.exe[Enter]","text_applied":"notepad.exe\n","census":{"keys_total":412,"chars_decoded":388,"unicode_events":3,"named_keys":21,"composed":4,"undecodable_scancodes":0,"redacted_runs":1,"redacted_chars":14,"slowpath_input_pdus":0,"truncated_runs":0}}"#;

    // ── Header ─────────────────────────────────────────────────────

    #[test]
    fn v4_header_fields_are_read() {
        let h = parse_keystroke_header(V4_HEADER);
        assert_eq!(h.version, 4);
        assert!(h.keystroke_metadata);
        assert_eq!(h.keyboard_layout.as_deref(), Some("0x00000416"));
        assert_eq!(h.keyboard_layout_source.as_deref(), Some("client_core"));
        assert_eq!(h.max_reorder_ms, 2000);
    }

    #[test]
    fn a_v3_header_reads_as_keystroke_metadata_false() {
        // The compatibility contract: version <= 3 has no
        // `keystroke_metadata` key, and absent must read as `false`.
        let h = parse_keystroke_header(r#"{"version":3,"screen_width":1920,"screen_height":1080}"#);
        assert_eq!(h.version, 3);
        assert!(!h.keystroke_metadata);
        assert_eq!(h.max_reorder_ms, 0);
        assert!(h.keyboard_layout.is_none());
    }

    #[test]
    fn a_malformed_header_reads_as_no_keystrokes() {
        let h = parse_keystroke_header("not json at all");
        assert_eq!(h, KeystrokeHeader::default());
        assert!(!h.keystroke_metadata);
    }

    #[test]
    fn keystroke_metadata_false_at_version_4_is_not_an_empty_transcript() {
        let bytes = file(
            r#"{"version":4,"keystroke_metadata":false,"max_reorder_ms":0}"#,
            &[record(10, 0x01, b"graphics")],
        );
        // `Ok(None)` is the "recording was not enabled" state, which a
        // caller must render differently from "nobody typed".
        assert!(read_transcript(&bytes).unwrap().is_none());
    }

    // ── Trailer fast path ──────────────────────────────────────────

    #[test]
    fn trailer_is_located_by_tail_seek() {
        let bytes = file(V4_HEADER, &[trailer_record(30_000, TRAILER_JSON)]);
        let t = read_trailer(&bytes).expect("trailer parses");
        assert_eq!(t.source, TranscriptSource::TrailerFooter);
        assert_eq!(t.trailer_version, 1);
        assert!(!t.rebuilt);
        assert!(t.complete);
        assert_eq!(t.text_decoding, "exact");
        assert_eq!(t.runs.len(), 2);
        assert_eq!(t.census.keys_total, 412);
        assert_eq!(t.census.redacted_chars, 14);
    }

    #[test]
    fn tail_seek_read_size_does_not_scale_with_the_artifact() {
        // The acceptance criterion for the fast path: growing the
        // graphics ahead of the trailer must not grow what a trailer
        // read looks at.
        let small = file(
            V4_HEADER,
            &[
                record(1, 0x07, &vec![0u8; 1024]),
                trailer_record(30_000, TRAILER_JSON),
            ],
        );
        let large = file(
            V4_HEADER,
            &[
                record(1, 0x07, &vec![0u8; 4 * 1024 * 1024]),
                trailer_record(30_000, TRAILER_JSON),
            ],
        );
        let a = read_trailer(&small).unwrap();
        let b = read_trailer(&large).unwrap();
        assert_eq!(a.bytes_examined, b.bytes_examined);
        // And it is bounded by the trailer, not the file: the large
        // artifact is >4 MiB, the read is a few hundred bytes.
        assert!(
            b.bytes_examined < 2048,
            "examined {} bytes",
            b.bytes_examined
        );
        assert!(large.len() > 4 * 1024 * 1024);
    }

    #[test]
    fn a_redacted_run_keeps_its_reason_and_count_and_no_text() {
        let bytes = file(V4_HEADER, &[trailer_record(30_000, TRAILER_JSON)]);
        let t = read_trailer(&bytes).unwrap();
        let r = &t.runs[1];
        assert!(r.redacted);
        assert_eq!(r.text, None);
        assert_eq!(r.reason.as_deref(), Some("known_secret"));
        assert_eq!(r.n, 14);
        assert_eq!(r.t, 20100);
    }

    #[test]
    fn search_text_is_rebuilt_from_non_redacted_runs_only() {
        let bytes = file(V4_HEADER, &[trailer_record(30_000, TRAILER_JSON)]);
        let t = read_trailer(&bytes).unwrap();
        assert_eq!(t.search_text, "notepad.exe[Enter]");
        assert_eq!(t.chars_indexed, "notepad.exe[Enter]".chars().count() as u64);
        assert!(t.warnings.is_empty(), "warnings: {:?}", t.warnings);
    }

    #[test]
    fn a_producer_search_text_carrying_redacted_content_is_not_indexed() {
        // The defence for rule 2: a producer bug that leaks a withheld
        // run into `search_text` must not reach a BastionVault index.
        let json = r#"{"trailer_version":1,"text_decoding":"exact","runs":[{"t":10,"d":5,"n":4,"text":"ls -l","redacted":false,"epoch":1},{"t":50,"d":9,"n":8,"text":null,"redacted":true,"reason":"known_secret","epoch":2}],"search_text":"ls -l\nhunter22","census":{}}"#;
        let bytes = file(V4_HEADER, &[trailer_record(9, json)]);
        let t = read_trailer(&bytes).unwrap();
        assert_eq!(t.search_text, "ls -l");
        assert!(!t.search_text.contains("hunter22"));
        assert!(
            t.warnings.iter().any(|w| w.contains("differs from")),
            "warnings: {:?}",
            t.warnings
        );
    }

    #[test]
    fn a_redacted_run_with_text_anyway_is_dropped_from_the_index() {
        let json = r#"{"trailer_version":1,"text_decoding":"exact","runs":[{"t":50,"d":9,"n":8,"text":"hunter22","redacted":true,"reason":"known_secret","epoch":2}],"search_text":"","census":{}}"#;
        let bytes = file(V4_HEADER, &[trailer_record(9, json)]);
        let t = read_trailer(&bytes).unwrap();
        assert_eq!(t.search_text, "");
        assert_eq!(t.chars_indexed, 0);
    }

    #[test]
    fn rebuilt_and_inexact_decoding_each_produce_a_warning() {
        let json = r#"{"trailer_version":1,"rebuilt":true,"text_decoding":"approximate","runs":[],"search_text":"","census":{}}"#;
        let bytes = file(V4_HEADER, &[trailer_record(9, json)]);
        let t = read_trailer(&bytes).unwrap();
        assert!(t.rebuilt);
        assert!(!t.complete);
        assert!(t.warnings.iter().any(|w| w.contains("rebuilt")));
        assert!(t.warnings.iter().any(|w| w.contains("approximate")));
    }

    #[test]
    fn an_unknown_trailer_version_warns_but_still_parses() {
        let json = r#"{"trailer_version":7,"text_decoding":"exact","runs":[{"t":1,"d":1,"n":1,"text":"a","redacted":false,"epoch":0}],"search_text":"a","census":{}}"#;
        let bytes = file(V4_HEADER, &[trailer_record(9, json)]);
        let t = read_trailer(&bytes).unwrap();
        assert_eq!(t.search_text, "a");
        assert!(t.warnings.iter().any(|w| w.contains("trailer_version 7")));
    }

    // ── Trailer rejections ─────────────────────────────────────────

    #[test]
    fn a_v3_file_has_no_trailer_magic() {
        let bytes = file(
            r#"{"version":3,"screen_width":800,"screen_height":600}"#,
            &[record(1, 0x01, b"bitmap"), record(2, 0x02, b"\x1e\x01")],
        );
        assert!(matches!(read_trailer(&bytes), Err(TrailerError::NoMagic)));
        assert!(read_transcript(&bytes).unwrap().is_none());
    }

    #[test]
    fn a_record_len_past_the_file_is_rejected() {
        let mut bytes = file(V4_HEADER, &[trailer_record(9, TRAILER_JSON)]);
        let n = bytes.len();
        bytes[n - 8..n - 4].copy_from_slice(&(u32::MAX).to_le_bytes());
        match read_trailer(&bytes) {
            Err(TrailerError::BadRecordLen { record_len, .. }) => {
                assert_eq!(record_len, u32::MAX as usize)
            }
            other => panic!("expected BadRecordLen, got {other:?}"),
        }
    }

    #[test]
    fn a_record_len_pointing_at_a_non_trailer_record_is_rejected() {
        // Point `record_len` at the graphics record instead.
        let graphics = record(1, 0x01, &vec![7u8; 64]);
        let trailer = trailer_record(9, TRAILER_JSON);
        let mut bytes = file(V4_HEADER, &[graphics.clone(), trailer.clone()]);
        let n = bytes.len();
        let bogus = (trailer.len() + graphics.len()) as u32;
        bytes[n - 8..n - 4].copy_from_slice(&bogus.to_le_bytes());
        match read_trailer(&bytes) {
            Err(TrailerError::NotTrailerRecord { event_type }) => assert_eq!(event_type, 0x01),
            other => panic!("expected NotTrailerRecord, got {other:?}"),
        }
    }

    #[test]
    fn an_absurd_record_len_is_capped_before_any_allocation() {
        let mut bytes = vec![0u8; MAX_TRAILER_RECORD_BYTES + 64];
        let n = bytes.len();
        bytes[n - 8..n - 4]
            .copy_from_slice(&((MAX_TRAILER_RECORD_BYTES + 32) as u32).to_le_bytes());
        bytes[n - 4..].copy_from_slice(TRAILER_MAGIC);
        assert!(matches!(
            read_trailer(&bytes),
            Err(TrailerError::BadRecordLen { .. })
        ));
    }

    #[test]
    fn a_short_artifact_is_rejected_without_indexing_past_the_end() {
        assert!(matches!(
            read_trailer(b"RREC"),
            Err(TrailerError::TooShort { len: 4 })
        ));
    }

    #[test]
    fn broken_trailer_json_is_reported_without_content() {
        let bytes = file(V4_HEADER, &[trailer_record(9, "{\"runs\": [ oops")]);
        match read_trailer(&bytes) {
            Err(TrailerError::BadJson(msg)) => {
                assert!(!msg.contains("oops"), "error leaked content: {msg}")
            }
            other => panic!("expected BadJson, got {other:?}"),
        }
    }

    // ── The `0x08` scan fallback ───────────────────────────────────

    #[test]
    fn a_file_truncated_mid_trailer_falls_back_and_yields_every_completed_run() {
        let full = file(
            V4_HEADER,
            &[
                text_input(4120, FLAG_RUN_END, 3, 11, "notepad.exe[Enter]"),
                text_input(20100, FLAG_REDACTED | FLAG_RUN_END, 4, 14, ""),
                text_input(31000, FLAG_RUN_END, 5, 5, "dir[Enter]"),
                trailer_record(40_000, TRAILER_JSON),
            ],
        );
        // Cut the file inside the trailer's JSON, losing the footer.
        let truncated = &full[..full.len() - 40];
        let t = read_transcript(truncated).unwrap().expect("a transcript");
        assert_eq!(t.source, TranscriptSource::TextRecordScan);
        assert!(!t.complete);
        assert_eq!(t.runs.len(), 3);
        assert_eq!(t.runs[0].text.as_deref(), Some("notepad.exe[Enter]"));
        assert!(t.runs[1].redacted);
        assert_eq!(t.runs[1].text, None);
        assert_eq!(t.runs[1].n, 14);
        assert_eq!(t.runs[2].text.as_deref(), Some("dir[Enter]"));
        assert_eq!(t.search_text, "notepad.exe[Enter]\ndir[Enter]");
        assert!(!t.search_text.contains("hunter"));
    }

    #[test]
    fn a_scan_concatenates_fragments_until_run_end() {
        let bytes = file(
            V4_HEADER,
            &[
                text_input(1000, 0, 1, 3, "net"),
                text_input(1100, 0, 1, 5, " user"),
                text_input(1200, FLAG_RUN_END | FLAG_COMPOSED, 1, 5, " /add"),
            ],
        );
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 1);
        assert_eq!(t.runs[0].text.as_deref(), Some("net user /add"));
        // The run's timestamp is its *first* keystroke, not its last.
        assert_eq!(t.runs[0].t, 1000);
        assert_eq!(t.runs[0].n, 13);
        assert!(t.runs[0].composed);
    }

    #[test]
    fn a_scan_drops_the_final_unclosed_run() {
        let bytes = file(
            V4_HEADER,
            &[
                text_input(10, FLAG_RUN_END, 1, 2, "ok"),
                text_input(20, 0, 2, 6, "unterm"),
            ],
        );
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 1);
        assert_eq!(t.search_text, "ok");
        assert!(t.warnings.iter().any(|w| w.contains("never closed")));
    }

    #[test]
    fn a_redacted_fragment_poisons_the_whole_run() {
        // A run whose verdict lands on a later fragment must not
        // publish the text its earlier fragments carried.
        let bytes = file(
            V4_HEADER,
            &[
                text_input(10, 0, 1, 4, "pass"),
                text_input(20, FLAG_REDACTED | FLAG_RUN_END, 1, 4, ""),
            ],
        );
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 1);
        assert!(t.runs[0].redacted);
        assert_eq!(t.runs[0].text, None);
        assert_eq!(t.search_text, "");
        assert_eq!(t.runs[0].n, 8);
    }

    #[test]
    fn a_scan_marks_approximate_but_never_claims_exact() {
        let approx = file(
            V4_HEADER,
            &[text_input(10, FLAG_RUN_END | FLAG_APPROXIMATE, 1, 2, "ab")],
        );
        assert_eq!(scan_text_records(&approx).text_decoding, "approximate");
        let plain = file(V4_HEADER, &[text_input(10, FLAG_RUN_END, 1, 2, "ab")]);
        assert_eq!(scan_text_records(&plain).text_decoding, "unknown");
    }

    #[test]
    fn a_malformed_text_record_is_skipped_not_fatal() {
        let mut short = record(10, EVENT_TEXT_INPUT, b"\x08\x00\x00");
        short.extend_from_slice(&text_input(20, FLAG_RUN_END, 1, 2, "ok"));
        let bytes = file(V4_HEADER, &[short]);
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 1);
        assert!(t.warnings.iter().any(|w| w.contains("malformed 0x08")));
    }

    #[test]
    fn unknown_event_types_are_skipped_by_payload_len_during_a_scan() {
        let bytes = file(
            V4_HEADER,
            &[
                record(1, 0x5A, &vec![0xAA; 300]),
                text_input(10, FLAG_RUN_END, 1, 2, "ok"),
                record(11, 0x5B, &vec![0xBB; 7]),
            ],
        );
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 1);
        assert_eq!(t.search_text, "ok");
    }

    #[test]
    fn a_scan_survives_non_monotonic_timestamps() {
        // Version 4's one behavioural break: a keystroke record is
        // written after graphics bearing a later timestamp.
        let bytes = file(
            V4_HEADER,
            &[
                record(9_000, 0x07, &vec![0u8; 16]),
                text_input(1_000, FLAG_RUN_END, 1, 2, "hi"),
                record(9_500, 0x07, &vec![0u8; 16]),
                text_input(4_000, FLAG_RUN_END, 2, 2, "yo"),
            ],
        );
        let t = scan_text_records(&bytes);
        assert_eq!(t.runs.len(), 2);
        assert_eq!(t.runs[0].t, 1_000);
        assert_eq!(t.runs[1].t, 4_000);
    }

    #[test]
    fn a_v4_file_with_a_trailer_prefers_the_trailer_over_the_scan() {
        let bytes = file(
            V4_HEADER,
            &[
                text_input(4120, FLAG_RUN_END, 3, 11, "notepad.exe[Enter]"),
                trailer_record(40_000, TRAILER_JSON),
            ],
        );
        let t = read_transcript(&bytes).unwrap().unwrap();
        assert_eq!(t.source, TranscriptSource::TrailerFooter);
        // The trailer carries durations; a scan cannot.
        assert_eq!(t.runs[0].d, 2310);
    }

    #[test]
    fn a_v4_file_whose_trailer_was_never_written_falls_back() {
        let bytes = file(
            V4_HEADER,
            &[text_input(4120, FLAG_RUN_END, 3, 11, "notepad.exe[Enter]")],
        );
        let t = read_transcript(&bytes).unwrap().unwrap();
        assert_eq!(t.source, TranscriptSource::TextRecordScan);
        assert_eq!(t.search_text, "notepad.exe[Enter]");
        assert!(t.warnings.iter().any(|w| w.contains("no keystroke trailer")));
    }

    #[test]
    fn header_and_start_rejects_a_foreign_magic() {
        assert!(header_and_start(b"XXXX{}\n").is_none());
        assert!(header_and_start(b"RREC{}").is_none(), "no newline");
        let (h, start) = header_and_start(b"RREC{\"version\":4}\nrest").unwrap();
        assert_eq!(h, "{\"version\":4}");
        assert_eq!(start, 4 + 13 + 1);
    }
}
