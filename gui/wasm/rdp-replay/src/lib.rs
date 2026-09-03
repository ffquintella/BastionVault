//! Decoder for Rustion `.rdp-rec` session recordings.
//!
//! Canonical, unit-tested reference implementation. The GUI runs the
//! 1:1 TypeScript port in `gui/src/lib/rdpDecoder.ts` so it needs no
//! wasm-bindgen build step; if you change one, change the other. The
//! tests here are the spec.
//!
//! ## File layout (all versions)
//!
//! ```text
//! [4]   magic "RREC"
//! [..]  JSON header, one line
//! [1]   '\n'
//! [..]  event records until EOF
//! ```
//!
//! Every event record:
//!
//! ```text
//! [u64 LE] timestamp_ms   elapsed ms since session start
//! [u8]     event_type
//! [u32 LE] payload_len
//! [..]     payload
//! ```
//!
//! Records tile the file exactly. Unknown `event_type` values are
//! skipped using `payload_len` — that is the format's forward
//! compatibility contract, and version 3 relies on it.
//!
//! ## Event types
//!
//! | type   | meaning                        |
//! |--------|--------------------------------|
//! | `0x01` | graphics update (wire bitmap)  |
//! | `0x02` | keyboard                       |
//! | `0x03` | mouse                          |
//! | `0x04` | window title (reserved)        |
//! | `0x05` | clipboard text (reserved)      |
//! | `0x06` | desktop size                   |
//! | `0x07` | surface update (decoded pixels)|
//! | `0x08` | keystroke run text (version 4) |
//! | `0x7F` | keystroke trailer (version 4)  |
//!
//! ## Version dispatch
//!
//! | version | geometry                      | `0x01`                     | `0x07` |
//! |---------|-------------------------------|----------------------------|--------|
//! | 1       | hardcoded 1920x1080 constant  | undelimited raw stream slice — **not decodable** | — |
//! | 2       | negotiated desktop, 0=unknown | exactly one `TS_BITMAP_DATA` | — |
//! | 3       | as version 2                  | as version 2               | decoded pixels |
//! | 4       | as version 2                  | as version 2               | as version 3   |
//!
//! ## Version 4 and this crate's scope
//!
//! Version 4 adds a searchable **keystroke transcript** — `0x08` text
//! records and a `0x7F` trailer — and changes nothing whatsoever
//! about graphics. This crate is the graphics reference, so it does
//! two things about version 4 and deliberately not a third:
//!
//! - it recognises and counts the two new event types instead of
//!   filing them under `unknown-event`, and refuses them (in their
//!   own bucket) in a file whose header predates them;
//! - it stops assuming a globally monotonic record stream, because
//!   version 4 no longer has one — `0x02` and `0x08` are buffered
//!   until their run closes, so they are written after graphics
//!   records bearing later timestamps, bounded by the header's
//!   `max_reorder_ms`. `duration_ms` is therefore the *maximum*
//!   timestamp, not the last one seen. `0x01`, `0x03`, `0x06` and
//!   `0x07` remain monotonic among themselves, so `timeline` is still
//!   correctly ordered and the paint path is untouched. **Do not add
//!   a monotonicity assertion**; it would fire on a valid version-4
//!   file.
//!
//! What it does **not** do is parse the transcript. That reader
//! exists twice, both copies unit-tested in CI —
//! `crates/bv-engine-rustion/src/rdp_keystrokes.rs` (the server, which
//! builds the search index) and `gui/src/lib/rdpKeystrokes.ts` (the
//! player) — and it carries the redaction rules that make it safe. A
//! third copy here, in a crate no CI job builds, would be a liability
//! rather than a reference: the rule that a redacted run is never
//! reconstructed has to hold in every copy that exists, so the right
//! number of copies is the smallest one that works.
//! Version 1 recordings came from a recording tap that parsed
//! unframed TCP chunks with a frame gate accepting about a quarter of
//! all bytes: forensics on three real recordings found 0 of 1779
//! graphics events carrying a self-consistent `TS_BITMAP_DATA`, at a
//! median payload entropy of 7.75 bits/byte — compressed codec bytes,
//! not pixels. So `0x01` is not decoded at version 1 at all; the
//! player reports a metadata-only state instead of painting noise.
//!
//! Version 3 is purely additive over version 2. Its `0x07` events
//! carry pixels the producer decoded client-side (ironrdp
//! `ActiveStage` plus the EGFX pipeline over drdynvc, including zgfx
//! and the RemoteFX / planar / NSCodec / progressive codecs),
//! deliberately so that a consumer needs no codec stack and the
//! recording stays readable years from now. **Do not add an RDP codec
//! here.**
//!
//! ## What the `0x01` path implements (versions >= 2)
//!
//! - Recorder rect header (`x/y/w/h`, 8 bytes) + `TS_BITMAP_DATA`
//!   parser for the bytes that follow it — see `decode_graphics` for
//!   the layout and why the two must not be conflated.
//! - Geometry validation against the desktop in force *before* any
//!   pixel allocation.
//! - **Uncompressed** 16/24/32 bpp. The legacy bitmap path is
//!   bottom-up by convention; we flip on emit.
//! - **RLE-compressed** 16 / 24 bpp per MS-RDPEGDI § 3.1.9 —
//!   Background / Foreground / Color / Foreground-or-Mix /
//!   Foreground-or-Mix-Set runs plus the MegaMega variants.
//!
//! Deferred on that path: 8 bpp RLE, NSCodec, RemoteFX, bitmap-cache
//! references. A modern Windows target does not use the legacy
//! `TS_UPDATE_BITMAP` path at all — it draws over surface commands or
//! RDP 8+ EGFX — which is why version 3 exists.
//!
//! Unsupported or rejected events surface as a per-event error string
//! and a distinct counter bucket rather than failing the whole stream.

#![deny(unsafe_code)]

use miniz_oxide::inflate::TINFLStatus;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAGIC: &[u8; 4] = b"RREC";

const EVENT_GRAPHICS: u8 = 0x01;
const EVENT_KEYBOARD: u8 = 0x02;
const EVENT_MOUSE: u8 = 0x03;
const EVENT_TITLE: u8 = 0x04;
const EVENT_CLIPBOARD: u8 = 0x05;
const EVENT_DESKTOP_SIZE: u8 = 0x06;
const EVENT_SURFACE: u8 = 0x07;
/// Version 4: a keystroke run's decoded text. Counted here; parsed by
/// `rdp_keystrokes` on the server and `rdpKeystrokes.ts` in the GUI.
const EVENT_TEXT_INPUT: u8 = 0x08;
/// Version 4: the keystroke trailer, always the last record.
const EVENT_KEYSTROKE_TRAILER: u8 = 0x7F;

const BITMAP_COMPRESSION: u16 = 0x0001;

/// `TS_BITMAP_DATA` flag: the optional 8-byte compressed-bitmap header
/// is absent.
const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// Size of the recorder's own `x/y/w/h` rectangle header that precedes
/// the `TS_BITMAP_DATA` in every `0x01` payload.
const REC_RECT_HEADER_LEN: usize = 8;

/// `0x07` payload prefix: `x:u16 y:u16 w:u16 h:u16 format:u8 encoding:u8`.
const SURFACE_PREFIX_LEN: usize = 10;

/// `0x07` `format`: 4 bytes per pixel in R, G, B, A order, row-major,
/// top-down, no row padding. Not BGRA and not bottom-up.
const SURFACE_FORMAT_RGBA8888: u8 = 1;

/// `0x07` `encoding` values. `1` is an RFC 1950 zlib stream — not raw
/// deflate, not gzip. The producer stores raw when the region is under
/// 512 bytes or compression did not shrink it, so both encodings
/// appear in the same file.
const SURFACE_ENCODING_RAW: u8 = 0;
const SURFACE_ENCODING_ZLIB: u8 = 1;

const BYTES_PER_PIXEL: u64 = 4;

/// Highest header version this decoder fully understands. A higher
/// version still parses — unknown event types are skipped by
/// `payload_len` — but the player says the file came from a newer
/// bastion so an operator knows the replay may be incomplete.
pub const MAX_SUPPORTED_VERSION: u32 = 4;

/// First version whose `0x01` payload is a real `TS_BITMAP_DATA`.
const FIRST_DECODABLE_BITMAP_VERSION: u32 = 2;

/// First version that carries decoded pixels in `0x07`.
const FIRST_SURFACE_VERSION: u32 = 3;

/// First version that can carry a keystroke track (`0x08` + `0x7F`).
pub const FIRST_KEYSTROKE_VERSION: u32 = 4;

/// Ceiling on a single rectangle's pixel count when no desktop size is
/// available (header `0x0` and no `0x06` seen yet). 8192x8192 is far
/// above any real RDP desktop and caps the RGBA allocation at 256 MiB.
///
/// Without a bound, a rectangle whose dimensions decode to garbage
/// (63426 x 63193 has been observed in the field) would make the
/// decoder ask for ~16 GB. Recording bytes come from the bastion, so
/// these fields are attacker-influenced input. This is a floor on
/// strictness, not a substitute for the desktop check — it applies
/// *only* when there is no desktop size to check against.
const MAX_RECT_PIXELS: u64 = 8192 * 8192;

// ─── Skip-reason taxonomy ───────────────────────────────────────────
//
// Every graphics event that is not painted lands in exactly one of
// these buckets, reported to the operator as
// "N rendered · M skipped · dominant reason: <key>". That reporting is
// what turned the black-canvas bug from invisible into diagnosable, so
// keep the buckets distinct and never fold one into another.

/// `0x01`, painted.
pub const COUNT_UNCOMPRESSED: &str = "uncompressed";
pub const COUNT_RLE16: &str = "rle16";
pub const COUNT_RLE24: &str = "rle24";
/// `0x07`, painted.
pub const COUNT_SURFACE: &str = "surface-rgba8888";

/// `0x01` at version 1: raw stream slabs. Never decoded.
pub const COUNT_V1_UNDECODABLE: &str = "version-1-undecodable";
/// `0x01` hit a codec this side does not implement.
pub const COUNT_UNSUPPORTED: &str = "unsupported";
/// Rectangle does not fit the desktop, is zero-sized, or blows the cap.
pub const COUNT_INVALID_GEOMETRY: &str = "invalid-geometry";
/// `0x01` parse failure (truncated header/body, short pixel run).
pub const COUNT_ERROR: &str = "error";

/// `0x07` seen in a file whose header version predates it.
pub const COUNT_SURFACE_BAD_VERSION: &str = "surface-unexpected-version";
/// `0x07` payload shorter than its own 10-byte prefix.
pub const COUNT_SURFACE_TRUNCATED: &str = "surface-truncated";
/// `0x07` `format` byte we do not know.
pub const COUNT_SURFACE_BAD_FORMAT: &str = "surface-unknown-format";
/// `0x07` `encoding` byte we do not know.
pub const COUNT_SURFACE_BAD_ENCODING: &str = "surface-unknown-encoding";
/// `0x07` data length (raw) or inflated length (zlib) != `w * h * 4`.
pub const COUNT_SURFACE_BAD_LENGTH: &str = "surface-length-mismatch";
/// `0x07` zlib stream would not inflate.
pub const COUNT_SURFACE_INFLATE_FAILED: &str = "surface-inflate-failed";

/// An `event_type` this decoder does not know. Skipped by
/// `payload_len` and counted, never an error: that is how version 3
/// added `0x07` without breaking older players, and how version 4
/// added `0x08` and `0x7F`.
pub const COUNT_UNKNOWN_EVENT: &str = "unknown-event";

/// `0x08` / `0x7F` seen in a file whose header version predates them.
/// Counted rather than read: a keystroke record contradicting its own
/// header is a file we do not trust to describe itself, and silently
/// accepting it would be a fallback on an audit surface.
pub const COUNT_KEYSTROKE_BAD_VERSION: &str = "keystroke-unexpected-version";

// ─── Public types ───────────────────────────────────────────────────

/// Cheap metadata pass — event counts only, no pixel work.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub ok: bool,
    pub error: Option<String>,
    pub header_json: Option<String>,
    pub version: u32,
    pub graphics: u64,
    pub surface_updates: u64,
    pub desktop_sizes: u64,
    pub keyboard: u64,
    pub mouse: u64,
    pub title: u64,
    pub clipboard: u64,
    pub unknown: u64,
    /// Version 4 `0x08` text-input records.
    pub text_input: u64,
    /// A `0x7F` keystroke trailer record was seen.
    pub keystroke_trailer: bool,
    /// Maximum `timestamp_ms` over every record, not the last one
    /// seen — version 4's stream is not monotonic.
    pub duration_ms: u64,
    pub event_count: u64,
    pub bytes_parsed: u64,
    /// Trailing bytes that do not form a complete record.
    pub truncated: Option<String>,
}

/// One decoded `0x01` rectangle, ready for `putImageData`.
#[derive(Debug, Clone, Serialize)]
pub struct Frame {
    pub timestamp_ms: u64,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub compressed: bool,
    /// `"uncompressed"` | `"rle16"` | `"rle24"` | `"none"`.
    pub decoder: String,
    /// RGBA8888, top-down. Empty when `error` is set.
    pub rgba: Vec<u8>,
    /// Set when this rectangle could not be decoded; the GUI can show a
    /// "missing pixel" placeholder.
    pub error: Option<String>,
}

/// A `0x07` surface update, indexed but **not** inflated.
///
/// Pixels stay in the file until the player reaches the event: a 454 s
/// session at the producer's default 1000 ms interval is ~450 dirty
/// regions, and eagerly inflating 450 full-desktop regions at
/// 1920 x 1080 x 4 would retain 3.7 GB. `decode_surface_update`
/// inflates one region at a time and the caller drops it after the
/// blit.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceUpdate {
    pub timestamp_ms: u64,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub format: u8,
    pub encoding: u8,
    /// Offset of the pixel bytes within the whole `.rdp-rec` buffer.
    pub data_offset: usize,
    pub data_len: usize,
    /// Set when static validation already rejected this update; it will
    /// never be painted and is already counted.
    pub error: Option<String>,
    /// The bucket this update was counted in when `error` is set.
    pub count_key: Option<String>,
}

/// A `0x06` desktop-size event. A size differing from the current
/// canvas means the canvas is resized and treated as cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DesktopSizeEvent {
    pub timestamp_ms: u64,
    pub width: u16,
    pub height: u16,
}

/// The ordered playback timeline. `0x06` must be applied in file order
/// relative to the paints around it, so the player walks one list
/// rather than merging three.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TimelineEvent {
    Bitmap { timestamp_ms: u64, index: usize },
    Surface { timestamp_ms: u64, index: usize },
    Desktop { timestamp_ms: u64, desktop: DesktopSizeEvent },
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodeOutput {
    pub ok: bool,
    pub error: Option<String>,
    pub header_json: Option<String>,
    /// Header `version`, or 0 when the header carries no numeric version.
    pub version: u32,
    /// Header `screen_width` / `screen_height`. `0` means unknown — the
    /// producer could not determine the geometry before writing the
    /// header. Never treat `0x0` as a valid desktop size.
    pub screen_width: u32,
    pub screen_height: u32,
    /// Header `graphics_encodings`: which encodings the producer could
    /// emit, hence which event types to expect.
    pub graphics_encodings: Vec<String>,
    /// Version 1: `0x01` payloads are undelimited raw stream slices and
    /// are not decodable. Metadata is still meaningful.
    pub graphics_undecodable: bool,
    /// Header version above `MAX_SUPPORTED_VERSION`.
    pub newer_format: bool,
    /// Version >= 3 with zero `0x01` and zero `0x07` events. A real
    /// state, not a parse failure: the session's graphics could not be
    /// decoded on the bastion. The remaining known cause is AVC420 /
    /// AVC444 (H.264) over EGFX, which the bastion counts but does not
    /// decode; it records the reason in a `RECORDING_GRAPHICS_CENSUS`
    /// log event and, when content was lost, a
    /// `recording_graphics_unrepresentable` audit entry. That signal is
    /// not carried in the recording sidecar BastionVault imports, so a
    /// consumer can only name the state, not the cause.
    pub graphics_not_recordable: bool,
    pub frames: Vec<Frame>,
    pub surface_updates: Vec<SurfaceUpdate>,
    pub desktop_sizes: Vec<DesktopSizeEvent>,
    pub timeline: Vec<TimelineEvent>,
    pub keyboard_events: u64,
    pub mouse_events: u64,
    pub title_events: u64,
    pub clipboard_events: u64,
    pub unknown_events: u64,
    /// Version 4 `0x08` text-input records. A count only — the text
    /// is read by `rdp_keystrokes` / `rdpKeystrokes.ts`, which carry
    /// the redaction rules.
    pub text_input_events: u64,
    /// A `0x7F` keystroke trailer record was seen while walking.
    pub keystroke_trailer: bool,
    /// Header `keystroke_metadata`. `false` means keystroke recording
    /// was off for this session — never that nobody typed.
    pub keystroke_metadata: bool,
    /// Header `max_reorder_ms`.
    pub max_reorder_ms: u64,
    /// Maximum `timestamp_ms` over every record, not the last one
    /// seen — version 4's stream is not monotonic.
    pub duration_ms: u64,
    /// Trailing bytes that do not form a complete record. The prefix
    /// before them is still valid and still replayed; a truncated
    /// recording must replay what it has, loudly, rather than silently
    /// dropping to nothing or painting half a record.
    pub truncated: Option<String>,
    /// Per-bucket counter — see the skip-reason taxonomy above.
    pub decoder_counts: std::collections::BTreeMap<String, u64>,
}

/// One region's pixels, produced on demand by `decode_surface_update`.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceRender {
    /// RGBA8888, top-down, `width * height * 4` bytes. Empty on error.
    pub rgba: Vec<u8>,
    pub error: Option<String>,
    /// Bucket to count this attempt in — a painted region included.
    pub count_key: String,
}

/// Version + geometry + advertised encodings, read off the JSON header.
#[derive(Debug, Clone, Default)]
struct HeaderFields {
    version: u32,
    screen_w: u32,
    screen_h: u32,
    graphics_encodings: Vec<String>,
    /// Version 4 `keystroke_metadata`. Absent (version <= 3) reads as
    /// `false`, which is how those files must read. **`false` does
    /// not mean nobody typed** — it means the feature was off.
    keystroke_metadata: bool,
    /// Version 4 `max_reorder_ms`: how far out of order a keystroke
    /// record may appear. `0` on version <= 3.
    max_reorder_ms: u64,
}

// ─── WASM entrypoints ───────────────────────────────────────────────

#[wasm_bindgen]
pub fn parse_rdp_rec(bytes: &[u8]) -> JsValue {
    let summary = walk(bytes);
    serde_wasm_bindgen::to_value(&summary).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn decode_rdp_rec(bytes: &[u8]) -> JsValue {
    let out = decode(bytes);
    serde_wasm_bindgen::to_value(&out).unwrap_or(JsValue::NULL)
}

/// Inflate the `index`-th `0x07` region of `bytes`. Split out from
/// `decode_rdp_rec` on purpose: the caller asks for one region at the
/// moment it paints it, and drops it afterwards.
#[wasm_bindgen]
pub fn decode_rdp_surface_update(bytes: &[u8], index: usize) -> JsValue {
    let out = decode(bytes);
    let render = match out.surface_updates.get(index) {
        Some(u) => decode_surface_update(bytes, u),
        None => SurfaceRender {
            rgba: Vec::new(),
            error: Some(format!(
                "no surface update at index {index} ({} in this recording)",
                out.surface_updates.len()
            )),
            count_key: COUNT_ERROR.to_string(),
        },
    };
    serde_wasm_bindgen::to_value(&render).unwrap_or(JsValue::NULL)
}

// ─── Native entrypoints ─────────────────────────────────────────────

pub fn walk(bytes: &[u8]) -> Summary {
    let (header, mut pos) = match header_and_start(bytes) {
        Ok(v) => v,
        Err(e) => return summary_err(&e),
    };
    let fields = parse_header_fields(&header);
    let mut s = Summary {
        ok: true,
        error: None,
        header_json: Some(header),
        version: fields.version,
        graphics: 0,
        surface_updates: 0,
        desktop_sizes: 0,
        keyboard: 0,
        mouse: 0,
        title: 0,
        clipboard: 0,
        unknown: 0,
        text_input: 0,
        keystroke_trailer: false,
        duration_ms: 0,
        event_count: 0,
        bytes_parsed: 0,
        truncated: None,
    };
    while let Some((ts, kind, _payload, next)) = read_event(bytes, pos) {
        match kind {
            EVENT_GRAPHICS => s.graphics += 1,
            EVENT_SURFACE => s.surface_updates += 1,
            EVENT_DESKTOP_SIZE => s.desktop_sizes += 1,
            EVENT_KEYBOARD => s.keyboard += 1,
            EVENT_MOUSE => s.mouse += 1,
            EVENT_TITLE => s.title += 1,
            EVENT_CLIPBOARD => s.clipboard += 1,
            EVENT_TEXT_INPUT => s.text_input += 1,
            EVENT_KEYSTROKE_TRAILER => s.keystroke_trailer = true,
            _ => s.unknown += 1,
        }
        // Version 4's records are not monotonic, so this is a
        // maximum, not an assignment of the last value seen.
        s.duration_ms = s.duration_ms.max(ts);
        s.event_count += 1;
        pos = next;
    }
    s.bytes_parsed = pos as u64;
    s.truncated = truncation_note(bytes.len() - pos);
    s
}

pub fn decode(bytes: &[u8]) -> DecodeOutput {
    let (header, mut pos) = match header_and_start(bytes) {
        Ok(v) => v,
        Err(e) => return decode_err(&e),
    };
    let fields = parse_header_fields(&header);

    let mut frames: Vec<Frame> = Vec::new();
    let mut surface_updates: Vec<SurfaceUpdate> = Vec::new();
    let mut desktop_sizes: Vec<DesktopSizeEvent> = Vec::new();
    let mut timeline: Vec<TimelineEvent> = Vec::new();
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    let mut keyboard = 0u64;
    let mut mouse = 0u64;
    let mut title = 0u64;
    let mut clipboard = 0u64;
    let mut unknown = 0u64;
    let mut text_input = 0u64;
    let mut keystroke_trailer = false;
    // Version 4's records are not monotonic: a keystroke record
    // written late but stamped early must not shorten the recording.
    let mut max_ts = 0u64;
    let mut graphics_events = 0u64;

    // The desktop in force at this point in the file: the most recent
    // `0x06`, falling back to the header. `0/0` means "no bound
    // available" and the per-rect cap applies instead.
    let mut desk_w = fields.screen_w;
    let mut desk_h = fields.screen_h;

    while let Some((ts, kind, payload, next)) = read_event(bytes, pos) {
        max_ts = max_ts.max(ts);
        let payload_offset = next - payload.len();
        match kind {
            EVENT_GRAPHICS => {
                graphics_events += 1;
                if fields.version < FIRST_DECODABLE_BITMAP_VERSION {
                    // Version 1: an undelimited slice of the raw byte
                    // stream. Not a codec we lack — not pixels at all.
                    bump(&mut counts, COUNT_V1_UNDECODABLE);
                } else {
                    let frame = decode_graphics(ts, payload, desk_w, desk_h);
                    bump(&mut counts, &bitmap_count_key(&frame));
                    timeline.push(TimelineEvent::Bitmap {
                        timestamp_ms: ts,
                        index: frames.len(),
                    });
                    frames.push(frame);
                }
            }
            EVENT_SURFACE => {
                graphics_events += 1;
                let u = index_surface_update(
                    ts,
                    payload,
                    payload_offset,
                    fields.version,
                    desk_w,
                    desk_h,
                );
                if let Some(key) = u.count_key.clone() {
                    bump(&mut counts, &key);
                }
                timeline.push(TimelineEvent::Surface {
                    timestamp_ms: ts,
                    index: surface_updates.len(),
                });
                surface_updates.push(u);
            }
            EVENT_DESKTOP_SIZE => {
                if payload.len() < 4 {
                    // A malformed geometry event tells us nothing about
                    // geometry, so leave the current desktop in force
                    // rather than guessing at a new one.
                    bump(&mut counts, COUNT_ERROR);
                } else {
                    let w = u16::from_le_bytes([payload[0], payload[1]]);
                    let h = u16::from_le_bytes([payload[2], payload[3]]);
                    desk_w = u32::from(w);
                    desk_h = u32::from(h);
                    let d = DesktopSizeEvent {
                        timestamp_ms: ts,
                        width: w,
                        height: h,
                    };
                    desktop_sizes.push(d);
                    timeline.push(TimelineEvent::Desktop {
                        timestamp_ms: ts,
                        desktop: d,
                    });
                }
            }
            EVENT_KEYBOARD => keyboard += 1,
            EVENT_MOUSE => mouse += 1,
            EVENT_TITLE => title += 1,
            EVENT_CLIPBOARD => clipboard += 1,
            EVENT_TEXT_INPUT => {
                // Version 4 keystroke text. Counted here; the payload
                // is read by `rdp_keystrokes` / `rdpKeystrokes.ts`.
                if fields.version < FIRST_KEYSTROKE_VERSION {
                    bump(&mut counts, COUNT_KEYSTROKE_BAD_VERSION);
                } else {
                    text_input += 1;
                }
            }
            EVENT_KEYSTROKE_TRAILER => {
                if fields.version < FIRST_KEYSTROKE_VERSION {
                    bump(&mut counts, COUNT_KEYSTROKE_BAD_VERSION);
                } else {
                    keystroke_trailer = true;
                }
            }
            _ => {
                // Forward compatibility: skip by `payload_len` and count.
                unknown += 1;
                bump(&mut counts, COUNT_UNKNOWN_EVENT);
            }
        }
        pos = next;
    }

    DecodeOutput {
        ok: true,
        error: None,
        header_json: Some(header),
        version: fields.version,
        screen_width: fields.screen_w,
        screen_height: fields.screen_h,
        graphics_encodings: fields.graphics_encodings,
        graphics_undecodable: fields.version < FIRST_DECODABLE_BITMAP_VERSION,
        newer_format: fields.version > MAX_SUPPORTED_VERSION,
        graphics_not_recordable: fields.version >= FIRST_SURFACE_VERSION
            && graphics_events == 0,
        frames,
        surface_updates,
        desktop_sizes,
        timeline,
        keyboard_events: keyboard,
        mouse_events: mouse,
        title_events: title,
        clipboard_events: clipboard,
        unknown_events: unknown,
        text_input_events: text_input,
        keystroke_trailer,
        keystroke_metadata: fields.keystroke_metadata,
        max_reorder_ms: fields.max_reorder_ms,
        duration_ms: max_ts,
        truncated: truncation_note(bytes.len() - pos),
        decoder_counts: counts,
    }
}

fn bump(counts: &mut std::collections::BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_string()).or_insert(0) += 1;
}

fn bitmap_count_key(frame: &Frame) -> String {
    match frame.error.as_deref() {
        None => frame.decoder.clone(),
        Some(e) if e.starts_with("unsupported") => COUNT_UNSUPPORTED.to_string(),
        Some(e) if e.starts_with("invalid geometry") => COUNT_INVALID_GEOMETRY.to_string(),
        Some(_) => COUNT_ERROR.to_string(),
    }
}

fn truncation_note(leftover: usize) -> Option<String> {
    if leftover == 0 {
        return None;
    }
    Some(format!(
        "truncated final record: {leftover} trailing byte{} do not form a complete (ts:u64, type:u8, len:u32, payload) record",
        if leftover == 1 { "" } else { "s" }
    ))
}

// ─── `0x07` surface updates ─────────────────────────────────────────

/// Parse and statically validate a `0x07` payload without inflating
/// it. Everything checkable from the prefix is checked here so the
/// player can report rejections before playback starts; the two checks
/// that need the inflate itself (stream validity and inflated length)
/// happen in `decode_surface_update`.
fn index_surface_update(
    timestamp_ms: u64,
    payload: &[u8],
    payload_offset: usize,
    version: u32,
    desk_w: u32,
    desk_h: u32,
) -> SurfaceUpdate {
    let mut u = SurfaceUpdate {
        timestamp_ms,
        x: 0,
        y: 0,
        width: 0,
        height: 0,
        format: 0,
        encoding: 0,
        data_offset: 0,
        data_len: 0,
        error: None,
        count_key: None,
    };
    if payload.len() < SURFACE_PREFIX_LEN {
        u.error = Some(format!(
            "surface update payload truncated: {} bytes, need at least {SURFACE_PREFIX_LEN}",
            payload.len()
        ));
        u.count_key = Some(COUNT_SURFACE_TRUNCATED.to_string());
        return u;
    }
    u.x = u16::from_le_bytes([payload[0], payload[1]]);
    u.y = u16::from_le_bytes([payload[2], payload[3]]);
    u.width = u16::from_le_bytes([payload[4], payload[5]]);
    u.height = u16::from_le_bytes([payload[6], payload[7]]);
    u.format = payload[8];
    u.encoding = payload[9];
    u.data_offset = payload_offset + SURFACE_PREFIX_LEN;
    u.data_len = payload.len() - SURFACE_PREFIX_LEN;

    // A `0x07` in a file that predates the event type contradicts its
    // own header. Skip and count rather than paint it: silently
    // accepting it would be a fallback on an audit surface.
    if version < FIRST_SURFACE_VERSION {
        u.error = Some(format!(
            "surface update in a version-{version} recording (0x07 was added in version {FIRST_SURFACE_VERSION})"
        ));
        u.count_key = Some(COUNT_SURFACE_BAD_VERSION.to_string());
        return u;
    }

    // Same geometry strictness as the `0x01` path, against the most
    // recent `0x06` if one has been seen and the header otherwise.
    if let Some(e) = check_geometry(u.x, u.y, u.width, u.height, desk_w, desk_h) {
        u.error = Some(e);
        u.count_key = Some(COUNT_INVALID_GEOMETRY.to_string());
        return u;
    }
    if u.format != SURFACE_FORMAT_RGBA8888 {
        u.error = Some(format!(
            "unknown surface format {} (known: {SURFACE_FORMAT_RGBA8888} = RGBA8888)",
            u.format
        ));
        u.count_key = Some(COUNT_SURFACE_BAD_FORMAT.to_string());
        return u;
    }
    if u.encoding != SURFACE_ENCODING_RAW && u.encoding != SURFACE_ENCODING_ZLIB {
        u.error = Some(format!(
            "unknown surface encoding {} (known: {SURFACE_ENCODING_RAW} = raw, {SURFACE_ENCODING_ZLIB} = zlib)",
            u.encoding
        ));
        u.count_key = Some(COUNT_SURFACE_BAD_ENCODING.to_string());
        return u;
    }
    let expected = surface_expected_len(&u);
    if u.encoding == SURFACE_ENCODING_RAW && u.data_len as u64 != expected {
        u.error = Some(format!(
            "raw surface data is {} bytes, expected {}x{}x{BYTES_PER_PIXEL} = {expected}",
            u.data_len, u.width, u.height
        ));
        u.count_key = Some(COUNT_SURFACE_BAD_LENGTH.to_string());
        return u;
    }
    u
}

fn surface_expected_len(u: &SurfaceUpdate) -> u64 {
    u64::from(u.width) * u64::from(u.height) * BYTES_PER_PIXEL
}

/// Inflate (when needed) and validate one `0x07` region's pixels.
///
/// `bytes` must be the whole `.rdp-rec` buffer the update was indexed
/// from; `data_offset` is absolute within it.
pub fn decode_surface_update(bytes: &[u8], u: &SurfaceUpdate) -> SurfaceRender {
    if let Some(e) = u.error.as_ref() {
        return SurfaceRender {
            rgba: Vec::new(),
            error: Some(e.clone()),
            count_key: u.count_key.clone().unwrap_or_else(|| COUNT_ERROR.to_string()),
        };
    }
    let expected = surface_expected_len(u);
    let end = u.data_offset.saturating_add(u.data_len);
    if end > bytes.len() {
        return SurfaceRender {
            rgba: Vec::new(),
            error: Some(format!(
                "surface data range {}..{end} is outside the {}-byte recording",
                u.data_offset,
                bytes.len()
            )),
            count_key: COUNT_SURFACE_BAD_LENGTH.to_string(),
        };
    }
    let data = &bytes[u.data_offset..end];

    if u.encoding == SURFACE_ENCODING_RAW {
        // Length was validated at index time.
        return SurfaceRender {
            rgba: data.to_vec(),
            error: None,
            count_key: COUNT_SURFACE.to_string(),
        };
    }

    // encoding == 1: an RFC 1950 zlib stream. The limit is the hard
    // allocation bound, one byte past what the geometry says the region
    // holds, so a stream that inflates to *more* than it claims is an
    // error rather than a silent truncation.
    let limit = usize::try_from(expected.saturating_add(1)).unwrap_or(usize::MAX);
    match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, limit) {
        Ok(out) => {
            if out.len() as u64 != expected {
                return SurfaceRender {
                    rgba: Vec::new(),
                    error: Some(format!(
                        "inflated surface data is {} bytes, expected {}x{}x{BYTES_PER_PIXEL} = {expected}",
                        out.len(),
                        u.width,
                        u.height
                    )),
                    count_key: COUNT_SURFACE_BAD_LENGTH.to_string(),
                };
            }
            SurfaceRender {
                rgba: out,
                error: None,
                count_key: COUNT_SURFACE.to_string(),
            }
        }
        // The stream inflates past the allocation bound: the region
        // claims less than it carries.
        Err(e) if e.status == TINFLStatus::HasMoreOutput => SurfaceRender {
            rgba: Vec::new(),
            error: Some(format!(
                "inflated surface data exceeds {}x{}x{BYTES_PER_PIXEL} = {expected} bytes",
                u.width, u.height
            )),
            count_key: COUNT_SURFACE_BAD_LENGTH.to_string(),
        },
        Err(e) => SurfaceRender {
            rgba: Vec::new(),
            error: Some(format!("zlib inflate failed: {:?}", e.status)),
            count_key: COUNT_SURFACE_INFLATE_FAILED.to_string(),
        },
    }
}

// ─── Header + framing ───────────────────────────────────────────────

/// Version, geometry and advertised encodings out of the recording's
/// JSON header, without taking a JSON dependency — this crate ships as
/// wasm in the GUI bundle and a handful of fields do not justify
/// pulling `serde_json` into it. Unknown header fields are ignored;
/// the producer may add more.
///
/// A missing or unparsable `version` reads as `0`, which
/// `graphics_undecodable` then treats like version 1: a header we
/// cannot understand is not a licence to paint its graphics events.
fn parse_header_fields(header: &str) -> HeaderFields {
    HeaderFields {
        version: json_u32(header, "version"),
        screen_w: json_u32(header, "screen_width"),
        screen_h: json_u32(header, "screen_height"),
        graphics_encodings: json_string_array(header, "graphics_encodings"),
        // A missing `keystroke_metadata` reads as `false` — which is
        // how every version <= 3 header reads, and the whole reason
        // version 4 needed no version gate here.
        keystroke_metadata: json_bool(header, "keystroke_metadata"),
        max_reorder_ms: json_u32(header, "max_reorder_ms") as u64,
    }
}

/// A boolean field. `false` when absent or unparsable — which is the
/// correct default for `keystroke_metadata` on a version <= 3 file.
fn json_bool(header: &str, name: &str) -> bool {
    let key = format!("\"{name}\"");
    let Some(at) = header.find(&key) else {
        return false;
    };
    let rest = &header[at + key.len()..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    rest[colon + 1..].trim_start().starts_with("true")
}

/// A non-negative integer field. `0` when absent or unparsable.
fn json_u32(header: &str, name: &str) -> u32 {
    let key = format!("\"{name}\"");
    let Some(at) = header.find(&key) else {
        return 0;
    };
    let rest = &header[at + key.len()..];
    let Some(colon) = rest.find(':') else {
        return 0;
    };
    rest[colon + 1..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// A flat array-of-strings field. Empty when absent or malformed.
fn json_string_array(header: &str, name: &str) -> Vec<String> {
    let key = format!("\"{name}\"");
    let Some(at) = header.find(&key) else {
        return Vec::new();
    };
    let rest = &header[at + key.len()..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find(']') else {
        return Vec::new();
    };
    rest[open + 1..open + close]
        .split(',')
        .filter_map(|item| {
            let t = item.trim();
            let inner = t.strip_prefix('"')?.strip_suffix('"')?;
            if inner.is_empty() {
                None
            } else {
                Some(inner.to_string())
            }
        })
        .collect()
}

/// Validate a rectangle against the desktop in force — the most recent
/// `0x06` if one has been seen, the header otherwise. Returns `None`
/// when the rect is usable, or an `"invalid geometry: …"` message
/// otherwise.
///
/// Runs *before* any `w * h * 4` allocation, and is shared by `0x01`
/// and `0x07` so there is exactly one geometry policy.
fn check_geometry(x: u16, y: u16, w: u16, h: u16, screen_w: u32, screen_h: u32) -> Option<String> {
    if w == 0 || h == 0 {
        return Some(format!("invalid geometry: zero-size rect {w}×{h}"));
    }
    if screen_w > 0 && screen_h > 0 {
        if u32::from(x) + u32::from(w) > screen_w || u32::from(y) + u32::from(h) > screen_h {
            return Some(format!(
                "invalid geometry: rect {w}×{h} at ({x},{y}) falls outside the recorded {screen_w}×{screen_h} desktop"
            ));
        }
        return None;
    }
    if u64::from(w) * u64::from(h) > MAX_RECT_PIXELS {
        return Some(format!(
            "invalid geometry: rect {w}×{h} exceeds the {MAX_RECT_PIXELS}-pixel cap"
        ));
    }
    None
}

fn header_and_start(bytes: &[u8]) -> Result<(String, usize), String> {
    if bytes.len() < MAGIC.len() {
        return Err("input shorter than the 4-byte magic prefix".into());
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err("magic mismatch (expected RREC)".into());
    }
    let mut nl = None;
    for (i, b) in bytes.iter().enumerate().skip(MAGIC.len()) {
        if *b == 0x0a {
            nl = Some(i);
            break;
        }
    }
    let nl = nl.ok_or_else(|| "no newline after header".to_string())?;
    let header = std::str::from_utf8(&bytes[MAGIC.len()..nl])
        .map(|s| s.to_string())
        .map_err(|e| format!("header is not utf-8: {e}"))?;
    Ok((header, nl + 1))
}

fn read_event(bytes: &[u8], pos: usize) -> Option<(u64, u8, &[u8], usize)> {
    if pos + 13 > bytes.len() {
        return None;
    }
    let ts = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
    let kind = bytes[pos + 8];
    let len = u32::from_le_bytes(bytes[pos + 9..pos + 13].try_into().ok()?) as usize;
    let next = pos.checked_add(13)?.checked_add(len)?;
    if next > bytes.len() {
        return None;
    }
    Some((ts, kind, &bytes[pos + 13..next], next))
}

fn summary_err(msg: &str) -> Summary {
    Summary {
        ok: false,
        error: Some(msg.to_string()),
        header_json: None,
        version: 0,
        graphics: 0,
        surface_updates: 0,
        desktop_sizes: 0,
        keyboard: 0,
        mouse: 0,
        title: 0,
        clipboard: 0,
        unknown: 0,
        text_input: 0,
        keystroke_trailer: false,
        duration_ms: 0,
        event_count: 0,
        bytes_parsed: 0,
        truncated: None,
    }
}

fn decode_err(msg: &str) -> DecodeOutput {
    DecodeOutput {
        ok: false,
        error: Some(msg.to_string()),
        header_json: None,
        version: 0,
        screen_width: 0,
        screen_height: 0,
        graphics_encodings: Vec::new(),
        graphics_undecodable: false,
        newer_format: false,
        graphics_not_recordable: false,
        frames: Vec::new(),
        surface_updates: Vec::new(),
        desktop_sizes: Vec::new(),
        timeline: Vec::new(),
        keyboard_events: 0,
        mouse_events: 0,
        title_events: 0,
        clipboard_events: 0,
        unknown_events: 0,
        text_input_events: 0,
        keystroke_trailer: false,
        keystroke_metadata: false,
        max_reorder_ms: 0,
        duration_ms: 0,
        truncated: None,
        decoder_counts: Default::default(),
    }
}

// ─── TS_BITMAP_DATA parser + decode dispatcher ──────────────────────

fn decode_graphics(timestamp_ms: u64, payload: &[u8], screen_w: u32, screen_h: u32) -> Frame {
    // Graphics event payload layout, per Rustion's
    // `docs/session-recording-format.md` and
    // `rustion-recording::rdp_recorder::record_event`:
    //
    //     x:u16 LE | y:u16 LE | w:u16 LE | h:u16 LE | pixel data
    //
    // The leading 8 bytes are the *recorder's* rectangle header, not
    // part of MS-RDPBCGR. Everything from offset 8 is the slice the
    // recorder's `parse_bitmap_update` copied out of the wire PDU,
    // which it takes to begin at a TS_BITMAP_DATA rectangle:
    //   destLeft        u16
    //   destTop         u16
    //   destRight       u16
    //   destBottom      u16
    //   width           u16  (bitmap source width)
    //   height          u16  (bitmap source height)
    //   bitsPerPixel    u16
    //   flags           u16
    //   bitmapLength    u16
    //   [compressed header 8 bytes if flags & BITMAP_COMPRESSION and
    //    not NO_BITMAP_COMPRESSION_HDR]
    //   bitmapDataStream bytes (bitmapLength bytes)
    //
    // Reading TS_BITMAP_DATA at offset 0 instead silently misreads the
    // recorder header as destLeft/destTop/destRight/destBottom and then
    // re-reads the *same* four bytes as width/height, because
    // `parse_bitmap_update` copies the rectangle it just parsed.
    // Every field from `bitsPerPixel` on is then garbage.
    if payload.len() < REC_RECT_HEADER_LEN {
        return frame_err(timestamp_ms, 0, 0, 0, 0, "recorder rect header truncated");
    }
    let x = u16::from_le_bytes([payload[0], payload[1]]);
    let y = u16::from_le_bytes([payload[2], payload[3]]);
    let width = u16::from_le_bytes([payload[4], payload[5]]);
    let height = u16::from_le_bytes([payload[6], payload[7]]);

    if let Some(msg) = check_geometry(x, y, width, height, screen_w, screen_h) {
        return frame_err(timestamp_ms, x, y, width, height, &msg);
    }

    let payload = &payload[REC_RECT_HEADER_LEN..];
    if payload.len() < 18 {
        return frame_err(
            timestamp_ms,
            x,
            y,
            width,
            height,
            "TS_BITMAP_DATA header truncated",
        );
    }
    let bpp = u16::from_le_bytes([payload[12], payload[13]]);
    let flags = u16::from_le_bytes([payload[14], payload[15]]);
    let bitmap_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;

    let mut cursor = 18;
    let compressed = (flags & BITMAP_COMPRESSION) != 0;
    if compressed && (flags & NO_BITMAP_COMPRESSION_HDR) == 0 {
        // Compressed bitmap header (8 bytes) precedes the body.
        if cursor + 8 > payload.len() {
            return frame_err(
                timestamp_ms, x, y, width, height,
                "compressed bitmap header truncated",
            );
        }
        // We don't need the cbCompFirstRowSize / cbCompMainBodySize
        // fields — the spec recommends using `bitmapLength` as the
        // canonical body length when this header is present, BUT
        // some servers use the cbCompMainBodySize field instead. We
        // skip past the header and let `bitmap_len` drive the read.
        cursor += 8;
    }
    if cursor + bitmap_len > payload.len() {
        return frame_err(
            timestamp_ms, x, y, width, height,
            "bitmap body truncated",
        );
    }
    let body = &payload[cursor..cursor + bitmap_len];

    if !compressed {
        return match decode_uncompressed(bpp, width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "uncompressed".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err(timestamp_ms, x, y, width, height, &e),
        };
    }

    // Compressed path
    match bpp {
        16 => match decode_rle16(width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "rle16".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err_decoder(timestamp_ms, x, y, width, height, "rle16", &e),
        },
        24 => match decode_rle24(width, height, body) {
            Ok(rgba) => Frame {
                timestamp_ms,
                x,
                y,
                width,
                height,
                bits_per_pixel: bpp,
                compressed,
                decoder: "rle24".into(),
                rgba,
                error: None,
            },
            Err(e) => frame_err_decoder(timestamp_ms, x, y, width, height, "rle24", &e),
        },
        other => Frame {
            timestamp_ms,
            x,
            y,
            width,
            height,
            bits_per_pixel: bpp,
            compressed,
            decoder: "none".into(),
            rgba: Vec::new(),
            error: Some(format!(
                "unsupported compressed bpp={other} (Phase 8.4: 16/24 only; 8 bpp + NSCodec + RemoteFX deferred)"
            )),
        },
    }
}

fn frame_err(ts: u64, x: u16, y: u16, w: u16, h: u16, msg: &str) -> Frame {
    Frame {
        timestamp_ms: ts,
        x,
        y,
        width: w,
        height: h,
        bits_per_pixel: 0,
        compressed: false,
        decoder: "none".into(),
        rgba: Vec::new(),
        error: Some(msg.to_string()),
    }
}

fn frame_err_decoder(
    ts: u64,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    decoder: &str,
    msg: &str,
) -> Frame {
    Frame {
        timestamp_ms: ts,
        x,
        y,
        width: w,
        height: h,
        bits_per_pixel: 0,
        compressed: true,
        decoder: decoder.into(),
        rgba: Vec::new(),
        error: Some(msg.to_string()),
    }
}

// ─── Uncompressed decoder ───────────────────────────────────────────

fn decode_uncompressed(
    bpp: u16,
    width: u16,
    height: u16,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let w = width as usize;
    let h = height as usize;
    let mut rgba = vec![0u8; w * h * 4];
    match bpp {
        16 => {
            // RGB565 (rrrrr gggggg bbbbb). Bottom-up.
            let expected = w * h * 2;
            if body.len() < expected {
                return Err(format!(
                    "16bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row; // bottom-up → top-down
                for col in 0..w {
                    let i = (src_row * w + col) * 2;
                    let lo = body[i] as u16;
                    let hi = body[i + 1] as u16;
                    let px = (hi << 8) | lo;
                    let r = ((px >> 11) & 0x1f) as u8;
                    let g = ((px >> 5) & 0x3f) as u8;
                    let b = (px & 0x1f) as u8;
                    let out = (row * w + col) * 4;
                    rgba[out] = (r << 3) | (r >> 2);
                    rgba[out + 1] = (g << 2) | (g >> 4);
                    rgba[out + 2] = (b << 3) | (b >> 2);
                    rgba[out + 3] = 0xff;
                }
            }
        }
        24 => {
            // BGR, bottom-up.
            let expected = w * h * 3;
            if body.len() < expected {
                return Err(format!(
                    "24bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row;
                for col in 0..w {
                    let i = (src_row * w + col) * 3;
                    let out = (row * w + col) * 4;
                    rgba[out] = body[i + 2]; // R
                    rgba[out + 1] = body[i + 1]; // G
                    rgba[out + 2] = body[i]; // B
                    rgba[out + 3] = 0xff;
                }
            }
        }
        32 => {
            // BGRA (or BGRX). Bottom-up.
            let expected = w * h * 4;
            if body.len() < expected {
                return Err(format!(
                    "32bpp body short: have {} want {expected}",
                    body.len()
                ));
            }
            for row in 0..h {
                let src_row = h - 1 - row;
                for col in 0..w {
                    let i = (src_row * w + col) * 4;
                    let out = (row * w + col) * 4;
                    rgba[out] = body[i + 2];
                    rgba[out + 1] = body[i + 1];
                    rgba[out + 2] = body[i];
                    rgba[out + 3] = 0xff;
                }
            }
        }
        other => return Err(format!("uncompressed bpp={other} not supported")),
    }
    Ok(rgba)
}

// ─── RLE16 / RLE24 decoder ──────────────────────────────────────────
//
// Subset of MS-RDPEGDI § 3.1.9. We expose `decode_rle16` and
// `decode_rle24`; both operate over a generic per-pixel reader/writer
// and share the state machine. Opcode values + length encodings are
// taken from the spec; see the test module below for round-trip
// vectors against synthetic streams.

#[derive(Clone, Copy)]
enum Code {
    BgRun(usize),
    FgRun(usize),
    Color(usize),
    Fom(usize),
    SetFgFom(usize),
    Setfg(usize),
    /// Literal block of N pixels read raw from the input.
    Pixels(usize),
    WhiteRun(usize),
    BlackRun(usize),
    Done,
}

fn parse_code(input: &[u8], pos: &mut usize) -> Result<Code, String> {
    if *pos >= input.len() {
        return Ok(Code::Done);
    }
    let b = input[*pos];
    *pos += 1;
    // The encoding is a 3-bit "regular" opcode prefix + 5-bit length,
    // or a 5-bit "lite" opcode prefix + 3-bit length, or a "mega-mega"
    // form where the length is in a following u16. See MS-RDPEGDI
    // § 2.2.2.5.1.1.
    let regular_op = b >> 5;
    let regular_len = (b & 0x1f) as usize;
    match regular_op {
        0 => {
            // Background Run. length=0 → mega-mega
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("BG mega: short".into());
                }
                // For BG runs, the lite "no length" form means the
                // run length is read as a byte after the opcode.
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::BgRun(n))
            } else {
                Ok(Code::BgRun(regular_len))
            }
        }
        1 => {
            // Foreground Run.
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("FG mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::FgRun(n))
            } else {
                Ok(Code::FgRun(regular_len))
            }
        }
        2 => {
            // Color Run (single colored run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("Color mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::Color(n))
            } else {
                Ok(Code::Color(regular_len))
            }
        }
        3 => {
            // FOM (foreground-or-mix). Length-based per bitmask.
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("FOM mega: short".into());
                }
                let n = input[*pos] as usize + 1;
                *pos += 1;
                Ok(Code::Fom(n))
            } else {
                Ok(Code::Fom(regular_len))
            }
        }
        4 => {
            // SetFG (set foreground, then a foreground-or-mix run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("SetFgFom mega: short".into());
                }
                let n = input[*pos] as usize + 1;
                *pos += 1;
                Ok(Code::SetFgFom(n))
            } else {
                Ok(Code::SetFgFom(regular_len))
            }
        }
        5 => {
            // SetFG (set foreground colour, then a colored run).
            if regular_len == 0 {
                if *pos + 1 > input.len() {
                    return Err("Setfg mega: short".into());
                }
                let n = input[*pos] as usize + 32;
                *pos += 1;
                Ok(Code::Setfg(n))
            } else {
                Ok(Code::Setfg(regular_len))
            }
        }
        6 => {
            // Lite form: top 5 bits indicate the opcode subgroup.
            // Reuse high-bits decode here for the common Lite variants.
            let lite_op = (b >> 4) & 0x0f;
            let lite_len = (b & 0x0f) as usize;
            match lite_op {
                0xc => Ok(Code::WhiteRun(lite_len.max(1))),
                0xd => Ok(Code::BlackRun(lite_len.max(1))),
                _ => Ok(Code::Pixels(lite_len.max(1))),
            }
        }
        7 => {
            // Special MEGA_MEGA code: full u16 length follows.
            if *pos + 2 > input.len() {
                return Err("mega-mega: short".into());
            }
            let n = u16::from_le_bytes([input[*pos], input[*pos + 1]]) as usize;
            *pos += 2;
            // Subkind in low 5 bits.
            match regular_len & 0x1f {
                0 => Ok(Code::BgRun(n)),
                1 => Ok(Code::FgRun(n)),
                2 => Ok(Code::Color(n)),
                3 => Ok(Code::Fom(n)),
                4 => Ok(Code::SetFgFom(n)),
                5 => Ok(Code::Setfg(n)),
                _ => Ok(Code::Pixels(n)),
            }
        }
        _ => Err(format!("unknown RLE opcode {regular_op}")),
    }
}

fn decode_rle_generic<F>(
    width: u16,
    height: u16,
    body: &[u8],
    bpp_bytes: usize,
    mut read_pixel: F,
    bg_pixel: [u8; 4],
    fg_pixel_default: [u8; 4],
) -> Result<Vec<u8>, String>
where
    F: FnMut(&[u8], &mut usize) -> Result<[u8; 4], String>,
{
    let w = width as usize;
    let h = height as usize;
    let mut rgba = vec![0u8; w * h * 4];
    let mut pos = 0usize;
    let mut out = 0usize;
    let total = w * h;
    let mut fg = fg_pixel_default;
    // Most RLE encoders only set fg/bg once; we track current fg.
    let _ = bpp_bytes; // unused outside per-pixel reader

    while pos < body.len() && out < total {
        let code = parse_code(body, &mut pos)?;
        match code {
            Code::Done => break,
            Code::BgRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, bg_pixel);
                }
            }
            Code::FgRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, fg);
                }
            }
            Code::WhiteRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, [0xff, 0xff, 0xff, 0xff]);
                }
            }
            Code::BlackRun(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, [0, 0, 0, 0xff]);
                }
            }
            Code::Color(n) => {
                // Single color read once, then n times.
                let px = read_pixel(body, &mut pos)?;
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, px);
                }
            }
            Code::Setfg(n) => {
                fg = read_pixel(body, &mut pos)?;
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    write_px(&mut rgba, &mut out, fg);
                }
            }
            Code::Fom(n) | Code::SetFgFom(n) => {
                // Foreground-or-mix: mask bits indicate per-pixel
                // foreground (1) or background-XOR-mix (0). For our
                // subset we approximate mix as fg, which is correct
                // for the regular FOM variant when both fields match.
                let mask_bytes = (n + 7) / 8;
                if pos + mask_bytes > body.len() {
                    return Err("FOM mask short".into());
                }
                if matches!(code, Code::SetFgFom(_)) {
                    fg = read_pixel(body, &mut pos)?;
                }
                for i in 0..n {
                    if out >= total {
                        break;
                    }
                    let byte = body[pos + i / 8];
                    let bit = (byte >> (i & 7)) & 1;
                    let px = if bit == 1 { fg } else { bg_pixel };
                    write_px(&mut rgba, &mut out, px);
                }
                pos += mask_bytes;
            }
            Code::Pixels(n) => {
                for _ in 0..n {
                    if out >= total {
                        break;
                    }
                    let px = read_pixel(body, &mut pos)?;
                    write_px(&mut rgba, &mut out, px);
                }
            }
        }
    }
    // Pad any remaining pixels with bg.
    while out < total {
        write_px(&mut rgba, &mut out, bg_pixel);
    }
    // Flip vertically (RDP is bottom-up).
    let mut flipped = vec![0u8; w * h * 4];
    for row in 0..h {
        let src = (h - 1 - row) * w * 4;
        let dst = row * w * 4;
        flipped[dst..dst + w * 4].copy_from_slice(&rgba[src..src + w * 4]);
    }
    Ok(flipped)
}

fn write_px(rgba: &mut [u8], out: &mut usize, px: [u8; 4]) {
    let i = *out * 4;
    rgba[i] = px[0];
    rgba[i + 1] = px[1];
    rgba[i + 2] = px[2];
    rgba[i + 3] = px[3];
    *out += 1;
}

fn decode_rle16(width: u16, height: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    decode_rle_generic(
        width,
        height,
        body,
        2,
        |input: &[u8], pos: &mut usize| -> Result<[u8; 4], String> {
            if *pos + 2 > input.len() {
                return Err("rle16: short pixel".into());
            }
            let lo = input[*pos] as u16;
            let hi = input[*pos + 1] as u16;
            *pos += 2;
            let px = (hi << 8) | lo;
            let r = (((px >> 11) & 0x1f) << 3) as u8;
            let g = (((px >> 5) & 0x3f) << 2) as u8;
            let b = ((px & 0x1f) << 3) as u8;
            Ok([r, g, b, 0xff])
        },
        [0, 0, 0, 0xff],
        [0xff, 0xff, 0xff, 0xff],
    )
}

fn decode_rle24(width: u16, height: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    decode_rle_generic(
        width,
        height,
        body,
        3,
        |input: &[u8], pos: &mut usize| -> Result<[u8; 4], String> {
            if *pos + 3 > input.len() {
                return Err("rle24: short pixel".into());
            }
            let b = input[*pos];
            let g = input[*pos + 1];
            let r = input[*pos + 2];
            *pos += 3;
            Ok([r, g, b, 0xff])
        },
        [0, 0, 0, 0xff],
        [0xff, 0xff, 0xff, 0xff],
    )
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN_W: u16 = 1920;
    const SCREEN_H: u16 = 1080;

    /// The 8-byte rectangle header Rustion's `RdpRecorder` writes ahead
    /// of the pixel data on every graphics event
    /// (`x:u16 | y:u16 | w:u16 | h:u16`, per Rustion
    /// `docs/session-recording-format.md`). Fixtures must include it or
    /// they test a payload shape the recorder never produces.
    fn rec_rect_header(x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(REC_RECT_HEADER_LEN);
        v.extend_from_slice(&x.to_le_bytes());
        v.extend_from_slice(&y.to_le_bytes());
        v.extend_from_slice(&w.to_le_bytes());
        v.extend_from_slice(&h.to_le_bytes());
        v
    }

    fn build_record(events: &[(u64, u8, Vec<u8>)]) -> Vec<u8> {
        build_record_with_header(
            events,
            &format!(
                "{{\"version\":2,\"screen_width\":{SCREEN_W},\"screen_height\":{SCREEN_H}}}\n"
            ),
        )
    }

    fn build_record_with_header(events: &[(u64, u8, Vec<u8>)], header: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(header.as_bytes());
        for (ts, kind, payload) in events {
            out.extend_from_slice(&ts.to_le_bytes());
            out.push(*kind);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    fn build_graphics_uncompressed_24(
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        pixels: &[(u8, u8, u8)],
    ) -> Vec<u8> {
        // Recorder rect header, then the TS_BITMAP_DATA the recorder
        // copies out of the wire PDU starting at destLeft.
        let mut p = rec_rect_header(x, y, w, h);
        let right = x + w;
        let bottom = y + h;
        p.extend_from_slice(&x.to_le_bytes());
        p.extend_from_slice(&y.to_le_bytes());
        p.extend_from_slice(&right.to_le_bytes());
        p.extend_from_slice(&bottom.to_le_bytes());
        p.extend_from_slice(&w.to_le_bytes());
        p.extend_from_slice(&h.to_le_bytes());
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(&0u16.to_le_bytes()); // flags = uncompressed
        p.extend_from_slice(&((pixels.len() * 3) as u16).to_le_bytes());
        // Pixels are bottom-up BGR. The decoder will flip; we ship
        // them in top-down order here and reverse the rows ourselves.
        let mut bgr = Vec::with_capacity(pixels.len() * 3);
        let stride = w as usize;
        for row in 0..h as usize {
            let src_row = h as usize - 1 - row; // bottom-up
            for col in 0..stride {
                let (r, g, b) = pixels[src_row * stride + col];
                bgr.push(b);
                bgr.push(g);
                bgr.push(r);
            }
        }
        p.extend_from_slice(&bgr);
        p
    }

    #[test]
    fn uncompressed_24bpp_round_trip() {
        let pixels = vec![
            (0xff, 0, 0), (0, 0xff, 0),
            (0, 0, 0xff), (0xff, 0xff, 0xff),
        ];
        let g = build_graphics_uncompressed_24(10, 20, 2, 2, &pixels);
        let rec = build_record(&[(100, EVENT_GRAPHICS, g)]);
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.frames.len(), 1);
        let f = &out.frames[0];
        assert!(f.error.is_none(), "frame error: {:?}", f.error);
        assert_eq!(f.x, 10);
        assert_eq!(f.y, 20);
        assert_eq!(f.width, 2);
        assert_eq!(f.height, 2);
        assert_eq!(f.decoder, "uncompressed");
        assert_eq!(f.rgba.len(), 16);
        // top-left should be red after the flip
        assert_eq!(&f.rgba[0..4], &[0xff, 0, 0, 0xff]);
        // bottom-right white
        assert_eq!(&f.rgba[12..16], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn truncated_bitmap_body_reports_error_not_panic() {
        let mut p = rec_rect_header(0, 0, 10, 10);
        p.extend_from_slice(&0u16.to_le_bytes()); // destLeft
        p.extend_from_slice(&0u16.to_le_bytes()); // destTop
        p.extend_from_slice(&10u16.to_le_bytes()); // destRight
        p.extend_from_slice(&10u16.to_le_bytes()); // destBottom
        p.extend_from_slice(&10u16.to_le_bytes()); // width
        p.extend_from_slice(&10u16.to_le_bytes()); // height
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(&0u16.to_le_bytes()); // flags
        p.extend_from_slice(&300u16.to_le_bytes()); // claim 300 bytes
        // no body
        let rec = build_record(&[(0, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.frames.len(), 1);
        assert!(out.frames[0].error.is_some());
        assert!(out.frames[0].rgba.is_empty());
    }

    #[test]
    fn walk_skips_non_graphics() {
        let g = build_graphics_uncompressed_24(0, 0, 1, 1, &[(1, 2, 3)]);
        let rec = build_record(&[
            (1, EVENT_KEYBOARD, vec![0, 0, 0]),
            (2, EVENT_GRAPHICS, g),
            (3, EVENT_MOUSE, vec![0, 0, 0, 0, 0]),
        ]);
        let s = walk(&rec);
        assert_eq!(s.graphics, 1);
        assert_eq!(s.keyboard, 1);
        assert_eq!(s.mouse, 1);
        assert_eq!(s.event_count, 3);
        assert_eq!(s.duration_ms, 3);
    }

    #[test]
    fn unsupported_compressed_bpp_reports_unsupported() {
        // 8 bpp compressed → unsupported in Phase 8.4
        let mut p = rec_rect_header(0, 0, 1, 1);
        p.extend_from_slice(&0u16.to_le_bytes()); // dest
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes()); // width
        p.extend_from_slice(&1u16.to_le_bytes()); // height
        p.extend_from_slice(&8u16.to_le_bytes()); // bpp=8
        p.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        p.extend_from_slice(&1u16.to_le_bytes()); // bitmapLength
        p.push(0x00); // 1 byte body
        let rec = build_record(&[(5, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert_eq!(out.frames.len(), 1);
        let err = out.frames[0].error.as_ref().unwrap();
        assert!(err.starts_with("unsupported"), "got: {err}");
    }

    #[test]
    fn rle24_bg_run_paints_black() {
        // Build a 4x1 RLE24 stream: one regular BG run of length 4.
        // Opcode byte: 0b000_00100 = 0x04 = "BgRun(4)"
        let mut p = rec_rect_header(0, 0, 4, 1);
        p.extend_from_slice(&0u16.to_le_bytes()); // dest
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes()); // width
        p.extend_from_slice(&1u16.to_le_bytes()); // height
        p.extend_from_slice(&24u16.to_le_bytes()); // bpp
        p.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        p.extend_from_slice(&1u16.to_le_bytes()); // bitmapLength = 1 (just the opcode)
        p.push(0x04); // BgRun(4)
        let rec = build_record(&[(7, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert_eq!(out.frames.len(), 1);
        let f = &out.frames[0];
        assert!(f.error.is_none(), "{:?}", f.error);
        assert_eq!(f.decoder, "rle24");
        // 4 px * RGBA = 16 bytes, all black opaque
        assert_eq!(f.rgba.len(), 16);
        for chunk in f.rgba.chunks(4) {
            assert_eq!(chunk, &[0, 0, 0, 0xff]);
        }
    }

    #[test]
    fn decoder_counts_split_by_path() {
        let g_ok = build_graphics_uncompressed_24(0, 0, 1, 1, &[(1, 2, 3)]);
        let mut g_bad = rec_rect_header(0, 0, 1, 1);
        g_bad.extend_from_slice(&0u16.to_le_bytes());
        g_bad.extend_from_slice(&0u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.extend_from_slice(&8u16.to_le_bytes());
        g_bad.extend_from_slice(
            &(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        g_bad.extend_from_slice(&1u16.to_le_bytes());
        g_bad.push(0);
        let rec = build_record(&[
            (1, EVENT_GRAPHICS, g_ok),
            (2, EVENT_GRAPHICS, g_bad),
        ]);
        let out = decode(&rec);
        assert_eq!(*out.decoder_counts.get("uncompressed").unwrap_or(&0), 1);
        assert_eq!(*out.decoder_counts.get("unsupported").unwrap_or(&0), 1);
    }

    // ── Regressions from rec_1a1c7d52 (a real 1920×1080 recording in
    // which all 424 graphics events were false positives from the
    // bastion's bitmap-update scanner) ──────────────────────────────

    #[test]
    fn rejects_rect_outside_recorded_desktop() {
        // 63426×63193 at (63426, 63193) — the exact shape observed in
        // the field. Must be refused on geometry, before any
        // allocation: w*h*4 here is ~16 GB.
        let mut p = rec_rect_header(63426, 63193, 63426, 63193);
        p.extend_from_slice(&[0xab; 64]);
        let rec = build_record(&[(0, EVENT_GRAPHICS, p)]);
        let out = decode(&rec);
        assert!(out.ok);
        let err = out.frames[0].error.as_ref().unwrap();
        assert!(err.starts_with("invalid geometry"), "got: {err}");
        assert!(out.frames[0].rgba.is_empty());
        assert_eq!(*out.decoder_counts.get("invalid-geometry").unwrap_or(&0), 1);
        // Not lumped in with genuine decoder failures — an operator
        // needs to tell "the recorder wrote nonsense" apart from
        // "we can't decode this codec".
        assert_eq!(*out.decoder_counts.get("error").unwrap_or(&0), 0);
    }

    #[test]
    fn caps_rect_size_without_screen_size_in_header() {
        let mut p = rec_rect_header(0, 0, u16::MAX, u16::MAX);
        p.extend_from_slice(&[0u8; 64]);
        let rec = build_record_with_header(
            &[(0, EVENT_GRAPHICS, p)],
            "{\"version\":2}\n",
        );
        let out = decode(&rec);
        let err = out.frames[0].error.as_ref().unwrap();
        assert!(err.contains("cap"), "got: {err}");
        assert!(out.frames[0].rgba.is_empty());
    }

    #[test]
    fn classifies_real_graphics_event_from_rec_1a1c7d52() {
        // Captured verbatim from a production recording
        // (evdc400.fgv.br:3389, 1920×1080). The bastion tagged this as
        // a graphics update, but the bytes from offset 8 are the RDP
        // *connection sequence* — GCC ConnectData `00 05 00 14 7c 00 01`,
        // the "McDn" h221 key, then SC_CORE / SC_NET / SC_SECURITY.
        // There is no bitmap here.
        //
        // Read as a recorder rect header it claims 63230×255 at
        // (513,3), which cannot fit a 1920×1080 desktop.
        let ev1: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x00, 0xfe, 0xf6, 0xff, 0x00, 0x01, 0x02, 0x03, 0x00,
            0xff, 0xf8, 0x02, 0x01, 0x02, 0x04, 0x3e, 0x00, 0x05, 0x00, 0x14, 0x7c,
            0x00, 0x01, 0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00,
            0x4d, 0x63, 0x44, 0x6e, 0x28, 0x01, 0x0c, 0x10, 0x00, 0x11, 0x00, 0x08,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x0c, 0x0c,
            0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03, 0x00, 0x00, 0x02, 0x0c, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let out = decode(&build_record(&[(7, EVENT_GRAPHICS, ev1)]));
        let f = &out.frames[0];
        assert_eq!((f.x, f.y, f.width, f.height), (513, 3, 63230, 255));
        let err = f.error.as_ref().unwrap();
        assert!(err.starts_with("invalid geometry"), "got: {err}");
        assert!(f.rgba.is_empty());
        assert_eq!(*out.decoder_counts.get("invalid-geometry").unwrap_or(&0), 1);
    }

    #[test]
    fn bitmap_data_is_read_after_the_recorder_rect_header() {
        // Guards the actual bug: parsing at offset 0 makes the
        // recorder's x/y/w/h masquerade as
        // destLeft/destTop/destRight/destBottom and pushes every later
        // field 8 bytes out of place, so bpp comes from the wrong bytes.
        let g = build_graphics_uncompressed_24(
            10, 20, 2, 2,
            &[(0xff, 0, 0), (0, 0xff, 0), (0, 0, 0xff), (0xff, 0xff, 0xff)],
        );
        assert_eq!(&g[..REC_RECT_HEADER_LEN], &rec_rect_header(10, 20, 2, 2)[..]);
        let out = decode(&build_record(&[(0, EVENT_GRAPHICS, g)]));
        assert!(out.frames[0].error.is_none(), "{:?}", out.frames[0].error);
        assert_eq!(out.frames[0].bits_per_pixel, 24);
    }

    #[test]
    fn parse_header_fields_reads_the_header() {
        let f = parse_header_fields(
            "{\"version\":3,\"screen_width\":1920,\"screen_height\":1080,\"graphics_encodings\":[\"ts_update_bitmap\",\"rgba8888\"]}",
        );
        assert_eq!(f.version, 3);
        assert_eq!((f.screen_w, f.screen_h), (1920, 1080));
        assert_eq!(f.graphics_encodings, vec!["ts_update_bitmap", "rgba8888"]);

        // Absent fields read as zero / empty, never as a default that
        // would let a rectangle through unchecked.
        let f = parse_header_fields("{\"version\":2}");
        assert_eq!(f.version, 2);
        assert_eq!((f.screen_w, f.screen_h), (0, 0));
        assert!(f.graphics_encodings.is_empty());

        let f = parse_header_fields("not json");
        assert_eq!(f.version, 0);
        assert_eq!((f.screen_w, f.screen_h), (0, 0));

        // Unknown fields are ignored — the producer may add more.
        let f = parse_header_fields(
            "{\"version\":4,\"a_field_we_have_never_seen\":{\"nested\":true},\"screen_width\":8}",
        );
        assert_eq!(f.version, 4);
        assert_eq!(f.screen_w, 8);
    }

    // ── Version 1: metadata only ────────────────────────────────────

    #[test]
    fn version_1_renders_nothing_and_says_so() {
        // A payload that decodes cleanly at version 2. At version 1 the
        // bytes are an undelimited slice of the raw stream that only
        // *looks* like a bitmap, so it must not be painted.
        let g = build_graphics_uncompressed_24(
            10,
            20,
            2,
            2,
            &[(0xff, 0, 0), (0, 0xff, 0), (0, 0, 0xff), (0xff, 0xff, 0xff)],
        );
        let rec = build_record_with_header(
            &[
                (1, EVENT_GRAPHICS, g.clone()),
                (2, EVENT_GRAPHICS, g),
                (3, EVENT_KEYBOARD, vec![0x1e, 0x00, 1]),
            ],
            &format!(
                "{{\"version\":1,\"screen_width\":{SCREEN_W},\"screen_height\":{SCREEN_H}}}\n"
            ),
        );
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.version, 1);
        assert!(out.graphics_undecodable);
        // Zero rendered: no frames produced at all, not "frames with
        // errors" that a caller might try to paint.
        assert!(out.frames.is_empty());
        assert!(out.timeline.is_empty());
        assert_eq!(out.decoder_counts.get(COUNT_V1_UNDECODABLE), Some(&2));
        assert_eq!(out.decoder_counts.get(COUNT_UNCOMPRESSED), None);
        // Metadata is still meaningful.
        assert_eq!(out.keyboard_events, 1);
        assert_eq!(out.duration_ms, 3);
    }

    #[test]
    fn a_header_with_no_version_is_undecodable_not_version_3() {
        let rec = build_record_with_header(
            &[(1, EVENT_SURFACE, surface_payload(0, 0, 1, 1, &[0, 0, 0, 0], 1, 0))],
            "{\"screen_width\":8,\"screen_height\":8}\n",
        );
        let out = decode(&rec);
        assert_eq!(out.version, 0);
        assert!(out.graphics_undecodable);
        assert!(out.surface_updates[0]
            .error
            .as_deref()
            .unwrap()
            .contains("version-0 recording"));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_VERSION), Some(&1));
    }

    // ── Version 3: `0x07` decoded pixels ────────────────────────────

    /// RFC 1950 zlib stream wrapping RFC 1951 *stored* deflate blocks,
    /// built by hand.
    ///
    /// Deliberately not miniz_oxide: a fixture built with the same
    /// library the decoder inflates with would prove only that the
    /// library round trips. This is the wire format straight from the
    /// RFCs — CMF/FLG header, `BFINAL`/`BTYPE=00` block headers with
    /// LEN/NLEN, and an Adler-32 trailer the inflate must verify.
    fn zlib_stored(data: &[u8]) -> Vec<u8> {
        // CM=8 (deflate), CINFO=7 (32K window), FLEVEL=0, FDICT=0.
        // (0x78 << 8 | 0x01) % 31 == 0, which is the FCHECK rule.
        let mut out = vec![0x78u8, 0x01];
        if data.is_empty() {
            out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        } else {
            let mut chunks = data.chunks(0xffff).peekable();
            while let Some(chunk) = chunks.next() {
                out.push(u8::from(chunks.peek().is_none())); // BFINAL, BTYPE=00
                let len = chunk.len() as u16;
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(&(!len).to_le_bytes());
                out.extend_from_slice(chunk);
            }
        }
        out.extend_from_slice(&adler32(data).to_be_bytes());
        out
    }

    fn adler32(data: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in data {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    /// `x:u16 y:u16 w:u16 h:u16 format:u8 encoding:u8` + data.
    fn surface_payload(
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        data: &[u8],
        format: u8,
        encoding: u8,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(SURFACE_PREFIX_LEN + data.len());
        p.extend_from_slice(&x.to_le_bytes());
        p.extend_from_slice(&y.to_le_bytes());
        p.extend_from_slice(&w.to_le_bytes());
        p.extend_from_slice(&h.to_le_bytes());
        p.push(format);
        p.push(encoding);
        p.extend_from_slice(data);
        p
    }

    /// RGBA8888, row-major, top-down, no row padding.
    fn solid_rgba(w: u16, h: u16, px: [u8; 4]) -> Vec<u8> {
        px.iter()
            .copied()
            .cycle()
            .take(usize::from(w) * usize::from(h) * 4)
            .collect()
    }

    fn surface_event(
        ts: u64,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        rgba: &[u8],
        compress: bool,
    ) -> (u64, u8, Vec<u8>) {
        let (data, encoding) = if compress {
            (zlib_stored(rgba), SURFACE_ENCODING_ZLIB)
        } else {
            (rgba.to_vec(), SURFACE_ENCODING_RAW)
        };
        (
            ts,
            EVENT_SURFACE,
            surface_payload(x, y, w, h, &data, SURFACE_FORMAT_RGBA8888, encoding),
        )
    }

    fn v3_header(w: u16, h: u16) -> String {
        format!(
            "{{\"version\":3,\"session_id\":\"00000000-0000-4000-8000-000000000001\",\
             \"user\":\"tester\",\"target\":\"test-host:3389\",\
             \"screen_width\":{w},\"screen_height\":{h},\
             \"graphics_encodings\":[\"ts_update_bitmap\",\"rgba8888\"]}}\n"
        )
    }

    /// A software canvas, so the assertions are about pixels. Mirrors
    /// what the GUI does with `putImageData`: paint each region at
    /// (x, y) over whatever is already there, in timeline order; a
    /// `0x06` whose size differs resizes and clears.
    struct Canvas {
        w: usize,
        h: usize,
        px: Vec<u8>,
    }

    impl Canvas {
        fn at(&self, x: usize, y: usize) -> [u8; 4] {
            let o = (y * self.w + x) * 4;
            [self.px[o], self.px[o + 1], self.px[o + 2], self.px[o + 3]]
        }
    }

    fn replay(bytes: &[u8], out: &DecodeOutput) -> (Canvas, u64, std::collections::BTreeMap<String, u64>) {
        let mut canvas = Canvas {
            w: out.screen_width.max(1) as usize,
            h: out.screen_height.max(1) as usize,
            px: vec![0; (out.screen_width.max(1) * out.screen_height.max(1) * 4) as usize],
        };
        let mut painted = 0u64;
        let mut live: std::collections::BTreeMap<String, u64> = Default::default();
        for ev in &out.timeline {
            match ev {
                TimelineEvent::Desktop { desktop, .. } => {
                    let (w, h) = (usize::from(desktop.width), usize::from(desktop.height));
                    if w != canvas.w || h != canvas.h {
                        canvas = Canvas { w, h, px: vec![0; w * h * 4] };
                    }
                }
                TimelineEvent::Bitmap { index, .. } => {
                    let f = &out.frames[*index];
                    if f.error.is_none() && !f.rgba.is_empty() {
                        put(&mut canvas, &f.rgba, f.x, f.y, f.width, f.height);
                        painted += 1;
                    }
                }
                TimelineEvent::Surface { index, .. } => {
                    let u = &out.surface_updates[*index];
                    let r = decode_surface_update(bytes, u);
                    if u.error.is_none() {
                        *live.entry(r.count_key.clone()).or_insert(0) += 1;
                    }
                    if r.error.is_none() {
                        put(&mut canvas, &r.rgba, u.x, u.y, u.width, u.height);
                        painted += 1;
                    }
                }
            }
        }
        (canvas, painted, live)
    }

    fn put(canvas: &mut Canvas, rgba: &[u8], x: u16, y: u16, w: u16, h: u16) {
        for row in 0..usize::from(h) {
            let dy = usize::from(y) + row;
            if dy >= canvas.h {
                continue;
            }
            for col in 0..usize::from(w) {
                let dx = usize::from(x) + col;
                if dx >= canvas.w {
                    continue;
                }
                let s = (row * usize::from(w) + col) * 4;
                let d = (dy * canvas.w + dx) * 4;
                canvas.px[d..d + 4].copy_from_slice(&rgba[s..s + 4]);
            }
        }
    }

    #[test]
    fn surface_updates_paint_rgba_top_down_raw_and_zlib() {
        // Asymmetric, non-grey pattern: a BGRA or bottom-up bug cannot
        // pass.
        let red = solid_rgba(8, 8, [255, 0, 0, 255]); // zlib
        let blue = solid_rgba(4, 4, [0, 0, 255, 255]); // raw, under 512 bytes
        // Top row green, the rest black — catches bottom-up row order.
        let mut striped = solid_rgba(4, 4, [0, 0, 0, 255]);
        for i in 0..4 {
            striped[i * 4..i * 4 + 4].copy_from_slice(&[0, 255, 0, 255]);
        }
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 8, 8, &red, true),
                surface_event(200, 8, 0, 4, 4, &blue, false),
                surface_event(300, 0, 16, 4, 4, &striped, true),
            ],
            &v3_header(64, 48),
        );
        let out = decode(&rec);
        assert!(out.ok);
        assert_eq!(out.version, 3);
        assert_eq!(out.graphics_encodings, vec!["ts_update_bitmap", "rgba8888"]);
        assert_eq!(out.surface_updates.len(), 3);
        assert!(out.surface_updates.iter().all(|u| u.error.is_none()));
        // Both encodings really are both encodings.
        assert_eq!(
            out.surface_updates.iter().map(|u| u.encoding).collect::<Vec<_>>(),
            vec![1, 0, 1]
        );

        let (canvas, painted, live) = replay(&rec, &out);
        assert_eq!(painted, 3);
        assert_eq!(live.get(COUNT_SURFACE), Some(&3));
        // Red block: R first, not B.
        assert_eq!(canvas.at(0, 0), [255, 0, 0, 255]);
        assert_eq!(canvas.at(7, 7), [255, 0, 0, 255]);
        // Blue block from the raw region, at its own offset.
        assert_eq!(canvas.at(8, 0), [0, 0, 255, 255]);
        assert_eq!(canvas.at(11, 3), [0, 0, 255, 255]);
        // The green row is the *first* row of the region, painted at
        // the region's top (y = 16), with black beneath it.
        assert_eq!(canvas.at(0, 16), [0, 255, 0, 255]);
        assert_eq!(canvas.at(3, 16), [0, 255, 0, 255]);
        assert_eq!(canvas.at(0, 17), [0, 0, 0, 255]);
        // Untouched canvas stays untouched.
        assert_eq!(canvas.at(40, 40), [0, 0, 0, 0]);
    }

    #[test]
    fn overlapping_regions_apply_in_order() {
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 8, 8, &solid_rgba(8, 8, [255, 0, 0, 255]), true),
                surface_event(200, 0, 0, 4, 4, &solid_rgba(4, 4, [255, 255, 0, 255]), true),
            ],
            &v3_header(16, 16),
        );
        let out = decode(&rec);
        let (canvas, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 2);
        assert_eq!(canvas.at(0, 0), [255, 255, 0, 255]); // later write wins
        assert_eq!(canvas.at(3, 3), [255, 255, 0, 255]);
        assert_eq!(canvas.at(4, 0), [255, 0, 0, 255]); // red survives outside
        assert_eq!(canvas.at(7, 7), [255, 0, 0, 255]);
    }

    #[test]
    fn inflates_a_real_zlib_stream_not_just_stored_blocks() {
        // Produced by CPython's zlib (`zlib.compress(b"\x01\x02\x03\xff" * 16, 9)`),
        // i.e. a dynamic-Huffman block from a third implementation. The
        // stored-block fixtures above exercise the framing; this
        // exercises the inflate proper.
        const PY_ZLIB_4X4: &[u8] = &[
            0x78, 0xda, 0x63, 0x64, 0x62, 0xfe, 0xcf, 0x48, 0x01, 0x06, 0x00, 0xfa, 0x9f, 0x10,
            0x51,
        ];
        let rec = build_record_with_header(
            &[(
                100,
                EVENT_SURFACE,
                surface_payload(0, 0, 4, 4, PY_ZLIB_4X4, 1, 1),
            )],
            &v3_header(16, 16),
        );
        let out = decode(&rec);
        let render = decode_surface_update(&rec, &out.surface_updates[0]);
        assert_eq!(render.error, None);
        assert_eq!(render.rgba.len(), 4 * 4 * 4);
        assert_eq!(&render.rgba[..4], &[1, 2, 3, 255]);
        assert_eq!(render.count_key, COUNT_SURFACE);
    }

    #[test]
    fn unknown_event_type_is_skipped_and_the_walk_reaches_the_last_event() {
        // The forward-compatibility contract: this is what let version
        // 3 add 0x07 without breaking older players.
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [1, 2, 3, 255]), false),
                // An event type no version defines. Was `0x7F`
                // before version 4 claimed that for the keystroke
                // trailer; the point of the fixture is an *unknown*
                // type, so it moved rather than colliding with a
                // real one.
                (200, 0x5a, vec![0xab; 97]),
                surface_event(300, 4, 0, 4, 4, &solid_rgba(4, 4, [9, 8, 7, 255]), true),
            ],
            &v3_header(16, 16),
        );
        let out = decode(&rec);
        assert_eq!(out.truncated, None);
        assert_eq!(out.unknown_events, 1);
        assert_eq!(out.decoder_counts.get(COUNT_UNKNOWN_EVENT), Some(&1));
        assert_eq!(out.surface_updates.len(), 2);
        assert_eq!(out.duration_ms, 300); // reached the last event
        let (canvas, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 2);
        assert_eq!(canvas.at(0, 0), [1, 2, 3, 255]);
        assert_eq!(canvas.at(4, 0), [9, 8, 7, 255]);
    }

    #[test]
    fn a_mid_file_desktop_size_rebounds_validation_and_clears_the_canvas() {
        // 8×8 at (1000,700) does not fit the 640×480 header desktop but
        // does fit the 1600×1200 the `0x06` renegotiates to.
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [255, 0, 0, 255]), false),
                (
                    200,
                    EVENT_DESKTOP_SIZE,
                    [1600u16.to_le_bytes(), 1200u16.to_le_bytes()].concat(),
                ),
                surface_event(300, 1000, 700, 8, 8, &solid_rgba(8, 8, [0, 255, 0, 255]), true),
            ],
            &v3_header(640, 480),
        );
        let out = decode(&rec);
        assert_eq!(
            out.desktop_sizes,
            vec![DesktopSizeEvent { timestamp_ms: 200, width: 1600, height: 1200 }]
        );
        assert!(out.surface_updates[0].error.is_none());
        assert!(out.surface_updates[1].error.is_none());
        let (canvas, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 2);
        assert_eq!((canvas.w, canvas.h), (1600, 1200));
        // The resize cleared the canvas, so the pre-resize red is gone.
        assert_eq!(canvas.at(0, 0), [0, 0, 0, 0]);
        assert_eq!(canvas.at(1000, 700), [0, 255, 0, 255]);
    }

    #[test]
    fn a_surface_region_outside_the_desktop_is_still_rejected() {
        // The guardrail: adding 0x07 must not become a way to relax
        // geometry validation.
        let rec = build_record_with_header(
            &[
                surface_event(100, 600, 400, 64, 64, &solid_rgba(64, 64, [255, 0, 0, 255]), true),
                (200, EVENT_SURFACE, surface_payload(0, 0, 0, 8, &[], 1, 0)),
            ],
            &v3_header(640, 480),
        );
        let out = decode(&rec);
        let first = out.surface_updates[0].error.as_deref().unwrap();
        assert!(first.starts_with("invalid geometry"), "{first}");
        assert!(first.contains("640×480"), "{first}");
        assert!(out.surface_updates[1]
            .error
            .as_deref()
            .unwrap()
            .contains("zero-size"));
        assert_eq!(out.decoder_counts.get(COUNT_INVALID_GEOMETRY), Some(&2));
        let (_, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 0);
        // Rejected on geometry, never inflated, never confused with a
        // codec failure.
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_INFLATE_FAILED), None);
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_LENGTH), None);
    }

    #[test]
    fn a_surface_region_whose_length_disagrees_is_skipped_and_counted() {
        let rec = build_record_with_header(
            &[
                // Claims 8×8 (256 bytes), inflates to 4×4 (64).
                (
                    100,
                    EVENT_SURFACE,
                    surface_payload(0, 0, 8, 8, &zlib_stored(&solid_rgba(4, 4, [1, 1, 1, 255])), 1, 1),
                ),
                // Claims 4×4 (64 bytes), inflates to 8×8 (256).
                (
                    200,
                    EVENT_SURFACE,
                    surface_payload(0, 0, 4, 4, &zlib_stored(&solid_rgba(8, 8, [2, 2, 2, 255])), 1, 1),
                ),
                // Raw, wrong length — caught statically, without inflating.
                (300, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &[0u8; 63], 1, 0)),
            ],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        assert!(out.surface_updates[2]
            .error
            .as_deref()
            .unwrap()
            .contains("raw surface data is 63 bytes"));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_LENGTH), Some(&1));
        // The two zlib ones can only be caught by inflating.
        assert!(out.surface_updates[0].error.is_none());
        assert!(out.surface_updates[1].error.is_none());
        let (_, painted, live) = replay(&rec, &out);
        assert_eq!(painted, 0);
        assert_eq!(live.get(COUNT_SURFACE_BAD_LENGTH), Some(&2));
        assert_eq!(live.get(COUNT_SURFACE), None);

        let short = decode_surface_update(&rec, &out.surface_updates[0]);
        assert!(short.rgba.is_empty());
        assert!(short.error.as_deref().unwrap().contains("= 256"));
        let long = decode_surface_update(&rec, &out.surface_updates[1]);
        assert!(long.rgba.is_empty());
        assert!(long.error.as_deref().unwrap().contains("= 64"));
    }

    #[test]
    fn unknown_surface_format_and_encoding_are_rejected_without_guessing() {
        let rgba = solid_rgba(4, 4, [1, 2, 3, 255]);
        let rec = build_record_with_header(
            &[
                (100, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &rgba, 2, 0)),
                (200, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &rgba, 1, 9)),
                (300, EVENT_SURFACE, vec![0, 0, 0, 0, 4, 0]), // prefix truncated
            ],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        assert!(out.surface_updates[0]
            .error
            .as_deref()
            .unwrap()
            .contains("unknown surface format 2"));
        assert!(out.surface_updates[1]
            .error
            .as_deref()
            .unwrap()
            .contains("unknown surface encoding 9"));
        assert!(out.surface_updates[2]
            .error
            .as_deref()
            .unwrap()
            .contains("payload truncated"));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_FORMAT), Some(&1));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_ENCODING), Some(&1));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_TRUNCATED), Some(&1));
        assert_eq!(replay(&rec, &out).1, 0);
    }

    #[test]
    fn encoding_1_is_zlib_only_not_gzip_or_raw_deflate() {
        // A raw deflate stored block (no zlib wrapper) and a gzip
        // stream must both fail rather than being guessed at.
        let rgba = solid_rgba(4, 4, [1, 2, 3, 255]);
        let mut raw_deflate = vec![0x01u8];
        let len = rgba.len() as u16;
        raw_deflate.extend_from_slice(&len.to_le_bytes());
        raw_deflate.extend_from_slice(&(!len).to_le_bytes());
        raw_deflate.extend_from_slice(&rgba);
        let mut gzip = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
        gzip.extend_from_slice(&raw_deflate);
        let rec = build_record_with_header(
            &[
                (100, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &raw_deflate, 1, 1)),
                (200, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &gzip, 1, 1)),
            ],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        let (_, painted, live) = replay(&rec, &out);
        assert_eq!(painted, 0);
        assert_eq!(live.get(COUNT_SURFACE_INFLATE_FAILED), Some(&2));
    }

    #[test]
    fn a_corrupt_adler_checksum_is_an_inflate_failure() {
        // The zlib trailer is what makes `encoding = 1` verifiable.
        let mut z = zlib_stored(&solid_rgba(4, 4, [1, 2, 3, 255]));
        let last = z.len() - 1;
        z[last] ^= 0xff;
        let rec = build_record_with_header(
            &[(100, EVENT_SURFACE, surface_payload(0, 0, 4, 4, &z, 1, 1))],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        let r = decode_surface_update(&rec, &out.surface_updates[0]);
        assert!(r.rgba.is_empty());
        assert_eq!(r.count_key, COUNT_SURFACE_INFLATE_FAILED);
    }

    #[test]
    fn a_truncated_final_record_is_reported_not_painted() {
        let full = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [255, 0, 0, 255]), false),
                surface_event(200, 4, 0, 4, 4, &solid_rgba(4, 4, [0, 255, 0, 255]), false),
            ],
            &v3_header(64, 64),
        );
        let cut = &full[..full.len() - 20];
        let out = decode(cut);
        assert!(out.ok);
        // 20 bytes were cut from a 87-byte record, so 67 remain: the
        // note reports the trailing bytes it cannot frame, not the cut.
        let note = out.truncated.as_deref().unwrap();
        assert!(note.starts_with("truncated final record: 67 trailing bytes"), "{note}");
        // The complete prefix still replays; the partial record
        // produces no event at all.
        assert_eq!(out.surface_updates.len(), 1);
        let (canvas, painted, _) = replay(cut, &out);
        assert_eq!(painted, 1);
        assert_eq!(canvas.at(0, 0), [255, 0, 0, 255]);
        assert_eq!(canvas.at(4, 0), [0, 0, 0, 0]);

        // Truncating inside the 13-byte record header behaves the same.
        let cut2 = &full[..full.len() - 20 - 4 * 4 * 4 - 10 - 6];
        let out2 = decode(cut2);
        assert!(out2.ok);
        assert!(out2.truncated.is_some());
    }

    #[test]
    fn a_version_3_file_with_no_graphics_is_a_named_state() {
        let rec = build_record_with_header(
            &[
                (100, EVENT_KEYBOARD, vec![0x1e, 0x00, 1]),
                (200, EVENT_MOUSE, vec![10, 0, 20, 0, 0]),
                (
                    300,
                    EVENT_DESKTOP_SIZE,
                    [1920u16.to_le_bytes(), 1080u16.to_le_bytes()].concat(),
                ),
            ],
            &v3_header(SCREEN_W, SCREEN_H),
        );
        let out = decode(&rec);
        assert!(out.ok);
        assert!(out.graphics_not_recordable);
        assert!(!out.graphics_undecodable);
        assert!(out.frames.is_empty());
        assert!(out.surface_updates.is_empty());
        assert_eq!(out.keyboard_events, 1);
        assert_eq!(out.mouse_events, 1);
        assert_eq!(replay(&rec, &out).1, 0);
    }

    #[test]
    fn a_version_3_file_with_graphics_is_not_flagged_not_recordable() {
        let rec = build_record_with_header(
            &[surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [1, 2, 3, 255]), false)],
            &v3_header(64, 64),
        );
        assert!(!decode(&rec).graphics_not_recordable);
    }

    #[test]
    fn a_version_3_file_may_carry_both_event_types() {
        let g = build_graphics_uncompressed_24(
            0,
            0,
            2,
            2,
            &[(0xff, 0, 0), (0, 0xff, 0), (0, 0, 0xff), (0xff, 0xff, 0xff)],
        );
        let rec = build_record_with_header(
            &[
                (100, EVENT_GRAPHICS, g),
                surface_event(200, 8, 8, 4, 4, &solid_rgba(4, 4, [7, 7, 7, 255]), true),
            ],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        assert_eq!(out.frames.len(), 1);
        assert!(out.frames[0].error.is_none());
        assert_eq!(out.surface_updates.len(), 1);
        let (canvas, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 2);
        assert_eq!(canvas.at(0, 0), [255, 0, 0, 255]);
        assert_eq!(canvas.at(8, 8), [7, 7, 7, 255]);
    }

    #[test]
    fn a_surface_update_in_a_version_2_file_is_skipped() {
        let rec = build_record(&[surface_event(
            100,
            0,
            0,
            4,
            4,
            &solid_rgba(4, 4, [1, 2, 3, 255]),
            false,
        )]);
        let out = decode(&rec);
        assert_eq!(out.version, 2);
        assert!(out.surface_updates[0]
            .error
            .as_deref()
            .unwrap()
            .contains("version-2 recording"));
        assert_eq!(out.decoder_counts.get(COUNT_SURFACE_BAD_VERSION), Some(&1));
        assert_eq!(replay(&rec, &out).1, 0);
    }

    #[test]
    fn a_newer_format_version_decodes_what_it_understands() {
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [255, 0, 0, 255]), true),
                (200, 0x33, vec![1u8; 41]),
                surface_event(300, 4, 0, 4, 4, &solid_rgba(4, 4, [0, 255, 0, 255]), false),
            ],
            // Version 5 does not exist. It stands in for "produced
            // by a bastion newer than this decoder" — which was
            // version 4 until this decoder learned version 4.
            "{\"version\":5,\"screen_width\":64,\"screen_height\":64,\
             \"graphics_encodings\":[\"rgba8888\",\"some_future_thing\"],\
             \"a_field_we_have_never_seen\":{\"nested\":true}}\n",
        );
        let out = decode(&rec);
        assert_eq!(out.version, 5);
        assert!(out.newer_format);
        assert_eq!(out.unknown_events, 1);
        assert_eq!(out.truncated, None);
        let (canvas, painted, _) = replay(&rec, &out);
        assert_eq!(painted, 2);
        assert_eq!(canvas.at(0, 0), [255, 0, 0, 255]);
        assert_eq!(canvas.at(4, 0), [0, 255, 0, 255]);
    }

    #[test]
    fn a_full_desktop_region_is_indexed_without_inflating_it() {
        // 1920×1080×4 = 8.3 MB per region. The index must not hold
        // pixels, or a real session's ~450 regions would retain
        // gigabytes.
        let rgba = solid_rgba(1920, 1080, [17, 34, 51, 255]);
        let rec = build_record_with_header(
            &[surface_event(1000, 0, 0, 1920, 1080, &rgba, true)],
            &v3_header(SCREEN_W, SCREEN_H),
        );
        let out = decode(&rec);
        let u = &out.surface_updates[0];
        assert!(u.error.is_none());
        // The index is offsets, not pixels.
        assert_eq!(u.data_offset + u.data_len, rec.len());
        let render = decode_surface_update(&rec, u);
        assert_eq!(render.error, None);
        assert_eq!(render.rgba.len(), 1920 * 1080 * 4);
        assert_eq!(&render.rgba[..4], &[17, 34, 51, 255]);
    }

    #[test]
    fn walk_counts_every_event_kind() {
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [1, 2, 3, 255]), false),
                (200, EVENT_KEYBOARD, vec![0x1e, 0x00, 1]),
                (300, EVENT_MOUSE, vec![0, 0, 0, 0, 0]),
                (
                    400,
                    EVENT_DESKTOP_SIZE,
                    [64u16.to_le_bytes(), 64u16.to_le_bytes()].concat(),
                ),
                (500, 0x5a, vec![0xab; 3]),
            ],
            &v3_header(64, 64),
        );
        let s = walk(&rec);
        assert!(s.ok);
        assert_eq!(s.version, 3);
        assert_eq!(s.surface_updates, 1);
        assert_eq!(s.keyboard, 1);
        assert_eq!(s.mouse, 1);
        assert_eq!(s.desktop_sizes, 1);
        assert_eq!(s.unknown, 1);
        assert_eq!(s.event_count, 5);
        assert_eq!(s.bytes_parsed as usize, rec.len());
        assert_eq!(s.truncated, None);
    }

    // ── Version 4: the keystroke track is transparent to the video ──

    fn v4_header(w: u32, h: u32, keystrokes: bool) -> String {
        let ks = if keystrokes {
            "\"keystroke_metadata\":true,\"keyboard_layout\":\"0x00000416\",\
             \"keyboard_layout_source\":\"client_core\",\"max_reorder_ms\":2000"
        } else {
            "\"keystroke_metadata\":false,\"max_reorder_ms\":0"
        };
        format!(
            "{{\"version\":4,\"screen_width\":{w},\"screen_height\":{h},\
             \"graphics_encodings\":[\"ts_update_bitmap\",\"rgba8888\"],{ks}}}\n"
        )
    }

    /// `flags:u8 field_epoch:u32 char_count:u16 text_len:u16 text[]`.
    fn text_input_payload(flags: u8, epoch: u32, text: &str) -> Vec<u8> {
        let mut p = vec![flags];
        p.extend_from_slice(&epoch.to_le_bytes());
        p.extend_from_slice(&(text.chars().count() as u16).to_le_bytes());
        p.extend_from_slice(&(text.len() as u16).to_le_bytes());
        p.extend_from_slice(text.as_bytes());
        p
    }

    /// A `0x7F` payload: trailer JSON then the self-locating footer.
    fn trailer_payload(json: &str) -> Vec<u8> {
        let payload_len = json.len() + 8;
        let record_len = (13 + payload_len) as u32;
        let mut p = Vec::from(json.as_bytes());
        p.extend_from_slice(&record_len.to_le_bytes());
        p.extend_from_slice(b"RKTR");
        p
    }

    const TRAILER_JSON: &str = r#"{"trailer_version":1,"text_decoding":"exact","runs":[{"t":150,"d":20,"n":2,"text":"hi","redacted":false,"epoch":1}],"search_text":"hi","census":{}}"#;

    #[test]
    fn a_version_4_file_renders_its_graphics_identically_to_version_3() {
        // The acceptance criterion: `0x08` and `0x7F` are transparent
        // to the video path. Same graphics records, one file with a
        // keystroke track interleaved and one without, identical
        // canvas.
        let graphics = || {
            vec![
                surface_event(100, 0, 0, 8, 8, &solid_rgba(8, 8, [255, 0, 0, 255]), true),
                (
                    200,
                    EVENT_DESKTOP_SIZE,
                    [64u16.to_le_bytes(), 64u16.to_le_bytes()].concat(),
                ),
                surface_event(300, 8, 0, 8, 8, &solid_rgba(8, 8, [0, 255, 0, 255]), false),
                surface_event(400, 0, 8, 8, 8, &solid_rgba(8, 8, [0, 0, 255, 255]), true),
            ]
        };
        let g = graphics();
        let v3 = build_record_with_header(&g, &v3_header(64, 64));
        let v4 = build_record_with_header(
            &[
                g[0].clone(),
                // Stamped *earlier* than the graphics around it —
                // version 4's non-monotonic stream.
                (150, EVENT_TEXT_INPUT, text_input_payload(0x08, 1, "hi")),
                g[1].clone(),
                g[2].clone(),
                (350, EVENT_TEXT_INPUT, text_input_payload(0x09, 2, "")),
                g[3].clone(),
                (
                    500,
                    EVENT_KEYSTROKE_TRAILER,
                    trailer_payload(TRAILER_JSON),
                ),
            ],
            &v4_header(64, 64, true),
        );

        let out3 = decode(&v3);
        let out4 = decode(&v4);
        let (canvas3, painted3, _) = replay(&v3, &out3);
        let (canvas4, painted4, _) = replay(&v4, &out4);
        assert_eq!(painted4, painted3);
        assert_eq!(canvas4.px, canvas3.px);
        assert_eq!(out4.surface_updates.len(), out3.surface_updates.len());
        assert_eq!(out4.desktop_sizes, out3.desktop_sizes);
        assert_eq!(out4.timeline.len(), out3.timeline.len());
        assert_eq!(
            out4.decoder_counts.get(COUNT_SURFACE),
            out3.decoder_counts.get(COUNT_SURFACE)
        );
    }

    #[test]
    fn keystroke_records_are_counted_not_filed_as_unknown() {
        let rec = build_record_with_header(
            &[
                surface_event(100, 0, 0, 4, 4, &solid_rgba(4, 4, [1, 2, 3, 255]), false),
                (150, EVENT_TEXT_INPUT, text_input_payload(0x08, 1, "hi")),
                (250, EVENT_TEXT_INPUT, text_input_payload(0x09, 2, "")),
                (500, EVENT_KEYSTROKE_TRAILER, trailer_payload(TRAILER_JSON)),
            ],
            &v4_header(64, 64, true),
        );
        let out = decode(&rec);
        assert_eq!(out.version, 4);
        assert!(!out.newer_format);
        assert_eq!(out.text_input_events, 2);
        assert!(out.keystroke_trailer);
        assert!(out.keystroke_metadata);
        assert_eq!(out.max_reorder_ms, 2000);
        // Known types now, so they do not inflate the unknown count.
        assert_eq!(out.unknown_events, 0);
        assert_eq!(out.decoder_counts.get(COUNT_UNKNOWN_EVENT), None);
        assert_eq!(out.truncated, None);
    }

    #[test]
    fn keystroke_metadata_false_is_distinguishable_from_absent() {
        // Both read as `false`, but the version tells them apart, and
        // neither may be rendered as "nothing was typed".
        let off = decode(&build_record_with_header(&[], &v4_header(64, 64, false)));
        assert_eq!(off.version, 4);
        assert!(!off.keystroke_metadata);
        assert_eq!(off.max_reorder_ms, 0);

        let v3 = decode(&build_record_with_header(&[], &v3_header(64, 64)));
        assert_eq!(v3.version, 3);
        assert!(!v3.keystroke_metadata);
    }

    #[test]
    fn duration_is_the_maximum_timestamp_not_the_last_one() {
        // Version 4's records are not monotonic: a keystroke record
        // written last but stamped early must not shorten the
        // recording.
        let rec = build_record_with_header(
            &[
                surface_event(9_000, 0, 0, 4, 4, &solid_rgba(4, 4, [1, 2, 3, 255]), false),
                (1_000, EVENT_TEXT_INPUT, text_input_payload(0x08, 1, "hi")),
            ],
            &v4_header(64, 64, true),
        );
        assert_eq!(decode(&rec).duration_ms, 9_000);
        assert_eq!(walk(&rec).duration_ms, 9_000);
    }

    #[test]
    fn a_keystroke_record_in_a_version_3_file_is_refused() {
        // A `0x08` at version 3 contradicts its own header. Counted
        // in its own bucket rather than read.
        let rec = build_record_with_header(
            &[
                (150, EVENT_TEXT_INPUT, text_input_payload(0x08, 1, "hi")),
                (500, EVENT_KEYSTROKE_TRAILER, trailer_payload(TRAILER_JSON)),
            ],
            &v3_header(64, 64),
        );
        let out = decode(&rec);
        assert_eq!(out.text_input_events, 0);
        assert!(!out.keystroke_trailer);
        assert_eq!(
            out.decoder_counts.get(COUNT_KEYSTROKE_BAD_VERSION),
            Some(&2)
        );
    }
}
