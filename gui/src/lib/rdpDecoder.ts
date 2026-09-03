// RDP `.rdp-rec` decoder — TypeScript port of
// `gui/wasm/rdp-replay/src/lib.rs`.
//
// The Rust crate is the canonical, unit-tested reference
// implementation. This file mirrors it 1:1 so the GUI can run in the
// browser without a wasm-bindgen build step. If you change one, change
// the other; the Rust tests are the spec.
//
// ## File layout (all versions)
//
//     [4]   magic "RREC"
//     [..]  JSON header, one line
//     [1]   '\n'
//     [..]  event records until EOF
//
// Every event record:
//
//     [u64 LE] timestamp_ms   elapsed ms since session start
//     [u8]     event_type
//     [u32 LE] payload_len
//     [..]     payload
//
// Records tile the file exactly. Unknown `event_type` values are
// skipped using `payload_len` — that is the format's forward
// compatibility contract, and version 3 relies on it.
//
// ## Version dispatch
//
// | version | geometry                     | `0x01`                | `0x07` |
// |---------|------------------------------|-----------------------|--------|
// | 1       | hardcoded 1920x1080 constant | undelimited raw stream slice — **not decodable** | — |
// | 2       | negotiated desktop, 0=unknown| exactly one TS_BITMAP_DATA | — |
// | 3       | as version 2                 | as version 2          | decoded pixels |
// | 4       | as version 2                 | as version 2          | as version 3   |
//
// Version 4 adds the keystroke track (`0x08` text input) and the
// keystroke trailer (`0x7F`) and changes **nothing** about graphics.
// Both new records are read by `gui/src/lib/rdpKeystrokes.ts`; this
// file counts them so the player can report them, and skips their
// payloads by `payload_len` exactly as it would any unknown type.
//
// ## Version 4 breaks monotonicity — and the video path is unaffected
//
// From version 4, `timestamp_ms` is **not monotonic across records**:
// `0x02` and `0x08` are buffered by the recorder until their run
// closes, so they are written after graphics records bearing later
// timestamps. The header declares the bound as `max_reorder_ms`.
//
// `0x01`, `0x03`, `0x06` and `0x07` remain monotonic *among
// themselves*, so `timeline` — which holds only those — is still
// correctly ordered and the player needs no change. Two things here
// had to stop assuming a globally sorted stream: `durationMs` is now
// the maximum timestamp rather than the last one seen, and nothing
// asserts monotonicity anywhere. Do not add such an assertion; it
// would fire on a valid version-4 file.
//
// Version 1 recordings were produced by a recording tap that parsed
// unframed TCP chunks with a frame gate accepting about a quarter of
// all bytes: forensics on three real recordings found 0 of 1779
// graphics events carrying a self-consistent `TS_BITMAP_DATA`, at a
// median payload entropy of 7.75 bits/byte (compressed codec bytes,
// not pixels). We therefore do not attempt to decode `0x01` at
// version 1 at all — rendering those slabs could only paint noise.
// The player says so instead of showing an empty canvas.
//
// Version 3 is purely additive over version 2: no existing event type
// or field changed. Its `0x07` surface updates carry pixels that the
// producer decoded client-side (ironrdp `ActiveStage` + the EGFX
// pipeline over drdynvc, including zgfx and the RemoteFX / planar /
// NSCodec / progressive codecs), precisely so that this side needs no
// codec stack. **Do not add an RDP codec here.**
//
// ## What the `0x01` path implements (versions >= 2)
//
// MS-RDPBCGR 2.2.9.1.1.3.1.2.2 + MS-RDPEGDI 3.1.9:
//   - `TS_BITMAP_DATA` parser (one rect per event)
//   - Uncompressed 16/24/32 bpp -> RGBA, top-down
//   - RLE16 / RLE24 (Bg/Fg/Color/FOM/SetFgFom/Setfg/Pixels/White/
//     Black + mega-mega forms)
// Out of scope on this path: 8 bpp RLE, NSCodec, RemoteFX,
// bitmap-cache references. A modern Windows target does not use the
// legacy `TS_UPDATE_BITMAP` path at all — it draws over surface
// commands or RDP 8+ EGFX — which is why version 3 exists.

import { unzlibSync } from "fflate";

const MAGIC = new Uint8Array([0x52, 0x52, 0x45, 0x43]); // "RREC"

const EVENT_GRAPHICS = 0x01;
const EVENT_KEYBOARD = 0x02;
const EVENT_MOUSE = 0x03;
const EVENT_TITLE = 0x04;
const EVENT_CLIPBOARD = 0x05;
const EVENT_DESKTOP_SIZE = 0x06;
const EVENT_SURFACE = 0x07;
/// Version 4: a keystroke run's decoded text. Read by
/// `rdpKeystrokes.ts`; counted here, payload skipped.
const EVENT_TEXT_INPUT = 0x08;
/// Version 4: the keystroke trailer, always the last record. Read by
/// `rdpKeystrokes.ts` via its self-locating footer; counted here.
const EVENT_KEYSTROKE_TRAILER = 0x7f;

const BITMAP_COMPRESSION = 0x0001;
const NO_BITMAP_COMPRESSION_HDR = 0x0400;

/// Size of the recorder's own `x/y/w/h` rectangle header that precedes
/// the `TS_BITMAP_DATA` in every `0x01` payload.
const REC_RECT_HEADER_LEN = 8;

/// `0x07` payload prefix: `x:u16 y:u16 w:u16 h:u16 format:u8 encoding:u8`.
const SURFACE_PREFIX_LEN = 10;

/// `0x07` `format` values we know. 1 = 4 bytes per pixel in R,G,B,A
/// order, row-major, top-down, no row padding. Not BGRA, not
/// bottom-up.
const SURFACE_FORMAT_RGBA8888 = 1;

/// `0x07` `encoding` values we know.
const SURFACE_ENCODING_RAW = 0;
const SURFACE_ENCODING_ZLIB = 1;

const BYTES_PER_PIXEL = 4;

/// Highest `.rdp-rec` header version this decoder fully understands.
/// A higher version still parses — unknown event types are skipped by
/// `payload_len` — but the player says the file came from a newer
/// bastion so an operator knows the replay may be incomplete.
export const MAX_SUPPORTED_VERSION = 4;

/// First version whose `0x01` payload is a real `TS_BITMAP_DATA`.
const FIRST_DECODABLE_BITMAP_VERSION = 2;

/// First version that carries decoded pixels in `0x07`.
const FIRST_SURFACE_VERSION = 3;

/// First version that can carry a keystroke track (`0x08` + `0x7F`).
export const FIRST_KEYSTROKE_VERSION = 4;

/// Ceiling on a single rectangle's pixel count when no desktop size is
/// available (header `0x0` and no `0x06` seen yet). 8192x8192 is far
/// above any real RDP desktop and caps the RGBA allocation at 256 MiB.
///
/// Without a bound, a rectangle whose dimensions decode to garbage
/// (63426 x 63193 has been observed in the field) makes the decoder
/// ask for ~16 GB and take down the replay window with an allocation
/// failure. Recording bytes come from the bastion, so these fields are
/// attacker-influenced input. This is a floor on strictness, not a
/// substitute for the desktop check — it applies *only* when there is
/// no desktop size to check against.
const MAX_RECT_PIXELS = 8192 * 8192;

// ─── Skip-reason taxonomy ───────────────────────────────────────────
//
// Every graphics event that is not painted lands in exactly one of
// these buckets. The player renders them as
// "N rendered · M skipped · dominant reason: <key>" — that reporting
// is what turned the black-canvas bug from invisible into diagnosable,
// so keep the buckets distinct and never fold one into another.

/// `0x01`, painted.
export const COUNT_UNCOMPRESSED = "uncompressed";
export const COUNT_RLE16 = "rle16";
export const COUNT_RLE24 = "rle24";
/// `0x07`, painted.
export const COUNT_SURFACE = "surface-rgba8888";

/// `0x01` at version 1: raw stream slabs from the broken tap. Never decoded.
export const COUNT_V1_UNDECODABLE = "version-1-undecodable";
/// `0x01` hit a codec this side does not implement (8 bpp RLE, NSCodec, …).
export const COUNT_UNSUPPORTED = "unsupported";
/// Rectangle does not fit the desktop, or is zero-sized, or blows the cap.
export const COUNT_INVALID_GEOMETRY = "invalid-geometry";
/// `0x01` parse failure (truncated header/body, short pixel run).
export const COUNT_ERROR = "error";

/// `0x07` seen in a file whose header version predates it.
export const COUNT_SURFACE_BAD_VERSION = "surface-unexpected-version";
/// `0x07` payload shorter than its own 10-byte prefix.
export const COUNT_SURFACE_TRUNCATED = "surface-truncated";
/// `0x07` `format` byte we do not know.
export const COUNT_SURFACE_BAD_FORMAT = "surface-unknown-format";
/// `0x07` `encoding` byte we do not know.
export const COUNT_SURFACE_BAD_ENCODING = "surface-unknown-encoding";
/// `0x07` data length (raw) or inflated length (zlib) != w * h * 4.
export const COUNT_SURFACE_BAD_LENGTH = "surface-length-mismatch";
/// `0x07` zlib stream would not inflate.
export const COUNT_SURFACE_INFLATE_FAILED = "surface-inflate-failed";

/// An `event_type` this decoder does not know. Skipped by
/// `payload_len` and counted, never an error: that is how version 3
/// was able to add `0x07` without breaking older players, and how
/// version 4 added `0x08` and `0x7F`.
export const COUNT_UNKNOWN_EVENT = "unknown-event";

/// `0x08` / `0x7F` seen in a file whose header version predates them.
/// Counted rather than parsed: a keystroke record contradicting its
/// own header is a file we do not trust to describe itself, and
/// silently reading it would be a fallback on an audit surface.
export const COUNT_KEYSTROKE_BAD_VERSION = "keystroke-unexpected-version";

export interface DecodedFrame {
  timestampMs: number;
  x: number;
  y: number;
  width: number;
  height: number;
  bitsPerPixel: number;
  compressed: boolean;
  decoder: "uncompressed" | "rle16" | "rle24" | "none";
  rgba: Uint8ClampedArray; // empty if error
  error: string | null;
}

/// A `0x07` surface update, indexed but **not** inflated.
///
/// Pixels stay in the file until the player reaches the event: a
/// 454 s session at the producer's default 1000 ms interval is ~450
/// dirty regions, and eagerly inflating 450 full-desktop regions at
/// 1920 x 1080 x 4 would retain 3.7 GB. `renderSurfaceUpdate` inflates
/// one region at a time, and the player discards it after the blit.
export interface SurfaceUpdate {
  timestampMs: number;
  x: number;
  y: number;
  width: number;
  height: number;
  format: number;
  encoding: number;
  /// Offset of the pixel bytes within the whole `.rdp-rec` buffer.
  dataOffset: number;
  dataLen: number;
  /// Set when static validation already rejected this update; it will
  /// never be painted and is already counted. `null` means "passed
  /// everything checkable without inflating".
  error: string | null;
  /// The bucket this update was counted in when `error` is set.
  countKey: string | null;
}

/// A `0x06` desktop-size event. A size differing from the current
/// canvas means the canvas is resized and treated as cleared.
export interface DesktopSizeEvent {
  timestampMs: number;
  width: number;
  height: number;
}

/// The ordered playback timeline. `0x06` must be applied in file order
/// relative to the paints around it, so the player walks one list
/// rather than merging three.
export type TimelineEvent =
  | { kind: "bitmap"; timestampMs: number; frame: DecodedFrame }
  | { kind: "surface"; timestampMs: number; update: SurfaceUpdate }
  | { kind: "desktop"; timestampMs: number; desktop: DesktopSizeEvent };

export interface DecodeResult {
  ok: boolean;
  error: string | null;
  headerJson: string | null;
  /// Header `version`, or 0 when the header carries no numeric version.
  version: number;
  /// Header `screen_width` / `screen_height`. `0` means unknown — the
  /// producer could not determine the geometry before writing the
  /// header. Never treat `0x0` as a valid desktop size.
  screenWidth: number;
  screenHeight: number;
  /// Header `graphics_encodings`: which encodings the producer could
  /// emit, hence which event types to expect.
  graphicsEncodings: string[];
  /// Version 1: `0x01` payloads are undelimited raw stream slices and
  /// are not decodable. Metadata is still meaningful.
  graphicsUndecodable: boolean;
  /// Header version above `MAX_SUPPORTED_VERSION`.
  newerFormat: boolean;
  /// Version >= 3 with zero `0x01` and zero `0x07` events. A real
  /// state, not a parse failure: the session's graphics could not be
  /// decoded on the bastion (the remaining known cause is AVC420 /
  /// AVC444 over EGFX, which the producer counts but does not decode).
  graphicsNotRecordable: boolean;
  /// `0x01` frames, in file order. Version >= 2 only.
  frames: DecodedFrame[];
  /// `0x07` updates, in file order, pixels not yet inflated.
  surfaceUpdates: SurfaceUpdate[];
  /// `0x06` events, in file order.
  desktopSizes: DesktopSizeEvent[];
  /// Everything the player has to walk in order.
  timeline: TimelineEvent[];
  keyboardEvents: number;
  mouseEvents: number;
  titleEvents: number;
  clipboardEvents: number;
  unknownEvents: number;
  /// Version 4 `0x08` text-input records. A count only — the text is
  /// read by `rdpKeystrokes.ts`, which is the module that carries the
  /// redaction rules.
  textInputEvents: number;
  /// Whether a `0x7F` keystroke trailer record was seen while
  /// walking. `rdpKeystrokes.readTrailer` finds it by tail-seek and
  /// does not need this; the player reports it.
  keystrokeTrailer: boolean;
  /// Header `keystroke_metadata`. `false` means keystroke recording
  /// was **off for this session** — never that nobody typed.
  keystrokeMetadata: boolean;
  /// Header `keyboard_layout` (a Windows KLID hex string) and
  /// `keyboard_layout_source` (`client_core` | `config` |
  /// `fallback`). `null` when absent.
  keyboardLayout: string | null;
  keyboardLayoutSource: string | null;
  /// Header `max_reorder_ms`: the bound on how far out of order a
  /// keystroke record may appear. `0` on version <= 3 and whenever
  /// `keystrokeMetadata` is false.
  maxReorderMs: number;
  /// The maximum `timestamp_ms` over every record, not the last one
  /// seen — version 4's stream is not monotonic.
  durationMs: number;
  /// Trailing bytes that do not form a complete record. The prefix
  /// before them is still valid and still replayed; a truncated
  /// recording must replay what it has, loudly, rather than silently
  /// dropping to nothing or painting half a record.
  truncated: string | null;
  decoderCounts: Record<string, number>;
}

interface HeaderFields {
  version: number;
  screenW: number;
  screenH: number;
  graphicsEncodings: string[];
  /// Version 4 keystroke fields. Absent (version <= 3) reads as
  /// `keystrokeMetadata: false` / `maxReorderMs: 0`, which is exactly
  /// how those files must read.
  keystrokeMetadata: boolean;
  keyboardLayout: string | null;
  keyboardLayoutSource: string | null;
  maxReorderMs: number;
}

export function decodeRdpRec(bytes: Uint8Array): DecodeResult {
  const headerOut = parseHeader(bytes);
  if ("error" in headerOut) return decodeErr(headerOut.error);
  const { header, start } = headerOut;
  const fields = parseHeaderFields(header);

  const frames: DecodedFrame[] = [];
  const surfaceUpdates: SurfaceUpdate[] = [];
  const desktopSizes: DesktopSizeEvent[] = [];
  const timeline: TimelineEvent[] = [];
  const counts: Record<string, number> = {};
  const bump = (key: string) => {
    counts[key] = (counts[key] ?? 0) + 1;
  };

  let keyboard = 0;
  let mouse = 0;
  let title = 0;
  let clipboard = 0;
  let unknown = 0;
  let textInput = 0;
  let keystrokeTrailer = false;
  // Version 4's records are not monotonic, so the duration is the
  // maximum timestamp, not the last one seen. A keystroke record
  // written late but stamped early must not shorten the recording.
  let maxTs = 0;
  let graphicsEvents = 0;

  // The desktop in force at this point in the file: the most recent
  // `0x06`, falling back to the header. `0/0` means "no bound
  // available" and the per-rect cap applies instead.
  let deskW = fields.screenW;
  let deskH = fields.screenH;

  let pos = start;
  while (pos + 13 <= bytes.length) {
    const ts = readU64Le(bytes, pos);
    const kind = bytes[pos + 8];
    const len = readU32Le(bytes, pos + 9);
    const dataStart = pos + 13;
    const next = dataStart + len;
    if (next > bytes.length) break; // trailing partial record; reported below
    const payload = bytes.subarray(dataStart, next);
    if (ts > maxTs) maxTs = ts;

    switch (kind) {
      case EVENT_GRAPHICS: {
        graphicsEvents += 1;
        if (fields.version < FIRST_DECODABLE_BITMAP_VERSION) {
          // Version 1: an undelimited slice of the raw byte stream.
          // Not a codec we lack — not pixels at all.
          bump(COUNT_V1_UNDECODABLE);
          break;
        }
        const f = decodeGraphics(ts, payload, deskW, deskH);
        bump(bitmapCountKey(f));
        frames.push(f);
        timeline.push({ kind: "bitmap", timestampMs: ts, frame: f });
        break;
      }
      case EVENT_SURFACE: {
        graphicsEvents += 1;
        const u = indexSurfaceUpdate(
          ts,
          payload,
          dataStart,
          fields.version,
          deskW,
          deskH,
        );
        if (u.countKey !== null) bump(u.countKey);
        surfaceUpdates.push(u);
        timeline.push({ kind: "surface", timestampMs: ts, update: u });
        break;
      }
      case EVENT_DESKTOP_SIZE: {
        if (payload.length < 4) {
          // Not a graphics event; a malformed one tells us nothing
          // about geometry, so leave the current desktop in force
          // rather than guessing at a new one.
          bump(COUNT_ERROR);
          break;
        }
        const w = readU16Le(payload, 0);
        const h = readU16Le(payload, 2);
        const d: DesktopSizeEvent = { timestampMs: ts, width: w, height: h };
        deskW = w;
        deskH = h;
        desktopSizes.push(d);
        timeline.push({ kind: "desktop", timestampMs: ts, desktop: d });
        break;
      }
      case EVENT_KEYBOARD:
        keyboard += 1;
        break;
      case EVENT_MOUSE:
        mouse += 1;
        break;
      case EVENT_TITLE:
        title += 1;
        break;
      case EVENT_CLIPBOARD:
        clipboard += 1;
        break;
      case EVENT_TEXT_INPUT:
        // Version 4 keystroke text. Counted here; the payload is
        // decoded by `rdpKeystrokes.ts`, which is where the
        // redaction rules live. A `0x08` in a file whose header
        // predates version 4 contradicts its own header, so it is
        // counted in its own bucket rather than folded into the
        // ordinary count.
        if (fields.version < FIRST_KEYSTROKE_VERSION) {
          bump(COUNT_KEYSTROKE_BAD_VERSION);
          break;
        }
        textInput += 1;
        break;
      case EVENT_KEYSTROKE_TRAILER:
        if (fields.version < FIRST_KEYSTROKE_VERSION) {
          bump(COUNT_KEYSTROKE_BAD_VERSION);
          break;
        }
        keystrokeTrailer = true;
        break;
      default:
        // Forward compatibility: skip by `payload_len` and count.
        unknown += 1;
        bump(COUNT_UNKNOWN_EVENT);
        break;
    }
    pos = next;
  }

  const leftover = bytes.length - pos;
  const truncated =
    leftover > 0
      ? `truncated final record: ${leftover} trailing byte${leftover === 1 ? "" : "s"} do not form a complete (ts:u64, type:u8, len:u32, payload) record`
      : null;

  return {
    ok: true,
    error: null,
    headerJson: header,
    version: fields.version,
    screenWidth: fields.screenW,
    screenHeight: fields.screenH,
    graphicsEncodings: fields.graphicsEncodings,
    graphicsUndecodable: fields.version < FIRST_DECODABLE_BITMAP_VERSION,
    newerFormat: fields.version > MAX_SUPPORTED_VERSION,
    graphicsNotRecordable:
      fields.version >= FIRST_SURFACE_VERSION && graphicsEvents === 0,
    frames,
    surfaceUpdates,
    desktopSizes,
    timeline,
    keyboardEvents: keyboard,
    mouseEvents: mouse,
    titleEvents: title,
    clipboardEvents: clipboard,
    unknownEvents: unknown,
    textInputEvents: textInput,
    keystrokeTrailer,
    keystrokeMetadata: fields.keystrokeMetadata,
    keyboardLayout: fields.keyboardLayout,
    keyboardLayoutSource: fields.keyboardLayoutSource,
    maxReorderMs: fields.maxReorderMs,
    durationMs: maxTs,
    truncated,
    decoderCounts: counts,
  };
}

function decodeErr(msg: string): DecodeResult {
  return {
    ok: false,
    error: msg,
    headerJson: null,
    version: 0,
    screenWidth: 0,
    screenHeight: 0,
    graphicsEncodings: [],
    graphicsUndecodable: false,
    newerFormat: false,
    graphicsNotRecordable: false,
    frames: [],
    surfaceUpdates: [],
    desktopSizes: [],
    timeline: [],
    keyboardEvents: 0,
    mouseEvents: 0,
    titleEvents: 0,
    clipboardEvents: 0,
    unknownEvents: 0,
    textInputEvents: 0,
    keystrokeTrailer: false,
    keystrokeMetadata: false,
    keyboardLayout: null,
    keyboardLayoutSource: null,
    maxReorderMs: 0,
    durationMs: 0,
    truncated: null,
    decoderCounts: {},
  };
}

function bitmapCountKey(f: DecodedFrame): string {
  if (f.error === null) return f.decoder;
  if (f.error.startsWith("unsupported")) return COUNT_UNSUPPORTED;
  if (f.error.startsWith("invalid geometry")) return COUNT_INVALID_GEOMETRY;
  return COUNT_ERROR;
}

// ─── `0x07` surface updates ─────────────────────────────────────────

/// Parse and statically validate a `0x07` payload without inflating
/// it. Everything checkable from the prefix is checked here so the
/// player can report rejections before playback starts; the two
/// checks that need the inflate itself (stream validity and inflated
/// length) happen in `renderSurfaceUpdate`.
function indexSurfaceUpdate(
  timestampMs: number,
  payload: Uint8Array,
  payloadOffset: number,
  version: number,
  deskW: number,
  deskH: number,
): SurfaceUpdate {
  const base: SurfaceUpdate = {
    timestampMs,
    x: 0,
    y: 0,
    width: 0,
    height: 0,
    format: 0,
    encoding: 0,
    dataOffset: 0,
    dataLen: 0,
    error: null,
    countKey: null,
  };

  if (payload.length < SURFACE_PREFIX_LEN) {
    return {
      ...base,
      error: `surface update payload truncated: ${payload.length} bytes, need at least ${SURFACE_PREFIX_LEN}`,
      countKey: COUNT_SURFACE_TRUNCATED,
    };
  }

  const u: SurfaceUpdate = {
    ...base,
    x: readU16Le(payload, 0),
    y: readU16Le(payload, 2),
    width: readU16Le(payload, 4),
    height: readU16Le(payload, 6),
    format: payload[8],
    encoding: payload[9],
    dataOffset: payloadOffset + SURFACE_PREFIX_LEN,
    dataLen: payload.length - SURFACE_PREFIX_LEN,
  };

  // A `0x07` in a file that predates the event type contradicts its
  // own header. Skip and count rather than paint it: silently
  // accepting it would be a fallback on an audit surface.
  if (version < FIRST_SURFACE_VERSION) {
    return {
      ...u,
      error: `surface update in a version-${version} recording (0x07 was added in version ${FIRST_SURFACE_VERSION})`,
      countKey: COUNT_SURFACE_BAD_VERSION,
    };
  }

  // Same geometry strictness as the `0x01` path, against the most
  // recent `0x06` if one has been seen and the header otherwise.
  const geomErr = checkGeometry(u.x, u.y, u.width, u.height, deskW, deskH);
  if (geomErr !== null) {
    return { ...u, error: geomErr, countKey: COUNT_INVALID_GEOMETRY };
  }

  if (u.format !== SURFACE_FORMAT_RGBA8888) {
    return {
      ...u,
      error: `unknown surface format ${u.format} (known: ${SURFACE_FORMAT_RGBA8888} = RGBA8888)`,
      countKey: COUNT_SURFACE_BAD_FORMAT,
    };
  }
  if (
    u.encoding !== SURFACE_ENCODING_RAW &&
    u.encoding !== SURFACE_ENCODING_ZLIB
  ) {
    return {
      ...u,
      error: `unknown surface encoding ${u.encoding} (known: ${SURFACE_ENCODING_RAW} = raw, ${SURFACE_ENCODING_ZLIB} = zlib)`,
      countKey: COUNT_SURFACE_BAD_ENCODING,
    };
  }

  const expected = u.width * u.height * BYTES_PER_PIXEL;
  if (u.encoding === SURFACE_ENCODING_RAW && u.dataLen !== expected) {
    return {
      ...u,
      error: `raw surface data is ${u.dataLen} bytes, expected ${u.width}x${u.height}x${BYTES_PER_PIXEL} = ${expected}`,
      countKey: COUNT_SURFACE_BAD_LENGTH,
    };
  }
  return u;
}

export interface SurfaceRender {
  /// RGBA8888, top-down, `width * height * 4` bytes. `null` on error.
  rgba: Uint8ClampedArray | null;
  error: string | null;
  /// Bucket to count this attempt in — a painted region included.
  countKey: string;
}

/// Inflate (when needed) and validate one `0x07` region's pixels.
///
/// Called by the player at the moment it paints, once per region, and
/// the result is discarded after the blit — see `SurfaceUpdate` for
/// why this is not done up front.
///
/// `bytes` must be the whole `.rdp-rec` buffer the update was indexed
/// from; `dataOffset` is absolute within it.
export function renderSurfaceUpdate(
  bytes: Uint8Array,
  u: SurfaceUpdate,
): SurfaceRender {
  if (u.error !== null) {
    return { rgba: null, error: u.error, countKey: u.countKey ?? COUNT_ERROR };
  }
  const expected = u.width * u.height * BYTES_PER_PIXEL;
  const data = bytes.subarray(u.dataOffset, u.dataOffset + u.dataLen);

  if (u.encoding === SURFACE_ENCODING_RAW) {
    // Length was validated at index time; the producer stores raw when
    // the region is under 512 bytes or compression did not shrink it,
    // so raw and zlib regions appear in the same file.
    return {
      rgba: new Uint8ClampedArray(data.slice().buffer),
      error: null,
      countKey: COUNT_SURFACE,
    };
  }

  // encoding == 1: an RFC 1950 zlib stream (not raw deflate, not gzip).
  //
  // `out` is the hard allocation bound, sized one byte past what the
  // geometry says the region holds. fflate treats `out` as a cap and
  // *silently truncates* a longer stream, so the sentinel byte is what
  // lets the length check below tell "exactly right" from "inflates to
  // more than it claims". A short result (fflate does not throw on a
  // truncated stream) fails the same check.
  let inflated: Uint8Array;
  try {
    inflated = unzlibSync(data, { out: new Uint8Array(expected + 1) });
  } catch (e) {
    return {
      rgba: null,
      error: `zlib inflate failed: ${e instanceof Error ? e.message : String(e)}`,
      countKey: COUNT_SURFACE_INFLATE_FAILED,
    };
  }
  if (inflated.length !== expected) {
    return {
      rgba: null,
      error:
        `inflated surface data is ${inflated.length > expected ? "more than" : ""}${inflated.length} bytes, ` +
        `expected ${u.width}x${u.height}x${BYTES_PER_PIXEL} = ${expected}`,
      countKey: COUNT_SURFACE_BAD_LENGTH,
    };
  }
  return {
    rgba: new Uint8ClampedArray(
      inflated.buffer,
      inflated.byteOffset,
      inflated.byteLength,
    ),
    error: null,
    countKey: COUNT_SURFACE,
  };
}

// ─── Header ─────────────────────────────────────────────────────────

function parseHeader(
  bytes: Uint8Array,
): { header: string; start: number } | { error: string } {
  if (bytes.length < MAGIC.length) {
    return { error: "input shorter than the 4-byte magic prefix" };
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) return { error: "magic mismatch (expected RREC)" };
  }
  let nl = -1;
  for (let i = MAGIC.length; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {
      nl = i;
      break;
    }
  }
  if (nl < 0) return { error: "no newline after header" };
  const header = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.subarray(MAGIC.length, nl),
  );
  return { header, start: nl + 1 };
}

/// Version + geometry + advertised encodings from the recording's JSON
/// header. Unknown header fields are ignored — the producer may add
/// more. Returns zeroes when the header is absent or malformed;
/// callers then fall back to `MAX_RECT_PIXELS` for geometry, and a
/// zero version is treated as version 1 (graphics undecodable), which
/// is the conservative reading: a header we cannot understand is not a
/// licence to paint its graphics events.
function parseHeaderFields(header: string): HeaderFields {
  try {
    const h = JSON.parse(header) as Record<string, unknown>;
    const num = (v: unknown) => (typeof v === "number" && v >= 0 ? v : 0);
    const encodings = Array.isArray(h.graphics_encodings)
      ? h.graphics_encodings.filter((e): e is string => typeof e === "string")
      : [];
    const str = (v: unknown) => (typeof v === "string" ? v : null);
    return {
      version: num(h.version),
      screenW: num(h.screen_width),
      screenH: num(h.screen_height),
      graphicsEncodings: encodings,
      // A missing `keystroke_metadata` reads as `false` — which is
      // how every version <= 3 header reads, and the whole reason
      // version 4 needed no version gate here.
      keystrokeMetadata: h.keystroke_metadata === true,
      keyboardLayout: str(h.keyboard_layout),
      keyboardLayoutSource: str(h.keyboard_layout_source),
      maxReorderMs: num(h.max_reorder_ms),
    };
  } catch {
    return {
      version: 0,
      screenW: 0,
      screenH: 0,
      graphicsEncodings: [],
      keystrokeMetadata: false,
      keyboardLayout: null,
      keyboardLayoutSource: null,
      maxReorderMs: 0,
    };
  }
}

function readU64Le(b: Uint8Array, p: number): number {
  // JS numbers are safe to 2^53; rec timestamps are ms since start
  // and easily fit.
  const lo =
    b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000);
  const hi =
    b[p + 4] | (b[p + 5] << 8) | (b[p + 6] << 16) | (b[p + 7] * 0x1000000);
  return lo + hi * 0x100000000;
}

function readU32Le(b: Uint8Array, p: number): number {
  return b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000);
}

function readU16Le(b: Uint8Array, p: number): number {
  return b[p] | (b[p + 1] << 8);
}

// ─── `0x01` graphics events (versions >= 2) ─────────────────────────

function decodeGraphics(
  timestampMs: number,
  payload: Uint8Array,
  screenW: number,
  screenH: number,
): DecodedFrame {
  // ── Recorder rectangle header (8 bytes, Rustion's own framing) ──
  if (payload.length < REC_RECT_HEADER_LEN) {
    return frameErr(timestampMs, 0, 0, 0, 0, "recorder rect header truncated");
  }
  const x = readU16Le(payload, 0);
  const y = readU16Le(payload, 2);
  const width = readU16Le(payload, 4);
  const height = readU16Le(payload, 6);

  // Reject impossible rectangles before allocating anything. A
  // graphics event whose rect does not fit the recorded desktop did
  // not come from a real bitmap update; decoding it would at best
  // paint noise and at worst request gigabytes of RGBA.
  const geomErr = checkGeometry(x, y, width, height, screenW, screenH);
  if (geomErr !== null) {
    return frameErr(timestampMs, x, y, width, height, geomErr);
  }

  // ── TS_BITMAP_DATA, which the recorder copies verbatim from the
  // wire PDU starting at destLeft (MS-RDPBCGR § 2.2.9.1.1.3.1.2.2) ──
  const bmp = payload.subarray(REC_RECT_HEADER_LEN);
  if (bmp.length < 18) {
    return frameErr(timestampMs, x, y, width, height, "TS_BITMAP_DATA header truncated");
  }
  const bpp = readU16Le(bmp, 12);
  const flags = readU16Le(bmp, 14);
  const bitmapLen = readU16Le(bmp, 16);

  let cursor = 18;
  const compressed = (flags & BITMAP_COMPRESSION) !== 0;
  if (compressed && (flags & NO_BITMAP_COMPRESSION_HDR) === 0) {
    if (cursor + 8 > bmp.length) {
      return frameErr(timestampMs, x, y, width, height, "compressed bitmap header truncated");
    }
    cursor += 8;
  }
  if (cursor + bitmapLen > bmp.length) {
    return frameErr(timestampMs, x, y, width, height, "bitmap body truncated");
  }
  const body = bmp.subarray(cursor, cursor + bitmapLen);

  if (!compressed) {
    try {
      const rgba = decodeUncompressed(bpp, width, height, body);
      return {
        timestampMs,
        x, y, width, height,
        bitsPerPixel: bpp,
        compressed,
        decoder: "uncompressed",
        rgba,
        error: null,
      };
    } catch (e) {
      return frameErr(timestampMs, x, y, width, height, String(e));
    }
  }

  if (bpp === 16) {
    try {
      const rgba = decodeRle(width, height, body, readPixel16, [0, 0, 0, 0xff], [0xff, 0xff, 0xff, 0xff]);
      return { timestampMs, x, y, width, height, bitsPerPixel: bpp, compressed, decoder: "rle16", rgba, error: null };
    } catch (e) {
      return frameErrDecoder(timestampMs, x, y, width, height, "rle16", String(e));
    }
  }
  if (bpp === 24) {
    try {
      const rgba = decodeRle(width, height, body, readPixel24, [0, 0, 0, 0xff], [0xff, 0xff, 0xff, 0xff]);
      return { timestampMs, x, y, width, height, bitsPerPixel: bpp, compressed, decoder: "rle24", rgba, error: null };
    } catch (e) {
      return frameErrDecoder(timestampMs, x, y, width, height, "rle24", String(e));
    }
  }
  return {
    timestampMs,
    x, y, width, height,
    bitsPerPixel: bpp,
    compressed,
    decoder: "none",
    rgba: new Uint8ClampedArray(0),
    error: `unsupported compressed bpp=${bpp} (8 bpp + NSCodec + RemoteFX are not decoded here; a version-3 recording carries decoded pixels in 0x07 instead)`,
  };
}

/// Validate a rectangle against the desktop in force — the most recent
/// `0x06` if one has been seen, the header otherwise. Returns null when
/// the rect is usable, or an `"invalid geometry: …"` message the caller
/// turns into a distinct `invalid-geometry` count.
///
/// Kept separate from the pixel decoders so the check runs *before*
/// any `w * h * 4` allocation, and shared by `0x01` and `0x07` so
/// there is exactly one geometry policy.
function checkGeometry(
  x: number, y: number, w: number, h: number,
  screenW: number, screenH: number,
): string | null {
  if (w === 0 || h === 0) {
    return `invalid geometry: zero-size rect ${w}×${h}`;
  }
  if (screenW > 0 && screenH > 0) {
    if (x + w > screenW || y + h > screenH) {
      return (
        `invalid geometry: rect ${w}×${h} at (${x},${y}) falls outside ` +
        `the recorded ${screenW}×${screenH} desktop`
      );
    }
    return null;
  }
  // No usable desktop size — fall back to the hard cap.
  if (w * h > MAX_RECT_PIXELS) {
    return `invalid geometry: rect ${w}×${h} exceeds the ${MAX_RECT_PIXELS}-pixel cap`;
  }
  return null;
}

function frameErr(ts: number, x: number, y: number, w: number, h: number, msg: string): DecodedFrame {
  return {
    timestampMs: ts, x, y, width: w, height: h,
    bitsPerPixel: 0, compressed: false, decoder: "none",
    rgba: new Uint8ClampedArray(0), error: msg,
  };
}

function frameErrDecoder(
  ts: number, x: number, y: number, w: number, h: number,
  decoder: "rle16" | "rle24", msg: string,
): DecodedFrame {
  return {
    timestampMs: ts, x, y, width: w, height: h,
    bitsPerPixel: 0, compressed: true, decoder,
    rgba: new Uint8ClampedArray(0), error: msg,
  };
}

function decodeUncompressed(
  bpp: number, width: number, height: number, body: Uint8Array,
): Uint8ClampedArray {
  const w = width, h = height;
  const rgba = new Uint8ClampedArray(w * h * 4);
  if (bpp === 16) {
    const expected = w * h * 2;
    if (body.length < expected) throw new Error(`16bpp body short: have ${body.length} want ${expected}`);
    for (let row = 0; row < h; row++) {
      const srcRow = h - 1 - row;
      for (let col = 0; col < w; col++) {
        const i = (srcRow * w + col) * 2;
        const px = body[i] | (body[i + 1] << 8);
        const r = (px >> 11) & 0x1f;
        const g = (px >> 5) & 0x3f;
        const b = px & 0x1f;
        const o = (row * w + col) * 4;
        rgba[o] = (r << 3) | (r >> 2);
        rgba[o + 1] = (g << 2) | (g >> 4);
        rgba[o + 2] = (b << 3) | (b >> 2);
        rgba[o + 3] = 0xff;
      }
    }
  } else if (bpp === 24) {
    const expected = w * h * 3;
    if (body.length < expected) throw new Error(`24bpp body short: have ${body.length} want ${expected}`);
    for (let row = 0; row < h; row++) {
      const srcRow = h - 1 - row;
      for (let col = 0; col < w; col++) {
        const i = (srcRow * w + col) * 3;
        const o = (row * w + col) * 4;
        rgba[o] = body[i + 2];
        rgba[o + 1] = body[i + 1];
        rgba[o + 2] = body[i];
        rgba[o + 3] = 0xff;
      }
    }
  } else if (bpp === 32) {
    const expected = w * h * 4;
    if (body.length < expected) throw new Error(`32bpp body short: have ${body.length} want ${expected}`);
    for (let row = 0; row < h; row++) {
      const srcRow = h - 1 - row;
      for (let col = 0; col < w; col++) {
        const i = (srcRow * w + col) * 4;
        const o = (row * w + col) * 4;
        rgba[o] = body[i + 2];
        rgba[o + 1] = body[i + 1];
        rgba[o + 2] = body[i];
        rgba[o + 3] = 0xff;
      }
    }
  } else {
    throw new Error(`uncompressed bpp=${bpp} not supported`);
  }
  return rgba;
}

// ─── RLE decoder ────────────────────────────────────────────────────

type Pixel = [number, number, number, number];
type PixelReader = (input: Uint8Array, posRef: { p: number }) => Pixel;

function readPixel16(input: Uint8Array, posRef: { p: number }): Pixel {
  if (posRef.p + 2 > input.length) throw new Error("rle16: short pixel");
  const px = input[posRef.p] | (input[posRef.p + 1] << 8);
  posRef.p += 2;
  const r = ((px >> 11) & 0x1f) << 3;
  const g = ((px >> 5) & 0x3f) << 2;
  const b = (px & 0x1f) << 3;
  return [r, g, b, 0xff];
}

function readPixel24(input: Uint8Array, posRef: { p: number }): Pixel {
  if (posRef.p + 3 > input.length) throw new Error("rle24: short pixel");
  const b = input[posRef.p];
  const g = input[posRef.p + 1];
  const r = input[posRef.p + 2];
  posRef.p += 3;
  return [r, g, b, 0xff];
}

type Code =
  | { tag: "bg"; n: number }
  | { tag: "fg"; n: number }
  | { tag: "color"; n: number }
  | { tag: "fom"; n: number }
  | { tag: "setFgFom"; n: number }
  | { tag: "setfg"; n: number }
  | { tag: "pixels"; n: number }
  | { tag: "white"; n: number }
  | { tag: "black"; n: number }
  | { tag: "done" };

function parseCode(input: Uint8Array, posRef: { p: number }): Code {
  if (posRef.p >= input.length) return { tag: "done" };
  const b = input[posRef.p];
  posRef.p += 1;
  const regularOp = b >> 5;
  const regularLen = b & 0x1f;
  const readBytePlus = (extra: number, ctx: string): number => {
    if (posRef.p + 1 > input.length) throw new Error(`${ctx} mega: short`);
    const n = input[posRef.p] + extra;
    posRef.p += 1;
    return n;
  };
  switch (regularOp) {
    case 0: return { tag: "bg", n: regularLen === 0 ? readBytePlus(32, "BG") : regularLen };
    case 1: return { tag: "fg", n: regularLen === 0 ? readBytePlus(32, "FG") : regularLen };
    case 2: return { tag: "color", n: regularLen === 0 ? readBytePlus(32, "Color") : regularLen };
    case 3: return { tag: "fom", n: regularLen === 0 ? readBytePlus(1, "FOM") : regularLen };
    case 4: return { tag: "setFgFom", n: regularLen === 0 ? readBytePlus(1, "SetFgFom") : regularLen };
    case 5: return { tag: "setfg", n: regularLen === 0 ? readBytePlus(32, "Setfg") : regularLen };
    case 6: {
      const liteOp = (b >> 4) & 0x0f;
      const liteLen = Math.max(1, b & 0x0f);
      if (liteOp === 0xc) return { tag: "white", n: liteLen };
      if (liteOp === 0xd) return { tag: "black", n: liteLen };
      return { tag: "pixels", n: liteLen };
    }
    case 7: {
      if (posRef.p + 2 > input.length) throw new Error("mega-mega: short");
      const n = input[posRef.p] | (input[posRef.p + 1] << 8);
      posRef.p += 2;
      switch (regularLen & 0x1f) {
        case 0: return { tag: "bg", n };
        case 1: return { tag: "fg", n };
        case 2: return { tag: "color", n };
        case 3: return { tag: "fom", n };
        case 4: return { tag: "setFgFom", n };
        case 5: return { tag: "setfg", n };
        default: return { tag: "pixels", n };
      }
    }
    default: throw new Error(`unknown RLE opcode ${regularOp}`);
  }
}

function decodeRle(
  width: number, height: number, body: Uint8Array,
  readPixel: PixelReader, bg: Pixel, fgDefault: Pixel,
): Uint8ClampedArray {
  const w = width, h = height;
  const rgba = new Uint8ClampedArray(w * h * 4);
  const total = w * h;
  let out = 0;
  let fg: Pixel = fgDefault;
  const posRef = { p: 0 };

  const writePx = (px: Pixel) => {
    const i = out * 4;
    rgba[i] = px[0]; rgba[i + 1] = px[1]; rgba[i + 2] = px[2]; rgba[i + 3] = px[3];
    out += 1;
  };

  while (posRef.p < body.length && out < total) {
    const code = parseCode(body, posRef);
    if (code.tag === "done") break;
    switch (code.tag) {
      case "bg":
        for (let i = 0; i < code.n && out < total; i++) writePx(bg);
        break;
      case "fg":
        for (let i = 0; i < code.n && out < total; i++) writePx(fg);
        break;
      case "white":
        for (let i = 0; i < code.n && out < total; i++) writePx([0xff, 0xff, 0xff, 0xff]);
        break;
      case "black":
        for (let i = 0; i < code.n && out < total; i++) writePx([0, 0, 0, 0xff]);
        break;
      case "color": {
        const px = readPixel(body, posRef);
        for (let i = 0; i < code.n && out < total; i++) writePx(px);
        break;
      }
      case "setfg": {
        fg = readPixel(body, posRef);
        for (let i = 0; i < code.n && out < total; i++) writePx(fg);
        break;
      }
      case "fom":
      case "setFgFom": {
        const maskBytes = Math.floor((code.n + 7) / 8);
        if (posRef.p + maskBytes > body.length) throw new Error("FOM mask short");
        if (code.tag === "setFgFom") fg = readPixel(body, posRef);
        for (let i = 0; i < code.n && out < total; i++) {
          const byte = body[posRef.p + Math.floor(i / 8)];
          const bit = (byte >> (i & 7)) & 1;
          writePx(bit === 1 ? fg : bg);
        }
        posRef.p += maskBytes;
        break;
      }
      case "pixels": {
        for (let i = 0; i < code.n && out < total; i++) {
          writePx(readPixel(body, posRef));
        }
        break;
      }
    }
  }
  while (out < total) writePx(bg);

  // Flip vertically (RDP's legacy bitmap path is bottom-up; `0x07`
  // surface updates are already top-down and never come through here).
  const flipped = new Uint8ClampedArray(w * h * 4);
  for (let row = 0; row < h; row++) {
    const src = (h - 1 - row) * w * 4;
    const dst = row * w * 4;
    flipped.set(rgba.subarray(src, src + w * 4), dst);
  }
  return flipped;
}
