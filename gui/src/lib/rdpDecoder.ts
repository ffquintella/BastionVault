// RDP `.rdp-rec` bitmap-update decoder — TypeScript port of
// `gui/wasm/rdp-replay/src/lib.rs`.
//
// The Rust crate is the canonical, unit-tested reference implementation
// (6 tests pass). This file mirrors it 1:1 so the GUI can run in the
// browser without a wasm-bindgen build step. If you change one, change
// the other; the Rust tests are the spec.
//
// Graphics event payload layout, per Rustion's
// `docs/session-recording-format.md` and `rustion-recording::
// rdp_recorder::record_event`:
//
//     x:u16 LE | y:u16 LE | w:u16 LE | h:u16 LE | pixel data
//
// The leading 8 bytes are the *recorder's* own rectangle header — not
// part of MS-RDPBCGR. Everything from offset 8 is the bytes the
// recorder's `parse_bitmap_update` copied out of the wire PDU, which
// it takes to start at a TS_BITMAP_DATA rectangle.
//
// Reading TS_BITMAP_DATA at offset 0 (as this decoder did before)
// silently misreads the recorder header as destLeft/destTop/destRight/
// destBottom and then re-reads the *same* four bytes as width/height,
// because `parse_bitmap_update` copies the rectangle it just parsed.
// Every field from `bitsPerPixel` on is then garbage.
//
// Implements per MS-RDPBCGR § 2.2.9.1.1.3.1.2.2 + MS-RDPEGDI § 3.1.9:
//   • TS_BITMAP_DATA parser (single-rect per event — recorder emits
//     one rectangle per graphics event)
//   • Uncompressed 16/24/32 bpp → RGBA, top-down
//   • RLE16 / RLE24 compressed paths (Bg/Fg/Color/FOM/SetFgFom/Setfg/
//     Pixels/White/Black + mega-mega forms)
//
// Out of scope for Phase 8.4:
//   • 8 bpp RLE          (vanishingly rare on modern Windows)
//   • NSCodec            (separate codec)
//   • RemoteFX           (separate codec)
//   • Bitmap-cache refs  (cached glyph bitmaps)

const MAGIC = new Uint8Array([0x52, 0x52, 0x45, 0x43]); // "RREC"
const EVENT_GRAPHICS = 0x01;
const EVENT_KEYBOARD = 0x02;
const EVENT_MOUSE = 0x03;

const BITMAP_COMPRESSION = 0x0001;
const NO_BITMAP_COMPRESSION_HDR = 0x0400;

/// Size of the recorder's own `x/y/w/h` rectangle header that precedes
/// the pixel data in every graphics event payload.
const REC_RECT_HEADER_LEN = 8;

/// Ceiling on a single rectangle's pixel count when the recording
/// header carries no usable screen size. 8192×8192 is far above any
/// real RDP desktop and caps the RGBA allocation at 256 MiB.
///
/// Without a bound, a rectangle whose dimensions decode to garbage
/// (63426 × 63193 has been observed in the field) makes the decoder
/// ask for ~16 GB and take down the replay window with an allocation
/// failure. Recording bytes come from the bastion, so these fields are
/// attacker-influenced input.
const MAX_RECT_PIXELS = 8192 * 8192;

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

export interface DecodeResult {
  ok: boolean;
  error: string | null;
  headerJson: string | null;
  frames: DecodedFrame[];
  keyboardEvents: number;
  mouseEvents: number;
  durationMs: number;
  decoderCounts: Record<string, number>;
}

export function decodeRdpRec(bytes: Uint8Array): DecodeResult {
  const headerOut = parseHeader(bytes);
  if ("error" in headerOut) {
    return {
      ok: false,
      error: headerOut.error,
      headerJson: null,
      frames: [],
      keyboardEvents: 0,
      mouseEvents: 0,
      durationMs: 0,
      decoderCounts: {},
    };
  }
  const { header, start } = headerOut;
  const { screenW, screenH } = parseScreenSize(header);
  const frames: DecodedFrame[] = [];
  let keyboard = 0,
    mouse = 0,
    lastTs = 0;
  const counts: Record<string, number> = {};
  let pos = start;
  while (pos + 13 <= bytes.length) {
    const ts = readU64Le(bytes, pos);
    const kind = bytes[pos + 8];
    const len = readU32Le(bytes, pos + 9);
    const next = pos + 13 + len;
    if (next > bytes.length) break;
    const payload = bytes.subarray(pos + 13, next);
    lastTs = ts;
    if (kind === EVENT_GRAPHICS) {
      const f = decodeGraphics(ts, payload, screenW, screenH);
      const key =
        f.error !== null
          ? f.error.startsWith("unsupported")
            ? "unsupported"
            : f.error.startsWith("invalid geometry")
              ? "invalid-geometry"
              : "error"
          : f.decoder;
      counts[key] = (counts[key] ?? 0) + 1;
      frames.push(f);
    } else if (kind === EVENT_KEYBOARD) {
      keyboard += 1;
    } else if (kind === EVENT_MOUSE) {
      mouse += 1;
    }
    pos = next;
  }
  return {
    ok: true,
    error: null,
    headerJson: header,
    frames,
    keyboardEvents: keyboard,
    mouseEvents: mouse,
    durationMs: lastTs,
    decoderCounts: counts,
  };
}

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

/// Screen size from the recording's JSON header. Returns 0/0 when the
/// header is absent or malformed — callers then fall back to
/// MAX_RECT_PIXELS rather than rejecting every rectangle.
function parseScreenSize(header: string): { screenW: number; screenH: number } {
  try {
    const h = JSON.parse(header) as Record<string, unknown>;
    const w = typeof h.screen_width === "number" ? h.screen_width : 0;
    const y = typeof h.screen_height === "number" ? h.screen_height : 0;
    return { screenW: w, screenH: y };
  } catch {
    return { screenW: 0, screenH: 0 };
  }
}

function readU64Le(b: Uint8Array, p: number): number {
  // JS numbers are safe to 2^53; rec timestamps are ms since start
  // and easily fit. Use a BigInt path then narrow.
  const lo =
    b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000);
  const hi =
    b[p + 4] | (b[p + 5] << 8) | (b[p + 6] << 16) | (b[p + 7] * 0x1000000);
  return lo + hi * 0x100000000;
}

function readU32Le(b: Uint8Array, p: number): number {
  return (
    b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] * 0x1000000)
  );
}

function readU16Le(b: Uint8Array, p: number): number {
  return b[p] | (b[p + 1] << 8);
}

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
    error: `unsupported compressed bpp=${bpp} (Phase 8.4: 16/24 only; 8 bpp + NSCodec + RemoteFX deferred)`,
  };
}

/// Validate a recorder rectangle against the recorded desktop size.
/// Returns null when the rect is usable, or an `"invalid geometry: …"`
/// message the caller turns into a distinct `invalid-geometry` count.
///
/// Kept separate from the pixel decoders so the check runs *before*
/// any `w * h * 4` allocation.
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
  // No usable screen size in the header — fall back to the hard cap.
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

  // Flip vertically (RDP is bottom-up).
  const flipped = new Uint8ClampedArray(w * h * 4);
  for (let row = 0; row < h; row++) {
    const src = (h - 1 - row) * w * 4;
    const dst = row * w * 4;
    flipped.set(rgba.subarray(src, src + w * 4), dst);
  }
  return flipped;
}
