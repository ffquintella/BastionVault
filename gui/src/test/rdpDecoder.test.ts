// End-to-end tests for the `.rdp-rec` replay pipeline.
//
// Mirrors the Rust unit tests in `gui/wasm/rdp-replay/src/lib.rs`.
// If a Rust test passes but the JS twin fails, the TS port has drifted.
//
// Fixtures are built from the format spec — the record framing, the
// `0x07` prefix layout, and the RFC 1950 zlib streams all come from
// `docs/rustion-integration.md` § .rdp-rec, not from the decoder.
// zlib streams are produced by **Node's** zlib, deliberately a
// different implementation from the `fflate` inflate under test, so a
// pass means real interop rather than a round trip through one codec.

import { describe, it, expect } from "vitest";
import { deflateSync, gzipSync, deflateRawSync } from "node:zlib";

import {
  COUNT_INVALID_GEOMETRY,
  COUNT_SURFACE,
  COUNT_SURFACE_BAD_ENCODING,
  COUNT_SURFACE_BAD_FORMAT,
  COUNT_SURFACE_BAD_LENGTH,
  COUNT_SURFACE_BAD_VERSION,
  COUNT_SURFACE_INFLATE_FAILED,
  COUNT_KEYSTROKE_BAD_VERSION,
  COUNT_UNKNOWN_EVENT,
  COUNT_V1_UNDECODABLE,
  decodeRdpRec,
  renderSurfaceUpdate,
  type DecodeResult,
} from "../lib/rdpDecoder";

const MAGIC = new TextEncoder().encode("RREC");
const EVENT_GRAPHICS = 0x01;
const EVENT_KEYBOARD = 0x02;
const EVENT_MOUSE = 0x03;
const EVENT_DESKTOP_SIZE = 0x06;
const EVENT_SURFACE = 0x07;
const BITMAP_COMPRESSION = 0x0001;
const NO_BITMAP_COMPRESSION_HDR = 0x0400;

function le16(n: number): number[] { return [n & 0xff, (n >> 8) & 0xff]; }
function le32(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
}
function le64(n: number): number[] {
  const lo = n >>> 0;
  const hi = Math.floor(n / 0x100000000) >>> 0;
  return [...le32(lo), ...le32(hi)];
}

const SCREEN_W = 1920;
const SCREEN_H = 1080;

/// The 8-byte rectangle header Rustion's `RdpRecorder` writes ahead of
/// the pixel data on every `0x01` graphics event
/// (`x:u16 | y:u16 | w:u16 | h:u16`). Fixtures must include it or they
/// test a payload shape the recorder never produces.
function recRectHeader(x: number, y: number, w: number, h: number): number[] {
  return [...le16(x), ...le16(y), ...le16(w), ...le16(h)];
}

interface Ev { ts: number; kind: number; payload: number[] }

/// Default header is version 2 — the first version whose `0x01`
/// payload is a real `TS_BITMAP_DATA`. Version 1 is covered by its own
/// regression test below.
function buildRecord(
  events: Ev[],
  header = `{"version":2,"screen_width":${SCREEN_W},"screen_height":${SCREEN_H}}\n`,
): Uint8Array {
  const out: number[] = [];
  MAGIC.forEach((b) => out.push(b));
  header.split("").forEach((c) => out.push(c.charCodeAt(0)));
  for (const e of events) {
    out.push(...le64(e.ts));
    out.push(e.kind);
    out.push(...le32(e.payload.length));
    out.push(...e.payload);
  }
  return new Uint8Array(out);
}

function v3Header(w = SCREEN_W, h = SCREEN_H): string {
  return JSON.stringify({
    version: 3,
    session_id: "00000000-0000-4000-8000-000000000001",
    user: "tester",
    bastion_user: "tester",
    target_user: "tester",
    target: "test-host:3389",
    started_at: "2026-01-01T00:00:00+00:00",
    screen_width: w,
    screen_height: h,
    graphics_encodings: ["ts_update_bitmap", "rgba8888"],
  }) + "\n";
}

function buildGraphicsUncompressed24(
  x: number, y: number, w: number, h: number,
  pixels: Array<[number, number, number]>,
): number[] {
  const right = x + w, bottom = y + h;
  const p: number[] = recRectHeader(x, y, w, h);
  p.push(...le16(x), ...le16(y), ...le16(right), ...le16(bottom));
  p.push(...le16(w), ...le16(h), ...le16(24));
  p.push(...le16(0));
  p.push(...le16(pixels.length * 3));
  for (let row = 0; row < h; row++) {
    const srcRow = h - 1 - row; // bottom-up
    for (let col = 0; col < w; col++) {
      const [r, g, b] = pixels[srcRow * w + col];
      p.push(b, g, r);
    }
  }
  return p;
}

// ─── `0x07` fixture builders (straight from the spec) ───────────────

/// `x:u16 y:u16 w:u16 h:u16 format:u8 encoding:u8` + data.
function surfacePayload(
  x: number, y: number, w: number, h: number,
  data: Uint8Array | number[],
  format = 1,
  encoding = 0,
): number[] {
  return [
    ...le16(x), ...le16(y), ...le16(w), ...le16(h),
    format, encoding,
    ...Array.from(data),
  ];
}

/// RGBA8888, row-major, top-down, no row padding.
function solidRgba(w: number, h: number, px: [number, number, number, number]): Uint8Array {
  const out = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) out.set(px, i * 4);
  return out;
}

/// zlib-wrapped deflate (RFC 1950), from Node's zlib.
function zlib(data: Uint8Array): Uint8Array {
  return new Uint8Array(deflateSync(data));
}

function surfaceEvent(
  ts: number, x: number, y: number, w: number, h: number,
  rgba: Uint8Array, compress: boolean,
): Ev {
  return {
    ts,
    kind: EVENT_SURFACE,
    payload: surfacePayload(x, y, w, h, compress ? zlib(rgba) : rgba, 1, compress ? 1 : 0),
  };
}

// ─── A software canvas, so the assertions are about pixels ──────────
//
// Mirrors what `RdpReplayCanvas` does with `putImageData`: paint each
// region at (x, y) over whatever is already there, in timeline order.
// A `0x06` whose size differs resizes and clears.

interface Canvas { w: number; h: number; px: Uint8Array }

function replay(bytes: Uint8Array, decoded: DecodeResult): {
  canvas: Canvas;
  painted: number;
  liveCounts: Record<string, number>;
} {
  let canvas: Canvas = {
    w: decoded.screenWidth || 1,
    h: decoded.screenHeight || 1,
    px: new Uint8Array((decoded.screenWidth || 1) * (decoded.screenHeight || 1) * 4),
  };
  let painted = 0;
  const liveCounts: Record<string, number> = {};
  const put = (rgba: Uint8ClampedArray, x: number, y: number, w: number, h: number) => {
    for (let row = 0; row < h; row++) {
      const dy = y + row;
      if (dy < 0 || dy >= canvas.h) continue;
      for (let col = 0; col < w; col++) {
        const dx = x + col;
        if (dx < 0 || dx >= canvas.w) continue;
        const s = (row * w + col) * 4;
        const d = (dy * canvas.w + dx) * 4;
        canvas.px[d] = rgba[s];
        canvas.px[d + 1] = rgba[s + 1];
        canvas.px[d + 2] = rgba[s + 2];
        canvas.px[d + 3] = rgba[s + 3];
      }
    }
    painted += 1;
  };
  for (const ev of decoded.timeline) {
    if (ev.kind === "desktop") {
      if (ev.desktop.width !== canvas.w || ev.desktop.height !== canvas.h) {
        canvas = {
          w: ev.desktop.width,
          h: ev.desktop.height,
          px: new Uint8Array(ev.desktop.width * ev.desktop.height * 4),
        };
      }
    } else if (ev.kind === "bitmap") {
      if (ev.frame.error === null && ev.frame.rgba.length > 0) {
        put(ev.frame.rgba, ev.frame.x, ev.frame.y, ev.frame.width, ev.frame.height);
      }
    } else {
      const out = renderSurfaceUpdate(bytes, ev.update);
      if (ev.update.error === null) {
        liveCounts[out.countKey] = (liveCounts[out.countKey] ?? 0) + 1;
      }
      if (out.rgba !== null) {
        put(out.rgba, ev.update.x, ev.update.y, ev.update.width, ev.update.height);
      }
    }
  }
  return { canvas, painted, liveCounts };
}

function pixelAt(c: Canvas, x: number, y: number): number[] {
  const o = (y * c.w + x) * 4;
  return Array.from(c.px.subarray(o, o + 4));
}

// ─── Version 2: the `0x01` TS_BITMAP_DATA path (pre-existing) ───────

describe("rdpDecoder — 0x01 wire bitmaps (version 2)", () => {
  it("uncompressed 24bpp round trip", () => {
    const pixels: Array<[number, number, number]> = [
      [0xff, 0, 0], [0, 0xff, 0],
      [0, 0, 0xff], [0xff, 0xff, 0xff],
    ];
    const g = buildGraphicsUncompressed24(10, 20, 2, 2, pixels);
    const rec = buildRecord([{ ts: 100, kind: EVENT_GRAPHICS, payload: g }]);
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.version).toBe(2);
    expect(out.frames.length).toBe(1);
    const f = out.frames[0];
    expect(f.error).toBeNull();
    expect(f.x).toBe(10);
    expect(f.y).toBe(20);
    expect(f.width).toBe(2);
    expect(f.height).toBe(2);
    expect(f.decoder).toBe("uncompressed");
    expect(f.rgba.length).toBe(16);
    expect(Array.from(f.rgba.slice(0, 4))).toEqual([0xff, 0, 0, 0xff]);
    expect(Array.from(f.rgba.slice(12, 16))).toEqual([0xff, 0xff, 0xff, 0xff]);
  });

  it("truncated bitmap body reports error not panic", () => {
    const p: number[] = recRectHeader(0, 0, 10, 10);
    p.push(...le16(0), ...le16(0), ...le16(10), ...le16(10));
    p.push(...le16(10), ...le16(10));
    p.push(...le16(24));
    p.push(...le16(0));
    p.push(...le16(300)); // claim 300 bytes, supply 0
    const rec = buildRecord([{ ts: 0, kind: EVENT_GRAPHICS, payload: p }]);
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.frames.length).toBe(1);
    expect(out.frames[0].error).not.toBeNull();
    expect(out.frames[0].rgba.length).toBe(0);
  });

  it("walks past non-graphics events", () => {
    const g = buildGraphicsUncompressed24(0, 0, 1, 1, [[1, 2, 3]]);
    const rec = buildRecord([
      { ts: 1, kind: EVENT_KEYBOARD, payload: [0, 0, 0] },
      { ts: 2, kind: EVENT_GRAPHICS, payload: g },
      { ts: 3, kind: EVENT_MOUSE, payload: [0, 0, 0, 0, 0] },
    ]);
    const out = decodeRdpRec(rec);
    expect(out.frames.length).toBe(1);
    expect(out.keyboardEvents).toBe(1);
    expect(out.mouseEvents).toBe(1);
    expect(out.durationMs).toBe(3);
  });

  it("reports unsupported compressed bpp", () => {
    const p: number[] = recRectHeader(0, 0, 1, 1);
    p.push(...le16(0), ...le16(0), ...le16(1), ...le16(1));
    p.push(...le16(1), ...le16(1));
    p.push(...le16(8)); // bpp=8
    p.push(...le16(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR));
    p.push(...le16(1));
    p.push(0x00);
    const rec = buildRecord([{ ts: 5, kind: EVENT_GRAPHICS, payload: p }]);
    const out = decodeRdpRec(rec);
    expect(out.frames.length).toBe(1);
    expect(out.frames[0].error).toMatch(/^unsupported/);
    expect(out.decoderCounts["unsupported"]).toBe(1);
  });

  it("RLE24 BG run paints black across the row", () => {
    const p: number[] = recRectHeader(0, 0, 4, 1);
    p.push(...le16(0), ...le16(0), ...le16(4), ...le16(1));
    p.push(...le16(4), ...le16(1));
    p.push(...le16(24));
    p.push(...le16(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR));
    p.push(...le16(1)); // bitmapLength = 1 (opcode byte only)
    p.push(0x04); // BgRun(4): regular_op=0, len=4
    const rec = buildRecord([{ ts: 0, kind: EVENT_GRAPHICS, payload: p }]);
    const out = decodeRdpRec(rec);
    expect(out.frames.length).toBe(1);
    const f = out.frames[0];
    expect(f.error).toBeNull();
    expect(f.decoder).toBe("rle24");
    expect(f.rgba.length).toBe(16);
    for (let i = 0; i < 4; i++) {
      expect(Array.from(f.rgba.slice(i * 4, i * 4 + 4))).toEqual([0, 0, 0, 0xff]);
    }
  });

  it("decoder_counts split by path", () => {
    const ok = buildGraphicsUncompressed24(0, 0, 1, 1, [[1, 2, 3]]);
    const bad: number[] = recRectHeader(0, 0, 1, 1);
    bad.push(...le16(0), ...le16(0), ...le16(1), ...le16(1));
    bad.push(...le16(1), ...le16(1));
    bad.push(...le16(8));
    bad.push(...le16(BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR));
    bad.push(...le16(1));
    bad.push(0x00);
    const rec = buildRecord([
      { ts: 1, kind: EVENT_GRAPHICS, payload: ok },
      { ts: 2, kind: EVENT_GRAPHICS, payload: bad },
    ]);
    const out = decodeRdpRec(rec);
    expect(out.decoderCounts["uncompressed"]).toBe(1);
    expect(out.decoderCounts["unsupported"]).toBe(1);
  });

  // ── Regressions from rec_1a1c7d52 (a real 1920×1080 recording in
  // which all 424 graphics events were false positives from the
  // bastion's bitmap-update scanner) ──────────────────────────────

  it("rejects a rect that does not fit the recorded desktop", () => {
    // 63426×63193 at (63426, 63193) — the exact shape observed in the
    // field. Must be refused on geometry, before any allocation.
    const p: number[] = recRectHeader(63426, 63193, 63426, 63193);
    p.push(...new Array(64).fill(0xab));
    const rec = buildRecord([{ ts: 0, kind: EVENT_GRAPHICS, payload: p }]);
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.frames[0].error).toMatch(/^invalid geometry/);
    expect(out.frames[0].rgba.length).toBe(0);
    expect(out.decoderCounts[COUNT_INVALID_GEOMETRY]).toBe(1);
    // Not lumped in with genuine decoder failures — an operator needs
    // to tell "the recorder wrote nonsense" apart from "we can't
    // decode this codec".
    expect(out.decoderCounts["error"]).toBeUndefined();
  });

  it("caps rect size when the header carries no screen size", () => {
    const p: number[] = recRectHeader(0, 0, 0xffff, 0xffff);
    p.push(...new Array(64).fill(0));
    const rec = buildRecord(
      [{ ts: 0, kind: EVENT_GRAPHICS, payload: p }],
      '{"version":2}\n',
    );
    const out = decodeRdpRec(rec);
    expect(out.frames[0].error).toMatch(/exceeds the .* cap/);
    expect(out.frames[0].rgba.length).toBe(0);
  });

  it("classifies the real graphics event #1 from rec_1a1c7d52", () => {
    // Captured verbatim from a production recording (evdc400.fgv.br:3389,
    // 1920×1080). The bastion tagged this as a graphics update, but the
    // bytes from offset 8 are the RDP *connection sequence* — GCC
    // ConnectData `00 05 00 14 7c 00 01`, the "McDn" h221 key, then
    // SC_CORE / SC_NET / SC_SECURITY. There is no bitmap here.
    //
    // Read as a recorder rect header, it claims 63230×255 at (513,3),
    // which cannot fit a 1920×1080 desktop. The decoder must say so
    // rather than allocating for it or reporting a codec failure.
    //
    // Read at version 2 here so the geometry path is what rejects it;
    // the real recording was version 1, which is covered separately.
    const ev1 = [
      0x01, 0x02, 0x03, 0x00, 0xfe, 0xf6, 0xff, 0x00, 0x01, 0x02, 0x03, 0x00,
      0xff, 0xf8, 0x02, 0x01, 0x02, 0x04, 0x3e, 0x00, 0x05, 0x00, 0x14, 0x7c,
      0x00, 0x01, 0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00,
      0x4d, 0x63, 0x44, 0x6e, 0x28, 0x01, 0x0c, 0x10, 0x00, 0x11, 0x00, 0x08,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x0c, 0x0c,
      0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03, 0x00, 0x00, 0x02, 0x0c, 0x0c,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const out = decodeRdpRec(
      buildRecord([{ ts: 7, kind: EVENT_GRAPHICS, payload: ev1 }]),
    );
    const f = out.frames[0];
    expect(f.x).toBe(513);
    expect(f.y).toBe(3);
    expect(f.width).toBe(63230);
    expect(f.height).toBe(255);
    expect(f.error).toMatch(/^invalid geometry/);
    expect(f.rgba.length).toBe(0);
    expect(out.decoderCounts[COUNT_INVALID_GEOMETRY]).toBe(1);
  });

  it("reads TS_BITMAP_DATA after the recorder rect header, not at offset 0", () => {
    // Guards the actual bug: parsing at offset 0 makes the recorder's
    // x/y/w/h masquerade as destLeft/destTop/destRight/destBottom and
    // pushes every later field 8 bytes out of place.
    const g = buildGraphicsUncompressed24(10, 20, 2, 2, [
      [0xff, 0, 0], [0, 0xff, 0], [0, 0, 0xff], [0xff, 0xff, 0xff],
    ]);
    expect(g.slice(0, 8)).toEqual(recRectHeader(10, 20, 2, 2));
    const out = decodeRdpRec(
      buildRecord([{ ts: 0, kind: EVENT_GRAPHICS, payload: g }]),
    );
    expect(out.frames[0].error).toBeNull();
    expect(out.frames[0].bitsPerPixel).toBe(24);
  });
});

// ─── Version 1: metadata only ───────────────────────────────────────

describe("rdpDecoder — version 1 is metadata only", () => {
  it("renders nothing and says the graphics are undecodable", () => {
    // A payload that would decode cleanly at version 2. At version 1
    // the bytes are an undelimited slice of the raw stream that only
    // *looks* like a bitmap, so it must not be painted.
    const g = buildGraphicsUncompressed24(10, 20, 2, 2, [
      [0xff, 0, 0], [0, 0xff, 0], [0, 0, 0xff], [0xff, 0xff, 0xff],
    ]);
    const rec = buildRecord(
      [
        { ts: 1, kind: EVENT_GRAPHICS, payload: g },
        { ts: 2, kind: EVENT_GRAPHICS, payload: g },
        { ts: 3, kind: EVENT_KEYBOARD, payload: [...le16(0x1e), 1] },
      ],
      `{"version":1,"screen_width":${SCREEN_W},"screen_height":${SCREEN_H}}\n`,
    );
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.version).toBe(1);
    expect(out.graphicsUndecodable).toBe(true);
    // Zero rendered: no frames produced at all, not "frames with errors".
    expect(out.frames.length).toBe(0);
    expect(out.timeline.length).toBe(0);
    expect(out.decoderCounts[COUNT_V1_UNDECODABLE]).toBe(2);
    expect(out.decoderCounts["uncompressed"]).toBeUndefined();
    // Metadata is still meaningful.
    expect(out.keyboardEvents).toBe(1);
    expect(out.durationMs).toBe(3);
    const { painted } = replay(rec, out);
    expect(painted).toBe(0);
  });

  it("treats a header with no version as undecodable, not as version 3", () => {
    const rec = buildRecord(
      [{ ts: 1, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 1, 1, solidRgba(1, 1, [1, 2, 3, 255])) }],
      '{"screen_width":8,"screen_height":8}\n',
    );
    const out = decodeRdpRec(rec);
    expect(out.version).toBe(0);
    expect(out.graphicsUndecodable).toBe(true);
    expect(out.surfaceUpdates[0].error).toMatch(/version-0 recording/);
    expect(out.decoderCounts[COUNT_SURFACE_BAD_VERSION]).toBe(1);
  });
});

// ─── Version 3: `0x07` decoded pixels ───────────────────────────────

describe("rdpDecoder — 0x07 surface updates (version 3)", () => {
  it("paints raw and zlib regions with RGBA channel order, top-down", () => {
    // Asymmetric, non-grey pattern: a BGRA or bottom-up bug cannot pass.
    const W = 64, H = 48;
    const red = solidRgba(8, 8, [255, 0, 0, 255]);      // zlib
    const blue = solidRgba(4, 4, [0, 0, 255, 255]);     // raw, under 512 bytes
    // Top row green, the rest black — catches bottom-up row order.
    const striped = new Uint8Array(4 * 4 * 4);
    for (let i = 0; i < 4; i++) striped.set([0, 255, 0, 255], i * 4);
    for (let i = 4; i < 16; i++) striped.set([0, 0, 0, 255], i * 4);

    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 8, 8, red, true),
        surfaceEvent(200, 8, 0, 4, 4, blue, false),
        surfaceEvent(300, 0, 16, 4, 4, striped, true),
      ],
      v3Header(W, H),
    );
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.version).toBe(3);
    expect(out.graphicsEncodings).toEqual(["ts_update_bitmap", "rgba8888"]);
    expect(out.surfaceUpdates.length).toBe(3);
    expect(out.surfaceUpdates.every((u) => u.error === null)).toBe(true);
    // Both encodings really are both encodings.
    expect(out.surfaceUpdates.map((u) => u.encoding)).toEqual([1, 0, 1]);

    const { canvas, painted, liveCounts } = replay(rec, out);
    expect(painted).toBe(3);
    expect(liveCounts[COUNT_SURFACE]).toBe(3);

    // Red block: R first, not B.
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 7, 7)).toEqual([255, 0, 0, 255]);
    // Blue block from the raw region, at its own offset.
    expect(pixelAt(canvas, 8, 0)).toEqual([0, 0, 255, 255]);
    expect(pixelAt(canvas, 11, 3)).toEqual([0, 0, 255, 255]);
    // Striped region: the green row is the *first* row of the region,
    // painted at the region's top (y = 16), with black beneath it.
    expect(pixelAt(canvas, 0, 16)).toEqual([0, 255, 0, 255]);
    expect(pixelAt(canvas, 3, 16)).toEqual([0, 255, 0, 255]);
    expect(pixelAt(canvas, 0, 17)).toEqual([0, 0, 0, 255]);
    expect(pixelAt(canvas, 0, 19)).toEqual([0, 0, 0, 255]);
    // Untouched canvas stays untouched.
    expect(pixelAt(canvas, 40, 40)).toEqual([0, 0, 0, 0]);
  });

  it("overlapping regions apply in order — the later one wins", () => {
    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 8, 8, solidRgba(8, 8, [255, 0, 0, 255]), true),
        surfaceEvent(200, 0, 0, 4, 4, solidRgba(4, 4, [255, 255, 0, 255]), true),
      ],
      v3Header(16, 16),
    );
    const out = decodeRdpRec(rec);
    const { canvas, painted } = replay(rec, out);
    expect(painted).toBe(2);
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 255, 0, 255]); // yellow on top
    expect(pixelAt(canvas, 3, 3)).toEqual([255, 255, 0, 255]);
    expect(pixelAt(canvas, 4, 0)).toEqual([255, 0, 0, 255]);   // red survives outside
    expect(pixelAt(canvas, 7, 7)).toEqual([255, 0, 0, 255]);
  });

  it("reproduces the spec's fixture generator canvas exactly", () => {
    // The synthetic artifact from docs/rustion-integration.md, byte for
    // byte: red 64×64 zlib at (0,0), blue 8×8 raw at (64,0), a green
    // top row over black at (0,64), a yellow 16×16 overlap at (0,0),
    // a `0x06`, an unknown `0x5A`, and a keyboard event.
    const W = 640, H = 480;
    const events: Ev[] = [
      surfaceEvent(100, 0, 0, 64, 64, solidRgba(64, 64, [255, 0, 0, 255]), true),
      surfaceEvent(200, 64, 0, 8, 8, solidRgba(8, 8, [0, 0, 255, 255]), false),
      (() => {
        const rows = new Uint8Array(32 * 32 * 4);
        for (let i = 0; i < 32; i++) rows.set([0, 255, 0, 255], i * 4);
        for (let i = 32; i < 32 * 32; i++) rows.set([0, 0, 0, 255], i * 4);
        return surfaceEvent(300, 0, 64, 32, 32, rows, true);
      })(),
      surfaceEvent(400, 0, 0, 16, 16, solidRgba(16, 16, [255, 255, 0, 255]), true),
      { ts: 500, kind: EVENT_DESKTOP_SIZE, payload: [...le16(W), ...le16(H)] },
      {
        // An event type no version defines. Was `0x7F` before
        // version 4 claimed that for the keystroke trailer; the point
        // of the fixture is an *unknown* type, so it moved rather
        // than colliding with a real one.
        ts: 600,
        kind: 0x5a,
        payload: Array.from(new TextEncoder().encode("reserved-for-a-future-bastion")),
      },
      { ts: 700, kind: EVENT_KEYBOARD, payload: [...le16(0x1e), 1] },
    ];
    const rec = buildRecord(events, v3Header(W, H));
    const out = decodeRdpRec(rec);

    expect(out.ok).toBe(true);
    expect(out.truncated).toBeNull();
    expect(out.keyboardEvents).toBe(1);
    expect(out.unknownEvents).toBe(1);
    expect(out.decoderCounts[COUNT_UNKNOWN_EVENT]).toBe(1);
    expect(out.desktopSizes).toEqual([{ timestampMs: 500, width: W, height: H }]);
    // Zero skipped graphics.
    expect(out.surfaceUpdates.filter((u) => u.error !== null).length).toBe(0);
    expect(out.durationMs).toBe(700);

    const { canvas, painted, liveCounts } = replay(rec, out);
    expect(painted).toBe(4);
    expect(liveCounts[COUNT_SURFACE]).toBe(4);
    // Red everywhere in (0,0)–(63,63) except the yellow 16×16 block.
    expect(pixelAt(canvas, 16, 0)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 63, 63)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 255, 0, 255]);
    expect(pixelAt(canvas, 15, 15)).toEqual([255, 255, 0, 255]);
    // Blue 8×8 at (64,0).
    expect(pixelAt(canvas, 64, 0)).toEqual([0, 0, 255, 255]);
    expect(pixelAt(canvas, 71, 7)).toEqual([0, 0, 255, 255]);
    // Green single-pixel row at y = 64 spanning x = 0..31, black beneath.
    expect(pixelAt(canvas, 0, 64)).toEqual([0, 255, 0, 255]);
    expect(pixelAt(canvas, 31, 64)).toEqual([0, 255, 0, 255]);
    expect(pixelAt(canvas, 0, 65)).toEqual([0, 0, 0, 255]);
    // Everything else untouched.
    expect(pixelAt(canvas, 300, 300)).toEqual([0, 0, 0, 0]);
  });

  it("skips an unknown event type mid-file and still reaches the last event", () => {
    // The forward-compatibility contract: this is what let version 3
    // add 0x07 without breaking older players.
    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [1, 2, 3, 255]), false),
        { ts: 200, kind: 0x5a, payload: Array.from(new Uint8Array(97).fill(0xab)) },
        surfaceEvent(300, 4, 0, 4, 4, solidRgba(4, 4, [9, 8, 7, 255]), true),
      ],
      v3Header(16, 16),
    );
    const out = decodeRdpRec(rec);
    expect(out.truncated).toBeNull();
    expect(out.unknownEvents).toBe(1);
    expect(out.surfaceUpdates.length).toBe(2);
    expect(out.durationMs).toBe(300); // reached the last event
    const { canvas, painted } = replay(rec, out);
    expect(painted).toBe(2);
    expect(pixelAt(canvas, 0, 0)).toEqual([1, 2, 3, 255]);
    expect(pixelAt(canvas, 4, 0)).toEqual([9, 8, 7, 255]);
  });

  it("a mid-file 0x06 changes the desktop and rebounds validation", () => {
    // 1200×800 at (0,0) does not fit the 640×480 header desktop, but
    // does fit the 1600×1200 the `0x06` renegotiates to.
    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [255, 0, 0, 255]), false),
        { ts: 200, kind: EVENT_DESKTOP_SIZE, payload: [...le16(1600), ...le16(1200)] },
        surfaceEvent(300, 1000, 700, 8, 8, solidRgba(8, 8, [0, 255, 0, 255]), true),
      ],
      v3Header(640, 480),
    );
    const out = decodeRdpRec(rec);
    expect(out.desktopSizes).toEqual([{ timestampMs: 200, width: 1600, height: 1200 }]);
    expect(out.surfaceUpdates[0].error).toBeNull();
    expect(out.surfaceUpdates[1].error).toBeNull();

    const { canvas, painted } = replay(rec, out);
    expect(painted).toBe(2);
    // The resize cleared the canvas, so the pre-resize red is gone.
    expect(canvas.w).toBe(1600);
    expect(canvas.h).toBe(1200);
    expect(pixelAt(canvas, 0, 0)).toEqual([0, 0, 0, 0]);
    expect(pixelAt(canvas, 1000, 700)).toEqual([0, 255, 0, 255]);
  });

  it("a region outside the desktop is still rejected", () => {
    // The guardrail: adding 0x07 must not become a way to relax
    // geometry validation.
    const rec = buildRecord(
      [
        surfaceEvent(100, 600, 400, 64, 64, solidRgba(64, 64, [255, 0, 0, 255]), true),
        { ts: 200, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 0, 8, []) },
      ],
      v3Header(640, 480),
    );
    const out = decodeRdpRec(rec);
    expect(out.surfaceUpdates[0].error).toMatch(/^invalid geometry/);
    expect(out.surfaceUpdates[0].error).toContain("640×480");
    expect(out.surfaceUpdates[1].error).toMatch(/zero-size/);
    expect(out.decoderCounts[COUNT_INVALID_GEOMETRY]).toBe(2);
    const { painted } = replay(rec, out);
    expect(painted).toBe(0);
    // Rejected on geometry, never inflated, never confused with a
    // codec failure.
    expect(out.decoderCounts[COUNT_SURFACE_INFLATE_FAILED]).toBeUndefined();
    expect(out.decoderCounts[COUNT_SURFACE_BAD_LENGTH]).toBeUndefined();
  });

  it("a region whose inflated length disagrees with w*h*4 is skipped and counted", () => {
    const rec = buildRecord(
      [
        // Claims 8×8 (256 bytes) but the stream inflates to 4×4 (64).
        { ts: 100, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 8, 8, zlib(solidRgba(4, 4, [1, 1, 1, 255])), 1, 1) },
        // Claims 4×4 (64 bytes) but the stream inflates to 8×8 (256).
        { ts: 200, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, zlib(solidRgba(8, 8, [2, 2, 2, 255])), 1, 1) },
        // Raw, wrong length — caught statically, without inflating.
        { ts: 300, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, new Uint8Array(63), 1, 0) },
      ],
      v3Header(64, 64),
    );
    const out = decodeRdpRec(rec);
    // The raw one is rejected up front.
    expect(out.surfaceUpdates[2].error).toMatch(/raw surface data is 63 bytes/);
    expect(out.decoderCounts[COUNT_SURFACE_BAD_LENGTH]).toBe(1);
    // The two zlib ones can only be caught by inflating.
    expect(out.surfaceUpdates[0].error).toBeNull();
    expect(out.surfaceUpdates[1].error).toBeNull();
    const { painted, liveCounts } = replay(rec, out);
    expect(painted).toBe(0);
    expect(liveCounts[COUNT_SURFACE_BAD_LENGTH]).toBe(2);
    expect(liveCounts[COUNT_SURFACE]).toBeUndefined();

    const short = renderSurfaceUpdate(rec, out.surfaceUpdates[0]);
    expect(short.rgba).toBeNull();
    expect(short.error).toMatch(/expected 8x8x4 = 256/);
    const long = renderSurfaceUpdate(rec, out.surfaceUpdates[1]);
    expect(long.rgba).toBeNull();
    expect(long.error).toMatch(/expected 4x4x4 = 64/);
  });

  it("rejects unknown format and encoding bytes without guessing", () => {
    const rgba = solidRgba(4, 4, [1, 2, 3, 255]);
    const rec = buildRecord(
      [
        { ts: 100, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, rgba, 2, 0) },
        { ts: 200, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, rgba, 1, 9) },
        { ts: 300, kind: EVENT_SURFACE, payload: [0, 0, 0, 0, 4, 0] }, // prefix truncated
      ],
      v3Header(64, 64),
    );
    const out = decodeRdpRec(rec);
    expect(out.surfaceUpdates[0].error).toMatch(/unknown surface format 2/);
    expect(out.surfaceUpdates[1].error).toMatch(/unknown surface encoding 9/);
    expect(out.surfaceUpdates[2].error).toMatch(/payload truncated/);
    expect(out.decoderCounts[COUNT_SURFACE_BAD_FORMAT]).toBe(1);
    expect(out.decoderCounts[COUNT_SURFACE_BAD_ENCODING]).toBe(1);
    expect(out.decoderCounts["surface-truncated"]).toBe(1);
    expect(replay(rec, out).painted).toBe(0);
  });

  it("rejects gzip and raw deflate — encoding 1 is RFC 1950 zlib only", () => {
    const rgba = solidRgba(4, 4, [1, 2, 3, 255]);
    const rec = buildRecord(
      [
        { ts: 100, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, new Uint8Array(gzipSync(rgba)), 1, 1) },
        { ts: 200, kind: EVENT_SURFACE, payload: surfacePayload(0, 0, 4, 4, new Uint8Array(deflateRawSync(rgba)), 1, 1) },
      ],
      v3Header(64, 64),
    );
    const out = decodeRdpRec(rec);
    const { painted, liveCounts } = replay(rec, out);
    expect(painted).toBe(0);
    expect(liveCounts[COUNT_SURFACE_INFLATE_FAILED]).toBe(2);
  });

  it("reports a truncated final record instead of painting half of it", () => {
    const full = buildRecord(
      [
        surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [255, 0, 0, 255]), false),
        surfaceEvent(200, 4, 0, 4, 4, solidRgba(4, 4, [0, 255, 0, 255]), false),
      ],
      v3Header(64, 64),
    );
    // Lop 20 bytes off the last record's payload.
    const cut = full.subarray(0, full.length - 20);
    const out = decodeRdpRec(cut);
    expect(out.ok).toBe(true);
    expect(out.truncated).toMatch(/truncated final record: \d+ trailing bytes/);
    // The complete prefix still replays; the partial record produces
    // no event at all.
    expect(out.surfaceUpdates.length).toBe(1);
    const { canvas, painted } = replay(cut, out);
    expect(painted).toBe(1);
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 4, 0)).toEqual([0, 0, 0, 0]);

    // Truncating inside the 13-byte record header behaves the same.
    const cutHeader = full.subarray(0, full.length - 20 - 4 * 4 * 4 - 10 - 6);
    const out2 = decodeRdpRec(cutHeader);
    expect(out2.ok).toBe(true);
    expect(out2.truncated).not.toBeNull();
  });

  it("a version-3 file with no graphics at all is a named state", () => {
    const rec = buildRecord(
      [
        { ts: 100, kind: EVENT_KEYBOARD, payload: [...le16(0x1e), 1] },
        { ts: 200, kind: EVENT_MOUSE, payload: [...le16(10), ...le16(20), 0] },
        { ts: 300, kind: EVENT_DESKTOP_SIZE, payload: [...le16(1920), ...le16(1080)] },
      ],
      v3Header(),
    );
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
    expect(out.graphicsNotRecordable).toBe(true);
    expect(out.graphicsUndecodable).toBe(false);
    expect(out.frames.length).toBe(0);
    expect(out.surfaceUpdates.length).toBe(0);
    expect(out.keyboardEvents).toBe(1);
    expect(out.mouseEvents).toBe(1);
    // Not an empty success: the flag is what the player renders the
    // "graphics were not recordable" notice from.
    expect(replay(rec, out).painted).toBe(0);
  });

  it("a version-3 file that does carry graphics is not flagged not-recordable", () => {
    const rec = buildRecord(
      [surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [1, 2, 3, 255]), false)],
      v3Header(64, 64),
    );
    expect(decodeRdpRec(rec).graphicsNotRecordable).toBe(false);
  });

  it("a version-3 file may carry both 0x01 and 0x07", () => {
    const g = buildGraphicsUncompressed24(0, 0, 2, 2, [
      [0xff, 0, 0], [0, 0xff, 0], [0, 0, 0xff], [0xff, 0xff, 0xff],
    ]);
    const rec = buildRecord(
      [
        { ts: 100, kind: EVENT_GRAPHICS, payload: g },
        surfaceEvent(200, 8, 8, 4, 4, solidRgba(4, 4, [7, 7, 7, 255]), true),
      ],
      v3Header(64, 64),
    );
    const out = decodeRdpRec(rec);
    expect(out.frames.length).toBe(1);
    expect(out.frames[0].error).toBeNull();
    expect(out.surfaceUpdates.length).toBe(1);
    expect(out.timeline.map((e) => e.kind)).toEqual(["bitmap", "surface"]);
    const { canvas, painted } = replay(rec, out);
    expect(painted).toBe(2);
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 8, 8)).toEqual([7, 7, 7, 255]);
  });

  it("a 0x07 in a version-2 file is skipped, not painted", () => {
    const rec = buildRecord([
      surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [1, 2, 3, 255]), false),
    ]);
    const out = decodeRdpRec(rec);
    expect(out.version).toBe(2);
    expect(out.surfaceUpdates[0].error).toMatch(/version-2 recording/);
    expect(out.decoderCounts[COUNT_SURFACE_BAD_VERSION]).toBe(1);
    expect(replay(rec, out).painted).toBe(0);
  });

  it("a newer format version decodes what it understands and flags itself", () => {
    // Version 5 does not exist. It stands in for "produced by a
    // bastion newer than this player" — which was version 4 until
    // this player learned version 4.
    const header = JSON.stringify({
      version: 5,
      screen_width: 64,
      screen_height: 64,
      graphics_encodings: ["rgba8888", "some_future_thing"],
      a_field_we_have_never_seen: { nested: true },
    }) + "\n";
    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [255, 0, 0, 255]), true),
        { ts: 200, kind: 0x33, payload: Array.from(new Uint8Array(41).fill(1)) },
        surfaceEvent(300, 4, 0, 4, 4, solidRgba(4, 4, [0, 255, 0, 255]), false),
      ],
      header,
    );
    const out = decodeRdpRec(rec);
    expect(out.version).toBe(5);
    expect(out.newerFormat).toBe(true);
    expect(out.unknownEvents).toBe(1);
    expect(out.truncated).toBeNull();
    const { canvas, painted } = replay(rec, out);
    expect(painted).toBe(2);
    expect(pixelAt(canvas, 0, 0)).toEqual([255, 0, 0, 255]);
    expect(pixelAt(canvas, 4, 0)).toEqual([0, 255, 0, 255]);
  });

  it("a full-desktop region is indexed without inflating it", () => {
    // 1920×1080×4 = 8.3 MB per region. The index must not hold pixels,
    // or a real session's ~450 regions would retain gigabytes.
    const rgba = solidRgba(1920, 1080, [17, 34, 51, 255]);
    const rec = buildRecord(
      [surfaceEvent(1000, 0, 0, 1920, 1080, rgba, true)],
      v3Header(),
    );
    const out = decodeRdpRec(rec);
    const u = out.surfaceUpdates[0];
    expect(u.error).toBeNull();
    expect(u.dataLen).toBeLessThan(1920 * 1080 * 4);
    expect(Object.keys(u)).not.toContain("rgba");
    const render = renderSurfaceUpdate(rec, u);
    expect(render.error).toBeNull();
    expect(render.rgba?.length).toBe(1920 * 1080 * 4);
    expect(Array.from(render.rgba!.subarray(0, 4))).toEqual([17, 34, 51, 255]);
    expect(render.countKey).toBe(COUNT_SURFACE);
  });
});

// ─── Version 4: the keystroke track is transparent to the video ────

describe("rdpDecoder — version 4 (keystroke metadata)", () => {
  const V4_KEYSTROKE_FIELDS = {
    keystroke_metadata: true,
    keyboard_layout: "0x00000416",
    keyboard_layout_source: "client_core",
    max_reorder_ms: 2000,
  };

  function v4Header(w = 64, h = 64, keystrokes = true): string {
    return (
      JSON.stringify({
        version: 4,
        screen_width: w,
        screen_height: h,
        graphics_encodings: ["ts_update_bitmap", "rgba8888"],
        ...(keystrokes
          ? V4_KEYSTROKE_FIELDS
          : { keystroke_metadata: false, keyboard_layout: null, max_reorder_ms: 0 }),
      }) + "\n"
    );
  }

  /// A `0x08` text-input record: `flags:u8 field_epoch:u32
  /// char_count:u16 text_len:u16 text[]`.
  function textInputPayload(flags: number, epoch: number, text: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(text));
    return [flags, ...le32(epoch), ...le16(text.length), ...le16(bytes.length), ...bytes];
  }

  /// A `0x7F` trailer record with its self-locating footer.
  function trailerPayload(json: string): number[] {
    const jsonBytes = Array.from(new TextEncoder().encode(json));
    const payloadLen = jsonBytes.length + 8;
    const recordLen = 13 + payloadLen;
    return [...jsonBytes, ...le32(recordLen), 0x52, 0x4b, 0x54, 0x52];
  }

  const TRAILER_JSON = JSON.stringify({
    trailer_version: 1,
    text_decoding: "exact",
    runs: [{ t: 150, d: 20, n: 2, text: "hi", redacted: false, epoch: 1 }],
    search_text: "hi",
    census: {},
  });

  /// The graphics half of a recording — identical bytes in the v3 and
  /// v4 fixtures below, so any difference in the decoded canvas is
  /// attributable to the keystroke records alone.
  const graphicsEvents = () => [
    surfaceEvent(100, 0, 0, 8, 8, solidRgba(8, 8, [255, 0, 0, 255]), true),
    { ts: 200, kind: EVENT_DESKTOP_SIZE, payload: [...le16(64), ...le16(64)] },
    surfaceEvent(300, 8, 0, 8, 8, solidRgba(8, 8, [0, 255, 0, 255]), false),
    surfaceEvent(400, 0, 8, 8, 8, solidRgba(8, 8, [0, 0, 255, 255]), true),
  ];

  it("renders a version-4 file's graphics identically to version 3", () => {
    // The acceptance criterion: `0x08` and `0x7F` are transparent to
    // the video path. Same graphics records, one file with a
    // keystroke track interleaved and one without, byte-identical
    // canvas.
    const v3 = buildRecord(graphicsEvents(), v3Header(64, 64));
    const v4 = buildRecord(
      [
        graphicsEvents()[0],
        // A keystroke record stamped *earlier* than the graphics
        // around it — version 4's non-monotonic stream.
        { ts: 150, kind: 0x08, payload: textInputPayload(0x08, 1, "hi") },
        graphicsEvents()[1],
        graphicsEvents()[2],
        { ts: 350, kind: 0x08, payload: textInputPayload(0x09, 2, "") },
        graphicsEvents()[3],
        { ts: 500, kind: 0x7f, payload: trailerPayload(TRAILER_JSON) },
      ],
      v4Header(),
    );

    const outV3 = decodeRdpRec(v3);
    const outV4 = decodeRdpRec(v4);
    const a = replay(v3, outV3);
    const b = replay(v4, outV4);
    expect(b.painted).toBe(a.painted);
    expect(Array.from(b.canvas.px)).toEqual(Array.from(a.canvas.px));
    expect(outV4.surfaceUpdates.length).toBe(outV3.surfaceUpdates.length);
    expect(outV4.desktopSizes).toEqual(outV3.desktopSizes);
    expect(outV4.timeline.length).toBe(outV3.timeline.length);
    // No graphics event landed in a skip bucket on either side.
    expect(outV4.decoderCounts[COUNT_SURFACE]).toBe(
      outV3.decoderCounts[COUNT_SURFACE],
    );
  });

  it("counts the keystroke records without treating them as unknown", () => {
    const rec = buildRecord(
      [
        surfaceEvent(100, 0, 0, 4, 4, solidRgba(4, 4, [1, 2, 3, 255]), false),
        { ts: 150, kind: 0x08, payload: textInputPayload(0x08, 1, "hi") },
        { ts: 250, kind: 0x08, payload: textInputPayload(0x09, 2, "") },
        { ts: 500, kind: 0x7f, payload: trailerPayload(TRAILER_JSON) },
      ],
      v4Header(),
    );
    const out = decodeRdpRec(rec);
    expect(out.version).toBe(4);
    expect(out.newerFormat).toBe(false);
    expect(out.textInputEvents).toBe(2);
    expect(out.keystrokeTrailer).toBe(true);
    // They are known types now, so they do not inflate the
    // unknown-event count that the player reports.
    expect(out.unknownEvents).toBe(0);
    expect(out.decoderCounts[COUNT_UNKNOWN_EVENT]).toBeUndefined();
    expect(out.truncated).toBeNull();
  });

  it("reads the version-4 header's keystroke fields", () => {
    const out = decodeRdpRec(buildRecord([], v4Header()));
    expect(out.keystrokeMetadata).toBe(true);
    expect(out.keyboardLayout).toBe("0x00000416");
    expect(out.keyboardLayoutSource).toBe("client_core");
    expect(out.maxReorderMs).toBe(2000);
  });

  it("distinguishes keystroke_metadata false from an absent field", () => {
    // Both read as `false`, but the version tells them apart, and the
    // player must not render either as "nothing was typed".
    const off = decodeRdpRec(buildRecord([], v4Header(64, 64, false)));
    expect(off.version).toBe(4);
    expect(off.keystrokeMetadata).toBe(false);
    expect(off.maxReorderMs).toBe(0);

    const v3 = decodeRdpRec(buildRecord([], v3Header(64, 64)));
    expect(v3.version).toBe(3);
    expect(v3.keystrokeMetadata).toBe(false);
  });

  it("takes durationMs from the maximum timestamp, not the last record", () => {
    // Version 4's records are not monotonic: a keystroke record
    // written last but stamped early must not shorten the recording.
    const rec = buildRecord(
      [
        surfaceEvent(9_000, 0, 0, 4, 4, solidRgba(4, 4, [1, 2, 3, 255]), false),
        { ts: 1_000, kind: 0x08, payload: textInputPayload(0x08, 1, "hi") },
      ],
      v4Header(),
    );
    expect(decodeRdpRec(rec).durationMs).toBe(9_000);
  });

  it("refuses a keystroke record in a file whose header predates it", () => {
    // A `0x08` at version 3 contradicts its own header. Counted in
    // its own bucket rather than read — silently accepting it would
    // be a fallback on an audit surface.
    const rec = buildRecord(
      [
        { ts: 150, kind: 0x08, payload: textInputPayload(0x08, 1, "hi") },
        { ts: 500, kind: 0x7f, payload: trailerPayload(TRAILER_JSON) },
      ],
      v3Header(64, 64),
    );
    const out = decodeRdpRec(rec);
    expect(out.textInputEvents).toBe(0);
    expect(out.keystrokeTrailer).toBe(false);
    expect(out.decoderCounts[COUNT_KEYSTROKE_BAD_VERSION]).toBe(2);
  });

  it("still replays a version-4 file truncated mid-trailer", () => {
    const full = buildRecord(
      [
        surfaceEvent(100, 0, 0, 8, 8, solidRgba(8, 8, [255, 0, 0, 255]), true),
        { ts: 500, kind: 0x7f, payload: trailerPayload(TRAILER_JSON) },
      ],
      v4Header(),
    );
    const cut = full.subarray(0, full.length - 30);
    const out = decodeRdpRec(cut);
    expect(out.ok).toBe(true);
    expect(out.truncated).not.toBeNull();
    // The complete prefix replays as normal.
    expect(out.surfaceUpdates.length).toBe(1);
    const { painted } = replay(cut, out);
    expect(painted).toBe(1);
  });
});
