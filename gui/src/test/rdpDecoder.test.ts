// Mirrors the Rust unit tests in gui/wasm/rdp-replay/src/lib.rs.
// If a Rust test passes but the JS twin fails, the TS port has drifted.

import { describe, it, expect } from "vitest";
import { decodeRdpRec } from "../lib/rdpDecoder";

const MAGIC = new TextEncoder().encode("RREC");
const EVENT_GRAPHICS = 0x01;
const EVENT_KEYBOARD = 0x02;
const EVENT_MOUSE = 0x03;
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
/// the pixel data on every graphics event
/// (`x:u16 | y:u16 | w:u16 | h:u16`, per Rustion
/// `docs/session-recording-format.md`). Fixtures must include it or
/// they test a payload shape the recorder never produces.
function recRectHeader(x: number, y: number, w: number, h: number): number[] {
  return [...le16(x), ...le16(y), ...le16(w), ...le16(h)];
}

function buildRecord(
  events: Array<{ ts: number; kind: number; payload: number[] }>,
  header = `{"version":1,"screen_width":${SCREEN_W},"screen_height":${SCREEN_H}}\n`,
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

describe("rdpDecoder", () => {
  it("uncompressed 24bpp round trip", () => {
    const pixels: Array<[number, number, number]> = [
      [0xff, 0, 0], [0, 0xff, 0],
      [0, 0, 0xff], [0xff, 0xff, 0xff],
    ];
    const g = buildGraphicsUncompressed24(10, 20, 2, 2, pixels);
    const rec = buildRecord([{ ts: 100, kind: EVENT_GRAPHICS, payload: g }]);
    const out = decodeRdpRec(rec);
    expect(out.ok).toBe(true);
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
    expect(out.decoderCounts["invalid-geometry"]).toBe(1);
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
      '{"version":1}\n',
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
    expect(out.decoderCounts["invalid-geometry"]).toBe(1);
  });

  it("reads TS_BITMAP_DATA after the recorder rect header, not at offset 0", () => {
    // Guards the actual bug: parsing at offset 0 makes the recorder's
    // x/y/w/h masquerade as destLeft/destTop/destRight/destBottom and
    // pushes every later field 8 bytes out of place. Here the recorder
    // header says 2×2 at (10,20) while the bitmap header that follows
    // carries the bpp/flags/length — a decoder reading offset 0 gets
    // bpp from the wrong bytes and fails.
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
