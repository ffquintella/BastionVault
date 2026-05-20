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

function buildRecord(events: Array<{ ts: number; kind: number; payload: number[] }>): Uint8Array {
  const out: number[] = [];
  MAGIC.forEach((b) => out.push(b));
  '{"version":1}\n'.split("").forEach((c) => out.push(c.charCodeAt(0)));
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
  const p: number[] = [];
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
    const p: number[] = [];
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
    const p: number[] = [];
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
    const p: number[] = [];
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
    const bad: number[] = [];
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
});
