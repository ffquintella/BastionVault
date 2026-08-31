// Mirrors the wire format written by `flush_frame` in
// gui/src-tauri/src/session/rdp.rs. If the Rust side changes the
// header or the rect table, these tests are what should fail first.

import { describe, it, expect } from "vitest";
import {
  decodeFrame,
  FrameDecodeError,
  FRAME_FLAG_FULL,
  FRAME_WIRE_VERSION,
} from "../lib/rdpFrames";

interface RectSpec {
  x: number;
  y: number;
  w: number;
  h: number;
  /** Byte value every pixel of this rect is filled with. */
  fill: number;
}

function le16(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff];
}

/** Build a frame message exactly as the Rust pump packs one. */
function buildFrame(opts: {
  version?: number;
  full?: boolean;
  width: number;
  height: number;
  rects: RectSpec[];
  /** Truncate the finished buffer to this many bytes. */
  truncateTo?: number;
  /** Claim a rect count different from the rects actually written. */
  rectCountOverride?: number;
}): ArrayBuffer {
  const out: number[] = [];
  out.push(opts.version ?? FRAME_WIRE_VERSION);
  out.push(opts.full ? FRAME_FLAG_FULL : 0);
  out.push(...le16(opts.rectCountOverride ?? opts.rects.length));
  out.push(...le16(opts.width));
  out.push(...le16(opts.height));
  for (const r of opts.rects) {
    out.push(...le16(r.x), ...le16(r.y), ...le16(r.w), ...le16(r.h));
  }
  for (const r of opts.rects) {
    for (let i = 0; i < r.w * r.h * 4; i++) out.push(r.fill);
  }
  const bytes = new Uint8Array(opts.truncateTo === undefined ? out : out.slice(0, opts.truncateTo));
  if (opts.truncateTo === undefined) bytes.set(out);
  return bytes.buffer as ArrayBuffer;
}

describe("decodeFrame", () => {
  it("decodes a single-rect incremental frame", () => {
    const buf = buildFrame({
      width: 1024,
      height: 600,
      rects: [{ x: 10, y: 20, w: 3, h: 2, fill: 0x7f }],
    });
    const frame = decodeFrame(buf);
    expect(frame.full).toBe(false);
    expect(frame.width).toBe(1024);
    expect(frame.height).toBe(600);
    expect(frame.rects).toHaveLength(1);
    const [rect] = frame.rects;
    expect(rect).toMatchObject({ x: 10, y: 20, width: 3, height: 2 });
    // Row-packed RGBA: 3 * 2 * 4 bytes.
    expect(rect.data).toHaveLength(24);
    expect([...rect.data].every((b) => b === 0x7f)).toBe(true);
  });

  it("reports the full-repaint flag", () => {
    const buf = buildFrame({
      full: true,
      width: 8,
      height: 4,
      rects: [{ x: 0, y: 0, w: 8, h: 4, fill: 1 }],
    });
    expect(decodeFrame(buf).full).toBe(true);
  });

  it("splits multiple rects at the right offsets", () => {
    const buf = buildFrame({
      width: 64,
      height: 64,
      rects: [
        { x: 0, y: 0, w: 2, h: 1, fill: 0xaa },
        { x: 30, y: 40, w: 1, h: 3, fill: 0xbb },
        { x: 5, y: 5, w: 4, h: 4, fill: 0xcc },
      ],
    });
    const { rects } = decodeFrame(buf);
    expect(rects).toHaveLength(3);
    expect(rects.map((r) => r.data.length)).toEqual([8, 12, 64]);
    expect(rects[0].data.every((b) => b === 0xaa)).toBe(true);
    expect(rects[1].data.every((b) => b === 0xbb)).toBe(true);
    expect(rects[2].data.every((b) => b === 0xcc)).toBe(true);
    expect(rects[1]).toMatchObject({ x: 30, y: 40, width: 1, height: 3 });
  });

  it("handles a frame with no rects", () => {
    const buf = buildFrame({ width: 100, height: 50, rects: [] });
    const frame = decodeFrame(buf);
    expect(frame.rects).toEqual([]);
    expect(frame.width).toBe(100);
  });

  it("returns views into the source buffer rather than copies", () => {
    const buf = buildFrame({
      width: 4,
      height: 1,
      rects: [{ x: 0, y: 0, w: 1, h: 1, fill: 0x11 }],
    });
    const { rects } = decodeFrame(buf);
    expect(rects[0].data.buffer).toBe(buf);
  });

  it("rejects a version it does not speak", () => {
    const buf = buildFrame({
      version: FRAME_WIRE_VERSION + 1,
      width: 4,
      height: 4,
      rects: [],
    });
    expect(() => decodeFrame(buf)).toThrow(FrameDecodeError);
    expect(() => decodeFrame(buf)).toThrow(/unsupported frame version/);
  });

  it("rejects a buffer shorter than the header", () => {
    expect(() => decodeFrame(new Uint8Array([1, 0, 0]).buffer as ArrayBuffer)).toThrow(
      /frame too short/,
    );
  });

  it("rejects a rect table truncated mid-entry", () => {
    // Claims two rects but only 8 header bytes + 8 table bytes exist.
    const buf = buildFrame({
      width: 16,
      height: 16,
      rects: [{ x: 0, y: 0, w: 1, h: 1, fill: 0 }],
      rectCountOverride: 2,
      truncateTo: 16,
    });
    expect(() => decodeFrame(buf)).toThrow(/truncated in rect table/);
  });

  it("rejects a frame whose pixel payload is short", () => {
    const full = buildFrame({
      width: 16,
      height: 16,
      rects: [{ x: 0, y: 0, w: 2, h: 2, fill: 9 }],
    });
    // Header (8) + table (8) + 16 of the 16 pixel bytes; drop 4.
    const buf = full.slice(0, full.byteLength - 4);
    expect(() => decodeFrame(buf)).toThrow(/truncated in rect 0/);
  });
});
