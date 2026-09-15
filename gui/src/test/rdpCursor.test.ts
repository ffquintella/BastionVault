import { describe, expect, it } from "vitest";

import {
  CursorDecodeError,
  cursorCssValue,
  decodeCursorRgba,
  type RdpCursorUpdate,
} from "../lib/rdpCursor";

/** Deterministic stand-in for the real canvas encoder. */
const fakeEncoder = (rgba: Uint8ClampedArray, w: number, h: number) =>
  `data:image/png;base64,FAKE_${w}x${h}_${rgba.length}`;

const b64 = (bytes: number[]) =>
  btoa(String.fromCharCode(...bytes));

/** A 1x1 opaque red sprite. */
const onePixel = b64([0xff, 0x00, 0x00, 0xff]);

describe("decodeCursorRgba", () => {
  it("decodes base64 RGBA of the declared size", () => {
    expect(Array.from(decodeCursorRgba(onePixel, 1, 1))).toEqual([255, 0, 0, 255]);
  });

  it("rejects a payload whose length disagrees with the declared size", () => {
    expect(() => decodeCursorRgba(onePixel, 2, 1)).toThrow(CursorDecodeError);
  });
});

describe("cursorCssValue", () => {
  it("hides the cursor when the server hides the pointer", () => {
    expect(cursorCssValue({ kind: "hidden" }, fakeEncoder)).toBe("none");
  });

  it("falls back to the local default on an explicit default", () => {
    expect(cursorCssValue({ kind: "default" }, fakeEncoder)).toBe("default");
  });

  it("builds a url() with the hotspot and a mandatory fallback keyword", () => {
    const update: RdpCursorUpdate = {
      kind: "bitmap",
      width: 1,
      height: 1,
      hotspot_x: 0,
      hotspot_y: 0,
      rgba_b64: onePixel,
    };
    expect(cursorCssValue(update, fakeEncoder)).toBe(
      "url(data:image/png;base64,FAKE_1x1_4) 0 0, default",
    );
  });

  it("clamps a hotspot outside the sprite instead of emitting an invalid rule", () => {
    // An out-of-range hotspot makes the whole declaration invalid,
    // which would leave the *previous* shape installed.
    const update: RdpCursorUpdate = {
      kind: "bitmap",
      width: 1,
      height: 1,
      hotspot_x: 9,
      hotspot_y: 9,
      rgba_b64: onePixel,
    };
    expect(cursorCssValue(update, fakeEncoder)).toBe(
      "url(data:image/png;base64,FAKE_1x1_4) 0 0, default",
    );
  });

  it("degrades to the default cursor when the sprite does not decode", () => {
    const update: RdpCursorUpdate = {
      kind: "bitmap",
      width: 4,
      height: 4,
      hotspot_x: 0,
      hotspot_y: 0,
      rgba_b64: onePixel,
    };
    expect(cursorCssValue(update, fakeEncoder)).toBe("default");
  });

  it("degrades to the default cursor when the encoder produces nothing", () => {
    const update: RdpCursorUpdate = {
      kind: "bitmap",
      width: 1,
      height: 1,
      hotspot_x: 0,
      hotspot_y: 0,
      rgba_b64: onePixel,
    };
    expect(cursorCssValue(update, () => "")).toBe("default");
  });
});
