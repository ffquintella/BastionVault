import { describe, expect, it } from "vitest";

import {
  createWheelAccumulator,
  PIXELS_PER_NOTCH,
  WHEEL_UNITS_PER_NOTCH,
} from "../lib/rdpWheel";

describe("createWheelAccumulator", () => {
  it("turns one notch down into one negative notch of rotation", () => {
    const acc = createWheelAccumulator();
    // DOM deltaY grows downwards; RDP rotation grows upwards.
    expect(acc({ deltaX: 0, deltaY: PIXELS_PER_NOTCH })).toEqual({
      vertical: -WHEEL_UNITS_PER_NOTCH,
      horizontal: 0,
    });
    expect(acc({ deltaX: 0, deltaY: -PIXELS_PER_NOTCH })).toEqual({
      vertical: WHEEL_UNITS_PER_NOTCH,
      horizontal: 0,
    });
  });

  it("keeps the DOM sign on the horizontal axis", () => {
    const acc = createWheelAccumulator();
    expect(acc({ deltaX: PIXELS_PER_NOTCH, deltaY: 0 }).horizontal).toBe(
      WHEEL_UNITS_PER_NOTCH,
    );
  });

  it("accumulates sub-unit trackpad deltas instead of rounding them away", () => {
    const acc = createWheelAccumulator();
    // 0.5 px is 0.6 units — below one unit, so nothing goes out yet.
    expect(acc({ deltaX: 0, deltaY: 0.5 })).toEqual({ vertical: 0, horizontal: 0 });
    // The carry pushes the second event over a whole unit.
    expect(acc({ deltaX: 0, deltaY: 0.5 }).vertical).toBe(-1);
  });

  it("does not lose rotation across a stream of small events", () => {
    const acc = createWheelAccumulator();
    let total = 0;
    for (let i = 0; i < 100; i++) total += acc({ deltaX: 0, deltaY: 1 }).vertical;
    // 100 px == one notch, less whatever fraction of a unit the carry
    // is still holding (1.2 units per event is not exact in binary).
    expect(total).toBeLessThanOrEqual(-WHEEL_UNITS_PER_NOTCH + 1);
    expect(total).toBeGreaterThanOrEqual(-WHEEL_UNITS_PER_NOTCH);
  });

  it("scales line and page deltas into pixels", () => {
    const lines = createWheelAccumulator();
    expect(lines({ deltaX: 0, deltaY: 3, deltaMode: 1 }).vertical).toBe(-118); // 99 px
    const pages = createWheelAccumulator();
    expect(pages({ deltaX: 0, deltaY: 1, deltaMode: 2 }).vertical).toBe(
      -4 * WHEEL_UNITS_PER_NOTCH,
    );
  });

  it("reports both axes from one diagonal event", () => {
    const acc = createWheelAccumulator();
    expect(acc({ deltaX: PIXELS_PER_NOTCH, deltaY: PIXELS_PER_NOTCH })).toEqual({
      vertical: -WHEEL_UNITS_PER_NOTCH,
      horizontal: WHEEL_UNITS_PER_NOTCH,
    });
  });

  it("prefers wheelDelta, which is already in RDP rotation units", () => {
    const acc = createWheelAccumulator();
    // WebKit on macOS reports a notch as a handful of pixels, but
    // wheelDeltaY as a full 120. The pixel value must be ignored.
    expect(
      acc({ deltaX: 0, deltaY: 4, wheelDeltaX: 0, wheelDeltaY: -WHEEL_UNITS_PER_NOTCH }),
    ).toEqual({ vertical: -WHEEL_UNITS_PER_NOTCH, horizontal: 0 });
  });

  it("negates wheelDeltaX, which counts leftwards", () => {
    const acc = createWheelAccumulator();
    expect(
      acc({ deltaX: 4, deltaY: 0, wheelDeltaX: -WHEEL_UNITS_PER_NOTCH, wheelDeltaY: 0 }),
    ).toEqual({ vertical: 0, horizontal: WHEEL_UNITS_PER_NOTCH });
  });

  it("reads a zero wheelDelta axis as a real zero, not a missing field", () => {
    const acc = createWheelAccumulator();
    // A purely horizontal gesture: wheelDeltaY is 0 and deltaY may be
    // 0 too, but the presence of both fields must still take the
    // wheelDelta path rather than falling back to pixels.
    expect(
      acc({ deltaX: 100, deltaY: 0, wheelDeltaX: -120, wheelDeltaY: 0 }),
    ).toEqual({ vertical: 0, horizontal: 120 });
  });

  it("accumulates sub-notch wheelDelta values", () => {
    const acc = createWheelAccumulator();
    expect(acc({ deltaX: 0, deltaY: 0, wheelDeltaX: 0, wheelDeltaY: 0.4 })).toEqual({
      vertical: 0,
      horizontal: 0,
    });
    expect(
      acc({ deltaX: 0, deltaY: 0, wheelDeltaX: 0, wheelDeltaY: 0.7 }).vertical,
    ).toBe(1);
  });

  it("falls back to pixels when wheelDelta is absent", () => {
    const acc = createWheelAccumulator();
    expect(acc({ deltaX: 0, deltaY: PIXELS_PER_NOTCH }).vertical).toBe(
      -WHEEL_UNITS_PER_NOTCH,
    );
  });
});
