// DOM wheel deltas → RDP wheel-rotation units.
//
// RDP counts wheel rotation in units of 120 per physical notch
// (MS-RDPBCGR 2.2.8.1.1.3.1.1.3, the wire equivalent of Windows'
// `WHEEL_DELTA`), signed: positive is up for the vertical wheel and
// right for the horizontal one.
//
// The unit we need is therefore *notches*, not pixels — and the only
// cross-platform source of it is the legacy `wheelDeltaX` /
// `wheelDeltaY` pair, which every WebKit and Chromium engine reports
// in exactly those 120-per-notch units. Preferring it is what makes
// this work on macOS: WKWebView's `deltaY` for one notch is nowhere
// near the ~100 px Chromium on Windows and Linux report, so a
// fixed pixels-per-notch conversion turned a full notch into a few
// units of rotation — far under the `WHEEL_DELTA` an application on
// the remote desktop divides by, i.e. no scrolling at all.
//
// `wheelDelta*` carries the opposite sign to `delta*` on both axes
// (positive is up / left), so the vertical axis passes through and
// the horizontal one is negated.
//
// Engines without `wheelDelta*` (Firefox removed it) fall back to the
// pixel path: normalise `deltaMode` to pixels and scale by
// `WHEEL_UNITS_PER_NOTCH / PIXELS_PER_NOTCH`.
//
// Either way a trackpad emits a long stream of sub-notch deltas
// rather than one notch per gesture, so we keep a fractional carry
// per axis: send the whole units, remember the remainder, and a slow
// scroll accumulates into movement instead of rounding to zero on
// every event.

/** RDP rotation units in one physical notch. Mirrors `WHEEL_UNITS_PER_NOTCH`
 *  in `gui/src-tauri/src/session/rdp.rs`. */
export const WHEEL_UNITS_PER_NOTCH = 120;

/** Pixels the DOM reports for one notch of a conventional mouse wheel
 *  on the engines that lack `wheelDelta*` (Firefox lands on ~100).
 *  Only used by the fallback path — see the header. */
export const PIXELS_PER_NOTCH = 100;

/** `deltaMode` 1 is lines; browsers that use it mean a text line. */
const PIXELS_PER_LINE = 33;

/** `deltaMode` 2 is pages. Sized so a page is four notches rather than
 *  a screenful, which would be an unusable jump on the remote side. */
const PIXELS_PER_PAGE = 400;

export interface WheelRotation {
  /** Signed rotation units, positive = up. Zero when the carry has
   *  not yet reached a whole unit. */
  vertical: number;
  /** Signed rotation units, positive = right. */
  horizontal: number;
}

export interface WheelDelta {
  deltaX: number;
  deltaY: number;
  deltaMode?: number;
  /** Legacy 120-per-notch rotation, positive = left. Present on
   *  WebKit and Chromium, absent on Firefox. */
  wheelDeltaX?: number;
  /** Legacy 120-per-notch rotation, positive = up. */
  wheelDeltaY?: number;
}

function toPixels(delta: number, mode: number): number {
  switch (mode) {
    case 1:
      return delta * PIXELS_PER_LINE;
    case 2:
      return delta * PIXELS_PER_PAGE;
    default:
      return delta;
  }
}

/** True only when both legacy fields are usable numbers. Checked by
 *  presence, not by value: a purely horizontal gesture reports
 *  `wheelDeltaY === 0`, which is a real reading and not a missing one. */
function hasWheelDelta(ev: WheelDelta): boolean {
  return (
    typeof ev.wheelDeltaX === "number" &&
    typeof ev.wheelDeltaY === "number" &&
    Number.isFinite(ev.wheelDeltaX) &&
    Number.isFinite(ev.wheelDeltaY)
  );
}

/**
 * Stateful DOM-delta → rotation-unit converter, one per session
 * window. Not reentrant; call it from the wheel handler only.
 */
export function createWheelAccumulator(): (ev: WheelDelta) => WheelRotation {
  // Sub-unit remainders, carried between events so a trackpad's
  // stream of fractional-notch deltas eventually scrolls.
  let carryX = 0;
  let carryY = 0;
  return (ev: WheelDelta): WheelRotation => {
    if (hasWheelDelta(ev)) {
      // Already in RDP's units. Vertical sign matches; horizontal is
      // negated because `wheelDeltaX` counts leftwards.
      carryY += ev.wheelDeltaY as number;
      carryX += -(ev.wheelDeltaX as number);
    } else {
      const mode = ev.deltaMode ?? 0;
      const scale = WHEEL_UNITS_PER_NOTCH / PIXELS_PER_NOTCH;
      // Negated: DOM deltaY grows downwards, RDP rotation grows upwards.
      carryY += -toPixels(ev.deltaY, mode) * scale;
      carryX += toPixels(ev.deltaX, mode) * scale;
    }
    // `+ 0` turns Math.trunc's -0 back into 0 — a signed zero is
    // still "no rotation", and callers compare against 0.
    const vertical = Math.trunc(carryY) + 0;
    const horizontal = Math.trunc(carryX) + 0;
    carryY -= vertical;
    carryX -= horizontal;
    return { vertical, horizontal };
  };
}
