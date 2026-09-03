// DOM wheel deltas → RDP wheel-rotation units.
//
// RDP counts wheel rotation in units of 120 per physical notch
// (MS-RDPBCGR 2.2.8.1.1.3.1.1.3, the wire equivalent of Windows'
// `WHEEL_DELTA`), signed: positive is up for the vertical wheel and
// right for the horizontal one. The DOM's sign convention is the
// opposite on the vertical axis — `deltaY > 0` means the content
// scrolls *down* — so the vertical axis is negated here and the
// horizontal one is not.
//
// A `WheelEvent` reports its delta in one of three units
// (`deltaMode`), and a trackpad emits a long stream of sub-notch
// pixel deltas rather than one notch per gesture. Both are handled by
// normalising to pixels and keeping a fractional carry per axis: we
// send the whole units and remember the remainder, so a slow scroll
// accumulates into movement instead of rounding to zero on every
// event.

/** RDP rotation units in one physical notch. Mirrors `WHEEL_UNITS_PER_NOTCH`
 *  in `gui/src-tauri/src/session/rdp.rs`. */
export const WHEEL_UNITS_PER_NOTCH = 120;

/** Pixels the DOM reports for one notch of a conventional mouse wheel
 *  (three 33-px lines — Chrome and Firefox both land on ~100). */
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

/**
 * Stateful DOM-delta → rotation-unit converter, one per session
 * window. Not reentrant; call it from the wheel handler only.
 */
export function createWheelAccumulator(): (ev: WheelDelta) => WheelRotation {
  // Sub-unit remainders, carried between events so a trackpad's
  // stream of 1-2 px deltas eventually scrolls.
  let carryX = 0;
  let carryY = 0;
  return (ev: WheelDelta): WheelRotation => {
    const mode = ev.deltaMode ?? 0;
    const scale = WHEEL_UNITS_PER_NOTCH / PIXELS_PER_NOTCH;
    // Negated: DOM deltaY grows downwards, RDP rotation grows upwards.
    carryY += -toPixels(ev.deltaY, mode) * scale;
    carryX += toPixels(ev.deltaX, mode) * scale;
    // `+ 0` turns Math.trunc's -0 back into 0 — a signed zero is
    // still "no rotation", and callers compare against 0.
    const vertical = Math.trunc(carryY) + 0;
    const horizontal = Math.trunc(carryX) + 0;
    carryY -= vertical;
    carryX -= horizontal;
    return { vertical, horizontal };
  };
}
