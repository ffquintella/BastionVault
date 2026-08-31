/**
 * Binary canvas-frame decoding for the RDP session window.
 *
 * The session pump (`gui/src-tauri/src/session/rdp.rs`) packs each
 * flush into one `ArrayBuffer` and pushes it down a Tauri IPC
 * `Channel`. Keeping the parse in its own module keeps it free of
 * DOM/Tauri imports, which is what makes it directly testable.
 *
 * Wire format, little-endian:
 *
 * ```text
 *   0      u8    version
 *   1      u8    flags   (bit 0: full-desktop repaint)
 *   2..4   u16   rect count
 *   4..6   u16   desktop width
 *   6..8   u16   desktop height
 *   8..    rect count × { u16 x, u16 y, u16 w, u16 h }
 *   ...          row-packed RGBA for each rect, in rect order
 * ```
 *
 * The desktop size is in every frame so the canvas can size itself
 * from the frame rather than from the separate `resize` event, which
 * is a different transport and can lose the race against the first
 * frame after a server-confirmed resize.
 */

export const FRAME_WIRE_VERSION = 1;
export const FRAME_FLAG_FULL = 0x01;

const HEADER_LEN = 8;
const RECT_LEN = 8;

export interface FrameRect {
  x: number;
  y: number;
  width: number;
  height: number;
  /**
   * Row-packed RGBA for this rect. A *view* into the frame buffer,
   * not a copy — it stays valid as long as the caller holds the
   * originating ArrayBuffer, which is exactly the lifetime of the
   * `putImageData` call it feeds.
   */
  data: Uint8ClampedArray;
}

export interface DecodedFrame {
  /** Repaints the whole desktop; anything previously drawn is stale. */
  full: boolean;
  /** Desktop size at the moment this frame was packed. */
  width: number;
  height: number;
  rects: FrameRect[];
}

export class FrameDecodeError extends Error {}

/**
 * Parse one frame message.
 *
 * Throws rather than returning a partial frame: a malformed buffer
 * means the Rust and TS sides disagree about the format, and
 * painting whatever survived the parse would show the operator a
 * corrupted desktop with no indication anything went wrong.
 */
export function decodeFrame(buffer: ArrayBuffer): DecodedFrame {
  if (buffer.byteLength < HEADER_LEN) {
    throw new FrameDecodeError(
      `frame too short: ${buffer.byteLength} bytes, need at least ${HEADER_LEN}`,
    );
  }
  const view = new DataView(buffer);
  const version = view.getUint8(0);
  if (version !== FRAME_WIRE_VERSION) {
    throw new FrameDecodeError(
      `unsupported frame version ${version} (this build speaks ${FRAME_WIRE_VERSION})`,
    );
  }
  const flags = view.getUint8(1);
  const rectCount = view.getUint16(2, true);
  const width = view.getUint16(4, true);
  const height = view.getUint16(6, true);

  const tableEnd = HEADER_LEN + rectCount * RECT_LEN;
  if (buffer.byteLength < tableEnd) {
    throw new FrameDecodeError(
      `frame truncated in rect table: ${buffer.byteLength} bytes, need ${tableEnd}`,
    );
  }

  const rects: FrameRect[] = [];
  let pixelOffset = tableEnd;
  for (let i = 0; i < rectCount; i++) {
    const base = HEADER_LEN + i * RECT_LEN;
    const x = view.getUint16(base, true);
    const y = view.getUint16(base + 2, true);
    const w = view.getUint16(base + 4, true);
    const h = view.getUint16(base + 6, true);
    const len = w * h * 4;
    if (pixelOffset + len > buffer.byteLength) {
      throw new FrameDecodeError(
        `frame truncated in rect ${i} (${w}x${h}): need ${len} bytes at ${pixelOffset}, ` +
          `buffer is ${buffer.byteLength}`,
      );
    }
    rects.push({
      x,
      y,
      width: w,
      height: h,
      data: new Uint8ClampedArray(buffer, pixelOffset, len),
    });
    pixelOffset += len;
  }

  return { full: (flags & FRAME_FLAG_FULL) !== 0, width, height, rects };
}
