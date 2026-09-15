/**
 * Remote pointer shape for the RDP session window.
 *
 * MS-RDPBCGR never paints the cursor into the framebuffer — it ships
 * it out of band as Pointer Update PDUs — so the canvas frame stream
 * carries no cursor at all. The host
 * (`gui/src-tauri/src/session/rdp.rs`) decodes those PDUs and emits
 * the sprite on a per-session Tauri event; this module turns one of
 * those payloads into the CSS `cursor` value to install on the
 * canvas.
 *
 * Applying it as a CSS cursor rather than compositing it into the
 * frame is what keeps the operator's pointer moving at local speed:
 * only the *shape* crosses the network, and it changes exactly when
 * the remote desktop says so — the resize arrows on a window edge,
 * the I-beam over a text field, the busy spinner.
 */

/** Mirror of the Rust `CursorUpdate` enum (`#[serde(tag = "kind")]`). */
export type RdpCursorUpdate =
  | { kind: "hidden" }
  | { kind: "default" }
  | {
      kind: "bitmap";
      width: number;
      height: number;
      hotspot_x: number;
      hotspot_y: number;
      /** Row-packed, top-down, non-premultiplied RGBA, base64. */
      rgba_b64: string;
    };

/**
 * Renders RGBA pixels to a `data:` URL. Injected so the pure
 * conversion below stays testable without a real canvas — jsdom has
 * no `toDataURL`.
 */
export type RgbaEncoder = (
  rgba: Uint8ClampedArray,
  width: number,
  height: number,
) => string;

export class CursorDecodeError extends Error {}

/** base64 → bytes, validating the length against the declared size. */
export function decodeCursorRgba(
  b64: string,
  width: number,
  height: number,
): Uint8ClampedArray {
  const binary = atob(b64);
  const expected = width * height * 4;
  if (binary.length !== expected) {
    throw new CursorDecodeError(
      `cursor ${width}x${height}: got ${binary.length} bytes, expected ${expected}`,
    );
  }
  const bytes = new Uint8ClampedArray(expected);
  for (let i = 0; i < expected; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * CSS `cursor` value for one update.
 *
 * Returns `"none"` for a hidden pointer and `"default"` both for an
 * explicit default and for any sprite we cannot render — a cursor
 * that is merely wrong is recoverable, a canvas with no cursor is
 * not.
 *
 * The fallback keyword after the `url()` is not optional: a
 * `cursor: url(...) x y` with no keyword is an invalid declaration
 * and browsers drop the whole rule.
 */
export function cursorCssValue(
  update: RdpCursorUpdate,
  encode: RgbaEncoder,
): string {
  switch (update.kind) {
    case "hidden":
      return "none";
    case "default":
      return "default";
    case "bitmap":
      break;
  }
  try {
    const rgba = decodeCursorRgba(update.rgba_b64, update.width, update.height);
    const url = encode(rgba, update.width, update.height);
    if (!url) return "default";
    // Clamp rather than trust the wire: a hotspot outside the sprite
    // is an invalid declaration, which would leave the *previous*
    // shape installed instead of falling back.
    const hx = Math.max(0, Math.min(update.width - 1, Math.round(update.hotspot_x)));
    const hy = Math.max(0, Math.min(update.height - 1, Math.round(update.hotspot_y)));
    return `url(${url}) ${hx} ${hy}, default`;
  } catch {
    return "default";
  }
}

/**
 * The real encoder: an offscreen 2D canvas, `alpha: true` because a
 * cursor is mostly transparent.
 *
 * `putImageData` does not blend — it writes the RGBA straight into
 * the backing store — which is why the host must send
 * non-premultiplied alpha (ironrdp's `Accelerated` decode target).
 */
export function canvasRgbaEncoder(
  rgba: Uint8ClampedArray,
  width: number,
  height: number,
): string {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  if (!ctx) return "";
  ctx.putImageData(
    new ImageData(rgba as unknown as Uint8ClampedArray<ArrayBuffer>, width, height),
    0,
    0,
  );
  return canvas.toDataURL("image/png");
}
