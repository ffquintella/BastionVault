/**
 * Resource Connect — RDP session pane (T38 Phases 1, 3 and 4).
 *
 * The canvas and chrome for one live RDP session, driven entirely by
 * props so the one-pane `/session/rdp` window and the Session Workspace
 * host the same component. Hands the host a binary IPC `Channel` for
 * canvas frames and forwards keyboard / mouse events back via dedicated
 * input commands.
 *
 * Keyboard: captured by the canvas while it has focus — never by the
 * window, so in a workspace only the focused pane's desktop gets keys.
 * Clicking the canvas grabs the keyboard; the release chord
 * (`lib/reservedChords`, `releaseKeyboard`) or clicking elsewhere gives it
 * back. Any other workspace chord is not forwarded. Keys still held when
 * the grab ends are released on the remote side, so a chord or a click
 * away never leaves a modifier stuck down on the desktop.
 *
 * The frame path is deliberately *not* a Tauri event. Events serialize
 * their payload to JSON and reach the webview as an `eval`'d script, so
 * a full-desktop repaint used to arrive as a multi-megabyte base64
 * string literal that this file then decoded one `charCodeAt` at a time.
 * A `Channel` carrying a raw body travels over the `ipc://` custom
 * protocol as real binary and lands here as an `ArrayBuffer` we can view
 * directly as `ImageData`. See `gui/src-tauri/src/session/rdp.rs` for the
 * wire format and `../../lib/rdpFrames` for the parse.
 */

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { extractError } from "../../lib/error";
import { canvasRgbaEncoder, cursorCssValue, type RdpCursorUpdate } from "../../lib/rdpCursor";
import { decodeFrame } from "../../lib/rdpFrames";
import { createWheelAccumulator } from "../../lib/rdpWheel";
import { activeChordBindings, formatChord, matchChord } from "../../lib/reservedChords";
import { useSessionInputPrefs } from "../../lib/sessionInputPrefs";
import { SessionPaneHeader, type SessionPaneStatus } from "./SessionPaneHeader";

interface ResizePayload {
  width: number;
  height: number;
}

/// Debounce window-resize → server-resize so we don't fire a
/// DisplayControl PDU for every pixel of drag. 250 ms feels
/// responsive without flooding the deactivation-reactivation
/// channel on a slow drag.
const RESIZE_DEBOUNCE_MS = 250;

export interface RdpPaneProps {
  token: string;
  closedEvent: string;
  resizeEvent: string;
  cursorEvent: string;
  label: string;
  /** Desktop size negotiated at open; the first frame header wins. */
  initialWidth: number;
  initialHeight: number;
  /** CSS height of the pane's root. The one-pane window passes `100vh`;
   *  a pane inside a layout fills its slot. */
  height?: string;
  /** Grab the keyboard when this becomes true (and on mount if it is). */
  focused?: boolean;
  onStatusChange?: (status: SessionPaneStatus) => void;
  /** The release chord was pressed: where focus should go next. */
  onReleaseKeyboard?: () => void;
  /** Workspace pane actions, rendered in the header. */
  headerExtra?: ReactNode;
}

export function RdpPane({
  token,
  closedEvent,
  resizeEvent,
  cursorEvent,
  label,
  initialWidth,
  initialHeight,
  height = "100%",
  focused = true,
  onStatusChange,
  onReleaseKeyboard,
  headerExtra,
}: RdpPaneProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  // Mirrors the canvas's backing-store size so we re-allocate it on
  // the next render after a server-confirmed resize without forcing a
  // React re-mount of the canvas element.
  const sizeRef = useRef<{ w: number; h: number }>({ w: initialWidth, h: initialHeight });
  const [status, setStatus] = useState<SessionPaneStatus>("connecting");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [keyboardGrabbed, setKeyboardGrabbed] = useState(false);
  // Re-render once the window's chord overrides land so the hint below
  // names the chord actually in force.
  useSessionInputPrefs();
  const onStatusRef = useRef(onStatusChange);
  onStatusRef.current = onStatusChange;
  const onReleaseRef = useRef(onReleaseKeyboard);
  onReleaseRef.current = onReleaseKeyboard;

  useEffect(() => {
    onStatusRef.current?.(status);
  }, [status]);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMessage("session token missing from URL");
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;

    // `alpha: false` — RDP framebuffers are opaque, and telling the
    // 2D context so lets the compositor skip per-pixel blending on
    // every putImageData.
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) {
      setStatus("error");
      setErrorMessage("could not acquire a 2D canvas context");
      return;
    }

    // Frame channel. Created here and handed to the host below;
    // until `session_attach_rdp_frames` resolves, the pump has
    // nowhere to send frames and simply keeps painting into its own
    // framebuffer, so the first frame we receive is always a
    // complete desktop.
    // Cleared by the effect teardown so a frame still in flight when
    // the pane unmounts cannot write to a detached canvas or set
    // state on a dead component.
    let attached = true;
    const frames = new Channel<ArrayBuffer>();
    frames.onmessage = (buffer) => {
      if (!attached) return;
      let frame;
      try {
        frame = decodeFrame(buffer);
      } catch (e) {
        // A parse failure is a version skew between this bundle and
        // the host binary, not a transient glitch. Say so instead of
        // painting a partially-decoded desktop.
        setStatus("error");
        setErrorMessage(e instanceof Error ? e.message : String(e));
        return;
      }
      // Resize off the frame header rather than waiting for the
      // `resize` event — separate transports, and the event can
      // arrive after the first frame at the new size. Reallocating
      // the backing store also clears it, which is fine: a frame
      // that changes the size is always a full repaint.
      if (frame.width !== canvas.width || frame.height !== canvas.height) {
        canvas.width = frame.width;
        canvas.height = frame.height;
        sizeRef.current = { w: frame.width, h: frame.height };
      }
      for (const rect of frame.rects) {
        // The Uint8ClampedArray is a view into `buffer`, which is a
        // concrete ArrayBuffer; the cast only restates that for TS,
        // whose ImageData signature rejects `ArrayBufferLike`.
        const image = new ImageData(
          rect.data as unknown as Uint8ClampedArray<ArrayBuffer>,
          rect.width,
          rect.height,
        );
        ctx.putImageData(image, rect.x, rect.y);
      }
      setStatus((prev) => (prev === "connecting" ? "open" : prev));
    };
    void invoke("session_attach_rdp_frames", { request: { token }, channel: frames }).then(
      () => {
        if (attached) setStatus((prev) => (prev === "connecting" ? "open" : prev));
      },
      (e: unknown) => {
        if (!attached) return;
        setStatus("error");
        setErrorMessage(`could not attach the frame channel: ${String(e)}`);
      },
    );

    const unlistenClosed = listen(closedEvent, () => {
      setStatus("closed");
    });

    // Server-confirmed DisplayControl resize. The backend has already
    // re-allocated its DecodedImage; resize ours to match so future
    // putImageData calls don't write outside the canvas backing store.
    const unlistenResize = resizeEvent
      ? listen<ResizePayload>(resizeEvent, (ev) => {
          const { width, height } = ev.payload;
          sizeRef.current = { w: width, h: height };
          canvas.width = width;
          canvas.height = height;
        })
      : Promise.resolve(() => undefined);

    // Remote pointer shape. The canvas keeps its local cursor
    // position — only the sprite crosses the network — so shape
    // changes the remote desktop drives (resize arrows on a window
    // edge, I-beam over a text field) show up without adding a round
    // trip to every mouse move.
    const unlistenCursor = cursorEvent
      ? listen<RdpCursorUpdate>(cursorEvent, (ev) => {
          canvas.style.cursor = cursorCssValue(ev.payload, canvasRgbaEncoder);
        })
      : Promise.resolve(() => undefined);

    // Container-resize → server-resize. Debounced so a drag emits one
    // DisplayControl PDU per pause, not per pixel. We measure the
    // outer container (which fills the pane) rather than the canvas
    // (which CSS-scales) — otherwise the canvas's own
    // resize-on-confirm would feed back into ResizeObserver.
    let resizeTimer: number | undefined;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const w = Math.max(200, Math.floor(entry.contentRect.width));
      const h = Math.max(200, Math.floor(entry.contentRect.height));
      if (resizeTimer !== undefined) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        // Cap at the DisplayControl ceiling (8192) — the backend
        // also clamps via MonitorLayoutEntry::adjust_display_size,
        // but trimming here saves one pointless round trip.
        const width = Math.min(8192, w);
        const height = Math.min(8192, h);
        if (width === sizeRef.current.w && height === sizeRef.current.h) return;
        void invoke("session_input_rdp_resize", {
          request: { token, width, height },
        }).catch(() => undefined);
      }, RESIZE_DEBOUNCE_MS);
    });
    if (containerRef.current) observer.observe(containerRef.current);

    // Viewport coords → canvas-relative coords, clamped to
    // [0, width-1] / [0, height-1]. The canvas CSS-scales, so the
    // ratio between its backing store and its box matters.
    const canvasPoint = (ev: { clientX: number; clientY: number }) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width / rect.width;
      const scaleY = canvas.height / rect.height;
      return {
        x: Math.max(0, Math.min(canvas.width - 1, Math.round((ev.clientX - rect.left) * scaleX))),
        y: Math.max(0, Math.min(canvas.height - 1, Math.round((ev.clientY - rect.top) * scaleY))),
      };
    };

    // Mouse forwarding. The button index follows JS MouseEvent
    // semantics (0=left, 1=middle, 2=right).
    const sendMouse = (ev: MouseEvent, kind: "move" | "down" | "up") => {
      const { x, y } = canvasPoint(ev);
      void invoke("session_input_rdp_mouse", {
        request: {
          token,
          x,
          y,
          button: kind === "move" ? null : kind,
          button_index: kind === "move" ? null : ev.button,
        },
      }).catch(() => undefined);
    };

    const onMouseMove = (ev: MouseEvent) => sendMouse(ev, "move");
    const onMouseDown = (ev: MouseEvent) => {
      // preventDefault also suppresses the default focus change, so grab
      // the keyboard explicitly: clicking the desktop is how an operator
      // says "type here".
      ev.preventDefault();
      canvas.focus({ preventScroll: true });
      sendMouse(ev, "down");
    };
    const onMouseUp = (ev: MouseEvent) => sendMouse(ev, "up");
    const onContextMenu = (ev: Event) => ev.preventDefault();

    // Wheel forwarding. Registered non-passive so preventDefault
    // actually suppresses the webview's own scroll — otherwise the
    // window rubber-bands while the remote desktop stays put. The
    // accumulator reads the event's 120-per-notch `wheelDelta*` where
    // the engine has it (WKWebView's pixel deltas are on a different
    // scale entirely, which is why scrolling did nothing on macOS)
    // and carries sub-notch remainders, which is what makes a
    // trackpad scroll at all: its gestures are a fraction of a notch
    // per event.
    const accumulateWheel = createWheelAccumulator();
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const { vertical, horizontal } = accumulateWheel(ev);
      if (vertical === 0 && horizontal === 0) return;
      const { x, y } = canvasPoint(ev);
      // Two axes are two PDUs — MS-RDPBCGR has no combined event.
      for (const [units, isHorizontal] of [
        [vertical, false],
        [horizontal, true],
      ] as const) {
        if (units === 0) continue;
        void invoke("session_input_rdp_wheel", {
          request: { token, x, y, units, horizontal: isHorizontal },
        }).catch(() => undefined);
      }
    };

    // Keyboard: on the canvas, so only the pane that has focus forwards
    // keys. `held` is every code we sent a key-down for; a key-up is
    // forwarded only for those, and whatever is still held when the grab
    // ends is released, so the remote never sees a stuck modifier.
    const held = new Set<string>();
    const sendKey = (code: string, pressed: boolean) => {
      void invoke("session_input_rdp_key", {
        request: { token, js_code: code, pressed },
      }).catch(() => undefined);
    };
    const releaseHeld = () => {
      for (const code of held) sendKey(code, false);
      held.clear();
    };
    const onKeyDown = (ev: KeyboardEvent) => {
      const action = matchChord(ev);
      if (action === "releaseKeyboard") {
        ev.preventDefault();
        ev.stopPropagation();
        canvas.blur();
        onReleaseRef.current?.();
        return;
      }
      // Any other workspace chord is the workspace's: not forwarded, and
      // left to bubble to the workspace's own handler.
      if (action !== null) return;
      // The host's `js_code_to_ps2_scancode` doesn't recognise
      // every key; suppress browser defaults for everything we
      // accept so Tab / arrow keys reach the remote session.
      ev.preventDefault();
      held.add(ev.code);
      sendKey(ev.code, true);
    };
    const onKeyUp = (ev: KeyboardEvent) => {
      ev.preventDefault();
      if (!held.delete(ev.code)) return;
      sendKey(ev.code, false);
    };
    const onFocus = () => setKeyboardGrabbed(true);
    const onBlur = () => {
      releaseHeld();
      setKeyboardGrabbed(false);
    };

    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mousedown", onMouseDown);
    canvas.addEventListener("mouseup", onMouseUp);
    canvas.addEventListener("contextmenu", onContextMenu);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("keydown", onKeyDown);
    canvas.addEventListener("keyup", onKeyUp);
    canvas.addEventListener("focus", onFocus);
    canvas.addEventListener("blur", onBlur);

    return () => {
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mousedown", onMouseDown);
      canvas.removeEventListener("mouseup", onMouseUp);
      canvas.removeEventListener("contextmenu", onContextMenu);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("keydown", onKeyDown);
      canvas.removeEventListener("keyup", onKeyUp);
      canvas.removeEventListener("focus", onFocus);
      canvas.removeEventListener("blur", onBlur);
      releaseHeld();
      attached = false;
      // No explicit detach command: the host drops the channel the
      // first time a send fails (the webview is gone by then) and
      // re-arms a full repaint, which is exactly what a reattaching
      // pane needs.
      void unlistenClosed.then((u) => u());
      void unlistenResize.then((u) => u());
      void unlistenCursor.then((u) => u());
      observer.disconnect();
      if (resizeTimer !== undefined) window.clearTimeout(resizeTimer);
      // Host-side teardown is owned by the host: closing the window
      // stops every session attached to it, and a workspace pane's close
      // button calls session_close. Do NOT call session_close here — React StrictMode
      // would drop the host session entry on the dev double-mount
      // while the actual WebviewWindow is still open. The Disconnect
      // button covers the user-driven close path explicitly.
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, closedEvent, resizeEvent, cursorEvent]);

  useEffect(() => {
    if (focused) canvasRef.current?.focus({ preventScroll: true });
  }, [focused, token]);

  async function handleDisconnect() {
    try {
      await invoke("session_close", { request: { token } });
    } catch (e) {
      // Refused (another window holds the session): say so instead of
      // pretending it closed.
      setErrorMessage(extractError(e));
      return;
    }
    setStatus("closed");
  }

  const release = activeChordBindings().byAction.get("releaseKeyboard");
  const releaseHint = release ? formatChord(release, activeChordBindings().platform) : "";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height,
        minHeight: 0,
        background: "#0b0b10",
        color: "#e6e6e6",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      }}
    >
      <SessionPaneHeader
        token={token}
        label={label}
        status={status}
        errorMessage={errorMessage}
        onDisconnect={handleDisconnect}
        extra={
          <>
            <span
              style={{ fontSize: 11, color: keyboardGrabbed ? "#7aa2f7" : "#8a8a9a", whiteSpace: "nowrap" }}
              title={
                keyboardGrabbed
                  ? `Keys go to the remote desktop. ${releaseHint} releases the keyboard.`
                  : "Click the desktop to send it keys."
              }
            >
              {keyboardGrabbed ? `keyboard → remote · ${releaseHint} releases` : "keyboard released"}
            </span>
            {headerExtra}
          </>
        }
      />

      <div
        ref={containerRef}
        style={{
          flex: 1,
          position: "relative",
          overflow: "hidden",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <canvas
          ref={canvasRef}
          width={initialWidth}
          height={initialHeight}
          style={{
            display: "block",
            background: "#0a0d18",
            // Placeholder until the first Pointer Update arrives —
            // replaced imperatively by the `cursorEvent` listener,
            // and left in place for a server that sends none.
            cursor: "crosshair",
            outline: "1px solid #1f2030",
            // Fill the container until the server confirms a resize.
            // The mouse-handler rescales coords via getBoundingClientRect,
            // so visual scaling stays input-correct.
            width: "100%",
            height: "100%",
            objectFit: "contain",
          }}
          tabIndex={0}
        />
      </div>
    </div>
  );
}
