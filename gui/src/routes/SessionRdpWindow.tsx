/**
 * Resource Connect — RDP session window (Phase 4).
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_rdp` command. Hands the host a binary IPC
 * `Channel` for canvas frames and forwards keyboard / mouse events
 * back via dedicated input commands.
 *
 * The frame path is deliberately *not* a Tauri event. Events
 * serialize their payload to JSON and reach the webview as an
 * `eval`'d script, so a full-desktop repaint used to arrive as a
 * multi-megabyte base64 string literal that this file then decoded
 * one `charCodeAt` at a time. A `Channel` carrying a raw body
 * travels over the `ipc://` custom protocol as real binary and
 * lands here as an `ArrayBuffer` we can view directly as
 * `ImageData`. See `gui/src-tauri/src/session/rdp.rs` for the wire
 * format and `../lib/rdpFrames` for the parse.
 */

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { RustionSessionChip } from "../components/RustionSessionChip";
import { decodeFrame } from "../lib/rdpFrames";

interface ResizePayload {
  width: number;
  height: number;
}

/// Debounce window-resize → server-resize so we don't fire a
/// DisplayControl PDU for every pixel of drag. 250 ms feels
/// responsive without flooding the deactivation-reactivation
/// channel on a slow drag.
const RESIZE_DEBOUNCE_MS = 250;

export function SessionRdpWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const resizeEvent = params.get("resize") ?? "";
  const label = params.get("label") ?? "rdp session";
  const initWidth = parseInt(params.get("w") ?? "1024", 10) || 1024;
  const initHeight = parseInt(params.get("h") ?? "600", 10) || 600;

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  // Mirrors the canvas's backing-store size so we re-allocate it on
  // the next render after a server-confirmed resize without forcing a
  // React re-mount of the canvas element.
  const sizeRef = useRef<{ w: number; h: number }>({ w: initWidth, h: initHeight });
  const [status, setStatus] = useState<"connecting" | "open" | "closed" | "error">(
    "connecting",
  );
  const [errorMessage, setErrorMessage] = useState<string>("");

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
    // the window unmounts cannot write to a detached canvas or set
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

    // Window-resize → server-resize. Debounced so a drag emits one
    // DisplayControl PDU per pause, not per pixel. We measure the
    // outer container (which fills the window) rather than the
    // canvas (which CSS-scales) — otherwise the canvas's own
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

    // Mouse forwarding. The button index follows JS MouseEvent
    // semantics (0=left, 1=middle, 2=right). canvas-relative
    // coordinates are clamped to [0, width-1] / [0, height-1].
    const sendMouse = (
      ev: MouseEvent,
      kind: "move" | "down" | "up",
    ) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width / rect.width;
      const scaleY = canvas.height / rect.height;
      const x = Math.max(0, Math.min(canvas.width - 1, Math.round((ev.clientX - rect.left) * scaleX)));
      const y = Math.max(0, Math.min(canvas.height - 1, Math.round((ev.clientY - rect.top) * scaleY)));
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
      ev.preventDefault();
      sendMouse(ev, "down");
    };
    const onMouseUp = (ev: MouseEvent) => sendMouse(ev, "up");
    const onContextMenu = (ev: Event) => ev.preventDefault();

    const onKeyDown = (ev: KeyboardEvent) => {
      // The host's `js_code_to_ps2_scancode` doesn't recognise
      // every key; suppress browser defaults for everything we
      // accept so Tab / arrow keys reach the remote session.
      ev.preventDefault();
      void invoke("session_input_rdp_key", {
        request: { token, js_code: ev.code, pressed: true },
      }).catch(() => undefined);
    };
    const onKeyUp = (ev: KeyboardEvent) => {
      ev.preventDefault();
      void invoke("session_input_rdp_key", {
        request: { token, js_code: ev.code, pressed: false },
      }).catch(() => undefined);
    };

    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mousedown", onMouseDown);
    canvas.addEventListener("mouseup", onMouseUp);
    canvas.addEventListener("contextmenu", onContextMenu);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);

    return () => {
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mousedown", onMouseDown);
      canvas.removeEventListener("mouseup", onMouseUp);
      canvas.removeEventListener("contextmenu", onContextMenu);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      attached = false;
      // No explicit detach command: the host drops the channel the
      // first time a send fails (the webview is gone by then) and
      // re-arms a full repaint, which is exactly what a reattaching
      // window needs.
      void unlistenClosed.then((u) => u());
      void unlistenResize.then((u) => u());
      observer.disconnect();
      if (resizeTimer !== undefined) window.clearTimeout(resizeTimer);
      // Host-side teardown is owned by the Tauri WindowEvent::
      // CloseRequested hook on the Rust side. Do NOT call
      // session_close here — React StrictMode would drop the host
      // session entry on the dev double-mount while the actual
      // WebviewWindow is still open. The Disconnect button covers
      // the user-driven close path explicitly.
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, closedEvent, resizeEvent]);

  async function handleDisconnect() {
    try {
      await invoke("session_close", { request: { token } });
    } catch {
      // ignore
    }
    setStatus("closed");
  }

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        background: "#0b0b10",
        color: "#e6e6e6",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      }}
    >
      <div
        style={{
          padding: "6px 12px",
          borderBottom: "1px solid #1f2030",
          background: "#11121a",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <strong style={{ fontSize: 13 }}>{label}</strong>
        <span
          style={{
            fontSize: 11,
            padding: "2px 8px",
            borderRadius: 999,
            background:
              status === "open"
                ? "#1a4533"
                : status === "closed"
                  ? "#3a3a3a"
                  : status === "error"
                    ? "#5e1f1f"
                    : "#2a2f5e",
            color: "#e6e6e6",
          }}
        >
          {status}
        </span>
        {errorMessage && (
          <span style={{ fontSize: 11, color: "#ff6e6e" }}>{errorMessage}</span>
        )}
        <div style={{ flex: 1 }} />
        <RustionSessionChip token={token} />
        <button
          onClick={handleDisconnect}
          disabled={status === "closed"}
          style={{
            background: "#5e1f1f",
            color: "#e6e6e6",
            border: "1px solid #7a2a2a",
            padding: "4px 10px",
            borderRadius: 4,
            cursor: status === "closed" ? "not-allowed" : "pointer",
            opacity: status === "closed" ? 0.6 : 1,
            fontSize: 12,
          }}
        >
          Disconnect
        </button>
      </div>

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
          width={initWidth}
          height={initHeight}
          style={{
            display: "block",
            background: "#0a0d18",
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
