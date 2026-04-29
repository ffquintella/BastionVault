/**
 * Resource Connect — RDP session window (Phase 4).
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_rdp` command. Subscribes to per-session frame
 * events (full-frame RGBA snapshots) and forwards keyboard /
 * mouse events back via dedicated input commands. Phase 4
 * limitations — no NLA / CredSSP, full-frame snapshots only — are
 * documented in `gui/src-tauri/src/session/rdp.rs`.
 */

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface FramePayload {
  bytes_b64: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

function b64ToBytes(b64: string): Uint8ClampedArray {
  const bin = atob(b64);
  // Allocate a fresh ArrayBuffer so the Uint8ClampedArray's buffer
  // is unambiguously `ArrayBuffer` (not `SharedArrayBuffer`) — the
  // ImageData constructor's TS signature requires that exact type.
  const ab = new ArrayBuffer(bin.length);
  const out = new Uint8ClampedArray(ab);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function SessionRdpWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const frameEvent = params.get("frame") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const label = params.get("label") ?? "rdp session";
  const initWidth = parseInt(params.get("w") ?? "1024", 10) || 1024;
  const initHeight = parseInt(params.get("h") ?? "600", 10) || 600;

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
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

    // Subscribe to frame events first so we don't miss the very
    // first paint (the active-stage pump can fire a frame as soon
    // as the deactivate-all sequence finishes).
    const unlistenFrame = listen<FramePayload>(frameEvent, (ev) => {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      const { bytes_b64, x, y, width, height } = ev.payload;
      const bytes = b64ToBytes(bytes_b64);
      // Phase 4 emits full-frame snapshots — width/height match the
      // canvas. Once the dirty-rect optimization lands, the same
      // putImageData call writes only the changed region. Cast the
      // typed array to satisfy `ImageDataArray` — TS infers
      // `ArrayBufferLike` because of the Tauri payload's lifetime
      // story, but the underlying ArrayBuffer we allocated above
      // is concrete.
      const image = new ImageData(bytes as unknown as Uint8ClampedArray<ArrayBuffer>, width, height);
      ctx.putImageData(image, x, y);
      if (status !== "open") setStatus("open");
    });
    const unlistenClosed = listen(closedEvent, () => {
      setStatus("closed");
    });

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
      void unlistenFrame.then((u) => u());
      void unlistenClosed.then((u) => u());
      void invoke("session_close", { request: { token } }).catch(() => undefined);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, frameEvent, closedEvent]);

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

      <div style={{ flex: 1, position: "relative", overflow: "hidden", display: "flex", justifyContent: "center", alignItems: "center" }}>
        <canvas
          ref={canvasRef}
          width={initWidth}
          height={initHeight}
          style={{
            display: "block",
            background: "#0a0d18",
            cursor: "crosshair",
            outline: "1px solid #1f2030",
          }}
          tabIndex={0}
        />
      </div>
    </div>
  );
}
