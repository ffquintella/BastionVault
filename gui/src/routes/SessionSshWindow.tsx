/**
 * Resource Connect — SSH session window.
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_ssh` command. The window claims its session via
 * the URL params:
 *   token     — opaque session id used by every Tauri command call
 *   stdout    — event name the host emits remote PTY bytes on
 *   closed    — event name the host emits when the remote PTY hangs up
 *   label     — operator-visible title (e.g. `ssh felipe@host:22`)
 *
 * The credential bytes never travel through this React layer; they
 * were resolved on the Rust side before the window was even
 * spawned. We just pump bytes between the local xterm.js terminal
 * and the host's session control channel.
 */

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

interface StdoutPayload {
  bytes_b64: string;
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function SessionSshWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const stdoutEvent = params.get("stdout") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const label = params.get("label") ?? "ssh session";

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
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
    if (!containerRef.current) return;

    // Create the xterm instance once and attach.
    const term = new Terminal({
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 13,
      theme: {
        background: "#0b0b10",
        foreground: "#e6e6e6",
        cursor: "#7aa2f7",
      },
      cursorBlink: true,
      convertEol: false,
      scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;
    setStatus("open");

    // Forward keystrokes → host. xterm gives us already-utf8 strings;
    // encode → bytes → base64 so we don't need a binary IPC channel.
    const onDataDispose = term.onData((data) => {
      const bytes = new TextEncoder().encode(data);
      void invoke("session_input", {
        request: { token, bytes_b64: bytesToB64(bytes) },
      }).catch((e) => {
        // Connection lost mid-write — reflect it in the status bar.
        setStatus("error");
        setErrorMessage(String(e));
      });
    });
    const onResizeDispose = term.onResize(({ cols, rows }) => {
      void invoke("session_resize", {
        request: { token, cols, rows },
      }).catch((e) => {
        // Resize racing with a closed session is harmless; only
        // log to the in-window status if the session is still
        // marked open.
        // eslint-disable-next-line no-console
        console.warn("session_resize failed:", e);
      });
    });

    // Subscribe to stdout events from the host.
    const unlistenStdout = listen<StdoutPayload>(stdoutEvent, (ev) => {
      const bytes = b64ToBytes(ev.payload.bytes_b64);
      // xterm wants either string or Uint8Array; pass the bytes
      // directly so escape sequences come through intact.
      term.write(bytes);
    });

    const unlistenClosed = listen(closedEvent, () => {
      setStatus("closed");
      term.write("\r\n\x1b[33m[connection closed by remote host]\x1b[0m\r\n");
    });

    // Initial fit sets the right cols/rows on the host side.
    void invoke("session_resize", {
      request: { token, cols: term.cols, rows: term.rows },
    }).catch(() => undefined);

    // Auto-fit on window resize.
    const onWindowResize = () => {
      try {
        fit.fit();
      } catch {
        // Fit can throw if the terminal isn't visible yet.
      }
    };
    window.addEventListener("resize", onWindowResize);

    return () => {
      window.removeEventListener("resize", onWindowResize);
      onDataDispose.dispose();
      onResizeDispose.dispose();
      void unlistenStdout.then((u) => u());
      void unlistenClosed.then((u) => u());
      // Best-effort host-side teardown. The window-close hook on
      // the Rust side also triggers this, so a double-close is
      // expected; it's idempotent.
      void invoke("session_close", { request: { token } }).catch(() => undefined);
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [token, stdoutEvent, closedEvent]);

  async function handleDisconnect() {
    try {
      await invoke("session_close", { request: { token } });
    } catch {
      // Ignore — we'll mark closed regardless.
    }
    setStatus("closed");
    termRef.current?.write(
      "\r\n\x1b[33m[disconnected]\x1b[0m\r\n",
    );
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
            background: status === "open" ? "#1a4533" : status === "closed" ? "#3a3a3a" : status === "error" ? "#5e1f1f" : "#2a2f5e",
            color: "#e6e6e6",
          }}
        >
          {status}
        </span>
        {errorMessage && (
          <span style={{ fontSize: 11, color: "#ff6e6e" }}>
            {errorMessage}
          </span>
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
      <div
        ref={containerRef}
        style={{ flex: 1, padding: 4, overflow: "hidden" }}
      />
    </div>
  );
}
