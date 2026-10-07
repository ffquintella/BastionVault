/**
 * Resource Connect — SSH session pane (T38 Phases 1, 3 and 4).
 *
 * The xterm.js terminal and its chrome for one live SSH session, driven
 * entirely by props so the one-pane `/session/ssh` window and the Session
 * Workspace host the same component:
 *   token        — opaque session id used by every Tauri command call
 *   stdoutEvent  — event name the host emits remote PTY bytes on
 *   closedEvent  — event name the host emits when the remote PTY hangs up
 *   label        — operator-visible title (e.g. `ssh felipe@host:22`)
 *
 * The credential bytes never travel through this React layer; they were
 * resolved on the Rust side before the session existed. We just pump
 * bytes between the local xterm.js terminal and the host's session
 * control channel.
 *
 * What a pane in a layout needs, and a window never did:
 * - it fits to its own box (`ResizeObserver`), not to the window, so a
 *   divider drag or a re-shown tab re-fits it — and xterm only reports a
 *   resize, and so the host only gets `session_resize`, when cols/rows
 *   actually changed;
 * - keystrokes matching a workspace chord (`lib/reservedChords`) are not
 *   forwarded, in this window or any other;
 * - a paste containing a line break is held for confirmation
 *   (`lib/pasteGuard`), naming this pane's target;
 * - a divider drag re-fits the terminal on every frame but tells the host
 *   only once the grid settles ({@link SSH_RESIZE_DEBOUNCE_MS}), so the
 *   remote program is not sent a burst of SIGWINCHes. The handshake resize
 *   is never delayed;
 * - output delivered at a handshake can carry a host notice (output that
 *   was dropped, or not kept across a move between windows — Phase 6),
 *   written dimmed before the bytes.
 */

import { useEffect, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { extractError } from "../../lib/error";
import { needsPasteConfirmation, summarisePaste } from "../../lib/pasteGuard";
import { matchChord } from "../../lib/reservedChords";
import { useSessionInputPrefs } from "../../lib/sessionInputPrefs";
import { SessionPaneHeader, type SessionPaneStatus } from "./SessionPaneHeader";

interface StdoutPayload {
  bytes_b64: string;
  /** Host-composed, never remote data; only on a handshake replay. */
  notice?: string;
}

/** How long the grid must hold still before the host hears a resize. */
export const SSH_RESIZE_DEBOUNCE_MS = 120;

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

export type PaneActivity = "output" | "bell";

export interface SshPaneProps {
  token: string;
  stdoutEvent: string;
  closedEvent: string;
  label: string;
  /** CSS height of the pane's root. The one-pane window passes `100vh`;
   *  a pane inside a layout fills its slot. */
  height?: string;
  /** Take keyboard focus when this becomes true (and on mount if it is).
   *  A one-pane window leaves it on. */
  focused?: boolean;
  onStatusChange?: (status: SessionPaneStatus) => void;
  /** Output or a bell — the workspace's unread dot for background tabs. */
  onActivity?: (kind: PaneActivity) => void;
  /** Workspace pane actions, rendered in the header. */
  headerExtra?: ReactNode;
}

export function SshPane({
  token,
  stdoutEvent,
  closedEvent,
  label,
  height = "100%",
  focused = true,
  onStatusChange,
  onActivity,
  headerExtra,
}: SshPaneProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [status, setStatus] = useState<SessionPaneStatus>("connecting");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [pendingPaste, setPendingPaste] = useState<string | null>(null);
  const inputPrefs = useSessionInputPrefs();
  const pasteGuardRef = useRef(inputPrefs.confirmMultilinePaste);
  pasteGuardRef.current = inputPrefs.confirmMultilinePaste;
  const onActivityRef = useRef(onActivity);
  onActivityRef.current = onActivity;
  const onStatusRef = useRef(onStatusChange);
  onStatusRef.current = onStatusChange;

  useEffect(() => {
    onStatusRef.current?.(status);
  }, [status]);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMessage("session token missing from URL");
      return;
    }
    const container = containerRef.current;
    if (!container) return;

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
    term.open(container);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;
    setStatus("open");

    // A workspace chord is the workspace's, never the remote host's: xterm
    // processes (and forwards) only keys that match no reserved chord.
    term.attachCustomKeyEventHandler((e) => matchChord(e) === null);

    // Forward keystrokes → host. xterm gives us already-utf8 strings;
    // encode → bytes → base64 so we don't need a binary IPC channel.
    const onDataDispose = term.onData((data) => {
      const bytes = new TextEncoder().encode(data);
      void invoke("session_input", {
        request: { token, bytes_b64: bytesToB64(bytes) },
      }).catch((e) => {
        // Connection lost mid-write — reflect it in the status bar.
        // Tauri serialises CommandError as `{ message: ... }`, so a
        // raw `String(e)` would render "[object Object]"; the
        // shared `extractError` helper unwraps the message field.
        setStatus("error");
        setErrorMessage(extractError(e));
      });
    });

    // Resizes reach the host only after the handshake below: the first
    // `session_resize` is what drains the host's early-bytes buffer, so
    // one sent before both listeners are live would flush the prompt and
    // MOTD into a void. A pane in a layout can be re-fitted before then
    // (its slot attaches, a divider moves); the handshake sends the size
    // as of that moment instead.
    let handshakeSent = false;
    let sent = { cols: term.cols, rows: term.rows };
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    const onResizeDispose = term.onResize(() => {
      if (!handshakeSent) return;
      if (resizeTimer !== undefined) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        resizeTimer = undefined;
        const { cols, rows } = term;
        if (cols === sent.cols && rows === sent.rows) return;
        sent = { cols, rows };
        void invoke("session_resize", {
          request: { token, cols, rows },
        }).catch((e) => {
          // Resize racing with a closed (or moved) session is harmless.
          // eslint-disable-next-line no-console
          console.warn("session_resize failed:", e);
        });
      }, SSH_RESIZE_DEBOUNCE_MS);
    });
    const onBellDispose = term.onBell(() => onActivityRef.current?.("bell"));

    // Subscribe to stdout events from the host.
    const unlistenStdout = listen<StdoutPayload>(stdoutEvent, (ev) => {
      if (ev.payload.notice) term.write(`\x1b[2m[${ev.payload.notice}]\x1b[0m\r\n`);
      const bytes = b64ToBytes(ev.payload.bytes_b64);
      // xterm wants either string or Uint8Array; pass the bytes
      // directly so escape sequences come through intact.
      term.write(bytes);
      onActivityRef.current?.("output");
    });

    let closedHandled = false;
    const unlistenClosed = listen<{ reason?: string }>(closedEvent, (ev) => {
      // The host re-emits the closed event a few times on a short
      // delay so we still catch it if the worker died before this
      // listener was registered. De-duplicate so the terminal
      // doesn't get the "[connection closed]" banner printed three
      // times in a row.
      if (closedHandled) return;
      closedHandled = true;
      const reason = ev.payload?.reason ?? "connection closed by remote host";
      setStatus("closed");
      setErrorMessage(reason);
      term.write(`\r\n\x1b[33m[${reason}]\x1b[0m\r\n`);
    });

    // Initial resize doubles as the "frontend listener is live"
    // handshake the host's pump task waits on before draining the
    // early-bytes buffer (the prompt + MOTD that arrived between
    // `request_shell` and the React effect mounting). It's
    // critical that the listen() subscription is fully registered
    // BEFORE we invoke session_resize — otherwise the host
    // flushes its buffer into a void and the operator sees an
    // empty terminal until the first keystroke wakes the shell.
    // listen() returns a Promise that resolves once Tauri has
    // installed the subscription; await both before resizing.
    let disposed = false;
    void Promise.all([unlistenStdout, unlistenClosed]).then(() => {
      if (disposed) return;
      handshakeSent = true;
      sent = { cols: term.cols, rows: term.rows };
      void invoke("session_resize", {
        request: { token, cols: term.cols, rows: term.rows },
      }).catch(() => undefined);
    });

    // Fit to the pane's own box. A hidden tab or a detached (zoomed-out)
    // pane reports 0×0 and is skipped. The fit itself runs on the next
    // frame: a terminal that opened while hidden only re-measures its
    // character cell when it becomes visible again, which xterm learns
    // from an IntersectionObserver delivered after this callback.
    let frame: number | undefined;
    const observer = new ResizeObserver((entries) => {
      const box = entries[0]?.contentRect;
      if (!box || box.width === 0 || box.height === 0) return;
      if (frame !== undefined) cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        frame = undefined;
        try {
          fit.fit();
        } catch {
          // Fit can throw if the terminal isn't laid out yet.
        }
      });
    });
    observer.observe(container);

    // Multi-line paste guard. Capture phase on the pane, so it runs before
    // xterm's own paste handler on its helper textarea and can hold the
    // paste back entirely.
    const onPaste = (e: ClipboardEvent) => {
      if (!pasteGuardRef.current) return;
      const text = e.clipboardData?.getData("text/plain") ?? "";
      if (!needsPasteConfirmation(text)) return;
      e.preventDefault();
      e.stopPropagation();
      setPendingPaste(text);
    };
    container.addEventListener("paste", onPaste, true);

    return () => {
      disposed = true;
      if (resizeTimer !== undefined) clearTimeout(resizeTimer);
      observer.disconnect();
      if (frame !== undefined) cancelAnimationFrame(frame);
      container.removeEventListener("paste", onPaste, true);
      onDataDispose.dispose();
      onResizeDispose.dispose();
      onBellDispose.dispose();
      void unlistenStdout.then((u) => u());
      void unlistenClosed.then((u) => u());
      // Host-side teardown is owned by the host: closing the window
      // stops every session attached to it, and a workspace pane's
      // close button calls session_close (see commands/connect.rs +
      // session/attachments.rs). We deliberately do NOT call
      // session_close here — React StrictMode runs effect cleanup on
      // every dev re-mount, which would otherwise drop the host's
      // session entry while the window is still open and leave the
      // second mount with an unknown token. The Disconnect button calls
      // session_close explicitly, which covers the user-driven close path.
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [token, stdoutEvent, closedEvent]);

  useEffect(() => {
    if (focused) termRef.current?.focus();
  }, [focused, token]);

  async function handleDisconnect() {
    try {
      await invoke("session_close", { request: { token } });
    } catch (e) {
      // The host refused (another window holds the session) or it is
      // already gone; say which instead of pretending it closed.
      setErrorMessage(extractError(e));
      return;
    }
    setStatus("closed");
    termRef.current?.write("\r\n\x1b[33m[disconnected]\x1b[0m\r\n");
  }

  function resolvePaste(confirmed: boolean) {
    const text = pendingPaste;
    setPendingPaste(null);
    if (confirmed && text !== null) termRef.current?.paste(text);
    termRef.current?.focus();
  }

  const paste = pendingPaste !== null ? summarisePaste(pendingPaste) : null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height,
        minHeight: 0,
        position: "relative",
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
        extra={headerExtra}
      />
      <div
        ref={containerRef}
        style={{ flex: 1, minHeight: 0, padding: 4, overflow: "hidden" }}
      />
      {paste && (
        <div
          role="alertdialog"
          aria-label="Confirm multi-line paste"
          onKeyDown={(e) => {
            if (e.key === "Escape") resolvePaste(false);
          }}
          style={{
            position: "absolute",
            inset: 0,
            background: "rgba(5, 5, 10, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 16,
          }}
        >
          <div
            style={{
              background: "#11121a",
              border: "1px solid #3a3f6e",
              borderRadius: 6,
              padding: 16,
              maxWidth: "min(640px, 100%)",
              minWidth: 0,
              fontSize: 12,
            }}
          >
            <p style={{ margin: "0 0 8px", fontSize: 13 }}>
              Paste {paste.lines} {paste.lines === 1 ? "line" : "lines"} ({paste.chars} characters) into{" "}
              <strong>{label}</strong>? Each line break runs what precedes it.
            </p>
            <pre
              style={{
                margin: "0 0 12px",
                padding: 8,
                background: "#0b0b10",
                border: "1px solid #1f2030",
                overflow: "hidden",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                maxHeight: 140,
              }}
            >
              {paste.preview.join("\n")}
              {paste.more > 0 ? `\n… ${paste.more} more` : ""}
            </pre>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                type="button"
                autoFocus
                onClick={() => resolvePaste(false)}
                style={{ padding: "4px 10px", borderRadius: 4, border: "1px solid #3a3a3a", background: "#1f2030", color: "#e6e6e6" }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => resolvePaste(true)}
                style={{ padding: "4px 10px", borderRadius: 4, border: "1px solid #7a2a2a", background: "#5e1f1f", color: "#e6e6e6" }}
              >
                Paste
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
