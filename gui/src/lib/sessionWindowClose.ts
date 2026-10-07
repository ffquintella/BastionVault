/**
 * Confirm before a window that renders live sessions closes natively — its
 * close button, Alt+F4, ⌘W in a session's own window (T108,
 * features/session-workspace.md §8).
 *
 * The window listens for Tauri's close request. While such a listener is
 * registered, Tauri vetoes the native close and hands the request to this
 * page; the host stops a window's sessions only once the window is
 * destroyed. So the page decides:
 *
 *   - nothing live → close at once (`session_window_close`);
 *   - a live session → show the confirmation, and once it is on screen tell
 *     the host the request was received (`session_window_closing`).
 *     Disconnect closes the window; Cancel keeps it and every session.
 *
 * The host forces the close — stopping the sessions — when a request goes
 * unanswered for a few seconds, so a hung or dead renderer can never trap
 * the window or keep its sessions alive. That is why the answer goes out
 * only after the confirmation has rendered: a page that cannot show it
 * does not answer, and the window still closes.
 *
 * Neither command names a window — each acts on the window that calls it.
 * Tauri's own `onCloseRequested` is not used: when the handler does not
 * veto, it calls `destroy()`, which needs `core:window:allow-destroy` — a
 * permission that would let this page destroy any window by label.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import type { SessionPaneStatus } from "../components/session/SessionPaneHeader";
import { sessionWindowClose, sessionWindowClosing } from "./api";
import { extractError } from "./error";

/** Tauri's `TauriEvent.WINDOW_CLOSE_REQUESTED`. */
export const WINDOW_CLOSE_REQUESTED_EVENT = "tauri://close-requested";

/** A session that is, or may still be, live: closing its window ends it.
 *  A pane that has not reported a status yet counts as connecting. */
export function isLiveStatus(status: SessionPaneStatus | undefined): boolean {
  return status === undefined || status === "open" || status === "connecting";
}

export interface WindowCloseGuard {
  /** The confirmation is open. */
  asking: boolean;
  /** Why the window did not close, if it did not. */
  error: string;
  dismissError: () => void;
  /** Disconnect and close. */
  confirm: () => void;
  /** Keep the window and its sessions. */
  cancel: () => void;
  /** Close now without asking — for a window with nothing live. */
  closeNow: () => Promise<void>;
}

function warn(what: string, e: unknown) {
  // eslint-disable-next-line no-console
  console.warn(`${what}:`, e);
}

/**
 * Take over this window's native close. `liveLabels` names the sessions a
 * close would end, read when the request arrives; `enabled` is false for a
 * window with no session at all, which then closes as any window does.
 */
export function useWindowCloseGuard(liveLabels: () => string[], enabled = true): WindowCloseGuard {
  const liveRef = useRef(liveLabels);
  liveRef.current = liveLabels;
  // 0 = not asking. Bumped per request, so a second close request while the
  // confirmation is open is answered too — an unanswered one would be forced.
  const [asking, setAsking] = useState(0);
  const [error, setError] = useState("");

  const closeNow = useCallback(async () => {
    try {
      await sessionWindowClose();
    } catch (e) {
      setError(`The window was not closed: ${extractError(e)}`);
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    let unlisten: (() => void) | null = null;
    const onCloseRequested = () => {
      if (!alive) return;
      setError("");
      if (liveRef.current().length === 0) {
        void closeNow();
        return;
      }
      setAsking((n) => n + 1);
    };
    try {
      getCurrentWindow()
        .listen(WINDOW_CLOSE_REQUESTED_EVENT, onCloseRequested)
        .then(
          (u) => {
            if (alive) unlisten = u;
            else u();
          },
          (e: unknown) => warn("could not take over the window's close", e),
        );
    } catch (e) {
      // No listener: the window closes without asking, and its sessions
      // stop when it is destroyed — the behaviour before T108.
      warn("could not take over the window's close", e);
    }
    return () => {
      alive = false;
      unlisten?.();
    };
  }, [enabled, closeNow]);

  // The confirmation is on screen: answer the host, which otherwise forces
  // the close (see the module comment).
  useEffect(() => {
    if (asking === 0) return;
    sessionWindowClosing().catch((e: unknown) => warn("session_window_closing failed", e));
  }, [asking]);

  const confirm = useCallback(() => {
    setAsking(0);
    void closeNow();
  }, [closeNow]);
  const cancel = useCallback(() => setAsking(0), []);
  const dismissError = useCallback(() => setError(""), []);

  return { asking: asking > 0, error, dismissError, confirm, cancel, closeNow };
}
