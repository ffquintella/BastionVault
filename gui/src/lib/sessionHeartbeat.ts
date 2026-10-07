/**
 * Window liveness for the host's orphan watchdog (T38 Phase 2,
 * features/session-workspace.md §3).
 *
 * A window that renders live sessions calls `session_heartbeat` once on
 * mount and then every {@link SESSION_HEARTBEAT_INTERVAL_MS}. One call per
 * window, never one per pane. The host identifies the window from the
 * call itself — the request names nothing — so a window can only vouch for
 * the sessions it holds.
 *
 * The host judges a stale heartbeat only on a window that is shown and
 * has heartbeated at least once, and not at all on macOS (where it hooks
 * the web content process's death instead), so a throttled background
 * window is never mistaken for a dead one.
 */

import { useEffect } from "react";
import { sessionHeartbeat } from "./api";

export const SESSION_HEARTBEAT_INTERVAL_MS = 15_000;

export function useSessionHeartbeat(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    const beat = () => {
      void sessionHeartbeat().catch((e: unknown) => {
        // Not fatal: an attachment that never heartbeats is never judged
        // stale. Worth a console line for whoever is debugging it.
        // eslint-disable-next-line no-console
        console.warn("session_heartbeat failed:", e);
      });
    };
    beat();
    const id = window.setInterval(beat, SESSION_HEARTBEAT_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [enabled]);
}
