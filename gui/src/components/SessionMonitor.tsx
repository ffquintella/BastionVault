import { useEffect, useRef } from "react";
import * as api from "../lib/api";
import { useAuthStore } from "../stores/authStore";
import { useToast } from "./ui";

/** How often to probe the active token while authenticated. */
const POLL_INTERVAL_MS = 30_000;
/** Warn the operator once when the token has less than this left. */
const EXPIRY_WARNING_THRESHOLD_S = 120;

/**
 * Background session monitor. Mounted once at the app root (inside the
 * ToastProvider) and renders nothing.
 *
 * The Rust process owns the token across webview reloads, so the React
 * route guard alone never notices when the *token itself* expires or is
 * revoked server-side — the operator keeps clicking around and only
 * discovers it via confusing "permission denied" toasts on the next
 * data fetch. This monitor closes that gap by polling
 * `auth/token/lookup-self` (via the `token_status` command):
 *
 *  - on a fixed interval while authenticated, and
 *  - immediately whenever the window regains focus / visibility — the
 *    common case is the app sitting idle in the background long enough
 *    for the token to lapse, then the operator returns to a stale UI.
 *
 * On a definitive expiry it calls `expireSession`, which drops auth and
 * lets `ProtectedRoute` bounce to `/login` with a "session expired"
 * banner. A transient, unreachable backend (network blip, briefly
 * sealed vault) reports `reachable: false` and is deliberately ignored
 * so a momentary hiccup never logs the operator out.
 */
export function SessionMonitor() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const expireSession = useAuthStore((s) => s.expireSession);
  const { toast } = useToast();
  // Guards a single in-flight probe so a slow round-trip can't stack up
  // behind the interval or a focus event.
  const checking = useRef(false);
  // Fire the low-TTL warning at most once per session.
  const warned = useRef(false);

  useEffect(() => {
    if (!isAuthenticated) {
      warned.current = false;
      return;
    }

    let cancelled = false;

    const check = async () => {
      if (checking.current) return;
      checking.current = true;
      try {
        const status = await api.tokenStatus();
        if (cancelled) return;
        // Ignore transient failures: only act on a definitive answer
        // that the token no longer authenticates.
        if (status.reachable && !status.valid) {
          expireSession();
          toast("error", "Your session has expired. Please sign in again.");
          return;
        }
        if (
          status.valid &&
          status.ttl_seconds != null &&
          status.ttl_seconds > 0 &&
          status.ttl_seconds <= EXPIRY_WARNING_THRESHOLD_S &&
          !warned.current
        ) {
          warned.current = true;
          const mins = Math.max(1, Math.round(status.ttl_seconds / 60));
          toast(
            "info",
            `Your session expires in about ${mins} minute${mins === 1 ? "" : "s"}.`,
          );
        }
      } catch {
        // tokenStatus already collapses transient errors into
        // `reachable: false`; a throw here is unexpected — fail open
        // (keep the session) rather than risk a spurious logout.
      } finally {
        checking.current = false;
      }
    };

    const interval = setInterval(check, POLL_INTERVAL_MS);
    const onVisible = () => {
      if (document.visibilityState === "visible") void check();
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
    // Probe right away on mount/login so a token that lapsed while the
    // UI was unmounted is caught without waiting a full interval.
    void check();

    return () => {
      cancelled = true;
      clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onVisible);
    };
  }, [isAuthenticated, expireSession, toast]);

  return null;
}
