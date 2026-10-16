// Phase 5: session renew + kill lifecycle hook for Rustion-mediated
// connections. Drop-in for any Connection Window:
//
//   const { renewing, renew, killing, kill, lastError, lastRenewed } =
//     useRustionSessionLifecycle({
//       token,               // the local session token this window holds
//       session,             // RustionSessionOpenResult-shaped expiry source
//       isIdle,              // true when the operator's terminal hasn't
//                            // received input recently — skip auto-renew
//       autoRenewEnabled,    // user toggle
//     });
//
// The hook auto-renews at `expires_at - 60s` IF !isIdle. When the
// renewal succeeds, it updates the internal expiry tracker and
// schedules the next renewal off the new expires_at. Failures bubble
// up via `lastError`; the caller picks the UX (modal? toast? auto-
// reconnect?).
//
// Termination is one-shot — calling `kill` POSTs the kill envelope at
// the bastion and marks the session terminated locally so the timer
// stops firing.
//
// Renew and kill go by `token` only (T145): the host checks the calling
// window holds that session and takes the bastion, session and
// correlation ids from the bundle it stashed at open. `session` here
// drives only the local expiry mirror and the reset on a new session.

import { useCallback, useEffect, useRef, useState } from "react";

import { sessionRustionKill, sessionRustionRenew } from "../lib/api";
import {
  type RustionSessionKillResult,
  type RustionSessionOpenResult,
  type RustionSessionRenewResult,
} from "../lib/rustion";

export interface UseRustionSessionLifecycleArgs {
  /** The local session token the calling window holds. */
  token: string;
  session: RustionSessionOpenResult | null;
  /** Whether the operator's terminal has been idle for the renew-skip
   *  window. Caller's choice of threshold (e.g. 5 minutes). */
  isIdle: boolean;
  autoRenewEnabled: boolean;
  /** How many seconds before expiry the renewal fires.
   *  Default 60s, matching the spec. */
  renewLeadSecs?: number;
  /** How long an explicit renew extends the session. Default 1800. */
  extendSecs?: number;
}

export interface UseRustionSessionLifecycleResult {
  /** Local mirror of the session's expiry — updated after every
   *  successful renew so the connection-window header can show it. */
  expiresAt: string | null;
  renewalsUsed: number;
  maxRenewals: number;
  renewing: boolean;
  killing: boolean;
  terminated: boolean;
  lastError: string | null;
  /** Trigger a manual renew right now (e.g. "Renew" button). */
  renew: () => Promise<RustionSessionRenewResult | null>;
  /** Terminate the session right now. */
  kill: () => Promise<RustionSessionKillResult | null>;
}

export function useRustionSessionLifecycle(
  args: UseRustionSessionLifecycleArgs,
): UseRustionSessionLifecycleResult {
  const {
    token,
    session,
    isIdle,
    autoRenewEnabled,
    renewLeadSecs = 60,
    extendSecs = 1800,
  } = args;

  const [expiresAt, setExpiresAt] = useState<string | null>(
    session?.expires_at ?? null,
  );
  const [renewalsUsed, setRenewalsUsed] = useState(0);
  const [maxRenewals, setMaxRenewals] = useState(0);
  const [renewing, setRenewing] = useState(false);
  const [killing, setKilling] = useState(false);
  const [terminated, setTerminated] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);

  // Refs so the auto-renew callback always sees the latest values
  // without re-creating the timer on every render.
  const isIdleRef = useRef(isIdle);
  isIdleRef.current = isIdle;
  const autoRenewRef = useRef(autoRenewEnabled);
  autoRenewRef.current = autoRenewEnabled;

  // Reset state when the session changes (open new connection).
  useEffect(() => {
    setExpiresAt(session?.expires_at ?? null);
    setRenewalsUsed(0);
    setMaxRenewals(0);
    setTerminated(false);
    setLastError(null);
  }, [session?.session_id]);

  const renew = useCallback(async () => {
    if (!session || terminated) return null;
    setRenewing(true);
    setLastError(null);
    try {
      const res = await sessionRustionRenew(token, extendSecs);
      setExpiresAt(res.expiresAt);
      setRenewalsUsed(res.renewalsUsed);
      setMaxRenewals(res.maxRenewals);
      return res;
    } catch (e) {
      setLastError(`renew failed: ${e}`);
      return null;
    } finally {
      setRenewing(false);
    }
  }, [token, session, terminated, extendSecs]);

  const kill = useCallback(async () => {
    if (!session || terminated) return null;
    setKilling(true);
    setLastError(null);
    try {
      const res = await sessionRustionKill(token);
      setTerminated(true);
      return res;
    } catch (e) {
      setLastError(`kill failed: ${e}`);
      return null;
    } finally {
      setKilling(false);
    }
  }, [token, session, terminated]);

  // Auto-renew timer. Fires at (expires_at - renewLeadSecs). Skips
  // when idle, when auto-renew is off, or when the budget is gone.
  useEffect(() => {
    if (!session || terminated) return;
    if (!expiresAt) return;
    const expiryMs = Date.parse(expiresAt);
    if (Number.isNaN(expiryMs)) return;
    const fireAt = expiryMs - renewLeadSecs * 1000;
    const delay = Math.max(0, fireAt - Date.now());
    const t = window.setTimeout(() => {
      if (!autoRenewRef.current) return;
      if (isIdleRef.current) return;
      if (maxRenewals > 0 && renewalsUsed >= maxRenewals) return;
      void renew();
    }, delay);
    return () => window.clearTimeout(t);
  }, [
    session,
    expiresAt,
    renewLeadSecs,
    renew,
    terminated,
    maxRenewals,
    renewalsUsed,
  ]);

  return {
    expiresAt,
    renewalsUsed,
    maxRenewals,
    renewing,
    killing,
    terminated,
    lastError,
    renew,
    kill,
  };
}
