/**
 * Rate-gated wrapper around Tauri's `invoke`.
 *
 * Every GUI request reaches the vault through `lib/api.ts`, and every
 * function there goes through this module. The gate exists because the
 * server runs an IP-based abuse guard (`DosGuard`, default 200 requests
 * per 10 s followed by a 300 s ban) that cannot tell the official client
 * apart from a flood: a page that fans out one read per listed object —
 * historically the PKI Certificates tab, but the shape recurs across the
 * app — trips it on a single load and locks the operator out for five
 * minutes.
 *
 * The fix has two halves. Bulk/paginated endpoints remove the fan-out at
 * the source; this gate is the backstop that bounds *any* caller, including
 * ones added later, so no page can reach the threshold by accident.
 *
 * Design notes:
 *
 * * **Token bucket, not a concurrency cap.** The guard counts requests per
 *   fixed window, so a rate limit maps directly onto what it measures.
 *   Tokens refill on wall-clock time and never depend on a request
 *   completing, so a long-lived command (an SSH session, a chunked
 *   recording fetch) cannot deadlock the queue the way an in-flight cap
 *   would.
 * * **Sized with headroom.** `RATE_PER_SEC * 10 + BURST` is the worst case
 *   any 10 s server window can see from one window of this client. It is
 *   set well under the server default so a second GUI window, a CLI, or a
 *   shared NAT egress IP still fits.
 * * **FIFO.** Queued callers are served in arrival order; a fan-out issued
 *   as `Promise.all` degrades into a steady stream rather than starving
 *   whatever the operator clicks next.
 * * **Backpressure on 429.** If the guard does fire (an older/looser build,
 *   another client on the same IP), the gate parks the queue briefly rather
 *   than letting every queued call fail in turn and raise its own toast.
 */

import { invoke as tauriInvoke } from "@tauri-apps/api/core";

/** Sustained requests per second allowed through the gate. */
const RATE_PER_SEC = 8;
/** Tokens available for an instantaneous burst (a fresh page load). */
const BURST = 16;
/**
 * How long to park the queue after a 429 when the server did not tell us
 * how long to wait. Deliberately short: the goal is to stop a queued
 * fan-out from turning one ban into fifty error toasts, not to sit out the
 * full ban — the operator gets an actionable error immediately either way.
 */
const DEFAULT_PAUSE_MS = 5_000;
/** Never park longer than this, however large the server's `Retry-After`. */
const MAX_PAUSE_MS = 30_000;

interface GateConfig {
  enabled: boolean;
  ratePerSec: number;
  burst: number;
}

const config: GateConfig = {
  // Vitest drives the api layer with a mocked `invoke` and no server; a
  // real bucket would just add latency (and, with fake timers, hang) to
  // every suite. `gateForTests` re-enables it for the gate's own tests.
  enabled: !import.meta.env?.VITEST,
  ratePerSec: RATE_PER_SEC,
  burst: BURST,
};

let tokens = config.burst;
let lastRefill = Date.now();
/** Wall-clock time before which nothing is dispatched (429 backpressure). */
let pausedUntil = 0;
/** FIFO of callers waiting for a token. */
const waiters: Array<() => void> = [];
let pumpTimer: ReturnType<typeof setTimeout> | null = null;

function refill(now: number): void {
  const elapsed = now - lastRefill;
  if (elapsed <= 0) return;
  lastRefill = now;
  tokens = Math.min(config.burst, tokens + (elapsed / 1000) * config.ratePerSec);
}

/**
 * Hand tokens to waiting callers, then schedule the next pump for the
 * moment the next token (or the end of a pause) becomes available.
 */
function pump(): void {
  if (pumpTimer !== null) {
    clearTimeout(pumpTimer);
    pumpTimer = null;
  }
  const now = Date.now();
  if (now < pausedUntil) {
    pumpTimer = setTimeout(pump, pausedUntil - now);
    return;
  }
  refill(now);
  while (waiters.length > 0 && tokens >= 1) {
    tokens -= 1;
    waiters.shift()!();
  }
  if (waiters.length > 0) {
    const waitMs = Math.max(1, Math.ceil(((1 - tokens) / config.ratePerSec) * 1000));
    pumpTimer = setTimeout(pump, waitMs);
  }
}

/** Block until this caller holds a token. */
function acquire(): Promise<void> {
  if (!config.enabled) return Promise.resolve();
  const now = Date.now();
  if (waiters.length === 0 && now >= pausedUntil) {
    refill(now);
    if (tokens >= 1) {
      tokens -= 1;
      return Promise.resolve();
    }
  }
  return new Promise<void>((resolve) => {
    waiters.push(resolve);
    pump();
  });
}

/**
 * Seconds the server asked us to wait, parsed out of the error message.
 *
 * `bv-client` folds the HTTP status and body into a single string and
 * appends the `Retry-After` header on a 429 as `(retry after Ns)`, because
 * the header itself does not survive the Tauri command boundary.
 */
function retryAfterSecs(message: string): number | null {
  const m = /retry after (\d+)s/i.exec(message);
  if (!m) return null;
  const secs = Number(m[1]);
  return Number.isFinite(secs) && secs > 0 ? secs : null;
}

function isRateLimited(message: string): boolean {
  return message.includes("429") || /too many requests/i.test(message);
}

/** Park the queue after a 429 so queued callers don't each earn their own. */
function applyBackpressure(e: unknown): void {
  const message =
    e instanceof Error
      ? e.message
      : typeof e === "object" && e !== null && "message" in e
        ? String((e as { message: unknown }).message)
        : String(e);
  if (!isRateLimited(message)) return;
  const secs = retryAfterSecs(message);
  const pauseMs = Math.min(MAX_PAUSE_MS, secs !== null ? secs * 1000 : DEFAULT_PAUSE_MS);
  pausedUntil = Math.max(pausedUntil, Date.now() + pauseMs);
  // Drop accumulated tokens too: resuming with a full bucket would let the
  // queue burst straight back into the guard.
  tokens = 0;
  lastRefill = Date.now();
}

/**
 * Drop-in replacement for Tauri's `invoke`, rate-gated. `lib/api.ts`
 * imports this instead of `@tauri-apps/api/core` so every command in the
 * app is covered without touching its ~400 call sites.
 */
export async function invoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  await acquire();
  try {
    return await tauriInvoke<T>(cmd, args);
  } catch (e) {
    applyBackpressure(e);
    throw e;
  }
}

/** Test hook: configure the gate and reset its state. Not used in the app. */
export function gateForTests(overrides: Partial<GateConfig>): void {
  Object.assign(config, overrides);
  tokens = config.burst;
  lastRefill = Date.now();
  pausedUntil = 0;
  waiters.length = 0;
  if (pumpTimer !== null) {
    clearTimeout(pumpTimer);
    pumpTimer = null;
  }
}

/** Test hook: current gate state, for assertions. */
export function gateStateForTests(): { queued: number; pausedUntil: number } {
  return { queued: waiters.length, pausedUntil };
}
