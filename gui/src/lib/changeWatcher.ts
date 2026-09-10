/**
 * Cross-client cache invalidation.
 *
 * The read cache in `lib/cache.ts` handles a client's own writes: it drops the
 * topic before reloading. It cannot know that *another* operator — or the same
 * operator's CLI — changed something, so without a signal it serves a stale
 * listing until the TTL expires. This module is the signal.
 *
 * The server bumps a per-mount epoch on every successful mutating request
 * (`Core::record_change_epoch`) and reports the epochs for mounts a client
 * names (`sys/cache/version`). A single shared poller asks about whatever
 * topics are currently subscribed, hands the answer to
 * {@link applyEpochs}, and notifies the subscribers whose topic moved.
 *
 * Design notes:
 *
 * * **One poller, not one per page.** Subscriptions are refcounted, so five
 *   mounted components watching the same mount cost one request per interval —
 *   the opposite of the per-object fan-out this whole feature exists to remove.
 * * **A poll, not a held request.** The server also supports `?watch=1`, which
 *   blocks until something changes. A desktop client with a handful of
 *   operators is better served by one small request every few seconds than by
 *   a connection held open per client; the long-poll stays available for
 *   clients that prefer it.
 * * **`coarse` means "drop everything".** When the server has more live topics
 *   than it will itemize it says so, and the only safe response is to clear
 *   the whole cache rather than trust a partial topic map.
 *
 * The honest limitation, inherited from the server: epochs are per-node
 * in-memory state and `bv-client` pins a session to one node, so two operators
 * on different nodes of an HA cluster will not invalidate each other. The
 * cache TTL remains the backstop for that case.
 */

import * as api from "./api";
import { applyEpochs, clearCache, invalidateTopic } from "./cache";

/** How often the poller asks the server for epochs. */
export const POLL_INTERVAL_MS = 10_000;

interface Subscription {
  /** Mount path, e.g. `pki/` — what the server keys its epochs by. */
  mount: string;
  /** Cache topic to invalidate, and the caller's refresh callback. */
  topic: string;
  onChanged: () => void;
}

/** Live subscriptions, keyed by an opaque handle. */
const subscriptions = new Map<number, Subscription>();
let nextHandle = 1;
let timer: ReturnType<typeof setInterval> | null = null;
/** True while a poll is in flight, so a slow answer cannot stack up polls. */
let polling = false;

function ensurePoller(): void {
  if (timer !== null || subscriptions.size === 0) return;
  timer = setInterval(() => void poll(), POLL_INTERVAL_MS);
}

function stopPollerIfIdle(): void {
  if (subscriptions.size > 0 || timer === null) return;
  clearInterval(timer);
  timer = null;
}

/**
 * One poll: ask about every subscribed mount, apply the answer, notify.
 *
 * Failures are swallowed. This is a background freshness mechanism — a server
 * that predates the endpoint, a token without the capability, or a transient
 * network error must not raise a toast, and the TTL still bounds staleness.
 */
async function poll(): Promise<void> {
  if (polling || subscriptions.size === 0) return;
  polling = true;
  try {
    const mounts = [...new Set([...subscriptions.values()].map((s) => s.mount))];
    const snapshot = await api.cacheVersion(mounts);

    if (snapshot.coarse) {
      // The server stopped itemizing; a partial topic map cannot be trusted.
      clearCache();
      for (const sub of subscriptions.values()) sub.onChanged();
      return;
    }

    // `applyEpochs` is keyed by cache topic, so translate the server's
    // mount-keyed answer first. A mount the caller may not read is absent
    // rather than zero, and is skipped: no epoch means no claim.
    const byTopic: Record<string, number> = {};
    for (const sub of subscriptions.values()) {
      const epoch = snapshot.topics[sub.mount];
      if (typeof epoch === "number") byTopic[sub.topic] = epoch;
    }
    const changed = new Set(applyEpochs(byTopic));
    if (changed.size === 0) return;
    for (const sub of subscriptions.values()) {
      if (changed.has(sub.topic)) sub.onChanged();
    }
  } catch {
    /* background freshness only — never surface a failure */
  } finally {
    polling = false;
  }
}

/**
 * Watch `mount` for changes made by anyone, invalidating `topic` and calling
 * `onChanged` when one lands.
 *
 * Returns an unsubscribe function; call it on unmount.
 */
export function watchTopic(
  mount: string,
  topic: string,
  onChanged: () => void,
): () => void {
  const handle = nextHandle++;
  subscriptions.set(handle, { mount, topic, onChanged });
  ensurePoller();
  return () => {
    subscriptions.delete(handle);
    stopPollerIfIdle();
  };
}

/**
 * Drop every subscription and stop polling. Called on logout and on switching
 * vaults — the epochs belonged to the previous session's server.
 */
export function stopChangeWatcher(): void {
  subscriptions.clear();
  stopPollerIfIdle();
}

/** Test hook: run one poll immediately rather than waiting for the interval. */
export async function pollNowForTests(): Promise<void> {
  await poll();
}

/** Test hook: current subscription count. */
export function subscriptionCountForTests(): number {
  return subscriptions.size;
}

/**
 * Invalidate a topic locally and tell its watchers, without waiting for the
 * next poll. Used right after this client's *own* write, so the operator sees
 * their change immediately.
 */
export function notifyLocalChange(topic: string): void {
  invalidateTopic(topic);
  for (const sub of subscriptions.values()) {
    if (sub.topic === topic) sub.onChanged();
  }
}
