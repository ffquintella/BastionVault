/**
 * Client-side read cache for listing and metadata reads.
 *
 * Together with the request gate (`lib/invoke.ts`) and the engines' bulk
 * `<list>/info` endpoints, this is the third reason the official client no
 * longer generates enough traffic to trip the server's per-IP abuse guard:
 * switching tabs, closing a modal, or remounting a page no longer refetches
 * what was fetched a moment ago.
 *
 * Three properties are deliberate:
 *
 * * **Opt-in, not blanket.** Callers name what is cacheable. Caching every
 *   read indiscriminately would cache seal status, token lookups and
 *   capability checks — answers whose staleness is a correctness or security
 *   problem, not a latency one.
 * * **Metadata only.** Entries hold listing projections: names, counts,
 *   timestamps, expiries. Secret values are never cached client-side.
 * * **Topic-scoped invalidation.** Every entry belongs to a topic
 *   (`<namespace>|<mount>`). A write invalidates its topic, so a client sees
 *   its own writes immediately; a topic epoch moving on the server
 *   invalidates it too, which is how a client learns about *another* client's
 *   write.
 *
 * The TTL is not a performance knob — it is the correctness backstop. Epoch
 * notifications are per-node by construction, so in an HA cluster two clients
 * pinned to different nodes will not invalidate each other. Every entry must
 * therefore expire on its own.
 */

/** Default entry lifetime. Short enough that a missed notification is a blip. */
export const DEFAULT_TTL_MS = 30_000;

interface Entry {
  topic: string;
  value: unknown;
  expiresAt: number;
}

const entries = new Map<string, Entry>();
/**
 * In-flight loads, keyed the same way as `entries`. Two components mounting
 * at once and asking for the same list share one request instead of racing —
 * on its own a meaningful cut in the burst a page load produces.
 */
const inflight = new Map<string, Promise<unknown>>();
/** Last epoch seen per topic, so a repeated notification is a no-op. */
const epochs = new Map<string, number>();

/**
 * Cache key for a topic and a call. `key` should capture every argument that
 * changes the answer — a cursor, a filter, a page size — or two different
 * pages will collide.
 */
function cacheKey(topic: string, key: string): string {
  return `${topic} ${key}`;
}

/**
 * Read through the cache.
 *
 * On a hit within the TTL the cached value is returned without calling
 * `load`. On a miss, `load` runs once even if several callers arrive at the
 * same time. A rejected `load` is neither cached nor retained.
 */
export async function cachedRead<T>(
  topic: string,
  key: string,
  load: () => Promise<T>,
  ttlMs: number = DEFAULT_TTL_MS,
): Promise<T> {
  const k = cacheKey(topic, key);
  const hit = entries.get(k);
  if (hit && hit.expiresAt > Date.now()) {
    return hit.value as T;
  }
  const pending = inflight.get(k);
  if (pending) {
    return pending as Promise<T>;
  }
  const p = load()
    .then((value) => {
      entries.set(k, { topic, value, expiresAt: Date.now() + ttlMs });
      return value;
    })
    .finally(() => {
      inflight.delete(k);
    });
  inflight.set(k, p);
  return p;
}

/**
 * Drop every entry for a topic. Call this after a write, *before* the reload
 * that follows it, so the reload cannot be served the pre-write answer.
 *
 * In-flight loads are dropped from the coalescing map as well: one started
 * before the write would otherwise be adopted by a caller after it and hand
 * back stale data.
 */
export function invalidateTopic(topic: string): void {
  const prefix = `${topic} `;
  for (const k of entries.keys()) {
    if (k.startsWith(prefix)) entries.delete(k);
  }
  for (const k of inflight.keys()) {
    if (k.startsWith(prefix)) inflight.delete(k);
  }
}

/** Drop one entry. */
export function invalidateEntry(topic: string, key: string): void {
  const k = cacheKey(topic, key);
  entries.delete(k);
  inflight.delete(k);
}

/**
 * Apply a topic to epoch snapshot from the server's change channel.
 *
 * A topic whose epoch is higher than the last one seen has been written to —
 * by this client or another — so its entries are dropped. A topic seen for
 * the first time is recorded without invalidating: the first snapshot after
 * connecting is a baseline, not news, and treating it as news would throw
 * away the cache on every reconnect.
 *
 * Returns the topics that were actually invalidated, so a caller can trigger
 * a refresh of whatever is on screen.
 */
export function applyEpochs(snapshot: Record<string, number>): string[] {
  const changed: string[] = [];
  for (const [topic, epoch] of Object.entries(snapshot)) {
    const seen = epochs.get(topic);
    epochs.set(topic, epoch);
    if (seen !== undefined && epoch > seen) {
      invalidateTopic(topic);
      changed.push(topic);
    }
  }
  return changed;
}

/**
 * Drop everything. Used on logout, on a namespace switch, and on connecting
 * to a different vault — in each case the cached answers belong to a
 * different authorization context and must not be reused.
 */
export function clearCache(): void {
  entries.clear();
  inflight.clear();
  epochs.clear();
}

/** Test hook: entry count, for asserting hits and invalidation. */
export function cacheSizeForTests(): number {
  return entries.size;
}
