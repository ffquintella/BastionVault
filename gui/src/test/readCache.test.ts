/**
 * The client read cache. Its job is to stop tab switches and remounts from
 * re-walking an inventory that was walked seconds ago — the third leg of
 * keeping the official client under the server's per-IP abuse ceiling.
 *
 * The properties pinned here are the ones whose failure is a correctness
 * problem rather than a performance one: invalidation must beat the reload
 * that follows a write, a baseline epoch snapshot must not be mistaken for
 * news, and a failed load must not be cached.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  cachedRead,
  invalidateTopic,
  invalidateEntry,
  applyEpochs,
  clearCache,
  cacheSizeForTests,
} from "../lib/cache";

describe("client read cache", () => {
  beforeEach(() => {
    clearCache();
  });

  it("serves a repeat read without calling the loader", async () => {
    const load = vi.fn().mockResolvedValue(["a", "b"]);
    expect(await cachedRead("pki|pki/", "certs-info", load)).toEqual(["a", "b"]);
    expect(await cachedRead("pki|pki/", "certs-info", load)).toEqual(["a", "b"]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("coalesces concurrent reads of the same key into one load", async () => {
    // Two components mounting at once must not each issue the request.
    let resolve!: (v: string[]) => void;
    const load = vi.fn().mockReturnValue(
      new Promise<string[]>((r) => {
        resolve = r;
      }),
    );
    const a = cachedRead("pki|pki/", "certs-info", load);
    const b = cachedRead("pki|pki/", "certs-info", load);
    resolve(["x"]);
    expect(await a).toEqual(["x"]);
    expect(await b).toEqual(["x"]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("expires an entry once its TTL passes", async () => {
    const load = vi.fn().mockResolvedValue("v1");
    await cachedRead("t", "k", load, 1_000);
    vi.setSystemTime(Date.now() + 1_500);
    load.mockResolvedValue("v2");
    expect(await cachedRead("t", "k", load, 1_000)).toBe("v2");
    expect(load).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it("drops a whole topic but leaves its neighbours alone", async () => {
    const load = vi.fn().mockResolvedValue("v");
    await cachedRead("pki|a/", "certs-info", load);
    await cachedRead("pki|a/", "issuers", load);
    await cachedRead("pki|b/", "certs-info", load);
    expect(cacheSizeForTests()).toBe(3);

    invalidateTopic("pki|a/");
    expect(cacheSizeForTests()).toBe(1);
    // The surviving entry is `b`'s: a write to one mount must not throw away
    // another mount's loaded inventory.
    await cachedRead("pki|b/", "certs-info", load);
    expect(load).toHaveBeenCalledTimes(3);
  });

  it("does not let an in-flight load outlive the invalidation that follows it", async () => {
    // The write-then-reload ordering: a load started before a write must not
    // be adopted by a caller arriving after it, or the reload shows the
    // pre-write answer.
    let resolveStale!: (v: string) => void;
    const stale = vi.fn().mockReturnValue(
      new Promise<string>((r) => {
        resolveStale = r;
      }),
    );
    const first = cachedRead("t", "k", stale);

    invalidateTopic("t");

    const fresh = vi.fn().mockResolvedValue("after-write");
    const second = cachedRead("t", "k", fresh);

    resolveStale("before-write");
    await first;
    expect(await second).toBe("after-write");
    expect(fresh).toHaveBeenCalledTimes(1);
  });

  it("drops a single entry with invalidateEntry", async () => {
    const load = vi.fn().mockResolvedValue("v");
    await cachedRead("t", "one", load);
    await cachedRead("t", "two", load);
    invalidateEntry("t", "one");
    expect(cacheSizeForTests()).toBe(1);
  });

  it("does not cache a failed load", async () => {
    const load = vi.fn().mockRejectedValue(new Error("boom"));
    await expect(cachedRead("t", "k", load)).rejects.toThrow("boom");
    expect(cacheSizeForTests()).toBe(0);
    // And a retry actually retries.
    await expect(cachedRead("t", "k", load)).rejects.toThrow("boom");
    expect(load).toHaveBeenCalledTimes(2);
  });

  describe("epoch snapshots", () => {
    it("treats the first snapshot as a baseline, not as news", async () => {
      // Otherwise every reconnect would throw away the whole cache.
      const load = vi.fn().mockResolvedValue("v");
      await cachedRead("pki|pki/", "certs-info", load);
      expect(applyEpochs({ "pki|pki/": 7 })).toEqual([]);
      expect(cacheSizeForTests()).toBe(1);
    });

    it("invalidates a topic whose epoch moved", async () => {
      const load = vi.fn().mockResolvedValue("v");
      await cachedRead("pki|pki/", "certs-info", load);
      applyEpochs({ "pki|pki/": 7 });
      expect(applyEpochs({ "pki|pki/": 8 })).toEqual(["pki|pki/"]);
      expect(cacheSizeForTests()).toBe(0);
    });

    it("ignores a repeated or lower epoch", async () => {
      const load = vi.fn().mockResolvedValue("v");
      applyEpochs({ t: 7 });
      await cachedRead("t", "k", load);
      expect(applyEpochs({ t: 7 })).toEqual([]);
      // A lower number can only mean the node restarted its counters; that
      // is not evidence of a write, and acting on it would be a cache-clear
      // storm on every failover.
      expect(applyEpochs({ t: 3 })).toEqual([]);
      expect(cacheSizeForTests()).toBe(1);
    });
  });
});
