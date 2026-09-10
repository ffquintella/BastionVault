/**
 * The cross-client cache-invalidation watcher.
 *
 * The read cache already handles a client's own writes. This closes the other
 * half: another operator's change lands, the server's epoch for that mount
 * moves, and this client drops the affected listings instead of serving them
 * until the TTL expires. See `features/client-request-efficiency.md`.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import {
  watchTopic,
  stopChangeWatcher,
  pollNowForTests,
  subscriptionCountForTests,
  notifyLocalChange,
} from "../lib/changeWatcher";
import { cachedRead, cacheSizeForTests, clearCache } from "../lib/cache";

const mockInvoke = vi.mocked(tauriInvoke);

/** Answer `cache_version` with these mount epochs. */
function serverEpochs(
  topics: Record<string, number>,
  opts: { coarse?: boolean; version?: number } = {},
) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "cache_version") {
      return Promise.resolve({
        version: opts.version ?? 1,
        topics,
        coarse: opts.coarse ?? false,
      });
    }
    return Promise.resolve(null);
  });
}

describe("change watcher", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    clearCache();
    stopChangeWatcher();
  });

  afterEach(() => {
    stopChangeWatcher();
  });

  it("treats the first epoch it sees as a baseline, not as a change", async () => {
    // Otherwise the first poll after every page load would throw away the
    // cache it just filled.
    const onChanged = vi.fn();
    await cachedRead("pki|pki/", "certs-info", async () => ["row"]);
    watchTopic("pki/", "pki|pki/", onChanged);

    serverEpochs({ "pki/": 7 });
    await pollNowForTests();

    expect(onChanged).not.toHaveBeenCalled();
    expect(cacheSizeForTests()).toBe(1);
  });

  it("invalidates and notifies when the epoch moves", async () => {
    const onChanged = vi.fn();
    await cachedRead("pki|pki/", "certs-info", async () => ["row"]);
    watchTopic("pki/", "pki|pki/", onChanged);

    serverEpochs({ "pki/": 7 });
    await pollNowForTests();
    serverEpochs({ "pki/": 8 });
    await pollNowForTests();

    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(cacheSizeForTests()).toBe(0);
  });

  it("does not notify a subscriber whose own topic did not move", async () => {
    // Per-topic epochs exist so a PKI write does not make every page in the
    // app refetch.
    const pki = vi.fn();
    const ssh = vi.fn();
    watchTopic("pki/", "pki|pki/", pki);
    watchTopic("ssh/", "ssh|ssh/", ssh);

    serverEpochs({ "pki/": 1, "ssh/": 1 });
    await pollNowForTests();
    serverEpochs({ "pki/": 2, "ssh/": 1 });
    await pollNowForTests();

    expect(pki).toHaveBeenCalledTimes(1);
    expect(ssh).not.toHaveBeenCalled();
  });

  it("asks about each mount once however many components watch it", async () => {
    // Five components on one mount must cost one request per interval — the
    // opposite of the per-object fan-out this feature removes.
    watchTopic("pki/", "pki|pki/", vi.fn());
    watchTopic("pki/", "pki|pki/", vi.fn());
    watchTopic("pki/", "pki|pki/", vi.fn());
    serverEpochs({ "pki/": 1 });
    await pollNowForTests();

    const calls = mockInvoke.mock.calls.filter((c) => c[0] === "cache_version");
    expect(calls).toHaveLength(1);
    expect((calls[0][1] as { topics: string[] }).topics).toEqual(["pki/"]);
  });

  it("drops the whole cache when the server stops itemizing", async () => {
    // `coarse` means the topic map is incomplete; trusting a partial map
    // would leave some pages stale with no way to find out.
    const onChanged = vi.fn();
    await cachedRead("pki|pki/", "certs-info", async () => ["row"]);
    await cachedRead("ssh|ssh/", "roles-info", async () => ["row"]);
    watchTopic("pki/", "pki|pki/", onChanged);

    serverEpochs({}, { coarse: true });
    await pollNowForTests();

    expect(cacheSizeForTests()).toBe(0);
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it("ignores a mount the server declined to report", async () => {
    // A mount the caller may not read is absent rather than zero. Treating
    // absence as zero would invalidate on every poll.
    const onChanged = vi.fn();
    await cachedRead("secret|payroll/", "list", async () => ["row"]);
    watchTopic("payroll/", "secret|payroll/", onChanged);

    serverEpochs({});
    await pollNowForTests();
    await pollNowForTests();

    expect(onChanged).not.toHaveBeenCalled();
    expect(cacheSizeForTests()).toBe(1);
  });

  it("stays quiet when the endpoint is unavailable", async () => {
    // Background freshness only: an older server, a token without the
    // capability, or a transient failure must not raise anything.
    const onChanged = vi.fn();
    watchTopic("pki/", "pki|pki/", onChanged);
    mockInvoke.mockRejectedValue({ message: "HTTP 404: path not supported" });

    await expect(pollNowForTests()).resolves.toBeUndefined();
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("unsubscribes on teardown", async () => {
    const onChanged = vi.fn();
    const stop = watchTopic("pki/", "pki|pki/", onChanged);
    expect(subscriptionCountForTests()).toBe(1);
    stop();
    expect(subscriptionCountForTests()).toBe(0);

    serverEpochs({ "pki/": 9 });
    await pollNowForTests();
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("notifies immediately for this client's own write", async () => {
    const onChanged = vi.fn();
    await cachedRead("pki|pki/", "certs-info", async () => ["row"]);
    watchTopic("pki/", "pki|pki/", onChanged);

    notifyLocalChange("pki|pki/");

    expect(cacheSizeForTests()).toBe(0);
    expect(onChanged).toHaveBeenCalledTimes(1);
  });
});

describe("topic helpers", () => {
  it("maps a GUI auth mount onto the path the server keys epochs by", async () => {
    // The GUI carries userpass-style mounts as `userpass/` and builds paths
    // as `auth/<mount>...`; the server files the epoch under the full
    // `auth/userpass/`. Getting this wrong fails *silently* — the watcher
    // would ask about a mount that never moves and simply never invalidate.
    const { authMount } = await import("../lib/topics");
    expect(authMount("userpass/")).toBe("auth/userpass/");
    expect(authMount("userpass")).toBe("auth/userpass/");
    expect(authMount("/userpass/")).toBe("auth/userpass/");
    // Already-qualified input is left alone rather than doubled up.
    expect(authMount("auth/userpass/")).toBe("auth/userpass/");
  });

  it("keeps one mount's pages in separate cache topics", async () => {
    // Three PKI tabs cache three listings off one mount. A local certificate
    // write should drop the certificate list, not the pending-CSR queue —
    // even though both watch the same mount and both fall to a real epoch
    // bump on it.
    const { topicFor } = await import("../lib/topics");
    expect(topicFor("pki-certs", "pki/")).not.toBe(topicFor("pki-csr", "pki/"));
    expect(topicFor("pki-certs", "a/")).not.toBe(topicFor("pki-certs", "b/"));
  });

  it("invalidates every topic watching a mount when its epoch moves", async () => {
    // The other half of the same design: separate topics, one shared signal.
    const certs = vi.fn();
    const csr = vi.fn();
    watchTopic("pki/", "pki-certs|pki/", certs);
    watchTopic("pki/", "pki-csr|pki/", csr);

    serverEpochs({ "pki/": 1 });
    await pollNowForTests();
    serverEpochs({ "pki/": 2 });
    await pollNowForTests();

    expect(certs).toHaveBeenCalledTimes(1);
    expect(csr).toHaveBeenCalledTimes(1);
  });
});
