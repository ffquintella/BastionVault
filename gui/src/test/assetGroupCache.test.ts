// The shared asset-group cache (lib/assetGroupCache) and the hook built on it:
// one batch read instead of LIST + GET per group, served from cache within the
// TTL, revalidated with `since`, dropped on this client's own group writes and
// on a namespace or session change. See features/resource-groups.md.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import {
  ASSET_GROUP_FULL_REFRESH_MS,
  ASSET_GROUP_TTL_MS,
  assetGroupContextKey,
  loadAssetGroups,
  peekAssetGroups,
  resetAssetGroupCacheForTests,
  subscribeAssetGroups,
} from "../lib/assetGroupCache";
import * as api from "../lib/api";
import { clearCache } from "../lib/cache";
import { useAssetGroupMap } from "../hooks/useAssetGroupMap";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

const mockInvoke = vi.mocked(tauriInvoke);

interface BatchArgs {
  shape: string;
  since: string | null;
}

/** What the fake server holds; tests mutate it between calls. */
let server: { version: string; byResource: Record<string, string[]> };
let batchCalls: BatchArgs[];

function answer(shape: string, unchanged: boolean) {
  const byResource = unchanged ? {} : server.byResource;
  return {
    unchanged,
    version: server.version,
    shape,
    namespace: "",
    groups: [],
    names: unchanged ? [] : [...new Set(Object.values(byResource).flat())].sort(),
    by_resource: byResource,
    by_secret: {},
    by_file: {},
    warnings: [],
  };
}

function serve() {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    switch (cmd) {
      case "asset_groups_batch": {
        const { shape, since } = args as BatchArgs;
        batchCalls.push({ shape, since });
        return Promise.resolve(answer(shape, since !== null && since === server.version));
      }
      case "write_asset_group":
      case "delete_asset_group":
        return Promise.resolve(null);
      default:
        return Promise.reject(new Error(`unexpected command ${cmd}`));
    }
  });
}

const CTX = assetGroupContextKey("", "token-1");

describe("asset-group cache", () => {
  let now = 1_000_000;

  beforeEach(() => {
    resetAssetGroupCacheForTests();
    mockInvoke.mockReset();
    server = { version: "v1", byResource: { web1: ["alpha"] } };
    batchCalls = [];
    serve();
    now = 1_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves a hit within the TTL without asking the server", async () => {
    const first = await loadAssetGroups(CTX, "slim");
    expect(first.index.byResource).toEqual({ web1: ["alpha"] });
    now += ASSET_GROUP_TTL_MS - 1;
    const second = await loadAssetGroups(CTX, "slim");
    expect(second).toBe(first);
    expect(batchCalls).toEqual([{ shape: "slim", since: null }]);
  });

  it("shares one request between concurrent callers", async () => {
    await Promise.all([loadAssetGroups(CTX, "slim"), loadAssetGroups(CTX, "slim")]);
    expect(batchCalls).toHaveLength(1);
  });

  it("revalidates with `since` after the TTL and keeps the data when unchanged", async () => {
    await loadAssetGroups(CTX, "slim");
    now += ASSET_GROUP_TTL_MS;
    const again = await loadAssetGroups(CTX, "slim");
    expect(batchCalls[1]).toEqual({ shape: "slim", since: "v1" });
    expect(again.index.byResource).toEqual({ web1: ["alpha"] });
    expect(again.fetchedAt).toBe(now);
    // The confirmation restarts the TTL.
    now += 1;
    await loadAssetGroups(CTX, "slim");
    expect(batchCalls).toHaveLength(2);
  });

  it("takes the new data when the server's version moved", async () => {
    await loadAssetGroups(CTX, "slim");
    server = { version: "v2", byResource: { web1: ["alpha"], web2: ["beta"] } };
    const fresh = await loadAssetGroups(CTX, "slim", { maxAgeMs: 0 });
    expect(batchCalls[1]).toEqual({ shape: "slim", since: "v1" });
    expect(fresh.version).toBe("v2");
    expect(fresh.index.byResource).toEqual({ web1: ["alpha"], web2: ["beta"] });
  });

  it("does a full read, not `since`, once the full-refresh window passes", async () => {
    await loadAssetGroups(CTX, "slim");
    for (let i = 0; i < 3; i++) {
      now += ASSET_GROUP_TTL_MS;
      await loadAssetGroups(CTX, "slim");
    }
    now += ASSET_GROUP_FULL_REFRESH_MS;
    await loadAssetGroups(CTX, "slim");
    expect(batchCalls.map((c) => c.since)).toEqual([null, "v1", "v1", "v1", null]);
  });

  it("drops the cache and notifies subscribers after this client writes a group", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      await loadAssetGroups(CTX, "slim");
      const notified = vi.fn();
      subscribeAssetGroups(notified);
      await api.writeAssetGroup("beta", "", "web2", "");
      expect(peekAssetGroups(CTX, "slim")).toBeNull();
      vi.runAllTimers();
      expect(notified).toHaveBeenCalledTimes(1);
      // A burst of writes (an import) is one notification.
      await api.writeAssetGroup("gamma", "", "web3", "");
      await api.deleteAssetGroup("gamma");
      vi.runAllTimers();
      expect(notified).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
    // The reload after an invalidation is a full read: never `since`.
    await loadAssetGroups(CTX, "slim");
    expect(batchCalls.map((c) => c.since)).toEqual([null, null]);
  });

  it("invalidates even when the write fails", async () => {
    await loadAssetGroups(CTX, "slim");
    mockInvoke.mockImplementationOnce(() => Promise.reject(new Error("permission denied")));
    await expect(api.writeAssetGroup("beta", "", "web2", "")).rejects.toThrow();
    expect(peekAssetGroups(CTX, "slim")).toBeNull();
  });

  it("never serves one namespace's or session's entry to another", async () => {
    await loadAssetGroups(CTX, "slim");
    const tenant = assetGroupContextKey("tenant-a", "token-1");
    const otherUser = assetGroupContextKey("", "token-2");
    expect(peekAssetGroups(tenant, "slim")).toBeNull();
    expect(peekAssetGroups(otherUser, "slim")).toBeNull();
    await loadAssetGroups(tenant, "slim");
    expect(batchCalls).toHaveLength(2);
    expect(peekAssetGroups(CTX, "slim")).toBeNull();
  });

  it("is dropped with the read cache (logout, namespace switch)", async () => {
    await loadAssetGroups(CTX, "slim");
    clearCache();
    expect(peekAssetGroups(CTX, "slim")).toBeNull();
  });

  it("falls back to LIST + GET each against a server without the batch route", async () => {
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      switch (cmd) {
        case "asset_groups_batch":
          return Promise.reject(new Error("1 error occurred: * unsupported path: path not supported"));
        case "list_asset_groups":
          return Promise.resolve({ groups: ["alpha"] });
        case "read_asset_group":
          return Promise.resolve({
            name: (args as { name: string }).name,
            description: "",
            members: ["web1", "<hidden>"],
            secrets: ["secret/a"],
            owner_entity_id: "",
            created_at: "",
            updated_at: "",
          });
        default:
          return Promise.reject(new Error(`unexpected command ${cmd}`));
      }
    });
    const snap = await loadAssetGroups(CTX, "slim");
    expect(snap.version).toBeNull();
    expect(snap.index.byResource).toEqual({ web1: ["alpha"] });
    expect(snap.index.bySecret).toEqual({ "secret/a": ["alpha"] });
  });
});

describe("useAssetGroupMap", () => {
  beforeEach(() => {
    resetAssetGroupCacheForTests();
    mockInvoke.mockReset();
    server = { version: "v1", byResource: { web1: ["alpha"] } };
    batchCalls = [];
    serve();
    useAuthStore.setState({ token: "token-1" });
    useNamespaceStore.setState({ active: "" });
  });

  it("loads the maps with one slim batch read and reloads after a group write", async () => {
    const { result } = renderHook(() => useAssetGroupMap());
    await waitFor(() => expect(result.current.available).toBe(true));
    expect(result.current.map.byResource).toEqual({ web1: ["alpha"] });
    expect(batchCalls).toEqual([{ shape: "slim", since: null }]);

    server = { version: "v2", byResource: { web1: ["alpha"], web2: ["beta"] } };
    await act(async () => {
      await api.writeAssetGroup("beta", "", "web2", "");
    });
    await waitFor(() => expect(result.current.map.byResource).toHaveProperty("web2"));
    expect(batchCalls).toHaveLength(2);
  });

  it("a second page mounting within the TTL costs no request", async () => {
    const first = renderHook(() => useAssetGroupMap());
    await waitFor(() => expect(first.result.current.available).toBe(true));
    const second = renderHook(() => useAssetGroupMap());
    expect(second.result.current.map.byResource).toEqual({ web1: ["alpha"] });
    await waitFor(() => expect(second.result.current.available).toBe(true));
    expect(batchCalls).toHaveLength(1);
  });

  it("revalidates with `since` when the window regains focus", async () => {
    const { result } = renderHook(() => useAssetGroupMap());
    await waitFor(() => expect(result.current.available).toBe(true));
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    await waitFor(() => expect(batchCalls).toHaveLength(2));
    expect(batchCalls[1]).toEqual({ shape: "slim", since: "v1" });
  });

  it("switches to the new namespace's maps on a namespace switch", async () => {
    const { result } = renderHook(() => useAssetGroupMap());
    await waitFor(() => expect(result.current.available).toBe(true));
    server = { version: "t1", byResource: { db1: ["tenant-g"] } };
    act(() => {
      useNamespaceStore.setState({ active: "tenant-a" });
    });
    await waitFor(() => expect(result.current.map.byResource).toEqual({ db1: ["tenant-g"] }));
    expect(batchCalls.map((c) => c.since)).toEqual([null, null]);
  });

  it("reports unavailable when the batch read is refused", async () => {
    mockInvoke.mockImplementation(() => Promise.reject(new Error("permission denied")));
    const { result } = renderHook(() => useAssetGroupMap());
    await waitFor(() => expect(result.current.available).toBe(false));
    expect(result.current.map.byResource).toEqual({});
  });
});
