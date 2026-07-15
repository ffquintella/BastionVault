import { describe, it, expect, beforeEach, vi } from "vitest";
import { useAuthStore } from "../stores/authStore";
import { useVaultStore } from "../stores/vaultStore";
import * as api from "../lib/api";
import { useNamespaceStore } from "../stores/namespaceStore";

describe("authStore", () => {
  beforeEach(() => {
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false });
  });

  it("starts unauthenticated", () => {
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.token).toBeNull();
    expect(state.policies).toEqual([]);
  });

  it("setAuth sets token, policies, and isAuthenticated", () => {
    useAuthStore.getState().setAuth("my-token-123", ["admin", "default"]);
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.token).toBe("my-token-123");
    expect(state.policies).toEqual(["admin", "default"]);
  });

  it("clearAuth resets to unauthenticated", () => {
    useAuthStore.getState().setAuth("token", ["root"]);
    useAuthStore.getState().clearAuth();
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.token).toBeNull();
    expect(state.policies).toEqual([]);
  });
});

describe("vaultStore", () => {
  beforeEach(() => {
    useVaultStore.setState({ mode: "Embedded", status: null });
  });

  it("starts with Embedded mode and null status", () => {
    const state = useVaultStore.getState();
    expect(state.mode).toBe("Embedded");
    expect(state.status).toBeNull();
  });

  it("setMode changes mode", () => {
    useVaultStore.getState().setMode("Remote");
    expect(useVaultStore.getState().mode).toBe("Remote");
  });

  it("setStatus updates vault status", () => {
    const status = { initialized: true, sealed: false, has_vault: true };
    useVaultStore.getState().setStatus(status);
    expect(useVaultStore.getState().status).toEqual(status);
  });
});

describe("namespaceStore", () => {
  beforeEach(() => {
    useNamespaceStore.setState({
      namespaces: ["team-a", "team-b"],
      active: "team-a",
      loaded: true,
    });
    vi.restoreAllMocks();
  });

  it("reset clears in-memory state back to a cold-start default", () => {
    useNamespaceStore.getState().reset();
    const s = useNamespaceStore.getState();
    expect(s.namespaces).toEqual([]);
    expect(s.active).toBe("");
    // loaded flips back to false so the next mount re-fetches instead of
    // short-circuiting on the previous session's stale `loaded`.
    expect(s.loaded).toBe(false);
  });

  it("refresh keeps the cached list when the list fetch fails", async () => {
    // A failed list fetch must NOT be treated as an empty list — otherwise
    // it would blank a good cached list and hide the switcher until restart.
    vi.spyOn(api, "listNamespaces").mockRejectedValue(new Error("boom"));
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");

    await useNamespaceStore.getState().refresh();

    const s = useNamespaceStore.getState();
    expect(s.namespaces).toEqual(["team-a", "team-b"]);
    expect(s.active).toBe("");
    expect(s.loaded).toBe(true);
  });

  it("refresh caches a genuinely empty list (single-tenant)", async () => {
    vi.spyOn(api, "listNamespaces").mockResolvedValue({ namespaces: [] });
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().namespaces).toEqual([]);
  });

  it("refresh keeps the cached active when the active fetch fails", async () => {
    vi.spyOn(api, "listNamespaces").mockResolvedValue({
      namespaces: ["team-a"],
    });
    vi.spyOn(api, "getActiveNamespace").mockRejectedValue(new Error("boom"));

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().active).toBe("team-a");
  });
});
