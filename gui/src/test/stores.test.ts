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
    vi.spyOn(api, "namespacesSelf").mockRejectedValue(new Error("boom"));
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");

    await useNamespaceStore.getState().refresh();

    const s = useNamespaceStore.getState();
    expect(s.namespaces).toEqual(["team-a", "team-b"]);
    expect(s.active).toBe("");
    expect(s.loaded).toBe(true);
  });

  it("refresh caches a genuinely empty list (single-tenant)", async () => {
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: [],
      token_namespace: "",
      root: false,
    });
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().namespaces).toEqual([]);
  });

  it("refresh keeps the cached active when the active fetch fails", async () => {
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: ["team-a"],
      token_namespace: "team-a",
      root: false,
    });
    vi.spyOn(api, "getActiveNamespace").mockRejectedValue(new Error("boom"));

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().active).toBe("team-a");
  });

  it("landSession starts a tenant-only session in its own namespace", async () => {
    // The concrete bug: a principal with no access to root used to log in at
    // root and then 403 on every fetch. The session must land on the namespace
    // its token is bound to, and only offer the namespaces it can reach.
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: ["dti/esi"],
      token_namespace: "dti/esi",
      root: false,
    });
    const setActive = vi
      .spyOn(api, "setActiveNamespace")
      .mockResolvedValue(undefined);

    await useNamespaceStore.getState().landSession();

    expect(setActive).toHaveBeenCalledWith("dti/esi");
    const s = useNamespaceStore.getState();
    expect(s.active).toBe("dti/esi");
    expect(s.namespaces).toEqual(["dti/esi"]);
    expect(s.loaded).toBe(true);
  });

  it("landSession leaves a root-operable admin at root", async () => {
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: ["", "dti", "dti/esi"],
      token_namespace: "",
      root: true,
    });
    vi.spyOn(api, "setActiveNamespace").mockResolvedValue(undefined);

    await useNamespaceStore.getState().landSession();

    const s = useNamespaceStore.getState();
    expect(s.active).toBe("");
    // Root participates as the empty string, so the switcher can offer it.
    expect(s.namespaces).toEqual(["", "dti", "dti/esi"]);
  });

  it("refresh widens a root-only answer with the admin namespace walk", async () => {
    // The concrete bug: a root-bound admin token that is not child-visible and
    // has no explicit namespace assignment is "operable" only at root, so
    // `namespaces-self` returns a single entry and the switcher hid itself —
    // even though the same session lists `dti` / `dti/esi` fine on the
    // Namespaces and Users pages, and logged in at root precisely to switch.
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: [""],
      token_namespace: "",
      root: false,
    });
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");
    vi.spyOn(api, "listNamespaces").mockResolvedValue({
      namespaces: ["dti", "dti/esi"],
    });

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().namespaces).toEqual([
      "",
      "dti",
      "dti/esi",
    ]);
  });

  it("refresh widens with the walk when namespaces-self is unavailable", async () => {
    // An older server has no `sys/namespaces-self` route at all. The walk still
    // answers for an admin, so the switcher must not go dark.
    vi.spyOn(api, "namespacesSelf").mockRejectedValue(new Error("404"));
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("");
    vi.spyOn(api, "listNamespaces").mockResolvedValue({
      namespaces: ["dti", "dti/esi"],
    });

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().namespaces).toEqual([
      "",
      "dti",
      "dti/esi",
    ]);
  });

  it("refresh leaves a tenant's single-namespace answer alone", async () => {
    // The walk is sudo-gated, so a tenant principal is 403'd there and the
    // fallback can never invent options its token cannot reach.
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: ["dti/esi"],
      token_namespace: "dti/esi",
      root: false,
    });
    vi.spyOn(api, "getActiveNamespace").mockResolvedValue("dti/esi");
    vi.spyOn(api, "listNamespaces").mockRejectedValue(new Error("403"));

    await useNamespaceStore.getState().refresh();

    expect(useNamespaceStore.getState().namespaces).toEqual(["dti/esi"]);
  });

  it("landSession widens a root-only answer with the admin walk", async () => {
    vi.spyOn(api, "namespacesSelf").mockResolvedValue({
      namespaces: [""],
      token_namespace: "",
      root: false,
    });
    vi.spyOn(api, "setActiveNamespace").mockResolvedValue(undefined);
    vi.spyOn(api, "listNamespaces").mockResolvedValue({
      namespaces: ["dti", "dti/esi"],
    });

    await useNamespaceStore.getState().landSession();

    const s = useNamespaceStore.getState();
    expect(s.active).toBe("");
    expect(s.namespaces).toEqual(["", "dti", "dti/esi"]);
  });

  it("landSession falls back to root when discovery is unavailable", async () => {
    vi.spyOn(api, "namespacesSelf").mockRejectedValue(new Error("boom"));
    const setActive = vi
      .spyOn(api, "setActiveNamespace")
      .mockResolvedValue(undefined);

    await useNamespaceStore.getState().landSession();

    const s = useNamespaceStore.getState();
    expect(s.active).toBe("");
    expect(s.namespaces).toEqual([]);
    expect(setActive).not.toHaveBeenCalled();
  });
});
