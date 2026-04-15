import { describe, it, expect, beforeEach } from "vitest";
import { useAuthStore } from "../stores/authStore";
import { useVaultStore } from "../stores/vaultStore";

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
