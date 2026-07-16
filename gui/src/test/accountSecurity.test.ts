import { describe, it, expect, vi, beforeEach } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import * as api from "../lib/api";

describe("account-security API wrappers", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("updateUser sends null for untouched account fields", async () => {
    await api.updateUser("userpass/", "alice", "", "admin");
    expect(mockInvoke).toHaveBeenCalledWith("update_user", {
      mountPath: "userpass/",
      username: "alice",
      password: "",
      policies: "admin",
      disabled: null,
      totpMfaEnabled: null,
      totpMount: null,
      totpKey: null,
      email: null,
      phone: null,
    });
  });

  it("updateUser forwards disable + MFA opts when provided", async () => {
    await api.updateUser("userpass/", "bob", "", "default", {
      disabled: true,
      totpMfaEnabled: true,
      totpMount: "totp/",
      totpKey: "bob-mfa",
      email: "bob@example.com",
      phone: "+55 21 91234-5678",
    });
    expect(mockInvoke).toHaveBeenCalledWith("update_user", {
      mountPath: "userpass/",
      username: "bob",
      password: "",
      policies: "default",
      disabled: true,
      totpMfaEnabled: true,
      totpMount: "totp/",
      totpKey: "bob-mfa",
      email: "bob@example.com",
      phone: "+55 21 91234-5678",
    });
  });

  it("unlockUser targets the unlock command", async () => {
    await api.unlockUser("userpass/", "carol");
    expect(mockInvoke).toHaveBeenCalledWith("unlock_user", {
      mountPath: "userpass/",
      username: "carol",
    });
  });

  it("setLockoutConfig maps camelCase args", async () => {
    await api.setLockoutConfig("userpass/", true, 3, 600);
    expect(mockInvoke).toHaveBeenCalledWith("set_lockout_config", {
      mountPath: "userpass/",
      enabled: true,
      maxFailedAttempts: 3,
      lockoutDurationSecs: 600,
    });
  });

  it("setMfaConfig maps camelCase args", async () => {
    await api.setMfaConfig("userpass/", true, "totp/");
    expect(mockInvoke).toHaveBeenCalledWith("set_mfa_config", {
      mountPath: "userpass/",
      enabled: true,
      defaultMount: "totp/",
    });
  });
});
