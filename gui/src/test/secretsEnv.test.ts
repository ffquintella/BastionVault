import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the Tauri invoke API at the module level so the api wrappers dispatch
// into a spy instead of a real backend.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import * as api from "../lib/api";

describe("KV env api wiring", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("readSecret forwards the env selector", async () => {
    mockInvoke.mockResolvedValueOnce({
      data: { host: "db.prod" },
      resolved_env: "prod",
      available_envs: ["prod", "staging"],
    });
    const res = await api.readSecret("secret/svc", "secret/", "kv-v2", "prod");
    expect(mockInvoke).toHaveBeenCalledWith("read_secret", {
      path: "secret/svc",
      mount: "secret/",
      mountType: "kv-v2",
      env: "prod",
    });
    expect(res.resolved_env).toBe("prod");
    expect(res.available_envs).toEqual(["prod", "staging"]);
  });

  it("readSecret omits env when not given (base read)", async () => {
    mockInvoke.mockResolvedValueOnce({ data: {}, available_envs: [] });
    await api.readSecret("secret/svc", "secret/", "kv-v2");
    expect(mockInvoke).toHaveBeenCalledWith("read_secret", {
      path: "secret/svc",
      mount: "secret/",
      mountType: "kv-v2",
      env: undefined,
    });
  });

  it("writeSecretEnv sends a targeted env patch", async () => {
    await api.writeSecretEnv(
      "secret/svc",
      "prod",
      { host: "db.prod2" },
      "secret/",
      "kv-v2",
    );
    expect(mockInvoke).toHaveBeenCalledWith("write_secret_env", {
      path: "secret/svc",
      env: "prod",
      data: { host: "db.prod2" },
      mount: "secret/",
      mountType: "kv-v2",
    });
  });

  it("engine config carries the environments registry", async () => {
    await api.writeKvV2EngineConfig("secret/", {
      max_versions: 0,
      cas_required: false,
      delete_version_after: "0s",
      environments: ["prod", "staging", "dev"],
    });
    expect(mockInvoke).toHaveBeenCalledWith("write_kv_v2_engine_config", {
      mount: "secret/",
      config: {
        max_versions: 0,
        cas_required: false,
        delete_version_after: "0s",
        environments: ["prod", "staging", "dev"],
      },
    });
  });
});
