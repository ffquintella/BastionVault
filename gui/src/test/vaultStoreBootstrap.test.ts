import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../lib/api", () => ({
  getMode: vi.fn(),
  getRemoteProfile: vi.fn(),
  getSelectedNode: vi.fn(),
}));

import * as api from "../lib/api";
import { useVaultStore } from "../stores/vaultStore";

const profile = { name: "prod", address: "https://vault:8200", tls_skip_verify: false };

describe("vaultStore.bootstrapConnection", () => {
  beforeEach(() => {
    vi.mocked(api.getMode).mockReset();
    vi.mocked(api.getRemoteProfile).mockReset();
    vi.mocked(api.getSelectedNode).mockReset();
    useVaultStore.getState().reset();
  });

  it("restores the remote connection after a webview reload", async () => {
    vi.mocked(api.getMode).mockResolvedValue("Remote");
    vi.mocked(api.getRemoteProfile).mockResolvedValue(profile);
    vi.mocked(api.getSelectedNode).mockResolvedValue(null);
    await useVaultStore.getState().bootstrapConnection();
    const s = useVaultStore.getState();
    expect(s.mode).toBe("Remote");
    expect(s.remoteProfile?.name).toBe("prod");
  });

  it("stays Embedded when the Rust side is in local mode", async () => {
    vi.mocked(api.getMode).mockResolvedValue("Embedded");
    await useVaultStore.getState().bootstrapConnection();
    expect(useVaultStore.getState().mode).toBe("Embedded");
    expect(api.getRemoteProfile).not.toHaveBeenCalled();
  });

  it("does not overwrite a connection already set by the connect flow", async () => {
    useVaultStore.getState().setMode("Remote");
    useVaultStore.getState().setRemoteProfile({ ...profile, name: "fresh" });
    await useVaultStore.getState().bootstrapConnection();
    expect(api.getMode).not.toHaveBeenCalled();
    expect(useVaultStore.getState().remoteProfile?.name).toBe("fresh");
  });
});
