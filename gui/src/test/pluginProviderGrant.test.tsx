/**
 * Plugins page: the credential-provider consent panel (ABI 1.3).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { PluginsPage } from "../routes/PluginsPage";

const PROVIDER = {
  name: "self-accounts",
  version: "1.0.0",
  plugin_type: "secret-engine",
  runtime: "wasm",
  abi_version: "1.3",
  sha256: "0".repeat(64),
  size: 1,
  description: "",
  capabilities: {
    log_emit: true,
    storage_prefix: "",
    audit_emit: true,
    allowed_keys: [],
    allowed_hosts: [],
    caller_identity: true,
    storage_scope: "entity",
    credential_provider: {
      display_name: "Self-account",
      selection: "operator",
      protocols: ["ssh", "rdp"],
      secret_kinds: ["password", "ssh-key"],
    },
  },
};

const PLAIN = { ...PROVIDER, name: "plain", capabilities: { ...PROVIDER.capabilities, credential_provider: null } };

function grantInfo(over: Record<string, unknown> = {}) {
  return {
    requested: PROVIDER.capabilities.credential_provider,
    requests_network: false,
    grant: null,
    live: false,
    ...over,
  };
}

function setup(info: Record<string, unknown>) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve({ plugins: [PROVIDER, PLAIN] });
      case "plugins_get_provider_grant":
        return Promise.resolve(info);
      case "plugins_set_provider_grant":
      case "plugins_delete_provider_grant":
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  });
}

async function open() {
  render(
    <MemoryRouter>
      <PluginsPage />
    </MemoryRouter>,
  );
  const btn = await screen.findByRole("button", { name: "Credentials" });
  await userEvent.click(btn);
}

beforeEach(() => mockInvoke.mockReset());

describe("credential-provider consent panel", () => {
  it("offers the panel only for a plugin that declares the capability", async () => {
    setup(grantInfo());
    render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await screen.findByText("plain");
    expect(screen.getAllByRole("button", { name: "Credentials" })).toHaveLength(1);
  });

  it("shows the declared block and keeps Approve disabled until consent is ticked", async () => {
    setup(grantInfo());
    await open();
    expect(await screen.findByText("Self-account")).toBeInTheDocument();
    expect(screen.getByText("ssh, rdp")).toBeInTheDocument();
    expect(screen.getByText(/Not approved/)).toBeInTheDocument();
    const approve = screen.getByRole("button", { name: "Approve" });
    expect(approve).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox"));
    expect(approve).toBeEnabled();
    await userEvent.click(approve);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_set_provider_grant", { name: "self-accounts" }),
    );
  });

  it("warns when the provider also requests network access", async () => {
    setup(grantInfo({ requests_network: true }));
    await open();
    expect(await screen.findByRole("alert")).toHaveTextContent(/network access/);
  });

  it("marks a grant pinned to an older block as stale", async () => {
    setup(
      grantInfo({
        grant: { granted_by: "e1", granted_at: "2026-10-01T00:00:00Z", capability_sha256: "x" },
        live: false,
      }),
    );
    await open();
    expect(await screen.findByText(/stale/)).toBeInTheDocument();
  });

  it("revokes an existing grant", async () => {
    setup(
      grantInfo({
        grant: { granted_by: "e1", granted_at: "2026-10-01T00:00:00Z", capability_sha256: "x" },
        live: true,
      }),
    );
    await open();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_delete_provider_grant", { name: "self-accounts" }),
    );
  });
});
