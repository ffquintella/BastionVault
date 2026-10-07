/**
 * Plugins page: per-user data of an entity-scoped plugin
 * (features/self-accounts.md Phase 5). Counts only, and a confirmed purge.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
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

const ENTITY_SCOPED = {
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

const PLAIN = {
  ...ENTITY_SCOPED,
  name: "plain",
  capabilities: { ...ENTITY_SCOPED.capabilities, storage_scope: "plugin", caller_identity: false, credential_provider: null },
};

type Usage = {
  entities: { entity_id: string; display_name?: string | null; accounts: number }[];
  total_accounts: number;
  total_entities: number;
  pending_purges: number;
};

function setup(usage: Usage | (() => Promise<unknown>)) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve({ plugins: [ENTITY_SCOPED, PLAIN] });
      case "plugins_entity_data_usage":
        return typeof usage === "function" ? usage() : Promise.resolve(usage);
      case "plugins_purge_entity_data":
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  });
}

const USAGE: Usage = {
  entities: [
    { entity_id: "4f0c-aaaa", display_name: "felipe", accounts: 3 },
    { entity_id: "9b1d-bbbb", accounts: 1 },
  ],
  total_accounts: 4,
  total_entities: 2,
  pending_purges: 0,
};

async function open() {
  render(
    <MemoryRouter>
      <PluginsPage />
    </MemoryRouter>,
  );
  await userEvent.click(await screen.findByRole("button", { name: "Per-user data" }));
}

beforeEach(() => mockInvoke.mockReset());

describe("per-user data of an entity-scoped plugin", () => {
  it("is offered only for a plugin that keeps per-user data", async () => {
    setup(USAGE);
    render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await screen.findByText("plain");
    expect(screen.getAllByRole("button", { name: "Per-user data" })).toHaveLength(1);
  });

  it("shows counts per user and nothing else", async () => {
    setup(USAGE);
    await open();
    expect(await screen.findByTestId("entity-data-totals")).toHaveTextContent("4 records across 2 users");
    expect(mockInvoke).toHaveBeenCalledWith("plugins_entity_data_usage", { name: "self-accounts" });
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("felipe")).toBeInTheDocument();
    expect(within(rows[0]).getByText("4f0c-aaaa")).toBeInTheDocument();
    expect(within(rows[0]).getByText("3")).toBeInTheDocument();
    expect(within(rows[1]).getByText("unknown")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("deletes one user's data only after confirmation, then reloads", async () => {
    setup(USAGE);
    await open();
    const rows = (await screen.findAllByRole("row")).slice(1);
    await userEvent.click(within(rows[0]).getByRole("button", { name: "Delete" }));
    expect(mockInvoke).not.toHaveBeenCalledWith("plugins_purge_entity_data", expect.anything());
    expect(await screen.findByText(/Delete every self-accounts record of felipe \(3 records\)/)).toBeInTheDocument();
    const dialogButtons = screen.getAllByRole("button", { name: "Delete" });
    await userEvent.click(dialogButtons[dialogButtons.length - 1]);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_purge_entity_data", {
        name: "self-accounts",
        entityId: "4f0c-aaaa",
      }),
    );
    await waitFor(() =>
      expect(mockInvoke.mock.calls.filter((c) => c[0] === "plugins_entity_data_usage")).toHaveLength(2),
    );
  });

  it("says when automatic purges are pending and when there is no data", async () => {
    setup({ entities: [], total_accounts: 0, total_entities: 0, pending_purges: 2 });
    await open();
    expect(await screen.findByRole("status")).toHaveTextContent("2 automatic purges have failed");
    expect(screen.getByText("No user keeps data in this plugin.")).toBeInTheDocument();
  });

  it("shows the server's refusal", async () => {
    setup(() => Promise.reject({ message: "HTTP 403: permission denied" }));
    await open();
    expect(await screen.findByRole("alert")).toHaveTextContent("permission denied");
  });
});
