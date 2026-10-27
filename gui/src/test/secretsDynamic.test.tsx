/**
 * Secrets → Dynamic (T62, features/dynamic-secrets.md Phase 5): mounts of
 * `secret/dynamic` plugins and their roles, with "Generate credential".
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
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

import { SecretsPage } from "../routes/SecretsPage";

const MOUNTS = [
  { path: "secret/", mount_type: "kv-v2", description: "" },
  { path: "team/", mount_type: "kv", description: "" },
  { path: "database/", mount_type: "plugin:pg", description: "" },
  { path: "tools/", mount_type: "plugin:static-tool", description: "" },
];

const PG = {
  name: "pg",
  version: "0.2.0",
  plugin_type: "secret/dynamic",
  engine_type: "database",
  runtime: "process",
  abi_version: "1.4",
  sha256: "0".repeat(64),
  size: 1,
  description: "",
  capabilities: {
    log_emit: true,
    storage_prefix: "",
    audit_emit: false,
    allowed_keys: [],
    allowed_hosts: [],
    dynamic_lease_register: true,
    dynamic_audit_emit: true,
    dynamic_pool_checkout: true,
  },
};

function setup(overrides: Record<string, (args?: unknown) => Promise<unknown>> = {}) {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "list_mounts":
        return Promise.resolve(MOUNTS);
      case "plugins_list_by_kind":
        return Promise.resolve({ plugins: [PG] });
      case "dynamic_list_roles":
        return Promise.resolve(["readonly", "admin"]);
      default:
        return Promise.resolve(null);
    }
  });
}

function renderPage() {
  render(
    <MemoryRouter>
      <SecretsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => mockInvoke.mockReset());

describe("Secrets → Dynamic", () => {
  it("loads nothing dynamic until the tab is opened", async () => {
    setup();
    renderPage();
    expect(await screen.findByText("team/")).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalledWith("plugins_list_by_kind", expect.anything());
    expect(mockInvoke).not.toHaveBeenCalledWith("dynamic_list_roles", expect.anything());
  });

  it("lists only the mounts of dynamic plugins, with their roles", async () => {
    setup();
    renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Dynamic" }));
    const roles = await screen.findByRole("list", { name: "Roles of database/" });
    expect(within(roles).getByText("readonly")).toBeInTheDocument();
    expect(within(roles).getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("database")).toBeInTheDocument();
    expect(screen.queryByText("tools/")).not.toBeInTheDocument();
    expect(mockInvoke).toHaveBeenCalledWith("plugins_list_by_kind", { kind: "secret/dynamic" });
    expect(mockInvoke).toHaveBeenCalledWith("dynamic_list_roles", { mount: "database/" });
    expect(mockInvoke).not.toHaveBeenCalledWith("dynamic_list_roles", { mount: "tools/" });
  });

  it("opens the generate dialog for a role without generating anything yet", async () => {
    setup();
    renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Dynamic" }));
    const roles = await screen.findByRole("list", { name: "Roles of database/" });
    const row = within(roles).getByText("readonly").closest("li")!;
    await userEvent.click(within(row).getByRole("button", { name: "Generate credential" }));
    expect(screen.getByText("Generate credential: readonly")).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalledWith("dynamic_generate_creds", expect.anything());
  });

  it("explains why dynamic mounts cannot be shown without catalog access", async () => {
    setup({ plugins_list_by_kind: () => Promise.reject({ message: "HTTP 403: permission denied" }) });
    renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Dynamic" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot read the plugin catalog/);
  });

  it("shows an empty state when no dynamic engine is mounted", async () => {
    setup({ plugins_list_by_kind: () => Promise.resolve({ plugins: [] }) });
    renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Dynamic" }));
    expect(await screen.findByText("No dynamic-secret engines mounted")).toBeInTheDocument();
  });
});
