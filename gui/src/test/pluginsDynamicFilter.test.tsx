/**
 * Plugins page "Dynamic engines" filter (T62, features/dynamic-secrets.md
 * Phase 5): `?kind=secret/dynamic`, engine_type and the dynamic capabilities.
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

const BASE_CAPS = {
  log_emit: true,
  storage_prefix: "",
  audit_emit: false,
  allowed_keys: [],
  allowed_hosts: [],
};

const STATIC = {
  name: "static-tool",
  version: "1.0.0",
  plugin_type: "secret-engine",
  runtime: "wasm",
  abi_version: "1.0",
  sha256: "0".repeat(64),
  size: 1,
  description: "",
  capabilities: BASE_CAPS,
};

const PG = {
  ...STATIC,
  name: "bastion-plugin-postgres",
  version: "0.2.0",
  plugin_type: "secret/dynamic",
  engine_type: "database",
  runtime: "process",
  abi_version: "1.5",
  capabilities: {
    ...BASE_CAPS,
    dynamic_lease_register: true,
    dynamic_audit_emit: true,
    dynamic_pool_checkout: true,
  },
};

function setup(dynamic: unknown[] = [PG]) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve({ plugins: [STATIC, PG] });
      case "plugins_list_by_kind":
        return Promise.resolve({ plugins: dynamic });
      default:
        return Promise.resolve(null);
    }
  });
}

function renderPage() {
  render(
    <MemoryRouter>
      <PluginsPage />
    </MemoryRouter>,
  );
}

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest("div.rounded-md") as HTMLElement;
}

beforeEach(() => mockInvoke.mockReset());

describe("Plugins → Dynamic engines filter", () => {
  it("asks the host for secret/dynamic plugins only", async () => {
    setup();
    renderPage();
    expect(await screen.findByText("static-tool")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Dynamic engines" }));
    await waitFor(() => expect(screen.queryByText("static-tool")).not.toBeInTheDocument());
    expect(mockInvoke).toHaveBeenCalledWith("plugins_list_by_kind", { kind: "secret/dynamic" });
    expect(screen.getByText("bastion-plugin-postgres")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Dynamic engines" })).toHaveAttribute("aria-pressed", "true");
  });

  it("shows engine_type and the declared dynamic capabilities", async () => {
    setup();
    renderPage();
    await screen.findByText("bastion-plugin-postgres");
    const pg = rowOf("bastion-plugin-postgres");
    expect(within(pg).getByText("engine: database")).toBeInTheDocument();
    for (const cap of ["lease_register", "dynamic_audit", "pool_checkout"]) {
      expect(within(pg).getByText(cap)).toBeInTheDocument();
    }
    const other = rowOf("static-tool");
    expect(within(other).queryByText(/^engine:/)).not.toBeInTheDocument();
    expect(within(other).queryByText("lease_register")).not.toBeInTheDocument();
  });

  it("keeps the catalog flow: register stays available and All lists everything again", async () => {
    setup([]);
    renderPage();
    await screen.findByText("static-tool");
    await userEvent.click(screen.getByRole("button", { name: "Dynamic engines" }));
    expect(await screen.findByText(/No dynamic-secret engine registered/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "+ Register plugin" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "All" }));
    expect(await screen.findByText("static-tool")).toBeInTheDocument();
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === "plugins_list")).toHaveLength(2);
  });
});
