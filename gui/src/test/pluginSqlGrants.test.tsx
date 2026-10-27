/**
 * Plugins page: the consent panel for the two ABI 1.4 SQL grants
 * (`sql-gate`, `resource-credentials`; features/sql-browser.md §9.2).
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

const BASE = {
  version: "1.0.0",
  plugin_type: "secret-engine",
  runtime: "process",
  abi_version: "1.4",
  sha256: "0".repeat(64),
  size: 1,
  description: "",
};
const CAPS = { log_emit: true, storage_prefix: "", audit_emit: true, allowed_keys: [], allowed_hosts: [], caller_identity: true };

const SQL_PLUGIN = {
  ...BASE,
  name: "dbms-management",
  capabilities: { ...CAPS, sql_gate: true, resource_credentials: ["sql"], sql_console: true },
};
const GATE_ONLY = { ...BASE, name: "gate-only", capabilities: { ...CAPS, sql_gate: true } };
const PLAIN = { ...BASE, name: "plain", abi_version: "1.3", capabilities: CAPS };

const SHA = "ab".repeat(32);
const grant = { v: 1, granted_by: "e1", granted_at: "2026-10-26T12:00:00Z", capability_sha256: SHA };

function info(over: Record<string, unknown> = {}) {
  return { requested: true, capability_sha256: SHA, grant: null, live: false, ...over };
}

function setup(plugins: unknown[], infos: Record<string, Record<string, unknown>> = {}) {
  mockInvoke.mockImplementation((cmd: string, args?: { kind?: string }) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve({ plugins });
      case "plugins_get_sql_grant":
        return Promise.resolve(infos[args!.kind!] ?? info());
      default:
        return Promise.resolve(null);
    }
  });
}

async function openFor(name: string) {
  render(
    <MemoryRouter>
      <PluginsPage />
    </MemoryRouter>,
  );
  await screen.findByText(name);
  const row = screen.getByText(name).closest("div.flex.items-start")!;
  await userEvent.click(within(row as HTMLElement).getByRole("button", { name: "SQL access" }));
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("SQL access consent panel", () => {
  it("is offered only for a plugin that requests one of the two grants", async () => {
    setup([SQL_PLUGIN, GATE_ONLY, PLAIN]);
    render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await screen.findByText("plain");
    expect(screen.getAllByRole("button", { name: "SQL access" })).toHaveLength(2);
  });

  it("is offered for a plugin that requests only the credential release", async () => {
    setup([{ ...BASE, name: "creds-only", capabilities: { ...CAPS, resource_credentials: ["sql"] } }]);
    render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("button", { name: "SQL access" })).toBeInTheDocument();
  });

  it("shows one section per requested grant, each with its own consent", async () => {
    setup([SQL_PLUGIN]);
    await openFor("dbms-management");
    const gate = await screen.findByTestId("sql-grant-sql-gate");
    const creds = screen.getByTestId("sql-grant-resource-credentials");
    expect(gate).toHaveTextContent(/which SQL privileges the signed-in caller holds/);
    expect(creds).toHaveTextContent(/release the login \(user name and password\)/);
    expect(creds).toHaveTextContent(/sql_endpoint/);
    expect(within(gate).getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(within(creds).getByRole("button", { name: "Approve" })).toBeDisabled();
  });

  it("shows only the gate section for a plugin that requests only the gate", async () => {
    setup([GATE_ONLY]);
    await openFor("gate-only");
    await screen.findByTestId("sql-grant-sql-gate");
    expect(screen.queryByTestId("sql-grant-resource-credentials")).not.toBeInTheDocument();
  });

  it("approves the gate and the credential release separately, after consent", async () => {
    setup([SQL_PLUGIN]);
    await openFor("dbms-management");
    const gate = await screen.findByTestId("sql-grant-sql-gate");
    await userEvent.click(within(gate).getByRole("checkbox"));
    await userEvent.click(within(gate).getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_set_sql_grant", { name: "dbms-management", kind: "sql-gate" }),
    );
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "plugins_set_sql_grant",
      expect.objectContaining({ kind: "resource-credentials" }),
    );

    const creds = screen.getByTestId("sql-grant-resource-credentials");
    await userEvent.click(within(creds).getByRole("checkbox"));
    await userEvent.click(within(creds).getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_set_sql_grant", {
        name: "dbms-management",
        kind: "resource-credentials",
      }),
    );
  });

  it("will not approve what the active manifest does not request", async () => {
    setup([SQL_PLUGIN], { "sql-gate": info({ requested: false }) });
    await openFor("dbms-management");
    const gate = await screen.findByTestId("sql-grant-sql-gate");
    await userEvent.click(within(gate).getByRole("checkbox"));
    expect(within(gate).getByRole("button", { name: "Approve" })).toBeDisabled();
  });

  it("marks an approval pinned to an older capability block as stale", async () => {
    setup([SQL_PLUGIN], { "sql-gate": info({ grant, live: false }) });
    await openFor("dbms-management");
    const gate = await screen.findByTestId("sql-grant-sql-gate");
    expect(await within(gate).findByText(/stale/)).toBeInTheDocument();
    expect(gate).toHaveTextContent("Approved by e1");
  });

  it("shows a live approval, names the pinned block, and revokes it", async () => {
    setup([SQL_PLUGIN], { "resource-credentials": info({ grant, live: true }) });
    await openFor("dbms-management");
    const creds = await screen.findByTestId("sql-grant-resource-credentials");
    expect(await within(creds).findByText("approved")).toBeInTheDocument();
    expect(creds).toHaveTextContent(`capability block sha256: ${SHA.slice(0, 16)}`);
    await userEvent.click(within(creds).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("plugins_delete_sql_grant", {
        name: "dbms-management",
        kind: "resource-credentials",
      }),
    );
  });
});
