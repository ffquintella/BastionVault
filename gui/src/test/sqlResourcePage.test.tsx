/**
 * The Resources page for a database resource: the Connection tab carries the
 * SQL browser's profile editor instead of the launcher's profile panel, and
 * the Sharing tab offers the SQL privileges (features/sql-browser.md §10).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
}));

const SQL_PROFILE = {
  id: "p_ro",
  name: "Read-only (svc_ro)",
  protocol: "sql",
  sql: { ceiling: ["sql_select"], tls: { mode: "verify-full" }, require_mfa: false },
  credential_source: { kind: "secret", secret_id: "svc_ro" },
};

function mockVault(type: string, typesSaved: unknown = null) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "resource_types_read_effective":
        return Promise.resolve({ source: typesSaved ? "mount" : "none", types: typesSaved });
      case "list_asset_groups":
      case "asset_groups_for_resource":
        return Promise.resolve({ groups: [] });
      case "search_resources":
        return Promise.resolve({ items: [{ name: "netrisk-db", type, hostname: "db1.example.net" }], total: 1, has_more: false });
      case "read_resource":
        return Promise.resolve({
          name: "netrisk-db",
          type,
          engine: "postgresql",
          hostname: "db1.example.net",
          connection_profiles: [SQL_PROFILE],
        });
      case "resource_sql_privileges":
        return Promise.resolve({ resource: "netrisk-db", server: ["sql_select"], resource_wide: ["sql_select"] });
      case "list_shares_for_target":
        return Promise.resolve([]);
      case "list_resource_secrets":
        return Promise.resolve({ keys: [] });
      case "list_entity_aliases":
        return Promise.resolve([]);
      case "get_resource_owner":
        return Promise.resolve({ owned: false });
      case "capabilities_self":
        return Promise.resolve({ paths: {} });
      default:
        return Promise.resolve(null);
    }
  });
}

async function openDetail() {
  const { ResourcesPage } = await import("../routes/ResourcesPage");
  render(
    <MemoryRouter>
      <ToastProvider>
        <ResourcesPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await userEvent.click(await screen.findByText("netrisk-db"));
}

beforeEach(() => {
  mockInvoke.mockReset();
  useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "entity-1" });
});

describe("a database resource", () => {
  it("has a Connection tab with the SQL browser's profiles, and not the launcher's profile panel", async () => {
    mockVault("database");
    await openDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Connection" }));
    expect(await screen.findByTestId("sql-profiles-card")).toHaveTextContent("Read-only (svc_ro)");
    expect(screen.queryByText("Connection profiles")).not.toBeInTheDocument();
    // The launcher's own transport and bastion previews do not apply here.
    expect(mockInvoke.mock.calls.map((c) => c[0])).not.toContain("resource_login_class");
  });

  it("does not report its sql profile as one from a newer version", async () => {
    mockVault("database", {
      database: { id: "database", label: "Database", color: "error", fields: [], connect: { protocols: ["ssh", "sql"] } },
    });
    await openDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Connection" }));
    await screen.findByTestId("sql-profiles-card");
    expect(screen.queryByText(/unsupported protocol or credential source/)).not.toBeInTheDocument();
  });

  it("offers the SQL privileges in the Sharing tab, starting on Read only", async () => {
    mockVault("database");
    await openDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Sharing" }));
    await userEvent.click(await screen.findByRole("button", { name: /grant access/i }));
    expect(await screen.findByTestId("sql-share-capabilities")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Read only" })).toHaveAttribute("aria-pressed", "true"),
    );
    expect(screen.getByRole("button", { name: "read" })).toHaveAttribute("aria-pressed", "false");
  });
});

describe("a resource of another type", () => {
  it("gets neither the SQL card nor the SQL chips", async () => {
    mockVault("firewall");
    await openDetail();
    await screen.findByRole("button", { name: "Sharing" });
    expect(screen.queryByRole("button", { name: "Connection" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sharing" }));
    await userEvent.click(await screen.findByRole("button", { name: /grant access/i }));
    expect(screen.queryByTestId("sql-share-capabilities")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "read" })).toHaveAttribute("aria-pressed", "true");
  });
});
