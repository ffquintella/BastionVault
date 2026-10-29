/**
 * Ways into the SQL browser (features/sql-browser.md §10, T125 Phase 4):
 * the launcher shared by every entry, the ⌘K palette's resource × `sql`
 * profile entries, and the Connection tab's SQL profile rows.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ConnectPalette } from "../components/ConnectPalette";
import { SqlProfilesCard } from "../components/SqlProfilesCard";
import { ToastProvider } from "../components/ui/Toast";
import { openConnectPalette } from "../lib/connectPaletteEvents";
import { DEFAULT_RESOURCE_TYPES } from "../lib/resourceTypes";
import { allPanes } from "../lib/sessionLayout";
import { defaultSqlProfile, launchableSqlProfiles, openSqlBrowser } from "../lib/sqlLaunch";
import { useSessionWorkspaceStore } from "../stores/sessionWorkspaceStore";
import type { ResourceMetadata, ResourceTypeDef } from "../lib/types";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const SQL_RO = {
  id: "p_ro",
  name: "Read-only",
  protocol: "sql",
  sql: { catalog: "app", tls: { mode: "verify-full" }, ceiling: ["sql_select"], require_mfa: true },
  credential_source: { kind: "secret", secret_id: "svc_ro" },
};
const SQL_BROKEN = { id: "p_bad", name: "Broken", protocol: "sql", sql: { ceiling: ["sql_select"], extra: 1 } };

function db(over: Record<string, unknown> = {}): ResourceMetadata {
  return {
    name: "netrisk-db",
    type: "database",
    tags: "",
    notes: "",
    created_at: "",
    updated_at: "",
    engine: "postgresql",
    hostname: "db1.example.net",
    connection_profiles: [SQL_RO, SQL_BROKEN],
    ...over,
  } as ResourceMetadata;
}

const OPENED = { token: "sess_x", window_label: "session-workspace", label: "sql netrisk-db/app · Read-only", status: {} };

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("the SQL launcher", () => {
  it("offers only the sql profiles the server would accept", () => {
    expect(launchableSqlProfiles(db() as Record<string, unknown>)).toEqual([
      { id: "p_ro", name: "Read-only", requireMfa: true },
    ]);
    expect(launchableSqlProfiles(db({ engine: "" }) as Record<string, unknown>)).toEqual([]);
    expect(defaultSqlProfile([])).toBeNull();
  });

  it("runs the MFA gate for a named profile and passes its ticket to the open", async () => {
    mockInvoke.mockResolvedValue(OPENED);
    const gate = vi.fn().mockResolvedValue({ connect_ticket: "tkt" });
    await openSqlBrowser(gate, "netrisk-db", { id: "p_ro", name: "Read-only", requireMfa: true }, "workspace-tab");
    expect(gate).toHaveBeenCalledWith("netrisk-db", "p_ro", "Read-only");
    expect(mockInvoke).toHaveBeenCalledWith("sql_session_open", {
      request: { resource_name: "netrisk-db", profile_id: "p_ro", connect_ticket: "tkt", placement: "workspace-tab" },
    });
  });

  it("opens nothing when the factor prompt is cancelled", async () => {
    const gate = vi.fn().mockResolvedValue(null);
    expect(await openSqlBrowser(gate, "netrisk-db", { id: "p_ro", name: "Read-only", requireMfa: true })).toBeNull();
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("lets the plugin pick without a profile, and explains its refusal codes", async () => {
    mockInvoke.mockRejectedValue(
      "plugin dbms-management returned status 4: mfa_required: this SQL profile requires an MFA ticket",
    );
    const gate = vi.fn();
    await expect(openSqlBrowser(gate, "netrisk-db", null)).rejects.toThrow(/needs a second factor/);
    expect(gate).not.toHaveBeenCalled();
    expect(mockInvoke).toHaveBeenCalledWith("sql_session_open", { request: { resource_name: "netrisk-db" } });
  });
});

describe("⌘K palette", () => {
  it("lists resource × sql profile and opens it at the requested placement", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "resource_types_read":
          return Promise.resolve(null);
        case "list_resources":
          return Promise.resolve({ resources: ["netrisk-db"] });
        case "read_resource":
          return Promise.resolve(db());
        case "connect_mfa_begin":
          return Promise.resolve({ required: false });
        case "sql_session_open":
          return Promise.resolve(OPENED);
        default:
          return Promise.reject(new Error(`unmocked ${cmd}`));
      }
    });
    render(
      <ToastProvider>
        <ConnectPalette armed />
      </ToastProvider>,
    );
    act(() => openConnectPalette("workspace-split-right"));
    const entry = await screen.findByText("Read-only");
    expect(screen.getByText("SQL")).toBeInTheDocument();
    expect(screen.queryByText("Broken")).toBeNull();
    await userEvent.click(entry);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("sql_session_open", {
        request: { resource_name: "netrisk-db", profile_id: "p_ro", placement: "workspace-split-right" },
      }),
    );
    expect(mockInvoke).toHaveBeenCalledWith("connect_mfa_begin", { resourceName: "netrisk-db", profileId: "p_ro" });
  });
});

describe("Connection tab", () => {
  it("opens the SQL browser from a profile row or with the plugin's choice", async () => {
    mockInvoke.mockRejectedValue(new Error("unmocked"));
    const onOpenSql = vi.fn();
    render(
      <SqlProfilesCard
        resource={db()}
        typeDef={DEFAULT_RESOURCE_TYPES["database"] as ResourceTypeDef}
        onUpdated={vi.fn()}
        onOpenSql={onOpenSql}
        toast={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Open SQL browser with Read-only" }));
    expect(onOpenSql).toHaveBeenLastCalledWith({ id: "p_ro", name: "Read-only", requireMfa: true });
    // The broken profile offers no Open.
    expect(screen.queryByRole("button", { name: "Open SQL browser with Broken" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Open SQL browser" }));
    expect(onOpenSql).toHaveBeenLastCalledWith(null);
  });
});

describe("Session Workspace", () => {
  it("adopts a SQL session the host placed there as a `sql` pane", () => {
    useSessionWorkspaceStore.getState().reset();
    const adopted = useSessionWorkspaceStore.getState().adopt([
      {
        token: "sess_sql",
        protocol: "sql",
        label: "sql netrisk-db/app · ro",
        resource_name: "netrisk-db",
        profile_id: "ro",
        stdout_event: null,
        closed_event: "",
        resize_event: null,
        cursor_event: null,
        width: null,
        height: null,
        opened_at: "2026-10-29T12:00:00Z",
        placement: "workspace-tab",
        pane_ref: null,
        attached_to: "session-workspace",
        attach_epoch: 1,
      },
    ]);
    expect(adopted).toEqual(["sess_sql"]);
    const panes = allPanes(useSessionWorkspaceStore.getState().layout);
    expect(panes.map((p) => [p.token, p.protocol])).toEqual([["sess_sql", "sql"]]);
  });
});
