/**
 * The SQL workspace (features/sql-browser.md §10, T125 Phase 4): privilege
 * chips and disabled actions, the vault's verdicts, confirmations, grid
 * edits with conflict reporting, and a session that ends underneath it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SqlWorkspace from "../components/sql/SqlWorkspace";
import type { SqlSessionStatus } from "../lib/api";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const TOKEN = "sess_0123456789abcdef0123456789abcdef";

function status(over: Partial<SqlSessionStatus> = {}): SqlSessionStatus {
  return {
    resource: "netrisk-db",
    profile: "ro",
    catalog: "app",
    engine: "postgresql",
    server_version: "16.15",
    enforcement: "database-first",
    db_enforced: true,
    read_only: false,
    database_read_only: false,
    privileges: ["sql_select", "sql_update"],
    ceiling: ["sql_select", "sql_update"],
    vault_only: [],
    transport: "direct",
    tls_mode: "verify-full",
    transaction: { open: false, failed: false, statements: 0, open_secs: null },
    active_run: null,
    idle_secs: 3,
    age_secs: 10,
    rows_read: 0,
    closed: null,
    taint: null,
    ...over,
  };
}

type Handler = (request: Record<string, unknown>) => unknown;

function setup(handlers: Record<string, Handler>) {
  mockInvoke.mockImplementation((cmd: string, args?: { request?: Record<string, unknown> }) => {
    const h = handlers[cmd];
    if (!h) return Promise.reject(new Error(`unmocked ${cmd}`));
    try {
      return Promise.resolve(h(args?.request ?? {}));
    } catch (e) {
      return Promise.reject(e);
    }
  });
}

const PAGE = {
  run_id: "r1",
  state: "done",
  statement_index: 0,
  columns: [
    { name: "id", type: "int4", kind: "number" },
    { name: "email", type: "text", kind: "string" },
    { name: "note", type: "text", kind: "string" },
  ],
  rows: [
    [1, "a@x", null],
    [2, "b@x", ""],
  ],
  truncated_cells: [],
  has_more: false,
  rows_read: 2,
  row_budget_exhausted: false,
  messages: [
    { index: 0, kind: "Select", outcome: "ok", rows_affected: null, rows_returned: 2, duration_ms: 4, truncated: false, error: null },
  ],
  elapsed_ms: 5,
};

function base(over: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    sql_session_status: () => status(),
    sql_privileges: () => ({ resource: "netrisk-db", server: ["sql_select", "sql_update"], resource_wide: [] }),
    sql_objects: () => ({ catalog: "app", keys: ["public"] }),
    ...over,
  };
}

async function typeAndRun(sql: string) {
  const editor = screen.getByLabelText("SQL editor");
  fireEvent.change(editor, { target: { value: sql } });
  await userEvent.click(screen.getByRole("button", { name: "Run (statement at the cursor)" }));
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("SQL workspace", () => {
  it("shows the caller's privileges as chips and the enforcement panel", async () => {
    setup(
      base({
        sql_session_status: () =>
          status({ db_enforced: false, ceiling: ["sql_select", "sql_update", "sql_drop"], vault_only: ["sql_drop"] }),
        sql_privileges: () => ({ resource: "netrisk-db", server: ["sql_update"], resource_wide: [] }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql netrisk-db/app · ro" />);
    const chips = await screen.findByTestId("sql-privilege-chips");
    await waitFor(() => expect(within(chips).getByText("sql_update")).toBeInTheDocument());
    expect(within(chips).queryByText("sql_select")).toBeNull();
    // Explain needs sql_select: disabled as a convenience, never as a control.
    expect(screen.getByRole("button", { name: "Your grant lacks sql_select" })).toBeDisabled();
    const enforcement = screen.getByTestId("sql-enforcement");
    expect(within(screen.getByTestId("sql-vault-only")).getByText("sql_drop")).toBeInTheDocument();
    expect(enforcement).toHaveTextContent("can do more than the grant");
    expect(enforcement).toHaveTextContent("db_enforced: false");
    expect(screen.queryByTestId("sql-residuals")).toBeNull();
  });

  it("states the engine's residuals in the enforcement panel", async () => {
    const residuals = ["SQL Server runs each statement as a T-SQL batch", "SQL Server has no read-only session guard"];
    setup(base({ sql_session_status: () => status({ engine: "mssql", residuals }) }));
    render(<SqlWorkspace token={TOKEN} label="sql netrisk-db/app · ro" />);
    const list = await screen.findByTestId("sql-residuals");
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual(residuals);
  });

  it("offers no manual commit in a read-only Oracle session and lists its residuals", async () => {
    const residuals = ["Oracle has no session-wide read-only mode", "Oracle has no server auto-commit"];
    setup(base({ sql_session_status: () => status({ engine: "oracle", read_only: true, residuals }) }));
    render(<SqlWorkspace token={TOKEN} label="sql orcl/FREEPDB1 · ro" />);
    const list = await screen.findByTestId("sql-residuals");
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    const mode = screen.getByLabelText("Commit mode");
    expect(mode).toBeDisabled();
    expect(mode).toHaveAttribute("title", expect.stringMatching(/manual commit is not available/));
  });

  it("runs a statement through the host with only the session token and shows NULL apart from ''", async () => {
    setup(base({ sql_execute: () => ({ run_id: "r1", state: "running", statements: [] }), sql_run: () => PAGE }));
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-privilege-chips");
    await typeAndRun("select * from users");
    await screen.findByText("a@x");
    expect(screen.getAllByText("NULL")).toHaveLength(1);
    expect(mockInvoke).toHaveBeenCalledWith("sql_execute", { request: { token: TOKEN, sql: "select * from users" } });
    expect(mockInvoke).toHaveBeenCalledWith("sql_run", { request: { token: TOKEN, run_id: "r1" } });
    // The webview names no path, mount, vault token or plugin session id.
    for (const [, args] of mockInvoke.mock.calls) {
      const req = (args as { request: Record<string, unknown> }).request;
      expect(req.token).toBe(TOKEN);
      expect(Object.keys(req).some((k) => ["path", "mount", "session_id", "vault_token"].includes(k))).toBe(false);
    }
    await userEvent.click(screen.getByRole("tab", { name: "Messages" }));
    expect(screen.getByLabelText("Messages")).toHaveTextContent("Select · ok · 2 rows · 4 ms");
  });

  it("shows the vault's verdict for a refused statement", async () => {
    setup(
      base({
        sql_execute: () => ({
          state: "refused",
          message: "needs `sql_update` on `app.public.permission_to_user`",
          statements: [
            {
              index: 0,
              kinds: ["Update"],
              unclassified: false,
              verdict: "refused",
              required: [
                {
                  capability: "sql_update",
                  target: { catalog: "app", schema: "public", object: "permission_to_user" },
                  allowed: false,
                  denied_by_deny: false,
                },
              ],
            },
          ],
        }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-privilege-chips");
    await typeAndRun("update permission_to_user set a = 1 where id = 2");
    const refusal = await screen.findByTestId("sql-refusal");
    expect(refusal).toHaveTextContent("Refused by the vault: needs `sql_update` on `app.public.permission_to_user`");
    expect(mockInvoke.mock.calls.some(([c]) => c === "sql_run")).toBe(false);
  });

  it("asks before DELETE without WHERE, and sends nothing when cancelled", async () => {
    setup(base({ sql_execute: () => ({ run_id: "r1", state: "running", statements: [] }), sql_run: () => ({ ...PAGE, columns: [], rows: [] }) }));
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-privilege-chips");
    await typeAndRun("delete from users");
    const dialog = await screen.findByRole("alertdialog", { name: "Run this statement?" });
    expect(dialog).toHaveTextContent("has no WHERE clause: it deletes every row");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(mockInvoke.mock.calls.some(([c]) => c === "sql_execute")).toBe(false);

    await userEvent.click(screen.getByRole("button", { name: "Run (statement at the cursor)" }));
    await userEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Run it" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("sql_execute", { request: { token: TOKEN, sql: "delete from users" } }),
    );
  });

  it("edits a row as a structured operation and reports a conflict", async () => {
    const edits: unknown[] = [];
    setup(
      base({
        sql_objects: (r) =>
          r.object
            ? {
                catalog: "app",
                schema: "public",
                name: "users",
                kind: "table",
                definition: null,
                columns: [],
                constraints: [],
                indexes: [],
                triggers: [],
                routines: [],
                edit: { editable: true, key: ["id"], reason: null },
              }
            : r.schema
              ? { catalog: "app", schema: "public", objects: [{ name: "users", kind: "table" }], truncated: false }
              : { catalog: "app", keys: ["public"] },
        sql_privileges: (r) => ({
          resource: "netrisk-db",
          server: ["sql_select"],
          resource_wide: [],
          ...(Array.isArray(r.objects) && r.objects.length > 0
            ? { objects: [{ catalog: "app", schema: "public", object: "users", addressable: true, capabilities: ["sql_select", "sql_update", "sql_delete"] }] }
            : {}),
        }),
        sql_execute: () => ({ run_id: "r1", state: "running", statements: [] }),
        sql_run: () => PAGE,
        sql_rows: (r) => {
          edits.push(r.edit);
          return { state: "conflict", rows_affected: 0, message: "the row changed (or is gone) since it was read; nothing was written" };
        },
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await userEvent.click(await screen.findByRole("button", { name: "public" }));
    await userEvent.click(await screen.findByRole("button", { name: "Open public.users" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("sql_execute", {
        request: { token: TOKEN, sql: 'SELECT * FROM "public"."users" LIMIT 500;' },
      }),
    );
    const cell = await screen.findByText("a@x");
    await userEvent.dblClick(cell);
    const input = screen.getByLabelText("Edit email");
    await userEvent.clear(input);
    await userEvent.type(input, "new@x{Enter}");
    await userEvent.click(screen.getByRole("button", { name: "Save row 1" }));
    await waitFor(() => expect(screen.getByTestId("row-outcome-0")).toHaveTextContent("Conflict"));
    expect(edits).toEqual([
      {
        object: { schema: "public", name: "users" },
        op: "update",
        key: { id: 1 },
        values: { email: "new@x" },
        original: { email: "a@x" },
      },
    ]);
    // Insert is not granted on the object: offered disabled, the vault decides anyway.
    expect(screen.getByRole("button", { name: "Add row" })).toBeDisabled();
  });

  it("keeps the grid read-only for a result that did not come from a table", async () => {
    setup(base({ sql_execute: () => ({ run_id: "r1", state: "running", statements: [] }), sql_run: () => PAGE }));
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-privilege-chips");
    await typeAndRun("select 1");
    await userEvent.dblClick(await screen.findByText("a@x"));
    expect(screen.queryByLabelText("Edit email")).toBeNull();
  });

  it("says so when the session ends underneath it", async () => {
    const onStatus = vi.fn();
    setup(
      base({
        sql_execute: () => ({ run_id: "r1", state: "running", statements: [] }),
        sql_run: () => {
          throw new Error("plugin dbms-management returned status 4: session_on_other_node: served by another instance");
        },
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" onStatusChange={onStatus} />);
    await screen.findByTestId("sql-privilege-chips");
    await typeAndRun("select 1");
    expect(await screen.findByText(/This SQL session has ended/)).toHaveTextContent("another vault node");
    expect(onStatus).toHaveBeenLastCalledWith("closed");
    expect(screen.getByRole("button", { name: "Run (statement at the cursor)" })).toBeDisabled();
  });

  it("shows the transaction badge and the commit controls in manual mode", async () => {
    let open = false;
    setup(
      base({
        sql_session_status: () =>
          status({ transaction: { open, failed: false, statements: open ? 3 : 0, open_secs: open ? 42 : null } }),
        sql_execute: (r) => {
          if (r.sql === "BEGIN") open = true;
          return { run_id: "r1", state: "running", statements: [] };
        },
        sql_run: () => ({ ...PAGE, columns: [], rows: [] }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-privilege-chips");
    await userEvent.selectOptions(screen.getByLabelText("Commit mode"), "manual");
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("sql_execute", { request: { token: TOKEN, sql: "BEGIN" } }));
    expect(await screen.findByTestId("sql-tx-badge")).toHaveTextContent("transaction open · 3 statements · 42 s");
    expect(screen.getByRole("button", { name: "COMMIT" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "ROLLBACK" })).toBeInTheDocument();
  });
});
