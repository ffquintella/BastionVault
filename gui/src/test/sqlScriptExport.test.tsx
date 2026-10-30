/**
 * T126 in the SQL workspace (features/sql-browser.md §8): scripts with their
 * confirmation and all-or-nothing refusal, exports the host writes to a file
 * (the webview never names a path or receives the data), `.sql` file load,
 * and the per-action step-up whose ticket only the host holds.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SqlWorkspace from "../components/sql/SqlWorkspace";
import type { SqlSessionStatus } from "../lib/api";
import { exportSummary, exportTableSql, refusals, stepUpActions } from "../lib/sqlWorkspace";
import { DEFAULT_STEP_UP, newSqlProfile } from "../lib/sqlProfile";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const TOKEN = "sess_0123456789abcdef0123456789abcdef";
const ALL = ["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_drop", "sql_export", "sql_script"];

function status(over: Partial<SqlSessionStatus> = {}): SqlSessionStatus {
  return {
    resource: "netrisk-db",
    profile: "rw",
    catalog: "app",
    engine: "postgresql",
    server_version: "16.15",
    enforcement: "database-first",
    db_enforced: true,
    read_only: false,
    database_read_only: false,
    privileges: ALL,
    ceiling: ALL,
    vault_only: [],
    transport: "direct",
    tls_mode: "verify-full",
    transaction: { open: false, failed: false, statements: 0, open_secs: null },
    active_run: null,
    idle_secs: 0,
    age_secs: 1,
    rows_read: 0,
    closed: null,
    taint: null,
    step_up: ["sql_drop", "sql_export"],
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

function base(over: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    sql_session_status: () => status(),
    sql_privileges: () => ({ resource: "netrisk-db", server: ALL, resource_wide: ALL }),
    sql_objects: (r) =>
      r.schema ? { catalog: "app", schema: "public", objects: [{ name: "t", kind: "table" }], truncated: false } : { catalog: "app", keys: ["public"] },
    ...over,
  };
}

const DONE_PAGE = {
  run_id: "r1",
  state: "done",
  statement_index: null,
  columns: [],
  rows: [],
  truncated_cells: [],
  has_more: false,
  rows_read: 0,
  row_budget_exhausted: false,
  messages: [
    { index: 0, kind: "Insert", outcome: "ok", rows_affected: 1, rows_returned: 0, duration_ms: 2, truncated: false, error: null },
    { index: 1, kind: "Update", outcome: "ok", rows_affected: 1, rows_returned: 0, duration_ms: 2, truncated: false, error: null },
  ],
  elapsed_ms: 5,
  script: { statements: 2, completed: 2, on_error: "stop", transaction: "single", tx_outcome: "committed" },
};

const calls = (cmd: string) => mockInvoke.mock.calls.filter((c) => c[0] === cmd).map((c) => (c[1] as { request: Record<string, unknown> }).request);

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("helpers", () => {
  it("composes Export table, step-up actions and the export summary", () => {
    expect(exportTableSql("public", 'we"ird')).toBe('SELECT * FROM "public"."we""ird"');
    expect(stepUpActions("sql_drop,sql_script")).toEqual(["sql_drop", "sql_script"]);
    expect(stepUpActions(undefined)).toEqual([]);
    const s = exportSummary({ state: "limit_reached", rows: 10, bytes: 2048, sha256: "ab".repeat(32), file: "x.csv", limit: "row_limit" });
    expect(s).toMatch(/Exported 10 rows \(2048 bytes\) to x\.csv/);
    expect(s).toMatch(/row limit: the file is incomplete/);
    const lines = refusals([], [{ capability: "sql_script", target: "server", allowed: false }]);
    expect(lines).toEqual(["needs `sql_script` on `the server` for the script"]);
  });

  it("starts a new profile on the suggested step-up list", () => {
    expect(DEFAULT_STEP_UP).toEqual(["sql_drop", "sql_admin", "sql_export", "sql_script"]);
    expect(newSqlProfile().stepUp).toEqual(DEFAULT_STEP_UP);
  });
});

describe("scripts", () => {
  it("confirms, then runs the editor as one script with its options", async () => {
    setup(base({ sql_script: () => ({ run_id: "r1", state: "running", statements: [], warnings: [] }), sql_run: () => DONE_PAGE }));
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    fireEvent.change(screen.getByLabelText("SQL editor"), {
      target: { value: "INSERT INTO t VALUES (1);\nUPDATE t SET a = 2 WHERE id = 1;" },
    });
    await userEvent.click(screen.getByLabelText("One transaction"));
    await userEvent.click(screen.getByRole("button", { name: "Run the editor as a script" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Run 2 statements as a script?" });
    expect(within(dialog).getByText(/one refusal runs nothing/)).toBeInTheDocument();
    expect(calls("sql_script")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "Run the script" }));
    await waitFor(() => expect(calls("sql_script")).toHaveLength(1));
    expect(calls("sql_script")[0]).toEqual({
      token: TOKEN,
      sql: "INSERT INTO t VALUES (1);\nUPDATE t SET a = 2 WHERE id = 1;",
      on_error: "stop",
      transaction: "single",
    });
    await waitFor(() => expect(calls("sql_run")).toHaveLength(1));
  });

  it("shows a refused script as refused, naming the statement, with nothing run", async () => {
    setup(
      base({
        sql_script: () => ({
          state: "refused",
          message: "statement 2 needs `sql_drop` on `app.public.t`",
          refused_statement: 1,
          statements: [
            { index: 0, kinds: ["Select"], unclassified: false, required: [], verdict: "allowed" },
            {
              index: 1,
              kinds: ["Drop"],
              unclassified: false,
              required: [{ capability: "sql_drop", target: { catalog: "app", schema: "public", object: "t" }, allowed: false }],
              verdict: "refused",
            },
          ],
          request: [{ capability: "sql_script", target: "server", allowed: true }],
        }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    fireEvent.change(screen.getByLabelText("SQL editor"), { target: { value: "SELECT 1; DROP TABLE public.t" } });
    await userEvent.click(screen.getByRole("button", { name: "Run the editor as a script" }));
    await userEvent.click(await screen.findByRole("button", { name: "Run the script" }));
    const refusal = await screen.findByTestId("sql-refusal");
    expect(refusal).toHaveTextContent("statement 2 needs `sql_drop`");
    expect(refusal).toHaveTextContent("nothing ran");
    expect(calls("sql_run")).toHaveLength(0);
  });

  it("loads a .sql file into a new tab without running it", async () => {
    setup(base());
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    const file = new File(["SELECT 42;"], "report.sql", { type: "text/plain" });
    await userEvent.upload(screen.getByLabelText("SQL file"), file);
    await waitFor(() => expect(screen.getByRole("tab", { name: "report.sql" })).toBeInTheDocument());
    expect(screen.getByLabelText("SQL editor")).toHaveValue("SELECT 42;");
    expect(calls("sql_execute")).toHaveLength(0);
    expect(calls("sql_script")).toHaveLength(0);
  });
});

describe("per-action step-up", () => {
  it("asks for a factor for exactly the action, then retries; the ticket never reaches the page", async () => {
    let executes = 0;
    setup(
      base({
        sql_execute: () => {
          executes += 1;
          return executes === 1
            ? { state: "step_up_required", action: "sql_drop", statements: [] }
            : { run_id: "r1", state: "running", statements: [] };
        },
        sql_run: () => ({ ...DONE_PAGE, script: undefined }),
        sql_step_up_begin: () => ({ required: true, methods: ["totp"], fido2: null }),
        sql_step_up_verify: () => ({ action: "sql_drop", method: "totp", expires_at: "2026-10-30T12:00:00Z" }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    fireEvent.change(screen.getByLabelText("SQL editor"), { target: { value: "DROP TABLE public.old" } });
    await userEvent.click(screen.getByRole("button", { name: "Run (statement at the cursor)" }));
    // DROP asks for the UX confirmation first.
    await userEvent.click(await screen.findByRole("button", { name: "Run it" }));
    const dialog = await screen.findByRole("dialog", { name: "Step-up required" });
    expect(within(dialog).getByText("sql_drop")).toBeInTheDocument();
    await waitFor(() => expect(calls("sql_step_up_begin")).toEqual([{ token: TOKEN, action: "sql_drop" }]));
    await userEvent.type(await within(dialog).findByLabelText("Authenticator code"), "123456");
    await userEvent.click(within(dialog).getByRole("button", { name: "Verify and retry" }));
    await waitFor(() => expect(calls("sql_execute")).toHaveLength(2));
    expect(calls("sql_step_up_verify")[0]).toEqual({ token: TOKEN, action: "sql_drop", method: "totp", code: "123456" });
    for (const r of calls("sql_execute")) expect(r).not.toHaveProperty("step_up_ticket");
    expect(screen.queryByRole("dialog", { name: "Step-up required" })).toBeNull();
  });

  it("runs nothing when the step-up is cancelled", async () => {
    setup(
      base({
        sql_execute: () => ({ state: "step_up_required", action: "sql_drop", statements: [] }),
        sql_step_up_begin: () => ({ required: true, methods: ["totp"], fido2: null }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    fireEvent.change(screen.getByLabelText("SQL editor"), { target: { value: "DROP TABLE public.old" } });
    await userEvent.click(screen.getByRole("button", { name: "Run (statement at the cursor)" }));
    await userEvent.click(await screen.findByRole("button", { name: "Run it" }));
    const dialog = await screen.findByRole("dialog", { name: "Step-up required" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Step-up required" })).toBeNull());
    expect(calls("sql_execute")).toHaveLength(1);
    expect(calls("sql_step_up_verify")).toHaveLength(0);
  });
});

describe("exports", () => {
  it("exports a table from the tree: SELECT * of the qualified name, written by the host", async () => {
    setup(
      base({
        sql_export_to_file: () => ({
          state: "done",
          rows: 2,
          bytes: 40,
          sha256: "cd".repeat(32),
          file: "netrisk-db-export.sql",
          limit: null,
          reply: null,
        }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await userEvent.click(await screen.findByRole("button", { name: "public" }));
    await userEvent.click(await screen.findByRole("button", { name: "Export public.t" }));
    const dialog = await screen.findByRole("dialog", { name: "Export" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Format"), "sql-insert");
    expect(within(dialog).getByLabelText("Target table")).toHaveValue("t");
    await userEvent.click(within(dialog).getByRole("button", { name: "Export" }));
    await waitFor(() => expect(calls("sql_export_to_file")).toHaveLength(1));
    const req = calls("sql_export_to_file")[0];
    expect(req).toEqual({
      token: TOKEN,
      sql: 'SELECT * FROM "public"."t"',
      format: "sql-insert",
      table: { schema: "public", name: "t" },
    });
    expect(Object.keys(req)).not.toContain("path");
    expect(await screen.findByText(/Exported 2 rows \(40 bytes\) to netrisk-db-export\.sql/)).toBeInTheDocument();
  });

  it("steps up for sql_export, then exports the statement at the cursor with the formula guard off on request", async () => {
    let n = 0;
    setup(
      base({
        sql_export_to_file: () => {
          n += 1;
          return n === 1
            ? { state: "step_up_required", rows: 0, bytes: 0, sha256: null, file: null, limit: null, reply: { state: "step_up_required", action: "sql_export", statements: [] } }
            : { state: "done", rows: 1, bytes: 9, sha256: "ef".repeat(32), file: "x.csv", limit: null, reply: null };
        },
        sql_step_up_begin: () => ({ required: true, methods: ["totp"], fido2: null }),
        sql_step_up_verify: () => ({ action: "sql_export", method: "totp", expires_at: "" }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await screen.findByTestId("sql-step-up");
    fireEvent.change(screen.getByLabelText("SQL editor"), { target: { value: "SELECT 1;" } });
    await userEvent.click(screen.getByRole("button", { name: /Export the statement at the cursor/ }));
    const dialog = await screen.findByRole("dialog", { name: "Export" });
    await userEvent.click(within(dialog).getByLabelText("Formula guard"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Export" }));
    const stepUp = await screen.findByRole("dialog", { name: "Step-up required" });
    await userEvent.type(await within(stepUp).findByLabelText("Authenticator code"), "654321");
    await userEvent.click(within(stepUp).getByRole("button", { name: "Verify and retry" }));
    await waitFor(() => expect(calls("sql_export_to_file")).toHaveLength(2));
    expect(calls("sql_export_to_file")[1]).toEqual({ token: TOKEN, sql: "SELECT 1", format: "csv", formula_guard: false });
    expect(await screen.findByText(/Exported 1 row \(9 bytes\) to x\.csv/)).toBeInTheDocument();
  });

  it("disables export and script for a caller without the grants (a convenience)", async () => {
    setup(
      base({
        sql_session_status: () => status({ privileges: ["sql_select"], step_up: [] }),
        sql_privileges: () => ({ resource: "netrisk-db", server: ["sql_select"], resource_wide: ["sql_select"] }),
      }),
    );
    render(<SqlWorkspace token={TOKEN} label="sql" />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Your grant lacks sql_export" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Your grant lacks sql_script" })).toBeDisabled();
  });
});
