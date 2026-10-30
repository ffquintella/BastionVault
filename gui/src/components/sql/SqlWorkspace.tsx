import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Play, Square, TextSelect, Wand2, ListTree, Plus, X, ScrollText, FileUp, Download } from "lucide-react";

import {
  sqlCancel,
  sqlDescribe,
  sqlExecute,
  sqlExportCancel,
  sqlExportToFile,
  sqlHistory,
  sqlPrivileges,
  sqlRows,
  sqlRun,
  sqlScript,
  sqlSessionStatus,
  type SqlColumn,
  type SqlDescribe,
  type SqlExportRequest,
  type SqlJournalRecord,
  type SqlRowEdit,
  type SqlSessionStatus,
  type SqlStatementMessage,
} from "../../lib/api";
import {
  DANGER_TEXT,
  buildDelete,
  buildInsert,
  buildUpdate,
  dangerousStatements,
  describeSqlError,
  editCapabilities,
  explainOf,
  exportSummary,
  exportTableSql,
  formatSql,
  gridEditBlocker,
  isSessionGone,
  refusals,
  selectAllFrom,
  splitStatements,
  statementAtCursor,
  type Danger,
  type EditTarget,
  beginStatement,
  manualCommitUnavailable,
} from "../../lib/sqlWorkspace";
import type { SessionPaneStatus } from "../session/SessionPaneHeader";
import { SqlConfirmDialog } from "./SqlDialog";
import { SqlExportDialog } from "./SqlExportDialog";
import { SqlInfoPanel } from "./SqlInfoPanel";
import { SqlStepUpDialog } from "./SqlStepUpDialog";
import { SqlObjectTree } from "./SqlObjectTree";
import { SqlResultGrid, type GridEditing, type RowOutcome } from "./SqlResultGrid";

/** How often the session status (timers, transaction badge) is re-read. */
export const STATUS_REFRESH_MS = 20_000;
const POLL_IDLE_MS = 200;
const MAX_RESULT_TABS = 12;
/** Largest `.sql` file loaded into an editor tab (the script limit). */
export const MAX_SQL_FILE_BYTES = 4 * 1024 * 1024;

interface EditorTab {
  id: string;
  title: string;
  text: string;
}

interface ResultTab {
  id: string;
  title: string;
  state: "running" | "done" | "failed" | "cancelled" | "refused" | "error";
  runId: string | null;
  columns: SqlColumn[];
  rows: unknown[][];
  truncated: Set<string>;
  messages: SqlStatementMessage[];
  refusal: { message: string; lines: string[] } | null;
  error: string | null;
  elapsedMs: number;
  budgetExhausted: boolean;
  /** The table this result was opened from: the grid may edit it. */
  target: SqlDescribe | null;
  /** The caller's capabilities on `target` (display only); null = unknown. */
  targetCaps: string[] | null;
  describe?: SqlDescribe;
}

interface LogLine {
  id: number;
  at: number;
  kind: "info" | "error" | "refused";
  text: string;
}

type Bottom = "results" | "messages" | "history";

let seq = 0;
const nextId = (p: string) => `${p}${++seq}`;
const preview = (s: string) => (s.length > 60 ? `${s.slice(0, 57)}…` : s).replace(/\s+/g, " ");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function messageLine(m: SqlStatementMessage): string {
  const rows = m.rows_affected ?? m.rows_returned;
  const base = `${m.kind} · ${m.outcome} · ${rows} row${rows === 1 ? "" : "s"} · ${m.duration_ms} ms`;
  const cut = m.truncated ? " · stopped at the grid limit" : "";
  return m.error ? `${base} · ${m.error.sqlstate ?? ""} ${m.error.message}`.trim() : base + cut;
}

/**
 * The SQL workspace (features/sql-browser.md §10): object tree, editor
 * tabs, results, messages and history, and the info panel. Rendered in a
 * `sql-<token>` window or as a Session Workspace pane. It holds only the
 * local session token; results live in memory and go with the tab.
 */
export default function SqlWorkspace({
  token,
  label,
  onStatusChange,
  headerExtra,
  onDisconnect,
}: {
  token: string;
  label: string;
  onStatusChange?: (s: SessionPaneStatus) => void;
  headerExtra?: ReactNode;
  /** Own window only: a Disconnect button that closes the session. */
  onDisconnect?: () => void;
}) {
  const [status, setStatus] = useState<SqlSessionStatus | null>(null);
  const [statusAt, setStatusAt] = useState(() => Date.now());
  const [effective, setEffective] = useState<string[] | null>(null);
  const [gone, setGone] = useState<string | null>(null);
  const [editors, setEditors] = useState<EditorTab[]>(() => [{ id: nextId("e"), title: "Query 1", text: "" }]);
  const [activeEditor, setActiveEditor] = useState(() => editors[0]?.id ?? "");
  const [results, setResults] = useState<ResultTab[]>([]);
  const [activeResult, setActiveResult] = useState<string | null>(null);
  const [bottom, setBottom] = useState<Bottom>("results");
  const [log, setLog] = useState<LogLine[]>([]);
  const [history, setHistory] = useState<SqlJournalRecord | null>(null);
  const [historyError, setHistoryError] = useState("");
  const [running, setRunning] = useState<{ resultId: string; runId: string | null } | null>(null);
  const [confirm, setConfirm] = useState<{ dangers: Danger[]; run: () => void; script?: number } | null>(null);
  const [manualTx, setManualTx] = useState(false);
  const [stepUp, setStepUp] = useState<{ action: string; resolve: (ok: boolean) => void } | null>(null);
  const [exportReq, setExportReq] = useState<{ sql: string; table?: { schema: string; name: string } } | null>(null);
  const [exporting, setExporting] = useState(false);
  const [scriptOnError, setScriptOnError] = useState<"stop" | "continue">("stop");
  const [scriptSingle, setScriptSingle] = useState(false);
  const textRef = useRef<HTMLTextAreaElement | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const aliveRef = useRef(true);
  const runningRef = useRef(running);
  runningRef.current = running;

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  const addLog = useCallback((kind: LogLine["kind"], text: string) => {
    setLog((l) => [...l.slice(-499), { id: ++seq, at: Date.now(), kind, text }]);
  }, []);

  // Once the session is gone it stays gone: a late status read must not
  // report it open again.
  const goneRef = useRef(false);
  const markGone = useCallback(
    (e: unknown) => {
      goneRef.current = true;
      setGone(describeSqlError(e));
      onStatusChange?.("closed");
    },
    [onStatusChange],
  );

  const refreshStatus = useCallback(async () => {
    if (goneRef.current) return;
    try {
      const s = await sqlSessionStatus(token);
      if (!aliveRef.current || goneRef.current) return;
      setStatus(s);
      setStatusAt(Date.now());
      if (s.closed) markGone(`session_closed: ${s.closed}`);
      else onStatusChange?.("open");
    } catch (e) {
      if (!aliveRef.current) return;
      if (isSessionGone(e)) markGone(e);
      else addLog("error", `Session status: ${describeSqlError(e)}`);
    }
  }, [token, markGone, onStatusChange, addLog]);

  useEffect(() => {
    if (!token) return;
    onStatusChange?.("connecting");
    void refreshStatus();
    sqlPrivileges(token).then(
      (p) => aliveRef.current && setEffective([...new Set([...(p.server ?? []), ...(p.resource_wide ?? [])])]),
      () => aliveRef.current && setEffective(null),
    );
    const t = setInterval(() => void refreshStatus(), STATUS_REFRESH_MS);
    return () => clearInterval(t);
    // onStatusChange is a fresh closure per render; the poll must not restart.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  /** Per-action step-up (§8.3): ask, and resolve true once the host holds
   *  a ticket for the retry. */
  const askStepUp = useCallback(
    (action: string) =>
      new Promise<boolean>((resolve) => {
        addLog("info", `Step-up required for ${action}.`);
        setStepUp({ action, resolve });
      }),
    [addLog],
  );

  const updateResult = useCallback((id: string, f: (r: ResultTab) => ResultTab) => {
    setResults((rs) => rs.map((r) => (r.id === id ? f(r) : r)));
  }, []);

  const addResult = useCallback((tab: ResultTab) => {
    setResults((rs) => [...rs.slice(-(MAX_RESULT_TABS - 1)), tab]);
    setActiveResult(tab.id);
    setBottom("results");
  }, []);

  const poll = useCallback(
    async (resultId: string, runId: string) => {
      for (;;) {
        if (!aliveRef.current) return;
        let page;
        try {
          page = await sqlRun(token, runId);
        } catch (e) {
          const text = describeSqlError(e);
          updateResult(resultId, (r) => ({ ...r, state: "error", error: text }));
          addLog("error", text);
          if (isSessionGone(e)) markGone(e);
          break;
        }
        const p = page;
        updateResult(resultId, (r) => {
          const truncated = new Set(r.truncated);
          for (const c of p.truncated_cells) truncated.add(`${r.rows.length + c.row}:${c.column}`);
          return {
            ...r,
            state: p.state,
            columns: p.columns.length > 0 ? p.columns : r.columns,
            rows: p.rows.length > 0 ? r.rows.concat(p.rows) : r.rows,
            truncated,
            messages: p.messages,
            elapsedMs: p.elapsed_ms,
            budgetExhausted: p.row_budget_exhausted,
          };
        });
        if (p.state !== "running" && !p.has_more) {
          for (const m of p.messages) addLog(m.error ? "error" : "info", messageLine(m));
          if (p.row_budget_exhausted) addLog("error", "The session's row budget is spent.");
          break;
        }
        if (p.rows.length === 0) await sleep(POLL_IDLE_MS);
      }
      setRunning(null);
      void refreshStatus();
    },
    [token, updateResult, addLog, markGone, refreshStatus],
  );

  const execute = useCallback(
    async (sql: string, opts: { target?: SqlDescribe | null; targetCaps?: string[] | null; confirmed?: boolean } = {}) => {
      const text = sql.trim();
      if (!text || runningRef.current || gone) return;
      if (!opts.confirmed) {
        const dangers = dangerousStatements(text);
        if (dangers.length > 0) {
          setConfirm({ dangers, run: () => void execute(sql, { ...opts, confirmed: true }) });
          return;
        }
      }
      const id = nextId("r");
      addResult({
        id,
        title: preview(text),
        state: "running",
        runId: null,
        columns: [],
        rows: [],
        truncated: new Set(),
        messages: [],
        refusal: null,
        error: null,
        elapsedMs: 0,
        budgetExhausted: false,
        target: opts.target ?? null,
        targetCaps: opts.targetCaps ?? null,
      });
      setRunning({ resultId: id, runId: null });
      addLog("info", `▶ ${preview(text)}`);
      let reply;
      try {
        reply = await sqlExecute(token, text);
      } catch (e) {
        const msg = describeSqlError(e);
        updateResult(id, (r) => ({ ...r, state: "error", error: msg }));
        addLog("error", msg);
        if (isSessionGone(e)) markGone(e);
        setRunning(null);
        return;
      }
      if (reply.state === "step_up_required" && reply.action) {
        const action = reply.action;
        updateResult(id, (r) => ({ ...r, state: "refused", refusal: { message: `needs a fresh MFA step-up for ${action}`, lines: [] } }));
        setRunning(null);
        if (await askStepUp(action)) await execute(sql, { ...opts, confirmed: true });
        return;
      }
      if (reply.state === "refused" || !reply.run_id) {
        const lines = refusals(reply.statements ?? []);
        const message = reply.message ?? "refused";
        updateResult(id, (r) => ({ ...r, state: "refused", refusal: { message, lines } }));
        addLog("refused", `Refused by the vault: ${message}`);
        setRunning(null);
        return;
      }
      const runId = reply.run_id;
      updateResult(id, (r) => ({ ...r, runId }));
      setRunning({ resultId: id, runId });
      await poll(id, runId);
    },
    [token, gone, addResult, addLog, updateResult, markGone, poll, askStepUp],
  );

  /** A script (§8.2): always confirmed first; every statement is authorized
   *  before the first runs, and a refusal names the statement. */
  const runScript = useCallback(
    async (sql: string, confirmed = false) => {
      const text = sql.trim();
      if (!text || runningRef.current || gone) return;
      if (!confirmed) {
        const count = splitStatements(text).length;
        setConfirm({ dangers: dangerousStatements(text), script: count, run: () => void runScript(sql, true) });
        return;
      }
      const id = nextId("r");
      addResult({
        id,
        title: `Script: ${preview(text)}`,
        state: "running",
        runId: null,
        columns: [],
        rows: [],
        truncated: new Set(),
        messages: [],
        refusal: null,
        error: null,
        elapsedMs: 0,
        budgetExhausted: false,
        target: null,
        targetCaps: null,
      });
      setRunning({ resultId: id, runId: null });
      addLog("info", `▶ script (${scriptOnError === "stop" ? "stop on error" : "continue on error"}${scriptSingle ? ", one transaction" : ""})`);
      let reply;
      try {
        reply = await sqlScript(token, text, { on_error: scriptOnError, transaction: scriptSingle ? "single" : "none" });
      } catch (e) {
        const msg = describeSqlError(e);
        updateResult(id, (r) => ({ ...r, state: "error", error: msg }));
        addLog("error", msg);
        if (isSessionGone(e)) markGone(e);
        setRunning(null);
        return;
      }
      if (reply.state === "step_up_required" && reply.action) {
        const action = reply.action;
        updateResult(id, (r) => ({ ...r, state: "refused", refusal: { message: `needs a fresh MFA step-up for ${action}`, lines: [] } }));
        setRunning(null);
        if (await askStepUp(action)) await runScript(sql, true);
        return;
      }
      if (reply.state === "refused" || !reply.run_id) {
        const lines = refusals(reply.statements ?? [], reply.request ?? []);
        const message = reply.message ?? "refused";
        updateResult(id, (r) => ({ ...r, state: "refused", refusal: { message: `${message} — nothing ran`, lines } }));
        addLog("refused", `Script refused by the vault: ${message}; nothing ran.`);
        setRunning(null);
        return;
      }
      for (const w of reply.warnings ?? []) addLog("error", w);
      const runId = reply.run_id;
      updateResult(id, (r) => ({ ...r, runId }));
      setRunning({ resultId: id, runId });
      await poll(id, runId);
    },
    [token, gone, addResult, addLog, updateResult, markGone, poll, askStepUp, scriptOnError, scriptSingle],
  );

  /** An export (§8.1): the host asks where to save and writes the file. */
  const runExport = useCallback(
    async (req: SqlExportRequest) => {
      if (runningRef.current || gone) return;
      setExporting(true);
      addLog("info", `⇩ export ${req.format}: ${preview(req.sql)}`);
      try {
        let out = await sqlExportToFile(token, req);
        if (out.state === "step_up_required" && out.reply?.action) {
          if (!(await askStepUp(out.reply.action))) {
            addLog("info", "Export not started: the step-up was cancelled.");
            return;
          }
          out = await sqlExportToFile(token, req);
        }
        if (out.state === "refused") {
          const message = out.reply?.message ?? "refused";
          addLog("refused", `Export refused by the vault: ${message}`);
          for (const l of refusals(out.reply?.statements ?? [])) addLog("refused", l);
        } else if (out.state === "cancelled") {
          addLog("info", "Export cancelled; no file was kept.");
        } else {
          addLog(out.state === "limit_reached" ? "error" : "info", exportSummary(out));
        }
      } catch (e) {
        addLog("error", `Export: ${describeSqlError(e)}`);
        if (isSessionGone(e)) markGone(e);
      } finally {
        setExporting(false);
        setBottom("messages");
        void refreshStatus();
      }
    },
    [token, gone, addLog, askStepUp, markGone, refreshStatus],
  );

  const editor = editors.find((e) => e.id === activeEditor) ?? editors[0];
  const setEditorText = (text: string) =>
    setEditors((es) => es.map((e) => (e.id === editor.id ? { ...e, text } : e)));

  const currentStatement = () => statementAtCursor(editor.text, textRef.current?.selectionStart ?? editor.text.length);
  const selection = () => {
    const el = textRef.current;
    if (!el || el.selectionStart === el.selectionEnd) return "";
    return editor.text.slice(el.selectionStart, el.selectionEnd);
  };

  const stop = () => {
    const r = runningRef.current;
    if (!r?.runId) return;
    sqlCancel(token, r.runId).then(
      () => addLog("info", "Cancel requested."),
      (e: unknown) => addLog("error", describeSqlError(e)),
    );
  };

  const openTable = async (schema: string, object: string) => {
    const text = selectAllFrom(schema, object);
    const id = nextId("e");
    setEditors((es) => [...es, { id, title: `${schema}.${object}`, text }]);
    setActiveEditor(id);
    let target: SqlDescribe | null = null;
    let caps: string[] | null = null;
    try {
      target = await sqlDescribe(token, schema, object);
    } catch (e) {
      addLog("error", `Describe ${schema}.${object}: ${describeSqlError(e)}`);
    }
    try {
      const p = await sqlPrivileges(token, [{ schema, object }]);
      caps = p.objects?.[0]?.capabilities ?? null;
    } catch {
      caps = null;
    }
    await execute(text, { target, targetCaps: caps });
  };

  const loadFile = (file: File) => {
    if (file.size > MAX_SQL_FILE_BYTES) {
      addLog("error", `${file.name} is larger than 4 MiB, the script limit.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : "";
      const id = nextId("e");
      setEditors((es) => [...es, { id, title: file.name, text }]);
      setActiveEditor(id);
      addLog("info", `Loaded ${file.name}; nothing runs until you run it.`);
    };
    reader.onerror = () => addLog("error", `Could not read ${file.name}.`);
    reader.readAsText(file);
  };

  const describe = async (schema: string, object: string) => {
    try {
      const d = await sqlDescribe(token, schema, object);
      addResult({
        id: nextId("r"),
        title: `${schema}.${object}`,
        state: "done",
        runId: null,
        columns: [],
        rows: [],
        truncated: new Set(),
        messages: [],
        refusal: null,
        error: null,
        elapsedMs: 0,
        budgetExhausted: false,
        target: null,
        targetCaps: null,
        describe: d,
      });
    } catch (e) {
      addLog("error", `Describe ${schema}.${object}: ${describeSqlError(e)}`);
    }
  };

  const loadHistory = useCallback(() => {
    setHistoryError("");
    sqlHistory(token).then(
      (h) => aliveRef.current && setHistory(h),
      (e: unknown) => aliveRef.current && setHistoryError(describeSqlError(e)),
    );
  }, [token]);

  useEffect(() => {
    if (bottom === "history") loadHistory();
  }, [bottom, loadHistory]);

  const setTxMode = (manual: boolean) => {
    if (manual === manualTx) return;
    if (!manual && status?.transaction.open) {
      addLog("error", "Commit or roll back the open transaction before switching to auto-commit.");
      return;
    }
    setManualTx(manual);
    if (manual) void execute(beginStatement(status?.engine));
  };

  const caps = effective ?? status?.privileges ?? null;
  const has = (c: string, set: string[] | null = caps) => set === null || set.includes(c);
  const live = !!status && !gone;
  const isRunning = running !== null;

  const editingFor = (r: ResultTab): GridEditing | null => {
    if (!r.target || r.columns.length === 0) return null;
    const blocker = status?.read_only
      ? "this session is read-only (the database refuses writes)"
      : gridEditBlocker(r.target, r.columns);
    const objectCaps = r.targetCaps ?? caps;
    const can = (op: "insert" | "update" | "delete") => !gone && editCapabilities(op).every((c) => has(c, objectCaps));
    const target: EditTarget = { schema: r.target.schema, name: r.target.name, key: r.target.edit.key ?? [] };
    const send = async (edit: SqlRowEdit, ok: string, after?: () => void): Promise<RowOutcome> => {
      try {
        const reply = await sqlRows(token, edit);
        if (reply.state === "step_up_required") {
          if (await askStepUp(reply.action)) return send(edit, ok, after);
          return { kind: "refused", text: `Needs a fresh MFA step-up for ${reply.action}` };
        }
        if (reply.state === "done") {
          after?.();
          addLog("info", `${edit.op} on ${target.schema}.${target.name}: 1 row`);
          return { kind: "saved", text: ok };
        }
        if (reply.state === "conflict") {
          addLog("error", `Conflict on ${target.schema}.${target.name}: ${reply.message}`);
          return { kind: "conflict", text: `Conflict: ${reply.message}. Re-run to see the current row.` };
        }
        if (reply.state === "refused") {
          addLog("refused", `Refused by the vault: ${reply.message}`);
          return { kind: "refused", text: `Refused: ${reply.message}` };
        }
        const text = `${reply.error.sqlstate ?? ""} ${reply.error.message}`.trim();
        addLog("error", text);
        return { kind: "error", text };
      } catch (e) {
        const text = describeSqlError(e);
        addLog("error", text);
        if (isSessionGone(e)) markGone(e);
        return { kind: "error", text };
      }
    };
    return {
      blocker,
      canUpdate: can("update"),
      canInsert: can("insert"),
      canDelete: can("delete"),
      onSave: async (row, changes) => {
        let edit;
        try {
          edit = buildUpdate(target, r.columns, r.rows[row], changes);
        } catch (e) {
          return { kind: "error", text: describeSqlError(e) };
        }
        return send(edit, "Saved", () =>
          updateResult(r.id, (cur) => {
            const rows = cur.rows.slice();
            const next = rows[row].slice();
            for (const [k, v] of Object.entries(changes)) next[cur.columns.findIndex((c) => c.name === k)] = v;
            rows[row] = next;
            return { ...cur, rows };
          }),
        );
      },
      onDelete: async (row) => {
        let edit;
        try {
          edit = buildDelete(target, r.columns, r.rows[row]);
        } catch (e) {
          return { kind: "error", text: describeSqlError(e) };
        }
        return send(edit, "Deleted");
      },
      onInsert: async (values) => {
        let edit;
        try {
          edit = buildInsert(target, values);
        } catch (e) {
          return { kind: "error", text: describeSqlError(e) };
        }
        return send(edit, "Inserted 1 row; run the query again to see it");
      },
    };
  };

  const result = results.find((r) => r.id === activeResult) ?? null;

  return (
    <div className="flex h-full min-h-0 min-w-0 flex-col bg-[var(--color-bg)] text-[var(--color-text)]" data-testid="sql-workspace">
      <div role="toolbar" aria-label="SQL toolbar" className="flex min-w-0 flex-wrap items-center gap-1 border-b border-[var(--color-border)] px-2 py-1 text-xs">
        <span className="min-w-0 max-w-[30%] truncate font-semibold" title={label}>
          {label}
        </span>
        <ToolButton title="Run (statement at the cursor)" disabled={!live || isRunning} onClick={() => void execute(currentStatement())}>
          <Play size={13} /> Run
        </ToolButton>
        <ToolButton title="Run selection" disabled={!live || isRunning} onClick={() => void execute(selection())}>
          <TextSelect size={13} /> Run selection
        </ToolButton>
        <ToolButton title="Stop the running statement" disabled={!running?.runId} onClick={stop}>
          <Square size={13} /> Stop
        </ToolButton>
        <ToolButton
          title={has("sql_select") ? "Explain (plan only)" : "Your grant lacks sql_select"}
          disabled={!live || isRunning || !has("sql_select")}
          onClick={() => void execute(explainOf(currentStatement()))}
        >
          <ListTree size={13} /> Explain
        </ToolButton>
        <ToolButton title="Format" disabled={!editor.text.trim()} onClick={() => setEditorText(formatSql(editor.text))}>
          <Wand2 size={13} /> Format
        </ToolButton>
        <span className="mx-1 h-4 w-px bg-[var(--color-border)]" aria-hidden />
        <ToolButton
          title={has("sql_script") ? "Run the editor as a script" : "Your grant lacks sql_script"}
          disabled={!live || isRunning || exporting || !editor.text.trim() || !has("sql_script")}
          onClick={() => void runScript(editor.text)}
        >
          <ScrollText size={13} /> Run script
        </ToolButton>
        <label className="flex items-center gap-1 text-[var(--color-text-muted)]">
          <span>On error</span>
          <select
            aria-label="On error"
            value={scriptOnError}
            disabled={scriptSingle}
            onChange={(e) => setScriptOnError(e.target.value as "stop" | "continue")}
            className="rounded border border-[var(--color-border)] bg-transparent px-1 text-[var(--color-text)]"
          >
            <option value="stop">Stop</option>
            <option value="continue">Continue</option>
          </select>
        </label>
        <label className="flex items-center gap-1 text-[var(--color-text-muted)]" title="Wrap the script in one transaction: any failure rolls all of it back">
          <input
            type="checkbox"
            aria-label="One transaction"
            checked={scriptSingle}
            onChange={(e) => {
              setScriptSingle(e.target.checked);
              if (e.target.checked) setScriptOnError("stop");
            }}
          />
          <span>One transaction</span>
        </label>
        <ToolButton title="Load a .sql file into a new tab" disabled={!live} onClick={() => fileRef.current?.click()}>
          <FileUp size={13} /> Load .sql
        </ToolButton>
        <input
          ref={fileRef}
          type="file"
          accept=".sql,text/plain"
          aria-label="SQL file"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) loadFile(file);
            e.target.value = "";
          }}
        />
        {exporting ? (
          <ToolButton title="Cancel the export" onClick={() => void sqlExportCancel(token).catch(() => undefined)}>
            <Square size={13} /> Cancel export
          </ToolButton>
        ) : (
          <ToolButton
            title={has("sql_export") ? "Export the statement at the cursor (or the selection)" : "Your grant lacks sql_export"}
            disabled={!live || isRunning || !has("sql_export")}
            onClick={() => {
              const sql = (selection() || currentStatement()).trim().replace(/;\s*$/, "");
              if (sql) setExportReq({ sql });
            }}
          >
            <Download size={13} /> Export
          </ToolButton>
        )}
        <label className="ml-2 flex items-center gap-1 text-[var(--color-text-muted)]">
          <span>Commit</span>
          <select
            aria-label="Commit mode"
            value={manualTx ? "manual" : "auto"}
            disabled={!live || isRunning || manualCommitUnavailable(status?.engine, status?.read_only) !== null}
            title={manualCommitUnavailable(status?.engine, status?.read_only) ?? undefined}
            onChange={(e) => setTxMode(e.target.value === "manual")}
            className="rounded border border-[var(--color-border)] bg-transparent px-1 text-[var(--color-text)]"
          >
            <option value="auto">Auto-commit</option>
            <option value="manual">Manual</option>
          </select>
        </label>
        {(manualTx || status?.transaction.open) && (
          <>
            <ToolButton title="COMMIT" disabled={!live || isRunning} onClick={() => void execute("COMMIT")}>
              Commit
            </ToolButton>
            <ToolButton title="ROLLBACK" disabled={!live || isRunning} onClick={() => void execute("ROLLBACK")}>
              Rollback
            </ToolButton>
          </>
        )}
        {status?.transaction.open && (
          <span className="rounded bg-yellow-900/50 px-1.5 py-0.5 text-yellow-200" data-testid="sql-toolbar-tx">
            transaction open · {status.transaction.statements} statements
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          {onDisconnect && (
            <ToolButton title="Close the SQL session" disabled={!!gone} onClick={onDisconnect}>
              Disconnect
            </ToolButton>
          )}
          {headerExtra}
        </span>
      </div>
      {gone && (
        <div role="alert" className="border-b border-[var(--color-border)] bg-red-950/60 px-2 py-1 text-xs text-red-200">
          This SQL session has ended: {gone}
        </div>
      )}
      {status?.enforcement === "classifier-only" && (
        <div className="border-b border-[var(--color-border)] bg-yellow-950/50 px-2 py-1 text-xs text-yellow-200" data-testid="sql-classifier-only">
          SQL grants on this database are enforced by BastionVault only; the database login can do more.
        </div>
      )}
      <div className="flex min-h-0 flex-1">
        <div className="w-56 shrink-0 border-r border-[var(--color-border)]">
          <SqlObjectTree
            token={token}
            disabled={!live}
            onOpen={(s, o) => void openTable(s, o)}
            onDescribe={(s, o) => void describe(s, o)}
            onExport={has("sql_export") && !exporting ? (s, o) => setExportReq({ sql: exportTableSql(s, o), table: { schema: s, name: o } }) : undefined}
            onError={(m) => addLog("error", m)}
          />
        </div>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div role="tablist" aria-label="Editors" className="flex min-w-0 items-center gap-0.5 overflow-x-auto border-b border-[var(--color-border)] px-1 text-xs">
            {editors.map((e) => (
              <span key={e.id} className={`flex shrink-0 items-center gap-1 rounded-t px-2 py-0.5 ${e.id === editor.id ? "bg-[var(--color-surface)]" : ""}`}>
                <button type="button" role="tab" aria-selected={e.id === editor.id} onClick={() => setActiveEditor(e.id)} className="max-w-40 truncate">
                  {e.title}
                </button>
                {editors.length > 1 && (
                  <button
                    type="button"
                    aria-label={`Close ${e.title}`}
                    onClick={() => {
                      const rest = editors.filter((x) => x.id !== e.id);
                      setEditors(rest);
                      if (e.id === editor.id) setActiveEditor(rest[0].id);
                    }}
                  >
                    <X size={11} />
                  </button>
                )}
              </span>
            ))}
            <button
              type="button"
              aria-label="New editor tab"
              onClick={() => {
                const id = nextId("e");
                setEditors((es) => [...es, { id, title: `Query ${es.length + 1}`, text: "" }]);
                setActiveEditor(id);
              }}
              className="px-1"
            >
              <Plus size={12} />
            </button>
          </div>
          <textarea
            ref={textRef}
            aria-label="SQL editor"
            spellCheck={false}
            value={editor.text}
            onChange={(e) => setEditorText(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                e.preventDefault();
                const sel = selection();
                void execute(sel || currentStatement());
              }
            }}
            placeholder="SELECT … — ⌘↵ / Ctrl+Enter runs the statement at the cursor"
            className="h-[38%] min-h-24 w-full resize-y border-b border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs outline-none"
          />
          <div role="tablist" aria-label="Output" className="flex min-w-0 items-center gap-0.5 overflow-x-auto border-b border-[var(--color-border)] px-1 text-xs">
            {/* Messages and History first: result tabs can overflow the strip. */}
            <button type="button" role="tab" aria-selected={bottom === "messages"} onClick={() => setBottom("messages")} className={`shrink-0 rounded-t px-2 py-0.5 ${bottom === "messages" ? "bg-[var(--color-surface)]" : ""}`}>
              Messages
            </button>
            <button type="button" role="tab" aria-selected={bottom === "history"} onClick={() => setBottom("history")} className={`shrink-0 rounded-t px-2 py-0.5 ${bottom === "history" ? "bg-[var(--color-surface)]" : ""}`}>
              History
            </button>
            {results.map((r) => (
              <button
                key={r.id}
                type="button"
                role="tab"
                aria-selected={bottom === "results" && r.id === activeResult}
                onClick={() => {
                  setActiveResult(r.id);
                  setBottom("results");
                }}
                title={r.title}
                className={`max-w-48 shrink-0 truncate rounded-t px-2 py-0.5 ${bottom === "results" && r.id === activeResult ? "bg-[var(--color-surface)]" : ""} ${r.state === "refused" || r.state === "error" || r.state === "failed" ? "text-red-300" : ""}`}
              >
                {r.describe ? `⌘ ${r.title}` : r.title}
              </button>
            ))}
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            {bottom === "results" && result && <ResultView result={result} editing={editingFor(result)} />}
            {bottom === "results" && !result && <p className="p-2 text-xs text-[var(--color-text-muted)]">Run a statement to see its result here.</p>}
            {bottom === "messages" && (
              <ul aria-label="Messages" className="h-full overflow-auto p-2 font-mono text-[11px]">
                {log.length === 0 && <li className="text-[var(--color-text-muted)]">No messages yet.</li>}
                {log.map((l) => (
                  <li key={l.id} className={l.kind === "error" ? "text-red-400" : l.kind === "refused" ? "text-yellow-300" : ""}>
                    <span className="text-[var(--color-text-muted)]">{new Date(l.at).toLocaleTimeString()} </span>
                    {l.text}
                  </li>
                ))}
              </ul>
            )}
            {bottom === "history" && <HistoryView record={history} error={historyError} onReload={loadHistory} />}
          </div>
        </div>
        <div className="w-64 shrink-0 border-l border-[var(--color-border)]">
          <SqlInfoPanel status={status} effective={effective} readAt={statusAt} />
        </div>
      </div>
      {stepUp && (
        <SqlStepUpDialog
          token={token}
          action={stepUp.action}
          onDone={(ok) => {
            const resolve = stepUp.resolve;
            setStepUp(null);
            if (!ok) addLog("info", "Step-up cancelled; nothing ran.");
            resolve(ok);
          }}
        />
      )}
      {exportReq && (
        <SqlExportDialog
          sql={exportReq.sql}
          table={exportReq.table}
          onCancel={() => setExportReq(null)}
          onExport={(req) => {
            setExportReq(null);
            void runExport(req);
          }}
        />
      )}
      {confirm && (
        <SqlConfirmDialog
          title={confirm.script !== undefined ? `Run ${confirm.script} statements as a script?` : "Run this statement?"}
          confirm={confirm.script !== undefined ? "Run the script" : "Run it"}
          onCancel={() => setConfirm(null)}
          onConfirm={() => {
            const run = confirm.run;
            setConfirm(null);
            run();
          }}
        >
          {confirm.script !== undefined && (
            <p>
              Every statement is checked by the vault before the first one runs; one refusal runs nothing.{" "}
              {scriptSingle ? "They run in one transaction: any failure rolls all of them back." : `On error: ${scriptOnError}.`}
            </p>
          )}
          {confirm.dangers.map((d, i) => (
            <p key={i}>
              <code className="break-all text-[var(--color-text)]">{d.statement}</code> {DANGER_TEXT[d.kind]}.
            </p>
          ))}
          <p className="text-[11px]">This question is a convenience; the vault still decides whether it may run.</p>
        </SqlConfirmDialog>
      )}
    </div>
  );
}

function ToolButton(props: { onClick: () => void; disabled?: boolean; title: string; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title}
      aria-label={props.title}
      className="flex items-center gap-1 rounded px-2 py-0.5 hover:bg-[var(--color-surface-hover)] disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {props.children}
    </button>
  );
}

function ResultView({ result, editing }: { result: ResultTab; editing: GridEditing | null }) {
  if (result.describe) return <DescribeView d={result.describe} />;
  if (result.refusal) {
    return (
      <div role="alert" className="space-y-1 p-2 text-xs" data-testid="sql-refusal">
        <p className="font-semibold text-yellow-300">Refused by the vault: {result.refusal.message}</p>
        <ul className="list-disc pl-5">
          {result.refusal.lines.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>
      </div>
    );
  }
  if (result.error) {
    return (
      <p role="alert" className="p-2 text-xs text-red-400 break-words">
        {result.error}
      </p>
    );
  }
  const failed = result.messages.find((m) => m.error);
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex min-w-0 items-center gap-3 border-b border-[var(--color-border)] px-2 py-0.5 text-[11px] text-[var(--color-text-muted)]">
        <span>{result.state === "running" ? "Running…" : result.state}</span>
        <span>{result.rows.length} rows</span>
        <span>{result.elapsedMs} ms</span>
        {result.budgetExhausted && <span className="text-red-400">row budget spent</span>}
        {failed?.error && (
          <span className="min-w-0 truncate text-red-400" title={failed.error.message}>
            {failed.error.sqlstate} {failed.error.message}
          </span>
        )}
      </div>
      <div className="min-h-0 flex-1">
        <SqlResultGrid columns={result.columns} rows={result.rows} truncated={result.truncated} editing={editing} />
      </div>
    </div>
  );
}

function DescribeView({ d }: { d: SqlDescribe }) {
  return (
    <div className="h-full space-y-2 overflow-auto p-2 text-xs" data-testid="sql-describe">
      <p className="font-semibold">
        {d.schema}.{d.name} <span className="font-normal text-[var(--color-text-muted)]">{d.kind}</span>
      </p>
      <p className="text-[var(--color-text-muted)]">
        {d.edit.editable ? `Editable in the grid (key: ${(d.edit.key ?? []).join(", ")})` : `Read-only in the grid: ${d.edit.reason ?? ""}`}
      </p>
      {d.columns.length > 0 && (
        <table className="font-mono text-[11px]">
          <tbody>
            {d.columns.map((c, i) => (
              <tr key={i}>
                <td className="pr-3">{c.name}</td>
                <td className="pr-3 text-[var(--color-text-muted)]">{c.type}</td>
                <td className="pr-3">{c.not_null ? "NOT NULL" : ""}</td>
                <td className="text-[var(--color-text-muted)]">{c.default ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {[...d.constraints, ...d.indexes, ...d.triggers].map((x, i) => (
        <pre key={i} className="whitespace-pre-wrap break-all font-mono text-[11px]">
          {x.name}: {x.definition}
        </pre>
      ))}
      {[d.definition, ...d.routines.map((r) => r.definition)].filter(Boolean).map((def, i) => (
        <pre key={`def${i}`} className="whitespace-pre-wrap break-all rounded bg-[var(--color-surface)] p-2 font-mono text-[11px]">
          {def}
        </pre>
      ))}
    </div>
  );
}

function HistoryView({ record, error, onReload }: { record: SqlJournalRecord | null; error: string; onReload: () => void }) {
  return (
    <div className="h-full overflow-auto p-2 text-[11px]" aria-label="History">
      <div className="mb-1 flex items-center gap-2 text-[var(--color-text-muted)]">
        <span>This session&apos;s statements from the journal (text as the resource&apos;s journal setting keeps it).</span>
        <button type="button" onClick={onReload} className="underline">
          Reload
        </button>
      </div>
      {error && <p className="text-red-400">{error}</p>}
      {record && record.statements.length === 0 && <p className="text-[var(--color-text-muted)]">Nothing recorded yet.</p>}
      <ul className="space-y-0.5 font-mono">
        {record?.statements.map((s, i) => (
          <li key={i} className="flex min-w-0 gap-2">
            <span className="shrink-0 text-[var(--color-text-muted)]">{new Date(s.at_ms).toLocaleTimeString()}</span>
            <span className="shrink-0">{s.kinds.join(",")}</span>
            <span className={`shrink-0 ${s.outcome === "ok" ? "" : "text-yellow-300"}`}>{s.outcome}</span>
            <span className="min-w-0 truncate" title={s.text ?? s.object ?? ""}>
              {s.text ?? (s.op ? `${s.op} ${s.object ?? ""} (${(s.columns ?? []).join(", ")})` : "(text not kept)")}
            </span>
          </li>
        ))}
      </ul>
      {record && record.statements_dropped > 0 && (
        <p className="text-[var(--color-text-muted)]">{record.statements_dropped} more not kept in this record.</p>
      )}
    </div>
  );
}
