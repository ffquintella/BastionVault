/**
 * Pure helpers of the SQL workspace (features/sql-browser.md §10, T125):
 * a small lexer for statement boundaries, the confirmation guard and the
 * formatter; plugin error codes; verdict text; grid cells; row edits.
 * All of it is UX. The vault and the plugin authorize every statement.
 */

import type {
  SqlCheckVerdict,
  SqlColumn,
  SqlColumnKind,
  SqlDescribe,
  SqlRowEdit,
  SqlStatementReport,
} from "./api";
import { extractError } from "./error";

// ── lexer ───────────────────────────────────────────────────────────────

export type SqlTokenKind = "word" | "string" | "ident" | "comment" | "space" | "semicolon" | "punct";

export interface SqlToken {
  kind: SqlTokenKind;
  text: string;
  start: number;
  end: number;
}

const WORD_START = /[A-Za-z_\u0080-￿]/;
const WORD_PART = /[A-Za-z0-9_$\u0080-￿]/;

/**
 * Tokens: `'…'` (with `''`, and `E'…'` escapes), `"…"` identifiers,
 * `$tag$…$tag$` bodies, `--` and nested block comments. An unterminated
 * literal or comment runs to the end, keeping the rest out of keyword checks.
 */
export function scanSql(text: string): SqlToken[] {
  const out: SqlToken[] = [];
  let i = 0;
  const push = (kind: SqlTokenKind, start: number, end: number) =>
    out.push({ kind, text: text.slice(start, end), start, end });
  while (i < text.length) {
    const c = text[i];
    const start = i;
    if (/\s/.test(c)) {
      while (i < text.length && /\s/.test(text[i])) i++;
      push("space", start, i);
    } else if (c === "-" && text[i + 1] === "-") {
      while (i < text.length && text[i] !== "\n") i++;
      push("comment", start, i);
    } else if (c === "/" && text[i + 1] === "*") {
      let depth = 0;
      while (i < text.length) {
        if (text[i] === "/" && text[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (text[i] === "*" && text[i + 1] === "/") {
          depth--;
          i += 2;
          if (depth === 0) break;
        } else i++;
      }
      push("comment", start, i);
    } else if (c === "'" || ((c === "E" || c === "e") && text[i + 1] === "'")) {
      const escapes = c !== "'";
      i += escapes ? 2 : 1;
      while (i < text.length) {
        if (escapes && text[i] === "\\") i += 2;
        else if (text[i] === "'" && text[i + 1] === "'") i += 2;
        else if (text[i] === "'") {
          i++;
          break;
        } else i++;
      }
      push("string", start, i);
    } else if (c === '"') {
      i++;
      while (i < text.length) {
        if (text[i] === '"' && text[i + 1] === '"') i += 2;
        else if (text[i] === '"') {
          i++;
          break;
        } else i++;
      }
      push("ident", start, i);
    } else if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i));
      if (m) {
        const tag = m[0];
        const close = text.indexOf(tag, i + tag.length);
        i = close < 0 ? text.length : close + tag.length;
        push("string", start, i);
      } else {
        i++;
        while (i < text.length && /[0-9]/.test(text[i])) i++;
        push("punct", start, i);
      }
    } else if (c === ";") {
      i++;
      push("semicolon", start, i);
    } else if (WORD_START.test(c)) {
      while (i < text.length && WORD_PART.test(text[i])) i++;
      push("word", start, i);
    } else {
      i++;
      push("punct", start, i);
    }
  }
  return out;
}

export interface SqlStatementSpan {
  text: string;
  start: number;
  end: number;
}

/** Top-level statements, split on `;` outside literals and comments. Blank
 *  and comment-only pieces are dropped. */
export function splitStatements(text: string): SqlStatementSpan[] {
  const spans: SqlStatementSpan[] = [];
  let begin = 0;
  let meaningful = false;
  const flush = (end: number) => {
    if (meaningful) {
      const raw = text.slice(begin, end);
      const lead = raw.length - raw.trimStart().length;
      spans.push({ text: raw.trim(), start: begin + lead, end: begin + lead + raw.trim().length });
    }
    meaningful = false;
  };
  for (const t of scanSql(text)) {
    if (t.kind === "semicolon") {
      flush(t.start);
      begin = t.end;
    } else if (t.kind !== "space" && t.kind !== "comment") {
      meaningful = true;
    }
  }
  flush(text.length);
  return spans;
}

/** What **Run** sends: the whole text when it is one statement, else the
 *  statement around the cursor (the last one before it on a boundary). */
export function statementAtCursor(text: string, cursor: number): string {
  const spans = splitStatements(text);
  if (spans.length <= 1) return spans[0]?.text ?? "";
  const hit = spans.find((s) => cursor >= s.start && cursor <= s.end);
  if (hit) return hit.text;
  const before = spans.filter((s) => s.end <= cursor);
  return (before[before.length - 1] ?? spans[0]).text;
}

/** Upper-cased words at parenthesis depth 0 (a CTE's body is skipped). */
const topLevelWords = (span: string) => {
  let depth = 0;
  const out: string[] = [];
  for (const t of scanSql(span)) {
    if (t.text === "(") depth++;
    else if (t.text === ")") depth = Math.max(0, depth - 1);
    else if (t.kind === "word" && depth === 0) out.push(t.text.toUpperCase());
  }
  return out;
};

// ── confirmations (UX guards, not controls) ─────────────────────────────

export type DangerKind = "drop" | "truncate" | "delete-without-where" | "update-without-where";

export interface Danger {
  kind: DangerKind;
  statement: string;
}

/** `DROP`, `TRUNCATE`, and `DELETE` / `UPDATE` without `WHERE` (§10). A UX
 *  guard: the vault's `sql_drop` / `sql_delete` / `sql_update` checks are the
 *  control. A leading `WITH … AS (…)` is skipped. */
export function dangerousStatements(text: string): Danger[] {
  const out: Danger[] = [];
  for (const span of splitStatements(text)) {
    const w = topLevelWords(span.text);
    let head = w[0];
    if (head === "WITH") head = w.find((x) => ["DELETE", "UPDATE", "SELECT", "INSERT", "MERGE"].includes(x)) ?? head;
    const statement = span.text.length > 160 ? `${span.text.slice(0, 157)}…` : span.text;
    if (head === "DROP") out.push({ kind: "drop", statement });
    else if (head === "TRUNCATE") out.push({ kind: "truncate", statement });
    else if (head === "DELETE" && !w.includes("WHERE")) out.push({ kind: "delete-without-where", statement });
    else if (head === "UPDATE" && !w.includes("WHERE")) out.push({ kind: "update-without-where", statement });
  }
  return out;
}

export const DANGER_TEXT: Record<DangerKind, string> = {
  drop: "destroys an object and everything in it",
  truncate: "removes every row of the table",
  "delete-without-where": "has no WHERE clause: it deletes every row",
  "update-without-where": "has no WHERE clause: it changes every row",
};

// ── formatting ──────────────────────────────────────────────────────────

const KEYWORDS = new Set(
  (
    "select from where and or not in is null as on join left right inner outer full cross group by order " +
    "having limit offset insert into values update set delete returning with union all distinct case when " +
    "then else end create table view index alter drop truncate begin commit rollback explain analyze asc " +
    "desc like ilike between exists primary key references default grant revoke to"
  ).split(" "),
);
const BREAK_BEFORE = new Set(
  "FROM WHERE GROUP ORDER HAVING LIMIT OFFSET VALUES SET RETURNING UNION JOIN LEFT RIGHT INNER FULL CROSS".split(" "),
);
const JOIN_PREFIX = ["LEFT", "RIGHT", "INNER", "FULL", "CROSS", "OUTER"];

/** Upper-case keywords and start each major clause on a new line at depth
 *  0. Literals, quoted identifiers, `$…$` bodies and comments are copied
 *  byte for byte, so formatting never changes what a statement means. */
export function formatSql(text: string): string {
  let out = "";
  let depth = 0;
  let prevWord = "";
  for (const t of scanSql(text)) {
    if (t.kind === "word") {
      const upper = t.text.toUpperCase();
      const isKw = KEYWORDS.has(t.text.toLowerCase());
      const continues =
        (upper === "JOIN" && JOIN_PREFIX.includes(prevWord)) ||
        (upper === "OUTER" && ["LEFT", "RIGHT", "FULL"].includes(prevWord)) ||
        (upper === "ALL" && prevWord === "UNION");
      if (isKw && depth === 0 && BREAK_BEFORE.has(upper) && !continues && out.trim() !== "") {
        out = out.replace(/[ \t]+$/, "");
        if (!out.endsWith("\n")) out += "\n";
      }
      out += isKw ? upper : t.text;
      prevWord = upper;
    } else if (t.kind === "space") {
      out += out.endsWith("\n") ? "" : t.text.includes("\n") ? "\n" : " ";
    } else {
      if (t.text === "(") depth++;
      if (t.text === ")") depth = Math.max(0, depth - 1);
      if (t.kind === "semicolon") depth = 0;
      out += t.text;
      prevWord = "";
    }
  }
  return out.trim();
}

/** `EXPLAIN <statement>` (plan only: it needs only what the statement reads). */
export function explainOf(statement: string): string {
  return `EXPLAIN ${statement.trim().replace(/;\s*$/, "")}`;
}

/** A double-quoted identifier, `"` doubled. */
export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/** The statement **Open** puts in the editor for a table or view. */
export function selectAllFrom(schema: string, object: string, limit = 500): string {
  return `SELECT * FROM ${quoteIdent(schema)}.${quoteIdent(object)} LIMIT ${limit};`;
}

/** "Export table" (§8.1): every row of the qualified name, as ordinary SQL. */
export function exportTableSql(schema: string, object: string): string {
  return `SELECT * FROM ${quoteIdent(schema)}.${quoteIdent(object)}`;
}

/** The capabilities of a step-up action (`sql_drop,sql_script`). */
export function stepUpActions(action: string | undefined): string[] {
  return (action ?? "").split(",").filter((a) => a.startsWith("sql_"));
}

/** The message-pane line for a finished export. */
export function exportSummary(o: {
  state: string;
  rows: number;
  bytes: number;
  sha256: string | null;
  file: string | null;
  limit: string | null;
}): string {
  const size = o.bytes >= 1024 * 1024 ? `${(o.bytes / 1024 / 1024).toFixed(1)} MiB` : `${o.bytes} bytes`;
  const where = o.file ? ` to ${o.file}` : "";
  const hash = o.sha256 ? ` · SHA-256 ${o.sha256.slice(0, 16)}…` : "";
  const cut =
    o.state === "limit_reached"
      ? ` · stopped at the ${o.limit === "byte_limit" ? "byte" : "row"} limit: the file is incomplete`
      : "";
  return `Exported ${o.rows} row${o.rows === 1 ? "" : "s"} (${size})${where}${hash}${cut}`;
}

// ── plugin errors and verdicts ──────────────────────────────────────────

export interface PluginError {
  code: string | null;
  message: string;
}

/** `plugin dbms-management returned status 4: session_busy: …` → code and
 *  message. The plugin prefixes every refusal with a stable code. */
export function parsePluginError(e: unknown): PluginError {
  const text = extractError(e);
  const m = /returned status -?\d+: ([a-z_]+): ([\s\S]*)$/.exec(text);
  if (m) return { code: m[1], message: m[2] };
  const bare = /^([a-z_]{3,40}): ([\s\S]*)$/.exec(text);
  if (bare) return { code: bare[1], message: bare[2] };
  return { code: null, message: text };
}

const CODE_HINTS: Record<string, string> = {
  session_on_other_node:
    "This SQL session lives on another vault node (sessions never fail over). Open a new session.",
  session_closed: "The SQL session has been closed. Open a new one.",
  session_tainted: "The session was closed because a setting changed behind the classifier's back.",
  session_busy: "Another statement or edit is still running in this session; wait for it or stop it.",
  use_script: "Run one statement at a time, or run the editor as a script (needs sql_script).",
  step_up_failed: "The step-up ticket was not accepted; verify a factor for this action again.",
  export_not_select: "Only a statement that needs nothing but sql_select can be exported.",
  export_one_statement: "An export runs exactly one statement.",
  export_expired: "The export was abandoned (nothing pulled for too long) and dropped.",
  script_tx_control: "A single-transaction script may not hold BEGIN, COMMIT, ROLLBACK or SAVEPOINT.",
  script_too_long: "The script has more statements than this server allows.",
  script_too_large: "The script is larger than this server allows.",
  transaction_open: "A transaction is open; commit or roll it back before a single-transaction script.",
  mfa_required: "This SQL profile needs a second factor. Open it from its profile so the prompt can run.",
  row_budget: "This session's row budget is spent.",
  context_stale: "The transaction is aborted: only ROLLBACK (or COMMIT) runs now.",
};

/** One sentence for the operator: the hint for a known code, then the
 *  plugin's own message. */
export function describeSqlError(e: unknown): string {
  const { code, message } = parsePluginError(e);
  const hint = code ? CODE_HINTS[code] : undefined;
  return hint ? `${hint} (${code}: ${message})` : code ? `${code}: ${message}` : message;
}

/** Whether the error means the session is gone for good. */
export function isSessionGone(e: unknown): boolean {
  const { code, message } = parsePluginError(e);
  if (code && ["session_on_other_node", "session_closed", "session_tainted"].includes(code)) return true;
  if (code === "not_found" && /session/i.test(message)) return true;
  return /the SQL session has ended/.test(message);
}

/** `catalog.schema.object`, or "the server" for a server-level check. */
export function targetLabel(target: unknown): string {
  if (target && typeof target === "object") {
    const t = target as Record<string, unknown>;
    return [t.catalog, t.schema, t.object].map((x) => (typeof x === "string" ? x : "")).join(".");
  }
  return "the server";
}

/** Each refused check as "needs `cap` on `target`", the request's own
 *  checks (a script's `sql_script`) first. */
export function refusals(statements: readonly SqlStatementReport[], request: readonly SqlCheckVerdict[] = []): string[] {
  const out: string[] = [];
  for (const r of request) {
    if (!r.allowed) out.push(`needs \`${r.capability}\` on \`${targetLabel(r.target)}\` for the script`);
  }
  for (const s of statements) {
    for (const r of s.required as SqlCheckVerdict[]) {
      if (r.allowed) continue;
      const why = r.denied_by_deny ? " (an explicit deny)" : "";
      out.push(`needs \`${r.capability}\` on \`${targetLabel(r.target)}\`${why}`);
    }
  }
  return out;
}

// ── grid cells ──────────────────────────────────────────────────────────

/** The grid's text for a cell. `NULL` is shown distinctly from `""`. */
export function cellText(value: unknown, kind: SqlColumnKind): string {
  if (value === null || value === undefined) return "NULL";
  if (kind === "binary" && typeof value === "string") return `(${Math.floor((value.length * 3) / 4)} bytes, binary)`;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

/** The raw value to copy: base64 for binary, JSON text for structured. */
export function cellCopyText(value: unknown): string {
  if (value === null || value === undefined) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Kinds the grid edits as text. Not binary or JSON: their text form would
 *  not compare equal to the stored value, so every edit would conflict. */
export function editableKind(kind: SqlColumnKind): boolean {
  return kind === "string" || kind === "number" || kind === "boolean" || kind === "datetime" || kind === "null";
}

// ── structured row edits ────────────────────────────────────────────────

export interface EditTarget {
  schema: string;
  name: string;
  /** The table's edit key from describe (primary or non-null unique key). */
  key: string[];
}

/** Why the grid cannot edit these rows, or null when it can. */
export function gridEditBlocker(describe: SqlDescribe | null, columns: readonly SqlColumn[]): string | null {
  if (!describe) return "open a table from the object tree to edit its rows";
  if (!describe.edit.editable || !describe.edit.key) return describe.edit.reason ?? "this object is read-only in the grid";
  const names = new Set(columns.map((c) => c.name));
  const missing = describe.edit.key.filter((k) => !names.has(k));
  if (missing.length > 0) return `the result does not include the key column(s) ${missing.join(", ")}`;
  return null;
}

function keyOf(target: EditTarget, columns: readonly SqlColumn[], row: readonly unknown[]): Record<string, unknown> {
  const key: Record<string, unknown> = {};
  for (const k of target.key) {
    const i = columns.findIndex((c) => c.name === k);
    if (i < 0) throw new Error(`the key column ${k} is not in the result`);
    if (row[i] === null || row[i] === undefined) throw new Error(`the key column ${k} is NULL`);
    key[k] = row[i];
  }
  return key;
}

/** `update`: the changed columns' new values, their originals (the plugin's
 *  conflict guard) and the row's key. */
export function buildUpdate(
  target: EditTarget,
  columns: readonly SqlColumn[],
  row: readonly unknown[],
  changes: Readonly<Record<string, unknown>>,
): SqlRowEdit {
  const values: Record<string, unknown> = {};
  const original: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(changes)) {
    const i = columns.findIndex((c) => c.name === name);
    if (i < 0) throw new Error(`unknown column ${name}`);
    values[name] = value;
    original[name] = row[i] ?? null;
  }
  if (Object.keys(values).length === 0) throw new Error("nothing changed");
  return {
    object: { schema: target.schema, name: target.name },
    op: "update",
    key: keyOf(target, columns, row),
    values,
    original,
  };
}

export function buildDelete(target: EditTarget, columns: readonly SqlColumn[], row: readonly unknown[]): SqlRowEdit {
  return { object: { schema: target.schema, name: target.name }, op: "delete", key: keyOf(target, columns, row) };
}

/** `insert`: only the columns the operator filled in; the rest default. */
export function buildInsert(target: EditTarget, values: Readonly<Record<string, unknown>>): SqlRowEdit {
  if (Object.keys(values).length === 0) throw new Error("fill in at least one column");
  return { object: { schema: target.schema, name: target.name }, op: "insert", values: { ...values } };
}

/** What an edit needs, for the convenience gating of the grid's buttons. */
export function editCapabilities(op: "insert" | "update" | "delete"): string[] {
  return [op === "insert" ? "sql_insert" : op === "update" ? "sql_update" : "sql_delete", "sql_select"];
}
