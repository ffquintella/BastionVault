import { useState } from "react";

import type { SqlExportFormat, SqlExportRequest } from "../../lib/api";

const FORMATS: { id: SqlExportFormat; label: string }[] = [
  { id: "csv", label: "CSV (RFC 4180)" },
  { id: "jsonl", label: "JSON Lines" },
  { id: "sql-insert", label: "SQL INSERT statements" },
];

/**
 * Export options (features/sql-browser.md §8.1). The statement is fixed
 * (the one at the cursor, or the tree's "Export table"); after "Export" the
 * host asks where to save and writes the file itself. Needs `sql_export` on
 * what it reads, checked by the vault.
 */
export function SqlExportDialog({
  sql,
  table,
  onCancel,
  onExport,
}: {
  sql: string;
  /** "Export table": the qualified name, the default INSERT target. */
  table?: { schema: string; name: string };
  onCancel: () => void;
  onExport: (req: SqlExportRequest) => void;
}) {
  const [format, setFormat] = useState<SqlExportFormat>("csv");
  const [maxRows, setMaxRows] = useState("");
  const [guard, setGuard] = useState(true);
  const [schema, setSchema] = useState(table?.schema ?? "");
  const [name, setName] = useState(table?.name ?? "");

  const rows = maxRows.trim() === "" ? undefined : Number(maxRows);
  const rowsBad = rows !== undefined && (!Number.isInteger(rows) || rows < 1);
  const nameBad = format === "sql-insert" && name.trim() === "";

  const submit = () => {
    if (rowsBad || nameBad) return;
    const req: SqlExportRequest = { sql, format };
    if (rows !== undefined) req.max_rows = rows;
    if (format === "csv" && !guard) req.formula_guard = false;
    if (format === "sql-insert") req.table = { name: name.trim(), ...(schema.trim() ? { schema: schema.trim() } : {}) };
    onExport(req);
  };

  return (
    <div
      role="dialog"
      aria-label="Export"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onKeyDown={(e) => {
        if (e.key === "Escape") onCancel();
      }}
    >
      <form
        className="w-full max-w-lg rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-sm shadow-2xl"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <h2 className="mb-2 font-semibold text-[var(--color-text)]">Export</h2>
        <pre className="mb-3 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--color-bg)] p-2 font-mono text-[11px] text-[var(--color-text-muted)]">
          {sql}
        </pre>
        <div className="grid grid-cols-2 gap-3 text-[var(--color-text-muted)]">
          <label className="col-span-2 flex min-w-0 flex-col gap-1">
            <span>Format</span>
            <select
              aria-label="Format"
              value={format}
              onChange={(e) => setFormat(e.target.value as SqlExportFormat)}
              className="rounded border border-[var(--color-border)] bg-transparent px-2 py-1 text-[var(--color-text)]"
            >
              {FORMATS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          <label className="col-span-2 flex min-w-0 flex-col gap-1">
            <span>Most rows (empty: the server&apos;s limit)</span>
            <input
              aria-label="Most rows"
              inputMode="numeric"
              value={maxRows}
              onChange={(e) => setMaxRows(e.target.value)}
              className="rounded border border-[var(--color-border)] bg-transparent px-2 py-1 text-[var(--color-text)] outline-none"
            />
            {rowsBad && <span className="text-red-400">A positive whole number, or empty.</span>}
          </label>
          {format === "csv" && (
            <label className="col-span-2 flex items-center gap-2">
              <input type="checkbox" checked={guard} onChange={(e) => setGuard(e.target.checked)} aria-label="Formula guard" />
              <span>
                Formula guard: prefix <code>&apos;</code> to text cells starting with <code>= + - @</code>, tab or CR, so a
                spreadsheet does not run them
              </span>
            </label>
          )}
          {format === "sql-insert" && (
            <>
              <label className="flex min-w-0 flex-col gap-1">
                <span>Target schema</span>
                <input
                  aria-label="Target schema"
                  value={schema}
                  onChange={(e) => setSchema(e.target.value)}
                  className="min-w-0 rounded border border-[var(--color-border)] bg-transparent px-2 py-1 text-[var(--color-text)] outline-none"
                />
              </label>
              <label className="flex min-w-0 flex-col gap-1">
                <span>Target table</span>
                <input
                  aria-label="Target table"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="min-w-0 rounded border border-[var(--color-border)] bg-transparent px-2 py-1 text-[var(--color-text)] outline-none"
                />
                {nameBad && <span className="text-red-400">The INSERTs need a table name.</span>}
              </label>
            </>
          )}
        </div>
        <p className="mt-3 text-[11px] text-[var(--color-text-muted)]">
          You will be asked where to save it. The file is written as it streams and checked against the server&apos;s
          SHA-256; exporting needs <code>sql_export</code> and is audited.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-[var(--color-border)] px-3 py-1 text-xs text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={rowsBad || nameBad}
            className="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
          >
            Export
          </button>
        </div>
      </form>
    </div>
  );
}
