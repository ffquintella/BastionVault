import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";

import type { SqlColumn } from "../../lib/api";
import { cellCopyText, cellText, editableKind } from "../../lib/sqlWorkspace";
import { SqlConfirmDialog } from "./SqlDialog";

export const ROW_HEIGHT = 26;
const COL_WIDTH = 168;
const NUM_WIDTH = 52;
const ACTION_WIDTH = 168;
const OVERSCAN = 12;

export type RowOutcome = { kind: "saved" | "conflict" | "refused" | "error"; text: string };

export interface GridEditing {
  /** Why rows cannot be edited here, or null. */
  blocker: string | null;
  canUpdate: boolean;
  canInsert: boolean;
  canDelete: boolean;
  onSave: (rowIndex: number, changes: Record<string, unknown>) => Promise<RowOutcome>;
  onDelete: (rowIndex: number) => Promise<RowOutcome>;
  onInsert: (values: Record<string, unknown>) => Promise<RowOutcome>;
}

/**
 * The result grid: virtualised rows, `NULL` shown apart from `""`, copy of
 * the selected cell. When the result is an editable table it edits rows as
 * structured operations (§7); the plugin builds the statement, binds the
 * values and reports a conflict when the row changed since it was read.
 */
export function SqlResultGrid({
  columns,
  rows,
  truncated,
  editing,
}: {
  columns: SqlColumn[];
  rows: unknown[][];
  /** `"<row>:<column>"` of cells the plugin cut at 64 KiB. */
  truncated: ReadonlySet<string>;
  editing: GridEditing | null;
}) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(480);
  const [selected, setSelected] = useState<{ row: number; col: number } | null>(null);
  const [editingCell, setEditingCell] = useState<{ row: number; col: number; text: string } | null>(null);
  const [pending, setPending] = useState<Record<number, Record<string, unknown>>>({});
  const [outcome, setOutcome] = useState<Record<number, RowOutcome>>({});
  const [busyRow, setBusyRow] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [inserting, setInserting] = useState<Record<string, string | null> | null>(null);
  const [insertOutcome, setInsertOutcome] = useState<RowOutcome | null>(null);

  // A new result resets the edit state.
  useEffect(() => {
    setPending({});
    setOutcome({});
    setEditingCell(null);
    setSelected(null);
    setInserting(null);
    setInsertOutcome(null);
  }, [columns]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el && el.clientHeight > 0) setHeight(el.clientHeight);
  }, []);

  const canEdit = !!editing && editing.blocker === null;
  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + height) / ROW_HEIGHT) + OVERSCAN);
  const width = NUM_WIDTH + columns.length * COL_WIDTH + (canEdit ? ACTION_WIDTH : 0);

  const cellEditable = (row: number, col: number) =>
    canEdit && editing!.canUpdate && editableKind(columns[col].kind) && !truncated.has(`${row}:${col}`);

  const commitCell = () => {
    if (!editingCell) return;
    const { row, col, text } = editingCell;
    const name = columns[col].name;
    setPending((p) => ({ ...p, [row]: { ...(p[row] ?? {}), [name]: text } }));
    setEditingCell(null);
  };

  const setNull = () => {
    if (!editingCell) return;
    const name = columns[editingCell.col].name;
    setPending((p) => ({ ...p, [editingCell.row]: { ...(p[editingCell.row] ?? {}), [name]: null } }));
    setEditingCell(null);
  };

  const save = async (row: number) => {
    if (!editing) return;
    setBusyRow(row);
    const result = await editing.onSave(row, pending[row] ?? {});
    setBusyRow(null);
    setOutcome((o) => ({ ...o, [row]: result }));
    if (result.kind === "saved") {
      setPending((p) => {
        const next = { ...p };
        delete next[row];
        return next;
      });
    }
  };

  const doDelete = async (row: number) => {
    setConfirmDelete(null);
    if (!editing) return;
    setBusyRow(row);
    const result = await editing.onDelete(row);
    setBusyRow(null);
    setOutcome((o) => ({ ...o, [row]: result }));
  };

  const doInsert = async () => {
    if (!editing || !inserting) return;
    const values: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(inserting)) if (v === null || v !== "") values[k] = v;
    const result = await editing.onInsert(values);
    setInsertOutcome(result);
    if (result.kind === "saved") setInserting(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!selected || editingCell) return;
    if ((e.metaKey || e.ctrlKey) && (e.key === "c" || e.key === "C")) {
      const v = rows[selected.row]?.[selected.col];
      // Copying a cell is a usability choice, not a boundary (§10).
      void navigator.clipboard?.writeText(cellCopyText(v)).catch(() => undefined);
      e.preventDefault();
    }
  };

  const outcomeClass = (k: RowOutcome["kind"]) =>
    k === "saved" ? "text-green-400" : k === "conflict" ? "text-yellow-300" : "text-red-400";

  return (
    <div className="flex h-full min-h-0 min-w-0 flex-col">
      {editing && (
        <div className="flex min-w-0 flex-wrap items-center gap-2 border-b border-[var(--color-border)] px-2 py-1 text-[11px]">
          {editing.blocker ? (
            <span className="min-w-0 truncate text-[var(--color-text-muted)]" title={editing.blocker}>
              Read-only: {editing.blocker}
            </span>
          ) : (
            <>
              <span className="text-[var(--color-text-muted)]">
                Double-click a cell to edit; each row is saved as one structured edit.
              </span>
              <button
                type="button"
                disabled={!editing.canInsert}
                title={editing.canInsert ? "Add a row" : "Your grant lacks sql_insert here (the vault decides on save)"}
                onClick={() => {
                  setInsertOutcome(null);
                  setInserting(Object.fromEntries(columns.filter((c) => editableKind(c.kind)).map((c) => [c.name, ""])));
                }}
                className="rounded border border-[var(--color-border)] px-2 py-0.5 hover:bg-[var(--color-surface-hover)] disabled:opacity-40"
              >
                Add row
              </button>
            </>
          )}
        </div>
      )}
      {inserting && (
        <div aria-label="New row" className="flex min-w-0 flex-wrap items-end gap-2 border-b border-[var(--color-border)] px-2 py-1 text-[11px]">
          {Object.keys(inserting).map((name) => (
            <label key={name} className="flex min-w-0 flex-col">
              <span className="truncate text-[var(--color-text-muted)]">{name}</span>
              <input
                aria-label={`New ${name}`}
                value={inserting[name] ?? ""}
                placeholder={inserting[name] === null ? "NULL" : "default"}
                onChange={(e) => setInserting((v) => ({ ...(v ?? {}), [name]: e.target.value }))}
                className="w-32 rounded border border-[var(--color-border)] bg-transparent px-1 font-mono"
              />
            </label>
          ))}
          <button type="button" onClick={() => void doInsert()} className="rounded bg-blue-600 px-2 py-0.5 text-white">
            Insert
          </button>
          <button type="button" onClick={() => setInserting(null)} className="rounded border border-[var(--color-border)] px-2 py-0.5">
            Cancel
          </button>
          {insertOutcome && <span className={outcomeClass(insertOutcome.kind)}>{insertOutcome.text}</span>}
        </div>
      )}
      {!inserting && insertOutcome && (
        <div className={`px-2 py-0.5 text-[11px] ${outcomeClass(insertOutcome.kind)}`}>{insertOutcome.text}</div>
      )}
      <div
        ref={scrollRef}
        role="grid"
        aria-rowcount={rows.length}
        aria-colcount={columns.length}
        tabIndex={0}
        onKeyDown={onKeyDown}
        onScroll={(e) => {
          setScrollTop(e.currentTarget.scrollTop);
          if (e.currentTarget.clientHeight > 0) setHeight(e.currentTarget.clientHeight);
        }}
        className="relative min-h-0 flex-1 overflow-auto font-mono text-[11px] outline-none"
      >
        <div style={{ width, minWidth: "100%" }}>
          <div role="row" className="sticky top-0 z-10 flex bg-[var(--color-surface)] font-semibold" style={{ height: ROW_HEIGHT }}>
            <div className="shrink-0 border-b border-r border-[var(--color-border)] px-1" style={{ width: NUM_WIDTH, order: -2 }} />
            {columns.map((c) => (
              <div
                key={c.name}
                role="columnheader"
                title={`${c.name} · ${c.type}`}
                className="shrink-0 truncate border-b border-r border-[var(--color-border)] px-1 leading-[26px]"
                style={{ width: COL_WIDTH }}
              >
                {c.name} <span className="font-normal text-[var(--color-text-muted)]">{c.type}</span>
              </div>
            ))}
            {/* Row actions sit right after the row number (flex order), so they stay in view in a narrow pane. */}
            {canEdit && <div className="shrink-0 border-b border-r border-[var(--color-border)]" style={{ width: ACTION_WIDTH, order: -1 }} />}
          </div>
          <div style={{ height: rows.length * ROW_HEIGHT, position: "relative" }}>
            {rows.slice(first, last).map((row, i) => {
              const r = first + i;
              const changes = pending[r];
              const out = outcome[r];
              const deleted = out?.kind === "saved" && out.text.startsWith("Deleted");
              return (
                <div
                  key={r}
                  role="row"
                  aria-rowindex={r + 1}
                  className={`absolute left-0 flex ${deleted ? "opacity-40 line-through" : ""}`}
                  style={{ top: r * ROW_HEIGHT, height: ROW_HEIGHT }}
                >
                  <div className="shrink-0 border-b border-r border-[var(--color-border)] px-1 text-right leading-[26px] text-[var(--color-text-muted)]" style={{ width: NUM_WIDTH, order: -2 }}>
                    {r + 1}
                  </div>
                  {columns.map((c, col) => {
                    const isEditing = editingCell?.row === r && editingCell.col === col;
                    const changed = changes && c.name in changes;
                    const value = changed ? changes[c.name] : row[col];
                    const isNull = value === null || value === undefined;
                    const isSel = selected?.row === r && selected.col === col;
                    const cut = truncated.has(`${r}:${col}`);
                    return (
                      <div
                        key={c.name}
                        role="gridcell"
                        aria-selected={isSel}
                        onClick={() => setSelected({ row: r, col })}
                        onDoubleClick={() => {
                          if (!cellEditable(r, col) || deleted) return;
                          setEditingCell({ row: r, col, text: isNull ? "" : cellText(value, c.kind) });
                        }}
                        title={cut ? "Truncated at 64 KiB; read-only in the grid" : undefined}
                        className={`shrink-0 truncate border-b border-r border-[var(--color-border)] px-1 leading-[26px] ${
                          isSel ? "outline outline-1 outline-blue-500" : ""
                        } ${changed ? "bg-yellow-900/40" : ""} ${isNull ? "italic text-[var(--color-text-muted)]" : ""}`}
                        style={{ width: COL_WIDTH }}
                      >
                        {isEditing ? (
                          <span className="flex items-center gap-0.5">
                            <input
                              autoFocus
                              onFocus={(e) => e.currentTarget.select()}
                              aria-label={`Edit ${c.name}`}
                              value={editingCell.text}
                              onChange={(e) => setEditingCell({ ...editingCell, text: e.target.value })}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") commitCell();
                                if (e.key === "Escape") setEditingCell(null);
                              }}
                              onBlur={commitCell}
                              className="min-w-0 flex-1 bg-[var(--color-surface-hover)] px-0.5 outline-none"
                            />
                            <button
                              type="button"
                              title="Set NULL"
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={setNull}
                              className="text-[10px] text-[var(--color-text-muted)]"
                            >
                              NULL
                            </button>
                          </span>
                        ) : (
                          <>
                            {cellText(value, c.kind)}
                            {cut ? " …" : ""}
                          </>
                        )}
                      </div>
                    );
                  })}
                  {canEdit && (
                    <div className="flex shrink-0 items-center gap-1 border-b border-r border-[var(--color-border)] px-1" style={{ width: ACTION_WIDTH, order: -1 }}>
                      {changes && !deleted && (
                        <>
                          <button
                            type="button"
                            aria-label={`Save row ${r + 1}`}
                            disabled={busyRow !== null}
                            onClick={() => void save(r)}
                            className="rounded bg-blue-600 px-1.5 text-white disabled:opacity-40"
                          >
                            Save
                          </button>
                          <button
                            type="button"
                            aria-label={`Revert row ${r + 1}`}
                            onClick={() =>
                              setPending((p) => {
                                const next = { ...p };
                                delete next[r];
                                return next;
                              })
                            }
                            className="rounded border border-[var(--color-border)] px-1.5"
                          >
                            Revert
                          </button>
                        </>
                      )}
                      {!changes && !deleted && (
                        <button
                          type="button"
                          aria-label={`Delete row ${r + 1}`}
                          disabled={!editing!.canDelete || busyRow !== null}
                          title={editing!.canDelete ? "Delete this row" : "Your grant lacks sql_delete here"}
                          onClick={() => setConfirmDelete(r)}
                          className="rounded border border-[var(--color-border)] px-1.5 disabled:opacity-40"
                        >
                          Delete
                        </button>
                      )}
                      {out && (
                        <span className={`min-w-0 truncate ${outcomeClass(out.kind)}`} title={out.text} data-testid={`row-outcome-${r}`}>
                          {out.text}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
        {rows.length === 0 && (
          <p className="px-2 py-3 text-[var(--color-text-muted)]">No rows.</p>
        )}
      </div>
      {confirmDelete !== null && (
        <SqlConfirmDialog
          title="Delete this row?"
          confirm="Delete row"
          onCancel={() => setConfirmDelete(null)}
          onConfirm={() => void doDelete(confirmDelete)}
        >
          <p>
            Row {confirmDelete + 1} is deleted by its key. If no row has that key any more, nothing is deleted and a
            conflict is reported.
          </p>
        </SqlConfirmDialog>
      )}
    </div>
  );
}
