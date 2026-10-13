import { useCallback, useEffect, useState, type ReactNode } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";
import { Button, Table, EmptyState } from "../ui";
import { SurfaceFormModal, rowParams, type SurfaceModalRequest } from "./SurfaceFormModal";

/**
 * Generic table renderer driven by a plugin's surface manifest.
 * Issues `binding.op = "list"` against the bound path with the
 * plugin's mount substituted in, then renders one row per entry
 * keyed by `field` from the surface's `columns` array.
 *
 * `row_actions[].binding` is dispatched on click; the row's record
 * supplies `{<field>}` placeholders. `confirm: true` row actions
 * prompt with `window.confirm` — a future revision will route
 * through the project's existing `ConfirmModal`.
 *
 * `revision` is the page's data revision: when it changes the list is
 * re-read, so writes made by sibling components (a form on the same
 * page) show up without remounting the table.
 *
 * Schema v2: `actions` render as buttons above the table (also when it is
 * empty) and a row action with `open_form` opens a modal form instead of
 * dispatching; both need `entry` and the page's modal `forms`.
 */
export function SurfaceTable({
  spec,
  mount,
  revision = 0,
  onAction,
  entry,
  forms = {},
}: {
  spec: api.SurfaceTable;
  mount: string;
  revision?: number;
  onAction?: () => void;
  /** The owning plugin's entry; required to open modal forms. */
  entry?: api.ActiveSurfaceEntry;
  /** The page's modal forms, by id. */
  forms?: Record<string, api.SurfaceForm>;
}) {
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [modal, setModal] = useState<SurfaceModalRequest | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const data = await api.pluginSurfaceDispatch(
        spec.binding.op,
        spec.binding.path,
        mount,
      );
      const keys = (data?.keys as unknown) as unknown;
      // A `list` response can take two shapes: `{keys: [...]}`
      // (vault-style) or `{entries: [...]}` (some engines). We
      // accept either; if neither, treat the whole `data` as a
      // single-row response (a degenerate but legitimate case).
      let asRows: Record<string, unknown>[] = [];
      if (Array.isArray(keys)) {
        asRows = keys.map((k) =>
          typeof k === "string" ? { name: k } : (k as Record<string, unknown>),
        );
      } else if (Array.isArray((data as { entries?: unknown })?.entries)) {
        asRows = (data as { entries: Record<string, unknown>[] }).entries;
      } else if (data && typeof data === "object") {
        asRows = [data as Record<string, unknown>];
      }
      setRows(asRows);
    } catch (e) {
      setErr(extractError(e));
    } finally {
      setLoading(false);
    }
  }, [spec.binding.op, spec.binding.path, mount]);

  useEffect(() => {
    void reload();
  }, [reload, revision]);

  async function runRowAction(action: api.SurfaceRowAction, row: Record<string, unknown>) {
    if (action.open_form) {
      // Never fall back to dispatching the binding: for an action that
      // opens a form it is the prefill `read`, not the action.
      setModal({ kind: "edit", action, row });
      return;
    }
    if (action.confirm && !window.confirm(`${action.label} this row?`)) return;
    // Build `{field}` substitutions from the row's fields. Only
    // string-valued fields are eligible (server-side validation
    // refuses anything else).
    const params = rowParams(row);
    try {
      await api.pluginSurfaceDispatch(
        action.binding.op,
        action.binding.path,
        mount,
        params,
      );
      // The page owner bumps `revision` from `onAction`, which reloads
      // this table along with its siblings; reload directly only when
      // rendered without one.
      if (onAction) onAction();
      else await reload();
    } catch (e) {
      setErr(extractError(e));
    }
  }

  const toolbar = spec.actions ?? [];
  // Wraps every state (loading, error, empty, rows) once the table has
  // toolbar actions or modal row actions; a v1 table renders bare, as
  // before.
  const hasModal = toolbar.length > 0 || (spec.row_actions ?? []).some((a) => a.open_form);
  const frame = (body: ReactNode) =>
    hasModal ? (
      <div className="space-y-3">
        {toolbar.length > 0 && (
          <div className="flex flex-wrap justify-end gap-2">
            {toolbar.map((a) => (
              <Button key={a.label} size="sm" onClick={() => setModal({ kind: "create", action: a })}>
                {a.label}
              </Button>
            ))}
          </div>
        )}
        {body}
        {modal &&
          (entry ? (
            <SurfaceFormModal
              request={modal}
              forms={forms}
              entry={entry}
              onClose={() => setModal(null)}
              onSaved={() => {
                if (onAction) onAction();
                else void reload();
              }}
            />
          ) : null)}
      </div>
    ) : (
      body
    );

  if (loading && rows.length === 0) {
    return frame(
      <div className="text-sm text-[var(--color-text-muted)] p-4">Loading…</div>,
    );
  }
  if (err) {
    return frame(
      <div className="text-sm text-[var(--color-danger)] p-4">{err}</div>,
    );
  }
  if (rows.length === 0) {
    return frame(
      <EmptyState
        title="No data"
        description={spec.empty_text || "Nothing to show yet."}
      />,
    );
  }

  const columns = spec.columns.map((c) => ({
    key: c.field,
    header: c.label,
    render: (row: Record<string, unknown>) => {
      const v = row[c.field];
      if (v == null) return <span className="text-[var(--color-text-muted)]">—</span>;
      if (typeof v === "string") return v;
      return JSON.stringify(v);
    },
  }));

  // Append a fixed `_actions` column when row_actions are declared.
  const allColumns =
    spec.row_actions && spec.row_actions.length > 0
      ? [
          ...columns,
          {
            key: "_actions",
            header: "",
            className: "text-right",
            render: (row: Record<string, unknown>) => (
              <div className="flex justify-end gap-2">
                {(spec.row_actions ?? []).map((a) => (
                  <Button
                    key={a.label}
                    variant={a.confirm ? "danger" : "ghost"}
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      void runRowAction(a, row);
                    }}
                  >
                    {a.label}
                  </Button>
                ))}
              </div>
            ),
          },
        ]
      : columns;

  return frame(
    <Table<Record<string, unknown>>
      columns={allColumns}
      data={rows}
      rowKey={(r) =>
        (typeof r.name === "string" && r.name) ||
        (typeof r.id === "string" && r.id) ||
        JSON.stringify(r)
      }
    />,
  );
}
