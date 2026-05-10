import { useCallback, useEffect, useState } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";
import { Button, Table, EmptyState } from "../ui";

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
 */
export function SurfaceTable({
  spec,
  mount,
  onAction,
}: {
  spec: api.SurfaceTable;
  mount: string;
  onAction?: () => void;
}) {
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

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
  }, [reload]);

  async function runRowAction(action: api.SurfaceRowAction, row: Record<string, unknown>) {
    if (action.confirm && !window.confirm(`${action.label} this row?`)) return;
    // Build `{field}` substitutions from the row's fields. Only
    // string-valued fields are eligible (server-side validation
    // refuses anything else).
    const params: Record<string, string> = {};
    for (const [k, v] of Object.entries(row)) {
      if (typeof v === "string") params[k] = v;
    }
    try {
      await api.pluginSurfaceDispatch(
        action.binding.op,
        action.binding.path,
        mount,
        params,
      );
      await reload();
      onAction?.();
    } catch (e) {
      setErr(extractError(e));
    }
  }

  if (loading && rows.length === 0) {
    return (
      <div className="text-sm text-[var(--color-text-muted)] p-4">Loading…</div>
    );
  }
  if (err) {
    return (
      <div className="text-sm text-[var(--color-danger)] p-4">{err}</div>
    );
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No data"
        description={spec.empty_text || "Nothing to show yet."}
      />
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

  return (
    <Table<Record<string, unknown>>
      columns={allColumns}
      data={rows}
      rowKey={(r) =>
        (typeof r.name === "string" && r.name) ||
        (typeof r.id === "string" && r.id) ||
        JSON.stringify(r)
      }
    />
  );
}
