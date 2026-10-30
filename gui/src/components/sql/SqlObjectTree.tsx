import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Database, Eye, FileText, Table2 } from "lucide-react";

import { sqlSchemaObjects, sqlSchemas, type SqlObjectList } from "../../lib/api";
import { describeSqlError } from "../../lib/sqlWorkspace";

const OPENABLE = new Set(["table", "view", "materialized_view", "foreign_table"]);

interface SchemaNode {
  open: boolean;
  loading: boolean;
  list: SqlObjectList | null;
  error: string;
}

/**
 * The object browser (§7): schemas, then each schema's objects, loaded
 * lazily. The plugin hides objects outside the caller's object-scoped
 * grants (best effort; the catalog is not a confidentiality boundary).
 */
export function SqlObjectTree({
  token,
  disabled,
  onOpen,
  onDescribe,
  onExport,
  onError,
}: {
  token: string;
  disabled: boolean;
  onOpen: (schema: string, object: string) => void;
  onDescribe: (schema: string, object: string) => void;
  /** "Export table" (§8.1): composes `SELECT * FROM` the qualified name. */
  onExport?: (schema: string, object: string) => void;
  onError: (message: string) => void;
}) {
  const [catalog, setCatalog] = useState("");
  const [schemas, setSchemas] = useState<string[] | null>(null);
  const [nodes, setNodes] = useState<Record<string, SchemaNode>>({});
  const [filter, setFilter] = useState("");
  const [loadError, setLoadError] = useState("");

  const load = useCallback(() => {
    setLoadError("");
    sqlSchemas(token).then(
      (r) => {
        setCatalog(r.catalog);
        setSchemas(r.keys);
      },
      (e: unknown) => setLoadError(describeSqlError(e)),
    );
  }, [token]);

  useEffect(() => {
    if (token && !disabled) load();
  }, [token, disabled, load]);

  const toggle = (schema: string) => {
    const cur = nodes[schema];
    if (cur?.open) {
      setNodes((n) => ({ ...n, [schema]: { ...cur, open: false } }));
      return;
    }
    if (cur?.list) {
      setNodes((n) => ({ ...n, [schema]: { ...cur, open: true } }));
      return;
    }
    setNodes((n) => ({ ...n, [schema]: { open: true, loading: true, list: null, error: "" } }));
    sqlSchemaObjects(token, schema).then(
      (list) => setNodes((n) => ({ ...n, [schema]: { open: true, loading: false, list, error: "" } })),
      (e: unknown) => {
        const error = describeSqlError(e);
        setNodes((n) => ({ ...n, [schema]: { open: true, loading: false, list: null, error } }));
        onError(error);
      },
    );
  };

  const q = filter.trim().toLowerCase();
  const visibleSchemas = (schemas ?? []).filter(
    (s) =>
      !q ||
      s.toLowerCase().includes(q) ||
      (nodes[s]?.list?.objects ?? []).some((o) => o.name.toLowerCase().includes(q)),
  );

  return (
    <nav aria-label="Object browser" className="flex h-full min-w-0 flex-col">
      <div className="flex items-center gap-1 border-b border-[var(--color-border)] px-2 py-1">
        <Database size={13} className="shrink-0 text-[var(--color-text-muted)]" />
        <span className="min-w-0 flex-1 truncate text-xs font-semibold" title={catalog}>
          {catalog || "…"}
        </span>
        <button
          type="button"
          onClick={load}
          disabled={disabled}
          className="text-[10px] text-[var(--color-text-muted)] hover:text-[var(--color-text)] disabled:opacity-40"
        >
          Refresh
        </button>
      </div>
      <input
        aria-label="Filter objects"
        placeholder="Filter…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="mx-2 my-1 rounded border border-[var(--color-border)] bg-transparent px-2 py-0.5 text-xs outline-none"
      />
      <div className="min-h-0 flex-1 overflow-auto px-1 pb-2 text-xs">
        {loadError && (
          <p role="alert" className="px-1 py-2 text-red-400 break-words">
            {loadError}
          </p>
        )}
        {schemas === null && !loadError && <p className="px-1 py-2 text-[var(--color-text-muted)]">Loading…</p>}
        {visibleSchemas.map((schema) => {
          const node = nodes[schema];
          const objects = (node?.list?.objects ?? []).filter((o) => !q || o.name.toLowerCase().includes(q) || schema.toLowerCase().includes(q));
          return (
            <div key={schema} className="min-w-0">
              <button
                type="button"
                aria-expanded={!!node?.open}
                onClick={() => toggle(schema)}
                className="flex w-full min-w-0 items-center gap-1 rounded px-1 py-0.5 text-left hover:bg-[var(--color-surface-hover)]"
              >
                {node?.open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span className="truncate">{schema}</span>
              </button>
              {node?.open && (
                <ul className="ml-4 min-w-0">
                  {node.loading && <li className="text-[var(--color-text-muted)]">Loading…</li>}
                  {node.error && <li className="text-red-400 break-words">{node.error}</li>}
                  {objects.map((o) => (
                    <li key={`${o.kind}:${o.name}`} className="group flex min-w-0 items-center gap-1 py-0.5">
                      {o.kind === "view" || o.kind === "materialized_view" ? (
                        <Eye size={11} className="shrink-0 text-[var(--color-text-muted)]" />
                      ) : o.kind === "table" ? (
                        <Table2 size={11} className="shrink-0 text-[var(--color-text-muted)]" />
                      ) : (
                        <FileText size={11} className="shrink-0 text-[var(--color-text-muted)]" />
                      )}
                      <span className="min-w-0 flex-1 truncate" title={`${schema}.${o.name} (${o.kind})`}>
                        {o.name}
                      </span>
                      {OPENABLE.has(o.kind) && (
                        <button
                          type="button"
                          aria-label={`Open ${schema}.${o.name}`}
                          onClick={() => onOpen(schema, o.name)}
                          disabled={disabled}
                          className="shrink-0 text-[10px] text-blue-300 hover:underline disabled:opacity-40"
                        >
                          Open
                        </button>
                      )}
                      {OPENABLE.has(o.kind) && onExport && (
                        <button
                          type="button"
                          aria-label={`Export ${schema}.${o.name}`}
                          onClick={() => onExport(schema, o.name)}
                          disabled={disabled}
                          className="shrink-0 text-[10px] text-[var(--color-text-muted)] hover:underline disabled:opacity-40"
                        >
                          Export
                        </button>
                      )}
                      {o.kind !== "index" && (
                        <button
                          type="button"
                          aria-label={`Describe ${schema}.${o.name}`}
                          onClick={() => onDescribe(schema, o.name)}
                          disabled={disabled}
                          className="shrink-0 text-[10px] text-[var(--color-text-muted)] hover:underline disabled:opacity-40"
                        >
                          Describe
                        </button>
                      )}
                    </li>
                  ))}
                  {node.list?.truncated && (
                    <li className="text-[var(--color-text-muted)]">… more objects than the browser lists</li>
                  )}
                  {node.list && objects.length === 0 && <li className="text-[var(--color-text-muted)]">No objects</li>}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </nav>
  );
}
