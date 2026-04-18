import { Badge } from "./Badge";
import { EmptyState } from "./EmptyState";
import { operationVariant, formatTimestamp } from "./SecretHistoryPanel";
import type { ResourceHistoryEntry } from "../../lib/types";

interface ResourceHistoryPanelProps {
  entries: ResourceHistoryEntry[];
  loading?: boolean;
}

/**
 * Timeline of resource-metadata changes. By design, resource history
 * records only WHICH top-level field names changed -- not the before or
 * after values. Callers who need full history with values should use the
 * per-secret panel (`SecretHistoryPanel`).
 */
export function ResourceHistoryPanel({ entries, loading = false }: ResourceHistoryPanelProps) {
  if (loading) {
    return <p className="text-sm text-[var(--color-text-muted)]">Loading history...</p>;
  }
  if (entries.length === 0) {
    return (
      <EmptyState
        title="No history"
        description="No changes have been recorded for this resource yet."
      />
    );
  }
  return (
    <div className="divide-y divide-[var(--color-border)]">
      {entries.map((e, i) => (
        <div key={`${e.ts}-${i}`} className="py-3 flex items-start gap-3">
          <div className="shrink-0 pt-0.5">
            <Badge label={e.op} variant={operationVariant(e.op)} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm">
              <span className="font-medium">{e.user || "unknown"}</span>
              <span className="text-[var(--color-text-muted)]"> · {formatTimestamp(e.ts)}</span>
            </div>
            {e.op !== "delete" && e.changed_fields.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {e.changed_fields.map((f) => (
                  <span
                    key={f}
                    className="px-1.5 py-0.5 bg-[var(--color-bg)] rounded text-[10px] font-mono text-[var(--color-text-muted)] border border-[var(--color-border)]"
                  >
                    {f}
                  </span>
                ))}
              </div>
            )}
            {e.op !== "delete" && e.changed_fields.length === 0 && (
              <div className="text-xs text-[var(--color-text-muted)] mt-1 italic">
                No field-level changes recorded.
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
