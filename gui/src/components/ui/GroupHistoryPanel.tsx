import { Badge } from "./Badge";
import { EmptyState } from "./EmptyState";
import { operationVariant, formatTimestamp } from "./SecretHistoryPanel";
import type { GroupHistoryEntry } from "../../lib/types";

interface GroupHistoryPanelProps {
  entries: GroupHistoryEntry[];
  loading?: boolean;
}

/**
 * Timeline of identity-group changes. Each entry records *which* fields
 * changed along with their before and after values, so operators can see
 * exactly what was added/removed from members, policies, and description.
 * Deletes retain the full final state in `before`.
 */
export function GroupHistoryPanel({ entries, loading = false }: GroupHistoryPanelProps) {
  if (loading) {
    return <p className="text-sm text-[var(--color-text-muted)]">Loading history...</p>;
  }
  if (entries.length === 0) {
    return (
      <EmptyState
        title="No history"
        description="No changes have been recorded for this group yet."
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

            {e.changed_fields.length === 0 && e.op !== "delete" && (
              <div className="text-xs text-[var(--color-text-muted)] mt-1 italic">
                No field-level changes recorded.
              </div>
            )}

            {e.changed_fields.length > 0 && (
              <div className="mt-2 space-y-2">
                {e.changed_fields.map((f) => (
                  <FieldDiff
                    key={f}
                    field={f}
                    before={e.before?.[f]}
                    after={e.after?.[f]}
                    op={e.op}
                  />
                ))}
              </div>
            )}

            {e.op === "delete" && e.changed_fields.length === 0 && (
              <div className="text-xs text-[var(--color-text-muted)] mt-1 italic">
                Group had no stored state when deleted.
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

interface FieldDiffProps {
  field: string;
  before: unknown;
  after: unknown;
  op: string;
}

function FieldDiff({ field, before, after, op }: FieldDiffProps) {
  const beforeIsArray = Array.isArray(before);
  const afterIsArray = Array.isArray(after);

  // Array diff — render added/removed chips rather than two full lists,
  // which is much easier to scan for members/policies.
  if (beforeIsArray || afterIsArray) {
    const b = (before as unknown[] | undefined)?.map(String) ?? [];
    const a = (after as unknown[] | undefined)?.map(String) ?? [];
    const added = a.filter((x) => !b.includes(x));
    const removed = b.filter((x) => !a.includes(x));

    return (
      <div>
        <FieldLabel field={field} />
        <div className="flex flex-wrap gap-1 mt-1">
          {added.map((x) => (
            <span
              key={`+${x}`}
              className="px-1.5 py-0.5 text-[10px] font-mono rounded border bg-green-500/10 border-green-500/30 text-green-400"
            >
              + {x}
            </span>
          ))}
          {removed.map((x) => (
            <span
              key={`-${x}`}
              className="px-1.5 py-0.5 text-[10px] font-mono rounded border bg-red-500/10 border-red-500/30 text-red-400 line-through"
            >
              &minus; {x}
            </span>
          ))}
          {added.length === 0 && removed.length === 0 && (
            <span className="text-[10px] text-[var(--color-text-muted)] italic">
              (no effective change)
            </span>
          )}
        </div>
      </div>
    );
  }

  // Scalar diff (description).
  const b = before === undefined ? "" : String(before);
  const a = after === undefined ? "" : String(after);

  return (
    <div>
      <FieldLabel field={field} />
      <div className="mt-1 grid grid-cols-1 sm:grid-cols-2 gap-1 text-xs">
        {op !== "create" && (
          <ValueBlock label="before" value={b} tone="removed" empty="(empty)" />
        )}
        {op !== "delete" && (
          <ValueBlock label="after" value={a} tone="added" empty="(empty)" />
        )}
      </div>
    </div>
  );
}

function FieldLabel({ field }: { field: string }) {
  return (
    <span className="px-1.5 py-0.5 bg-[var(--color-bg)] rounded text-[10px] font-mono text-[var(--color-text-muted)] border border-[var(--color-border)]">
      {field}
    </span>
  );
}

function ValueBlock({
  label,
  value,
  tone,
  empty,
}: {
  label: string;
  value: string;
  tone: "added" | "removed";
  empty: string;
}) {
  const toneClasses =
    tone === "added"
      ? "bg-green-500/5 border-green-500/20"
      : "bg-red-500/5 border-red-500/20";
  return (
    <div className={`rounded border px-2 py-1 ${toneClasses}`}>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">
        {label}
      </div>
      <div className="font-mono break-all whitespace-pre-wrap">
        {value === "" ? (
          <span className="italic text-[var(--color-text-muted)]">{empty}</span>
        ) : (
          value
        )}
      </div>
    </div>
  );
}
