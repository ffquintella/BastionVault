import { useState } from "react";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { operationVariant, formatTimestamp } from "./SecretHistoryPanel";
import type { PolicyHistoryEntry } from "../../lib/types";

interface PolicyHistoryPanelProps {
  entries: PolicyHistoryEntry[];
  loading?: boolean;
  /** If provided, enables a Restore button on entries with non-empty
   *  `before_raw` that re-writes the old HCL as a new policy version. */
  onRestore?: (rawHcl: string) => Promise<void>;
}

/**
 * Timeline of ACL policy changes. Each entry shows the operation and
 * an expandable before/after view of the full HCL text so operators
 * can audit and, if `onRestore` is provided, roll back a prior version.
 */
export function PolicyHistoryPanel({
  entries,
  loading = false,
  onRestore,
}: PolicyHistoryPanelProps) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [restoring, setRestoring] = useState<number | null>(null);

  if (loading) {
    return <p className="text-sm text-[var(--color-text-muted)]">Loading history...</p>;
  }
  if (entries.length === 0) {
    return (
      <EmptyState
        title="No history"
        description="No changes have been recorded for this policy yet."
      />
    );
  }

  async function handleRestore(i: number, raw: string) {
    if (!onRestore) return;
    setRestoring(i);
    try {
      await onRestore(raw);
    } finally {
      setRestoring(null);
    }
  }

  return (
    <div className="divide-y divide-[var(--color-border)]">
      {entries.map((e, i) => {
        const isOpen = expanded === i;
        return (
          <div key={`${e.ts}-${i}`} className="py-3">
            <button
              type="button"
              onClick={() => setExpanded(isOpen ? null : i)}
              className="w-full flex items-start gap-3 text-left hover:bg-[var(--color-surface-hover)] rounded px-2 -mx-2 py-1"
            >
              <div className="shrink-0 pt-0.5">
                <Badge label={e.op} variant={operationVariant(e.op)} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm">
                  <span className="font-medium">{e.user || "unknown"}</span>
                  <span className="text-[var(--color-text-muted)]">
                    {" "}
                    · {formatTimestamp(e.ts)}
                  </span>
                </div>
                <div className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  {isOpen ? "Hide diff" : "Show diff"}
                </div>
              </div>
            </button>

            {isOpen && (
              <div className="mt-2 space-y-2">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 text-xs">
                  {e.op !== "create" && (
                    <HclBlock label="before" value={e.before_raw} tone="removed" />
                  )}
                  {e.op !== "delete" && (
                    <HclBlock label="after" value={e.after_raw} tone="added" />
                  )}
                </div>
                {onRestore && e.before_raw && (
                  <div className="flex justify-end">
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => handleRestore(i, e.before_raw)}
                      loading={restoring === i}
                    >
                      Restore this version
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function HclBlock({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "added" | "removed";
}) {
  const toneClasses =
    tone === "added"
      ? "bg-green-500/5 border-green-500/20"
      : "bg-red-500/5 border-red-500/20";
  return (
    <div className={`rounded border ${toneClasses}`}>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] px-2 pt-1">
        {label}
      </div>
      <pre className="font-mono text-xs px-2 py-1 whitespace-pre-wrap break-all max-h-80 overflow-auto">
        {value === "" ? (
          <span className="italic text-[var(--color-text-muted)]">(empty)</span>
        ) : (
          value
        )}
      </pre>
    </div>
  );
}
