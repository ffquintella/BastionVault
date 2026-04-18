import { useState } from "react";
import { Button } from "./Button";
import { Badge } from "./Badge";
import { EmptyState } from "./EmptyState";
import { MaskedValue } from "./MaskedValue";

export interface SecretHistoryVersion {
  version: number;
  created_time: string;
  username: string;
  operation: string;
  /** Only set for KV-v2 (soft-delete support). */
  deletion_time?: string;
  destroyed?: boolean;
}

interface SecretHistoryPanelProps {
  versions: SecretHistoryVersion[];
  loading?: boolean;
  /** Fetch a version's data lazily when the user picks it from the timeline. */
  loadVersion: (version: number) => Promise<Record<string, unknown>>;
  /** If provided, the detail view shows a "Restore" button that re-writes
   *  the old values as a new version. */
  onRestore?: (version: number, data: Record<string, unknown>) => Promise<void>;
  /** If provided, a Close button returns to the parent view. */
  onClose?: () => void;
}

/** Shared timeline + version-detail panel used by both KV secrets and
 *  per-resource secrets. Agnostic about transport -- the caller passes a
 *  pre-fetched version list and a `loadVersion` adapter. */
export function SecretHistoryPanel({
  versions,
  loading = false,
  loadVersion,
  onRestore,
  onClose,
}: SecretHistoryPanelProps) {
  const [selected, setSelected] = useState<SecretHistoryVersion | null>(null);
  const [selectedData, setSelectedData] = useState<Record<string, unknown> | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [restoring, setRestoring] = useState(false);

  async function openVersion(v: SecretHistoryVersion) {
    setSelected(v);
    setSelectedData(null);
    setDetailError(null);
    setLoadingDetail(true);
    try {
      const data = await loadVersion(v.version);
      setSelectedData(data);
    } catch (e) {
      setDetailError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingDetail(false);
    }
  }

  function closeDetail() {
    setSelected(null);
    setSelectedData(null);
    setDetailError(null);
  }

  async function handleRestore() {
    if (!selected || !selectedData || !onRestore) return;
    setRestoring(true);
    try {
      await onRestore(selected.version, selectedData);
      closeDetail();
    } finally {
      setRestoring(false);
    }
  }

  if (loading) {
    return <p className="text-sm text-[var(--color-text-muted)]">Loading history...</p>;
  }

  // ── Detail view ─────────────────────────────────────────────────
  if (selected) {
    return (
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm">v{selected.version}</span>
              {selected.operation && (
                <Badge
                  label={selected.operation}
                  variant={operationVariant(selected.operation)}
                />
              )}
              {selected.destroyed && <Badge label="destroyed" variant="error" />}
              {selected.deletion_time && !selected.destroyed && (
                <Badge label="deleted" variant="warning" />
              )}
            </div>
            <div className="text-xs text-[var(--color-text-muted)] mt-1">
              by {selected.username || "unknown"} ·{" "}
              {formatTimestamp(selected.created_time)}
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={closeDetail}>
            &larr; Back
          </Button>
        </div>

        {loadingDetail ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading version...</p>
        ) : detailError ? (
          <p className="text-sm text-[var(--color-danger)]">{detailError}</p>
        ) : selectedData ? (
          Object.keys(selectedData).length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">Empty secret.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--color-text-muted)] text-left">
                  <th className="pb-2 font-medium">Key</th>
                  <th className="pb-2 font-medium">Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(selectedData).map(([k, v]) => (
                  <tr key={k} className="border-t border-[var(--color-border)]">
                    <td className="py-2 font-mono text-[var(--color-primary)]">{k}</td>
                    <td className="py-2 font-mono">
                      <MaskedValue value={String(v)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : null}

        {onRestore && selectedData && !selected.destroyed && (
          <div className="flex gap-2 pt-2">
            <Button size="sm" onClick={handleRestore} loading={restoring} disabled={restoring}>
              Restore this version
            </Button>
          </div>
        )}
      </div>
    );
  }

  // ── Timeline ───────────────────────────────────────────────────
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">History</h3>
        {onClose && (
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        )}
      </div>
      {versions.length === 0 ? (
        <EmptyState
          title="No history"
          description="No versions have been recorded for this secret yet."
        />
      ) : (
        <div className="divide-y divide-[var(--color-border)]">
          {versions.map((v) => (
            <button
              key={v.version}
              type="button"
              onClick={() => openVersion(v)}
              className="w-full flex items-start justify-between gap-3 py-2 px-2 -mx-2 rounded hover:bg-[var(--color-surface-hover)] transition-colors text-left"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm">v{v.version}</span>
                  {v.operation && (
                    <Badge label={v.operation} variant={operationVariant(v.operation)} />
                  )}
                  {v.destroyed && <Badge label="destroyed" variant="error" />}
                  {v.deletion_time && !v.destroyed && (
                    <Badge label="deleted" variant="warning" />
                  )}
                </div>
                <div className="text-xs text-[var(--color-text-muted)] mt-0.5 truncate">
                  by {v.username || "unknown"} · {formatTimestamp(v.created_time)}
                </div>
              </div>
              <div className="text-xs text-[var(--color-text-muted)] shrink-0 pt-0.5">
                View &rarr;
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function operationVariant(
  op: string,
): "success" | "info" | "warning" | "error" | "neutral" {
  switch (op) {
    case "create":
      return "success";
    case "update":
      return "info";
    case "restore":
      return "info";
    case "delete":
      return "error";
    default:
      return "neutral";
  }
}

export function formatTimestamp(ts: string): string {
  if (!ts) return "unknown time";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}
