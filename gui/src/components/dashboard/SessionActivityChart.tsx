import type { ReactNode } from "react";

/**
 * "Updated N min ago" for a statistics timestamp. Pure + exported for tests.
 * Returns `null` when the timestamp is missing or unparseable.
 */
export function formatUpdatedAgo(computedAt: string | null | undefined, nowMs: number): string | null {
  if (!computedAt) return null;
  const t = Date.parse(computedAt);
  if (Number.isNaN(t)) return null;
  const s = Math.max(0, Math.floor((nowMs - t) / 1000));
  if (s < 60) return "updated just now";
  if (s < 3600) return `updated ${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `updated ${Math.floor(s / 3600)} h ago`;
  return `updated ${Math.floor(s / 86400)} d ago`;
}

interface SessionActivityChartProps {
  /** 24 hourly counts, oldest first, from the server's precomputed
   *  statistics. `null` when the statistics are unavailable to the caller. */
  buckets: number[] | null;
  /** The server has not computed the statistics yet. */
  pending?: boolean;
  /** RFC3339 instant the buckets describe; drives the freshness label. */
  computedAt?: string | null;
  /** The statistics are 30 minutes old or more. */
  stale?: boolean;
  /** Set when some audit source could not be read; shown as a "partial"
   *  marker whose tooltip names the sources. */
  partialTitle?: string;
  nowMs: number;
  loading?: boolean;
}

/** Pure-CSS 24-bar hourly activity chart from the precomputed audit
 *  statistics in the dashboard summary. */
export function SessionActivityChart({
  buckets,
  pending,
  computedAt,
  stale,
  partialTitle,
  nowMs,
  loading,
}: SessionActivityChartProps) {
  const bars = buckets ?? [];
  const peak = Math.max(1, ...bars);
  const total = bars.reduce((a, b) => a + b, 0);
  const updated = formatUpdatedAgo(computedAt, nowMs);

  let body: ReactNode;
  if (loading) {
    body = <div className="h-[72px] rounded bg-[var(--color-surface-hover)] animate-pulse" />;
  } else if (pending) {
    body = (
      <div className="h-[72px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
        Statistics are being computed — check back in a few minutes
      </div>
    );
  } else if (buckets === null) {
    body = (
      <div className="h-[72px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
        Activity unavailable
      </div>
    );
  } else if (total === 0) {
    body = (
      <div className="h-[72px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
        No activity in the last 24 hours
      </div>
    );
  } else {
    body = (
      <div
        className="flex items-end gap-[3px] h-[72px]"
        role="img"
        aria-label={`${total} audit events over the last 24 hours`}
      >
        {bars.map((count, i) => (
          <div
            key={i}
            className="flex-1 rounded-t bg-[var(--color-primary)] min-h-[2px]"
            style={{ height: `${Math.max(3, (count / peak) * 100)}%` }}
            title={`${count} event${count === 1 ? "" : "s"}`}
          />
        ))}
      </div>
    );
  }

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4 min-w-0">
      <div className="flex items-center justify-between gap-2 mb-3 min-w-0">
        <h3 className="text-sm font-medium text-[var(--color-text-muted)] truncate">
          Activity · last 24h
          {partialTitle && (
            <span className="ml-2 text-xs text-[var(--color-warning)]" title={partialTitle}>
              partial
            </span>
          )}
        </h3>
        <span
          className={`text-xs shrink-0 ${stale ? "text-[var(--color-warning)]" : "text-[var(--color-text-muted)]"}`}
          title={computedAt ?? undefined}
        >
          {buckets !== null && !pending ? `peak ${peak}` : ""}
          {updated && buckets !== null && !pending ? ` · ${updated}` : ""}
        </span>
      </div>
      {body}
    </div>
  );
}
