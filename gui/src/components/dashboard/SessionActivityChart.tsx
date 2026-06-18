import type { AuditEvent } from "../../lib/types";

/**
 * Bucket events into `hours` hourly buckets ending at `nowMs`.
 * Bucket 0 is the oldest hour, the last bucket is the current hour.
 * Events outside the window are ignored. Pure + exported for tests.
 */
export function bucketByHour(
  events: { ts: string }[],
  nowMs: number,
  hours = 24,
): number[] {
  const buckets = new Array(hours).fill(0);
  const windowStart = nowMs - hours * 3600_000;
  for (const e of events) {
    const t = Date.parse(e.ts);
    if (Number.isNaN(t) || t < windowStart || t > nowMs) continue;
    let idx = Math.floor((t - windowStart) / 3600_000);
    if (idx < 0) idx = 0;
    if (idx >= hours) idx = hours - 1;
    buckets[idx] += 1;
  }
  return buckets;
}

interface SessionActivityChartProps {
  events: AuditEvent[];
  nowMs: number;
  loading?: boolean;
}

/** Pure-CSS 24-bar hourly activity chart from the audit stream. */
export function SessionActivityChart({
  events,
  nowMs,
  loading,
}: SessionActivityChartProps) {
  const buckets = bucketByHour(events, nowMs, 24);
  const peak = Math.max(1, ...buckets);
  const total = buckets.reduce((a, b) => a + b, 0);

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-[var(--color-text-muted)]">
          Activity · last 24h
        </h3>
        <span className="text-xs text-[var(--color-text-muted)]">peak {peak}</span>
      </div>
      {loading ? (
        <div className="h-[72px] rounded bg-[var(--color-surface-hover)] animate-pulse" />
      ) : total === 0 ? (
        <div className="h-[72px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
          No activity in the last 24 hours
        </div>
      ) : (
        <div
          className="flex items-end gap-[3px] h-[72px]"
          role="img"
          aria-label={`${total} audit events over the last 24 hours`}
        >
          {buckets.map((count, i) => (
            <div
              key={i}
              className="flex-1 rounded-t bg-[var(--color-primary)] min-h-[2px]"
              style={{ height: `${Math.max(3, (count / peak) * 100)}%` }}
              title={`${count} event${count === 1 ? "" : "s"}`}
            />
          ))}
        </div>
      )}
    </div>
  );
}
