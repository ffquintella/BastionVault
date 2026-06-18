import { Link } from "react-router-dom";
import type { AuditEvent } from "../../lib/types";

function relTime(ts: string, nowMs: number): string {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.floor((nowMs - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

const opColor: Record<string, string> = {
  create: "text-[var(--color-success)]",
  update: "text-[var(--color-primary)]",
  delete: "text-[var(--color-danger)]",
};
const opGlyph: Record<string, string> = {
  create: "+",
  update: "✎",
  delete: "−",
};

interface RecentAuditCardProps {
  events: AuditEvent[];
  nowMs: number;
  loading?: boolean;
  limit?: number;
}

/** The last N change-history events, op-colored, linking to the full
 *  Audit page. */
export function RecentAuditCard({
  events,
  nowMs,
  loading,
  limit = 6,
}: RecentAuditCardProps) {
  const rows = events.slice(0, limit);
  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-[var(--color-text-muted)]">Recent activity</h3>
        <Link to="/audit" className="text-xs text-[var(--color-primary)] hover:underline">
          View audit →
        </Link>
      </div>
      {loading ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-4 rounded bg-[var(--color-surface-hover)] animate-pulse" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <div className="text-xs text-[var(--color-text-muted)] py-2">No recent activity.</div>
      ) : (
        <ul className="space-y-2">
          {rows.map((e, i) => (
            <li key={i} className="flex items-center gap-2 text-sm min-w-0">
              <span className={`${opColor[e.op] ?? "text-[var(--color-text-muted)]"} w-3 text-center`}>
                {opGlyph[e.op] ?? "•"}
              </span>
              <span className="text-[var(--color-text-muted)] text-xs shrink-0">{e.category}</span>
              <span className="truncate text-[var(--color-text)]" title={e.target}>
                {e.target}
              </span>
              <span className="ml-auto text-xs text-[var(--color-text-muted)] shrink-0">
                {relTime(e.ts, nowMs)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
