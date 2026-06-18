import { Link } from "react-router-dom";
import type { RustionTelemetryTarget } from "../../lib/rustion";

function duration(openedAt: string, nowMs: number): string {
  const t = Date.parse(openedAt);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.floor((nowMs - t) / 1000));
  const m = Math.floor(s / 60);
  const sec = s % 60;
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}:${String(m % 60).padStart(2, "0")}`;
  return `${m}:${String(sec).padStart(2, "0")}`;
}

interface LiveSessionsCardProps {
  /** null = Rustion not mounted / unavailable. */
  targets: RustionTelemetryTarget[] | null;
  nowMs: number;
  loading?: boolean;
  limit?: number;
}

/** Active bastion sessions, refreshed by the parent's poll. */
export function LiveSessionsCard({
  targets,
  nowMs,
  loading,
  limit = 6,
}: LiveSessionsCardProps) {
  const sessions =
    targets?.flatMap((t) =>
      t.active.map((s) => ({ ...s, targetName: t.targetName })),
    ) ?? [];
  sessions.sort((a, b) => Date.parse(a.openedAt) - Date.parse(b.openedAt));

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-[var(--color-text-muted)]">Live sessions</h3>
        <Link
          to="/rustion-sessions"
          className="text-xs text-[var(--color-primary)] hover:underline"
        >
          Manage →
        </Link>
      </div>
      {loading ? (
        <div className="space-y-2">
          {[0, 1].map((i) => (
            <div key={i} className="h-4 rounded bg-[var(--color-surface-hover)] animate-pulse" />
          ))}
        </div>
      ) : targets === null ? (
        <div className="text-xs text-[var(--color-text-muted)] py-2">
          Bastion telemetry not available.
        </div>
      ) : sessions.length === 0 ? (
        <div className="text-xs text-[var(--color-text-muted)] py-2">No active sessions.</div>
      ) : (
        <ul className="space-y-2">
          {sessions.slice(0, limit).map((s) => (
            <li key={s.sessionId} className="flex items-center gap-2 text-sm min-w-0">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-success)] shrink-0" />
              <span className="truncate text-[var(--color-text)]">
                {s.operatorVaultUser || "?"} → {s.targetHost}
              </span>
              <span className="text-[10px] uppercase text-[var(--color-text-muted)] shrink-0">
                {s.protocol}
              </span>
              <span className="ml-auto text-xs text-[var(--color-text-muted)] shrink-0">
                {duration(s.openedAt, nowMs)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
