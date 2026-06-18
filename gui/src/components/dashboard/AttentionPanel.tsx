import { Link } from "react-router-dom";
import type { RustionTargetHealth } from "../../lib/rustion";

type Severity = "danger" | "warning";

interface Row {
  severity: Severity;
  label: string;
  to?: string;
}

interface AttentionPanelProps {
  sealed: boolean | null;
  /** null = Rustion not mounted (no bastion health to assess). */
  health: RustionTargetHealth[] | null;
  /** Request-level counters from the dashboard summary (null when the
   *  summary endpoint is unavailable). */
  auditWriteFailures?: number | null;
  failedLogins1h?: number | null;
  loading?: boolean;
}

/** Surfaces operational concerns we can derive from data the dashboard
 *  already loads: seal state, bastion health, and the request-level
 *  stats aggregator (audit-write failures, failed logins). Renders
 *  "All clear" when there is nothing to flag. */
export function AttentionPanel({
  sealed,
  health,
  auditWriteFailures,
  failedLogins1h,
  loading,
}: AttentionPanelProps) {
  const rows: Row[] = [];

  if (sealed) {
    rows.push({ severity: "danger", label: "Vault is sealed — secrets are inaccessible" });
  }
  if (auditWriteFailures && auditWriteFailures > 0) {
    rows.push({
      severity: "danger",
      label: `${auditWriteFailures} audit-write failure${auditWriteFailures === 1 ? "" : "s"} (24h)`,
      to: "/audit",
    });
  }
  if (failedLogins1h && failedLogins1h > 0) {
    rows.push({
      severity: "warning",
      label: `${failedLogins1h} failed login${failedLogins1h === 1 ? "" : "s"} (last hour)`,
      to: "/audit",
    });
  }
  if (health) {
    const down = health.filter((h) => h.enabled && h.status === "down").length;
    const degraded = health.filter((h) => h.enabled && h.status === "degraded").length;
    if (down > 0) {
      rows.push({
        severity: "danger",
        label: `${down} bastion${down === 1 ? "" : "s"} down`,
        to: "/rustion-sessions",
      });
    }
    if (degraded > 0) {
      rows.push({
        severity: "warning",
        label: `${degraded} bastion${degraded === 1 ? "" : "s"} degraded`,
        to: "/rustion-sessions",
      });
    }
  }

  const dot: Record<Severity, string> = {
    danger: "bg-[var(--color-danger)]",
    warning: "bg-[var(--color-warning)]",
  };

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4">
      <h3 className="text-sm font-medium text-[var(--color-text-muted)] mb-3">Needs attention</h3>
      {loading ? (
        <div className="h-4 rounded bg-[var(--color-surface-hover)] animate-pulse" />
      ) : rows.length === 0 ? (
        <div className="flex items-center gap-2 text-sm text-[var(--color-success)]">
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-success)]" />
          All clear — nothing needs attention
        </div>
      ) : (
        <ul className="space-y-2">
          {rows.map((r, i) => {
            const content = (
              <span className="flex items-center gap-2 text-sm text-[var(--color-text)]">
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot[r.severity]}`} />
                <span className="truncate">{r.label}</span>
              </span>
            );
            return (
              <li key={i}>
                {r.to ? (
                  <Link to={r.to} className="hover:underline">
                    {content}
                  </Link>
                ) : (
                  content
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
