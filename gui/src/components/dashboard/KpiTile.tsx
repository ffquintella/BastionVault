import { Link } from "react-router-dom";
import type { ReactNode } from "react";

export type Tone = "default" | "success" | "warning" | "danger" | "muted";

const toneClass: Record<Tone, string> = {
  default: "text-[var(--color-text)]",
  success: "text-[var(--color-success)]",
  warning: "text-[var(--color-warning)]",
  danger: "text-[var(--color-danger)]",
  muted: "text-[var(--color-text-muted)]",
};

interface KpiTileProps {
  label: string;
  /** Big value. `null` renders an em-dash (data unavailable). */
  value: string | number | null;
  /** Optional secondary line under the value. */
  sub?: string;
  subTone?: Tone;
  /** When set, the tile becomes a link to this route. */
  to?: string;
  /** Muted hint shown when value is null (e.g. "not mounted"). */
  unavailableHint?: string;
  loading?: boolean;
  icon?: ReactNode;
}

export function KpiTile({
  label,
  value,
  sub,
  subTone = "muted",
  to,
  unavailableHint,
  loading,
  icon,
}: KpiTileProps) {
  const unavailable = value === null || value === undefined;
  const body = (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4 h-full min-w-0 transition-colors hover:border-[var(--color-surface-hover)]">
      <div className="flex items-center gap-1.5 text-[var(--color-text-muted)]">
        {icon && <span className="text-sm">{icon}</span>}
        <span className="text-xs font-medium truncate">{label}</span>
      </div>
      {loading ? (
        <div className="mt-2 h-7 w-12 rounded bg-[var(--color-surface-hover)] animate-pulse" />
      ) : unavailable ? (
        <div className="mt-1 text-2xl font-bold text-[var(--color-text-muted)]">—</div>
      ) : (
        <div className="mt-1 text-2xl font-bold text-[var(--color-text)] truncate">{value}</div>
      )}
      {!loading && unavailable && unavailableHint ? (
        <div className="text-[11px] text-[var(--color-text-muted)] truncate">
          {unavailableHint}
        </div>
      ) : (
        !loading &&
        sub && <div className={`text-[11px] truncate ${toneClass[subTone]}`}>{sub}</div>
      )}
    </div>
  );

  return to ? (
    <Link to={to} className="block min-w-0">
      {body}
    </Link>
  ) : (
    body
  );
}
