import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import * as api from "../../lib/api";
import type { SharePointer } from "../../lib/types";
import { extractError } from "../../lib/error";
import { KpiTile } from "./KpiTile";

/** Display label per share target kind (see `ShareTargetKind` server-side). */
const KIND_LABEL: Record<string, string> = {
  resource: "Resource",
  "kv-secret": "Secret",
  "asset-group": "Asset group",
  file: "File",
};

/** Where "Open" should land for a given share. Mirrors SharingPage:
 *  resources open in the resource detail, KV secrets in the secrets
 *  browser; anything else routes to the Sharing page, which is the one
 *  destination every authenticated user can reach. */
function openHref(p: SharePointer): string {
  if (p.target_kind === "resource") {
    return `/resources/${encodeURIComponent(p.target_path)}`;
  }
  if (p.target_kind === "kv-secret") {
    return `/secrets/${p.target_path}`;
  }
  return "/sharing";
}

const cardClass =
  "bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4";

/**
 * Cropped dashboard for non-admin users. The operator dashboard's KPIs
 * (secret engines, policies, identities, audit, bastion telemetry, seal)
 * are all admin-only and resolve to "unavailable" for a standard user,
 * so we replace the whole surface with what a regular user actually has:
 * the resources / secrets / groups shared with them.
 */
export function UserDashboard() {
  const [entries, setEntries] = useState<SharePointer[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await api.listSharesForMe();
        if (!cancelled) setEntries(resp.entries);
      } catch (e: unknown) {
        if (!cancelled) setError(extractError(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const all = entries ?? [];
  const countOf = (kind: string) =>
    entries === null ? null : all.filter((e) => e.target_kind === kind).length;
  const total = entries === null ? null : all.length;
  const shown = all.slice(0, 8);

  return (
    <>
      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* KPI tiles — scoped to what's shared with this user. */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <KpiTile
          label="Shared with me"
          value={total}
          unavailableHint="unavailable"
          to="/sharing"
          loading={loading}
        />
        <KpiTile
          label="Resources"
          value={countOf("resource")}
          unavailableHint="unavailable"
          to="/resources"
          loading={loading}
        />
        <KpiTile
          label="Secrets"
          value={countOf("kv-secret")}
          unavailableHint="unavailable"
          to="/secrets"
          loading={loading}
        />
      </div>

      {/* Shared-with-me list. */}
      <div className={cardClass}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-[var(--color-text-muted)]">
            Shared with me
          </h3>
          <Link
            to="/sharing"
            className="text-xs text-[var(--color-primary)] hover:underline"
          >
            View all →
          </Link>
        </div>
        {loading ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-5 rounded bg-[var(--color-surface-hover)] animate-pulse"
              />
            ))}
          </div>
        ) : shown.length === 0 ? (
          <div className="text-xs text-[var(--color-text-muted)] py-2">
            Nothing has been shared with you yet.
          </div>
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {shown.map((p) => (
              <li
                key={`${p.target_kind}|${p.target_path}`}
                className="flex items-center gap-3 py-2 min-w-0"
              >
                <span className="shrink-0 text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]">
                  {KIND_LABEL[p.target_kind] ?? p.target_kind}
                </span>
                <span className="font-mono text-xs truncate flex-1 min-w-0">
                  {p.target_path}
                </span>
                <Link
                  to={openHref(p)}
                  className="shrink-0 text-xs text-[var(--color-primary)] hover:underline"
                >
                  Open
                </Link>
              </li>
            ))}
          </ul>
        )}
        {!loading && all.length > shown.length && (
          <div className="mt-2 text-xs text-[var(--color-text-muted)]">
            +{all.length - shown.length} more on the Sharing page.
          </div>
        )}
      </div>
    </>
  );
}
