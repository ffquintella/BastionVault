// Phase 9.3 — Dispatcher preview for the Resource → Connection tab.
//
// Resolves the effective bastion policy for a resource and shows the
// candidate ordering the next Connect would walk ("Will try: A → B"),
// plus any targets the dispatcher would skip and why. Read-only — it
// opens no session. Renders nothing when no bastion is involved (the
// resource dials direct), so it stays out of the way for non-Rustion
// resources.

import { useEffect, useState } from "react";

import { Card } from "./ui";
import { extractError, isPermissionDenied } from "../lib/error";
import {
  rustionDispatcherPreview,
  type RustionDispatcherPreview as Preview,
  type RustionHealthStatus,
} from "../lib/rustion";

const STATUS_DOT: Record<string, string> = {
  up: "var(--color-success, #16a34a)",
  degraded: "var(--color-warning, #d97706)",
  down: "var(--color-danger, #dc2626)",
  unknown: "var(--color-text-muted)",
};

function StatusDot({ status }: { status: RustionHealthStatus }) {
  return (
    <span
      aria-label={status || "unknown"}
      title={status || "unknown"}
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: STATUS_DOT[status] ?? STATUS_DOT.unknown }}
    />
  );
}

const MODE_LABEL: Record<string, string> = {
  "ordered-fallback": "ordered fallback",
  "random-pool": "random pool",
  group: "group",
};

export function RustionDispatcherPreview({
  resourceId,
  resourceType,
  assetGroupIds,
}: {
  resourceId: string;
  resourceType: string;
  assetGroupIds: string[];
}) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    rustionDispatcherPreview({ resourceId, resourceType, assetGroupIds })
      .then((p) => {
        if (!cancelled) setPreview(p);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        // A 403 here is an expected permission boundary, not a fault:
        // read-only share-grantees and non-admins can't read the
        // dispatcher preview. This panel is purely informational, so
        // stay out of the way rather than render a red error — same as
        // it does when no bastion is involved.
        if (isPermissionDenied(e)) setPreview(null);
        else setError(extractError(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // assetGroupIds is a fresh array each render; key on its contents.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resourceId, resourceType, assetGroupIds.join(",")]);

  if (loading) return null;
  if (error) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-danger,#dc2626)]">
          Bastion preview unavailable: {error}
        </p>
      </Card>
    );
  }
  if (!preview) return null;

  const { candidates, dropped, mode, groupName, sourceTier } = preview;
  // No bastion list resolved and nothing skipped → this resource dials
  // direct. Don't render the panel at all.
  if (candidates.length === 0 && dropped.length === 0) return null;

  return (
    <Card>
      <div className="flex items-center justify-between gap-2 mb-2">
        <h3 className="text-sm font-semibold">Bastion routing</h3>
        <span className="text-[11px] text-[var(--color-text-muted)]">
          {MODE_LABEL[mode] ?? mode}
          {groupName ? ` · group "${groupName}"` : ""}
          {sourceTier ? ` · from ${sourceTier}` : ""}
        </span>
      </div>

      {candidates.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 text-sm">
          <span className="text-[var(--color-text-muted)] mr-1">Will try:</span>
          {candidates.map((c, i) => (
            <span key={c.id} className="flex items-center gap-1.5">
              {i > 0 && (
                <span className="text-[var(--color-text-muted)]">→</span>
              )}
              <span className="flex items-center gap-1 px-2 py-0.5 bg-[var(--color-bg)] rounded">
                <StatusDot status={c.status} />
                <span className="truncate min-w-0">{c.name}</span>
              </span>
            </span>
          ))}
        </div>
      ) : (
        <p className="text-sm text-[var(--color-danger,#dc2626)]">
          No healthy bastion available — Connect will fail with{" "}
          <code>bastion_unavailable</code> until one recovers.
        </p>
      )}

      {dropped.length > 0 && (
        <div className="mt-2 text-[11px] text-[var(--color-text-muted)]">
          Skipped:{" "}
          {dropped.map((d, i) => (
            <span key={d.id}>
              {i > 0 ? ", " : ""}
              {d.name} ({d.reason})
            </span>
          ))}
        </div>
      )}
    </Card>
  );
}
