import { useEffect, useState } from "react";

import * as api from "../lib/api";
import { useAuthStore } from "../stores/authStore";

/**
 * Resolve whether the caller may modify a resource's metadata (e.g. its
 * connection profiles or per-resource Rustion policy). Returns `null`
 * while loading, `true`/`false` once known.
 *
 * `capabilities-self` only reports policy-based capabilities — it is
 * evaluated against a synthetic request with no identity, so it can NOT
 * see access granted by resource ownership or an `owner`-scoped rule.
 * We therefore mirror the Sharing card's authorization model and treat
 * an admin or the resource owner as allowed even when the bare policy
 * check comes back empty. The server still enforces the real boundary;
 * this only governs whether the GUI offers the edit controls.
 *
 * Fails toward `false` on a denied policy check so read-only callers
 * (the common case: a share grants them read but not write) see the
 * mutation controls disabled rather than enabled-then-403.
 *
 * Pass `enabled = false` to short-circuit the check (returns `true`) for
 * callers that don't want resource-owner gating — e.g. the Rustion policy
 * editor at the type/asset-group tiers, which carry their own admin /
 * group-owner gating instead.
 */
export function useCanWriteResource(
  resourceName: string,
  enabled = true,
): boolean | null {
  const policies = useAuthStore((s) => s.policies);
  const entityId = useAuthStore((s) => s.entityId);
  const isAdmin = policies.some((p) => p === "root" || p === "admin");
  const [allowed, setAllowed] = useState<boolean | null>(null);
  useEffect(() => {
    if (!enabled) {
      setAllowed(true);
      return;
    }
    if (isAdmin) {
      setAllowed(true);
      return;
    }
    let cancelled = false;
    setAllowed(null);
    const path = `resources/resources/${resourceName}`;
    Promise.all([
      api
        .capabilitiesSelf([path])
        .then((r) => r.paths[path] ?? [])
        .catch(() => [] as string[]),
      api.getResourceOwner(resourceName).catch(() => null),
    ]).then(([caps, owner]) => {
      if (cancelled) return;
      const byPolicy =
        caps.includes("update") ||
        caps.includes("create") ||
        caps.includes("root");
      const byOwner =
        owner?.owned === true &&
        owner.entity_id === entityId &&
        entityId !== "";
      setAllowed(byPolicy || byOwner);
    });
    return () => {
      cancelled = true;
    };
  }, [resourceName, isAdmin, entityId, enabled]);
  return allowed;
}
