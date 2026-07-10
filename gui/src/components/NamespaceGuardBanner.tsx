import { useEffect, useState } from "react";

import * as api from "../lib/api";

/**
 * Multi-tenancy honesty banner.
 *
 * A token is *bound* to the namespace it logged into and — unless it is
 * child-visible — may only operate there. The namespace switcher, however,
 * only sets the active-namespace header; it does not re-authenticate. So a
 * root-bound admin who switches the switcher to a child namespace keeps a
 * token that cannot read or write that tenant's data. `sys/`-scoped calls
 * (mount list, capability probes, namespace list) are exempt from the binding
 * check, so the sidebar and pages render as if everything were available —
 * then every real request into the namespace 403s with no explanation.
 *
 * `capabilities-self` now reports `namespace_operable = false` in exactly that
 * situation (and returns empty capabilities). We surface it here as a
 * persistent strip so the operator understands *why* actions fail and what to
 * do, instead of walking into an opaque "HTTP 403: Permission denied."
 *
 * Renders nothing when the token can operate in the active namespace (the
 * common case, incl. root-scoped sessions and single-tenant builds).
 */
export function NamespaceGuardBanner() {
  const [state, setState] = useState<{
    tokenNs: string;
    activeNs: string;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // The queried path is irrelevant — operability is decided by the
        // active-namespace header, not the path — so probe a cheap sys path.
        const res = await api.capabilitiesSelf(["sys/mounts"]);
        if (cancelled) return;
        if (res.namespace_operable === false) {
          setState({
            tokenNs: res.token_namespace,
            activeNs: res.active_namespace,
          });
        } else {
          setState(null);
        }
      } catch {
        // Best-effort: if the probe fails, show nothing rather than a
        // misleading warning.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!state) return null;

  const label = (ns: string) => (ns === "" ? "root" : ns);

  return (
    <div
      role="alert"
      className="w-full px-4 py-2 text-sm bg-amber-500/10 border-b border-amber-500/30 text-amber-400 flex items-center gap-2 flex-wrap"
    >
      <span className="font-semibold">Read-only here.</span>
      <span className="min-w-0 text-amber-400/90">
        Your session token is bound to the{" "}
        <code className="font-mono">{label(state.tokenNs)}</code> namespace, so
        it can browse <code className="font-mono">{label(state.activeNs)}</code>{" "}
        but cannot read or write its data. Sign in directly to{" "}
        <code className="font-mono">{label(state.activeNs)}</code> to manage it.
      </span>
    </div>
  );
}
