import { useCallback, useEffect, useState } from "react";

import * as api from "../lib/api";
import { useToast } from "./ui/Toast";
import { extractError } from "../lib/error";

/**
 * Multi-tenancy honesty banner — and, for an operator who can fix it, the fix.
 *
 * A token is *bound* to the namespace it logged into. It may operate there,
 * in a descendant when it is child-visible, and in any namespace covered by
 * the principal's **namespace assignment** (`sys/identity/ns-assignment/…`,
 * the "Allowed namespaces" chips on the Users and AppRole pages) — that last
 * one is what lets an admin who signed in at root work inside `dti/esi`
 * without a second login, and it is resolved live on every request, so
 * granting it takes effect on an already-open session.
 *
 * The namespace switcher only sets the active-namespace header; it does not
 * re-authenticate. So when none of those three rules covers the namespace the
 * switcher moved to, the session can browse it but not read or write its data.
 * `sys/`-scoped calls (mount list, capability probes, namespace list) are
 * exempt from the binding check, so the sidebar and pages render as if
 * everything were available — then every real request into the namespace 403s.
 *
 * `capabilities-self` reports `namespace_operable = false` in exactly that
 * situation (and returns empty capabilities). Rather than tell the operator to
 * sign in again — which does not help, because a fresh login binds to whatever
 * namespace it names and the assignment is still missing — we name the missing
 * assignment and offer to write it. The write goes to a root/sudo-gated route,
 * so the button can only succeed for a caller who could already grant it from
 * the Users page; it creates no authority that caller did not already hold.
 *
 * Renders nothing when the token can operate in the active namespace (the
 * common case, incl. root-scoped sessions and single-tenant builds).
 */
export function NamespaceGuardBanner() {
  const { toast } = useToast();
  const [state, setState] = useState<{
    tokenNs: string;
    activeNs: string;
  } | null>(null);
  // The session's `(mount, name)`. `null` while unresolved; `known: false`
  // when the token carries no principal an assignment could be keyed on.
  const [principal, setPrincipal] = useState<api.SessionPrincipal | null>(null);
  const [granting, setGranting] = useState(false);

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
          // Only now is the principal worth a round-trip.
          const who = await api.sessionPrincipal().catch(() => null);
          if (!cancelled) setPrincipal(who);
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

  const grant = useCallback(async () => {
    if (!state || !principal?.known) return;
    setGranting(true);
    try {
      // Add to the existing list rather than replacing it: the principal may
      // already be assigned other namespaces, and an empty list would clear
      // the restriction entirely instead of widening it.
      const current = await api.getNsAssignment(principal.mount, principal.name);
      const next = current.namespaces.includes(state.activeNs)
        ? current.namespaces
        : [...current.namespaces, state.activeNs];
      await api.setNsAssignment(principal.mount, principal.name, next);
      // The verdict is resolved per request, so a reload is enough — no new
      // token, no re-login.
      window.location.reload();
    } catch (e: unknown) {
      setGranting(false);
      toast("error", extractError(e));
    }
  }, [state, principal, toast]);

  if (!state) return null;

  const label = (ns: string) => (ns === "" ? "root" : ns);
  const canFix = principal?.known === true;

  return (
    <div
      role="alert"
      className="w-full px-4 py-2 text-sm bg-amber-500/10 border-b border-amber-500/30 text-amber-400 flex items-center gap-2 flex-wrap"
    >
      <span className="font-semibold">Read-only here.</span>
      <span className="min-w-0 text-amber-400/90">
        Your session token is bound to the{" "}
        <code className="font-mono">{label(state.tokenNs)}</code> namespace and{" "}
        {canFix ? (
          <>
            <code className="font-mono">
              {principal.mount}
              {principal.name}
            </code>{" "}
            has no allowed-namespace entry covering{" "}
          </>
        ) : (
          <>this session's principal cannot be matched to an allowed-namespace
            entry for{" "}
          </>
        )}
        <code className="font-mono">{label(state.activeNs)}</code>, so it can
        browse this namespace but not read or write its data.{" "}
        {canFix
          ? "Granting it applies to this session immediately — no new sign-in."
          : "An administrator can grant it under Admin → Users → Allowed namespaces."}
      </span>
      {canFix && (
        <button
          type="button"
          onClick={grant}
          disabled={granting}
          className="ml-auto shrink-0 px-3 py-1 rounded-md text-sm font-medium border border-amber-500/50 text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
        >
          {granting ? "Granting…" : `Grant access to ${label(state.activeNs)}`}
        </button>
      )}
    </div>
  );
}
