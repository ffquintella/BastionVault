// Resolve, for every resource card on screen, whether one click on Connect
// could launch anything — see `lib/connectValidation.ts` for the model and
// why it fails open. This hook is the React binding: it batches the page's
// candidates into one validation pass, keeps the result in state, and re-runs
// when the operator forces a revalidation from the app menu.

import { useEffect, useState, useSyncExternalStore } from "react";

import {
  connectAccessEpoch,
  subscribeConnectAccess,
  validateConnectAccess,
  type ConnectCandidate,
  type ConnectVerdict,
} from "../lib/connectValidation";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

export interface ConnectAccessState {
  /** Verdict per resource name. A missing name is "not resolved yet". */
  byName: Record<string, ConnectVerdict>;
  /** True while a validation pass is in flight. */
  validating: boolean;
}

/**
 * `candidates` may be a fresh array on every render; the effect keys off a
 * serialisation of its contents so a re-render with identical candidates
 * doesn't re-probe.
 */
export function useConnectAccess(
  candidates: ConnectCandidate[],
): ConnectAccessState {
  const [byName, setByName] = useState<Record<string, ConnectVerdict>>({});
  const [validating, setValidating] = useState(false);
  // Authorization scope: a verdict resolved for one identity in one
  // namespace must never be reused for another.
  const entityId = useAuthStore((s) => s.entityId);
  const namespace = useNamespaceStore((s) => s.active);
  const scope = `${entityId}@${namespace}`;
  // Re-runs the pass whenever `revalidateConnectAccess()` fires.
  const epoch = useSyncExternalStore(
    subscribeConnectAccess,
    connectAccessEpoch,
    connectAccessEpoch,
  );
  const key = JSON.stringify(candidates);

  useEffect(() => {
    const wanted: ConnectCandidate[] = JSON.parse(key);
    if (wanted.length === 0) {
      setByName({});
      return;
    }
    let cancelled = false;
    setValidating(true);
    validateConnectAccess(wanted, scope)
      .then((res) => {
        if (cancelled) return;
        // Replace rather than merge: a forced revalidation must not leave a
        // superseded verdict behind for a card that is still on screen.
        setByName(res);
      })
      .catch(() => {
        // `validateConnectAccess` already resolves per-candidate failures to
        // an indeterminate (permissive) verdict; a rejection here can only be
        // a programming error. Leave the map untouched, which means "unknown"
        // and leaves the chips live.
      })
      .finally(() => {
        if (!cancelled) setValidating(false);
      });
    return () => {
      cancelled = true;
    };
  }, [key, scope, epoch]);

  return { byName, validating };
}
