// Resolve a resource's effective Rustion transport policy across all four
// tiers (global → type → asset group → resource).
//
// Why this exists as its own hook: the per-resource tier that the Connection
// tab's policy editor reads is only *one* contributor. A resource can be
// pinned to `rustion-required` by the global, type, or asset-group tier while
// its own tier is empty — so nothing that reads a single tier can answer "will
// this session go through a bastion?". That question decides what the launcher
// may offer to a connect-only caller, so it has to be asked of the resolver.
//
// Every authenticated principal can call the resolver (see the `rustion/`
// block in the implicit `default` / `namespace-self` policies). A 403 is
// therefore a narrowed baseline rather than a routine share, and it resolves
// to `null` here: "unknown", never "direct". Callers must treat `null` as
// "don't claim it's brokered" — the connect path itself refuses to dial rather
// than guess (`read_effective_policy`).

import { useEffect, useState } from "react";

import { isPermissionDenied } from "../lib/error";
import {
  rustionPolicyEffective,
  type RustionEffectivePolicy,
} from "../lib/rustion";

export interface EffectivePolicyState {
  /** The resolver's verdict, or null while loading / on failure. */
  policy: RustionEffectivePolicy | null;
  loading: boolean;
  /** True when the resolver refused the caller (403). */
  denied: boolean;
}

export function useEffectivePolicy(
  resourceId: string,
  resourceType: string,
  assetGroupIds: string[],
): EffectivePolicyState {
  const [state, setState] = useState<EffectivePolicyState>({
    policy: null,
    loading: true,
    denied: false,
  });
  // assetGroupIds is a fresh array on every render; key the effect on its
  // contents so we don't refetch on every parent re-render.
  const groupKey = assetGroupIds.join(",");
  useEffect(() => {
    if (!resourceId) {
      setState({ policy: null, loading: false, denied: false });
      return;
    }
    let cancelled = false;
    setState({ policy: null, loading: true, denied: false });
    rustionPolicyEffective({
      resourceId,
      resourceType,
      assetGroupIds: groupKey ? groupKey.split(",") : [],
    })
      .then((policy) => {
        if (!cancelled) setState({ policy, loading: false, denied: false });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setState({
          policy: null,
          loading: false,
          denied: isPermissionDenied(e),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [resourceId, resourceType, groupKey]);
  return state;
}
