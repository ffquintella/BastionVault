import { useEffect, useState } from "react";
import {
  ASSET_GROUP_TTL_MS,
  assetGroupContextKey,
  loadAssetGroups,
  peekAssetGroups,
  subscribeAssetGroups,
  type AssetGroupSnapshot,
} from "../lib/assetGroupCache";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

/**
 * Reverse-map view of asset-group membership for object-list pages (Resources,
 * Secrets): which of the active namespace's groups each object is in.
 * `bySecret` keys are canonical KV paths; canonicalize with
 * `canonicalizeSecretPath` before indexing in.
 */
export interface AssetGroupMap {
  byResource: Record<string, string[]>;
  bySecret: Record<string, string[]>;
  byFile: Record<string, string[]>;
}

/** Strip the KV-v2 `data/` or `metadata/` segment in the second path
 *  position, as `ResourceGroupStore::canonicalize_secret_path` does on the
 *  backend, to index the asset-group map only. Never for an owner or share
 *  call: those key a secret on its own name (`secretOwnPath`, T508), and
 *  this reads a secret named `data/x` as `x` (the group store too, T507). */
export function canonicalizeSecretPath(raw: string): string {
  const trimmed = raw.trim().replace(/^\/+|\/+$/g, "");
  if (!trimmed) return trimmed;
  const segs = trimmed.split("/");
  if (segs.length >= 2 && (segs[1] === "data" || segs[1] === "metadata")) {
    return [segs[0], ...segs.slice(2)].join("/");
  }
  return trimmed;
}

interface State {
  map: AssetGroupMap;
  loading: boolean;
  /** `null` until the first answer; `false` when groups cannot be read here
   *  (no `resource-group/` mount, or no grant): render no chips then. */
  available: boolean | null;
}

const EMPTY: AssetGroupMap = { byResource: {}, bySecret: {}, byFile: {} };
const UNAVAILABLE: State = { map: EMPTY, loading: false, available: false };

function stateFrom(snap: AssetGroupSnapshot | null): State {
  if (!snap) return { map: EMPTY, loading: true, available: null };
  const { byResource, bySecret, byFile } = snap.index;
  return { map: { byResource, bySecret, byFile }, loading: false, available: true };
}

/**
 * The asset-group maps for the active namespace and session, from the shared
 * cache (`lib/assetGroupCache`): one `slim` batch read for every mounted page,
 * shown stale while it revalidates on mount, window focus and every TTL tick,
 * and reloaded at once after this client changes a group.
 */
export function useAssetGroupMap(): State {
  const namespace = useNamespaceStore((s) => s.active);
  const token = useAuthStore((s) => s.token);
  const ctx = assetGroupContextKey(namespace, token);
  const [state, setState] = useState<State>(() => stateFrom(peekAssetGroups(ctx, "slim")));

  useEffect(() => {
    let cancelled = false;
    const revalidate = (maxAgeMs: number) => {
      loadAssetGroups(ctx, "slim", { maxAgeMs })
        .then((snap) => {
          if (!cancelled) setState(stateFrom(snap));
        })
        .catch(() => {
          // Keep showing what this context already had; a failed first load
          // means groups are not readable here.
          if (!cancelled) setState((prev) => (prev.available ? prev : UNAVAILABLE));
        });
    };

    // Stale-while-revalidate: paint this context's cached maps right away.
    setState(stateFrom(peekAssetGroups(ctx, "slim")));
    revalidate(ASSET_GROUP_TTL_MS);
    const unsubscribe = subscribeAssetGroups(() => revalidate(0));
    const onFocus = () => revalidate(0);
    window.addEventListener("focus", onFocus);
    const tick = setInterval(() => revalidate(0), ASSET_GROUP_TTL_MS);
    return () => {
      cancelled = true;
      unsubscribe();
      window.removeEventListener("focus", onFocus);
      clearInterval(tick);
    };
  }, [ctx]);

  return state;
}
