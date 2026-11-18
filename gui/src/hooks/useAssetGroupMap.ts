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
 * `bySecret` keys are each KV secret's own `<mount>/<name>`, as the server
 * keys group members (T507): index with the list path plus the key, trimmed
 * of outer slashes, nothing stripped.
 */
export interface AssetGroupMap {
  byResource: Record<string, string[]>;
  bySecret: Record<string, string[]>;
  byFile: Record<string, string[]>;
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
