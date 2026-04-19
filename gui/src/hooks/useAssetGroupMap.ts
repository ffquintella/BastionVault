import { useEffect, useState } from "react";
import * as api from "../lib/api";

/**
 * Reverse-map view of asset-group membership, computed by pulling every
 * asset group once and indexing its `members` (resources) and `secrets`
 * lists. Used by object-list pages (Resources, Secrets) to render
 * per-row membership chips without paying a round-trip per row.
 *
 * Keys:
 *   - `byResource[resource_name]` -> group names containing that resource
 *   - `bySecret[canonical_path]`  -> group names containing that KV path
 *
 * `bySecret` keys are stored canonicalized the same way the backend
 * stores them (KV-v2 `data/` / `metadata/` segments stripped), so a
 * caller passing either the v1 or v2 form must canonicalize with
 * `canonicalizeSecretPath` below before indexing in.
 */
export interface AssetGroupMap {
  byResource: Record<string, string[]>;
  bySecret: Record<string, string[]>;
}

/** Strip the KV-v2 `data/` or `metadata/` segment in the second path
 *  position so `secret/data/foo/bar` and `secret/foo/bar` index to the
 *  same entry. Mirrors `ResourceGroupStore::canonicalize_secret_path`
 *  on the backend. */
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
  /** `null` on first load, `true` once at least one fetch has succeeded. */
  available: boolean | null;
}

/**
 * Load every asset group and build reverse maps. `available` is `false`
 * when the `resource-group/` mount is not enabled on this deployment;
 * callers should render no chips in that case rather than treat it as
 * an error.
 *
 * Single-shot fetch: O(groups) requests on mount, independent of the
 * number of resources/secrets on the calling page.
 */
export function useAssetGroupMap(): State {
  const [state, setState] = useState<State>({
    map: { byResource: {}, bySecret: {} },
    loading: true,
    available: null,
  });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mounts = await api.listMounts();
        const enabled = mounts.some((m) => m.path === "resource-group/");
        if (!enabled) {
          if (!cancelled) {
            setState({
              map: { byResource: {}, bySecret: {} },
              loading: false,
              available: false,
            });
          }
          return;
        }

        const list = await api.listAssetGroups();
        const byResource: Record<string, string[]> = {};
        const bySecret: Record<string, string[]> = {};

        // Parallel reads; swallow individual failures so one bad group
        // doesn't wipe the whole map.
        const reads = await Promise.all(
          list.groups.map((name) =>
            api.readAssetGroup(name).catch(() => null),
          ),
        );
        for (const info of reads) {
          if (!info) continue;
          for (const m of info.members) {
            (byResource[m] ||= []).push(info.name);
          }
          for (const s of info.secrets) {
            const canonical = canonicalizeSecretPath(s);
            if (!canonical) continue;
            (bySecret[canonical] ||= []).push(info.name);
          }
        }
        // Keep the per-key group lists in a stable, sorted order.
        for (const k of Object.keys(byResource)) byResource[k].sort();
        for (const k of Object.keys(bySecret)) bySecret[k].sort();

        if (!cancelled) {
          setState({
            map: { byResource, bySecret },
            loading: false,
            available: true,
          });
        }
      } catch {
        if (!cancelled) {
          setState({
            map: { byResource: {}, bySecret: {} },
            loading: false,
            available: false,
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
