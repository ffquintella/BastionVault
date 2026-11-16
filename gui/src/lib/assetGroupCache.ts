// Shared client cache of the asset-group batch read
// (`resource-group/v2/groups/batch`, features/resource-groups.md). One entry per
// shape for the active (namespace, token) context, served stale while a
// revalidation runs; revalidations send the cached `version` as `since`, so an
// unchanged vault costs one small request carrying no group data.

import * as api from "./api";
import { onCacheCleared } from "./cache";
import { onAssetGroupsChanged } from "./assetGroupEvents";
import { isRouteUnsupported } from "./error";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import type { AssetGroupBatchEntry, AssetGroupBatchResult, AssetGroupBatchShape } from "./types";

/** An entry younger than this is served without asking the server. */
export const ASSET_GROUP_TTL_MS = 45_000;
/** `since` proves no group changed, not that the caller's grants did not
 *  (shares, policies): a full read at least this often bounds that. */
export const ASSET_GROUP_FULL_REFRESH_MS = 5 * 60_000;
/** Coalesces a burst of invalidations (an import) into one notification. */
const NOTIFY_DELAY_MS = 100;

/** `member -> group names`, over the active namespace's own groups. */
export interface AssetGroupIndex {
  byResource: Record<string, string[]>;
  bySecret: Record<string, string[]>;
  byFile: Record<string, string[]>;
  /** Every returned group, own and inherited. */
  names: string[];
}

export interface AssetGroupSnapshot {
  shape: AssetGroupBatchShape;
  index: AssetGroupIndex;
  /** `full` shape only. */
  groups: AssetGroupBatchEntry[];
  /** `null`: the server has none to offer, so never revalidate with it. */
  version: string | null;
  /** Last time the server confirmed this data (full read or `since`). */
  fetchedAt: number;
  /** Last full read. */
  fullAt: number;
}

interface Entry extends AssetGroupSnapshot {
  ctx: string;
}

const entries = new Map<AssetGroupBatchShape, Entry>();
const inflight = new Map<string, Promise<AssetGroupSnapshot>>();
const listeners = new Set<() => void>();
/** Bumped on every invalidation; a load that started before one is not kept. */
let generation = 0;
let notifyTimer: ReturnType<typeof setTimeout> | null = null;

/** FNV-1a tag, so the token itself is not copied into cache keys. An identity
 *  tag only, not a security control: entries are also dropped on logout. */
function fingerprint(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16);
}

/** Cache context for a namespace and a session token. */
export function assetGroupContextKey(namespace: string, token: string | null | undefined): string {
  return `${namespace}\u001f${fingerprint(token ?? "")}`;
}

/** The context of the session as it stands now. */
export function currentAssetGroupContext(): string {
  return assetGroupContextKey(useNamespaceStore.getState().active, useAuthStore.getState().token);
}

/** What is cached for `ctx`, however old; `null` when nothing is. */
export function peekAssetGroups(ctx: string, shape: AssetGroupBatchShape): AssetGroupSnapshot | null {
  const e = entries.get(shape);
  return e && e.ctx === ctx ? e : null;
}

function indexFromGroups(groups: AssetGroupBatchEntry[], names: string[]): AssetGroupIndex {
  const index: AssetGroupIndex = { byResource: {}, bySecret: {}, byFile: {}, names };
  for (const g of groups.filter((g) => !g.inherited)) {
    for (const [map, members] of [
      [index.byResource, g.members],
      [index.bySecret, g.secrets],
      [index.byFile, g.files],
    ] as const) {
      for (const m of members) {
        if (m !== "<hidden>") (map[m] ||= []).push(g.name);
      }
    }
  }
  for (const map of [index.byResource, index.bySecret, index.byFile]) {
    for (const k of Object.keys(map)) map[k].sort();
  }
  return index;
}

function snapshotFrom(shape: AssetGroupBatchShape, r: AssetGroupBatchResult, now: number): AssetGroupSnapshot {
  const groups = r.groups ?? [];
  const index: AssetGroupIndex =
    shape === "full"
      ? indexFromGroups(groups, r.names ?? [])
      : {
          byResource: r.by_resource ?? {},
          bySecret: r.by_secret ?? {},
          byFile: r.by_file ?? {},
          names: r.names ?? [],
        };
  return { shape, index, groups, version: r.version ?? null, fetchedAt: now, fullAt: now };
}

/** A server without the batch route: the old LIST + GET-each path. */
async function legacySnapshot(shape: AssetGroupBatchShape): Promise<AssetGroupSnapshot> {
  const list = await api.listAssetGroups();
  const reads = await Promise.all(list.groups.map((n) => api.readAssetGroup(n).catch(() => null)));
  const groups: AssetGroupBatchEntry[] = reads
    .filter((g): g is NonNullable<typeof g> => g !== null)
    .map((g) => ({ ...g, files: [], namespace: "", inherited: false }));
  const r: AssetGroupBatchResult = {
    unchanged: false,
    version: null,
    shape,
    namespace: "",
    groups,
    names: groups.map((g) => g.name),
    by_resource: {},
    by_secret: {},
    by_file: {},
    warnings: [],
  };
  // Derive the maps client-side for both shapes; `full` keeps the rows too.
  const snap = snapshotFrom("full", r, Date.now());
  return { ...snap, shape, groups: shape === "full" ? groups : [] };
}

async function fetchSnapshot(
  shape: AssetGroupBatchShape,
  cached: AssetGroupSnapshot | null,
): Promise<AssetGroupSnapshot> {
  const now = Date.now();
  const since =
    cached && cached.version && now - cached.fullAt < ASSET_GROUP_FULL_REFRESH_MS ? cached.version : null;
  let r: AssetGroupBatchResult;
  try {
    r = await api.assetGroupsBatch(shape, since);
  } catch (e) {
    if (isRouteUnsupported(e)) return legacySnapshot(shape);
    throw e;
  }
  if (!r || typeof r !== "object") throw new Error("asset-group batch read returned no data");
  if (r.unchanged) {
    // Only ever answered to a `since` we sent, i.e. with a cached entry.
    if (cached && since) return { ...cached, version: r.version ?? cached.version, fetchedAt: now };
    return snapshotFrom(shape, await api.assetGroupsBatch(shape, null), now);
  }
  return snapshotFrom(shape, r, now);
}

/**
 * The snapshot for `ctx`: the cached one when younger than `maxAgeMs`
 * (default: the TTL), else revalidated with the server. Concurrent callers
 * share one request.
 */
export function loadAssetGroups(
  ctx: string,
  shape: AssetGroupBatchShape,
  opts: { maxAgeMs?: number } = {},
): Promise<AssetGroupSnapshot> {
  const maxAge = opts.maxAgeMs ?? ASSET_GROUP_TTL_MS;
  const cached = peekAssetGroups(ctx, shape);
  if (cached && Date.now() - cached.fetchedAt < maxAge) return Promise.resolve(cached);
  const key = `${ctx}\u001e${shape}`;
  const pending = inflight.get(key);
  if (pending) return pending;
  const gen = generation;
  const p = fetchSnapshot(shape, cached)
    .then((snap) => {
      // Invalidated while in flight: it may predate the write, so the caller
      // gets it (a refetch is already on its way) but the cache does not.
      if (gen !== generation) return snap;
      const entry: Entry = { ...snap, ctx };
      entries.set(shape, entry);
      return entry;
    })
    .finally(() => {
      if (inflight.get(key) === p) inflight.delete(key);
    });
  inflight.set(key, p);
  return p;
}

/** Drop every entry now and tell subscribers (coalesced) to reload. */
export function invalidateAssetGroups(): void {
  entries.clear();
  inflight.clear();
  generation++;
  if (listeners.size === 0 || notifyTimer !== null) return;
  notifyTimer = setTimeout(() => {
    notifyTimer = null;
    for (const listener of [...listeners]) listener();
  }, NOTIFY_DELAY_MS);
}

/** Called after every invalidation; returns the unsubscribe function. */
export function subscribeAssetGroups(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// This client's own group writes, logout, namespace switch and vault switch.
onAssetGroupsChanged(invalidateAssetGroups);
onCacheCleared(invalidateAssetGroups);

/** Test hook: forget everything, subscribers and pending notification too. */
export function resetAssetGroupCacheForTests(): void {
  entries.clear();
  inflight.clear();
  listeners.clear();
  generation++;
  if (notifyTimer !== null) clearTimeout(notifyTimer);
  notifyTimer = null;
}
