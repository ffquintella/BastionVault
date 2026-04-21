import { create } from "zustand";
import type { EntityAliasInfo } from "../lib/types";
import * as api from "../lib/api";

/**
 * Small cache around `/v2/identity/entity/aliases` so every share
 * surface that needs to turn an `entity_id` into a human label shares
 * the same underlying data. Loaded lazily on first `ensureLoaded()`
 * call; one in-flight load is deduped so multiple share tables
 * mounting at once don't fire parallel lookups.
 *
 * The store fails open: if the caller lacks access to
 * `/v2/identity/entity/aliases` the lookup map stays empty and every
 * `lookup(id)` returns `null` — callers render the raw UUID, which
 * matches the pre-humanization behavior. No errors surface.
 */
interface EntityDirectoryState {
  aliases: EntityAliasInfo[];
  byEntity: Map<string, EntityAliasInfo>;
  loaded: boolean;
  loading: Promise<void> | null;
  /** Load the alias list if it isn't already loaded / loading. */
  ensureLoaded: () => Promise<void>;
  /** Force a refresh (after creating a user, for example). */
  refresh: () => Promise<void>;
  /** `entity_id` → alias record, or `null` when not in the directory. */
  lookup: (entityId: string) => EntityAliasInfo | null;
}

export const useEntityDirectoryStore = create<EntityDirectoryState>((set, get) => ({
  aliases: [],
  byEntity: new Map(),
  loaded: false,
  loading: null,
  ensureLoaded: async () => {
    const s = get();
    if (s.loaded) return;
    if (s.loading) return s.loading;
    return get().refresh();
  },
  refresh: async () => {
    const promise = (async () => {
      try {
        const list = await api.listEntityAliases();
        const map = new Map<string, EntityAliasInfo>();
        for (const a of list) {
          if (a.entity_id) map.set(a.entity_id, a);
        }
        set({ aliases: list, byEntity: map, loaded: true, loading: null });
      } catch {
        // Directory denied (e.g. caller lacks read on
        // `identity/entity/aliases`). Leave the cache empty and call
        // sites fall back to raw UUIDs.
        set({ aliases: [], byEntity: new Map(), loaded: true, loading: null });
      }
    })();
    set({ loading: promise });
    return promise;
  },
  lookup: (entityId: string) => {
    if (!entityId) return null;
    return get().byEntity.get(entityId) ?? null;
  },
}));
