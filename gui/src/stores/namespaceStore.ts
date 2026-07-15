import { create } from "zustand";
import * as api from "../lib/api";

// localStorage keys. `ACTIVE_KEY` mirrors the backend's session-active
// namespace for display continuity; `LIST_KEY` caches the last-known
// namespace list so the sidebar switcher can paint instantly on a cold
// webview reload before the async re-fetch resolves.
const ACTIVE_KEY = "bv.activeNamespace";
const LIST_KEY = "bv.namespaces";

function readCachedList(): string[] {
  try {
    const raw = localStorage.getItem(LIST_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === "string")
      : [];
  } catch {
    return [];
  }
}

function readCachedActive(): string {
  try {
    return localStorage.getItem(ACTIVE_KEY) ?? "";
  } catch {
    return "";
  }
}

interface NamespaceState {
  namespaces: string[];
  active: string;
  /** True once a live fetch has resolved at least once this session. */
  loaded: boolean;
  /**
   * Fetch the namespace list + active namespace exactly once per session
   * (no-op if already loaded). Safe to call from every mount of the
   * switcher — the store persists across route changes, so navigation
   * never triggers a redundant round-trip or a disappear/reappear flicker.
   */
  ensureLoaded: () => Promise<void>;
  /** Force a live re-fetch (e.g. after creating/deleting a namespace). */
  refresh: () => Promise<void>;
  /** Set the backend session's active namespace and mirror it locally. */
  setActive: (path: string) => Promise<void>;
  /**
   * Wipe all namespace state — in-memory and the `localStorage` mirror —
   * back to a cold-start default. Called on a deliberate sign-out / vault
   * switch so the next login starts at root instead of inheriting the
   * previous session's active namespace. Without this the module-level
   * store (which survives client-side navigation) keeps showing the old
   * namespace and `ensureLoaded` short-circuits on the stale `loaded`.
   */
  reset: () => void;
}

/**
 * Namespace picker state, cached in a module-level store so it survives
 * route changes (each page mounts its own `<Layout>`, which would
 * otherwise re-fetch on every navigation). Initial values are seeded
 * from `localStorage` so even a hard webview reload paints the switcher
 * with the last-known values before the background refresh completes.
 */
export const useNamespaceStore = create<NamespaceState>((set, get) => ({
  namespaces: readCachedList(),
  active: readCachedActive(),
  loaded: false,

  refresh: async () => {
    // Fetch list + active independently so one failing doesn't blank the
    // other. Crucially, a *failed* list fetch (null) must NOT be treated as
    // an *empty* list ([]) — the latter is a real "single-tenant, no child
    // namespaces" answer we cache, the former would wrongly wipe a good
    // cached list and hide the switcher until the next app restart.
    const list = await api
      .listNamespaces()
      .then((r) => r.namespaces)
      .catch(() => null);
    const current = await api.getActiveNamespace().catch(() => null);

    set((s) => ({
      namespaces: list ?? s.namespaces,
      active: current ?? s.active,
      loaded: true,
    }));

    try {
      if (list) localStorage.setItem(LIST_KEY, JSON.stringify(list));
      if (current !== null) {
        if (current) localStorage.setItem(ACTIVE_KEY, current);
        else localStorage.removeItem(ACTIVE_KEY);
      }
    } catch {
      /* storage unavailable — in-memory state still holds */
    }
  },

  ensureLoaded: async () => {
    if (get().loaded) return;
    await get().refresh();
  },

  setActive: async (path: string) => {
    await api.setActiveNamespace(path);
    set({ active: path });
    try {
      if (path) localStorage.setItem(ACTIVE_KEY, path);
      else localStorage.removeItem(ACTIVE_KEY);
    } catch {
      /* storage unavailable — in-memory state still holds */
    }
  },

  reset: () => {
    set({ namespaces: [], active: "", loaded: false });
    try {
      localStorage.removeItem(ACTIVE_KEY);
      localStorage.removeItem(LIST_KEY);
    } catch {
      /* storage unavailable — in-memory reset still holds */
    }
  },
}));
