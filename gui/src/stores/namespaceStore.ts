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
    try {
      const [list, current] = await Promise.all([
        api.listNamespaces().catch(() => ({ namespaces: [] as string[] })),
        api.getActiveNamespace().catch(() => ""),
      ]);
      set({ namespaces: list.namespaces, active: current, loaded: true });
      try {
        localStorage.setItem(LIST_KEY, JSON.stringify(list.namespaces));
        if (current) localStorage.setItem(ACTIVE_KEY, current);
        else localStorage.removeItem(ACTIVE_KEY);
      } catch {
        /* storage unavailable — in-memory state still holds */
      }
    } catch {
      // Namespaces unavailable (e.g. minimal build). Mark loaded so we
      // stop retrying; the switcher hides gracefully on empty state.
      set({ loaded: true });
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
}));
