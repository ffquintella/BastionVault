import { create } from "zustand";
import * as api from "../lib/api";

/**
 * Plugin Extensibility v1 — client-side state slice for the
 * aggregated active-surface bundle. Populated on login and after
 * an explicit refresh; consumed by Layout (sidebar slots) and the
 * SurfaceRouter (page resolution).
 *
 * The Tauri side (`plugin_surfaces_refresh`) handles the bv-client
 * cache, hash verification, and ETag round-trip — this store is
 * just a typed view onto the resulting bundle plus the loading
 * + error state the GUI needs to render.
 */
interface PluginSurfacesState {
  bundle: api.ActiveSurfaceBundle | null;
  loading: boolean;
  error: string | null;
  /** Fetch the active-surface bundle. Safe to call multiple times;
   *  the cache underneath this is content-addressed by ETag. */
  refresh: () => Promise<void>;
  /** Clear local state. Call on sign-out / vault switch so a stale
   *  bundle from the previous vault doesn't leak into the new one. */
  clear: () => void;
  /** Lookup helpers — return references into `bundle.entries` so a
   *  consumer can render in a single pass without re-walking. */
  menusForSection: (
    section: api.SurfaceSection,
    havePolicies: string[],
  ) => Array<{ menu: api.SurfaceMenu; entry: api.ActiveSurfaceEntry }>;
  pageByRoute: (
    route: string,
  ) => { page: api.SurfacePage; entry: api.ActiveSurfaceEntry } | null;
}

export const usePluginSurfacesStore = create<PluginSurfacesState>((set, get) => ({
  bundle: null,
  loading: false,
  error: null,

  async refresh() {
    set({ loading: true, error: null });
    try {
      const bundle = await api.pluginSurfacesRefresh();
      set({ bundle, loading: false, error: null });
    } catch (e) {
      set({
        loading: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  },

  clear() {
    set({ bundle: null, loading: false, error: null });
  },

  menusForSection(section, havePolicies) {
    const b = get().bundle;
    if (!b) return [];
    const out: Array<{ menu: api.SurfaceMenu; entry: api.ActiveSurfaceEntry }> = [];
    for (const entry of b.entries) {
      for (const menu of entry.surface.menus ?? []) {
        if (menu.section !== section) continue;
        // `min_policy` is a UX hint — server ACLs are the only
        // real gate. Hide menus the active token wouldn't satisfy
        // so the sidebar isn't cluttered with always-403 links.
        if (menu.min_policy && !havePolicies.includes(menu.min_policy)) continue;
        out.push({ menu, entry });
      }
    }
    return out;
  },

  pageByRoute(route) {
    const b = get().bundle;
    if (!b) return null;
    for (const entry of b.entries) {
      for (const page of entry.surface.pages ?? []) {
        if (page.route === route) return { page, entry };
      }
    }
    return null;
  },
}));
