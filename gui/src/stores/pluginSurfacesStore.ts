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
  /** Plugin Extensibility v1 / Phase 5: name + version of the
   *  most recent surface change picked up by the watcher. The GUI
   *  reads this to drive a non-modal "<plugin> updated" toast and
   *  resets it via `clearLastUpdate` after consumption. */
  lastUpdate: { plugin: string; version: string }[] | null;
  /** Extensibility v2 (Phase 2): menus pushed at runtime by plugin app
   *  modules via the `plugin-menus-updated` Tauri event. Merged with the
   *  static bundle menus in `menusForSection`. Replaced wholesale on
   *  each event; cleared on sign-out. */
  dynamicMenus: api.DynamicMenu[];
  /** Fetch the active-surface bundle. Safe to call multiple times;
   *  the cache underneath this is content-addressed by ETag. */
  refresh: () => Promise<void>;
  /** Start the long-poll watcher loop. Idempotent — repeated
   *  invocations are no-ops while a loop is already live. The
   *  loop ends when `clear()` (or `stopWatch()`) flips the running
   *  flag to false; callers don't have to await anything to stop. */
  startWatch: () => void;
  /** Stop the watcher loop (idempotent). The currently-blocked
   *  Tauri call resolves on the next server tick, sees `running ==
   *  false`, and exits. */
  stopWatch: () => void;
  /** Clear local state. Call on sign-out / vault switch so a stale
   *  bundle from the previous vault doesn't leak into the new one.
   *  Also stops the watcher. */
  clear: () => void;
  /** Drop the `lastUpdate` marker after the toast has been shown. */
  clearLastUpdate: () => void;
  /** Replace the dynamic-menu set (from the `plugin-menus-updated`
   *  event). Passing `[]` clears them (instance teardown). */
  setDynamicMenus: (menus: api.DynamicMenu[]) => void;
  /** Lookup helpers — return references into `bundle.entries` so a
   *  consumer can render in a single pass without re-walking. Static
   *  (bundle) and dynamic (app-module) menus are merged; `dynamic` +
   *  `plugin` let the renderer route click callbacks. */
  menusForSection: (
    section: api.SurfaceSection,
    havePolicies: string[],
  ) => Array<{
    menu: api.SurfaceMenu;
    entry: api.ActiveSurfaceEntry | null;
    plugin: string;
    dynamic: boolean;
  }>;
  pageByRoute: (
    route: string,
  ) => { page: api.SurfacePage; entry: api.ActiveSurfaceEntry } | null;
}

// In-module flag rather than a state field because changing it
// shouldn't trigger a re-render; the watcher loop reads it on each
// iteration to decide whether to keep going.
let watchRunning = false;

export const usePluginSurfacesStore = create<PluginSurfacesState>((set, get) => ({
  bundle: null,
  loading: false,
  error: null,
  lastUpdate: null,
  dynamicMenus: [],

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

  startWatch() {
    if (watchRunning) return;
    watchRunning = true;
    void (async () => {
      // Backoff for transport errors so a flaky network doesn't
      // hammer the server. Resets to zero after every successful
      // tick (whether the bundle changed or not).
      let backoffMs = 0;
      const maxBackoffMs = 60_000;
      while (watchRunning) {
        try {
          const tick = await api.pluginSurfaceWatchTick();
          backoffMs = 0;
          if (!watchRunning) break;
          if (tick.updated && tick.bundle) {
            const prev = get().bundle;
            const prevByPlugin = new Map(
              (prev?.entries ?? []).map((e) => [e.plugin, e.version]),
            );
            const changes = tick.bundle.entries
              .filter((e) => prevByPlugin.get(e.plugin) !== e.version)
              .map((e) => ({ plugin: e.plugin, version: e.version }));
            set({
              bundle: tick.bundle,
              error: null,
              lastUpdate: changes.length > 0 ? changes : null,
            });
          }
        } catch (e) {
          // Don't spam the console on every failed tick; surface
          // through `error` so the GUI can render an unobtrusive
          // hint if it wants to.
          set({
            error: e instanceof Error ? e.message : String(e),
          });
          backoffMs = Math.min(maxBackoffMs, Math.max(2_000, backoffMs * 2));
          await new Promise((r) => setTimeout(r, backoffMs));
        }
      }
    })();
  },

  stopWatch() {
    watchRunning = false;
  },

  clear() {
    watchRunning = false;
    set({
      bundle: null,
      loading: false,
      error: null,
      lastUpdate: null,
      dynamicMenus: [],
    });
  },

  clearLastUpdate() {
    set({ lastUpdate: null });
  },

  setDynamicMenus(menus) {
    set({ dynamicMenus: menus });
  },

  menusForSection(section, havePolicies) {
    // `min_policy` is a UX hint — server ACLs are the only real gate.
    // Hide menus the active token wouldn't satisfy so the sidebar isn't
    // cluttered with always-403 links.
    const passesPolicy = (mp?: string) => !mp || havePolicies.includes(mp);
    const out: Array<{
      menu: api.SurfaceMenu;
      entry: api.ActiveSurfaceEntry | null;
      plugin: string;
      dynamic: boolean;
    }> = [];
    const b = get().bundle;
    if (b) {
      for (const entry of b.entries) {
        for (const menu of entry.surface.menus ?? []) {
          if (menu.section !== section) continue;
          if (!passesPolicy(menu.min_policy)) continue;
          out.push({ menu, entry, plugin: entry.plugin, dynamic: false });
        }
      }
    }
    // Dynamic menus pushed by app modules render identically to static
    // ones; `dynamic: true` lets the slot fire the `bvx_menu_click`
    // callback on navigation.
    for (const menu of get().dynamicMenus) {
      if (menu.section !== section) continue;
      if (!passesPolicy(menu.min_policy)) continue;
      out.push({ menu, entry: null, plugin: menu.plugin, dynamic: true });
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
