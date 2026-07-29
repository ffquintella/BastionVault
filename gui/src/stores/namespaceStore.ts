import { create } from "zustand";
import * as api from "../lib/api";

// localStorage keys. `ACTIVE_KEY` mirrors the backend's session-active
// namespace for display continuity; `LIST_KEY` caches the last-known
// namespace list so the sidebar switcher can paint instantly on a cold
// webview reload before the async re-fetch resolves.
//
// `LIST_KEY` is versioned: the list now holds the *operable* namespaces of the
// session token (including `""` for root) rather than the child paths under
// root, so a pre-v2 cache would make the switcher silently drop the root option
// until the live fetch resolved.
const ACTIVE_KEY = "bv.activeNamespace";
const LIST_KEY = "bv.namespaces.v2";

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

function persist(namespaces: string[] | null, active: string | null) {
  try {
    if (namespaces) localStorage.setItem(LIST_KEY, JSON.stringify(namespaces));
    if (active !== null) {
      if (active) localStorage.setItem(ACTIVE_KEY, active);
      else localStorage.removeItem(ACTIVE_KEY);
    }
  } catch {
    /* storage unavailable — in-memory state still holds */
  }
}

interface NamespaceState {
  /**
   * Namespaces the session token may operate in, sorted. The root namespace is
   * the empty string, so `""` is present exactly when the caller may operate at
   * root — a tenant-only principal gets a list without it.
   */
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
  /**
   * Run once per successful login: discover the namespaces this session may
   * operate in and land it in the namespace its token is actually bound to.
   *
   * A principal restricted to a child namespace gets a token bound there, and
   * such a token may not operate at root — so leaving the session's active
   * namespace at the default would make every first data fetch 403 even though
   * the login succeeded. Resolves silently to the previous (root) behaviour
   * when namespace discovery is unavailable.
   */
  landSession: () => Promise<void>;
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
    //
    // `namespaces-self` rather than `list_namespaces`: the latter walks the
    // sudo-gated `sys/namespaces` CRUD surface, so it 403s for every non-admin
    // and would leave a tenant user with no switcher at all. This one is
    // filtered server-side to what the caller can actually reach, so admins
    // still see the whole tree.
    const list = await api
      .namespacesSelf()
      .then((r) => r.namespaces)
      .catch(() => null);
    const current = await api.getActiveNamespace().catch(() => null);

    set((s) => ({
      namespaces: list ?? s.namespaces,
      active: current ?? s.active,
      loaded: true,
    }));

    persist(list, current);
  },

  ensureLoaded: async () => {
    if (get().loaded) return;
    await get().refresh();
  },

  landSession: async () => {
    const self = await api.namespacesSelf().catch(() => null);
    if (!self) {
      // No answer (older server, transient failure): keep the pre-existing
      // behaviour of starting at root rather than guessing a namespace.
      set({ namespaces: [], active: "", loaded: true });
      persist([], "");
      return;
    }
    const active = self.token_namespace;
    // Mirror the token's binding onto the session so every subsequent request
    // carries the matching `X-BastionVault-Namespace` header.
    try {
      await api.setActiveNamespace(active);
    } catch {
      /* the header stays at root; the switcher still shows what's reachable */
    }
    set({ namespaces: self.namespaces, active, loaded: true });
    persist(self.namespaces, active);
  },

  setActive: async (path: string) => {
    await api.setActiveNamespace(path);
    set({ active: path });
    persist(null, path);
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
