import { create } from "zustand";
import * as api from "../lib/api";

/**
 * Snapshot of the post-login auth state for a single vault. Kept in
 * memory and re-hydrated from the Rust-side `AppState` on app boot
 * via `bootstrapAuth`. The Rust process owns the active bv-client
 * (and its token) across webview reloads — focus-triggered re-paints
 * (e.g. the MCP screenshot path), Vite HMR, and `location.reload()`
 * all drop in-memory React state, but the Rust client survives. By
 * making Rust the source of truth and re-fetching policies on every
 * boot, the UI stays authenticated without persisting a token to
 * `localStorage`/`sessionStorage` (which is brittle: the screenshot
 * path was clearing sessionStorage in practice, and `localStorage`
 * across launches conflicts with the "tokens are ephemeral to the
 * running process" model).
 */
interface VaultSession {
  token: string;
  policies: string[];
  entityId: string;
  principal: string;
  /** Wall-clock seconds at which we remembered this session. Used
   *  only for diagnostics today; a future rev could prune stale
   *  entries automatically. */
  rememberedAt: number;
}

interface AuthState {
  token: string | null;
  policies: string[];
  isAuthenticated: boolean;
  /**
   * True while the boot-time `bootstrapAuth` call is in flight. The
   * route guard waits for this to flip false before bouncing an
   * unauthenticated user to `/login`, so a webview reload during a
   * protected route does not flicker through the login screen on
   * its way back to the dashboard.
   */
  bootstrapping: boolean;
  /** Stable entity_id for the logged-in user, used by ownership and sharing features. */
  entityId: string;
  /** Principal username (UserPass) or role name (AppRole); for display only. */
  principal: string;
  /**
   * Per-vault-id session cache. When the operator flips between
   * saved vaults via the sidebar's Switch button, we stash the
   * current session under the source vault's id and try to restore
   * the target vault's cached session before sending the user to
   * `/login`. Empty until a successful login runs at least once
   * per vault in this session.
   */
  sessions: Record<string, VaultSession>;
  setAuth: (token: string, policies: string[]) => void;
  clearAuth: () => void;
  /**
   * Re-hydrate auth from the Rust-side `AppState`. Idempotent —
   * called once on app mount (see App.tsx) and short-circuits if a
   * token is already in memory. On success, also runs `loadEntity`
   * so owner-aware UI has `entityId` immediately.
   */
  bootstrapAuth: () => Promise<void>;
  /** Populate `entityId` + `principal` by calling `identity/entity/self`. */
  loadEntity: () => Promise<void>;
  /** Stash the current auth fields under `vaultId` so a subsequent
   *  `restoreSession(vaultId)` can short-circuit the login flow. */
  rememberSession: (vaultId: string) => void;
  /** Try to restore the cached session for `vaultId`. Validates the
   *  stashed token against the currently-open vault via
   *  `login_token`, which re-installs it in the Rust-side AppState;
   *  returns true on success. Returns false silently (and drops the
   *  stale cache entry) if the token no longer authenticates. */
  restoreSession: (vaultId: string) => Promise<boolean>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  policies: [],
  isAuthenticated: false,
  // Start "bootstrapping" so the route guard does not bounce a
  // returning user to `/login` during the first paint while the
  // Rust query is still in flight. App.tsx clears this on completion.
  bootstrapping: true,
  entityId: "",
  principal: "",
  sessions: {},
  setAuth: (token, policies) =>
    set({ token, policies, isAuthenticated: true, bootstrapping: false }),
  clearAuth: () =>
    set({
      token: null,
      policies: [],
      isAuthenticated: false,
      bootstrapping: false,
      entityId: "",
      principal: "",
    }),
  bootstrapAuth: async () => {
    if (get().isAuthenticated) {
      set({ bootstrapping: false });
      return;
    }
    try {
      const token = await api.getCurrentToken();
      if (!token) {
        set({ bootstrapping: false });
        return;
      }
      // Re-run the token validation path against the live AppState.
      // Cheap (one `auth/token/lookup-self` round-trip) and returns
      // the current effective policy list — important because the
      // operator may have edited policies between webview reloads.
      const resp = await api.loginToken(token);
      set({
        token: resp.token,
        policies: resp.policies,
        isAuthenticated: true,
        bootstrapping: false,
      });
      // Best-effort follow-up: populate entity_id for owner-aware UI.
      void get().loadEntity();
    } catch {
      // The Rust side has no token, or it no longer authenticates.
      // Leave the store unauthenticated; the route guard will bounce
      // protected pages to `/login`.
      set({ bootstrapping: false });
    }
  },
  loadEntity: async () => {
    if (!get().isAuthenticated) return;
    try {
      const self = await api.getEntitySelf();
      set({
        entityId: self.entity_id ?? "",
        principal: self.username || self.role_name || "",
      });
    } catch {
      // Best-effort: leave entityId empty. Owner-aware UI will show
      // "unknown" rather than silently claiming nothing is owned.
    }
  },
  rememberSession: (vaultId) => {
    if (!vaultId) return;
    const s = get();
    if (!s.token || !s.isAuthenticated) return;
    set({
      sessions: {
        ...s.sessions,
        [vaultId]: {
          token: s.token,
          policies: s.policies,
          entityId: s.entityId,
          principal: s.principal,
          rememberedAt: Math.floor(Date.now() / 1000),
        },
      },
    });
  },
  restoreSession: async (vaultId) => {
    const s = get();
    const cached = s.sessions[vaultId];
    if (!cached) return false;
    try {
      // Re-install the cached token into the Rust-side AppState and
      // prove it still authenticates against the newly-opened vault.
      // `loginToken` calls `auth/token/lookup-self` which any valid
      // token can serve and an invalid one cannot — so a failure
      // here means the token was revoked / expired between sessions.
      const resp = await api.loginToken(cached.token);
      set({
        token: resp.token,
        policies: resp.policies.length > 0 ? resp.policies : cached.policies,
        isAuthenticated: true,
        bootstrapping: false,
        entityId: cached.entityId,
        principal: cached.principal,
      });
      return true;
    } catch {
      // Stale entry — drop it so we don't keep trying on every switch.
      const next = { ...s.sessions };
      delete next[vaultId];
      set({ sessions: next });
      return false;
    }
  },
}));
