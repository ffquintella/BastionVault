import { create } from "zustand";
import * as api from "../lib/api";

/**
 * Snapshot of the post-login auth state for a single vault. Kept in
 * memory (not persisted to disk) so closing the GUI forgets every
 * cached token — matching the operator's mental model that tokens
 * are ephemeral to the running process.
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
  entityId: "",
  principal: "",
  sessions: {},
  setAuth: (token, policies) =>
    set({ token, policies, isAuthenticated: true }),
  clearAuth: () =>
    set({
      token: null,
      policies: [],
      isAuthenticated: false,
      entityId: "",
      principal: "",
    }),
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
