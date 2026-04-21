import { create } from "zustand";
import * as api from "../lib/api";

interface AuthState {
  token: string | null;
  policies: string[];
  isAuthenticated: boolean;
  /** Stable entity_id for the logged-in user, used by ownership and sharing features. */
  entityId: string;
  /** Principal username (UserPass) or role name (AppRole); for display only. */
  principal: string;
  setAuth: (token: string, policies: string[]) => void;
  clearAuth: () => void;
  /** Populate `entityId` + `principal` by calling `identity/entity/self`. */
  loadEntity: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  policies: [],
  isAuthenticated: false,
  entityId: "",
  principal: "",
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
}));
