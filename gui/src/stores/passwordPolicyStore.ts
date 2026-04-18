import { create } from "zustand";
import * as api from "../lib/api";
import { DEFAULT_PASSWORD_POLICY, type PasswordPolicy } from "../lib/types";

interface PasswordPolicyState {
  policy: PasswordPolicy;
  /** True once `load()` has resolved (success or fall back to defaults). */
  loaded: boolean;
  /**
   * In-flight promise for the current `load()` call, so overlapping calls
   * during render (e.g. Settings page + PasswordGenerator both mounting)
   * do not fire duplicate IPC requests. Cleared once the promise settles.
   */
  loading: Promise<void> | null;
  /** Read the policy from the backend preferences file. Idempotent. */
  load: () => Promise<void>;
  /** Persist a new policy and update local state. */
  update: (policy: PasswordPolicy) => Promise<void>;
}

export const usePasswordPolicyStore = create<PasswordPolicyState>((set, get) => ({
  policy: DEFAULT_PASSWORD_POLICY,
  loaded: false,
  loading: null,
  async load() {
    const existing = get().loading;
    if (existing) return existing;
    const p = (async () => {
      try {
        const fetched = await api.getPasswordPolicy();
        set({ policy: fetched, loaded: true });
      } catch {
        set({ policy: DEFAULT_PASSWORD_POLICY, loaded: true });
      } finally {
        set({ loading: null });
      }
    })();
    set({ loading: p });
    return p;
  },
  async update(policy) {
    await api.setPasswordPolicy(policy);
    set({ policy, loaded: true });
  },
}));
