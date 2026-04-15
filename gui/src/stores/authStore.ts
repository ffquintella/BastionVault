import { create } from "zustand";

interface AuthState {
  token: string | null;
  policies: string[];
  isAuthenticated: boolean;
  setAuth: (token: string, policies: string[]) => void;
  clearAuth: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  policies: [],
  isAuthenticated: false,
  setAuth: (token, policies) =>
    set({ token, policies, isAuthenticated: true }),
  clearAuth: () =>
    set({ token: null, policies: [], isAuthenticated: false }),
}));
