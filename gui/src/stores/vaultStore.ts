import { create } from "zustand";
import type { VaultMode, VaultStatus, RemoteProfile } from "../lib/types";

interface VaultState {
  mode: VaultMode;
  status: VaultStatus | null;
  remoteProfile: RemoteProfile | null;
  setMode: (mode: VaultMode) => void;
  setStatus: (status: VaultStatus) => void;
  setRemoteProfile: (profile: RemoteProfile | null) => void;
  reset: () => void;
}

export const useVaultStore = create<VaultState>((set) => ({
  mode: "Embedded",
  status: null,
  remoteProfile: null,
  setMode: (mode) => set({ mode }),
  setStatus: (status) => set({ status }),
  setRemoteProfile: (remoteProfile) => set({ remoteProfile }),
  reset: () => set({ mode: "Embedded", status: null, remoteProfile: null }),
}));
