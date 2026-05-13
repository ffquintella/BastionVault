import { create } from "zustand";
import type {
  VaultMode,
  VaultStatus,
  RemoteProfile,
  SelectedNode,
} from "../lib/types";

interface VaultState {
  mode: VaultMode;
  status: VaultStatus | null;
  remoteProfile: RemoteProfile | null;
  /**
   * Cluster-discovery result for the live remote connection. `null`
   * when the operator used a literal URL or disabled discovery — the
   * status bar then falls back to showing just the cluster name.
   */
  selectedNode: SelectedNode | null;
  setMode: (mode: VaultMode) => void;
  setStatus: (status: VaultStatus) => void;
  setRemoteProfile: (profile: RemoteProfile | null) => void;
  setSelectedNode: (node: SelectedNode | null) => void;
  reset: () => void;
}

export const useVaultStore = create<VaultState>((set) => ({
  mode: "Embedded",
  status: null,
  remoteProfile: null,
  selectedNode: null,
  setMode: (mode) => set({ mode }),
  setStatus: (status) => set({ status }),
  setRemoteProfile: (remoteProfile) => set({ remoteProfile }),
  setSelectedNode: (selectedNode) => set({ selectedNode }),
  reset: () =>
    set({
      mode: "Embedded",
      status: null,
      remoteProfile: null,
      selectedNode: null,
    }),
}));
