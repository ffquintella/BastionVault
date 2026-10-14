import { create } from "zustand";
import * as api from "../lib/api";
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
  /**
   * Re-hydrate the connection fields from the Rust-side `AppState`.
   * This store is in-memory only, so any `location.reload()` (the
   * namespace switcher reloads after every switch, Vite HMR, the MCP
   * screenshot path) resets it to the `Embedded` default and the
   * sidebar would label a live remote connection "Local". The Rust
   * process owns the connection across webview reloads, so read it
   * back on every boot — same contract as `bootstrapAuth`.
   */
  bootstrapConnection: () => Promise<void>;
  reset: () => void;
}

export const useVaultStore = create<VaultState>((set, get) => ({
  mode: "Embedded",
  status: null,
  remoteProfile: null,
  selectedNode: null,
  setMode: (mode) => set({ mode }),
  setStatus: (status) => set({ status }),
  setRemoteProfile: (remoteProfile) => set({ remoteProfile }),
  setSelectedNode: (selectedNode) => set({ selectedNode }),
  bootstrapConnection: async () => {
    // A connect flow that already populated the store wins.
    if (get().remoteProfile) return;
    try {
      const mode = await api.getMode();
      if (mode !== "Remote") {
        set({ mode });
        return;
      }
      const [remoteProfile, selectedNode] = await Promise.all([
        api.getRemoteProfile(),
        api.getSelectedNode().catch(() => null),
      ]);
      // Re-check: ConnectPage may have finished while we awaited.
      if (get().remoteProfile) return;
      set({ mode, remoteProfile, selectedNode });
    } catch {
      // Rust side unreachable: keep the defaults. The label is display
      // only; every request goes through the Rust-held client anyway.
    }
  },
  reset: () =>
    set({
      mode: "Embedded",
      status: null,
      remoteProfile: null,
      selectedNode: null,
    }),
}));
