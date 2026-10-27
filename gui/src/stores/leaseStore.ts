import { create } from "zustand";
import { useAuthStore } from "./authStore";

/**
 * Leases this window issued through "Generate credential" (T62). The host has
 * no endpoint that lists live leases, so the Leases page can show only these.
 * In memory only, cleared on logout, and never the credential: lease metadata.
 */
export interface IssuedLease {
  lease_id: string;
  mount: string;
  role: string;
  /** Epoch ms of the last issue or renewal. */
  since: number;
  /** Seconds from `since`; null when the host did not report it. */
  lease_duration: number | null;
  renewable: boolean;
  /** A credential-cache hit: the lease is shared with an earlier read. */
  shared: boolean;
}

interface LeaseState {
  issued: IssuedLease[];
  record: (lease: IssuedLease) => void;
  renewed: (leaseId: string, leaseDuration: number | null, renewable: boolean | null) => void;
  forget: (leaseId: string) => void;
  clear: () => void;
}

export const useLeaseStore = create<LeaseState>((set) => ({
  issued: [],
  record: (lease) =>
    set((s) => ({
      issued: [lease, ...s.issued.filter((l) => l.lease_id !== lease.lease_id)],
    })),
  renewed: (leaseId, leaseDuration, renewable) =>
    set((s) => ({
      issued: s.issued.map((l) =>
        l.lease_id === leaseId
          ? {
              ...l,
              since: Date.now(),
              lease_duration: leaseDuration,
              renewable: renewable ?? l.renewable,
            }
          : l,
      ),
    })),
  forget: (leaseId) =>
    set((s) => ({ issued: s.issued.filter((l) => l.lease_id !== leaseId) })),
  clear: () => set({ issued: [] }),
}));

// Another operator signing in on this window must not see these lease ids.
useAuthStore.subscribe((state, prev) => {
  if (prev.isAuthenticated && !state.isAuthenticated) {
    useLeaseStore.getState().clear();
  }
});
