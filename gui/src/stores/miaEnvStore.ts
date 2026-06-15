import { create } from "zustand";

/**
 * The MIA environment selected in the GUI, shared across every screen that
 * dials a FerroGate MIA (the Machines Config + Machine Login tabs and the
 * connect-time machine gate). Lifting it out of any single page's React state
 * is what makes a selection on one screen the default on the others.
 *
 * `environment` is a tri-state:
 *   - `null`  — nothing chosen yet; screens fall back to the saved config /
 *               server-advertised value and seed this via `seedEnvironment`.
 *   - `""`    — an explicit "(default)" choice → the default `mia.toml`.
 *   - `"hml"` — an explicit environment → `mia-<env>.toml`.
 *
 * `setEnvironment` records an explicit operator choice (and therefore wins over
 * later seeds); `seedEnvironment` only fills the initial default and never
 * clobbers an explicit choice.
 */
interface MiaEnvState {
  environment: string | null;
  /** Record an explicit operator selection (sticks across navigation). */
  setEnvironment: (env: string) => void;
  /** Seed the default from config/server — no-op once a value is set. */
  seedEnvironment: (env: string) => void;
  /** Forget the selection (e.g. on disconnect) so the next deployment re-seeds. */
  reset: () => void;
}

export const useMiaEnvStore = create<MiaEnvState>((set, get) => ({
  environment: null,
  setEnvironment: (environment) => set({ environment }),
  seedEnvironment: (environment) => {
    if (get().environment === null) set({ environment });
  },
  reset: () => set({ environment: null }),
}));
