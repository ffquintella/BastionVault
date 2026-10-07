/**
 * The session-workspace preferences as Settings edits them (T38). One
 * copy per window, shared by the Session layout card and the Session
 * keyboard card, so saving one card never writes back the other's stale
 * values.
 */

import { create } from "zustand";

import { getSessionWorkspacePrefs, setSessionWorkspacePrefs, type SessionWorkspacePrefs } from "../lib/api";
import { extractError } from "../lib/error";

interface SessionPrefsState {
  prefs: SessionWorkspacePrefs | null;
  loadError: string;
  loading: Promise<void> | null;
  /** Read the preferences once; later calls share the first. */
  load: () => Promise<void>;
  /** Merge `patch`, save (the host validates), then publish. Throws the
   *  host's refusal; nothing changes locally on failure. */
  update: (patch: Partial<SessionWorkspacePrefs>) => Promise<void>;
  reset: () => void;
}

export const useSessionPrefsStore = create<SessionPrefsState>((set, get) => ({
  prefs: null,
  loadError: "",
  loading: null,
  load() {
    const { prefs, loading } = get();
    if (prefs) return Promise.resolve();
    if (loading) return loading;
    const p = getSessionWorkspacePrefs().then(
      (loaded) => {
        if (!loaded || typeof loaded.layout_mode !== "string") {
          set({ loadError: "The session preferences reply was empty or malformed.", loading: null });
          return;
        }
        set({
          prefs: {
            ...loaded,
            // A host older than Phase 4 sends neither key.
            confirm_multiline_paste: loaded.confirm_multiline_paste !== false,
            chord_overrides: loaded.chord_overrides ?? {},
            // A host older than Phase 6 sends no `replay_buffer`: off.
            replay_buffer: loaded.replay_buffer === true,
          },
          loadError: "",
          loading: null,
        });
      },
      (e: unknown) => set({ loadError: extractError(e), loading: null }),
    );
    set({ loading: p });
    return p;
  },
  async update(patch) {
    const current = get().prefs;
    if (!current) throw new Error("session preferences are not loaded");
    const next = { ...current, ...patch };
    await setSessionWorkspacePrefs(next);
    set({ prefs: next });
  },
  reset() {
    set({ prefs: null, loadError: "", loading: null });
  },
}));
