/**
 * The two session-workspace preferences a session pane reads while it
 * forwards input (T38 Phase 4): the chord overrides and the multi-line
 * paste guard.
 *
 * Read once per window from the GUI preferences file, in session windows
 * and in the workspace alike. Until the read lands — and if it fails — the
 * safe values are in force: the default chord table and the paste guard
 * ON. A preferences file that cannot be read never turns the guard off.
 */

import { useEffect, useState } from "react";

import { getSessionWorkspacePrefs } from "./api";
import { setChordOverrides, type BindingProblem } from "./reservedChords";

export interface SessionInputPrefs {
  confirmMultilinePaste: boolean;
  chordProblems: readonly BindingProblem[];
  /** The layout mode, for offering "Move to workspace" in a session's own
   *  window (T38 Phase 6). `null` until read — and if unreadable — so the
   *  action is not offered on a guess; the host refuses it in `windows`
   *  mode regardless. */
  layoutMode: "workspace" | "windows" | null;
}

const SAFE_DEFAULTS: SessionInputPrefs = { confirmMultilinePaste: true, chordProblems: [], layoutMode: null };

let current: SessionInputPrefs = SAFE_DEFAULTS;
let loading: Promise<SessionInputPrefs> | null = null;
const subscribers = new Set<(p: SessionInputPrefs) => void>();

export function loadSessionInputPrefs(): Promise<SessionInputPrefs> {
  if (!loading) {
    loading = getSessionWorkspacePrefs().then(
      (prefs) => {
        const chordProblems = setChordOverrides(prefs?.chord_overrides ?? {});
        if (chordProblems.length > 0) {
          // eslint-disable-next-line no-console
          console.warn("session workspace: chord overrides not applied", chordProblems);
        }
        current = {
          // Only an explicit `false` turns the guard off.
          confirmMultilinePaste: prefs?.confirm_multiline_paste !== false,
          chordProblems,
          layoutMode: prefs?.layout_mode === "workspace" || prefs?.layout_mode === "windows" ? prefs.layout_mode : null,
        };
        subscribers.forEach((s) => s(current));
        return current;
      },
      (e: unknown) => {
        // eslint-disable-next-line no-console
        console.warn("session workspace: preferences unreadable; using the default chords and the paste guard", e);
        return current;
      },
    );
  }
  return loading;
}

export function currentSessionInputPrefs(): SessionInputPrefs {
  return current;
}

/** Load once per window and re-render when the values land. */
export function useSessionInputPrefs(): SessionInputPrefs {
  const [prefs, setPrefs] = useState<SessionInputPrefs>(current);
  useEffect(() => {
    subscribers.add(setPrefs);
    void loadSessionInputPrefs().then(setPrefs);
    return () => {
      subscribers.delete(setPrefs);
    };
  }, []);
  return prefs;
}

/** Tests only: forget what was loaded. */
export function resetSessionInputPrefsForTests(): void {
  current = SAFE_DEFAULTS;
  loading = null;
  subscribers.clear();
  setChordOverrides({});
}
