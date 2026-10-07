/**
 * Session Workspace state (T38 Phase 3): the layout (pure reducer in
 * `lib/sessionLayout`), the per-session data a pane needs to render, and
 * each pane's live status. Lives only in the `session-workspace` window.
 *
 * Holds tokens and event names — never a credential, never session output.
 */

import { create } from "zustand";

import type { OpenSessionListing } from "../lib/api";
import { SESSION_WORKSPACE_LABEL } from "../lib/api";
import {
  emptyLayout,
  layoutReducer,
  paneOfToken,
  type LayoutAction,
  type PaneKind,
  type WorkspaceLayout,
} from "../lib/sessionLayout";
import type { SessionPaneStatus } from "../components/session/SessionPaneHeader";

interface SessionWorkspaceState {
  layout: WorkspaceLayout;
  /** token → the host's descriptor for it. */
  sessions: Record<string, OpenSessionListing>;
  /** token → pane status, for the tab strip. */
  status: Record<string, SessionPaneStatus>;
  /** Tokens whose host element a layout slot has put in the document; a
   *  pane is mounted only then, so xterm never opens on a detached node. */
  hostReady: Record<string, true>;
  /** Tokens whose pane left this window (closed, or moved to another
   *  window), with the holder epoch it left at. A listing at that epoch —
   *  fetched before the close or move landed — never resurrects the pane;
   *  a session moved back here arrives at a later epoch and is adopted. */
  retired: Record<string, number>;
  dispatch: (action: LayoutAction) => void;
  /** Take the host's session list and place every session attached to
   *  this window that has no pane yet — into its restore placeholder when
   *  it names one. Returns the tokens placed. */
  adopt: (rows: readonly OpenSessionListing[]) => string[];
  setStatus: (token: string, status: SessionPaneStatus) => void;
  markHostReady: (token: string) => void;
  /** Forget a session whose pane has been removed from the layout. */
  forget: (token: string) => void;
  reset: () => void;
}

function paneKind(protocol: string): PaneKind | null {
  return protocol === "ssh" || protocol === "rdp" ? protocol : null;
}

export const useSessionWorkspaceStore = create<SessionWorkspaceState>((set, get) => ({
  layout: emptyLayout(),
  sessions: {},
  status: {},
  hostReady: {},
  retired: {},

  dispatch(action) {
    const current = get().layout;
    const next = layoutReducer(current, action);
    if (next !== current) set({ layout: next });
  },

  adopt(rows) {
    const { sessions, layout, retired } = get();
    const fresh = rows
      .filter((r) => r.attached_to === SESSION_WORKSPACE_LABEL)
      .filter((r) => !sessions[r.token] && !paneOfToken(layout, r.token))
      .filter((r) => retired[r.token] === undefined || (r.attach_epoch ?? 0) > retired[r.token])
      .filter((r) => paneKind(r.protocol) !== null)
      // Deterministic order: as opened, then by token.
      .sort((a, b) => a.opened_at.localeCompare(b.opened_at) || a.token.localeCompare(b.token));
    if (fresh.length === 0) return [];
    let next = layout;
    const nextSessions = { ...sessions };
    for (const row of fresh) {
      nextSessions[row.token] = row;
      const session = { token: row.token, protocol: paneKind(row.protocol)!, label: row.label };
      const filled = row.pane_ref ? layoutReducer(next, { type: "fillPlaceholder", paneRef: row.pane_ref, session }) : next;
      next = filled !== next ? filled : layoutReducer(next, { type: "place", session, placement: row.placement });
    }
    set({ layout: next, sessions: nextSessions });
    return fresh.map((r) => r.token);
  },

  setStatus(token, status) {
    if (get().status[token] === status) return;
    set((s) => ({ status: { ...s.status, [token]: status } }));
  },

  markHostReady(token) {
    if (get().hostReady[token]) return;
    set((s) => ({ hostReady: { ...s.hostReady, [token]: true } }));
  },

  forget(token) {
    set((s) => {
      const sessions = { ...s.sessions };
      const status = { ...s.status };
      const hostReady = { ...s.hostReady };
      const epoch = s.sessions[token]?.attach_epoch ?? 0;
      delete sessions[token];
      delete status[token];
      delete hostReady[token];
      return { sessions, status, hostReady, retired: { ...s.retired, [token]: Math.max(epoch, s.retired[token] ?? 0) } };
    });
  },

  reset() {
    set({ layout: emptyLayout(), sessions: {}, status: {}, hostReady: {}, retired: {} });
  },
}));
