/**
 * Session Workspace window (T38, features/session-workspace.md): the
 * `/workspace` route of the singleton `session-workspace` window. Tabs,
 * each a binary split of SSH / RDP panes.
 *
 * How sessions arrive. The host registers a session as attached to this
 * window *before* it says anything, then sends `session://placed` with no
 * payload. This window answers every such event — and its own first load
 * — by reading `session_list_open` and placing every session attached to
 * it that has no pane yet, as a tab or a split per the placement recorded
 * at open, or into the restore placeholder it names. A session placed
 * while the window was still loading is picked up by that first read.
 *
 * DOM continuity (§2). Panes render through portals into long-lived host
 * elements (`lib/paneHosts`), keyed by token, from a list whose parent
 * never moves; the layout only moves those host elements between slots.
 * Splitting, zooming, closing a neighbour or switching tabs never rebuilds
 * a terminal. Background tabs are `display: none`, not unmounted.
 *
 * Teardown. A pane's close button, the tab's close button and the
 * close-pane chord ask first when a session is still live, then call
 * `session_close` and drop the pane only once the host has stopped the
 * session. Closing the last tab closes the window. Closing the window
 * natively (its close button, Alt+F4) asks first too when a session is
 * live (T108, `lib/sessionWindowClose`); the host stops every session
 * still attached to the window once it is destroyed.
 *
 * Layout persistence (Phase 5). The layout skeleton is saved, debounced,
 * whenever its shape changes; the host turns each pane's token into the
 * resource / profile / namespace it was opened from and writes nothing
 * else. The layout saved by an earlier run is read once when the window
 * opens and offered — never applied — as "Restore last layout": each pane
 * is re-opened through the normal connect path, MFA included, into a
 * placeholder holding its place in the saved shape.
 *
 * Moving (Phase 6). "Pop out" (or dragging a tab out of the strip) moves a
 * live session to a window of its own; the session keeps running.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { listen } from "@tauri-apps/api/event";

import { useConnectMfa } from "../components/ConnectMfaPrompt";
import { CloseConfirm } from "../components/session/CloseConfirm";
import { RdpPane } from "../components/session/RdpPane";
import { SshPane } from "../components/session/SshPane";
import type { SessionPaneStatus } from "../components/session/SessionPaneHeader";
import { SplitView } from "../components/session/workspace/SplitView";
import { TabStrip } from "../components/session/workspace/TabStrip";
import {
  SESSION_PLACED_EVENT,
  sessionClose,
  sessionLayoutForget,
  sessionLayoutGet,
  sessionLayoutSave,
  sessionListOpen,
  sessionMove,
  type OpenSessionListing,
  type SavedLayout,
} from "../lib/api";
import { openConnectPalette } from "../lib/connectPaletteEvents";
import { extractError } from "../lib/error";
import { paneHost, releasePaneHost } from "../lib/paneHosts";
import { activeChordBindings, formatChord, matchChord, type WorkspaceAction } from "../lib/reservedChords";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";
import { useSessionInputPrefs } from "../lib/sessionInputPrefs";
import { isLiveStatus, useWindowCloseGuard } from "../lib/sessionWindowClose";
import {
  activeTab,
  allPanes,
  hasPlaceholders,
  leaves,
  placeholders,
  restoreRefusal,
  savedPanes,
  skeleton,
  type Direction,
  type PaneNode,
} from "../lib/sessionLayout";
import { reopenSavedPane } from "../lib/sessionRestore";
import { useSessionWorkspaceStore } from "../stores/sessionWorkspaceStore";

/** How long the layout must hold still before it is saved. */
export const LAYOUT_SAVE_DEBOUNCE_MS = 1000;

/** A text field that is not a terminal: workspace chords are swallowed
 *  there (so ⌘W cannot reach the native Close Window) but not run. */
function isForeignInput(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.classList.contains("xterm-helper-textarea")) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

function chordHint(action: WorkspaceAction): string {
  const b = activeChordBindings();
  const c = b.byAction.get(action);
  return c ? formatChord(c, b.platform) : "";
}

/** A pane whose session is (or may still be) live: closing it ends that
 *  session, so the workspace asks first. A pane that has not reported a
 *  status yet counts as connecting. */
function isLive(pane: PaneNode, status: Readonly<Record<string, SessionPaneStatus>>): boolean {
  if (pane.pending || pane.protocol === "replay") return false;
  return isLiveStatus(status[pane.token]);
}

/** Labels of every live session in the workspace — what closing the whole
 *  window would end. Read from the store, so a session placed while the
 *  window-close confirmation is open is named in it. */
function liveSessionLabels(): string[] {
  const st = useSessionWorkspaceStore.getState();
  return allPanes(st.layout)
    .filter((p) => isLive(p, st.status))
    .map((p) => p.label);
}

const FOCUS: Partial<Record<WorkspaceAction, Direction>> = {
  focusLeft: "left",
  focusRight: "right",
  focusUp: "up",
  focusDown: "down",
};
const RESIZE: Partial<Record<WorkspaceAction, Direction>> = {
  resizeLeft: "left",
  resizeRight: "right",
  resizeUp: "up",
  resizeDown: "down",
};

interface PendingClose {
  paneIds: string[];
  /** Labels of the live sessions closing would end. */
  labels: string[];
}

/** The layout an earlier run saved, held for this window's lifetime so it
 *  stays restorable after the first save of this run replaces the file. */
interface PreviousRun {
  vaultId: string;
  layout: SavedLayout;
}

function findPane(paneId: string): PaneNode | undefined {
  return allPanes(useSessionWorkspaceStore.getState().layout).find((p) => p.id === paneId);
}

export function SessionWorkspaceWindow() {
  const layout = useSessionWorkspaceStore((s) => s.layout);
  const sessions = useSessionWorkspaceStore((s) => s.sessions);
  const status = useSessionWorkspaceStore((s) => s.status);
  const hostReady = useSessionWorkspaceStore((s) => s.hostReady);
  const dispatch = useSessionWorkspaceStore((s) => s.dispatch);
  const markHostReady = useSessionWorkspaceStore((s) => s.markHostReady);
  const [error, setError] = useState("");
  const rootRef = useRef<HTMLDivElement | null>(null);
  const aliveRef = useRef(true);
  const { gateConnect, mfaPrompt } = useConnectMfa();
  const gateRef = useRef(gateConnect);
  gateRef.current = gateConnect;

  const [previousRun, setPreviousRun] = useState<PreviousRun | null>(null);
  // No save until the earlier run's layout has been read: the first save
  // of this run replaces it in the file.
  const [previousLoaded, setPreviousLoaded] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const restoringRef = useRef(false);
  const [restoreRound, setRestoreRound] = useState(0);
  const awaitingBaseline = useRef(false);
  const savedSignature = useRef<string | null>(null);
  const lastSaveError = useRef("");
  const [pendingClose, setPendingClose] = useState<PendingClose | null>(null);
  const pendingCloseRef = useRef<PendingClose | null>(null);
  pendingCloseRef.current = pendingClose;

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  // One heartbeat for the whole window, not one per pane.
  useSessionHeartbeat(true);
  // The native close (close button, Alt+F4) asks first while a session is
  // live (T108).
  const closeGuard = useWindowCloseGuard(liveSessionLabels);
  const windowAskingRef = useRef(false);
  windowAskingRef.current = closeGuard.asking;
  useEffect(() => {
    // The window question replaces a pane question that was open.
    if (closeGuard.asking) setPendingClose(null);
  }, [closeGuard.asking]);
  const { error: closeError, dismissError: dismissCloseError } = closeGuard;
  useEffect(() => {
    if (!closeError) return;
    setError(closeError);
    dismissCloseError();
  }, [closeError, dismissCloseError]);
  // Chord overrides + the paste guard, read once for this window.
  useSessionInputPrefs();

  const reconcile = useCallback(async () => {
    try {
      const rows = await sessionListOpen();
      if (!aliveRef.current) return;
      useSessionWorkspaceStore.getState().adopt(rows);
    } catch (e) {
      if (aliveRef.current) setError(`Could not read the open sessions: ${extractError(e)}`);
    }
  }, []);

  // Adopt sessions: on load (once the listener is live) and on every
  // `session://placed`.
  useEffect(() => {
    let alive = true;
    const unlisten = listen(SESSION_PLACED_EVENT, () => void reconcile());
    void unlisten.then(() => {
      if (alive) void reconcile();
    });
    return () => {
      alive = false;
      void unlisten.then((u) => u());
    };
  }, [reconcile]);

  // The layout an earlier run saved: read once, offered, never applied.
  useEffect(() => {
    let alive = true;
    sessionLayoutGet().then(
      (view) => {
        if (!alive) return;
        if (view?.layout && savedPanes(view.layout).length > 0) {
          setPreviousRun({ vaultId: view.vault_id, layout: view.layout });
        }
        setPreviousLoaded(true);
      },
      (e: unknown) => {
        if (!alive) return;
        setError(`Could not read the saved layout: ${extractError(e)}`);
        setPreviousLoaded(true);
      },
    );
    return () => {
      alive = false;
    };
  }, []);

  // A token that left the layout: forget it and drop its host element,
  // after the commit that unmounted its portal.
  const tokensInLayout = useMemo(() => new Set(allPanes(layout).map((p) => p.token)), [layout]);
  const previousTokens = useRef<Set<string>>(new Set());
  useEffect(() => {
    for (const token of previousTokens.current) {
      if (!tokensInLayout.has(token)) {
        useSessionWorkspaceStore.getState().forget(token);
        releasePaneHost(token);
      }
    }
    previousTokens.current = tokensInLayout;
  }, [tokensInLayout]);

  // The last tab closed: so does the window. Every session in it has
  // already been stopped, so there is nothing to ask.
  const { closeNow } = closeGuard;
  useEffect(() => {
    if (!layout.closeWindow) return;
    void closeNow();
  }, [layout.closeWindow, closeNow]);

  // Save the layout skeleton when its shape changes (debounced). Not while
  // a restore is laying out placeholders, never an empty layout, and not
  // the shape a restore just produced — a partial restore must not replace
  // the saved layout until the operator changes something.
  useEffect(() => {
    if (!previousLoaded || restoringRef.current || hasPlaceholders(layout)) return;
    const tabs = skeleton(layout);
    const signature = JSON.stringify(tabs);
    if (awaitingBaseline.current) {
      awaitingBaseline.current = false;
      savedSignature.current = signature;
      return;
    }
    if (tabs.length === 0 || signature === savedSignature.current) return;
    const timer = setTimeout(() => {
      sessionLayoutSave(tabs).then(
        () => {
          savedSignature.current = signature;
          lastSaveError.current = "";
        },
        (e: unknown) => {
          const message = `The session layout was not saved: ${extractError(e)}`;
          if (message !== lastSaveError.current && aliveRef.current) {
            lastSaveError.current = message;
            setError(message);
          }
        },
      );
    }, LAYOUT_SAVE_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [layout, restoreRound, previousLoaded]);

  const restore = useCallback(async () => {
    if (restoringRef.current || !previousRun) return;
    let view;
    try {
      view = await sessionLayoutGet();
    } catch (e) {
      setError(`Could not read the active namespace: ${extractError(e)}`);
      return;
    }
    if (view.vault_id !== previousRun.vaultId) {
      setError("The saved layout belongs to another vault than the one now open; it was not restored.");
      return;
    }
    const refusal = restoreRefusal(previousRun.layout, view.active_namespace);
    if (refusal) {
      setError(refusal);
      return;
    }
    restoringRef.current = true;
    setRestoring(true);
    setError("");
    setPreviousRun(null);
    const store = useSessionWorkspaceStore.getState;
    const before = new Set(placeholders(store().layout).map((p) => p.pending!.ref));
    store().dispatch({ type: "restore", layout: previousRun.layout });
    const mine = placeholders(store().layout)
      .map((p) => p.pending!)
      .filter((p) => !before.has(p.ref));
    const failures: string[] = [];
    for (const pending of mine) {
      if (!aliveRef.current) break;
      // The operator may have closed the placeholder meanwhile.
      if (!placeholders(store().layout).some((p) => p.pending?.ref === pending.ref)) continue;
      store().dispatch({ type: "placeholderState", paneRef: pending.ref, state: "opening" });
      try {
        await reopenSavedPane(pending, { gateConnect: (...a) => gateRef.current(...a) });
        // Fill the placeholder now rather than on the event, so the next
        // pane's turn starts from the restored shape.
        await reconcile();
      } catch (e) {
        failures.push(`${pending.resource_name}: ${extractError(e)}`);
      }
      // Failed — or opened but not listed yet, in which case the next
      // `session://placed` places it as a tab.
      store().dispatch({ type: "dropPlaceholder", paneRef: pending.ref });
    }
    restoringRef.current = false;
    awaitingBaseline.current = true;
    if (!aliveRef.current) return;
    setRestoring(false);
    setRestoreRound((n) => n + 1);
    if (failures.length > 0) {
      setError(`${failures.length} of ${mine.length} panes were not restored — ${failures.join("; ")}`);
    }
  }, [previousRun, reconcile]);

  const forgetSaved = useCallback(async () => {
    try {
      await sessionLayoutForget();
      setPreviousRun(null);
    } catch (e) {
      setError(`Could not forget the saved layout: ${extractError(e)}`);
    }
  }, []);

  const closePaneNow = useCallback(async (paneId: string) => {
    const pane = findPane(paneId);
    if (!pane) return;
    if (pane.pending) {
      // A placeholder skipped mid-restore: no session to stop, and the
      // window stays open even if it was the last one.
      useSessionWorkspaceStore.getState().dispatch({ type: "dropPlaceholder", paneRef: pane.pending.ref });
      return;
    }
    try {
      await sessionClose(pane.token);
    } catch (e) {
      // Keep the pane: the host did not stop the session.
      setError(`${pane.label}: ${extractError(e)}`);
      return;
    }
    useSessionWorkspaceStore.getState().dispatch({ type: "closePane", paneId });
  }, []);

  /** Close panes, asking first if that would end a live session. */
  const requestClose = useCallback(
    (paneIds: string[]) => {
      const panes = paneIds.map(findPane).filter((p): p is PaneNode => !!p);
      const st = useSessionWorkspaceStore.getState().status;
      const live = panes.filter((p) => isLive(p, st));
      if (live.length === 0) {
        void (async () => {
          for (const p of panes) await closePaneNow(p.id);
        })();
        return;
      }
      setPendingClose({ paneIds: panes.map((p) => p.id), labels: live.map((p) => p.label) });
    },
    [closePaneNow],
  );

  const confirmClose = useCallback(async () => {
    const pc = pendingCloseRef.current;
    setPendingClose(null);
    if (!pc) return;
    for (const id of pc.paneIds) await closePaneNow(id);
  }, [closePaneNow]);

  const closeTab = useCallback(
    (tabId: string) => {
      const tab = useSessionWorkspaceStore.getState().layout.tabs.find((t) => t.id === tabId);
      if (tab) requestClose(leaves(tab.root).map((p) => p.id));
    },
    [requestClose],
  );

  /** Move a live session to a window of its own; it keeps running. A pane
   *  whose session already ended stays: its new window would never hear
   *  the closed notice. */
  const movePaneOut = useCallback(async (paneId: string) => {
    const pane = findPane(paneId);
    if (!pane || !isLive(pane, useSessionWorkspaceStore.getState().status)) return;
    try {
      await sessionMove(pane.token, "own-window");
    } catch (e) {
      setError(`${pane.label}: ${extractError(e)}`);
      return;
    }
    // No `session_close`: the session lives on in its new window.
    useSessionWorkspaceStore.getState().dispatch({ type: "closePane", paneId });
  }, []);

  const tearOffTab = useCallback(
    async (tabId: string) => {
      const tab = useSessionWorkspaceStore.getState().layout.tabs.find((t) => t.id === tabId);
      if (!tab) return;
      for (const pane of leaves(tab.root)) await movePaneOut(pane.id);
    },
    [movePaneOut],
  );

  const releaseKeyboard = useCallback(() => {
    const el = document.activeElement;
    if (el instanceof HTMLElement) el.blur();
    rootRef.current?.focus({ preventScroll: true });
  }, []);

  const runAction = useCallback(
    (action: WorkspaceAction) => {
      const st = useSessionWorkspaceStore.getState();
      const current = activeTab(st.layout);
      if (FOCUS[action]) return st.dispatch({ type: "focusDirection", dir: FOCUS[action]! });
      if (RESIZE[action]) return st.dispatch({ type: "resizeFocused", dir: RESIZE[action]! });
      if (action.startsWith("selectTab")) {
        return st.dispatch({ type: "selectTabIndex", index: Number(action.slice("selectTab".length)) - 1 });
      }
      switch (action) {
        case "newTab":
          return openConnectPalette("workspace-tab");
        case "splitRight":
          return openConnectPalette(current ? "workspace-split-right" : "workspace-tab");
        case "splitDown":
          return openConnectPalette(current ? "workspace-split-down" : "workspace-tab");
        case "closePane":
          if (!current) {
            // No tab, so no session: the window just closes.
            void closeNow();
            return;
          }
          requestClose([current.focusedPaneId]);
          return;
        case "toggleZoom":
          return st.dispatch({ type: "toggleZoom" });
        case "prevTab":
          return st.dispatch({ type: "cycleTab", delta: -1 });
        case "nextTab":
          return st.dispatch({ type: "cycleTab", delta: 1 });
        case "releaseKeyboard":
          return releaseKeyboard();
      }
    },
    [requestClose, releaseKeyboard, closeNow],
  );

  // Workspace chords. Capture phase on the window: the workspace sees a
  // chord before the terminal or the RDP canvas does, so neither forwards
  // it, and `preventDefault` keeps it from the native menu (⌘W would
  // otherwise close the whole window and every session in it). While the
  // close confirmation is open, chords are swallowed and not run.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.defaultPrevented) return;
      const action = matchChord(e);
      if (!action) return;
      e.preventDefault();
      e.stopPropagation();
      if (isForeignInput(e.target) || pendingCloseRef.current || windowAskingRef.current) return;
      runAction(action);
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [runAction]);

  const onRatio = useCallback(
    (tabId: string) => (path: string, ratio: number) => dispatch({ type: "setRatio", tabId, path, ratio }),
    [dispatch],
  );
  const onFocusPane = useCallback((paneId: string) => dispatch({ type: "focusPane", paneId }), [dispatch]);

  const current = activeTab(layout);
  const panes = allPanes(layout);
  const liveLabels = panes.filter((p) => isLive(p, status)).map((p) => p.label);
  const savedCount = previousRun ? savedPanes(previousRun.layout).length : 0;
  const restoreLabel = `Restore last layout (${savedCount} ${savedCount === 1 ? "pane" : "panes"})`;

  return (
    <div
      ref={rootRef}
      tabIndex={-1}
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        width: "100vw",
        minWidth: 0,
        outline: "none",
        background: "#0b0b10",
        color: "#e6e6e6",
      }}
    >
      <TabStrip
        tabs={layout.tabs}
        activeTabId={layout.activeTabId}
        status={status}
        onActivate={(tabId) => dispatch({ type: "activateTab", tabId })}
        onClose={closeTab}
        onMove={(from, to) => dispatch({ type: "moveTab", from, to })}
        onNew={() => openConnectPalette("workspace-tab")}
        newTabHint={chordHint("newTab")}
        onTearOff={(tabId) => void tearOffTab(tabId)}
        trailing={
          previousRun && layout.tabs.length > 0 ? (
            <button
              type="button"
              onClick={() => void restore()}
              disabled={restoring}
              title="Re-open the sessions of the layout saved by an earlier run, each through the normal connect path"
              style={{ ...stripButton, marginLeft: "auto" }}
            >
              {restoreLabel}
            </button>
          ) : null
        }
      />
      {error && (
        <div
          role="alert"
          style={{
            display: "flex",
            gap: 8,
            alignItems: "center",
            padding: "4px 12px",
            background: "#3a1a1a",
            color: "#ffb4b4",
            fontSize: 12,
            minWidth: 0,
          }}
        >
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{error}</span>
          <button
            type="button"
            onClick={() => setError("")}
            style={{ background: "transparent", border: "1px solid #7a2a2a", color: "inherit", borderRadius: 4 }}
          >
            Dismiss
          </button>
        </div>
      )}
      <div style={{ position: "relative", flex: 1, minHeight: 0 }}>
        {layout.tabs.length === 0 && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
              color: "#a0a0b0",
              fontSize: 13,
              textAlign: "center",
              padding: 24,
            }}
          >
            <p style={{ margin: 0 }}>
              No sessions here yet. Press {chordHint("newTab")} or use Connect on a resource.
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center" }}>
              <button type="button" onClick={() => openConnectPalette("workspace-tab")} style={emptyButton}>
                Connect…
              </button>
              {previousRun && (
                <>
                  <button
                    type="button"
                    onClick={() => void restore()}
                    disabled={restoring}
                    style={emptyButton}
                  >
                    {restoreLabel}
                  </button>
                  <button type="button" onClick={() => void forgetSaved()} style={emptyButton}>
                    Forget it
                  </button>
                </>
              )}
            </div>
            {previousRun && (
              <p style={{ margin: 0, fontSize: 12, maxWidth: 520 }}>
                Restoring re-opens each session through the normal connect path — you may be asked for a
                second factor per pane. Nothing is resumed and no credential was saved.
              </p>
            )}
          </div>
        )}
        {layout.tabs.map((tab) => (
          <div
            key={tab.id}
            role="tabpanel"
            style={{ position: "absolute", inset: 0, display: tab.id === layout.activeTabId ? "flex" : "none" }}
          >
            <SplitView
              tab={tab}
              active={tab.id === layout.activeTabId}
              onFocusPane={onFocusPane}
              onRatio={onRatio(tab.id)}
              onHostAttached={markHostReady}
            />
          </div>
        ))}
      </div>
      {panes
        .filter((pane) => hostReady[pane.token] && (pane.pending || sessions[pane.token]))
        .map((pane) =>
          createPortal(
            pane.pending ? (
              <RestorePlaceholder pane={pane} onClose={() => requestClose([pane.id])} />
            ) : (
              <WorkspacePane
                pane={pane}
                row={sessions[pane.token]}
                focused={!!current && current.focusedPaneId === pane.id}
                zoomed={current?.zoomedPaneId === pane.id}
                canZoom={
                  !!current && current.root.kind === "split" && leaves(current.root).some((l) => l.id === pane.id)
                }
                onClose={() => requestClose([pane.id])}
                canPopOut={isLive(pane, status)}
                onPopOut={() => void movePaneOut(pane.id)}
                onReleaseKeyboard={releaseKeyboard}
              />
            ),
            paneHost(pane.token),
            pane.token,
          ),
        )}
      {closeGuard.asking ? (
        <CloseConfirm
          scope="window"
          labels={liveLabels}
          onCancel={closeGuard.cancel}
          onConfirm={closeGuard.confirm}
        />
      ) : (
        pendingClose && (
          <CloseConfirm
            labels={pendingClose.labels}
            onCancel={() => setPendingClose(null)}
            onConfirm={() => void confirmClose()}
          />
        )
      )}
      {mfaPrompt}
    </div>
  );
}

/** A saved pane waiting to be re-opened (Phase 5). */
function RestorePlaceholder({ pane, onClose }: { pane: PaneNode; onClose: () => void }) {
  const p = pane.pending!;
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
        height: "100%",
        minWidth: 0,
        color: "#a0a0b0",
        fontSize: 12,
        textAlign: "center",
        padding: 12,
      }}
    >
      <strong style={{ color: "#e6e6e6", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", maxWidth: "100%" }}>
        {p.resource_name}
      </strong>
      <span>
        {p.state === "opening" ? `Connecting (${p.protocol})… answer any second-factor prompt` : "Waiting to reconnect"}
      </span>
      <button type="button" onClick={onClose} aria-label={`Skip restoring ${p.resource_name}`} style={paneButton}>
        Skip
      </button>
    </div>
  );
}

interface WorkspacePaneProps {
  pane: PaneNode;
  row: OpenSessionListing;
  focused: boolean;
  zoomed: boolean;
  canZoom: boolean;
  onClose: () => void;
  canPopOut: boolean;
  onPopOut: () => void;
  onReleaseKeyboard: () => void;
}

function WorkspacePane({
  pane,
  row,
  focused,
  zoomed,
  canZoom,
  onClose,
  canPopOut,
  onPopOut,
  onReleaseKeyboard,
}: WorkspacePaneProps) {
  const setStatus = useSessionWorkspaceStore((s) => s.setStatus);
  const dispatch = useSessionWorkspaceStore((s) => s.dispatch);
  const token = pane.token;

  const actions = (
    <>
      {canZoom && (
        <button
          type="button"
          aria-pressed={zoomed}
          title={`${zoomed ? "Un-zoom" : "Zoom"} pane (${chordHint("toggleZoom")})`}
          onClick={() => dispatch({ type: "toggleZoom" })}
          style={paneButton}
        >
          {zoomed ? "Un-zoom" : "Zoom"}
        </button>
      )}
      {canPopOut && (
        <button
          type="button"
          aria-label={`Move ${pane.label} to its own window`}
          title="Move to its own window — the session keeps running"
          onClick={onPopOut}
          style={paneButton}
        >
          Pop out
        </button>
      )}
      <button
        type="button"
        aria-label={`Close pane ${pane.label}`}
        title={`Close pane — disconnects the session (${chordHint("closePane")})`}
        onClick={onClose}
        style={paneButton}
      >
        ×
      </button>
    </>
  );

  if (row.protocol === "ssh") {
    return (
      <SshPane
        token={token}
        stdoutEvent={row.stdout_event ?? ""}
        closedEvent={row.closed_event}
        label={pane.label}
        height="100%"
        focused={focused}
        onStatusChange={(s) => setStatus(token, s)}
        onActivity={(kind) => dispatch({ type: "activity", token, kind })}
        headerExtra={actions}
      />
    );
  }
  return (
    <RdpPane
      token={token}
      closedEvent={row.closed_event}
      resizeEvent={row.resize_event ?? ""}
      cursorEvent={row.cursor_event ?? ""}
      label={pane.label}
      initialWidth={row.width ?? 1024}
      initialHeight={row.height ?? 768}
      height="100%"
      focused={focused}
      onStatusChange={(s) => setStatus(token, s)}
      onReleaseKeyboard={onReleaseKeyboard}
      headerExtra={actions}
    />
  );
}

const paneButton = {
  background: "#1f2030",
  color: "#e6e6e6",
  border: "1px solid #2f3150",
  padding: "3px 8px",
  borderRadius: 4,
  cursor: "pointer",
  fontSize: 12,
} as const;

const stripButton = {
  background: "transparent",
  color: "#a0a0b0",
  border: "none",
  borderLeft: "1px solid #1f2030",
  cursor: "pointer",
  padding: "0 12px",
  fontSize: 12,
  whiteSpace: "nowrap",
} as const;

const emptyButton = {
  padding: "4px 12px",
  borderRadius: 4,
  border: "1px solid #3a3f6e",
  background: "#1a1c2b",
  color: "#e6e6e6",
} as const;
