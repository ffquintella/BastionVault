/**
 * Long-lived host elements for session panes — the DOM-continuity rule of
 * the Session Workspace (T38 Phase 3, features/session-workspace.md §2).
 *
 * An xterm.js instance loses its screen and scrollback when its container
 * is unmounted, and an RDP `<canvas>` loses its backing store. React
 * unmounts a subtree whenever it moves to a different parent, which is
 * exactly what a split, a zoom or a tab move does. So a pane's content is
 * not owned by the tree that lays it out:
 *
 * - each session token gets one host `<div>`, created here and kept until
 *   the session's pane is closed;
 * - the pane itself is rendered into that host through a React portal
 *   whose parent never moves (`SessionWorkspaceWindow`);
 * - the layout's leaf (`PaneSlot`) owns an empty slot and, in a layout
 *   effect, appends the host into it.
 *
 * Moving a pane therefore moves one DOM node; the terminal, its scrollback
 * and its subscriptions are untouched.
 */

const hosts = new Map<string, HTMLDivElement>();

/** The host element for `token`, created on first use. Identity-stable
 *  until {@link releasePaneHost}. */
export function paneHost(token: string): HTMLDivElement {
  let el = hosts.get(token);
  if (!el) {
    el = document.createElement("div");
    el.className = "h-full w-full min-w-0 min-h-0";
    el.style.height = "100%";
    el.style.width = "100%";
    el.dataset.paneHost = "";
    hosts.set(token, el);
  }
  return el;
}

export function hasPaneHost(token: string): boolean {
  return hosts.has(token);
}

/** Drop `token`'s host once its pane is gone. Returns whether there was
 *  one, so a caller can tell a second release from the first. */
export function releasePaneHost(token: string): boolean {
  const el = hosts.get(token);
  if (!el) return false;
  hosts.delete(token);
  el.remove();
  return true;
}

/** Tokens with a live host element (tests and diagnostics). */
export function paneHostTokens(): string[] {
  return [...hosts.keys()];
}

/** Tests only. */
export function resetPaneHostsForTests(): void {
  for (const el of hosts.values()) el.remove();
  hosts.clear();
}
