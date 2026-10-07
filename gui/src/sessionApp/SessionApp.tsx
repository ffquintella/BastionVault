/**
 * The session-only frontend, loaded from `session.html`
 * (features/session-workspace.md, T110).
 *
 * Every window that renders a live session or a recording loads this
 * bundle instead of the vault UI: a session's own window (`ssh-<token>` /
 * `rdp-<token>`), the Session Workspace (`session-workspace`) and a
 * recording replay (`replay-<id>`). It mounts only the routes those windows
 * use — no admin page, no auth store, no session monitor — and never asks
 * the host for the vault token, so a renderer compromise in one pane of the
 * shared workspace realm finds neither the admin UI nor a token to replay.
 *
 * What the bundle contains is defence in depth. The boundary is the host's
 * per-window command ACL (`src-tauri/capabilities/session-*.json`, the sets
 * in `src-tauri/permissions/window-sets.json`): a session window can
 * call only the commands its set names, whatever script runs in it.
 * `sessionBundle.test.ts` walks this file's import graph and fails if an
 * admin route, the auth store or the `ui` barrel becomes reachable, or if
 * the bundle can call a command its window's set does not grant.
 */
import type { ReactNode } from "react";
import { HashRouter, Route, Routes } from "react-router";

import { ConnectPalette } from "../components/ConnectPalette";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { ToastProvider } from "../components/ui/Toast";
import { SessionRdpWindow } from "../routes/SessionRdpWindow";
import { SessionReplayWindow } from "../routes/SessionReplayWindow";
import { SessionSshWindow } from "../routes/SessionSshWindow";
import { SessionWorkspaceWindow } from "../routes/SessionWorkspaceWindow";

/**
 * The Session Workspace and its ⌘K palette. The palette is armed outright:
 * this bundle has no auth state to wait for, and the host refuses every
 * command the palette calls when nobody is logged in. ⌘T / ⌘D / ⌘⇧D open it
 * with the placement the new session should get.
 */
function WorkspaceWindow() {
  return (
    <>
      <SessionWorkspaceWindow />
      <ConnectPalette armed />
    </>
  );
}

/** Anything else: say so, link nowhere. */
function NotASessionRoute() {
  return (
    <div className="flex h-full items-center justify-center p-6 text-sm text-[var(--color-text-muted)]">
      This window shows sessions only.
    </div>
  );
}

/**
 * The route table, and the only one. The host builds each window's URL
 * against these paths (`session.html#/session/ssh?…` etc. in
 * `src-tauri/src/session/workspace.rs`).
 */
export const SESSION_ROUTES: ReadonlyArray<{ path: string; element: ReactNode }> = [
  // A session's own window: the host registered the session and its
  // event names before building the window, so there is no auth gate.
  { path: "/session/ssh", element: <SessionSshWindow /> },
  { path: "/session/rdp", element: <SessionRdpWindow /> },
  // The singleton Session Workspace (T38): tabs and splits of SSH / RDP
  // panes, each placed by the host.
  { path: "/workspace", element: <WorkspaceWindow /> },
  // A recording opened from the Recordings page.
  { path: "/session-replay", element: <SessionReplayWindow /> },
];

export function SessionRoutes() {
  return (
    <Routes>
      {SESSION_ROUTES.map((r) => (
        <Route key={r.path} path={r.path} element={r.element} />
      ))}
      <Route path="*" element={<NotASessionRoute />} />
    </Routes>
  );
}

export function SessionApp() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <HashRouter>
          <SessionRoutes />
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
