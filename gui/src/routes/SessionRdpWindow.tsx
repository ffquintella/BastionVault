/**
 * Resource Connect — RDP session window (Phase 4).
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_rdp` command (own-window placement). A one-pane wrapper
 * (T38 Phase 1): it reads the session's identity and initial desktop size
 * from the URL params and renders [[RdpPane]], which owns the canvas, the
 * binary frame channel, input forwarding and the chrome.
 *
 * The window, not the pane, heartbeats the host (T38 Phase 2), and owns
 * the native close: closing the window while the session is live asks
 * first (T108, `lib/sessionWindowClose`).
 */

import { useState } from "react";
import { useSearchParams } from "react-router";
import { RdpPane } from "../components/session/RdpPane";
import { MoveToWorkspaceButton } from "../components/session/MoveToWorkspaceButton";
import { WindowCloseConfirm } from "../components/session/CloseConfirm";
import type { SessionPaneStatus } from "../components/session/SessionPaneHeader";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";
import { isLiveStatus, useWindowCloseGuard } from "../lib/sessionWindowClose";

export function SessionRdpWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const resizeEvent = params.get("resize") ?? "";
  const cursorEvent = params.get("cursor") ?? "";
  const label = params.get("label") ?? "rdp session";
  const initWidth = parseInt(params.get("w") ?? "1024", 10) || 1024;
  const initHeight = parseInt(params.get("h") ?? "600", 10) || 600;
  const [status, setStatus] = useState<SessionPaneStatus | undefined>(undefined);

  useSessionHeartbeat(token !== "");
  const live = token !== "" && isLiveStatus(status) ? [label] : [];
  const closeGuard = useWindowCloseGuard(() => live, token !== "");

  return (
    <>
      <RdpPane
        token={token}
        closedEvent={closedEvent}
        resizeEvent={resizeEvent}
        cursorEvent={cursorEvent}
        label={label}
        initialWidth={initWidth}
        initialHeight={initHeight}
        height="100vh"
        onStatusChange={setStatus}
        headerExtra={<MoveToWorkspaceButton token={token} />}
      />
      <WindowCloseConfirm guard={closeGuard} labels={live} />
    </>
  );
}
