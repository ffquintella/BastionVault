/**
 * Resource Connect — RDP session window (Phase 4).
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_rdp` command (own-window placement). A one-pane wrapper
 * (T38 Phase 1): it reads the session's identity and initial desktop size
 * from the URL params and renders [[RdpPane]], which owns the canvas, the
 * binary frame channel, input forwarding and the chrome.
 *
 * The window, not the pane, heartbeats the host (T38 Phase 2).
 */

import { useSearchParams } from "react-router";
import { RdpPane } from "../components/session/RdpPane";
import { MoveToWorkspaceButton } from "../components/session/MoveToWorkspaceButton";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";

export function SessionRdpWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const resizeEvent = params.get("resize") ?? "";
  const cursorEvent = params.get("cursor") ?? "";
  const label = params.get("label") ?? "rdp session";
  const initWidth = parseInt(params.get("w") ?? "1024", 10) || 1024;
  const initHeight = parseInt(params.get("h") ?? "600", 10) || 600;

  useSessionHeartbeat(token !== "");

  return (
    <RdpPane
      token={token}
      closedEvent={closedEvent}
      resizeEvent={resizeEvent}
      cursorEvent={cursorEvent}
      label={label}
      initialWidth={initWidth}
      initialHeight={initHeight}
      height="100vh"
      headerExtra={<MoveToWorkspaceButton token={token} />}
    />
  );
}
