/**
 * Resource Connect — SSH session window.
 *
 * Loaded into a fresh Tauri WebviewWindow spawned by the
 * `session_open_ssh` command (own-window placement). A one-pane wrapper
 * (T38 Phase 1): it reads the session's identity from the URL params and
 * renders [[SshPane]], which owns the terminal, the handshake and the
 * chrome:
 *   token     — opaque session id used by every Tauri command call
 *   stdout    — event name the host emits remote PTY bytes on
 *   closed    — event name the host emits when the remote PTY hangs up
 *   label     — operator-visible title (e.g. `ssh felipe@host:22`)
 *
 * The window, not the pane, heartbeats the host (T38 Phase 2): liveness
 * is per window, so a future multi-pane window still sends one.
 */

import { useSearchParams } from "react-router";
import { SshPane } from "../components/session/SshPane";
import { MoveToWorkspaceButton } from "../components/session/MoveToWorkspaceButton";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";

export function SessionSshWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const stdoutEvent = params.get("stdout") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const label = params.get("label") ?? "ssh session";

  useSessionHeartbeat(token !== "");

  return (
    <SshPane
      token={token}
      stdoutEvent={stdoutEvent}
      closedEvent={closedEvent}
      label={label}
      height="100vh"
      headerExtra={<MoveToWorkspaceButton token={token} />}
    />
  );
}
