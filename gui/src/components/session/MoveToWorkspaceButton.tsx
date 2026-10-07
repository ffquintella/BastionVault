/**
 * "Move to workspace" for a session's own window (T38 Phase 6): hands the
 * live session to the Session Workspace as a new tab and closes this
 * window; the session keeps running. Offered only in the workspace layout
 * mode — the host refuses the move in *Separate windows* mode regardless.
 */

import { useState } from "react";

import { sessionMove } from "../../lib/api";
import { extractError } from "../../lib/error";
import { useSessionInputPrefs } from "../../lib/sessionInputPrefs";

export function MoveToWorkspaceButton({ token }: { token: string }) {
  const { layoutMode } = useSessionInputPrefs();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  if (!token || layoutMode !== "workspace") return null;
  return (
    <>
      {error && <span style={{ fontSize: 11, color: "#ff6e6e" }}>{error}</span>}
      <button
        type="button"
        disabled={busy}
        title="Move this session into the Session Workspace as a tab — it keeps running"
        onClick={async () => {
          setBusy(true);
          setError("");
          try {
            // On success the host closes this window.
            await sessionMove(token, "workspace");
          } catch (e) {
            setError(extractError(e));
            setBusy(false);
          }
        }}
        style={{
          background: "#1f2030",
          color: "#e6e6e6",
          border: "1px solid #2f3150",
          padding: "3px 8px",
          borderRadius: 4,
          cursor: busy ? "wait" : "pointer",
          fontSize: 12,
        }}
      >
        Move to workspace
      </button>
    </>
  );
}
