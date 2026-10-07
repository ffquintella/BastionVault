/**
 * "Disconnect these sessions?" — the confirmation shown before a pane, a
 * tab or a whole window that holds live sessions is closed (T38 Phase 3–4
 * residuals; the window form is T108). Names every session it would end;
 * Cancel has the focus, and Escape cancels.
 */

import type { ReactNode } from "react";

import type { WindowCloseGuard } from "../../lib/sessionWindowClose";

export interface CloseConfirmProps {
  /** Labels of the live sessions closing would end. */
  labels: string[];
  onCancel: () => void;
  onConfirm: () => void;
  /** `window`: the whole window is closing, not one pane or tab. */
  scope?: "pane" | "window";
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

function lead(scope: "pane" | "window", n: number): ReactNode {
  const them = n === 1 ? "it" : "them";
  if (scope === "window") {
    if (n === 0) return "Close this window?";
    return (
      <>
        Close this window? It disconnects {n === 1 ? "this session" : `these ${n} sessions`} — closing ends {them} on
        the remote host.
      </>
    );
  }
  return (
    <>
      Disconnect {n === 1 ? "this session" : `these ${n} sessions`}? Closing ends {them} on the remote host.
    </>
  );
}

export function CloseConfirm({ labels, onCancel, onConfirm, scope = "pane" }: CloseConfirmProps) {
  const n = labels.length;
  return (
    <div
      role="alertdialog"
      aria-label={scope === "window" ? "Confirm close window" : "Confirm disconnect"}
      onKeyDown={(e) => {
        if (e.key === "Escape") onCancel();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(5, 5, 10, 0.75)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 16,
        zIndex: 50,
      }}
    >
      <div
        style={{
          background: "#11121a",
          border: "1px solid #3a3f6e",
          borderRadius: 6,
          padding: 16,
          maxWidth: "min(560px, 100%)",
          minWidth: 0,
          fontSize: 12,
          color: "#e6e6e6",
        }}
      >
        <p style={{ margin: "0 0 8px", fontSize: 13 }}>{lead(scope, n)}</p>
        {n > 0 && (
          <ul style={{ margin: "0 0 12px", paddingLeft: 18 }}>
            {labels.map((l, i) => (
              <li key={i} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {l}
              </li>
            ))}
          </ul>
        )}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button type="button" autoFocus onClick={onCancel} style={paneButton}>
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            style={{ ...paneButton, background: "#5e1f1f", border: "1px solid #7a2a2a" }}
          >
            {scope === "window" ? "Disconnect and close" : "Disconnect"}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * A session's own window's half of T108: the window-close confirmation
 * while the guard is asking, and — if the host did not close the window —
 * why, until dismissed.
 */
export function WindowCloseConfirm({ guard, labels }: { guard: WindowCloseGuard; labels: string[] }) {
  if (guard.asking) {
    return <CloseConfirm scope="window" labels={labels} onCancel={guard.cancel} onConfirm={guard.confirm} />;
  }
  if (!guard.error) return null;
  return (
    <div
      role="alert"
      style={{
        position: "fixed",
        left: 8,
        right: 8,
        bottom: 8,
        display: "flex",
        gap: 8,
        alignItems: "center",
        padding: "4px 12px",
        background: "#3a1a1a",
        color: "#ffb4b4",
        fontSize: 12,
        borderRadius: 4,
        minWidth: 0,
        zIndex: 50,
      }}
    >
      <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{guard.error}</span>
      <button type="button" onClick={guard.dismissError} style={paneButton}>
        Dismiss
      </button>
    </div>
  );
}
