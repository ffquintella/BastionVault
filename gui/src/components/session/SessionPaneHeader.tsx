/**
 * Per-pane chrome shared by the SSH and RDP panes: the session label, the
 * status pill, the last error, the Rustion lifecycle chip and Disconnect.
 *
 * Extracted unchanged from the two session windows (T38 Phase 1); the
 * Session Workspace (Phase 3) renders one per pane, with its pane actions
 * (zoom, close pane) in `extra`. The label is the target `user@host`, so
 * every pane — not just the tab — names where keystrokes go.
 */

import type { ReactNode } from "react";

import { RustionSessionChip } from "../RustionSessionChip";

export type SessionPaneStatus = "connecting" | "open" | "closed" | "error";

function statusBackground(status: SessionPaneStatus): string {
  switch (status) {
    case "open":
      return "#1a4533";
    case "closed":
      return "#3a3a3a";
    case "error":
      return "#5e1f1f";
    case "connecting":
      return "#2a2f5e";
  }
}

export interface SessionPaneHeaderProps {
  token: string;
  label: string;
  status: SessionPaneStatus;
  errorMessage: string;
  onDisconnect: () => void;
  /** Shown left of Disconnect: hints and the workspace's pane actions. */
  extra?: ReactNode;
}

export function SessionPaneHeader({
  token,
  label,
  status,
  errorMessage,
  onDisconnect,
  extra,
}: SessionPaneHeaderProps) {
  return (
    <div
      style={{
        padding: "6px 12px",
        borderBottom: "1px solid #1f2030",
        background: "#11121a",
        display: "flex",
        alignItems: "center",
        gap: 12,
      }}
    >
      <strong
        style={{ fontSize: 13, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={label}
      >
        {label}
      </strong>
      <span
        style={{
          fontSize: 11,
          padding: "2px 8px",
          borderRadius: 999,
          background: statusBackground(status),
          color: "#e6e6e6",
        }}
      >
        {status}
      </span>
      {errorMessage && (
        <span style={{ fontSize: 11, color: "#ff6e6e" }}>{errorMessage}</span>
      )}
      <div style={{ flex: 1 }} />
      <RustionSessionChip token={token} />
      {extra}
      <button
        onClick={onDisconnect}
        disabled={status === "closed"}
        style={{
          background: "#5e1f1f",
          color: "#e6e6e6",
          border: "1px solid #7a2a2a",
          padding: "4px 10px",
          borderRadius: 4,
          cursor: status === "closed" ? "not-allowed" : "pointer",
          opacity: status === "closed" ? 0.6 : 1,
          fontSize: 12,
        }}
      >
        Disconnect
      </button>
    </div>
  );
}
