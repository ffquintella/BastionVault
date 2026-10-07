/**
 * Session Workspace tab strip (T38 Phase 3): one tab per layout tab, with
 * its title (the focused pane's session label), a status dot, an
 * unread / bell dot for background tabs, a close button, and reorder by
 * dragging.
 *
 * Reorder uses pointer events rather than HTML5 drag-and-drop: WebView2
 * swallows HTML5 drops while Tauri's file-drop handler is on.
 *
 * Tear-off (T38 Phase 6): a tab dragged out of the strip — released more
 * than {@link TEAR_OFF_DISTANCE_PX} below it, or outside the window — moves
 * its sessions to windows of their own, still running.
 */

import { useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";

import { leaves, tabTitle, type WorkspaceTab } from "../../../lib/sessionLayout";
import type { SessionPaneStatus } from "../SessionPaneHeader";

export interface TabStripProps {
  tabs: readonly WorkspaceTab[];
  activeTabId: string | null;
  status: Readonly<Record<string, SessionPaneStatus>>;
  onActivate: (tabId: string) => void;
  onClose: (tabId: string) => void;
  onMove: (from: number, to: number) => void;
  onNew: () => void;
  /** Shown on the + button, e.g. `⌘T`. */
  newTabHint: string;
  /** A tab was dragged out of the strip. */
  onTearOff?: (tabId: string) => void;
  /** Rendered at the end of the strip (e.g. the restore offer). */
  trailing?: ReactNode;
}

/** How far below the strip a released tab must be to tear off. */
export const TEAR_OFF_DISTANCE_PX = 48;

/** Whether a drag released at (x, y) left the strip far enough to tear off. */
export function isTearOff(
  x: number,
  y: number,
  strip: { bottom: number },
  viewport: { width: number; height: number },
): boolean {
  const outside = x < 0 || y < 0 || x > viewport.width || y > viewport.height;
  return outside || y > strip.bottom + TEAR_OFF_DISTANCE_PX;
}

const STATUS_COLOR: Record<SessionPaneStatus, string> = {
  open: "#3fb27f",
  connecting: "#7aa2f7",
  closed: "#6b6b6b",
  error: "#ff6e6e",
};

/** One status for a tab: an error anywhere wins, then connecting, then
 *  open; closed only when every pane is closed. */
export function tabStatus(
  tab: WorkspaceTab,
  status: Readonly<Record<string, SessionPaneStatus>>,
): SessionPaneStatus {
  const all = leaves(tab.root).map((l) => status[l.token] ?? "connecting");
  if (all.includes("error")) return "error";
  if (all.includes("connecting")) return "connecting";
  if (all.includes("open")) return "open";
  return "closed";
}

export function TabStrip({
  tabs,
  activeTabId,
  status,
  onActivate,
  onClose,
  onMove,
  onNew,
  newTabHint,
  onTearOff,
  trailing,
}: TabStripProps) {
  const [dragging, setDragging] = useState<number | null>(null);
  const dragState = useRef<{ from: number; startX: number; startY: number; moved: boolean } | null>(null);
  const stripRef = useRef<HTMLDivElement | null>(null);

  function onPointerDown(e: ReactPointerEvent<HTMLDivElement>, index: number) {
    if (e.button !== 0) return;
    dragState.current = { from: index, startX: e.clientX, startY: e.clientY, moved: false };
    // Keep receiving the drag when the pointer leaves the window.
    try {
      e.currentTarget.setPointerCapture?.(e.pointerId);
    } catch {
      // Not every engine (or test DOM) supports capture; window listeners
      // still see an in-window release.
    }
    const move = (ev: PointerEvent) => {
      const d = dragState.current;
      if (d && !d.moved && (Math.abs(ev.clientX - d.startX) > 4 || Math.abs(ev.clientY - d.startY) > 4)) {
        d.moved = true;
        setDragging(d.from);
      }
    };
    const up = (ev: PointerEvent) => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      const d = dragState.current;
      dragState.current = null;
      setDragging(null);
      if (!d?.moved) return;
      const strip = stripRef.current?.getBoundingClientRect();
      if (
        onTearOff &&
        strip &&
        isTearOff(ev.clientX, ev.clientY, strip, { width: window.innerWidth, height: window.innerHeight })
      ) {
        const tab = tabs[d.from];
        if (tab) onTearOff(tab.id);
        return;
      }
      if (typeof document.elementFromPoint !== "function") return;
      const target = (document.elementFromPoint(ev.clientX, ev.clientY) as HTMLElement | null)?.closest<HTMLElement>(
        "[data-tab-index]",
      );
      if (target) onMove(d.from, Number(target.dataset.tabIndex));
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  return (
    <div
      ref={stripRef}
      role="tablist"
      aria-label="Sessions"
      style={{
        display: "flex",
        alignItems: "stretch",
        minWidth: 0,
        overflowX: "auto",
        background: "#0e0f16",
        borderBottom: "1px solid #1f2030",
        fontFamily: "ui-sans-serif, system-ui, sans-serif",
        fontSize: 12,
        userSelect: "none",
      }}
    >
      {tabs.map((tab, index) => {
        const title = tabTitle(tab);
        const selected = tab.id === activeTabId;
        const s = tabStatus(tab, status);
        return (
          <div
            key={tab.id}
            role="tab"
            aria-selected={selected}
            data-tab-index={index}
            title={onTearOff ? `${title} — drag out of the strip to move it to its own window` : title}
            onClick={() => onActivate(tab.id)}
            onPointerDown={(e) => onPointerDown(e, index)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              minWidth: 0,
              maxWidth: 260,
              padding: "6px 8px 6px 10px",
              cursor: "pointer",
              borderRight: "1px solid #1f2030",
              background: selected ? "#1a1c2b" : "transparent",
              color: selected ? "#e6e6e6" : "#a0a0b0",
              opacity: dragging === index ? 0.5 : 1,
              boxShadow: selected ? "inset 0 -2px 0 #7aa2f7" : undefined,
            }}
          >
            <span
              aria-label={`status ${s}`}
              style={{ width: 8, height: 8, borderRadius: 999, background: STATUS_COLOR[s], flex: "0 0 8px" }}
            />
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {title}
            </span>
            {(tab.unread || tab.bell) && (
              <span
                aria-label={tab.bell ? "bell" : "unread output"}
                title={tab.bell ? "A bell rang in this tab" : "New output in this tab"}
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 999,
                  background: tab.bell ? "#e0af68" : "#7aa2f7",
                  flex: "0 0 7px",
                }}
              />
            )}
            <button
              type="button"
              aria-label={`Close tab ${title}`}
              title="Close tab (disconnects its sessions)"
              onPointerDown={(e) => e.stopPropagation()}
              onClick={(e) => {
                e.stopPropagation();
                onClose(tab.id);
              }}
              style={{
                background: "transparent",
                border: "none",
                color: "inherit",
                cursor: "pointer",
                padding: "0 2px",
                fontSize: 14,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>
        );
      })}
      <button
        type="button"
        aria-label="New tab"
        title={`New tab (${newTabHint})`}
        onClick={onNew}
        style={{
          background: "transparent",
          border: "none",
          color: "#a0a0b0",
          cursor: "pointer",
          padding: "0 12px",
          fontSize: 16,
        }}
      >
        +
      </button>
      {trailing}
    </div>
  );
}
