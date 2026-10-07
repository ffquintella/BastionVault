/**
 * Session Workspace split-tree renderer (T38 Phase 3).
 *
 * Renders one tab's layout tree. Leaves are {@link PaneSlot}s: an empty
 * `<div>` that, in a layout effect, adopts the session's long-lived host
 * element from `lib/paneHosts`. The pane itself is rendered into that host
 * by a portal elsewhere (`SessionWorkspaceWindow`), so when a split,
 * close or zoom re-parents a leaf, React unmounts and remounts only the
 * empty slot — the terminal or canvas inside the host is moved, never
 * rebuilt.
 */

import { useLayoutEffect, useRef, type PointerEvent as ReactPointerEvent, type RefObject } from "react";

import { paneHost } from "../../../lib/paneHosts";
import { leaves, pathOf, type LayoutNode, type PaneNode, type SplitNode, type WorkspaceTab } from "../../../lib/sessionLayout";

export interface SplitViewProps {
  tab: WorkspaceTab;
  /** Whether this tab is the visible one (its focused pane gets the ring). */
  active: boolean;
  onFocusPane: (paneId: string) => void;
  onRatio: (path: string, ratio: number) => void;
  /** A slot has put `token`'s host element into the document. */
  onHostAttached: (token: string) => void;
}

/** One tab's body: the whole tree, or only the zoomed pane. Zoom never
 *  touches the tree, so un-zooming restores it exactly. */
export function SplitView({ tab, active, onFocusPane, onRatio, onHostAttached }: SplitViewProps) {
  const multiPane = tab.root.kind === "split";
  const zoomed = tab.zoomedPaneId ? leaves(tab.root).find((l) => l.id === tab.zoomedPaneId) : undefined;
  const ctx: NodeContext = {
    focusedPaneId: active ? tab.focusedPaneId : null,
    multiPane: multiPane && !zoomed,
    onFocusPane,
    onRatio,
    onHostAttached,
  };
  if (zoomed) {
    return <NodeView node={zoomed} path={pathOf(tab.root, zoomed.id) ?? ""} ctx={ctx} />;
  }
  return <NodeView node={tab.root} path="" ctx={ctx} />;
}

interface NodeContext {
  focusedPaneId: string | null;
  multiPane: boolean;
  onFocusPane: (paneId: string) => void;
  onRatio: (path: string, ratio: number) => void;
  onHostAttached: (token: string) => void;
}

function NodeView({ node, path, ctx }: { node: LayoutNode; path: string; ctx: NodeContext }) {
  if (node.kind === "pane") {
    return <PaneSlot key={node.id} pane={node} ctx={ctx} />;
  }
  return <SplitContainer node={node} path={path} ctx={ctx} />;
}

function SplitContainer({ node, path, ctx }: { node: SplitNode; path: string; ctx: NodeContext }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const row = node.dir === "row";
  return (
    <div
      ref={ref}
      data-split={node.dir}
      style={{ display: "flex", flexDirection: row ? "row" : "column", width: "100%", height: "100%", minWidth: 0, minHeight: 0 }}
    >
      <div style={{ flex: `0 0 calc(${node.ratio * 100}% - 2px)`, minWidth: 0, minHeight: 0, overflow: "hidden" }}>
        <NodeView node={node.a} path={`${path}a`} ctx={ctx} />
      </div>
      <Divider dir={node.dir} ratio={node.ratio} containerRef={ref} onRatio={(r) => ctx.onRatio(path, r)} />
      <div style={{ flex: "1 1 0", minWidth: 0, minHeight: 0, overflow: "hidden" }}>
        <NodeView node={node.b} path={`${path}b`} ctx={ctx} />
      </div>
    </div>
  );
}

/**
 * Drag to resize. The ratio is the pointer's position across the split's
 * own box; the reducer clamps it to [0.1, 0.9], so no drag can shrink a
 * pane out of reach.
 */
function Divider({
  dir,
  ratio,
  containerRef,
  onRatio,
}: {
  dir: "row" | "col";
  ratio: number;
  containerRef: RefObject<HTMLDivElement | null>;
  onRatio: (ratio: number) => void;
}) {
  const row = dir === "row";
  function onPointerDown(e: ReactPointerEvent<HTMLDivElement>) {
    if (e.button !== 0) return;
    e.preventDefault();
    const el = e.currentTarget;
    el.setPointerCapture?.(e.pointerId);
    const move = (ev: PointerEvent) => {
      const box = containerRef.current?.getBoundingClientRect();
      if (!box || box.width === 0 || box.height === 0) return;
      onRatio(row ? (ev.clientX - box.left) / box.width : (ev.clientY - box.top) / box.height);
    };
    const up = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", up);
      el.removeEventListener("pointercancel", up);
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
  }
  return (
    <div
      role="separator"
      aria-orientation={row ? "vertical" : "horizontal"}
      aria-valuemin={10}
      aria-valuemax={90}
      aria-valuenow={Math.round(ratio * 100)}
      onPointerDown={onPointerDown}
      style={{
        flex: "0 0 4px",
        cursor: row ? "col-resize" : "row-resize",
        background: "#1f2030",
        touchAction: "none",
      }}
    />
  );
}

/**
 * A layout leaf. Owns an empty slot and adopts the session's host element
 * into it; on unmount, gives it back (detached, still alive) for whichever
 * slot renders the pane next.
 */
function PaneSlot({ pane, ctx }: { pane: PaneNode; ctx: NodeContext }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const { onHostAttached, onFocusPane } = ctx;
  useLayoutEffect(() => {
    const slot = ref.current;
    if (!slot) return;
    const host = paneHost(pane.token);
    slot.appendChild(host);
    onHostAttached(pane.token);
    return () => {
      if (host.parentElement === slot) slot.removeChild(host);
    };
  }, [pane.token, onHostAttached]);
  // A native listener, not React's `onPointerDownCapture`: the pane is a
  // portal whose React parent is the workspace root, so a synthetic event
  // from inside it never passes through this slot.
  useLayoutEffect(() => {
    const slot = ref.current;
    if (!slot) return;
    const onPointerDown = () => onFocusPane(pane.id);
    slot.addEventListener("pointerdown", onPointerDown, true);
    return () => slot.removeEventListener("pointerdown", onPointerDown, true);
  }, [pane.id, onFocusPane]);
  const focused = ctx.focusedPaneId === pane.id;
  return (
    <div
      ref={ref}
      data-pane-id={pane.id}
      data-focused={focused ? "true" : undefined}
      style={{
        width: "100%",
        height: "100%",
        minWidth: 0,
        minHeight: 0,
        boxSizing: "border-box",
        // The focused-pane border: with several panes visible, the target
        // of the next keystroke must be obvious at a glance.
        padding: ctx.multiPane ? 2 : 0,
        background: ctx.multiPane ? (focused ? "#7aa2f7" : "#1f2030") : undefined,
      }}
    />
  );
}
