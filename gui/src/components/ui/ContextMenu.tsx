import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

export interface ContextMenuItem {
  label: string;
  icon?: ReactNode;
  onSelect: () => void;
  disabled?: boolean;
  /** Tooltip — handy for explaining a disabled item. */
  title?: string;
  variant?: "default" | "danger";
}

/**
 * A lightweight right-click menu anchored to a viewport coordinate.
 *
 * Render it conditionally from the owning page (usually with an
 * `{x, y, ...}` state object set on `onContextMenu`) so only one menu
 * is ever mounted. It closes on outside click, Escape, scroll, resize,
 * or window blur, and nudges itself back inside the viewport when the
 * anchor is near an edge.
 */
export function ContextMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState({ x, y });

  // Measure after mount and clamp into the viewport so a menu opened
  // near the right/bottom edge doesn't spill off-screen.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const pad = 8;
    let nx = x;
    let ny = y;
    if (nx + rect.width > window.innerWidth - pad)
      nx = window.innerWidth - rect.width - pad;
    if (ny + rect.height > window.innerHeight - pad)
      ny = window.innerHeight - rect.height - pad;
    setPos({ x: Math.max(pad, nx), y: Math.max(pad, ny) });
  }, [x, y]);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    // Any scroll / layout shift invalidates the anchor — just close.
    const onDismiss = () => onClose();
    document.addEventListener("mousedown", onDown, true);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onDismiss, true);
    window.addEventListener("resize", onDismiss);
    window.addEventListener("blur", onDismiss);
    return () => {
      document.removeEventListener("mousedown", onDown, true);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onDismiss, true);
      window.removeEventListener("resize", onDismiss);
      window.removeEventListener("blur", onDismiss);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      role="menu"
      style={{ position: "fixed", left: pos.x, top: pos.y, zIndex: 60 }}
      className="min-w-[10rem] py-1 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg shadow-2xl"
      onContextMenu={(e) => e.preventDefault()}
    >
      {items.map((item, i) => (
        <button
          key={i}
          type="button"
          role="menuitem"
          disabled={item.disabled}
          title={item.title}
          onClick={() => {
            if (item.disabled) return;
            onClose();
            item.onSelect();
          }}
          className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm transition-colors
            disabled:opacity-40 disabled:cursor-not-allowed
            ${
              item.variant === "danger"
                ? "text-red-400 hover:bg-red-500/10"
                : "text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
            }`}
        >
          {item.icon && (
            <span className="shrink-0 w-4 h-4 flex items-center justify-center">
              {item.icon}
            </span>
          )}
          {item.label}
        </button>
      ))}
    </div>
  );
}
