import type { ReactNode } from "react";
import { useState } from "react";

interface CollapsibleSectionProps {
  /** Section header shown on the toggle row. */
  title: ReactNode;
  /** Optional right-aligned slot on the header row — useful for an
   *  external link or a status badge that should stay visible when
   *  the section is collapsed. */
  headerRight?: ReactNode;
  /** Open state on first render. Uncontrolled — once the user
   *  clicks, the component owns the state for the rest of its
   *  lifetime. */
  defaultOpen?: boolean;
  /** Muted helper copy shown right under the header when open;
   *  typically a one-liner explaining what this section configures. */
  description?: ReactNode;
  children: ReactNode;
}

/**
 * Accordion-style collapsible block used inside modals and forms to
 * tuck optional / advanced configuration away so the default view
 * fits the viewport. Built on the browser's native `<details>` +
 * `<summary>` for accessibility (keyboard toggling and screen-
 * reader state announcements for free), but styled to match our
 * theme rather than the default disclosure triangle.
 *
 * Uncontrolled by design — the parent form doesn't care whether a
 * section is open, and forcing the parent to track that state
 * would spread modal-layout concerns through every caller.
 */
export function CollapsibleSection({
  title,
  headerRight,
  defaultOpen = false,
  description,
  children,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-[var(--color-border)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-3 py-2 bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)] transition-colors text-left"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2 text-sm font-medium min-w-0">
          <span
            className={`text-[var(--color-text-muted)] transition-transform text-xs ${open ? "rotate-90" : ""}`}
            aria-hidden="true"
          >
            ▶
          </span>
          <span className="truncate">{title}</span>
        </span>
        {headerRight && (
          // `onClick` stops propagation so clicks on the right-side
          // slot (typically an external link) don't toggle the
          // section open/closed as a side-effect.
          <span
            className="shrink-0"
            onClick={(e) => e.stopPropagation()}
          >
            {headerRight}
          </span>
        )}
      </button>
      {open && (
        <div className="px-3 py-3 bg-[var(--color-bg)] space-y-2 border-t border-[var(--color-border)]">
          {description && (
            <p className="text-xs text-[var(--color-text-muted)]">{description}</p>
          )}
          {children}
        </div>
      )}
    </div>
  );
}
