import type { ReactNode } from "react";

/** A confirmation over the SQL workspace. A UX guard (§10), never a control:
 *  the vault still decides the statement after the operator confirms. */
export function SqlConfirmDialog({
  title,
  children,
  confirm,
  onCancel,
  onConfirm,
}: {
  title: string;
  children: ReactNode;
  confirm: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div
      role="alertdialog"
      aria-label={title}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onKeyDown={(e) => {
        if (e.key === "Escape") onCancel();
      }}
    >
      <div className="w-full max-w-lg rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-2xl">
        <h2 className="mb-2 text-sm font-semibold text-[var(--color-text)]">{title}</h2>
        <div className="space-y-2 text-sm text-[var(--color-text-muted)]">{children}</div>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            autoFocus
            onClick={onCancel}
            className="rounded-md border border-[var(--color-border)] px-3 py-1 text-xs text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="rounded-md bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-500"
          >
            {confirm}
          </button>
        </div>
      </div>
    </div>
  );
}

/** A capability chip. `muted` when the caller lacks it. */
export function CapChip({ cap, tone = "info", title }: { cap: string; tone?: "info" | "warn" | "muted"; title?: string }) {
  const cls =
    tone === "warn"
      ? "border-yellow-600/60 text-yellow-300"
      : tone === "muted"
        ? "border-[var(--color-border)] text-[var(--color-text-muted)] line-through"
        : "border-blue-500/50 text-blue-300";
  return (
    <span title={title} className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] ${cls}`}>
      {cap}
    </span>
  );
}
