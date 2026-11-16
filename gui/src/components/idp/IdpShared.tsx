import { useState, type ReactNode } from "react";
import { Badge, useToast } from "../ui";
import type { IdpListenerStatus } from "../../lib/idp";

export function StateBadge({ state }: { state: string }) {
  const variant =
    state === "active" ? "success" : state === "disabled" ? "warning" : state === "removed" ? "error" : "neutral";
  return <Badge variant={variant} label={state} dot />;
}

/** A public value (pin, kid, key, URL) on one truncated line with a copy button. */
export function CopyValue({ label, value }: { label: string; value: string }) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast("error", "Could not copy to clipboard");
    }
  }
  return (
    <div
      title={value}
      className="flex min-w-0 items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-hover)] px-3 py-1.5"
    >
      <span className="shrink-0 text-[10px] font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
        {label}
      </span>
      <code className="min-w-0 flex-1 truncate font-mono text-xs">{value || "—"}</code>
      <button
        type="button"
        onClick={() => void copy()}
        disabled={!value}
        aria-label={`Copy ${label}`}
        className="shrink-0 rounded border border-[var(--color-border)] px-2 py-0.5 text-xs text-[var(--color-text-muted)] transition-colors enabled:hover:border-[var(--color-primary)] enabled:hover:text-[var(--color-primary)] disabled:opacity-50"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

/** A prominent notice for a plaintext transport or another weakened default. */
export function TransportWarning({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-md border border-[var(--color-danger)] bg-[var(--color-danger)]/10 p-3 text-xs space-y-1" role="alert">
      <p className="font-semibold text-[var(--color-danger)]">{title}</p>
      <div>{children}</div>
    </div>
  );
}

export function Warnings({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <ul className="rounded-md border border-[var(--color-warning)] bg-[var(--color-warning)]/10 p-3 text-xs list-disc pl-6 space-y-1" role="status">
      {warnings.map((w) => (
        <li key={w} className="break-words">
          {w}
        </li>
      ))}
    </ul>
  );
}

export function ListenerLine({ status, names }: { status?: IdpListenerStatus; names: [keyof IdpListenerStatus, string][] }) {
  if (!status) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      {names.map(([key, label]) => {
        const addr = status[key];
        return (
          <span key={key} className="inline-flex min-w-0 items-center gap-1">
            <span className="text-[var(--color-text-muted)]">{label}</span>
            <Badge variant={addr ? "success" : "neutral"} label={addr ? String(addr) : "not listening"} />
          </span>
        );
      })}
      {status.last_error && (
        <span className="min-w-0 truncate text-[var(--color-danger)]" title={status.last_error}>
          {status.last_error}
        </span>
      )}
    </div>
  );
}

/** A copyable configuration snippet (no secrets ever go in one). */
export function Snippet({ title, text }: { title: string; text: string }) {
  const { toast } = useToast();
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      toast("success", `${title} copied`);
    } catch {
      toast("error", "Could not copy to clipboard");
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <span className="min-w-0 truncate text-xs font-medium text-[var(--color-text-muted)]">{title}</span>
        <button
          type="button"
          onClick={() => void copy()}
          className="shrink-0 rounded border border-[var(--color-border)] px-2 py-0.5 text-xs text-[var(--color-text-muted)] hover:border-[var(--color-primary)] hover:text-[var(--color-primary)]"
        >
          Copy
        </button>
      </div>
      <pre className="overflow-x-auto rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] p-3 font-mono text-xs">
        {text}
      </pre>
    </div>
  );
}

/** `<select>` options for the active environments, with a placeholder. */
export function environmentOptions(names: string[], placeholder = "Select an environment") {
  return [{ value: "", label: placeholder }, ...names.map((n) => ({ value: n, label: n }))];
}
