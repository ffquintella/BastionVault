import { useState } from "react";
import { useToast } from "./Toast";

interface CopyablePathProps {
  /** The full, namespace-qualified ACL path (already assembled by the caller). */
  path: string;
  /** Small caption above the path. Defaults to "Policy path". */
  label?: string;
  /**
   * Optional hint explaining that this is the string to drop into a policy
   * `path "..."` stanza. Rendered as the row's tooltip rather than a second
   * line so the control stays a single row.
   */
  hint?: string;
}

/**
 * Displays a full, namespace-qualified ACL path in monospace with a
 * copy-to-clipboard control. The namespace prefix matters because policies
 * created inside a namespace must reference namespace-prefixed paths
 * (see `src/modules/namespace/policy_scope.rs`), which is exactly the form
 * assembled by callers and shown here.
 */
export function CopyablePath({
  path,
  label = "Policy path",
  hint,
}: CopyablePathProps) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
      toast("success", "Path copied to clipboard");
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast("error", "Could not copy to clipboard");
    }
  }

  return (
    <div
      title={hint ? `${path} — ${hint}` : path}
      className="flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-hover)] px-3 py-1.5"
    >
      <span className="shrink-0 text-[10px] font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
        {label}
      </span>
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-[var(--color-text)]">
        {path}
      </code>
      <button
        type="button"
        onClick={copy}
        title="Copy full path"
        className="shrink-0 rounded border border-[var(--color-border)] px-2 py-0.5 text-xs text-[var(--color-text-muted)] transition-colors hover:border-[var(--color-primary)] hover:text-[var(--color-primary)]"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
