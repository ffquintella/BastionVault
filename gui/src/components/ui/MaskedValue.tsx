import { useState } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { useToast } from "./Toast";

/**
 * Display a secret value obscured by a blur filter with show/hide and
 * copy-to-clipboard controls.
 *
 * We intentionally do NOT render the value into an `<input type="password">` —
 * Chromium/WebView2 would then propose autosaving it. Plain text inside a
 * blurred `<span>` is display-only and not subject to the form-autofill cache.
 *
 * Copying never requires revealing the value first: the plaintext is already in
 * the renderer (the blur is presentation only), so gating the copy behind the
 * toggle would buy no confidentiality and only cost a click.
 */
export function MaskedValue({ value }: { value: string }) {
  const { toast } = useToast();
  const [visible, setVisible] = useState(false);
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
    <span className="inline-flex items-center gap-2">
      <span className={visible ? "min-w-0 break-all" : "min-w-0 break-all blur-sm select-none"}>
        {value}
      </span>
      <button
        type="button"
        onClick={() => setVisible(!visible)}
        title={visible ? "Hide value" : "Show value"}
        aria-label={visible ? "Hide value" : "Show value"}
        aria-pressed={visible}
        className="shrink-0 rounded border border-[var(--color-border)] p-1 text-[var(--color-text-muted)] transition-colors hover:border-[var(--color-primary)] hover:text-[var(--color-primary)]"
      >
        {visible ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
      <button
        type="button"
        onClick={copy}
        title={copied ? "Copied" : "Copy value to clipboard"}
        aria-label="Copy value to clipboard"
        className="shrink-0 rounded border border-[var(--color-border)] p-1 text-[var(--color-text-muted)] transition-colors hover:border-[var(--color-primary)] hover:text-[var(--color-primary)]"
      >
        {copied ? (
          <Check size={14} className="text-[var(--color-success)]" />
        ) : (
          <Copy size={14} />
        )}
      </button>
    </span>
  );
}
