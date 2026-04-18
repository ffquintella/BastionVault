import { useState } from "react";

/**
 * Display a secret value obscured by a blur filter with a show/hide toggle.
 *
 * We intentionally do NOT render the value into an `<input type="password">` —
 * Chromium/WebView2 would then propose autosaving it. Plain text inside a
 * blurred `<span>` is display-only and not subject to the form-autofill cache.
 */
export function MaskedValue({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <span className="inline-flex items-center gap-2">
      <span className={visible ? "" : "blur-sm select-none"}>{value}</span>
      <button
        type="button"
        onClick={() => setVisible(!visible)}
        className="text-xs text-[var(--color-primary)] hover:underline shrink-0"
      >
        {visible ? "Hide" : "Show"}
      </button>
    </span>
  );
}
