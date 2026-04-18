import { useState, type InputHTMLAttributes } from "react";

interface SecretInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
  error?: string;
  hint?: string;
  /** Start with the value visible. Defaults to false (masked). */
  initiallyVisible?: boolean;
}

/**
 * Password-typed input for secret values.
 *
 * Hardened against WebView2 / browser form-autofill capture:
 *  - type="password" + autoComplete="new-password" so Chromium never stores
 *    the value in its Web Data (autofill) SQLite cache.
 *  - spellCheck={false} so the renderer does not ship the text to a speller.
 *  - data-* hints to pacify common password managers (1Password, LastPass).
 *
 * A built-in show/hide toggle lets the user verify what they typed without
 * changing the underlying input semantics.
 */
export function SecretInput({
  label,
  error,
  hint,
  className = "",
  id,
  initiallyVisible = false,
  autoComplete,
  spellCheck,
  ...props
}: SecretInputProps) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  const [visible, setVisible] = useState(initiallyVisible);

  return (
    <div className="space-y-1">
      {label && (
        <label htmlFor={inputId} className="block text-sm font-medium text-[var(--color-text-muted)]">
          {label}
        </label>
      )}
      <div className="relative">
        <input
          id={inputId}
          type={visible ? "text" : "password"}
          autoComplete={autoComplete ?? "new-password"}
          spellCheck={spellCheck ?? false}
          data-form-type="other"
          data-lpignore="true"
          data-1p-ignore="true"
          className={`w-full bg-[var(--color-bg)] border rounded-lg pl-3 pr-10 py-2 text-sm
            placeholder:text-[var(--color-text-muted)]/50
            focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)]
            disabled:opacity-50 disabled:cursor-not-allowed
            ${error ? "border-[var(--color-danger)]" : "border-[var(--color-border)]"}
            ${className}`}
          {...props}
        />
        <button
          type="button"
          tabIndex={-1}
          aria-label={visible ? "Hide secret" : "Show secret"}
          onClick={() => setVisible((v) => !v)}
          className="absolute inset-y-0 right-0 px-3 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)] focus:outline-none"
        >
          {visible ? "hide" : "show"}
        </button>
      </div>
      {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
      {hint && !error && <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>}
    </div>
  );
}
