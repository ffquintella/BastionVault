import type { InputHTMLAttributes } from "react";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export function Input({
  label,
  error,
  hint,
  className = "",
  id,
  autoComplete,
  spellCheck,
  ...props
}: InputProps) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  // Default every field to non-autofillable + no spellcheck. This is a desktop
  // secrets-management UI — we never want Chromium/WebView2 persisting typed
  // values to its Web Data / autofill SQLite cache (see CHANGELOG 2026-04-18).
  // Callers can still opt in explicitly by passing autoComplete / spellCheck.
  return (
    <div className="space-y-1">
      {label && (
        <label htmlFor={inputId} className="block text-sm font-medium text-[var(--color-text-muted)]">
          {label}
        </label>
      )}
      <input
        id={inputId}
        autoComplete={autoComplete ?? "off"}
        spellCheck={spellCheck ?? false}
        data-form-type="other"
        data-lpignore="true"
        data-1p-ignore="true"
        className={`w-full bg-[var(--color-bg)] border rounded-lg px-3 py-2 text-sm
          placeholder:text-[var(--color-text-muted)]/50
          focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)]
          disabled:opacity-50 disabled:cursor-not-allowed
          ${error ? "border-[var(--color-danger)]" : "border-[var(--color-border)]"}
          ${className}`}
        {...props}
      />
      {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
      {hint && !error && <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>}
    </div>
  );
}
