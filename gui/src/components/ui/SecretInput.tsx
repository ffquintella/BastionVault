import { useState, type InputHTMLAttributes } from "react";
import { PasswordGenerator } from "./PasswordGenerator";

interface SecretInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
  error?: string;
  hint?: string;
  /** Start with the value visible. Defaults to false (masked). */
  initiallyVisible?: boolean;
  /** Show a dice icon that opens the PasswordGenerator popover. */
  showGenerator?: boolean;
  /**
   * Called with the generated value when the user accepts one from the
   * generator. Caller is responsible for updating its own state. Required
   * when `showGenerator` is true.
   */
  onGenerate?: (value: string) => void;
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
 * changing the underlying input semantics. When `showGenerator` is set, a
 * dice button opens an inline PasswordGenerator popover; the user picks
 * length + character groups, previews, and clicks "Use" to fill the field.
 */
export function SecretInput({
  label,
  error,
  hint,
  className = "",
  id,
  initiallyVisible = false,
  showGenerator = false,
  onGenerate,
  autoComplete,
  spellCheck,
  ...props
}: SecretInputProps) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  const [visible, setVisible] = useState(initiallyVisible);
  const [genOpen, setGenOpen] = useState(false);

  // How much right-side padding the input needs so the overlay buttons do
  // not collide with the text. show/hide = ~pr-12; show/hide + gen = ~pr-20.
  const rightPadding = showGenerator ? "pr-20" : "pr-10";

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
          className={`w-full bg-[var(--color-bg)] border rounded-lg pl-3 ${rightPadding} py-2 text-sm
            placeholder:text-[var(--color-text-muted)]/50
            focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)]
            disabled:opacity-50 disabled:cursor-not-allowed
            ${error ? "border-[var(--color-danger)]" : "border-[var(--color-border)]"}
            ${className}`}
          {...props}
        />

        {/* Show / hide toggle */}
        <button
          type="button"
          tabIndex={-1}
          aria-label={visible ? "Hide secret" : "Show secret"}
          onClick={() => setVisible((v) => !v)}
          className="absolute inset-y-0 right-0 px-3 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)] focus:outline-none"
        >
          {visible ? "hide" : "show"}
        </button>

        {/* Generator toggle (optional) */}
        {showGenerator && (
          <button
            type="button"
            tabIndex={-1}
            aria-label="Generate password"
            title="Generate password"
            onClick={() => setGenOpen((v) => !v)}
            className="absolute inset-y-0 right-10 px-2 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-primary)] focus:outline-none"
          >
            &#x2684;
          </button>
        )}

        {/* Popover. Absolute so it overlays adjacent UI; rendered inline
            (not portaled) so it scrolls with the form. */}
        {showGenerator && genOpen && onGenerate && (
          <div className="absolute right-0 top-full mt-1 z-20">
            <PasswordGenerator
              onGenerate={(v) => onGenerate(v)}
              onClose={() => setGenOpen(false)}
            />
          </div>
        )}
      </div>
      {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
      {hint && !error && <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>}
    </div>
  );
}
