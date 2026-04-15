import type { TextareaHTMLAttributes } from "react";

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
}

export function Textarea({ label, error, className = "", id, ...props }: TextareaProps) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  return (
    <div className="space-y-1">
      {label && (
        <label htmlFor={inputId} className="block text-sm font-medium text-[var(--color-text-muted)]">
          {label}
        </label>
      )}
      <textarea
        id={inputId}
        className={`w-full bg-[var(--color-bg)] border rounded-lg px-3 py-2 text-sm font-mono
          placeholder:text-[var(--color-text-muted)]/50
          focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)]
          disabled:opacity-50 resize-y min-h-[120px]
          ${error ? "border-[var(--color-danger)]" : "border-[var(--color-border)]"}
          ${className}`}
        {...props}
      />
      {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
    </div>
  );
}
