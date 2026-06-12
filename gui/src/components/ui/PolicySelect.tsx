import { useState } from "react";
import type { KeyboardEvent } from "react";

import { Input } from "./Input";

interface PolicySelectProps {
  label?: string;
  /** Currently-selected policy names. */
  selected: string[];
  /** Known/grantable policy names — the only values the autocomplete will add (the validator). */
  options: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  /**
   * When true the known-policy list could not be fetched (e.g. the caller lacks
   * admin on the policies path); degrade to a plain comma-separated free-text
   * field so the editor still works rather than locking the operator out.
   */
  fallbackFreeText?: boolean;
  helpText?: string;
}

/**
 * Selected entries that are not known policies — surfaced with a ⚠ in the UI and
 * used by callers to block a save that would silently grant nothing (a mistyped
 * or since-deleted policy name).
 */
export function unknownPolicies(selected: string[], options: string[]): string[] {
  return selected.filter((p) => !options.includes(p));
}

/**
 * Multi-select autocomplete over a vault's existing policies. Type to filter,
 * Enter or click to add — only names present in `options` can be added, so a
 * typo can't slip through. Selected policies show as removable chips; any that
 * are not (or no longer) known render with a ⚠ so the operator can fix them.
 */
export function PolicySelect({
  label,
  selected,
  options,
  onChange,
  placeholder,
  fallbackFreeText,
  helpText,
}: PolicySelectProps) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const inputId = label?.toLowerCase().replace(/\s+/g, "-");

  // No policy list available — fall back to a free-text comma field.
  if (fallbackFreeText) {
    return (
      <div className="space-y-1">
        {label && (
          <label htmlFor={inputId} className="block text-sm font-medium text-[var(--color-text-muted)]">
            {label}
          </label>
        )}
        <Input
          id={inputId}
          value={selected.join(",")}
          onChange={(e) => onChange(e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
          placeholder={placeholder || "reader,administrator"}
        />
        <p className="text-xs text-[var(--color-text-muted)]">
          Could not list policies — enter names manually, comma-separated.
        </p>
      </div>
    );
  }

  const q = query.trim().toLowerCase();
  const suggestions = options
    .filter((p) => !selected.includes(p))
    .filter((p) => (q ? p.toLowerCase().includes(q) : true));

  function add(policy: string) {
    if (!options.includes(policy) || selected.includes(policy)) return;
    onChange([...selected, policy]);
    setQuery("");
  }
  function remove(policy: string) {
    onChange(selected.filter((p) => p !== policy));
  }
  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      // An exact (case-insensitive) match wins; otherwise the lone suggestion.
      const exact = options.find((p) => p.toLowerCase() === q && !selected.includes(p));
      if (exact) add(exact);
      else if (suggestions.length === 1) add(suggestions[0]);
    } else if (e.key === "Backspace" && !query && selected.length) {
      remove(selected[selected.length - 1]);
    }
  }

  const unknown = unknownPolicies(selected, options);

  return (
    <div className="space-y-1">
      {label && (
        <label htmlFor={inputId} className="block text-sm font-medium text-[var(--color-text-muted)]">
          {label}
        </label>
      )}
      <div
        className={`w-full bg-[var(--color-bg)] border rounded-lg px-2 py-1.5
          focus-within:ring-2 focus-within:ring-[var(--color-primary)]/40 focus-within:border-[var(--color-primary)]
          ${unknown.length ? "border-amber-500" : "border-[var(--color-border)]"}`}
      >
        <div className="flex flex-wrap items-center gap-1.5">
          {selected.map((p) => {
            const bad = !options.includes(p);
            return (
              <span
                key={p}
                className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs ${
                  bad
                    ? "bg-amber-500/20 text-amber-600"
                    : "bg-[var(--color-primary)]/15 text-[var(--color-primary)]"
                }`}
              >
                {bad ? `${p} ⚠` : p}
                <button
                  type="button"
                  onClick={() => remove(p)}
                  className="leading-none hover:opacity-70"
                  aria-label={`Remove ${p}`}
                >
                  ×
                </button>
              </span>
            );
          })}
          <input
            id={inputId}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 120)}
            onKeyDown={onKeyDown}
            autoComplete="off"
            spellCheck={false}
            data-1p-ignore="true"
            placeholder={selected.length ? "" : placeholder || "type to search policies…"}
            className="flex-1 min-w-[8rem] bg-transparent px-1 py-0.5 text-sm focus:outline-none placeholder:text-[var(--color-text-muted)]/50"
          />
        </div>
      </div>
      {open && suggestions.length > 0 && (
        <div className="relative">
          <ul className="absolute z-10 mt-1 max-h-48 w-full overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] py-1 shadow-lg">
            {suggestions.map((p) => (
              <li key={p}>
                <button
                  type="button"
                  // onMouseDown (not onClick) so the add fires before the
                  // input's onBlur closes the list.
                  onMouseDown={(e) => {
                    e.preventDefault();
                    add(p);
                  }}
                  className="block w-full px-3 py-1.5 text-left text-sm hover:bg-[var(--color-primary)]/10"
                >
                  {p}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {unknown.length > 0 ? (
        <p className="text-xs text-amber-600">
          Unknown {unknown.length > 1 ? "policies" : "policy"}: {unknown.join(", ")} — remove or create them.
        </p>
      ) : helpText ? (
        <p className="text-xs text-[var(--color-text-muted)]">{helpText}</p>
      ) : null}
    </div>
  );
}
