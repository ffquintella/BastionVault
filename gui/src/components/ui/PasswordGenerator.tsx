import { useEffect, useRef, useState } from "react";
import { Button } from "./Button";
import { generatePassword, type PasswordOptions } from "../../lib/password";
import { usePasswordPolicyStore } from "../../stores/passwordPolicyStore";

interface PasswordGeneratorProps {
  /** Called with the generated password when the user clicks "Use". */
  onGenerate: (value: string) => void;
  /** Called when the user dismisses the popover (Cancel / outside-click / Esc). */
  onClose: () => void;
  /** Initial length; defaults to 24 (subject to policy clamp). */
  defaultLength?: number;
}

/**
 * Inline popover that generates a cryptographically-random password with
 * user-configurable length and character groups. Intended to be positioned
 * with absolute positioning by the parent (e.g. below a SecretInput).
 *
 * Respects the configured password policy: the length never goes below
 * `policy.min_length`, and any groups marked required by the policy are
 * forced ON (their toggles are disabled). Users may raise the length or
 * enable additional non-required groups.
 */
export function PasswordGenerator({ onGenerate, onClose, defaultLength = 24 }: PasswordGeneratorProps) {
  const policy = usePasswordPolicyStore((s) => s.policy);
  const loadPolicy = usePasswordPolicyStore((s) => s.load);
  const policyLoaded = usePasswordPolicyStore((s) => s.loaded);

  // Kick off a policy fetch the first time the popover opens. No-op if
  // already loaded or in flight.
  useEffect(() => {
    if (!policyLoaded) loadPolicy();
  }, [policyLoaded, loadPolicy]);

  const minLength = Math.max(1, policy.min_length);
  const [length, setLength] = useState(Math.max(defaultLength, minLength));
  const [lowercase, setLowercase] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(policy.require_symbols);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);
  const [preview, setPreview] = useState("");
  const rootRef = useRef<HTMLDivElement | null>(null);

  // If the policy becomes stricter while the popover is open, bump our
  // local state so we never violate it.
  useEffect(() => {
    if (length < minLength) setLength(minLength);
    if (policy.require_lowercase && !lowercase) setLowercase(true);
    if (policy.require_uppercase && !uppercase) setUppercase(true);
    if (policy.require_digits && !digits) setDigits(true);
    if (policy.require_symbols && !symbols) setSymbols(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy]);

  // Effective flags: toggles off in local state are forced on if the policy
  // requires them. This is what is actually fed into generatePassword().
  const effLower = lowercase || policy.require_lowercase;
  const effUpper = uppercase || policy.require_uppercase;
  const effDigits = digits || policy.require_digits;
  const effSymbols = symbols || policy.require_symbols;

  const opts: PasswordOptions = {
    length,
    lowercase: effLower,
    uppercase: effUpper,
    digits: effDigits,
    symbols: effSymbols,
    excludeAmbiguous,
  };
  const anyGroup = effLower || effUpper || effDigits || effSymbols;

  // Regenerate preview whenever any option changes.
  useEffect(() => {
    if (anyGroup) setPreview(generatePassword(opts));
    else setPreview("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [length, lowercase, uppercase, digits, symbols, excludeAmbiguous, policy]);

  // Close on Escape + outside click.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    function onClick(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose();
    }
    document.addEventListener("keydown", onKey);
    const t = setTimeout(() => document.addEventListener("mousedown", onClick), 0);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
      clearTimeout(t);
    };
  }, [onClose]);

  function reroll() {
    if (anyGroup) setPreview(generatePassword(opts));
  }

  function commit() {
    if (preview) {
      onGenerate(preview);
      onClose();
    }
  }

  const policyShown =
    minLength > 1 ||
    policy.require_lowercase ||
    policy.require_uppercase ||
    policy.require_digits ||
    policy.require_symbols;

  return (
    <div
      ref={rootRef}
      role="dialog"
      aria-label="Password generator"
      className="z-20 w-80 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg space-y-3"
    >
      {/* Preview row */}
      <div className="flex items-center gap-2">
        <code
          className="flex-1 min-w-0 truncate font-mono text-xs bg-[var(--color-bg)] px-2 py-1.5 rounded border border-[var(--color-border)]"
          title={preview}
        >
          {preview || (anyGroup ? "\u00a0" : "Select at least one group")}
        </code>
        <button
          type="button"
          onClick={reroll}
          disabled={!anyGroup}
          title="Reroll"
          aria-label="Reroll"
          className="shrink-0 text-xs px-2 py-1 rounded border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
        >
          &#x21bb;
        </button>
      </div>

      {/* Length */}
      <div className="space-y-1">
        <div className="flex justify-between text-xs text-[var(--color-text-muted)]">
          <label htmlFor="pwgen-length">
            Length
            {minLength > 1 && <span className="ml-1">(min {minLength})</span>}
          </label>
          <span className="font-mono">{length}</span>
        </div>
        <div className="flex items-center gap-2">
          <input
            id="pwgen-length"
            type="range"
            min={minLength}
            max={Math.max(128, minLength)}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            className="flex-1 accent-[var(--color-primary)]"
          />
          <input
            type="number"
            min={minLength}
            max={512}
            value={length}
            onChange={(e) => {
              const n = Number(e.target.value);
              if (Number.isFinite(n)) {
                setLength(Math.max(minLength, Math.min(512, Math.floor(n))));
              }
            }}
            className="w-16 text-xs bg-[var(--color-bg)] border border-[var(--color-border)] rounded px-2 py-1"
          />
        </div>
      </div>

      {/* Character groups */}
      <div className="grid grid-cols-2 gap-1 text-xs">
        <Toggle
          label="Lowercase (a-z)"
          checked={effLower}
          onChange={setLowercase}
          locked={policy.require_lowercase}
        />
        <Toggle
          label="Uppercase (A-Z)"
          checked={effUpper}
          onChange={setUppercase}
          locked={policy.require_uppercase}
        />
        <Toggle
          label="Digits (0-9)"
          checked={effDigits}
          onChange={setDigits}
          locked={policy.require_digits}
        />
        <Toggle
          label="Symbols (!@#...)"
          checked={effSymbols}
          onChange={setSymbols}
          locked={policy.require_symbols}
        />
        <Toggle
          label="Exclude 0/O/1/l/I"
          checked={excludeAmbiguous}
          onChange={setExcludeAmbiguous}
          className="col-span-2"
        />
      </div>

      {policyShown && (
        <p className="text-[10px] text-[var(--color-text-muted)] leading-snug">
          {"Policy enforced from Settings → Password Policy. Locked groups cannot be disabled from here."}
        </p>
      )}

      {/* Actions */}
      <div className="flex justify-end gap-2 pt-1">
        <Button variant="ghost" size="sm" onClick={onClose}>
          Cancel
        </Button>
        <Button size="sm" onClick={commit} disabled={!preview}>
          Use
        </Button>
      </div>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  locked = false,
  className = "",
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  locked?: boolean;
  className?: string;
}) {
  return (
    <label
      className={`flex items-center gap-2 select-none ${
        locked ? "cursor-not-allowed" : "cursor-pointer"
      } ${className}`}
      title={locked ? "Required by policy" : undefined}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={locked}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-[var(--color-primary)]"
      />
      <span
        className={`${
          locked ? "text-[var(--color-text-muted)]/80" : "text-[var(--color-text-muted)]"
        }`}
      >
        {label}
        {locked && <span className="ml-1 text-[9px] uppercase tracking-wider">req</span>}
      </span>
    </label>
  );
}
