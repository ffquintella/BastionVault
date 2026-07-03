import { useEffect, useMemo, useRef, useState } from "react";
import type { GroupKind } from "../../lib/types";
import * as api from "../../lib/api";

interface GroupNamePickerProps {
  /** "user" → identity groups bundling UserPass principals,
   *  "app" → groups bundling AppID principals. */
  kind: GroupKind;
  /** Currently selected group name (empty when nothing chosen). */
  value: string;
  onChange: (name: string) => void;
  label?: string;
  hint?: string;
  placeholder?: string;
}

/**
 * Typeahead picker for identity group names. Loads the list lazily on
 * first focus via `listGroups(kind)`. Falls back to raw free-text entry
 * if the endpoint is denied — admins on legacy tokens can still type a
 * name and the parent's onChange fires.
 */
export function GroupNamePicker({
  kind,
  value,
  onChange,
  label,
  hint,
  placeholder = "Start typing a group name...",
}: GroupNamePickerProps) {
  const [names, setNames] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Reload the list whenever `kind` flips so the user sees the right
  // pool after switching from User → App group in the parent modal.
  useEffect(() => {
    setNames(null);
    setLoadError(false);
  }, [kind]);

  async function ensureLoaded() {
    if (names !== null || loading) return;
    setLoading(true);
    try {
      const list = await api.listGroups(kind);
      setNames(list.groups ?? []);
      setLoadError(false);
    } catch {
      setNames([]);
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const filtered = useMemo(() => {
    if (!names) return [];
    const q = value.trim().toLowerCase();
    if (!q) return names.slice(0, 50);
    return names.filter((n) => n.toLowerCase().includes(q)).slice(0, 50);
  }, [names, value]);

  return (
    <div ref={containerRef} className="relative">
      {label && (
        <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
          {label}
        </label>
      )}
      <input
        type="text"
        value={value}
        onFocus={() => {
          setOpen(true);
          ensureLoaded();
        }}
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
        }}
        placeholder={placeholder}
        className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
        autoComplete="off"
      />
      {open && (
        <div className="absolute z-10 mt-1 w-full max-h-60 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg">
          {loading ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">
              Loading groups...
            </div>
          ) : loadError ? (
            <div className="px-3 py-2 text-xs text-[var(--color-text-muted)] italic">
              Group lookup denied. Type the group name directly.
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">
              {value.trim() ? "No matches" : "No groups on record yet"}
            </div>
          ) : (
            filtered.map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => {
                  onChange(n);
                  setOpen(false);
                }}
                className={`w-full text-left px-3 py-2 hover:bg-[var(--color-surface-hover)] ${
                  n === value ? "bg-[var(--color-surface-hover)]" : ""
                }`}
              >
                <span className="text-sm font-medium">{n}</span>
              </button>
            ))
          )}
        </div>
      )}
      {hint && (
        <p className="text-xs text-[var(--color-text-muted)] mt-1">{hint}</p>
      )}
    </div>
  );
}
