import { useEffect, useMemo, useRef, useState } from "react";
import type { EntityAliasInfo } from "../../lib/types";
import * as api from "../../lib/api";

interface EntityPickerProps {
  /** Currently selected `entity_id`. Empty string when nothing chosen. */
  value: string;
  /** Called when the user picks an alias from the dropdown. */
  onChange: (entityId: string, alias: EntityAliasInfo | null) => void;
  /** Input label. */
  label?: string;
  /** Hint text shown below the input. */
  hint?: string;
  /** Placeholder when empty. */
  placeholder?: string;
  /** Restrict the dropdown to aliases on a specific mount (e.g.,
   *  `"userpass/"`). Falsy = all mounts. */
  mountFilter?: string;
}

/**
 * Typeahead picker that resolves a login (mount + principal name)
 * to a stable `entity_id`. Loads the alias list lazily on first
 * focus and filters client-side. Fails open — if the list can't
 * load (e.g. caller lacks access to `identity/entity/aliases`), the
 * input falls back to raw `entity_id` entry so admin-flows still
 * work.
 */
export function EntityPicker({
  value,
  onChange,
  label = "Grantee",
  hint,
  placeholder = "Start typing a login...",
  mountFilter,
}: EntityPickerProps) {
  const [aliases, setAliases] = useState<EntityAliasInfo[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Reflect external value changes: if the parent resets `value`,
  // clear the query so the picker is usable again.
  useEffect(() => {
    if (value === "" && query !== "") {
      setQuery("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  async function ensureLoaded() {
    if (aliases !== null || loading) return;
    setLoading(true);
    try {
      const list = await api.listEntityAliases();
      setAliases(list);
      setLoadError(false);
    } catch {
      setAliases([]);
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
    if (!aliases) return [];
    const q = query.trim().toLowerCase();
    let base = aliases;
    if (mountFilter) {
      base = base.filter((a) => a.mount === mountFilter);
    }
    if (!q) return base.slice(0, 25);
    return base
      .filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          a.mount.toLowerCase().includes(q) ||
          a.entity_id.toLowerCase().includes(q),
      )
      .slice(0, 25);
  }, [aliases, query, mountFilter]);

  const selectedAlias = useMemo(() => {
    if (!aliases || !value) return null;
    return aliases.find((a) => a.entity_id === value) ?? null;
  }, [aliases, value]);

  function select(alias: EntityAliasInfo) {
    onChange(alias.entity_id, alias);
    setQuery(`${alias.name} @ ${alias.mount}`);
    setOpen(false);
  }

  function handleInput(e: React.ChangeEvent<HTMLInputElement>) {
    setQuery(e.target.value);
    setOpen(true);
    // If the caller typed in a full UUID, pass it through directly.
    // Useful when the aliases endpoint is restricted and the admin
    // already knows the target entity_id.
    const v = e.target.value.trim();
    if (v.length >= 32 && /^[0-9a-fA-F-]+$/.test(v)) {
      onChange(v, null);
    } else if (v === "") {
      onChange("", null);
    }
  }

  return (
    <div ref={containerRef} className="relative">
      {label && (
        <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
          {label}
        </label>
      )}
      <input
        type="text"
        value={query || (selectedAlias ? `${selectedAlias.name} @ ${selectedAlias.mount}` : value)}
        onFocus={() => {
          setOpen(true);
          ensureLoaded();
        }}
        onChange={handleInput}
        placeholder={placeholder}
        className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
        autoComplete="off"
      />
      {open && (
        <div className="absolute z-10 mt-1 w-full max-h-60 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg">
          {loading ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">
              Loading users...
            </div>
          ) : loadError ? (
            <div className="px-3 py-2 text-xs text-[var(--color-text-muted)] italic">
              Directory lookup denied. Paste the grantee's entity_id directly.
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">
              {query.trim() ? "No matches" : "No entities on record yet"}
            </div>
          ) : (
            filtered.map((a) => (
              <button
                key={`${a.mount}|${a.name}`}
                type="button"
                onClick={() => select(a)}
                className={`w-full text-left px-3 py-2 hover:bg-[var(--color-surface-hover)] flex items-center justify-between gap-2 ${
                  a.entity_id === value ? "bg-[var(--color-surface-hover)]" : ""
                }`}
              >
                <span className="text-sm">
                  <span className="font-medium">{a.name}</span>
                  <span className="text-[var(--color-text-muted)]"> @ {a.mount}</span>
                </span>
                <span className="font-mono text-[10px] text-[var(--color-text-muted)] truncate max-w-[50%]">
                  {a.entity_id}
                </span>
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
