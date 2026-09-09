import { useEffect, useMemo, useRef, useState } from "react";
import type { ShareTargetKind } from "../../lib/types";
import * as api from "../../lib/api";

interface TargetPickerProps {
  /** Which kind is being picked. Determines the dropdown source and
   *  the placeholder. */
  kind: ShareTargetKind;
  /** Current value (resource name or KV path). */
  value: string;
  /** Called whenever the user edits the field or selects a suggestion. */
  onChange: (v: string) => void;
  /** Input label. */
  label?: string;
}

/**
 * Typeahead picker for share targets.
 *
 * - `resource`: loads resource names via `listResources` on first
 *   focus and filters client-side.
 * - `kv-secret`: loads the set of KV paths already carried by asset
 *   groups (via `listAssetGroups` → `read_asset_group`), which is the
 *   only cheap enumeration of "known" secret paths we have without
 *   recursively walking the KV mount. Operators can also type any
 *   path directly; the input is free-form.
 * - `asset-group`: (not surfaced on the manage-target tab today, but
 *   cheap to support) loads asset group names.
 * - `file`: loads file ids and reads each one's metadata so the
 *   dropdown can show the display name. The *value* is always the
 *   server-assigned UUID — that is what the share record and the ACL
 *   evaluator key on; names are editable and not unique.
 *
 * Lookup fails open — if the relevant list endpoint is denied, the
 * picker silently degrades to a plain text input. Matches the
 * behavior of `EntityPicker` so operator experience is consistent.
 */
/** Options whose display text is the value itself. */
function plain(vals: string[]): { value: string; label: string }[] {
  return vals.map((v) => ({ value: v, label: v }));
}

export function TargetPicker({
  kind,
  value,
  onChange,
  label,
}: TargetPickerProps) {
  // `value` is what a selection writes back; `label` is what the row
  // shows. They differ only for `file`, where the target is a UUID but
  // the operator thinks in file names.
  const [options, setOptions] = useState<
    { value: string; label: string }[] | null
  >(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Reload whenever the caller switches kinds.
  useEffect(() => {
    setOptions(null);
  }, [kind]);

  async function ensureLoaded() {
    if (options !== null || loading) return;
    setLoading(true);
    try {
      if (kind === "resource") {
        const r = await api.listResources();
        setOptions(plain(r.resources ?? []));
      } else if (kind === "file") {
        const r = await api.listFiles();
        const metas = await Promise.all(
          (r.ids ?? []).map((id) => api.readFileMeta(id).catch(() => null)),
        );
        setOptions(
          (r.ids ?? []).map((id, i) => {
            const name = metas[i]?.name;
            return { value: id, label: name ? `${name} — ${id}` : id };
          }),
        );
      } else if (kind === "kv-secret") {
        // Enumerate paths already referenced by asset groups — cheap
        // and covers the "known secrets" set. Operators can still type
        // any path not present in a group.
        const groups = await api.listAssetGroups();
        const names = await Promise.all(
          (groups.groups ?? []).map((g) =>
            api.readAssetGroup(g).catch(() => null),
          ),
        );
        const paths = new Set<string>();
        for (const g of names) {
          if (!g) continue;
          for (const s of g.secrets ?? []) paths.add(s);
        }
        setOptions(plain(Array.from(paths).sort()));
      } else if (kind === "asset-group") {
        const r = await api.listAssetGroups();
        setOptions(plain(r.groups ?? []));
      } else {
        setOptions([]);
      }
    } catch {
      setOptions([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const filtered = useMemo(() => {
    if (!options) return [];
    const q = value.trim().toLowerCase();
    if (!q) return options.slice(0, 25);
    return options
      .filter(
        (o) =>
          o.value.toLowerCase().includes(q) ||
          o.label.toLowerCase().includes(q),
      )
      .slice(0, 25);
  }, [options, value]);

  const placeholder =
    kind === "resource"
      ? "server-01"
      : kind === "kv-secret"
      ? "secret/foo/bar"
      : kind === "file"
      ? "file id (UUID)"
      : "asset group name";

  const hint =
    kind === "kv-secret"
      ? "Type any KV path; suggestions are drawn from existing asset groups."
      : kind === "file"
      ? "Search by file name; the share is stored against the file's id."
      : undefined;

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
              Loading...
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-3 py-2 text-xs text-[var(--color-text-muted)] italic">
              {value.trim()
                ? "No matches — will use this value as-is"
                : "Start typing to search"}
            </div>
          ) : (
            filtered.map((o) => (
              <button
                key={o.value}
                type="button"
                onClick={() => {
                  onChange(o.value);
                  setOpen(false);
                }}
                className={`w-full text-left px-3 py-2 text-sm font-mono hover:bg-[var(--color-surface-hover)] ${
                  o.value === value ? "bg-[var(--color-surface-hover)]" : ""
                }`}
              >
                {o.label}
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
