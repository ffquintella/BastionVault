import { useEffect, useMemo, useRef, useState } from "react";
import type { PkiManagedKey, PkiRoleConfig } from "../lib/types";
import * as api from "../lib/api";

/**
 * Collapse a `(key_type, key_bits)` pair to the algorithm the engine
 * resolves it to (`KeyAlgorithm::from_role` in
 * `crates/bv-engine-pki/src/crypto.rs`). `bits = 0` means the default
 * size for RSA/EC; every other family encodes its strength in the name.
 */
function algorithmOf(keyType: string, keyBits: number): string {
  const type = keyType.trim().toLowerCase();
  if (type === "rsa") return `rsa-${keyBits || 2048}`;
  if (type === "ec") return `ec-${keyBits || 256}`;
  return type;
}

export type KeyRefPolicy =
  | { kind: "unknown" }
  | { kind: "reuse-disabled" }
  | { kind: "ok"; compatible: PkiManagedKey[]; incompatible: number };

/**
 * Which managed keys `pki/issue/:role` would accept for `role`. Mirrors
 * the server's `resolve_pinned_key` so the picker never offers a key the
 * engine will refuse: reuse must be enabled, the key must be on the
 * role's `allowed_key_refs` (by id or name) when that list is non-empty,
 * and the key's algorithm must equal the role's.
 */
export function keyRefPolicy(role: PkiRoleConfig | null, keys: PkiManagedKey[]): KeyRefPolicy {
  if (!role) return { kind: "unknown" };
  if (!role.allow_key_reuse) return { kind: "reuse-disabled" };
  const roleAlg = algorithmOf(role.key_type, role.key_bits);
  const allowList = role.allowed_key_refs ?? [];
  const compatible = keys.filter((k) => {
    if (algorithmOf(k.key_type, k.key_bits) !== roleAlg) return false;
    if (allowList.length === 0) return true;
    return allowList.includes(k.key_id) || (!!k.name && allowList.includes(k.name));
  });
  return { kind: "ok", compatible, incompatible: keys.length - compatible.length };
}

function keyLabel(k: PkiManagedKey): string {
  const alg = k.key_bits ? `${k.key_type} ${k.key_bits}` : k.key_type;
  return `${k.name || k.key_id} (${alg})`;
}

interface PkiKeyRefPickerProps {
  mount: string;
  /** Role the key will be pinned under. Empty = no role chosen yet. */
  role: string;
  /** The `key_ref` sent to the engine: a key name or id, or "". */
  value: string;
  onChange: (keyRef: string) => void;
  label?: string;
  disabled?: boolean;
}

/**
 * Typeahead for the optional `key_ref` on issue/renew. Lists the mount's
 * managed keys filtered to the ones the selected role accepts, searchable
 * by name, id and algorithm. Free text is still passed through, so an
 * operator who cannot list keys can paste a name or id; the server stays
 * the authority and refuses anything the role does not allow.
 */
export function PkiKeyRefPicker({
  mount,
  role,
  value,
  onChange,
  label = "Pin managed key (optional)",
  disabled,
}: PkiKeyRefPickerProps) {
  const [keys, setKeys] = useState<PkiManagedKey[] | null>(null);
  const [keysError, setKeysError] = useState(false);
  const [roleConfig, setRoleConfig] = useState<PkiRoleConfig | null>(null);
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    setKeys(null);
    setKeysError(false);
    (async () => {
      try {
        const refs = await api.pkiListKeys(mount);
        const entries = await Promise.all(refs.map((r) => api.pkiReadKey(mount, r).catch(() => null)));
        if (!cancelled) setKeys(entries.filter((k): k is PkiManagedKey => !!k));
      } catch {
        if (!cancelled) {
          setKeys([]);
          setKeysError(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mount]);

  useEffect(() => {
    let cancelled = false;
    setRoleConfig(null);
    if (!role) return;
    api
      .pkiReadRole(mount, role)
      .then((cfg) => {
        if (!cancelled) setRoleConfig(cfg);
      })
      // A caller who can issue but not read the role still gets the
      // unfiltered list; the server enforces the policy either way.
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [mount, role]);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const policy = useMemo(() => keyRefPolicy(roleConfig, keys ?? []), [roleConfig, keys]);
  const candidates = policy.kind === "ok" ? policy.compatible : policy.kind === "unknown" ? keys ?? [] : [];

  const filtered = useMemo(() => {
    const q = value.trim().toLowerCase();
    if (!q) return candidates.slice(0, 50);
    return candidates
      .filter(
        (k) =>
          k.name.toLowerCase().includes(q) ||
          k.key_id.toLowerCase().includes(q) ||
          k.key_type.toLowerCase().includes(q),
      )
      .slice(0, 50);
  }, [candidates, value]);

  let hint: string;
  if (policy.kind === "reuse-disabled") {
    hint = `Role "${role}" does not allow pinning a key (allow_key_reuse is off).`;
  } else if (policy.kind === "ok" && policy.incompatible > 0) {
    hint = `${policy.incompatible} key(s) hidden: wrong algorithm or not in the role's allowed_key_refs.`;
  } else {
    hint = "Leave empty to generate a fresh key.";
  }

  function select(k: PkiManagedKey) {
    onChange(k.name || k.key_id);
    setOpen(false);
  }

  return (
    <div ref={containerRef} className="relative min-w-0">
      <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">{label}</label>
      <input
        type="text"
        role="combobox"
        aria-expanded={open}
        aria-label={label}
        value={value}
        disabled={disabled}
        onFocus={() => setOpen(true)}
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
          if (e.key === "Enter" && open && filtered.length > 0) {
            e.preventDefault();
            select(filtered[0]);
          }
        }}
        placeholder="Search managed keys by name, id or type"
        className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] disabled:opacity-60"
        autoComplete="off"
      />
      {open && !disabled && (
        <div
          role="listbox"
          className="absolute z-10 mt-1 w-full max-h-60 overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg"
        >
          {keys === null ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">Loading keys…</div>
          ) : keysError ? (
            <div className="px-3 py-2 text-xs text-[var(--color-text-muted)] italic">
              Key listing denied. Type the key name or id directly.
            </div>
          ) : policy.kind === "reuse-disabled" ? (
            <div className="px-3 py-2 text-xs text-[var(--color-text-muted)]">
              This role does not allow key reuse. Enable allow_key_reuse on the role to pin a key.
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-3 py-2 text-sm text-[var(--color-text-muted)]">
              {value.trim() ? "No compatible key matches" : "No compatible managed keys on this mount"}
            </div>
          ) : (
            filtered.map((k) => (
              <button
                key={k.key_id}
                type="button"
                role="option"
                aria-selected={value === k.name || value === k.key_id}
                onClick={() => select(k)}
                className="w-full text-left px-3 py-2 hover:bg-[var(--color-surface-hover)] flex items-center justify-between gap-2"
              >
                <span className="text-sm min-w-0 truncate font-medium">{keyLabel(k)}</span>
                <span className="font-mono text-[10px] text-[var(--color-text-muted)] truncate max-w-[50%]">
                  {k.key_id}
                </span>
              </button>
            ))
          )}
        </div>
      )}
      <p className="text-xs text-[var(--color-text-muted)] mt-1 truncate">{hint}</p>
    </div>
  );
}
