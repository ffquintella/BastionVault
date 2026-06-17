import { useEffect, useState } from "react";
import * as api from "../lib/api";

const STORAGE_KEY = "bv.activeNamespace";

/**
 * Top-of-sidebar namespace picker (multi-tenancy). Selecting a namespace sets
 * the session's active namespace on the backend — every subsequent logical
 * request carries the `X-BastionVault-Namespace` header — then reloads so all
 * pages re-fetch their data under the new tenant. The backend `AppState` is the
 * source of truth across webview reloads; `localStorage` only mirrors the
 * current value for display continuity.
 */
export function NamespaceSwitcher() {
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [active, setActive] = useState<string>("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [list, current] = await Promise.all([
          api.listNamespaces().catch(() => ({ namespaces: [] as string[] })),
          api.getActiveNamespace().catch(() => ""),
        ]);
        if (cancelled) return;
        setNamespaces(list.namespaces);
        setActive(current);
        if (current) localStorage.setItem(STORAGE_KEY, current);
        else localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* namespaces unavailable (e.g. minimal build) — hide gracefully */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function onChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const next = e.target.value;
    setBusy(true);
    try {
      await api.setActiveNamespace(next);
      if (next) localStorage.setItem(STORAGE_KEY, next);
      else localStorage.removeItem(STORAGE_KEY);
      // Reload so every page re-fetches under the new namespace.
      window.location.reload();
    } catch {
      setBusy(false);
    }
  }

  // Nothing to switch between — don't clutter the sidebar on single-tenant
  // deployments that never created a child namespace.
  if (namespaces.length === 0 && !active) return null;

  return (
    <div className="mt-3">
      <label className="block text-[10px] uppercase tracking-wide text-[var(--color-text-muted)] mb-1">
        Namespace
      </label>
      <select
        value={active}
        onChange={onChange}
        disabled={busy}
        className="w-full text-sm rounded-md bg-[var(--color-bg)] border border-[var(--color-border)] px-2 py-1.5 min-w-0 truncate"
      >
        <option value="">root</option>
        {namespaces.map((ns) => (
          <option key={ns} value={ns}>
            {ns}
          </option>
        ))}
      </select>
    </div>
  );
}
