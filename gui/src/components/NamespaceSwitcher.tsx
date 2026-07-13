import { useEffect, useState } from "react";
import { useNamespaceStore } from "../stores/namespaceStore";

/**
 * Top-of-sidebar namespace picker (multi-tenancy). Selecting a namespace sets
 * the session's active namespace on the backend — every subsequent logical
 * request carries the `X-BastionVault-Namespace` header — then reloads so all
 * pages re-fetch their data under the new tenant.
 *
 * State lives in `useNamespaceStore`, a module-level cache seeded from
 * `localStorage`. Because each page mounts its own `<Layout>`, an in-component
 * fetch would re-run on every navigation and briefly render nothing — the
 * "disappear then reappear" flicker. The store persists across route changes,
 * so the switcher paints its cached value immediately and refreshes in the
 * background only once per session.
 */
export function NamespaceSwitcher() {
  const namespaces = useNamespaceStore((s) => s.namespaces);
  const active = useNamespaceStore((s) => s.active);
  const ensureLoaded = useNamespaceStore((s) => s.ensureLoaded);
  const setActive = useNamespaceStore((s) => s.setActive);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void ensureLoaded();
  }, [ensureLoaded]);

  async function onChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const next = e.target.value;
    setBusy(true);
    try {
      await setActive(next);
      // Reload so every page re-fetches under the new namespace.
      window.location.reload();
    } catch {
      setBusy(false);
    }
  }

  // Nothing to switch between — don't clutter the sidebar on single-tenant
  // deployments that never created a child namespace. Seeded from cache, so
  // multi-tenant sessions render immediately without a load flicker.
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
