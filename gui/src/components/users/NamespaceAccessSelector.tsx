/**
 * Namespace login-restriction chips, shared by the userpass and SSO user
 * dialogs. Hidden on single-tenant installs (no child namespaces). An empty
 * selection means the principal may authenticate into any namespace; the
 * root namespace is offered as the "root" chip (value "").
 */
export function NamespaceAccessSelector({
  available,
  selected,
  onToggle,
  label = "Allowed namespaces",
}: {
  available: string[];
  selected: string[];
  onToggle: (ns: string) => void;
  label?: string;
}) {
  if (available.length === 0) return null;
  const options = ["", ...available];
  return (
    <div>
      <label className="block text-sm text-[var(--color-text-muted)] mb-1">{label}</label>
      <div className="flex flex-wrap gap-2">
        {options.map((ns) => {
          const isSelected = selected.includes(ns);
          return (
            <button
              key={ns || "__root__"}
              type="button"
              aria-pressed={isSelected}
              onClick={() => onToggle(ns)}
              className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                isSelected
                  ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                  : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
              }`}
            >
              {ns === "" ? "root" : ns}
            </button>
          );
        })}
      </div>
      <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
        {selected.length === 0
          ? "No restriction — this user may log in to any namespace."
          : `Login restricted to: ${selected.map((n) => n || "root").join(", ")} (and descendants).`}
      </p>
    </div>
  );
}
