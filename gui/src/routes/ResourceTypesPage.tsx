import { Layout } from "../components/Layout";
import { ResourceTypesCard } from "../components/ResourceTypesCard";
import { useNamespaceStore } from "../stores/namespaceStore";

/**
 * Resource types for the active namespace. Settings (where the root
 * namespace edits them) is root-only, so this is how a child namespace
 * manages its own `resources/config/types` — including opting a type in to
 * web credential release. In the root namespace it edits the same
 * configuration Settings → Resources does.
 */
export function ResourceTypesPage() {
  const activeNamespace = useNamespaceStore((s) => s.active);
  return (
    <Layout>
      <div className="space-y-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold">Resource Types</h1>
          <p className="text-sm text-[var(--color-text-muted)] truncate">
            {activeNamespace ? `Namespace ${activeNamespace}` : "Root namespace"}
          </p>
        </div>
        {/* Remount on a namespace switch so the card reads the new mount. */}
        <ResourceTypesCard key={activeNamespace} inNamespace={activeNamespace !== ""} />
      </div>
    </Layout>
  );
}
