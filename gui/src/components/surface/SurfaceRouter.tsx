import { useLocation } from "react-router-dom";
import { usePluginSurfacesStore } from "../../stores/pluginSurfacesStore";
import { Layout } from "../Layout";
import { Card, EmptyState } from "../ui";
import { SurfaceTable } from "./SurfaceTable";
import { SurfaceForm } from "./SurfaceForm";
import { SurfaceDetail } from "./SurfaceDetail";

/**
 * Top-level renderer for plugin-contributed pages. Looks up the
 * current path in the active-surface bundle and walks the matching
 * page's component tree, instantiating one of `<SurfaceTable>` /
 * `<SurfaceForm>` / `<SurfaceDetail>` per entry.
 *
 * Mounted at `/plugin/:plugin/*` in App.tsx; the splat pattern lets
 * a plugin declare multiple pages that share a prefix
 * (`/plugin/totp/codes`, `/plugin/totp/codes/:name`, …).
 */
export function SurfaceRouter() {
  const location = useLocation();
  const pageByRoute = usePluginSurfacesStore((s) => s.pageByRoute);
  const loading = usePluginSurfacesStore((s) => s.loading);
  const error = usePluginSurfacesStore((s) => s.error);

  const match = pageByRoute(location.pathname);

  if (loading && !match) {
    return (
      <Layout>
        <div className="p-6 text-sm text-[var(--color-text-muted)]">
          Loading plugin surfaces…
        </div>
      </Layout>
    );
  }
  if (error && !match) {
    return (
      <Layout>
        <div className="p-6">
          <Card>
            <div className="p-4 text-sm text-[var(--color-danger)]">
              Could not load plugin surfaces: {error}
            </div>
          </Card>
        </div>
      </Layout>
    );
  }
  if (!match) {
    return (
      <Layout>
        <div className="p-6">
          <EmptyState
            title="Plugin page not found"
            description={`No registered plugin contributes a page at ${location.pathname}.`}
          />
        </div>
      </Layout>
    );
  }

  const { page, entry } = match;
  const refresh = usePluginSurfacesStore.getState().refresh;

  return (
    <Layout>
      <div className="p-6 space-y-4">
        <div className="flex items-baseline justify-between">
          <h1 className="text-2xl font-bold">{page.title}</h1>
          <span className="text-xs text-[var(--color-text-muted)]">
            {entry.plugin} v{entry.version}
          </span>
        </div>
        <div className="space-y-4">
          {page.components.map((c) => (
            <Card key={c.id}>
              <div className="p-4">
                {c.kind === "table" && (
                  <SurfaceTable
                    spec={c}
                    mount={entry.mount}
                    onAction={() => void refresh()}
                  />
                )}
                {c.kind === "form" && (
                  <SurfaceForm
                    spec={c}
                    mount={entry.mount}
                    onSubmitted={() => void refresh()}
                  />
                )}
                {c.kind === "detail" && (
                  <SurfaceDetail spec={c} mount={entry.mount} />
                )}
              </div>
            </Card>
          ))}
        </div>
      </div>
    </Layout>
  );
}
