import { useCallback, useState, type ReactNode } from "react";
import { useLocation, useSearchParams } from "react-router";
import { usePluginSurfacesStore } from "../../stores/pluginSurfacesStore";
import { SUPPORTED_SURFACE_SCHEMA_VERSION, type SurfaceForm as SurfaceFormSpec } from "../../lib/api";
import { Layout } from "../Layout";
import { Card, EmptyState } from "../ui";
import { SurfaceTable } from "./SurfaceTable";
import { SurfaceForm } from "./SurfaceForm";
import { SurfaceDetail } from "./SurfaceDetail";

function SurfaceFrame({
  children,
  pluginWindow,
}: {
  children: ReactNode;
  pluginWindow: boolean;
}) {
  return pluginWindow ? (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      {children}
    </div>
  ) : (
    <Layout>{children}</Layout>
  );
}

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
  const [searchParams] = useSearchParams();
  const pageByRoute = usePluginSurfacesStore((s) => s.pageByRoute);
  const loading = usePluginSurfacesStore((s) => s.loading);
  const error = usePluginSurfacesStore((s) => s.error);
  // Bumped whenever a component on the page changes server data (a form
  // submit, a table row action). Every table re-issues its `list` binding
  // when it moves, so a record added by a form shows up without leaving
  // the page.
  const [dataRevision, setDataRevision] = useState(0);
  const markDataChanged = useCallback(() => setDataRevision((r) => r + 1), []);

  // Extensibility v2 (Phase 3): when rendered inside a plugin-owned
  // window (`?pluginWindow=<handle>`), drop the host sidebar/chrome and
  // render the page bare — the window is a focused surface, not the
  // full app. The window handle is threaded to `subscribe`-enabled
  // components so they consume `plugin-window-data-<handle>` events.
  const pluginWindow = searchParams.get("pluginWindow");
  const isPluginWindow = pluginWindow != null;

  const match = pageByRoute(location.pathname);

  if (loading && !match) {
    return (
      <SurfaceFrame pluginWindow={isPluginWindow}>
        <div className="p-6 text-sm text-[var(--color-text-muted)]">
          Loading plugin surfaces…
        </div>
      </SurfaceFrame>
    );
  }
  if (error && !match) {
    return (
      <SurfaceFrame pluginWindow={isPluginWindow}>
        <div className="p-6">
          <Card>
            <div className="p-4 text-sm text-[var(--color-danger)]">
              Could not load plugin surfaces: {error}
            </div>
          </Card>
        </div>
      </SurfaceFrame>
    );
  }
  if (!match) {
    return (
      <SurfaceFrame pluginWindow={isPluginWindow}>
        <div className="p-6">
          <EmptyState
            title="Plugin page not found"
            description={`No registered plugin contributes a page at ${location.pathname}.`}
          />
        </div>
      </SurfaceFrame>
    );
  }

  const { page, entry } = match;
  const refresh = usePluginSurfacesStore.getState().refresh;

  // A surface newer than this GUI is not rendered: the keys it relies on
  // were dropped on the way here, so it would render as something else
  // (e.g. modal forms inline, an Edit button that only reads).
  const schemaVersion = entry.surface.schema_version;
  if (typeof schemaVersion === "number" && schemaVersion > SUPPORTED_SURFACE_SCHEMA_VERSION) {
    return (
      <SurfaceFrame pluginWindow={isPluginWindow}>
        <div className="p-6">
          <EmptyState
            title="Update BastionVault to open this page"
            description={`${entry.plugin} v${entry.version} uses plugin page schema ${schemaVersion}; this version of BastionVault renders up to ${SUPPORTED_SURFACE_SCHEMA_VERSION}.`}
          />
        </div>
      </SurfaceFrame>
    );
  }

  // Schema v2: modal forms stay off the page; table actions and row
  // actions on the same page open them.
  const modalForms: Record<string, SurfaceFormSpec> = {};
  for (const c of page.components) {
    if (c.kind === "form" && c.presentation === "modal") modalForms[c.id] = c;
  }
  const inlineComponents = page.components.filter(
    (c) => !(c.kind === "form" && c.presentation === "modal"),
  );

  if (!entry.mount.trim()) {
    return (
      <SurfaceFrame pluginWindow={isPluginWindow}>
        <div className="p-6">
          <EmptyState
            title="Plugin mount required"
            description={`${entry.plugin} is not mounted in the active namespace. Open Admin → Mounts, choose Mount Engine, and select ${entry.plugin} as the engine type.`}
          />
        </div>
      </SurfaceFrame>
    );
  }

  return (
    <SurfaceFrame pluginWindow={isPluginWindow}>
      <div className="p-6 space-y-4">
        <div className="flex items-baseline justify-between">
          <h1 className="text-2xl font-bold">{page.title}</h1>
          <span className="text-xs text-[var(--color-text-muted)]">
            {entry.plugin} v{entry.version}
          </span>
        </div>
        <div className="space-y-4">
          {inlineComponents.map((c) => (
            <Card key={c.id}>
              <div className="p-4">
                {c.kind === "table" && (
                  <SurfaceTable
                    spec={c}
                    mount={entry.mount}
                    revision={dataRevision}
                    onAction={() => {
                      markDataChanged();
                      void refresh();
                    }}
                    entry={entry}
                    forms={modalForms}
                  />
                )}
                {c.kind === "form" && (
                  <SurfaceForm
                    spec={c}
                    entry={entry}
                    onSubmitted={markDataChanged}
                  />
                )}
                {c.kind === "detail" && (
                  <SurfaceDetail
                    spec={c}
                    mount={entry.mount}
                    windowHandle={pluginWindow}
                  />
                )}
              </div>
            </Card>
          ))}
        </div>
      </div>
    </SurfaceFrame>
  );
}
