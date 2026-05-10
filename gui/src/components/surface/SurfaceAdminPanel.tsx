import { useMemo, useState } from "react";
import * as api from "../../lib/api";
import { usePluginSurfacesStore } from "../../stores/pluginSurfacesStore";
import { Button, Card, Modal } from "../ui";

/**
 * Plugin Extensibility v1 / Phase 6 — operator UX redesign.
 *
 * Two pieces:
 *
 * 1. [`<SurfaceStats>`] — small inline badge cluster the
 *    `PluginRow` renders alongside the existing capability badges.
 *    Reports menu / page / asset counts + a *Preview surface*
 *    button.
 * 2. [`<ActiveSurfaceMapCard>`] — full-width card rendered below
 *    the registered-plugins list. Walks every active plugin's
 *    surface and shows a tree of contributed menus, useful for
 *    spotting collisions before activate.
 *
 * Both read from the existing `usePluginSurfacesStore` populated
 * by Phase 5's watcher loop, so the UI auto-refreshes without
 * extra plumbing.
 */

/** Compact "M menus / P pages / A assets" badge cluster + the
 *  Preview-Surface trigger. Renders nothing for plugins that ship
 *  no surface (the v1 plugins from before Phase 0 of this redesign).
 */
export function SurfaceStats({ pluginName }: { pluginName: string }) {
  const bundle = usePluginSurfacesStore((s) => s.bundle);
  const [previewOpen, setPreviewOpen] = useState(false);

  const entry = useMemo(
    () => bundle?.entries.find((e) => e.plugin === pluginName),
    [bundle, pluginName],
  );
  if (!entry) return null;

  const menuCount = entry.surface.menus?.length ?? 0;
  const pageCount = entry.surface.pages?.length ?? 0;
  const assetCount = entry.assets.length;

  return (
    <>
      <div className="flex flex-wrap items-center gap-1 mt-1.5">
        <span
          title="Menu entries this plugin contributes to the sidebar"
          className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-blue-500/20 text-blue-400"
        >
          {menuCount} menu{menuCount === 1 ? "" : "s"}
        </span>
        <span
          title="Plugin-rendered pages"
          className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-blue-500/20 text-blue-400"
        >
          {pageCount} page{pageCount === 1 ? "" : "s"}
        </span>
        {assetCount > 0 && (
          <span
            title="Client-side WASM assets (form hooks)"
            className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-purple-500/20 text-purple-400"
          >
            {assetCount} asset{assetCount === 1 ? "" : "s"}
          </span>
        )}
        <button
          type="button"
          onClick={() => setPreviewOpen(true)}
          className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-border)] transition-colors"
        >
          Preview surface
        </button>
      </div>
      {previewOpen && (
        <PreviewSurfaceModal
          entry={entry}
          onClose={() => setPreviewOpen(false)}
        />
      )}
    </>
  );
}

/** Modal that breaks down a single plugin's surface contribution
 *  without actually mounting it: menu list grouped by section, page
 *  components keyed by ID, raw JSON view as fallback for anything
 *  the structured view doesn't surface yet. */
function PreviewSurfaceModal({
  entry,
  onClose,
}: {
  entry: api.ActiveSurfaceEntry;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<"structured" | "raw">("structured");

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Preview ${entry.plugin} v${entry.version}`}
      size="lg"
    >
      <div className="flex gap-2 mb-3 text-sm">
        <button
          type="button"
          onClick={() => setTab("structured")}
          className={`px-3 py-1 rounded ${
            tab === "structured"
              ? "bg-[var(--color-primary)] text-white"
              : "bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]"
          }`}
        >
          Structured
        </button>
        <button
          type="button"
          onClick={() => setTab("raw")}
          className={`px-3 py-1 rounded ${
            tab === "raw"
              ? "bg-[var(--color-primary)] text-white"
              : "bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]"
          }`}
        >
          Raw JSON
        </button>
      </div>

      {tab === "structured" ? (
        <SurfaceStructuredView entry={entry} />
      ) : (
        <pre className="text-xs font-mono bg-[var(--color-bg)] border border-[var(--color-border)] rounded p-3 overflow-auto max-h-[60vh]">
          {JSON.stringify(entry.surface, null, 2)}
        </pre>
      )}
    </Modal>
  );
}

function SurfaceStructuredView({ entry }: { entry: api.ActiveSurfaceEntry }) {
  const { surface, mount, assets } = entry;
  const menus = surface.menus ?? [];
  const pages = surface.pages ?? [];

  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap gap-2 text-xs">
        <span className="px-2 py-0.5 rounded bg-[var(--color-surface-hover)]">
          mount: <code className="font-mono">{mount || "—"}</code>
        </span>
        <span className="px-2 py-0.5 rounded bg-[var(--color-surface-hover)]">
          schema_version: {surface.schema_version}
        </span>
      </div>

      <section>
        <h4 className="font-semibold text-sm mb-1">Menus ({menus.length})</h4>
        {menus.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">
            This plugin contributes no sidebar entries.
          </p>
        ) : (
          <ul className="space-y-1 text-xs">
            {menus.map((m) => (
              <li
                key={m.id}
                className="flex items-baseline gap-2 font-mono"
              >
                <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                  {m.section}
                </span>
                <span className="text-[var(--color-text)]">{m.label}</span>
                <span className="text-[var(--color-text-muted)]">
                  {m.route}
                </span>
                {m.min_policy && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400">
                    needs {m.min_policy}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h4 className="font-semibold text-sm mb-1">Pages ({pages.length})</h4>
        {pages.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">
            No pages declared.
          </p>
        ) : (
          <ul className="space-y-2 text-xs">
            {pages.map((p) => (
              <li
                key={p.route}
                className="border border-[var(--color-border)] rounded p-2"
              >
                <div className="flex items-baseline justify-between">
                  <span className="font-medium">{p.title}</span>
                  <code className="font-mono text-[var(--color-text-muted)]">
                    {p.route}
                  </code>
                </div>
                <ul className="mt-1 ml-4 list-disc space-y-0.5 text-[var(--color-text-muted)]">
                  {p.components.map((c) => (
                    <li key={c.id}>
                      <code className="font-mono">{c.kind}</code>{" "}
                      <code className="font-mono">{c.id}</code>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </section>

      {assets.length > 0 && (
        <section>
          <h4 className="font-semibold text-sm mb-1">
            Client assets ({assets.length})
          </h4>
          <ul className="space-y-0.5 text-xs font-mono">
            {assets.map(([name, sha]) => (
              <li key={sha}>
                {name}{" "}
                <span className="text-[var(--color-text-muted)]">
                  · {sha.slice(0, 16)}…
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

/** Aggregated tree of every active plugin's menu contributions,
 *  grouped by section. The collision detector flags two menus that
 *  declare the same `route` — a bug surface authors hit when they
 *  copy-paste a template and forget to retitle. */
export function ActiveSurfaceMapCard() {
  const bundle = usePluginSurfacesStore((s) => s.bundle);
  const refresh = usePluginSurfacesStore((s) => s.refresh);
  const loading = usePluginSurfacesStore((s) => s.loading);

  const sections: api.SurfaceSection[] = [
    "secrets",
    "sharing",
    "admin",
    "settings",
  ];

  // Detect duplicate routes across plugins — these would surface as
  // two sidebar entries pointing at the same page, which is almost
  // always an authoring mistake.
  const collisions = useMemo(() => {
    const byRoute = new Map<string, string[]>();
    for (const entry of bundle?.entries ?? []) {
      for (const menu of entry.surface.menus ?? []) {
        const list = byRoute.get(menu.route) ?? [];
        list.push(entry.plugin);
        byRoute.set(menu.route, list);
      }
    }
    return Array.from(byRoute.entries()).filter(([, plugins]) => plugins.length > 1);
  }, [bundle]);

  return (
    <Card title="Active surface map">
      <div className="flex items-baseline justify-between mb-2">
        <p className="text-xs text-[var(--color-text-muted)]">
          Tree of every menu the active version of every active plugin
          contributes. Useful for spotting route collisions before flipping a
          version live.
        </p>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void refresh()}
          disabled={loading}
        >
          {loading ? "Refreshing…" : "Refresh"}
        </Button>
      </div>

      {collisions.length > 0 && (
        <div className="mb-3 p-2 border border-[var(--color-danger)] rounded bg-[var(--color-danger)]/10 text-xs">
          <strong className="text-[var(--color-danger)]">
            {collisions.length} route collision
            {collisions.length === 1 ? "" : "s"} detected:
          </strong>
          <ul className="mt-1 space-y-0.5">
            {collisions.map(([route, plugins]) => (
              <li key={route} className="font-mono">
                {route}{" "}
                <span className="text-[var(--color-text-muted)]">
                  — claimed by {plugins.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!bundle || bundle.entries.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">
          No active plugin surfaces. Register and activate a plugin that ships
          a <code className="font-mono">surface.json</code> to see entries
          here.
        </p>
      ) : (
        <div className="space-y-3">
          {sections.map((section) => {
            const items = (bundle.entries ?? []).flatMap((entry) =>
              (entry.surface.menus ?? [])
                .filter((m) => m.section === section)
                .map((menu) => ({ entry, menu })),
            );
            if (items.length === 0) return null;
            return (
              <section key={section}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-1">
                  {section} ({items.length})
                </h4>
                <ul className="space-y-1 text-xs">
                  {items.map(({ entry, menu }) => (
                    <li
                      key={`${entry.plugin}#${menu.id}`}
                      className="flex items-baseline gap-2 font-mono"
                    >
                      <span className="px-1.5 py-0.5 rounded bg-[var(--color-surface-hover)]">
                        {entry.plugin}@{entry.version}
                      </span>
                      <span className="text-[var(--color-text)]">
                        {menu.label}
                      </span>
                      <span className="text-[var(--color-text-muted)]">
                        {menu.route}
                      </span>
                      {menu.min_policy && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400">
                          needs {menu.min_policy}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
          {bundle.etag && (
            <p className="text-[10px] text-[var(--color-text-muted)] font-mono">
              etag: {bundle.etag.slice(0, 16)}…
            </p>
          )}
        </div>
      )}
    </Card>
  );
}
