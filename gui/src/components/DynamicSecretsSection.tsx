import { useEffect, useState } from "react";
import { Badge, Button, Card, EmptyState } from "./ui";
import { DynamicCredsModal } from "./DynamicCredsModal";
import * as api from "../lib/api";
import { extractError, isPermissionDenied } from "../lib/error";

/** Mount type prefix of a plugin mount (`src/plugins/mod.rs`, PLUGIN_MOUNT_PREFIX). */
const PLUGIN_MOUNT_PREFIX = "plugin:";

interface DynamicMount {
  path: string;
  plugin: string;
  engineType: string | null;
}

type Roles = { state: "loading" } | { state: "ok"; roles: string[] } | { state: "error"; message: string };

/**
 * Secrets → Dynamic (T62, features/dynamic-secrets.md Phase 5): the mounts of
 * `secret/dynamic` plugins and their roles, each with "Generate credential".
 * A plugin mount's type names only the plugin, so the plugin catalog
 * (`GET /v2/sys/plugins?kind=secret/dynamic`) tells which mounts are dynamic.
 */
export function DynamicSecretsSection() {
  const [mounts, setMounts] = useState<DynamicMount[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [roles, setRoles] = useState<Record<string, Roles>>({});
  const [generating, setGenerating] = useState<{ mount: string; role: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.listMounts(), api.pluginsListByKind(api.PLUGIN_TYPE_DYNAMIC)])
      .then(([all, plugins]) => {
        if (cancelled) return;
        const engines = new Map(plugins.map((p) => [p.name, p.engine_type ?? null]));
        const dynamic = all
          .filter((m) => m.mount_type.startsWith(PLUGIN_MOUNT_PREFIX))
          .map((m) => ({ path: m.path, plugin: m.mount_type.slice(PLUGIN_MOUNT_PREFIX.length) }))
          .filter((m) => engines.has(m.plugin))
          .map((m) => ({ ...m, engineType: engines.get(m.plugin) ?? null }));
        setMounts(dynamic);
        for (const m of dynamic) loadRoles(m.path, () => cancelled);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(
          isPermissionDenied(e)
            ? "Your token cannot read the plugin catalog (sys/plugins), so dynamic-secret mounts cannot be told apart from other plugin mounts."
            : extractError(e),
        );
        setMounts([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function loadRoles(path: string, cancelled: () => boolean) {
    setRoles((r) => ({ ...r, [path]: { state: "loading" } }));
    api
      .dynamicListRoles(path)
      .then((list) => {
        if (!cancelled()) setRoles((r) => ({ ...r, [path]: { state: "ok", roles: list } }));
      })
      .catch((e) => {
        if (!cancelled()) setRoles((r) => ({ ...r, [path]: { state: "error", message: extractError(e) } }));
      });
  }

  if (mounts === null) {
    return <p className="text-sm text-[var(--color-text-muted)]">Loading dynamic mounts...</p>;
  }
  if (error) {
    return <p className="text-sm text-[var(--color-danger)]" role="alert">{error}</p>;
  }
  if (mounts.length === 0) {
    return (
      <EmptyState
        title="No dynamic-secret engines mounted"
        description="Register a secret/dynamic plugin on the Plugins page and mount it from the Mounts page."
      />
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--color-text-muted)]">
        Each credential is created on the target system when you generate it, is shown once, and is
        revoked when its lease ends. Manage leases on the Leases page.
      </p>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {mounts.map((m) => {
          const r = roles[m.path];
          return (
            <Card key={m.path}>
              <div className="flex items-center gap-2 flex-wrap mb-3 min-w-0">
                <span className="font-mono text-[var(--color-primary)] font-medium truncate min-w-0" title={m.path}>
                  {m.path}
                </span>
                <Badge label={m.plugin} variant="neutral" />
                {m.engineType && <Badge label={m.engineType} variant="info" />}
              </div>
              {!r || r.state === "loading" ? (
                <p className="text-xs text-[var(--color-text-muted)]">Loading roles...</p>
              ) : r.state === "error" ? (
                <p className="text-xs text-[var(--color-danger)] break-words">{r.message}</p>
              ) : r.roles.length === 0 ? (
                <p className="text-xs text-[var(--color-text-muted)]">No roles defined on this mount.</p>
              ) : (
                <ul className="space-y-1" aria-label={`Roles of ${m.path}`}>
                  {r.roles.map((role) => (
                    <li
                      key={role}
                      className="flex items-center justify-between gap-3 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm"
                    >
                      <span className="font-mono truncate min-w-0" title={role}>{role}</span>
                      <Button size="sm" onClick={() => setGenerating({ mount: m.path, role })}>
                        Generate credential
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          );
        })}
      </div>
      {generating && (
        <DynamicCredsModal
          mount={generating.mount}
          role={generating.role}
          onClose={() => setGenerating(null)}
        />
      )}
    </div>
  );
}
