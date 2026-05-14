import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { StatusBadge } from "../components/StatusBadge";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import type { MountInfo } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function DashboardPage() {
  const setStatus = useVaultStore((s) => s.setStatus);
  const status = useVaultStore((s) => s.status);
  const policies = useAuthStore((s) => s.policies);
  const principal = useAuthStore((s) => s.principal);
  const entityId = useAuthStore((s) => s.entityId);
  const loadEntity = useAuthStore((s) => s.loadEntity);
  const [mounts, setMounts] = useState<MountInfo[]>([]);
  const [authMethods, setAuthMethods] = useState<MountInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboard();
    // Hydrate the logged-in user's display name on first mount. The
    // store keeps `principal` empty until something asks `entity/self`
    // — without this call, opening the app straight on /dashboard
    // would show an empty greeting until the user visited Sharing.
    if (!principal) loadEntity().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadDashboard() {
    try {
      const [st, m, a] = await Promise.all([
        api.getVaultStatus(),
        api.listMounts().catch(() => [] as MountInfo[]),
        api.listAuthMethods().catch(() => [] as MountInfo[]),
      ]);
      setStatus(st);
      setMounts(m);
      setAuthMethods(a);
    } catch (e: unknown) {
      setError(extractError(e));
    }
  }

  async function handleSeal() {
    try {
      await api.sealVault();
      const st = await api.getVaultStatus();
      setStatus(st);
    } catch (e: unknown) {
      setError(extractError(e));
    }
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Dashboard</h1>
            {principal && (
              <p
                className="text-sm text-[var(--color-text-muted)] mt-0.5"
                title={entityId || undefined}
              >
                Signed in as <span className="font-medium text-[var(--color-text)]">{principal}</span>
              </p>
            )}
          </div>
          {status && (
            <StatusBadge
              status={status.sealed ? "error" : "ok"}
              label={status.sealed ? "Sealed" : "Unsealed"}
            />
          )}
        </div>

        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Status cards */}
        <div className="grid grid-cols-3 gap-4">
          <Card title="Vault Status">
            {status ? (
              <div className="space-y-2 text-sm">
                <Row label="Initialized" value={status.initialized ? "Yes" : "No"} />
                <Row label="Sealed" value={status.sealed ? "Yes" : "No"} />
              </div>
            ) : (
              <span className="text-[var(--color-text-muted)] text-sm">Loading...</span>
            )}
          </Card>

          <Card title="Policies">
            <div className="space-y-1">
              {policies.length > 0 ? (
                policies.map((p) => (
                  <span
                    key={p}
                    className="inline-block mr-1 mb-1 px-2 py-0.5 bg-[var(--color-bg)] rounded text-xs"
                  >
                    {p}
                  </span>
                ))
              ) : (
                <span className="text-[var(--color-text-muted)] text-sm">None</span>
              )}
            </div>
          </Card>

          <Card title="Actions">
            <button
              onClick={handleSeal}
              disabled={status?.sealed}
              className="px-3 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-sm hover:bg-red-500/30 disabled:opacity-50 transition-colors"
            >
              Seal Vault
            </button>
          </Card>
        </div>

        {/* Secret Engines */}
        <Card title="Secret Engines">
          {mounts.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--color-text-muted)] text-left">
                  <th className="pb-2 font-medium">Path</th>
                  <th className="pb-2 font-medium">Type</th>
                  <th className="pb-2 font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                {mounts.map((m) => (
                  <tr key={m.path} className="border-t border-[var(--color-border)]">
                    <td className="py-2 font-mono text-[var(--color-primary)]">{m.path}</td>
                    <td className="py-2">{m.mount_type}</td>
                    <td className="py-2 text-[var(--color-text-muted)]">{m.description || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <span className="text-[var(--color-text-muted)] text-sm">No secret engines mounted</span>
          )}
        </Card>

        {/* Auth Methods */}
        <Card title="Auth Methods">
          {authMethods.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--color-text-muted)] text-left">
                  <th className="pb-2 font-medium">Path</th>
                  <th className="pb-2 font-medium">Type</th>
                </tr>
              </thead>
              <tbody>
                {authMethods.map((m) => (
                  <tr key={m.path} className="border-t border-[var(--color-border)]">
                    <td className="py-2 font-mono text-[var(--color-primary)]">{m.path}</td>
                    <td className="py-2">{m.mount_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <span className="text-[var(--color-text-muted)] text-sm">No auth methods enabled</span>
          )}
        </Card>
      </div>
    </Layout>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-4">
      <h3 className="text-sm font-medium text-[var(--color-text-muted)] mb-3">{title}</h3>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-[var(--color-text-muted)]">{label}</span>
      <span>{value}</span>
    </div>
  );
}
