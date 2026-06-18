import { useEffect, useRef, useState } from "react";
import { Layout } from "../components/Layout";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import type { AuditEvent } from "../lib/types";
import * as api from "../lib/api";
import type { DashboardSummary, ServerInfo } from "../lib/api";
import {
  rustionTelemetryList,
  rustionTargetHealthAll,
  type RustionTelemetryTarget,
  type RustionTargetHealth,
} from "../lib/rustion";
import { extractError } from "../lib/error";
import { KpiTile } from "../components/dashboard/KpiTile";
import { HealthStrip } from "../components/dashboard/HealthStrip";
import { SessionActivityChart } from "../components/dashboard/SessionActivityChart";
import { RecentAuditCard } from "../components/dashboard/RecentAuditCard";
import { LiveSessionsCard } from "../components/dashboard/LiveSessionsCard";
import { AttentionPanel } from "../components/dashboard/AttentionPanel";
import { QuickActions } from "../components/dashboard/QuickActions";

const POLL_MS = 5000;

export function DashboardPage() {
  const setStatus = useVaultStore((s) => s.setStatus);
  const status = useVaultStore((s) => s.status);
  const principal = useAuthStore((s) => s.principal);
  const entityId = useAuthStore((s) => s.entityId);
  const loadEntity = useAuthStore((s) => s.loadEntity);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [server, setServer] = useState<ServerInfo | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [telemetry, setTelemetry] = useState<RustionTelemetryTarget[] | null>(null);
  const [health, setHealth] = useState<RustionTargetHealth[] | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const liveLoaded = useRef(false);

  useEffect(() => {
    loadDashboard();
    if (!principal) loadEntity().catch(() => {});
    const id = setInterval(pollLive, POLL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadDashboard() {
    const now = Date.now();
    const from = new Date(now - 24 * 3600_000).toISOString();
    const to = new Date(now).toISOString();

    const [st, sum, srv, ev, tel, hl] = await Promise.allSettled([
      api.getVaultStatus(),
      api.dashboardSummary(),
      api.getServerInfo(),
      api.listAuditEvents(from, to, 200),
      rustionTelemetryList(),
      rustionTargetHealthAll(),
    ]);

    if (st.status === "fulfilled") setStatus(st.value);
    else setError(extractError(st.reason));

    setSummary(sum.status === "fulfilled" ? sum.value : null);
    setServer(srv.status === "fulfilled" ? srv.value : null);
    setAudit(ev.status === "fulfilled" ? ev.value : []);
    setTelemetry(tel.status === "fulfilled" ? tel.value : null);
    setHealth(hl.status === "fulfilled" ? hl.value : null);
    liveLoaded.current = true;
    setNowMs(Date.now());
    setLoading(false);
  }

  // Only the live-session widgets poll; the rest is manual-refresh.
  async function pollLive() {
    const [tel, hl] = await Promise.allSettled([
      rustionTelemetryList(),
      rustionTargetHealthAll(),
    ]);
    if (tel.status === "fulfilled") setTelemetry(tel.value);
    if (hl.status === "fulfilled") setHealth(hl.value);
    setNowMs(Date.now());
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

  const sealed = status ? status.sealed : summary ? summary.seal.sealed : null;

  // Bastion health rollup.
  const enabledHealth = health?.filter((h) => h.enabled) ?? null;
  const healthyCount = enabledHealth?.filter((h) => h.status === "up").length ?? null;
  const totalCount = enabledHealth?.length ?? null;
  const problemCount =
    enabledHealth?.filter((h) => h.status === "down" || h.status === "degraded").length ?? 0;

  // Active session rollup.
  const activeSessions =
    telemetry?.reduce((n, t) => n + (t.stats?.active ?? t.active.length), 0) ?? null;

  // Audit 24h: prefer the server-computed total; fall back to the
  // fetched window length when the summary endpoint is unavailable.
  const audit24h = summary ? summary.audit_24h_total : audit.length > 0 ? audit.length : null;

  return (
    <Layout>
      <div className="space-y-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <h1 className="text-2xl font-bold">Dashboard</h1>
            {principal && (
              <p
                className="text-sm text-[var(--color-text-muted)] mt-0.5"
                title={entityId || undefined}
              >
                {summary?.namespace ? `${summary.namespace} · ` : ""}Signed in as{" "}
                <span className="font-medium text-[var(--color-text)]">{principal}</span>
              </p>
            )}
          </div>
          <HealthStrip sealed={sealed} server={server} />
        </div>

        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* KPI tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <KpiTile
            label="Live sessions"
            value={activeSessions}
            sub={activeSessions ? "through bastion" : undefined}
            subTone="muted"
            unavailableHint="no bastion"
            to="/rustion-sessions"
            loading={loading}
          />
          <KpiTile
            label="Bastions healthy"
            value={totalCount === null ? null : `${healthyCount}/${totalCount}`}
            sub={problemCount > 0 ? `${problemCount} need attention` : "all up"}
            subTone={problemCount > 0 ? "warning" : "success"}
            unavailableHint="no bastion"
            to="/rustion-sessions"
            loading={loading}
          />
          <KpiTile
            label="Secret engines"
            value={summary ? summary.counts.secret_mounts : null}
            sub={summary ? `${summary.counts.auth_mounts} auth methods` : undefined}
            unavailableHint="unavailable"
            to="/mounts"
            loading={loading}
          />
          <KpiTile
            label="Policies"
            value={summary ? summary.counts.policies : null}
            unavailableHint="unavailable"
            to="/policies"
            loading={loading}
          />
          <KpiTile
            label="Identities"
            value={summary ? summary.counts.entities : null}
            unavailableHint="unavailable"
            to="/users"
            loading={loading}
          />
          <KpiTile
            label="Audit events 24h"
            value={audit24h}
            sub={
              summary && summary.audit_24h_denied > 0
                ? `${summary.audit_24h_denied} denied`
                : undefined
            }
            subTone="danger"
            unavailableHint="unavailable"
            to="/audit"
            loading={loading}
          />
        </div>

        {/* Activity chart + attention */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SessionActivityChart events={audit} nowMs={nowMs} loading={loading} />
          <AttentionPanel
            sealed={sealed}
            health={health}
            auditWriteFailures={summary ? summary.audit_24h_write_failures : null}
            failedLogins1h={summary ? summary.failed_logins_1h : null}
            loading={loading}
          />
        </div>

        {/* Live sessions + recent audit */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <LiveSessionsCard targets={telemetry} nowMs={nowMs} loading={loading} />
          <RecentAuditCard events={audit} nowMs={nowMs} loading={loading} />
        </div>

        <QuickActions sealed={sealed} onSeal={handleSeal} />
      </div>
    </Layout>
  );
}
