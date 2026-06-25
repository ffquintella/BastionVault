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
import { UserDashboard } from "../components/dashboard/UserDashboard";
import { UnsealModal } from "../components/UnsealModal";
import { ConfirmModal } from "../components/ui";
import { isAdminUser } from "../lib/access";

const POLL_MS = 5000;

export function DashboardPage() {
  const setStatus = useVaultStore((s) => s.setStatus);
  const status = useVaultStore((s) => s.status);
  const principal = useAuthStore((s) => s.principal);
  const entityId = useAuthStore((s) => s.entityId);
  const loadEntity = useAuthStore((s) => s.loadEntity);
  const policies = useAuthStore((s) => s.policies);
  // Standard users get a cropped dashboard scoped to what's shared with
  // them; the operator KPIs (engines, policies, identities, audit,
  // bastion telemetry, seal) are all admin-only and would just render
  // "unavailable" for them.
  const isAdmin = isAdminUser(policies);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [server, setServer] = useState<ServerInfo | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [telemetry, setTelemetry] = useState<RustionTelemetryTarget[] | null>(null);
  const [health, setHealth] = useState<RustionTargetHealth[] | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sealConfirm, setSealConfirm] = useState(false);
  const [sealing, setSealing] = useState(false);
  const [unsealOpen, setUnsealOpen] = useState(false);
  const mode = useVaultStore((s) => s.mode);
  const liveLoaded = useRef(false);

  useEffect(() => {
    if (!principal) loadEntity().catch(() => {});
    if (!isAdmin) {
      // Non-admin: only the header's status/version badges need data;
      // everything else lives in <UserDashboard>, which fetches its own
      // shares. Skip the operator endpoints entirely so we don't fire a
      // burst of calls that resolve to "permission denied".
      loadLite();
      return;
    }
    loadDashboard();
    const id = setInterval(pollLive, POLL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Header-only fetch for the cropped (non-admin) dashboard: vault seal
  // state + server info drive the <HealthStrip> badges; both are
  // readable by any authenticated token.
  async function loadLite() {
    const [st, srv] = await Promise.allSettled([
      api.getVaultStatus(),
      api.getServerInfo(),
    ]);
    if (st.status === "fulfilled") setStatus(st.value);
    if (srv.status === "fulfilled") setServer(srv.value);
    setNowMs(Date.now());
    setLoading(false);
  }

  async function loadDashboard() {
    // Fetch the latest events with no time window — the "Recent activity"
    // feed shows the most recent happenings regardless of age (their
    // relative-time labels make the age obvious), while the chart + KPI
    // scope to 24h client-side. This keeps the dashboard correct even if
    // the server were to ignore the window params.
    const [st, sum, srv, ev, tel, hl] = await Promise.allSettled([
      api.getVaultStatus(),
      api.dashboardSummary(),
      api.getServerInfo(),
      api.listAuditEvents("", "", 200),
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
    setSealing(true);
    try {
      const outcome = await api.sealVault();
      setStatus(outcome.status);
      setSealConfirm(false);
      // Cluster fan-out: surface any node that refused to seal.
      const failed = outcome.nodes.filter((n) => n.error);
      if (failed.length > 0) {
        setError(
          `Sealed ${outcome.nodes.length - failed.length}/${outcome.nodes.length} nodes. Failed: ${failed
            .map((n) => `${n.address} (${n.error})`)
            .join(", ")}`,
        );
      } else {
        setError(null);
      }
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setSealing(false);
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

  // Audit 24h: prefer the server-computed total; otherwise count the
  // fetched events that fall within the last 24h (the fetch is unwindowed,
  // so we must filter here, not use the raw length).
  const cutoff24h = nowMs - 24 * 3600_000;
  const audit24h = summary
    ? summary.audit_24h_total
    : audit.length > 0
      ? audit.filter((e) => Date.parse(e.ts) >= cutoff24h).length
      : null;

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

        {!isAdmin ? (
          <UserDashboard />
        ) : (
        <>
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

        <QuickActions
          sealed={sealed}
          onSeal={() => setSealConfirm(true)}
          onUnseal={() => setUnsealOpen(true)}
        />
        </>
        )}
      </div>

      <ConfirmModal
        open={sealConfirm}
        onClose={() => setSealConfirm(false)}
        onConfirm={handleSeal}
        title="Seal the vault?"
        message="Sealing locks the barrier and drops every active session. Secrets stay encrypted at rest and become unreadable until the vault is unsealed again."
        confirmLabel="Seal vault"
        variant="danger"
        loading={sealing}
      />

      <UnsealModal
        open={unsealOpen}
        onClose={() => setUnsealOpen(false)}
        mode={mode}
        onUnsealed={(st) => {
          setStatus(st);
          if (!st.sealed) setUnsealOpen(false);
        }}
      />
    </Layout>
  );
}
