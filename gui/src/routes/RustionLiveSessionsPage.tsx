// Phase 8.1 — Rustion Live Sessions.
//
// Polls every 5s for the BV-cached telemetry snapshot. Each row is a
// session currently active on an enrolled bastion. Operators with the
// right policy can terminate a session from the row's Terminate button
// (which fires `rustionSessionKill`).
//
// The 60s background BV-side poller (`telemetry::start_poller`) does
// the actual pulling from each Rustion `/v1/sessions/active` + `/stats`.
// The "Refresh" button forces a synchronous pass via
// `rustionTelemetryPoll`.

import { useCallback, useEffect, useMemo, useState } from "react";

import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  Select,
  Table,
  useToast,
} from "../components/ui";
import { extractError } from "../lib/error";
import {
  rustionSessionKill,
  rustionTelemetryList,
  rustionTelemetryPoll,
  type RustionTelemetrySession,
  type RustionTelemetryTarget,
} from "../lib/rustion";

const AUTO_REFRESH_MS = 5_000;

export function RustionLiveSessionsPage() {
  const toast = useToast();
  const [targets, setTargets] = useState<RustionTelemetryTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [polling, setPolling] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filterBastion, setFilterBastion] = useState("");
  const [search, setSearch] = useState("");
  const [killing, setKilling] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const rows = await rustionTelemetryList();
      setTargets(rows);
    } catch (e) {
      toast.toast("error", `Failed to load telemetry: ${extractError(e)}`);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void load();
    }, AUTO_REFRESH_MS);
    return () => window.clearInterval(t);
  }, [autoRefresh, load]);

  const handlePoll = async () => {
    setPolling(true);
    try {
      const rows = await rustionTelemetryPoll();
      setTargets(rows);
      toast.toast("success", "Telemetry refreshed");
    } catch (e) {
      toast.toast("error", `Refresh failed: ${extractError(e)}`);
    } finally {
      setPolling(false);
    }
  };

  const handleKill = async (
    sess: RustionTelemetrySession,
    bastionId: string,
  ) => {
    if (killing) return;
    setKilling(sess.sessionId);
    try {
      await rustionSessionKill({
        bastionId,
        sessionId: sess.sessionId,
        correlationId: sess.correlationId,
      });
      toast.toast("success", `Terminated ${sess.sessionId}`);
      // Force a synchronous poll so the now-dead session drops out of the
      // cached snapshot immediately instead of lingering until the next 60s tick.
      setTargets(await rustionTelemetryPoll());
    } catch (e) {
      const msg = extractError(e);
      // The bastion is the source of truth: if it already tore the session
      // down, our cached row is just stale. Treat that as success and refresh.
      if (msg.includes("session_already_terminated")) {
        toast.toast("info", `Session ${sess.sessionId} was already terminated`);
        setTargets(await rustionTelemetryPoll());
      } else {
        toast.toast("error", `Terminate failed: ${msg}`);
      }
    } finally {
      setKilling(null);
    }
  };

  // Flatten into one row-per-session for the table, retaining the
  // bastion id so the Terminate button knows where to POST.
  const rows = useMemo(() => {
    const out: Array<{
      session: RustionTelemetrySession;
      bastion: RustionTelemetryTarget;
    }> = [];
    for (const t of targets) {
      if (filterBastion && t.targetId !== filterBastion) continue;
      for (const s of t.active) {
        if (search) {
          const q = search.trim().toLowerCase();
          const hay = `${s.sessionId} ${s.operatorVaultUser} ${s.targetHost} ${s.targetUser} ${s.protocol}`.toLowerCase();
          if (!hay.includes(q)) continue;
        }
        out.push({ session: s, bastion: t });
      }
    }
    return out;
  }, [targets, filterBastion, search]);

  const totalActive = useMemo(
    () => targets.reduce((acc, t) => acc + t.active.length, 0),
    [targets],
  );
  const aggregateStats = useMemo(() => {
    let active = 0;
    let total = 0;
    let totalDuration = 0;
    const topTargets = new Map<string, number>();
    const topOperators = new Map<string, number>();
    for (const t of targets) {
      active += t.stats.active;
      total += t.stats.total;
      totalDuration += t.stats.totalDurationSecs;
      for (const [k, v] of t.stats.topTargets) {
        topTargets.set(k, (topTargets.get(k) ?? 0) + v);
      }
      for (const [k, v] of t.stats.topOperators) {
        topOperators.set(k, (topOperators.get(k) ?? 0) + v);
      }
    }
    const sortDesc = (m: Map<string, number>) =>
      [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    return {
      active,
      total,
      totalDuration,
      topTargets: sortDesc(topTargets),
      topOperators: sortDesc(topOperators),
    };
  }, [targets]);

  // Recent audit witness rows (across all bastions, most recent first).
  const recentAudit = useMemo(() => {
    const all = targets.flatMap((t) => t.recentAudit);
    all.sort((a, b) => b.sequence - a.sequence);
    return all.slice(0, 30);
  }, [targets]);

  return (
    <Layout>
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-semibold">Rustion live sessions</h1>
          <p className="text-sm text-neutral-400 mt-1">
            Active sessions across every enrolled Rustion bastion. BV polls
            the bastion fleet every 60s; this page auto-refreshes its view
            of that cache every 5s when enabled.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Card title="Active sessions">
            <div className="text-3xl font-semibold">{totalActive}</div>
            <div className="text-xs text-[var(--color-text-muted)] mt-1">
              across {targets.length} bastion{targets.length === 1 ? "" : "s"}
            </div>
          </Card>
          <Card title="Lifetime sessions (rolling)">
            <div className="text-3xl font-semibold">{aggregateStats.total}</div>
            <div className="text-xs text-[var(--color-text-muted)] mt-1">
              {aggregateStats.active} currently active per bastion stats
            </div>
          </Card>
          <Card title="Total session time">
            <div className="text-3xl font-semibold">
              {formatDuration(aggregateStats.totalDuration)}
            </div>
            <div className="text-xs text-[var(--color-text-muted)] mt-1">
              summed across the fleet
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <Card title="Top targets (fleet)">
            {aggregateStats.topTargets.length === 0 ? (
              <div className="text-xs text-[var(--color-text-muted)]">
                No data yet.
              </div>
            ) : (
              <ul className="space-y-1.5">
                {aggregateStats.topTargets.map(([host, count]) => (
                  <li key={host} className="flex items-center gap-2 text-xs">
                    <span className="font-mono min-w-0 truncate flex-1">{host}</span>
                    <span className="text-[var(--color-text-muted)]">
                      {count} session{count === 1 ? "" : "s"}
                    </span>
                    <div
                      className="bg-blue-500/60 h-2 rounded"
                      style={{
                        width: `${Math.max(8, (count / aggregateStats.topTargets[0][1]) * 60)}px`,
                      }}
                    />
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Top operators (fleet)">
            {aggregateStats.topOperators.length === 0 ? (
              <div className="text-xs text-[var(--color-text-muted)]">
                No data yet.
              </div>
            ) : (
              <ul className="space-y-1.5">
                {aggregateStats.topOperators.map(([user, count]) => (
                  <li key={user} className="flex items-center gap-2 text-xs">
                    <span className="font-mono min-w-0 truncate flex-1">{user}</span>
                    <span className="text-[var(--color-text-muted)]">
                      {count} session{count === 1 ? "" : "s"}
                    </span>
                    <div
                      className="bg-green-500/60 h-2 rounded"
                      style={{
                        width: `${Math.max(8, (count / aggregateStats.topOperators[0][1]) * 60)}px`,
                      }}
                    />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <Card>
          <div className="flex flex-wrap items-end justify-between gap-3 mb-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 flex-1">
              <Input
                label="Search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="session id, operator, host, user…"
              />
              <Select
                label="Bastion"
                value={filterBastion}
                onChange={(e) => setFilterBastion(e.target.value)}
                options={[
                  { value: "", label: "All bastions" },
                  ...targets.map((t) => ({
                    value: t.targetId,
                    label: `${t.targetName} (${t.active.length} active)`,
                  })),
                ]}
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="inline-flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                Auto-refresh ({AUTO_REFRESH_MS / 1000}s)
              </label>
              <Button onClick={handlePoll} loading={polling} variant="secondary">
                Force refresh
              </Button>
            </div>
          </div>

          {loading ? (
            <div className="py-8 text-center text-neutral-400 text-sm">
              Loading…
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              title={
                targets.length === 0
                  ? "No bastions enrolled"
                  : totalActive === 0
                    ? "No active sessions"
                    : "No sessions match the current filters"
              }
              description={
                targets.length === 0
                  ? "Enrol a Rustion bastion under Settings → Rustion to see live sessions here."
                  : totalActive === 0
                    ? "Open a session on a connected resource — it will appear here within 60s."
                    : "Adjust the filters above to widen the view."
              }
            />
          ) : (
            <Table
              data={rows}
              rowKey={(r) => `${r.bastion.targetId}/${r.session.sessionId}`}
              columns={[
                {
                  key: "bastion",
                  header: "Bastion",
                  render: (r) => (
                    <div>
                      <div className="font-mono text-xs">{r.bastion.targetName}</div>
                      {r.bastion.lastPullError && (
                        <Badge variant="warning" label="last pull failed" />
                      )}
                    </div>
                  ),
                },
                {
                  key: "session",
                  header: "Session",
                  render: (r) => (
                    <span className="font-mono text-xs">{r.session.sessionId}</span>
                  ),
                },
                {
                  key: "protocol",
                  header: "Protocol",
                  render: (r) => <Badge variant="info" label={r.session.protocol} />,
                },
                {
                  key: "operator",
                  header: "Operator",
                  render: (r) => (
                    <>
                      <div>{r.session.operatorVaultUser || "—"}</div>
                      <div className="text-xs font-mono text-[var(--color-text-muted)]">
                        {r.session.operatorSrcIp}
                      </div>
                    </>
                  ),
                },
                {
                  key: "target",
                  header: "Target",
                  render: (r) => (
                    <>
                      <span className="font-mono text-xs">{r.session.targetUser}</span>
                      <span className="text-[var(--color-text-muted)]"> @ </span>
                      <span className="font-mono text-xs">
                        {r.session.targetHost}:{r.session.targetPort}
                      </span>
                    </>
                  ),
                },
                {
                  key: "opened",
                  header: "Opened",
                  render: (r) => (
                    <span className="text-xs">{formatDate(r.session.openedAt)}</span>
                  ),
                },
                {
                  key: "expires",
                  header: "Expires",
                  render: (r) => (
                    <span className="text-xs">{formatDate(r.session.expiresAt)}</span>
                  ),
                },
                {
                  key: "renewals",
                  header: "Renewals",
                  render: (r) => (
                    <span className="text-xs">
                      {r.session.renewalsUsed}/{r.session.maxRenewals}
                    </span>
                  ),
                },
                {
                  key: "actions",
                  header: "",
                  render: (r) => (
                    <Button
                      size="sm"
                      variant="danger"
                      loading={killing === r.session.sessionId}
                      onClick={() => handleKill(r.session, r.bastion.targetId)}
                    >
                      Terminate
                    </Button>
                  ),
                },
              ]}
            />
          )}
        </Card>

        <Card title={`Recent audit witness (${recentAudit.length})`}>
          <p className="text-xs text-[var(--color-text-muted)] mb-2">
            Hash-chain entries pulled from every enrolled bastion's audit
            log. Each row's <code>hash</code> chains forward; BV stores the
            full set under <code>rustion/audit_witness/</code> for SOC tooling.
          </p>
          {recentAudit.length === 0 ? (
            <EmptyState
              title="No audit entries yet"
              description="The 60s telemetry poller will pull audit entries from every bastion's hash chain on the next tick."
            />
          ) : (
            <Table
              data={recentAudit}
              rowKey={(e) => `${e.targetId}/${e.hash}`}
              columns={[
                {
                  key: "seq",
                  header: "Seq",
                  render: (e) => (
                    <span className="font-mono text-xs">{e.sequence}</span>
                  ),
                },
                {
                  key: "ts",
                  header: "Timestamp",
                  render: (e) => (
                    <span className="text-xs">{formatDate(e.timestamp)}</span>
                  ),
                },
                {
                  key: "bastion",
                  header: "Bastion",
                  render: (e) => (
                    <span className="font-mono text-xs">{e.targetId}</span>
                  ),
                },
                {
                  key: "actor",
                  header: "Actor",
                  render: (e) => <span className="font-mono text-xs">{e.actor}</span>,
                },
                {
                  key: "event",
                  header: "Event",
                  render: (e) => {
                    const ev = e.event as { type?: string } | null;
                    return (
                      <Badge variant="info" label={ev?.type ?? "(unknown)"} />
                    );
                  },
                },
                {
                  key: "hash",
                  header: "Hash",
                  render: (e) => (
                    <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
                      {e.hash.slice(0, 12)}…
                    </span>
                  ),
                },
              ]}
            />
          )}
        </Card>
      </div>
    </Layout>
  );
}

function formatDate(iso: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${(secs / 3600).toFixed(1)}h`;
  return `${(secs / 86400).toFixed(1)}d`;
}
