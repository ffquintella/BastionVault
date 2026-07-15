import { useState, useEffect, useCallback, useRef } from "react";
import { Button, Card, Table, Badge, Input, Modal, ConfirmModal, EmptyState, useToast } from "./ui";
import * as api from "../lib/api";
import type { DosConfig, DosStats, DosIpUsage, DosBanRecord } from "../lib/api";
import { extractError } from "../lib/error";

const STATS_POLL_MS = 5000;

const EMPTY_CONFIG: DosConfig = {
  enabled: true,
  window_secs: 10,
  max_requests: 200,
  auth_max_requests: 20,
  ban_secs: 300,
  refresh_secs: 30,
};

function fmtDuration(secs: number): string {
  if (secs <= 0) return "expired";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

/**
 * IP-based DoS / request-abuse protection panel (Settings → Abuse Protection).
 * Shows live per-IP request statistics and active bans, lets the operator edit
 * the thresholds, and manually ban/unban a client IP. Backed by `v2/sys/dos/*`.
 */
export function DosProtectionPanel() {
  const { toast } = useToast();
  const [config, setConfig] = useState<DosConfig>(EMPTY_CONFIG);
  const [form, setForm] = useState<DosConfig>(EMPTY_CONFIG);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [stats, setStats] = useState<DosStats | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Manual-ban modal state.
  const [banOpen, setBanOpen] = useState(false);
  const [banIpValue, setBanIpValue] = useState("");
  const [banTtl, setBanTtl] = useState("");
  const [banReason, setBanReason] = useState("");
  const [banBusy, setBanBusy] = useState(false);
  // Unban confirmation state.
  const [unbanTarget, setUnbanTarget] = useState<string | null>(null);
  const [unbanBusy, setUnbanBusy] = useState(false);

  const editingRef = useRef(editing);
  editingRef.current = editing;

  const loadConfig = useCallback(async () => {
    try {
      const c = await api.getDosConfig();
      setConfig(c);
      // Don't clobber an in-progress edit.
      if (!editingRef.current) setForm(c);
    } catch (e) {
      setLoadError(extractError(e));
    }
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const s = await api.getDosStats();
      setStats(s);
      setLoadError(null);
      if (s.config && !editingRef.current) {
        setConfig(s.config);
        setForm(s.config);
      }
    } catch (e) {
      setLoadError(extractError(e));
    }
  }, []);

  useEffect(() => {
    void loadConfig();
    void loadStats();
    const id = setInterval(() => {
      void loadStats();
    }, STATS_POLL_MS);
    return () => clearInterval(id);
  }, [loadConfig, loadStats]);

  const onField = (key: keyof DosConfig, value: string | boolean) => {
    setForm((f) => ({
      ...f,
      [key]: typeof value === "boolean" ? value : Math.max(0, Number(value) || 0),
    }));
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const effective = await api.setDosConfig(form);
      setConfig(effective);
      setForm(effective);
      setEditing(false);
      toast("success", "DoS-protection thresholds updated");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  };

  const submitBan = async () => {
    const ip = banIpValue.trim();
    if (!ip) {
      toast("error", "Enter an IP address to ban");
      return;
    }
    setBanBusy(true);
    try {
      const ttl = banTtl.trim() ? Number(banTtl) : undefined;
      await api.banIp(ip, ttl && ttl > 0 ? ttl : undefined, banReason.trim() || undefined);
      toast("success", `Banned ${ip}`);
      setBanOpen(false);
      setBanIpValue("");
      setBanTtl("");
      setBanReason("");
      await loadStats();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBanBusy(false);
    }
  };

  const confirmUnban = async () => {
    if (!unbanTarget) return;
    setUnbanBusy(true);
    try {
      await api.unbanIp(unbanTarget);
      toast("success", `Unbanned ${unbanTarget}`);
      setUnbanTarget(null);
      await loadStats();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setUnbanBusy(false);
    }
  };

  const banColumns = [
    {
      key: "ip",
      header: "IP address",
      className: "w-1/4",
      render: (b: DosBanRecord) => <span className="font-mono min-w-0 truncate">{b.ip}</span>,
    },
    {
      key: "kind",
      header: "Type",
      render: (b: DosBanRecord) => (
        <Badge variant={b.kind === "manual" ? "info" : "warning"} label={b.kind} />
      ),
    },
    {
      key: "reason",
      header: "Reason",
      render: (b: DosBanRecord) => (
        <span className="min-w-0 truncate text-[var(--color-text-muted)]">{b.reason}</span>
      ),
    },
    {
      key: "expires",
      header: "Expires in",
      render: (b: DosBanRecord) => fmtDuration(b.expires_in_secs),
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-24",
      render: (b: DosBanRecord) => (
        <Button variant="ghost" size="sm" onClick={() => setUnbanTarget(b.ip)}>
          Unban
        </Button>
      ),
    },
  ];

  const bannedIps = new Set((stats?.bans ?? []).map((b) => b.ip));
  const trackedColumns = [
    {
      key: "ip",
      header: "IP address",
      className: "w-1/4",
      render: (u: DosIpUsage) => <span className="font-mono min-w-0 truncate">{u.ip}</span>,
    },
    {
      key: "requests",
      header: "Requests / window",
      render: (u: DosIpUsage) => (
        <span>
          {u.requests}
          <span className="text-[var(--color-text-muted)]"> / {u.window_secs}s</span>
        </span>
      ),
    },
    {
      key: "auth",
      header: "Auth requests",
      render: (u: DosIpUsage) => u.auth_requests,
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-24",
      render: (u: DosIpUsage) =>
        bannedIps.has(u.ip) ? (
          <Badge variant="error" label="banned" />
        ) : (
          <Button
            variant="danger"
            size="sm"
            onClick={() => {
              setBanIpValue(u.ip);
              setBanOpen(true);
            }}
          >
            Ban
          </Button>
        ),
    },
  ];

  return (
    <>
      {/* Thresholds */}
      <Card
        title="Abuse-Protection Thresholds"
        actions={
          editing ? (
            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setForm(config);
                  setEditing(false);
                }}
              >
                Cancel
              </Button>
              <Button variant="primary" size="sm" loading={saving} onClick={saveConfig}>
                Save
              </Button>
            </div>
          ) : (
            <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
              Edit
            </Button>
          )
        }
      >
        <p className="text-sm text-[var(--color-text-muted)] mb-4">
          Requests are counted per client IP over a sliding window. An IP that exceeds the request
          ceiling is temporarily banned. A separate, stricter ceiling applies to authentication
          paths (brute-force defense). Set any limit to <span className="font-mono">0</span> to
          disable that rule.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <label className="flex items-center gap-2 col-span-1 sm:col-span-2 lg:col-span-3">
            <input
              type="checkbox"
              checked={form.enabled}
              disabled={!editing}
              onChange={(e) => onField("enabled", e.target.checked)}
            />
            <span className="text-sm">
              Protection enabled
              {!form.enabled && (
                <span className="ml-2">
                  <Badge variant="warning" label="disabled" />
                </span>
              )}
            </span>
          </label>
          <Input
            label="Window (seconds)"
            type="number"
            min={1}
            value={String(form.window_secs)}
            disabled={!editing}
            onChange={(e) => onField("window_secs", e.target.value)}
          />
          <Input
            label="Max requests / window"
            type="number"
            min={0}
            hint="0 disables"
            value={String(form.max_requests)}
            disabled={!editing}
            onChange={(e) => onField("max_requests", e.target.value)}
          />
          <Input
            label="Max auth requests / window"
            type="number"
            min={0}
            hint="0 disables"
            value={String(form.auth_max_requests)}
            disabled={!editing}
            onChange={(e) => onField("auth_max_requests", e.target.value)}
          />
          <Input
            label="Ban duration (seconds)"
            type="number"
            min={0}
            hint="0 = never auto-ban"
            value={String(form.ban_secs)}
            disabled={!editing}
            onChange={(e) => onField("ban_secs", e.target.value)}
          />
          <Input
            label="Refresh interval (seconds)"
            type="number"
            min={5}
            hint="manual-ban reload / sweep cadence"
            value={String(form.refresh_secs)}
            disabled={!editing}
            onChange={(e) => onField("refresh_secs", e.target.value)}
          />
        </div>
      </Card>

      {/* Active bans */}
      <Card
        title="Active Bans"
        actions={
          <Button variant="secondary" size="sm" onClick={() => setBanOpen(true)}>
            Ban IP…
          </Button>
        }
      >
        {loadError && <p className="text-sm text-red-400 mb-3">{loadError}</p>}
        {stats && stats.bans.length === 0 ? (
          <EmptyState title="No active bans" description="No client IPs are currently banned." />
        ) : (
          <Table
            columns={banColumns}
            data={stats?.bans ?? []}
            rowKey={(b) => b.ip}
            tableClassName="table-fixed"
          />
        )}
      </Card>

      {/* Live per-IP activity */}
      <Card title="Client IP Activity (current window, this node)">
        {stats && stats.tracked.length === 0 ? (
          <EmptyState
            title="No tracked activity"
            description="No client IPs have made requests in the current window."
          />
        ) : (
          <Table
            columns={trackedColumns}
            data={stats?.tracked ?? []}
            rowKey={(u) => u.ip}
            tableClassName="table-fixed"
          />
        )}
      </Card>

      {/* Manual-ban modal */}
      <Modal
        open={banOpen}
        onClose={() => setBanOpen(false)}
        title="Ban a client IP"
        actions={
          <>
            <Button variant="ghost" onClick={() => setBanOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={banBusy} onClick={submitBan}>
              Ban
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="IP address"
            placeholder="203.0.113.7"
            value={banIpValue}
            onChange={(e) => setBanIpValue(e.target.value)}
          />
          <Input
            label="Duration (seconds)"
            type="number"
            min={1}
            hint="Leave blank to use the configured ban duration"
            value={banTtl}
            onChange={(e) => setBanTtl(e.target.value)}
          />
          <Input
            label="Reason (optional)"
            placeholder="manual operator block"
            value={banReason}
            onChange={(e) => setBanReason(e.target.value)}
          />
        </div>
      </Modal>

      {/* Unban confirmation */}
      <ConfirmModal
        open={unbanTarget !== null}
        onClose={() => setUnbanTarget(null)}
        onConfirm={confirmUnban}
        title="Unban IP"
        message={`Remove the ban on ${unbanTarget ?? ""}? The IP will be able to make requests again immediately on this node.`}
        confirmLabel="Unban"
        variant="primary"
        loading={unbanBusy}
      />
    </>
  );
}
