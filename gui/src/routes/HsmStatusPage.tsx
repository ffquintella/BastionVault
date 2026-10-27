import { useCallback, useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, EmptyState, Table } from "../components/ui";
import * as api from "../lib/api";
import type {
  HsmStatus,
  HsmPoolMember,
  HsmDeviceAuditMember,
  HsmRepairRun,
} from "../lib/api";
import { extractError } from "../lib/error";

// Human labels for the raw seal `type` values the server reports.
function sealTypeLabel(type: string): string {
  switch (type) {
    case "hsm":
      return "HSM auto-unseal";
    case "shamir":
      return "Shamir (manual unseal)";
    default:
      return type;
  }
}

function backendLabel(backend?: string): string {
  switch (backend) {
    case "yubihsm2":
      return "YubiHSM 2";
    case "mock":
      return "Mock (development)";
    default:
      return backend || "—";
  }
}

function recoveryLabel(recovery?: string): string {
  switch (recovery) {
    case "none":
      return "None";
    case "shamir-ceremony":
      return "Shamir recovery ceremony";
    default:
      return recovery || "—";
  }
}

// One label/value row. `mono` renders identifiers (serials, UUIDs) in a
// monospace font and truncates so long values never break the layout.
function Field({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-[var(--color-text-muted)] mb-0.5">{label}</div>
      <div
        className={`text-sm text-[var(--color-text)] ${mono ? "font-mono truncate" : ""}`}
        title={mono && typeof value === "string" ? value : undefined}
      >
        {value}
      </div>
    </div>
  );
}

type BadgeVariant = "success" | "warning" | "error" | "info" | "neutral";

function memberStateVariant(state?: string): BadgeVariant {
  switch (state) {
    case "active":
      return "success";
    case "joining":
    case "bootstrap":
      return "info";
    case "faulted":
      return "error";
    default:
      return "neutral";
  }
}

// Timestamps arrive as unix seconds (device audit) or, defensively, as an
// RFC3339 string / unix seconds (repair run).
function fmtTime(t?: number | string | null): string {
  if (t == null || t === "") return "—";
  const d = typeof t === "number" ? new Date(t * 1000) : new Date(t);
  return Number.isNaN(d.getTime()) ? String(t) : d.toLocaleString();
}

function num(n?: number | null): string {
  return n != null ? String(n) : "—";
}

const WARN_BOX =
  "rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 px-3 py-2 text-sm";

function PoolMembersCard({ members }: { members: HsmPoolMember[] }) {
  return (
    <Card title="Pool Members">
      <div className="overflow-x-auto">
        <Table<HsmPoolMember>
          tableClassName="table-fixed min-w-[800px]"
          data={members}
          rowKey={(m) => m.name}
          emptyMessage="No pool members reported"
          columns={[
            {
              key: "name",
              header: "Name",
              className: "w-1/6 pr-2",
              render: (m) => (
                <div className="min-w-0 truncate" title={m.hsm_id || m.name}>
                  <span className="font-medium">{m.name}</span>
                  {m.prefer && (
                    <span className="ml-1 text-xs text-[var(--color-text-muted)]">
                      (preferred)
                    </span>
                  )}
                </div>
              ),
            },
            {
              key: "state",
              header: "State",
              className: "w-24 pr-2",
              render: (m) => (
                <Badge variant={memberStateVariant(m.state)} label={m.state || "unknown"} />
              ),
            },
            {
              key: "up",
              header: "Link",
              className: "w-20 pr-2",
              render: (m) => (
                <Badge variant={m.up ? "success" : "error"} label={m.up ? "Up" : "Down"} dot />
              ),
            },
            {
              key: "latency_ms",
              header: "Latency",
              className: "w-20 pr-2",
              render: (m) => (m.latency_ms != null ? `${m.latency_ms} ms` : "—"),
            },
            {
              key: "serial",
              header: "Serial",
              className: "w-24 pr-2",
              render: (m) => (
                <div className="min-w-0 truncate font-mono" title={m.serial || ""}>
                  {m.serial || "—"}
                </div>
              ),
            },
            {
              key: "holds_kek_copy",
              header: "KEK Copy",
              className: "w-24 pr-2",
              render: (m) => (
                <Badge
                  variant={m.holds_kek_copy ? "success" : "warning"}
                  label={m.holds_kek_copy ? "Yes" : "No"}
                />
              ),
            },
            {
              key: "pending_revocations",
              header: "Pending Revocations",
              className: "w-1/6 pr-2",
              render: (m) => {
                const n = m.pending_revocations?.length ?? 0;
                return n > 0 ? (
                  <div
                    className="min-w-0 truncate text-yellow-400"
                    title={(m.pending_revocations ?? []).join(", ")}
                  >
                    {n} pending
                  </div>
                ) : (
                  <span className="text-[var(--color-text-muted)]">0</span>
                );
              },
            },
            {
              key: "last_error",
              header: "Last Error",
              className: "pr-2",
              render: (m) => (
                <div
                  className={`min-w-0 truncate ${m.last_error ? "text-[var(--color-danger)]" : ""}`}
                  title={m.last_error || ""}
                >
                  {m.last_error || "—"}
                </div>
              ),
            },
          ]}
        />
      </div>
    </Card>
  );
}

function RepairRunFields({ run }: { run: HsmRepairRun }) {
  const failures = run.failures ?? [];
  const ready = run.ready_to_promote ?? [];
  const auditors = run.auditors_installed ?? [];
  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <Field label="Last Run Started" value={fmtTime(run.started_at)} />
        <Field label="Last Run Finished" value={fmtTime(run.finished_at)} />
        <Field label="Sets Scanned" value={num(run.sets_scanned)} />
        <Field label="Copies Added" value={num(run.copies_added)} />
        <Field label="Copies Removed" value={num(run.copies_removed)} />
        <Field label="Recovery Copies Added" value={num(run.recovery_copies_added)} />
        <Field
          label="Still Under-Replicated"
          value={
            (run.under_replicated ?? 0) > 0 ? (
              <Badge variant="warning" label={String(run.under_replicated)} />
            ) : (
              num(run.under_replicated)
            )
          }
        />
        <Field
          label="Failures"
          value={
            failures.length > 0 ? (
              <Badge variant="error" label={String(failures.length)} />
            ) : (
              "0"
            )
          }
        />
        <Field label="Ready To Promote" value={ready.length > 0 ? ready.join(", ") : "None"} />
        <Field
          label="Auditor Keys Installed"
          value={auditors.length > 0 ? auditors.join(", ") : "None"}
        />
      </div>
      {failures.length > 0 && (
        <ul className="mt-3 space-y-1">
          {failures.map((f, i) => (
            <li
              key={`${i}-${f}`}
              className="min-w-0 truncate text-sm text-[var(--color-danger)]"
              title={f}
            >
              {f}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function auditorBadge(enrolled?: boolean | null): { variant: BadgeVariant; label: string } {
  if (enrolled === true) return { variant: "success", label: "Auditor key" };
  if (enrolled === false) return { variant: "warning", label: "No auditor key" };
  return { variant: "neutral", label: "Not drained yet" };
}

function DeviceAuditRow({ m }: { m: HsmDeviceAuditMember }) {
  const badge = auditorBadge(m.enrolled);
  return (
    <div className="rounded-lg border border-[var(--color-border)] p-3">
      <div className="flex items-center gap-2 min-w-0 mb-2">
        <span className="font-medium text-sm truncate" title={m.hsm_id || m.name}>
          {m.name}
        </span>
        <Badge variant={badge.variant} label={badge.label} />
      </div>
      {m.enrolled === true && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Field label="Last Index" value={num(m.last_index)} />
          <Field label="Last Drain" value={fmtTime(m.last_drain_at)} />
          <Field label="Drained By" value={m.drained_by || "—"} />
          <Field label="Entries Drained" value={num(m.entries_drained)} />
          <Field
            label="Gaps"
            value={
              (m.gaps ?? 0) > 0 ? (
                <Badge variant="warning" label={`${m.gaps} gap${m.gaps === 1 ? "" : "s"}`} />
              ) : (
                num(m.gaps)
              )
            }
          />
        </div>
      )}
      {m.enrolled === false && (
        <div className="min-w-0 text-sm text-yellow-400">
          This device's log is not drained. Install the key with{" "}
          <code className="font-mono break-all">bvault operator hsm repair --run --admin {m.name}</code>
        </div>
      )}
      {m.enrolled == null && (
        <div className="text-sm text-[var(--color-text-muted)]">
          This node has not drained the device logs yet.
        </div>
      )}
      {m.last_error && (
        <div
          className="mt-2 min-w-0 truncate text-sm text-[var(--color-danger)]"
          title={m.last_error}
        >
          {m.last_error}
        </div>
      )}
    </div>
  );
}

// Pool-only sections. Read-only: ceremonies (repair, rotate, recovery,
// revoke) stay CLI-only, so nothing here acts on the vault.
function PoolSections({ status }: { status: HsmStatus }) {
  const members = status.members ?? [];
  const pending = status.pending_revocations ?? [];
  const under = status.under_replicated_sets ?? 0;
  const run = status.repair?.last_run ?? null;
  const audit = status.device_audit;
  const recoveryPresent =
    status.recovery_configured != null ||
    status.recovery_fingerprint != null ||
    status.recovery_threshold != null;

  return (
    <>
      {(under > 0 || status.kek_under_replicated) && (
        <div className={WARN_BOX} role="alert">
          {under > 0 && (
            <div>
              {under} wrapped set{under === 1 ? " is" : "s are"} under-replicated (below the
              minimum of {num(status.min_wrap_copies)} wrap copies).
            </div>
          )}
          {status.kek_under_replicated && (
            <div>The cluster KEK is under-replicated across the pool members.</div>
          )}
        </div>
      )}

      <Card title="Pool Replication">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <Field label="Min Wrap Copies" value={num(status.min_wrap_copies)} />
          <Field label="Seal Record Version" value={num(status.seal_record_version)} />
          <Field
            label="Under-Replicated Sets"
            value={<Badge variant={under > 0 ? "warning" : "success"} label={String(under)} />}
          />
        </div>
      </Card>

      <PoolMembersCard members={members} />

      {pending.length > 0 && (
        <Card title="Pending Revocations">
          <div className={`${WARN_BOX} mb-3`}>
            Every node treats these members as down until the revocation is applied: the
            revoked node's key is still on the device. Apply it with{" "}
            <code className="font-mono break-all">bvault operator hsm repair --run --admin &lt;member&gt;</code>.
          </div>
          <ul className="space-y-1">
            {pending.map((p) => (
              <li
                key={`${p.member}:${p.node}`}
                className="min-w-0 truncate text-sm"
                title={`${p.member}: revoke ${p.node}`}
              >
                <span className="font-medium">{p.member}</span>
                <span className="text-[var(--color-text-muted)]"> still holds the key of revoked node </span>
                <span className="font-mono">{p.node}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {status.repair && (
        <Card title="Repair">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-3">
            <Field
              label="Repair Rate"
              value={status.repair.repair_rate != null ? String(status.repair.repair_rate) : "—"}
            />
            <Field
              label="Interval"
              value={status.repair.interval_secs != null ? `${status.repair.interval_secs}s` : "—"}
            />
          </div>
          {run ? (
            <RepairRunFields run={run} />
          ) : (
            <div className="text-sm text-[var(--color-text-muted)]">
              No repair run has completed yet.
            </div>
          )}
        </Card>
      )}

      {audit && (
        <Card title="Device Audit">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-3">
            <Field
              label="Mode"
              value={
                <Badge
                  variant={audit.mode === "off" ? "neutral" : "info"}
                  label={audit.mode || "—"}
                />
              }
            />
            <Field
              label="Interval"
              value={audit.interval_secs != null ? `${audit.interval_secs}s` : "—"}
            />
          </div>
          <div className="space-y-2">
            {(audit.members ?? []).map((m) => (
              <DeviceAuditRow key={m.name} m={m} />
            ))}
          </div>
        </Card>
      )}

      {recoveryPresent && (
        <Card title="Recovery">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <Field
              label="Recovery Key"
              value={
                <Badge
                  variant={status.recovery_configured ? "success" : "neutral"}
                  label={status.recovery_configured ? "Configured" : "Not configured"}
                />
              }
            />
            {status.recovery_fingerprint && (
              <Field label="Fingerprint" value={status.recovery_fingerprint} mono />
            )}
            {status.recovery_threshold != null && (
              <Field
                label="Threshold"
                value={`${status.recovery_threshold} of ${num(status.recovery_shares)} shares`}
              />
            )}
            {status.recovery_configured && (
              <Field
                label="KEK Recovery Copy"
                value={
                  <Badge
                    variant={status.kek_recovery_copy ? "success" : "warning"}
                    label={status.kek_recovery_copy ? "Present" : "Missing"}
                  />
                }
              />
            )}
            {(status.recovery_progress ?? 0) > 0 && (
              <Field
                label="Ceremony"
                value={
                  <Badge
                    variant="info"
                    label={`In progress (${status.recovery_progress} share${
                      status.recovery_progress === 1 ? "" : "s"
                    } held)`}
                  />
                }
              />
            )}
          </div>
        </Card>
      )}
    </>
  );
}

export function HsmStatusPage() {
  const [status, setStatus] = useState<HsmStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await api.hsmStatus();
      setStatus(s);
    } catch (e) {
      setError(extractError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const isHsm = status?.type === "hsm";

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">HSM / Seal</h1>
          <Button variant="secondary" onClick={() => void load()} disabled={loading}>
            {loading ? "Refreshing…" : "Refresh"}
          </Button>
        </div>

        {error && (
          <Card>
            <div className="text-sm text-[var(--color-danger)]">{error}</div>
          </Card>
        )}

        {!error && !status && loading && (
          <Card>
            <div className="text-sm text-[var(--color-text-muted)]">Loading seal status…</div>
          </Card>
        )}

        {status && (
          <>
            {/* Seal posture — applies to every seal provider. */}
            <Card title="Seal Posture">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Field label="Seal Type" value={sealTypeLabel(status.type)} />
                <Field
                  label="State"
                  value={
                    <Badge
                      variant={status.sealed ? "error" : "success"}
                      label={status.sealed ? "Sealed" : "Unsealed"}
                      dot
                    />
                  }
                />
                <Field
                  label="Initialized"
                  value={
                    <Badge
                      variant={status.initialized ? "success" : "warning"}
                      label={status.initialized ? "Yes" : "No"}
                    />
                  }
                />
                <Field
                  label="Auto-Unseal"
                  value={
                    <Badge
                      variant={status.auto_unseal ? "info" : "neutral"}
                      label={status.auto_unseal ? "Enabled" : "Disabled"}
                    />
                  }
                />
              </div>
            </Card>

            {isHsm ? (
              <>
                {/* HSM device + backend details. */}
                <Card title="HSM Device">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Field label="Backend" value={backendLabel(status.backend)} />
                    <Field
                      label="Device Serial"
                      value={status.device_serial || "—"}
                      mono
                    />
                    <Field label="Recovery Mode" value={recoveryLabel(status.recovery)} />
                    <Field
                      label="PQC Key Cache TTL"
                      value={
                        status.pqc_key_cache_ttl_secs != null
                          ? `${status.pqc_key_cache_ttl_secs}s`
                          : "—"
                      }
                    />
                  </div>
                </Card>

                {/* Cluster key-replication state. */}
                <Card title="Cluster Key Custody">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Field label="This Node" value={status.node_id || "—"} mono />
                    <Field
                      label="Cluster UUID"
                      value={status.cluster_uuid || "—"}
                      mono
                    />
                    <Field
                      label="Key Epoch"
                      value={status.epoch != null ? String(status.epoch) : "—"}
                    />
                    <Field
                      label="Enrolled Nodes"
                      value={
                        status.enrolled_nodes != null
                          ? String(status.enrolled_nodes)
                          : "—"
                      }
                    />
                    <Field
                      label="This Node Enrolled"
                      value={
                        <Badge
                          variant={status.this_node_enrolled ? "success" : "warning"}
                          label={status.this_node_enrolled ? "Yes" : "No"}
                        />
                      }
                    />
                  </div>
                </Card>

                {status.topology === "pool" && <PoolSections status={status} />}
              </>
            ) : (
              <Card>
                <EmptyState
                  title="No HSM configured"
                  description={`This vault uses the ${sealTypeLabel(
                    status.type,
                  )} provider. HSM device and cluster-custody details appear here when the vault is sealed with a hardware security module. See features/hsm-support.md for setup.`}
                />
              </Card>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}
