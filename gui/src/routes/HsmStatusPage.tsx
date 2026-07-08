import { useCallback, useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, EmptyState } from "../components/ui";
import * as api from "../lib/api";
import type { HsmStatus } from "../lib/api";
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
