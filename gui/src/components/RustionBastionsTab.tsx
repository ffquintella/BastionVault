// Settings → Rustion Bastions section. Phase 1 surface:
//   - Table of enrolled targets with live health dot per row.
//   - Enrolment wizard (paste hybrid pubkey + endpoint).
//   - "Test Connection" button (synchronous probe).
//   - Edit + Delete per row.
//   - Master-cert configuration slot + pubkey export panel.
//
// Phase 2+ will add bastion-group CRUD, the policy ladder, and the
// dispatcher preview. Wiring those in later is mechanical — the
// command surface lives in gui/src/lib/rustion.ts.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Badge,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  Input,
  Modal,
  Textarea,
  useToast,
} from "./ui";
import * as api from "../lib/api";
import * as rustion from "../lib/rustion";
import type { PkiRoleConfig } from "../lib/types";
import type {
  RustionHealthStatus,
  RustionMasterConfig,
  RustionMasterPubkey,
  RustionTargetHealth,
  RustionTargetSummary,
} from "../lib/rustion";
import { extractError } from "../lib/error";

export function RustionBastionsTab() {
  const { toast } = useToast();
  const [targets, setTargets] = useState<RustionTargetSummary[]>([]);
  const [health, setHealth] = useState<Record<string, RustionTargetHealth>>({});
  const [loading, setLoading] = useState(true);
  const [showWizard, setShowWizard] = useState(false);
  const [editTarget, setEditTarget] = useState<RustionTargetSummary | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<RustionTargetSummary | null>(null);
  const [probingId, setProbingId] = useState<string | null>(null);
  const [masterCfg, setMasterCfg] = useState<RustionMasterConfig | null>(null);
  const [masterPub, setMasterPub] = useState<RustionMasterPubkey | null>(null);
  const [showMasterEdit, setShowMasterEdit] = useState(false);
  const [showMasterBootstrap, setShowMasterBootstrap] = useState(false);
  // Phase 9.1: this BV deployment's stable UUID. Pasted into the
  // bastion's authority record at enrolment time.
  const [deploymentId, setDeploymentId] = useState<string>("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [ts, hs, mc, mp, depId] = await Promise.all([
        rustion.rustionTargetList(),
        rustion.rustionTargetHealthAll(),
        rustion.rustionMasterRead(),
        rustion.rustionMasterPubkeyExport(),
        rustion.rustionDeploymentIdRead().catch(() => ""),
      ]);
      setTargets(ts);
      const map: Record<string, RustionTargetHealth> = {};
      for (const h of hs) map[h.id] = h;
      setHealth(map);
      setMasterCfg(mc);
      setMasterPub(mp);
      setDeploymentId(depId);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleProbe(id?: string) {
    setProbingId(id ?? "all");
    try {
      const r = await rustion.rustionTargetProbe(id);
      if (id) {
        toast(
          r.status === "up" ? "success" : "error",
          r.status === "up"
            ? `${r.name}: up (${r.latency_ms_p50}ms${r.version ? ", " + r.version : ""})`
            : `${r.name}: ${r.status}${r.last_error ? " — " + r.last_error : ""}`,
        );
      } else {
        toast("success", "Probe sweep complete");
      }
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setProbingId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await rustion.rustionTargetDelete(deleteTarget.id);
      toast("success", `Removed ${deleteTarget.name}`);
      setDeleteTarget(null);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <div className="space-y-4">
      <Card
        title="Rustion bastions"
        actions={
          <div className="flex gap-2">
            <Button
              variant="ghost"
              onClick={() => handleProbe()}
              disabled={probingId !== null || targets.length === 0}
            >
              {probingId === "all" ? "Probing..." : "Probe all"}
            </Button>
            <Button onClick={() => setShowWizard(true)}>+ Enrol bastion</Button>
          </div>
        }
      >
        <p className="text-xs text-[var(--color-text-muted)] mb-3">
          Resource Connect can mediate SSH / RDP sessions through one or
          more Rustion bastions. Each enrolled instance is health-probed
          every 30 seconds; the dispatcher routes only to targets in the
          <em> up</em> state. Multi-instance is the default — enrol per
          region, primary + DR, or PCI zone as needed.
        </p>

        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
        ) : targets.length === 0 ? (
          <EmptyState
            title="No Rustion bastions enrolled"
            description="Enrol the first Rustion instance to start routing Connect sessions through a PQC bastion with native recording."
            action={
              <Button onClick={() => setShowWizard(true)}>
                Enrol your first bastion
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-[var(--color-text-muted)]">
                <tr>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Endpoint</th>
                  <th className="py-2 pr-3">Latency</th>
                  <th className="py-2 pr-3">Version</th>
                  <th className="py-2 pr-3">Sessions</th>
                  <th className="py-2 pr-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => {
                  const h = health[t.id];
                  return (
                    <tr
                      key={t.id}
                      className="border-t border-[var(--color-border)]"
                    >
                      <td className="py-2 pr-3">
                        <HealthDot status={h?.status ?? "unknown"} enabled={t.enabled} />
                      </td>
                      <td className="py-2 pr-3">
                        <div className="font-medium">{t.name}</div>
                        {t.tags.length > 0 && (
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {t.tags.map((tag) => (
                              <Badge key={tag} label={tag} variant="neutral" />
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {t.endpoint}
                      </td>
                      <td className="py-2 pr-3 text-xs">
                        {h?.latency_ms_p50 ? `${h.latency_ms_p50} ms` : "—"}
                      </td>
                      <td className="py-2 pr-3 text-xs">
                        {h?.version || "—"}
                      </td>
                      <td className="py-2 pr-3 text-xs">
                        {h?.active_sessions ?? "—"}
                      </td>
                      <td className="py-2 pr-3 text-right">
                        <div className="flex gap-1 justify-end">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleProbe(t.id)}
                            disabled={probingId !== null}
                          >
                            {probingId === t.id ? "Testing..." : "Test"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setEditTarget(t)}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setDeleteTarget(t)}
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="Master signing cert"
        actions={
          <div className="flex gap-2">
            {!masterPub?.issued && (
              <Button onClick={() => setShowMasterBootstrap(true)}>
                Bootstrap master
              </Button>
            )}
            <Button variant="ghost" onClick={() => setShowMasterEdit(true)}>
              Configure
            </Button>
          </div>
        }
      >
        <p className="text-xs text-[var(--color-text-muted)] mb-3">
          BastionVault signs every session-grant envelope with a long-lived
          master keypair. Each Rustion bastion pins the public half as a
          trust anchor in its <code>authorities/</code> store. Phase 2 of
          the integration wires up the issue / rotate flow against the
          PKI engine; today this panel surfaces the configuration slot
          and the pubkey export shape.
        </p>
        {!masterPub?.issued && (
          <div className="mb-3 p-3 rounded border border-dashed border-[var(--color-border)] text-xs">
            <div className="font-semibold mb-1">Master not issued yet.</div>
            <div className="text-[var(--color-text-muted)]">
              Click <b>Bootstrap master</b> to run the one-shot wizard
              (PKI mount + root + two roles + master config + issue).
              Equivalent CLI:{" "}
              <code className="font-mono">scripts/rustion-master-bootstrap.sh</code>.
            </div>
          </div>
        )}
        {masterCfg && (
          <div className="grid grid-cols-2 gap-3 text-xs">
            <Field label="Algorithm" value={masterCfg.algorithm || "—"} />
            <Field label="Configured" value={masterCfg.configured ? "yes" : "no"} />
            <Field
              label="PKI mount"
              value={masterCfg.pki_mount || "(unset)"}
            />
            <Field
              label="PKI role (Ed25519)"
              value={masterCfg.pki_role || "(unset)"}
            />
            <Field
              label="PKI role (ML-DSA-65)"
              value={masterCfg.pki_role_pqc || "(unset)"}
            />
            <Field
              label="Default TTL"
              value={`${masterCfg.default_ttl_secs}s`}
            />
            <Field
              label="Rotation grace"
              value={`${masterCfg.rotate_grace_secs}s`}
            />
            <Field
              label="Current serial"
              value={masterCfg.current_serial || "(none — not issued yet)"}
              mono
            />
            <Field
              label="Current not_after"
              value={masterCfg.current_not_after || "—"}
            />
          </div>
        )}
        {masterPub?.issued && (
          <div className="mt-4">
            <div className="text-xs text-[var(--color-text-muted)] mb-1">
              Public-key export (paste both halves into the Rustion authority record):
            </div>
            <Textarea
              label="ed25519"
              value={masterPub.ed25519_pem}
              readOnly
              rows={3}
              className="font-mono text-xs"
            />
            <Textarea
              label="mldsa65"
              value={masterPub.mldsa65_pem}
              readOnly
              rows={3}
              className="font-mono text-xs mt-2"
            />
            <div className="text-xs text-[var(--color-text-muted)] mt-1">
              Fingerprint: <span className="font-mono">{masterPub.fingerprint}</span>
            </div>
          </div>
        )}
        {/* Phase 9.1 — deployment_id. Operators paste this into the
            bastion's authority record at enrolment time. Rustion pins
            it on approval and refuses envelopes from a different
            deployment with `403 attestation_mismatch`. */}
        {deploymentId && (
          <div className="mt-4 pt-4 border-t border-[var(--color-border)]">
            <h3 className="text-sm font-semibold mb-2">Deployment ID</h3>
            <p className="text-xs text-[var(--color-text-muted)] mb-1">
              Paste into the bastion's <code>authority.deployment_id</code> at
              enrolment time. Rustion pins this on approval and refuses
              envelopes from any other deployment.
            </p>
            <code className="font-mono text-xs select-all break-all">
              {deploymentId}
            </code>
          </div>
        )}
      </Card>

      <EnrolWizardModal
        open={showWizard || editTarget !== null}
        target={editTarget}
        onClose={() => {
          setShowWizard(false);
          setEditTarget(null);
        }}
        onSaved={async () => {
          setShowWizard(false);
          setEditTarget(null);
          await refresh();
        }}
      />

      <MasterEditModal
        open={showMasterEdit}
        current={masterCfg}
        onClose={() => setShowMasterEdit(false)}
        onSaved={async () => {
          setShowMasterEdit(false);
          await refresh();
        }}
      />

      <BootstrapMasterModal
        open={showMasterBootstrap}
        onClose={() => setShowMasterBootstrap(false)}
        onDone={async () => {
          setShowMasterBootstrap(false);
          await refresh();
        }}
      />

      <ConfirmModal
        open={deleteTarget !== null}
        title="Remove Rustion bastion"
        message={
          deleteTarget
            ? `Remove "${deleteTarget.name}"? Active sessions, if any, must be drained first.`
            : ""
        }
        confirmLabel="Remove"
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}

function HealthDot({
  status,
  enabled,
}: {
  status: RustionHealthStatus;
  enabled: boolean;
}) {
  if (!enabled) {
    return <Badge label="disabled" variant="neutral" />;
  }
  switch (status) {
    case "up":
      return <Badge label="up" variant="success" />;
    case "degraded":
      return <Badge label="degraded" variant="warning" />;
    case "down":
      return <Badge label="down" variant="error" />;
    default:
      return <Badge label="unknown" variant="neutral" />;
  }
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-[var(--color-text-muted)]">{label}</div>
      <div className={mono ? "font-mono break-all" : "break-all"}>{value}</div>
    </div>
  );
}

function EnrolWizardModal({
  open,
  target,
  onClose,
  onSaved,
}: {
  open: boolean;
  target: RustionTargetSummary | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const editing = target !== null;
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [ed25519, setEd25519] = useState("");
  const [mldsa65, setMldsa65] = useState("");
  const [kemPub, setKemPub] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setName(target?.name ?? "");
      setEndpoint(target?.endpoint ?? "");
      setEd25519(target?.public_key_ed25519 ?? "");
      setMldsa65(target?.public_key_mldsa65 ?? "");
      setKemPub(target?.kem_public_key ?? "");
      setDescription(target?.description ?? "");
      setTags(target?.tags.join(", ") ?? "");
      setEnabled(target?.enabled ?? true);
    }
  }, [open, target]);

  const canSave = useMemo(
    () =>
      name.trim() &&
      endpoint.trim() &&
      endpoint.includes(":") &&
      ed25519.trim() &&
      mldsa65.trim() &&
      kemPub.trim(),
    [name, endpoint, ed25519, mldsa65, kemPub],
  );

  async function handleSave() {
    if (!canSave) return;
    setSaving(true);
    try {
      await rustion.rustionTargetUpsert(
        {
          name: name.trim(),
          endpoint: endpoint.trim(),
          public_key_ed25519: ed25519.trim(),
          public_key_mldsa65: mldsa65.trim(),
          kem_public_key: kemPub.trim(),
          description: description.trim(),
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          enabled,
          default_recording_dir: target?.default_recording_dir ?? "",
        },
        editing ? target?.id : undefined,
      );
      toast("success", editing ? "Bastion updated" : "Bastion enrolled");
      onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? `Edit ${target?.name}` : "Enrol Rustion bastion"}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={!canSave || saving}>
            {saving ? "Saving…" : editing ? "Save" : "Enrol"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-[var(--color-text-muted)]">
          Paste the hybrid public key Rustion exports via{" "}
          <code>rustion control-plane identity export</code>. Both
          halves (Ed25519 + ML-DSA-65) are required — a classical-only
          enrolment is refused as a downgrade attack.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="eu-prod-1"
            disabled={editing}
          />
          <Input
            label="Endpoint (host:port)"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="rustion-eu-1.internal:9443"
          />
        </div>
        <Textarea
          label="public_key.ed25519 (base64 SPKI)"
          value={ed25519}
          onChange={(e) => setEd25519(e.target.value)}
          rows={2}
          className="font-mono text-xs"
        />
        <Textarea
          label="public_key.mldsa65 (base64 raw)"
          value={mldsa65}
          onChange={(e) => setMldsa65(e.target.value)}
          rows={3}
          className="font-mono text-xs"
        />
        <Textarea
          label="kem_public_key (base64 raw ML-KEM-768)"
          value={kemPub}
          onChange={(e) => setKemPub(e.target.value)}
          rows={3}
          className="font-mono text-xs"
        />
        <Input
          label="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="EU production primary bastion"
        />
        <Input
          label="Tags (comma-separated)"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          placeholder="region=eu-west-1, zone=prod"
        />
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled (dispatcher routes to this instance when healthy)
        </label>
      </div>
    </Modal>
  );
}

function MasterEditModal({
  open,
  current,
  onClose,
  onSaved,
}: {
  open: boolean;
  current: RustionMasterConfig | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [pkiMount, setPkiMount] = useState("");
  const [pkiRole, setPkiRole] = useState("");
  const [pkiRolePqc, setPkiRolePqc] = useState("");
  const [issuerRef, setIssuerRef] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open && current) {
      setPkiMount(current.pki_mount);
      setPkiRole(current.pki_role);
      setPkiRolePqc(current.pki_role_pqc);
      setIssuerRef(current.issuer_ref);
    }
  }, [open, current]);

  async function handleSave() {
    if (!current) return;
    setSaving(true);
    try {
      await rustion.rustionMasterWrite({
        ...current,
        pki_mount: pkiMount.trim(),
        pki_role: pkiRole.trim(),
        pki_role_pqc: pkiRolePqc.trim(),
        issuer_ref: issuerRef.trim(),
      });
      toast("success", "Master-cert config saved");
      onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Configure master signing cert"
      size="md"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-[var(--color-text-muted)]">
          Point at the PKI mount + role that will mint the master cert
          when Phase 2's issue flow lands. The role's CA should match
          the hybrid algorithm (Ed25519 + ML-DSA-65) so the issued cert
          can sign BVRG-v1 envelopes.
        </p>
        <Input
          label="PKI mount"
          value={pkiMount}
          onChange={(e) => setPkiMount(e.target.value)}
          placeholder="pki-internal/"
        />
        <Input
          label="PKI role (Ed25519)"
          value={pkiRole}
          onChange={(e) => setPkiRole(e.target.value)}
          placeholder="rustion-master-ed25519"
        />
        <Input
          label="PKI role (ML-DSA-65)"
          value={pkiRolePqc}
          onChange={(e) => setPkiRolePqc(e.target.value)}
          placeholder="rustion-master-mldsa65"
        />
        <Input
          label="Issuer ref (optional)"
          value={issuerRef}
          onChange={(e) => setIssuerRef(e.target.value)}
          placeholder="(leave blank for mount default)"
        />
      </div>
    </Modal>
  );
}

// ── Bootstrap Master wizard ──────────────────────────────────────────
//
// One-shot orchestrator that mirrors `scripts/rustion-master-bootstrap.sh`:
// detects existing PKI mount / root / roles, fills in the gaps, writes
// the rustion master config, then calls `rustion/master/issue`. Each
// step renders a live ✓ / ✗ status line so the operator can see which
// command failed if anything goes wrong, and retry without reopening
// the modal.

type StepStatus = "pending" | "running" | "ok" | "err" | "skipped";

interface BootstrapStep {
  key: string;
  label: string;
  status: StepStatus;
  detail?: string;
}

const BOOTSTRAP_DEFAULTS = {
  pkiMount: "pki",
  ed25519Role: "rustion-master-ed25519",
  mldsa65Role: "rustion-master-mldsa65",
  commonName: "BastionVault Rustion Master Root",
  rootTtl: "87600h",
  roleTtl: "8760h",
  roleMaxTtl: "87600h",
  rotateGraceSecs: 86400,
};

function bootstrapRoleConfig(keyType: string, ttl: string, maxTtl: string): PkiRoleConfig {
  return {
    ttl,
    max_ttl: maxTtl,
    key_type: keyType,
    key_bits: 0,
    allow_localhost: false,
    allow_any_name: true,
    allow_subdomains: false,
    allow_bare_domains: false,
    allow_ip_sans: false,
    server_flag: false,
    client_flag: true,
    use_csr_sans: false,
    use_csr_common_name: false,
    key_usage: ["DigitalSignature"],
    ext_key_usage: [],
    country: "",
    province: "",
    locality: "",
    organization: "",
    ou: "",
    no_store: false,
    generate_lease: false,
    issuer_ref: "",
    allow_key_reuse: false,
    allowed_key_refs: [],
    allowed_domains: [],
    allow_glob_domains: false,
    acme_enabled: false,
  };
}

export function BootstrapMasterModal({
  open,
  onClose,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const { toast } = useToast();
  const [pkiMount, setPkiMount] = useState(BOOTSTRAP_DEFAULTS.pkiMount);
  const [edRole, setEdRole] = useState(BOOTSTRAP_DEFAULTS.ed25519Role);
  const [mlRole, setMlRole] = useState(BOOTSTRAP_DEFAULTS.mldsa65Role);
  const [commonName, setCommonName] = useState(BOOTSTRAP_DEFAULTS.commonName);
  const [rootTtl, setRootTtl] = useState(BOOTSTRAP_DEFAULTS.rootTtl);
  const [roleTtl, setRoleTtl] = useState(BOOTSTRAP_DEFAULTS.roleTtl);
  const [roleMaxTtl, setRoleMaxTtl] = useState(BOOTSTRAP_DEFAULTS.roleMaxTtl);
  const [graceSecs, setGraceSecs] = useState(
    BOOTSTRAP_DEFAULTS.rotateGraceSecs,
  );
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<BootstrapStep[]>([]);

  function reset() {
    setSteps([]);
    setRunning(false);
  }

  async function handleBootstrap() {
    const mountPath = pkiMount.trim().replace(/\/+$/, "");
    if (!mountPath || !edRole.trim() || !mlRole.trim()) {
      toast("error", "PKI mount and both role names are required");
      return;
    }
    setRunning(true);

    const initial: BootstrapStep[] = [
      { key: "mount", label: `Enable PKI mount '${mountPath}/'`, status: "pending" },
      { key: "root", label: "Generate root certificate", status: "pending" },
      { key: "ed", label: `Create Ed25519 role '${edRole}'`, status: "pending" },
      { key: "ml", label: `Create ML-DSA-65 role '${mlRole}'`, status: "pending" },
      { key: "config", label: "Write rustion master config", status: "pending" },
      { key: "issue", label: "Mint hybrid master keypair", status: "pending" },
    ];
    setSteps(initial);

    const update = (key: string, patch: Partial<BootstrapStep>) =>
      setSteps((s) =>
        s.map((step) => (step.key === key ? { ...step, ...patch } : step)),
      );

    // 1. PKI mount.
    update("mount", { status: "running" });
    try {
      const mounts = await api.pkiListMounts();
      const present = mounts.some(
        (m) => m.path.replace(/\/+$/, "") === mountPath,
      );
      if (present) {
        update("mount", { status: "skipped", detail: "already mounted" });
      } else {
        await api.pkiEnableMount(`${mountPath}/`);
        update("mount", { status: "ok" });
      }
    } catch (e) {
      update("mount", { status: "err", detail: extractError(e) });
      setRunning(false);
      return;
    }

    // 2. Root. The rustion master needs a signing chain whose root key
    //    can produce an Ed25519 AND an ML-DSA-65 leaf. The PKI engine
    //    refuses classical→PQ hybrid chains, so an EC / RSA default
    //    issuer here will fail later at `pki/issue/<mldsa65-role>` with
    //    `ErrPkiKeyTypeInvalid`. If the mount already has issuers, read
    //    the default and reject up-front when its key_type is anything
    //    other than ed25519 or ml-dsa-65 — far clearer than letting the
    //    failure surface five steps later.
    update("root", { status: "running" });
    try {
      const issuers = await api.pkiListIssuers(mountPath).catch(() => ({
        issuers: [],
      }));
      if (issuers.issuers && issuers.issuers.length > 0) {
        // Inspect the default issuer (the one rustion master uses by
        // virtue of `issuer_ref: "default"` below).
        let defaultDetail: { key_type: string; common_name: string } | null = null;
        try {
          defaultDetail = await api.pkiReadIssuer(mountPath, "default");
        } catch (_) {
          // No default set, or read failed — fall through to the
          // "skipped" behaviour and let the issue step surface a clearer
          // error if it actually matters.
        }
        if (defaultDetail) {
          const kt = (defaultDetail.key_type || "").toLowerCase();
          const compatible = kt === "ed25519" || kt === "ml-dsa-65";
          if (!compatible) {
            update("root", {
              status: "err",
              detail:
                `default issuer at '${mountPath}/' has key_type='${kt || "unknown"}' ` +
                `(CN='${defaultDetail.common_name || "?"}'), which cannot sign the ` +
                `ML-DSA-65 master leaf. Fix: re-run with a fresh PKI mount ` +
                `(e.g. 'pki-rustion'), OR delete the incompatible issuer ` +
                `(bvault delete ${mountPath}/issuer/default) and re-run, OR ` +
                `promote a compatible Ed25519 issuer at this mount to default.`,
            });
            setRunning(false);
            return;
          }
          update("root", {
            status: "skipped",
            detail: `issuer already present (key_type=${kt})`,
          });
        } else {
          update("root", {
            status: "skipped",
            detail: "issuer already present",
          });
        }
      } else {
        await api.pkiGenerateRoot({
          mount: mountPath,
          mode: "internal",
          common_name: commonName,
          ttl: rootTtl,
        });
        update("root", { status: "ok" });
      }
    } catch (e) {
      update("root", { status: "err", detail: extractError(e) });
      setRunning(false);
      return;
    }

    // 3 + 4. Roles.
    async function writeRole(
      stepKey: string,
      roleName: string,
      keyType: string,
    ): Promise<boolean> {
      update(stepKey, { status: "running" });
      try {
        await api.pkiWriteRole(
          mountPath,
          roleName,
          bootstrapRoleConfig(keyType, roleTtl, roleMaxTtl),
        );
        update(stepKey, { status: "ok" });
        return true;
      } catch (e) {
        update(stepKey, { status: "err", detail: extractError(e) });
        return false;
      }
    }
    if (!(await writeRole("ed", edRole.trim(), "ed25519"))) {
      setRunning(false);
      return;
    }
    if (!(await writeRole("ml", mlRole.trim(), "ml-dsa-65"))) {
      setRunning(false);
      return;
    }

    // 5. Master config.
    update("config", { status: "running" });
    try {
      await rustion.rustionMasterWrite({
        pki_mount: mountPath,
        pki_role: edRole.trim(),
        pki_role_pqc: mlRole.trim(),
        issuer_ref: "default",
        algorithm: "",
        default_ttl_secs: 31536000,
        rotate_grace_secs: graceSecs,
        current_serial: "",
        current_not_after: "",
        updated_at: "",
        configured: false,
      });
      update("config", { status: "ok" });
    } catch (e) {
      update("config", { status: "err", detail: extractError(e) });
      setRunning(false);
      return;
    }

    // 6. Issue. ErrPkiKeyTypeInvalid here almost always means the
    //    default issuer at `<mount>/` is classical (EC / RSA) and the
    //    PKI engine refuses to sign the ML-DSA-65 leaf with it. The
    //    upfront check in step 2 catches this on a re-run, but a brand-
    //    new mount whose root was created with the wrong defaults (or a
    //    race) can still trip it — rewrite the error so the operator
    //    knows what to do next.
    update("issue", { status: "running" });
    try {
      const res = await rustion.rustionMasterIssue();
      update("issue", {
        status: "ok",
        detail: res.serial ? `serial=${res.serial}` : undefined,
      });
    } catch (e) {
      const raw = extractError(e);
      const detail = raw.includes("ErrPkiKeyTypeInvalid")
        ? `${raw} — the default issuer at '${mountPath}/' is likely ` +
          `classical (EC / RSA) and cannot sign the ML-DSA-65 leaf. Fix: ` +
          `re-run this wizard with a fresh PKI mount (e.g. 'pki-rustion'), ` +
          `OR delete the incompatible issuer ` +
          `(bvault delete ${mountPath}/issuer/default) and re-run.`
        : raw;
      update("issue", { status: "err", detail });
      setRunning(false);
      return;
    }

    setRunning(false);
    toast("success", "Master bootstrap complete");
    onDone();
  }

  return (
    <Modal
      open={open}
      onClose={() => {
        if (!running) {
          reset();
          onClose();
        }
      }}
      title="Bootstrap Rustion master"
      size="md"
      actions={
        <>
          <Button
            variant="ghost"
            disabled={running}
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Close
          </Button>
          <Button onClick={handleBootstrap} disabled={running}>
            {running ? "Bootstrapping…" : "Bootstrap"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-[var(--color-text-muted)]">
          One-shot equivalent of{" "}
          <code className="font-mono">scripts/rustion-master-bootstrap.sh</code>.
          Enables the PKI mount, generates a root certificate, writes
          both PKI roles, points the rustion master at them, and mints
          the hybrid keypair. Each step is idempotent — already-present
          state is skipped.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="PKI mount"
            value={pkiMount}
            onChange={(e) => setPkiMount(e.target.value)}
            disabled={running}
          />
          <Input
            label="Rotate grace (secs)"
            type="number"
            value={String(graceSecs)}
            onChange={(e) =>
              setGraceSecs(Math.max(0, Number(e.target.value) || 0))
            }
            disabled={running}
          />
          <Input
            label="Ed25519 role"
            value={edRole}
            onChange={(e) => setEdRole(e.target.value)}
            disabled={running}
          />
          <Input
            label="ML-DSA-65 role"
            value={mlRole}
            onChange={(e) => setMlRole(e.target.value)}
            disabled={running}
          />
          <Input
            label="Role TTL"
            value={roleTtl}
            onChange={(e) => setRoleTtl(e.target.value)}
            disabled={running}
          />
          <Input
            label="Role max TTL"
            value={roleMaxTtl}
            onChange={(e) => setRoleMaxTtl(e.target.value)}
            disabled={running}
          />
          <Input
            label="Root TTL"
            value={rootTtl}
            onChange={(e) => setRootTtl(e.target.value)}
            disabled={running}
          />
          <Input
            label="Root common name"
            value={commonName}
            onChange={(e) => setCommonName(e.target.value)}
            disabled={running}
          />
        </div>
        {steps.length > 0 && (
          <div className="mt-3 border-t border-[var(--color-border)] pt-3 space-y-1.5 text-xs">
            {steps.map((step) => (
              <div key={step.key} className="flex items-start gap-2 min-w-0">
                <StepIcon status={step.status} />
                <div className="min-w-0 flex-1">
                  <div className="truncate">{step.label}</div>
                  {step.detail && (
                    <div className="text-[var(--color-text-muted)] truncate">
                      {step.detail}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}

function StepIcon({ status }: { status: StepStatus }) {
  switch (status) {
    case "ok":
      return <span className="text-emerald-400" aria-label="ok">✓</span>;
    case "skipped":
      return <span className="text-sky-400" aria-label="skipped">✓</span>;
    case "err":
      return <span className="text-red-400" aria-label="error">✗</span>;
    case "running":
      return <span className="text-amber-400" aria-label="running">…</span>;
    default:
      return <span className="text-[var(--color-text-muted)]" aria-label="pending">•</span>;
  }
}
