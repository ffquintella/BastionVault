//! Cert-Lifecycle GUI — Phases L5–L7 of the PKI key-management +
//! lifecycle initiative.
//!
//! - Mount picker over `cert-lifecycle/` mounts (auto-mount when none
//!   exists, mirroring the PkiPage flow).
//! - Target inventory with state surfaced inline (current serial, last
//!   error, failure count).
//! - Manual renew button per target → calls
//!   `cert-lifecycle/renew/<name>` and toasts the receipt.
//! - Scheduler config card — the `client_token` field is write-only;
//!   we display only `client_token_set` to confirm it's configured.
//! - Deliverer registry banner — quick at-a-glance check that the
//!   plugin trait found the built-in `file` + `http-push` impls (and
//!   any future external ones).

import { useCallback, useEffect, useMemo, useState } from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  Input,
  Modal,
  Select,
  Table,
  Tabs,
  useToast,
} from "../components/ui";
import * as api from "../lib/api";
import type {
  CertLifecycleMountInfo,
  CertLifecycleSchedulerConfig,
  CertLifecycleState,
  CertLifecycleTarget,
} from "../lib/types";
import { extractError } from "../lib/error";

type TabId = "targets" | "scheduler";

export function CertLifecyclePage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<CertLifecycleMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState("");
  const [tab, setTab] = useState<TabId>("targets");
  const [busy, setBusy] = useState(true);
  const [enabling, setEnabling] = useState(false);

  const reloadMounts = useCallback(async () => {
    setBusy(true);
    try {
      const list = await api.certLifecycleListMounts();
      setMounts(list);
      if (list.length > 0 && !list.some((m) => m.path === activeMount)) {
        setActiveMount(list[0].path);
      }
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }, [activeMount, toast]);

  useEffect(() => {
    void reloadMounts();
  }, [reloadMounts]);

  async function enableMount() {
    setEnabling(true);
    try {
      await api.certLifecycleEnableMount("cert-lifecycle/");
      toast("success", "cert-lifecycle/ mounted");
      await reloadMounts();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setEnabling(false);
    }
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-xl font-semibold">Cert Lifecycle</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              Renewal targets that consume the PKI engine and deliver
              certs to file directories or http-push webhooks.
            </p>
          </div>
          {mounts.length > 0 && (
            <Select
              label=""
              value={activeMount}
              onChange={(e) => setActiveMount(e.target.value)}
              options={mounts.map((m) => ({ value: m.path, label: m.path }))}
            />
          )}
        </div>

        {busy ? (
          <Card>
            <div className="text-sm text-[var(--color-text-muted)]">
              Loading…
            </div>
          </Card>
        ) : mounts.length === 0 ? (
          <Card>
            <EmptyState
              title="No cert-lifecycle engine mounted"
              description="Mount the cert-lifecycle engine on `cert-lifecycle/` to manage automated cert renewal targets."
              action={
                <Button onClick={enableMount} disabled={enabling}>
                  {enabling ? "Mounting…" : "Mount cert-lifecycle engine"}
                </Button>
              }
            />
          </Card>
        ) : (
          <>
            <DeliverersBanner mount={activeMount} />
            <Card>
              <Tabs
                tabs={[
                  { id: "targets", label: "Targets" },
                  { id: "scheduler", label: "Scheduler" },
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>
            {tab === "targets" && <TargetsTab mount={activeMount} />}
            {tab === "scheduler" && <SchedulerTab mount={activeMount} />}
          </>
        )}
      </div>
    </Layout>
  );
}

// ── Deliverers banner ─────────────────────────────────────────────

function DeliverersBanner({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [names, setNames] = useState<string[] | null>(null);
  useEffect(() => {
    api
      .certLifecycleListDeliverers(mount)
      .then((list) => setNames(list))
      .catch((e) => toast("error", extractError(e)));
  }, [mount, toast]);
  if (names === null) return null;
  return (
    <Card>
      <div className="flex items-center gap-2 flex-wrap text-sm">
        <span className="text-[var(--color-text-muted)]">Deliverers:</span>
        {names.map((n) => (
          <Badge key={n} label={n} variant="info" />
        ))}
      </div>
    </Card>
  );
}

// ── Targets tab ───────────────────────────────────────────────────

function TargetsTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [names, setNames] = useState<string[]>([]);
  const [targets, setTargets] = useState<Record<string, CertLifecycleTarget>>({});
  const [states, setStates] = useState<Record<string, CertLifecycleState>>({});
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<CertLifecycleTarget | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.certLifecycleListTargets(mount);
      setNames(list);
      const tmap: Record<string, CertLifecycleTarget> = {};
      const smap: Record<string, CertLifecycleState> = {};
      for (const n of list) {
        try {
          tmap[n] = await api.certLifecycleReadTarget(mount, n);
        } catch {
          /* skip rows that fail to read */
        }
        try {
          smap[n] = await api.certLifecycleReadState(mount, n);
        } catch {
          /* state can be missing on never-renewed targets */
        }
      }
      setTargets(tmap);
      setStates(smap);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [mount, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function renew(name: string) {
    try {
      const r = await api.certLifecycleRenew(mount, name);
      toast(
        "success",
        `Renewed ${name} → ${r.delivery_kind} (${r.delivery_note || "ok"})`,
      );
      await reload();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function deleteTarget(name: string) {
    try {
      await api.certLifecycleDeleteTarget(mount, name);
      toast("success", `Target ${name} deleted`);
      await reload();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card title="Renewal targets">
      <div className="flex justify-end mb-3">
        <Button onClick={() => setShowCreate(true)}>New target</Button>
      </div>
      {loading ? (
        <div className="text-sm text-[var(--color-text-muted)]">Loading…</div>
      ) : names.length === 0 ? (
        <EmptyState
          title="No targets configured"
          description="Create a target to drive cert renewal into a file directory or http-push webhook."
          action={<Button onClick={() => setShowCreate(true)}>New target</Button>}
        />
      ) : (
        <Table<{ name: string }>
          columns={[
            {
              key: "name",
              header: "Name",
              render: ({ name }) => <span className="text-sm font-mono">{name}</span>,
            },
            {
              key: "kind",
              header: "Kind",
              render: ({ name }) => (
                <Badge label={targets[name]?.kind || "?"} variant="neutral" />
              ),
            },
            {
              key: "address",
              header: "Address",
              render: ({ name }) => (
                <code className="text-xs break-all">{targets[name]?.address || "—"}</code>
              ),
            },
            {
              key: "status",
              header: "Status",
              render: ({ name }) => {
                const s = states[name];
                if (!s || !s.current_serial) {
                  return <Badge label="never renewed" variant="warning" />;
                }
                if (s.last_error) {
                  return <Badge label="failing" variant="error" />;
                }
                return <Badge label="healthy" variant="success" />;
              },
            },
            {
              key: "serial",
              header: "Current serial",
              render: ({ name }) => (
                <code className="text-xs break-all">
                  {states[name]?.current_serial || "—"}
                </code>
              ),
            },
            {
              key: "fails",
              header: "Failures",
              render: ({ name }) => (
                <span className="text-sm">{states[name]?.failure_count ?? 0}</span>
              ),
            },
            {
              key: "actions",
              header: "",
              render: ({ name }) => (
                <div className="flex gap-1">
                  <Button variant="ghost" onClick={() => renew(name)}>
                    Renew
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => setEditing(targets[name])}
                    disabled={!targets[name]}
                  >
                    Edit
                  </Button>
                  <Button variant="ghost" onClick={() => setConfirmDelete(name)}>
                    Delete
                  </Button>
                </div>
              ),
            },
          ]}
          data={names.map((name) => ({ name }))}
          rowKey={(r) => r.name}
        />
      )}
      <TargetEditorModal
        open={showCreate || editing !== null}
        mount={mount}
        target={editing}
        onClose={() => {
          setShowCreate(false);
          setEditing(null);
        }}
        onSaved={() => {
          setShowCreate(false);
          setEditing(null);
          void reload();
        }}
      />
      <ConfirmModal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        onConfirm={async () => {
          if (!confirmDelete) return;
          const name = confirmDelete;
          setConfirmDelete(null);
          await deleteTarget(name);
        }}
        title="Delete target"
        message={
          confirmDelete
            ? `Delete target \`${confirmDelete}\`? Stored state for the target is also cleared.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
}

const KIND_OPTIONS = [
  { value: "file", label: "file (atomic-write to a directory)" },
  { value: "http-push", label: "http-push (POST JSON envelope)" },
];

const KEY_POLICY_OPTIONS = [
  { value: "rotate", label: "rotate (mint a fresh keypair every renewal)" },
  { value: "reuse", label: "reuse (pin a managed key — needs role.allow_key_reuse)" },
];

function TargetEditorModal({
  open,
  mount,
  target,
  onClose,
  onSaved,
}: {
  open: boolean;
  mount: string;
  target: CertLifecycleTarget | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [draft, setDraft] = useState<CertLifecycleTarget>(blankTarget());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setDraft(target ? { ...target } : blankTarget());
    }
  }, [open, target]);

  const setField = <K extends keyof CertLifecycleTarget>(
    key: K,
    value: CertLifecycleTarget[K],
  ) => setDraft((d) => ({ ...d, [key]: value }));

  async function save() {
    if (!draft.name.trim()) {
      toast("error", "Name is required");
      return;
    }
    setBusy(true);
    try {
      await api.certLifecycleWriteTarget(mount, draft);
      toast("success", `Target ${draft.name} saved`);
      onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const isEdit = target !== null;
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? `Edit target \`${target!.name}\`` : "New target"}
      size="lg"
    >
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="Name"
          value={draft.name}
          onChange={(e) => setField("name", e.target.value)}
          disabled={isEdit}
          placeholder="svc"
        />
        <Select
          label="Kind"
          value={draft.kind}
          onChange={(e) => setField("kind", e.target.value as CertLifecycleTarget["kind"])}
          options={KIND_OPTIONS}
        />
        <Input
          label={
            draft.kind === "http-push"
              ? "Webhook URL"
              : "Output directory (must exist)"
          }
          value={draft.address}
          onChange={(e) => setField("address", e.target.value)}
          placeholder={
            draft.kind === "http-push"
              ? "https://hooks.example.com/cert"
              : "/var/lib/svc/tls"
          }
        />
        <Input
          label="PKI mount"
          value={draft.pki_mount}
          onChange={(e) => setField("pki_mount", e.target.value)}
          placeholder="pki"
        />
        <Input
          label="Role"
          value={draft.role_ref}
          onChange={(e) => setField("role_ref", e.target.value)}
          placeholder="web"
        />
        <Input
          label="Common name"
          value={draft.common_name}
          onChange={(e) => setField("common_name", e.target.value)}
          placeholder="svc.example.com"
        />
        <Input
          label="DNS SANs (comma-separated)"
          value={draft.alt_names.join(",")}
          onChange={(e) =>
            setField(
              "alt_names",
              e.target.value
                .split(",")
                .map((s) => s.trim())
                .filter((s) => s.length > 0),
            )
          }
        />
        <Input
          label="IP SANs (comma-separated)"
          value={draft.ip_sans.join(",")}
          onChange={(e) =>
            setField(
              "ip_sans",
              e.target.value
                .split(",")
                .map((s) => s.trim())
                .filter((s) => s.length > 0),
            )
          }
        />
        <Input
          label="TTL (optional)"
          value={draft.ttl}
          onChange={(e) => setField("ttl", e.target.value)}
          placeholder="720h"
        />
        <Input
          label="Renew before"
          value={draft.renew_before}
          onChange={(e) => setField("renew_before", e.target.value)}
          placeholder="168h"
        />
        <Select
          label="Key policy"
          value={draft.key_policy}
          onChange={(e) =>
            setField("key_policy", e.target.value as CertLifecycleTarget["key_policy"])
          }
          options={KEY_POLICY_OPTIONS}
        />
        <Input
          label="Key ref (required for reuse)"
          value={draft.key_ref}
          onChange={(e) => setField("key_ref", e.target.value)}
          disabled={draft.key_policy !== "reuse"}
          placeholder="key-name | uuid"
        />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
      </div>
    </Modal>
  );
}

function blankTarget(): CertLifecycleTarget {
  return {
    name: "",
    kind: "file",
    address: "",
    pki_mount: "pki",
    role_ref: "",
    common_name: "",
    alt_names: [],
    ip_sans: [],
    ttl: "",
    key_policy: "rotate",
    key_ref: "",
    renew_before: "168h",
    created_at: 0,
  };
}

// ── Scheduler tab ─────────────────────────────────────────────────

function SchedulerTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<CertLifecycleSchedulerConfig | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      const c = await api.certLifecycleReadSchedulerConfig(mount);
      setCfg({ ...c, client_token: "" });
    } catch (e) {
      toast("error", extractError(e));
    }
  }, [mount, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  if (!cfg) {
    return (
      <Card>
        <div className="text-sm text-[var(--color-text-muted)]">Loading…</div>
      </Card>
    );
  }

  async function save() {
    if (!cfg) return;
    setBusy(true);
    try {
      await api.certLifecycleWriteSchedulerConfig(mount, cfg);
      toast("success", "Scheduler config saved");
      await reload();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const tokenStatus = useMemo(() => {
    if (cfg.client_token.trim().length > 0) {
      return { label: "new token will be saved", variant: "info" as const };
    }
    if (cfg.client_token_set) {
      return { label: "token configured", variant: "success" as const };
    }
    return { label: "token not configured", variant: "warning" as const };
  }, [cfg]);

  return (
    <Card title="Renewal scheduler">
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-sm">
          <span className="text-[var(--color-text-muted)]">
            The scheduler is opt-in per mount. When enabled it walks every
            target and fires renewal via{" "}
            <code>cert-lifecycle/renew/&lt;name&gt;</code> using the
            configured client token. Failures back off exponentially.
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={cfg.enabled}
              onChange={(e) =>
                setCfg({ ...cfg, enabled: e.target.checked })
              }
            />
            Enabled
          </label>
          <Input
            label="Tick interval (seconds, ≥ 30)"
            type="number"
            value={cfg.tick_interval_seconds}
            onChange={(e) =>
              setCfg({
                ...cfg,
                tick_interval_seconds: Number(e.target.value),
              })
            }
          />
          <Input
            label="Base backoff (seconds)"
            type="number"
            value={cfg.base_backoff_seconds}
            onChange={(e) =>
              setCfg({
                ...cfg,
                base_backoff_seconds: Number(e.target.value),
              })
            }
          />
          <Input
            label="Max backoff (seconds)"
            type="number"
            value={cfg.max_backoff_seconds}
            onChange={(e) =>
              setCfg({
                ...cfg,
                max_backoff_seconds: Number(e.target.value),
              })
            }
          />
          <Input
            label="Client token (write-only — leave empty to keep)"
            value={cfg.client_token}
            onChange={(e) => setCfg({ ...cfg, client_token: e.target.value })}
            placeholder="hvs.…"
          />
          <div className="flex items-center gap-2 text-sm pt-6">
            <span className="text-[var(--color-text-muted)]">Token state:</span>
            <Badge label={tokenStatus.label} variant={tokenStatus.variant} />
          </div>
        </div>
        <div className="flex justify-end">
          <Button onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Card>
  );
}
