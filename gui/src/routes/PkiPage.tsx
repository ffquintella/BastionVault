import { useState, useEffect, useCallback } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Textarea,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type {
  PkiMountInfo,
  PkiIssuerSummary,
  PkiIssuerDetail,
  PkiRoleConfig,
  PkiIssueResult,
  PkiTidyStatus,
  PkiAutoTidyConfig,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "issuers" | "roles" | "issue" | "certs" | "tidy";

const KEY_TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "ec", label: "ECDSA P-256 (default)" },
  { value: "rsa", label: "RSA" },
  { value: "ed25519", label: "Ed25519" },
  { value: "ml-dsa-44", label: "ML-DSA-44 (PQC)" },
  { value: "ml-dsa-65", label: "ML-DSA-65 (PQC)" },
  { value: "ml-dsa-87", label: "ML-DSA-87 (PQC)" },
];

const RSA_BITS = [
  { value: "2048", label: "2048" },
  { value: "3072", label: "3072" },
  { value: "4096", label: "4096" },
];
const EC_BITS = [
  { value: "256", label: "256 (P-256)" },
  { value: "384", label: "384 (P-384)" },
];

const ALL_USAGES = ["issuing-certificates", "crl-signing", "ocsp-signing"] as const;

function defaultRoleConfig(): PkiRoleConfig {
  return {
    ttl: "",
    max_ttl: "",
    key_type: "ec",
    key_bits: 0,
    allow_localhost: true,
    allow_any_name: true,
    allow_subdomains: false,
    allow_bare_domains: false,
    allow_ip_sans: true,
    server_flag: true,
    client_flag: true,
    use_csr_sans: true,
    use_csr_common_name: true,
    key_usage: ["DigitalSignature", "KeyEncipherment"],
    ext_key_usage: [],
    country: "",
    province: "",
    locality: "",
    organization: "",
    ou: "",
    no_store: false,
    generate_lease: false,
    issuer_ref: "",
  };
}

function fmtUnix(t: number | null | undefined): string {
  if (!t || t === 0) return "—";
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function PkiPage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<PkiMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState<string>("");
  const [tab, setTab] = useState<TabId>("issuers");
  const [showEnable, setShowEnable] = useState(false);
  const [newMountPath, setNewMountPath] = useState("pki/");
  const [enabling, setEnabling] = useState(false);

  const refreshMounts = useCallback(async () => {
    try {
      const list = await api.pkiListMounts();
      setMounts(list);
      if (list.length > 0 && !activeMount) {
        setActiveMount(list[0].path.replace(/\/$/, ""));
      }
    } catch (e) {
      toast("error", extractError(e));
    }
  }, [activeMount, toast]);

  useEffect(() => {
    refreshMounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleEnableMount() {
    if (!newMountPath.trim()) return;
    setEnabling(true);
    try {
      await api.pkiEnableMount(newMountPath.trim());
      toast("success", `Mounted PKI engine at ${newMountPath}`);
      setShowEnable(false);
      setNewMountPath("pki/");
      await refreshMounts();
      setActiveMount(newMountPath.trim().replace(/\/$/, ""));
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setEnabling(false);
    }
  }

  const mountOptions = mounts.length === 0
    ? [{ value: "", label: "No PKI mounts" }]
    : mounts.map((m) => ({
        value: m.path.replace(/\/$/, ""),
        label: m.path,
      }));

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h1 className="text-xl font-semibold">PKI</h1>
          <Button onClick={() => setShowEnable(true)}>+ Mount PKI engine</Button>
        </div>

        <Card>
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-sm text-[var(--color-text-muted)]">Mount</label>
            <Select
              label=""
              value={activeMount}
              onChange={(e) => setActiveMount(e.target.value)}
              disabled={mounts.length === 0}
              options={mountOptions}
              className="min-w-[200px]"
            />
            <Button variant="ghost" onClick={refreshMounts}>
              Refresh
            </Button>
          </div>
        </Card>

        {!activeMount ? (
          <Card>
            <EmptyState
              title="No PKI engine mounted"
              description="Mount the PKI engine on a path (typically `pki/`) to manage CAs, roles, and certificate issuance."
              action={
                <Button onClick={() => setShowEnable(true)}>Mount PKI engine</Button>
              }
            />
          </Card>
        ) : (
          <>
            <Card>
              <Tabs
                tabs={[
                  { id: "issuers", label: "Issuers" },
                  { id: "roles", label: "Roles" },
                  { id: "issue", label: "Issue" },
                  { id: "certs", label: "Certificates" },
                  { id: "tidy", label: "Tidy" },
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>

            {tab === "issuers" && <IssuersTab mount={activeMount} />}
            {tab === "roles" && <RolesTab mount={activeMount} />}
            {tab === "issue" && <IssueTab mount={activeMount} />}
            {tab === "certs" && <CertsTab mount={activeMount} />}
            {tab === "tidy" && <TidyTab mount={activeMount} />}
          </>
        )}
      </div>

      <Modal
        open={showEnable}
        onClose={() => setShowEnable(false)}
        title="Mount PKI engine"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowEnable(false)}>
              Cancel
            </Button>
            <Button onClick={handleEnableMount} disabled={enabling || !newMountPath.trim()}>
              {enabling ? "Mounting..." : "Mount"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="Mount path"
            value={newMountPath}
            onChange={(e) => setNewMountPath(e.target.value)}
            placeholder="pki/"
            autoFocus
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            The engine is mounted at <code>/v1/&lt;path&gt;/*</code>. Common choices:{" "}
            <code>pki/</code> for the default mount, <code>pki-int/</code> for an intermediate
            mount.
          </p>
        </div>
      </Modal>
    </Layout>
  );
}

// ── Issuers Tab ───────────────────────────────────────────────────

function IssuersTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [issuers, setIssuers] = useState<PkiIssuerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<PkiIssuerDetail | null>(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [showRename, setShowRename] = useState(false);
  const [showUsages, setShowUsages] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PkiIssuerSummary | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [usageValues, setUsageValues] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.pkiListIssuers(mount);
      setIssuers(result.issuers);
      if (result.issuers.length > 0) {
        const first = detail
          ? result.issuers.find((i) => i.id === detail.id) ?? result.issuers[0]
          : result.issuers[0];
        const d = await api.pkiReadIssuer(mount, first.id);
        setDetail(d);
      } else {
        setDetail(null);
      }
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectIssuer(id: string) {
    try {
      const d = await api.pkiReadIssuer(mount, id);
      setDetail(d);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function setAsDefault(id: string) {
    try {
      await api.pkiSetDefaultIssuer(mount, id);
      toast("success", "Default issuer updated");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleRename() {
    if (!detail || !renameValue.trim()) return;
    try {
      await api.pkiRenameIssuer(mount, detail.id, renameValue.trim());
      toast("success", "Issuer renamed");
      setShowRename(false);
      setRenameValue("");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleSetUsages() {
    if (!detail) return;
    try {
      await api.pkiSetIssuerUsages(mount, detail.id, usageValues);
      toast("success", "Usages updated");
      setShowUsages(false);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.pkiDeleteIssuer(mount, deleteTarget.id);
      toast("success", `Issuer ${deleteTarget.name} deleted`);
      setDeleteTarget(null);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card
      title="Issuers"
      actions={<Button onClick={() => setShowGenerate(true)}>+ Generate root CA</Button>}
    >
      {loading ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : issuers.length === 0 ? (
        <EmptyState
          title="No issuers configured"
          description="Generate a root CA to start issuing certificates. The first issuer becomes the mount default automatically."
          action={<Button onClick={() => setShowGenerate(true)}>Generate root CA</Button>}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div>
            <div className="space-y-1">
              {issuers.map((i) => (
                <button
                  key={i.id}
                  onClick={() => selectIssuer(i.id)}
                  className={`block w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                    detail?.id === i.id
                      ? "bg-[var(--color-surface-hover)] font-semibold"
                      : "hover:bg-[var(--color-surface-hover)]"
                  }`}
                >
                  <span className="truncate">{i.name}</span>
                  {i.is_default && (
                    <Badge label="default" variant="success" />
                  )}
                </button>
              ))}
            </div>
          </div>

          {detail && (
            <div className="lg:col-span-2 space-y-3 min-w-0">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Name" value={detail.name} />
                <Field label="Kind" value={detail.ca_kind} />
                <Field label="Common Name" value={detail.common_name} />
                <Field label="Key Type" value={detail.key_type} />
                <Field label="Not After" value={fmtUnix(detail.not_after)} />
                <Field label="Default" value={detail.is_default ? "yes" : "no"} />
                <Field label="Issuer ID" value={detail.id} mono />
                <Field label="Usages" value={detail.usage.join(", ") || "(none)"} />
              </div>
              <div className="flex gap-2 flex-wrap">
                {!detail.is_default && (
                  <Button variant="ghost" onClick={() => setAsDefault(detail.id)}>
                    Set as default
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={() => {
                    setRenameValue(detail.name);
                    setShowRename(true);
                  }}
                >
                  Rename
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setUsageValues(detail.usage);
                    setShowUsages(true);
                  }}
                >
                  Edit usages
                </Button>
                <Button
                  variant="ghost"
                  onClick={() =>
                    setDeleteTarget({
                      id: detail.id,
                      name: detail.name,
                      is_default: detail.is_default,
                    })
                  }
                >
                  Delete
                </Button>
              </div>
              <Textarea
                label="Certificate (PEM)"
                value={detail.certificate}
                readOnly
                rows={8}
                className="font-mono text-xs"
              />
            </div>
          )}
        </div>
      )}

      <GenerateRootModal
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        mount={mount}
        onSuccess={refresh}
      />

      <Modal
        open={showRename}
        onClose={() => setShowRename(false)}
        title="Rename issuer"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowRename(false)}>
              Cancel
            </Button>
            <Button onClick={handleRename} disabled={!renameValue.trim()}>
              Rename
            </Button>
          </>
        }
      >
        <Input
          label="New name"
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          autoFocus
        />
      </Modal>

      <Modal
        open={showUsages}
        onClose={() => setShowUsages(false)}
        title="Edit issuer usages"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowUsages(false)}>
              Cancel
            </Button>
            <Button onClick={handleSetUsages} disabled={usageValues.length === 0}>
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {ALL_USAGES.map((u) => (
            <label key={u} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={usageValues.includes(u)}
                onChange={(e) => {
                  if (e.target.checked) {
                    setUsageValues((prev) => Array.from(new Set([...prev, u])));
                  } else {
                    setUsageValues((prev) => prev.filter((v) => v !== u));
                  }
                }}
              />
              <code>{u}</code>
            </label>
          ))}
          <p className="text-xs text-[var(--color-text-muted)]">
            At least one usage must be enabled. An issuer with no usages can never be invoked.
          </p>
        </div>
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete issuer?"
        message={
          deleteTarget
            ? `Delete issuer "${deleteTarget.name}"? Certs already issued by this issuer remain in the cert store and tidy will sweep them after expiry.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
}

// ── Generate Root Modal ──────────────────────────────────────────

function GenerateRootModal({
  open,
  onClose,
  mount,
  onSuccess,
}: {
  open: boolean;
  onClose: () => void;
  mount: string;
  onSuccess: () => void;
}) {
  const { toast } = useToast();
  const [commonName, setCommonName] = useState("");
  const [organization, setOrganization] = useState("");
  const [keyType, setKeyType] = useState("ec");
  const [keyBits, setKeyBits] = useState("0");
  const [ttl, setTtl] = useState("87600h");
  const [issuerName, setIssuerName] = useState("");
  const [exported, setExported] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ private_key?: string } | null>(null);

  function reset() {
    setCommonName("");
    setOrganization("");
    setKeyType("ec");
    setKeyBits("0");
    setTtl("87600h");
    setIssuerName("");
    setExported(false);
    setResult(null);
  }

  async function submit() {
    if (!commonName.trim()) return;
    setBusy(true);
    try {
      const r = await api.pkiGenerateRoot({
        mount,
        mode: exported ? "exported" : "internal",
        common_name: commonName.trim(),
        organization: organization.trim() || undefined,
        key_type: keyType,
        key_bits: Number(keyBits) || undefined,
        ttl: ttl.trim() || undefined,
        issuer_name: issuerName.trim() || undefined,
      });
      toast("success", `Root CA generated as issuer "${r.issuer_name}"`);
      setResult({ private_key: r.private_key });
      onSuccess();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  function handleClose() {
    reset();
    onClose();
  }

  const bitsOptions = keyType === "rsa" ? RSA_BITS : keyType === "ec" ? EC_BITS : [];

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Generate root CA"
      size="md"
      actions={
        result ? (
          <Button onClick={handleClose}>Close</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={handleClose}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={busy || !commonName.trim()}>
              {busy ? "Generating…" : "Generate"}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="space-y-3">
          <p className="text-sm text-green-500">Root CA generated.</p>
          {result.private_key && (
            <Textarea
              label="Private key (PKCS#8 PEM) — store this securely; it will not be shown again"
              value={result.private_key}
              readOnly
              rows={8}
              className="font-mono text-xs"
            />
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Common Name"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
              placeholder="My Internal Root"
              autoFocus
            />
            <Input
              label="Organization (optional)"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
            />
            <Select
              label="Key type"
              value={keyType}
              onChange={(e) => {
                setKeyType(e.target.value);
                setKeyBits("0");
              }}
              options={KEY_TYPE_OPTIONS}
            />
            {bitsOptions.length > 0 && (
              <Select
                label="Key bits"
                value={keyBits === "0" ? bitsOptions[0].value : keyBits}
                onChange={(e) => setKeyBits(e.target.value)}
                options={bitsOptions}
              />
            )}
            <Input
              label="TTL"
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              placeholder="87600h (10 years)"
            />
            <Input
              label="Issuer name (optional)"
              value={issuerName}
              onChange={(e) => setIssuerName(e.target.value)}
              placeholder="default | issuer-2 | …"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={exported}
              onChange={(e) => setExported(e.target.checked)}
            />
            Export private key (returns the key in the response — copy it before closing)
          </label>
        </div>
      )}
    </Modal>
  );
}

// ── Roles Tab ─────────────────────────────────────────────────────

function RolesTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [config, setConfig] = useState<PkiRoleConfig | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [draft, setDraft] = useState<PkiRoleConfig>(defaultRoleConfig());
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const list = await api.pkiListRoles(mount);
      setRoles(list);
      if (selected && !list.includes(selected)) setSelected(null);
      if (selected && list.includes(selected)) {
        const c = await api.pkiReadRole(mount, selected);
        setConfig(c);
      }
    } catch (e) {
      toast("error", extractError(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount, selected]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectRole(name: string) {
    try {
      const c = await api.pkiReadRole(mount, name);
      setSelected(name);
      setConfig(c);
      setEditing(false);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newName.trim()) return;
    try {
      await api.pkiWriteRole(mount, newName.trim(), draft);
      toast("success", `Role ${newName} created`);
      setShowCreate(false);
      setNewName("");
      setDraft(defaultRoleConfig());
      await refresh();
      const created = newName.trim();
      setSelected(created);
      const c = await api.pkiReadRole(mount, created);
      setConfig(c);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleSaveEdit() {
    if (!selected || !config) return;
    try {
      await api.pkiWriteRole(mount, selected, config);
      toast("success", "Role updated");
      setEditing(false);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.pkiDeleteRole(mount, deleteTarget);
      toast("success", `Role ${deleteTarget} deleted`);
      setDeleteTarget(null);
      if (selected === deleteTarget) {
        setSelected(null);
        setConfig(null);
      }
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card title="Roles" actions={<Button onClick={() => setShowCreate(true)}>+ Create role</Button>}>
      {roles.length === 0 ? (
        <EmptyState
          title="No roles configured"
          description="Create a role to define which CN, SANs, and TTLs are allowed when issuing certificates."
          action={<Button onClick={() => setShowCreate(true)}>Create role</Button>}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-1">
            {roles.map((r) => (
              <button
                key={r}
                onClick={() => selectRole(r)}
                className={`block w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  selected === r
                    ? "bg-[var(--color-surface-hover)] font-semibold"
                    : "hover:bg-[var(--color-surface-hover)]"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <div className="lg:col-span-2 min-w-0">
            {config ? (
              <RoleEditor
                config={config}
                editing={editing}
                onChange={setConfig}
                onEdit={() => setEditing(true)}
                onSave={handleSaveEdit}
                onCancel={() => {
                  setEditing(false);
                  if (selected) selectRole(selected);
                }}
                onDelete={() => selected && setDeleteTarget(selected)}
              />
            ) : (
              <p className="text-sm text-[var(--color-text-muted)]">
                Select a role to view its configuration.
              </p>
            )}
          </div>
        </div>
      )}

      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="Create role"
        size="lg"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!newName.trim()}>
              Create
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="Role name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="web-server"
            autoFocus
          />
          <RoleEditor config={draft} editing={true} onChange={setDraft} compact />
        </div>
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete role?"
        message={`Delete role "${deleteTarget}"? Existing certs issued under this role keep working until they expire or are revoked.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
}

function RoleEditor({
  config,
  editing,
  onChange,
  onEdit,
  onSave,
  onCancel,
  onDelete,
  compact,
}: {
  config: PkiRoleConfig;
  editing: boolean;
  onChange: (c: PkiRoleConfig) => void;
  onEdit?: () => void;
  onSave?: () => void;
  onCancel?: () => void;
  onDelete?: () => void;
  compact?: boolean;
}) {
  const set = (patch: Partial<PkiRoleConfig>) => onChange({ ...config, ...patch });

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="TTL"
          value={config.ttl}
          onChange={(e) => set({ ttl: e.target.value })}
          disabled={!editing}
          placeholder="720h"
        />
        <Input
          label="Max TTL"
          value={config.max_ttl}
          onChange={(e) => set({ max_ttl: e.target.value })}
          disabled={!editing}
          placeholder="2160h"
        />
        <Select
          label="Key type"
          value={config.key_type}
          onChange={(e) => set({ key_type: e.target.value })}
          disabled={!editing}
          options={KEY_TYPE_OPTIONS}
        />
        <Input
          label="Key bits (0 = default)"
          type="number"
          value={config.key_bits}
          onChange={(e) => set({ key_bits: Number(e.target.value) })}
          disabled={!editing}
        />
        <Input
          label="Issuer ref (empty = mount default)"
          value={config.issuer_ref}
          onChange={(e) => set({ issuer_ref: e.target.value })}
          disabled={!editing}
          placeholder="default | uuid"
        />
        <Input
          label="Organization"
          value={config.organization}
          onChange={(e) => set({ organization: e.target.value })}
          disabled={!editing}
        />
      </div>

      {!compact && (
        <div className="grid grid-cols-2 gap-2">
          <Toggle
            label="allow_any_name"
            checked={config.allow_any_name}
            onChange={(b) => set({ allow_any_name: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_localhost"
            checked={config.allow_localhost}
            onChange={(b) => set({ allow_localhost: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_subdomains"
            checked={config.allow_subdomains}
            onChange={(b) => set({ allow_subdomains: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_bare_domains"
            checked={config.allow_bare_domains}
            onChange={(b) => set({ allow_bare_domains: b })}
            disabled={!editing}
          />
          <Toggle
            label="allow_ip_sans"
            checked={config.allow_ip_sans}
            onChange={(b) => set({ allow_ip_sans: b })}
            disabled={!editing}
          />
          <Toggle
            label="server_flag (ServerAuth EKU)"
            checked={config.server_flag}
            onChange={(b) => set({ server_flag: b })}
            disabled={!editing}
          />
          <Toggle
            label="client_flag (ClientAuth EKU)"
            checked={config.client_flag}
            onChange={(b) => set({ client_flag: b })}
            disabled={!editing}
          />
          <Toggle
            label="no_store"
            checked={config.no_store}
            onChange={(b) => set({ no_store: b })}
            disabled={!editing}
          />
        </div>
      )}

      {!compact && (onEdit || onSave) && (
        <div className="flex gap-2 justify-end">
          {editing ? (
            <>
              <Button variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
              <Button onClick={onSave}>Save</Button>
            </>
          ) : (
            <>
              {onDelete && (
                <Button variant="ghost" onClick={onDelete}>
                  Delete
                </Button>
              )}
              <Button onClick={onEdit}>Edit</Button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (b: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
      />
      <code className="text-xs">{label}</code>
    </label>
  );
}

// ── Issue Tab ────────────────────────────────────────────────────

function IssueTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [role, setRole] = useState("");
  const [commonName, setCommonName] = useState("");
  const [altNames, setAltNames] = useState("");
  const [ipSans, setIpSans] = useState("");
  const [ttl, setTtl] = useState("");
  const [issuerRef, setIssuerRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PkiIssueResult | null>(null);

  useEffect(() => {
    api
      .pkiListRoles(mount)
      .then((list) => {
        setRoles(list);
        if (list.length > 0 && !role) setRole(list[0]);
      })
      .catch((e) => toast("error", extractError(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  async function submit() {
    if (!role || !commonName.trim()) return;
    setBusy(true);
    try {
      const r = await api.pkiIssueCert({
        mount,
        role,
        common_name: commonName.trim(),
        alt_names: altNames.trim() || undefined,
        ip_sans: ipSans.trim() || undefined,
        ttl: ttl.trim() || undefined,
        issuer_ref: issuerRef.trim() || undefined,
      });
      setResult(r);
      toast("success", `Certificate issued (serial ${r.serial_number})`);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  function copy(text: string, label: string) {
    navigator.clipboard.writeText(text).then(
      () => toast("success", `${label} copied`),
      () => toast("error", `Failed to copy ${label}`),
    );
  }

  if (roles.length === 0) {
    return (
      <Card>
        <EmptyState
          title="No roles configured"
          description="Create a role on the Roles tab before issuing a certificate."
        />
      </Card>
    );
  }

  return (
    <Card title="Issue a certificate">
      <div className="grid grid-cols-2 gap-3">
        <Select
          label="Role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          options={roles.map((r) => ({ value: r, label: r }))}
        />
        <Input
          label="Common Name"
          value={commonName}
          onChange={(e) => setCommonName(e.target.value)}
          placeholder="api.example.com"
        />
        <Input
          label="DNS / IP SANs (comma-separated)"
          value={altNames}
          onChange={(e) => setAltNames(e.target.value)}
          placeholder="api-alt.example.com, 127.0.0.1"
        />
        <Input
          label="Extra IP SANs (comma-separated)"
          value={ipSans}
          onChange={(e) => setIpSans(e.target.value)}
        />
        <Input
          label="TTL (optional)"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          placeholder="720h"
        />
        <Input
          label="Issuer override (optional)"
          value={issuerRef}
          onChange={(e) => setIssuerRef(e.target.value)}
          placeholder="default | uuid"
        />
      </div>
      <div className="mt-4">
        <Button onClick={submit} disabled={busy || !role || !commonName.trim()}>
          {busy ? "Issuing…" : "Issue"}
        </Button>
      </div>

      {result && (
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge label="issued" variant="success" />
            <code className="text-sm break-all">{result.serial_number}</code>
            <span className="text-xs text-[var(--color-text-muted)]">
              issuer {result.issuer_id}
            </span>
          </div>
          <PemBlock
            label="Certificate"
            value={result.certificate}
            onCopy={() => copy(result.certificate, "certificate")}
          />
          <PemBlock
            label="Private key (PKCS#8)"
            value={result.private_key}
            onCopy={() => copy(result.private_key, "private key")}
          />
          <PemBlock
            label="Issuing CA"
            value={result.issuing_ca}
            onCopy={() => copy(result.issuing_ca, "issuing CA")}
          />
        </div>
      )}
    </Card>
  );
}

function PemBlock({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium text-[var(--color-text-muted)]">{label}</span>
        <Button variant="ghost" onClick={onCopy}>
          Copy
        </Button>
      </div>
      <Textarea label="" value={value} readOnly rows={6} className="font-mono text-xs" />
    </div>
  );
}

// ── Certificates Tab ──────────────────────────────────────────────

function CertsTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [serials, setSerials] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [cert, setCert] = useState<{
    certificate: string;
    issued_at: number;
    revoked_at?: number | null;
  } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await api.pkiListCerts(mount);
      setSerials([...list].sort());
    } catch (e) {
      toast("error", extractError(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function selectSerial(serial: string) {
    try {
      const c = await api.pkiReadCert(mount, serial);
      setSelected(serial);
      setCert({
        certificate: c.certificate,
        issued_at: c.issued_at,
        revoked_at: c.revoked_at ?? null,
      });
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    try {
      await api.pkiRevokeCert(mount, revokeTarget);
      toast("success", `Certificate ${revokeTarget} revoked`);
      setRevokeTarget(null);
      if (selected === revokeTarget) await selectSerial(revokeTarget);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function rotateCrl() {
    try {
      const r = await api.pkiRotateCrl(mount);
      toast("success", `CRL rotated (number ${r.crl_number})`);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const filtered = filter
    ? serials.filter((s) => s.toLowerCase().includes(filter.toLowerCase()))
    : serials;

  return (
    <Card
      title="Issued certificates"
      actions={
        <>
          <Input
            label=""
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter…"
            className="w-48"
          />
          <Button variant="ghost" onClick={refresh}>
            Refresh
          </Button>
          <Button variant="ghost" onClick={rotateCrl}>
            Rotate CRL
          </Button>
        </>
      }
    >
      {serials.length === 0 ? (
        <EmptyState
          title="No certificates issued yet"
          description="Issued certificates appear here. Roles with `no_store = true` skip persistence."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="max-h-96 overflow-auto">
            <Table
              columns={[
                {
                  key: "serial",
                  header: "Serial",
                  render: (s: { serial: string }) => (
                    <button
                      onClick={() => selectSerial(s.serial)}
                      className={`text-left w-full font-mono text-xs truncate ${
                        selected === s.serial
                          ? "font-semibold text-[var(--color-primary)]"
                          : ""
                      }`}
                    >
                      {s.serial}
                    </button>
                  ),
                },
              ]}
              data={filtered.map((s) => ({ serial: s }))}
              rowKey={(r: { serial: string }) => r.serial}
              emptyMessage="No matching serials"
            />
          </div>
          {cert && selected && (
            <div className="lg:col-span-2 space-y-3 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <code className="text-sm break-all">{selected}</code>
                {cert.revoked_at ? (
                  <Badge label={`revoked ${fmtUnix(cert.revoked_at)}`} variant="error" />
                ) : (
                  <Badge label="active" variant="success" />
                )}
              </div>
              <Field label="Issued at" value={fmtUnix(cert.issued_at)} />
              <PemBlock
                label="Certificate"
                value={cert.certificate}
                onCopy={() =>
                  navigator.clipboard.writeText(cert.certificate).then(
                    () => toast("success", "certificate copied"),
                    () => toast("error", "Failed to copy"),
                  )
                }
              />
              {!cert.revoked_at && (
                <Button variant="ghost" onClick={() => setRevokeTarget(selected)}>
                  Revoke
                </Button>
              )}
            </div>
          )}
        </div>
      )}

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
        title="Revoke certificate?"
        message={`Revoke ${revokeTarget}? The CRL will rebuild immediately.`}
        confirmLabel="Revoke"
        variant="danger"
      />
    </Card>
  );
}

// ── Tidy Tab ──────────────────────────────────────────────────────

function TidyTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [status, setStatus] = useState<PkiTidyStatus | null>(null);
  const [autoTidy, setAutoTidy] = useState<PkiAutoTidyConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [safetyBuffer, setSafetyBuffer] = useState("72h");
  const [tidyCertStore, setTidyCertStore] = useState(true);
  const [tidyRevoked, setTidyRevoked] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([
        api.pkiReadTidyStatus(mount),
        api.pkiReadAutoTidy(mount),
      ]);
      setStatus(s);
      setAutoTidy(a);
    } catch (e) {
      toast("error", extractError(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function runTidy() {
    setBusy(true);
    try {
      const r = await api.pkiRunTidy({
        mount,
        tidy_cert_store: tidyCertStore,
        tidy_revoked_certs: tidyRevoked,
        safety_buffer: safetyBuffer,
      });
      toast(
        "success",
        `Tidy: ${r.certs_deleted} certs, ${r.revoked_entries_deleted} revoked entries removed (${r.duration_ms}ms)`,
      );
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveAutoTidy() {
    if (!autoTidy) return;
    try {
      await api.pkiWriteAutoTidy(mount, autoTidy);
      toast("success", "Auto-tidy configuration saved");
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <div className="space-y-4">
      <Card title="Run tidy on demand">
        <div className="grid grid-cols-2 gap-3 mb-3">
          <Input
            label="Safety buffer"
            value={safetyBuffer}
            onChange={(e) => setSafetyBuffer(e.target.value)}
            placeholder="72h"
          />
          <div className="flex items-end gap-3">
            <Toggle label="cert_store" checked={tidyCertStore} onChange={setTidyCertStore} />
            <Toggle label="revoked_certs" checked={tidyRevoked} onChange={setTidyRevoked} />
          </div>
        </div>
        <Button onClick={runTidy} disabled={busy}>
          {busy ? "Running…" : "Run tidy"}
        </Button>
      </Card>

      <Card title="Last tidy run">
        {status && status.last_run_at_unix > 0 ? (
          <div className="grid grid-cols-2 gap-3">
            <Field label="Last run at" value={fmtUnix(status.last_run_at_unix)} />
            <Field label="Source" value={status.source} />
            <Field label="Certs deleted" value={String(status.certs_deleted)} />
            <Field
              label="Revoked entries deleted"
              value={String(status.revoked_entries_deleted)}
            />
            <Field label="Duration (ms)" value={String(status.last_run_duration_ms)} />
            <Field label="Safety buffer (s)" value={String(status.safety_buffer_seconds)} />
          </div>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            Tidy has not run yet on this mount.
          </p>
        )}
      </Card>

      <Card
        title="Auto-tidy"
        actions={autoTidy ? <Button onClick={saveAutoTidy}>Save</Button> : null}
      >
        {autoTidy && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Interval"
                value={autoTidy.interval}
                onChange={(e) => setAutoTidy({ ...autoTidy, interval: e.target.value })}
                placeholder="12h"
              />
              <Input
                label="Safety buffer"
                value={autoTidy.safety_buffer}
                onChange={(e) =>
                  setAutoTidy({ ...autoTidy, safety_buffer: e.target.value })
                }
                placeholder="72h"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 mt-3">
              <Toggle
                label="enabled"
                checked={autoTidy.enabled}
                onChange={(b) => setAutoTidy({ ...autoTidy, enabled: b })}
              />
              <Toggle
                label="tidy_cert_store"
                checked={autoTidy.tidy_cert_store}
                onChange={(b) => setAutoTidy({ ...autoTidy, tidy_cert_store: b })}
              />
              <Toggle
                label="tidy_revoked_certs"
                checked={autoTidy.tidy_revoked_certs}
                onChange={(b) => setAutoTidy({ ...autoTidy, tidy_revoked_certs: b })}
              />
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

// ── Shared atom ───────────────────────────────────────────────────

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
    <div className="min-w-0">
      <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
        {label}
      </label>
      <div
        className={`bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm truncate ${
          mono ? "font-mono text-xs" : ""
        }`}
      >
        {value || "—"}
      </div>
    </div>
  );
}
