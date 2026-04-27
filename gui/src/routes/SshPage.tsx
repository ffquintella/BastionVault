import { useState, useEffect, useCallback, useMemo } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Textarea,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  Badge,
  useToast,
} from "../components/ui";
import type {
  SshMountInfo,
  SshCaInfo,
  SshRoleConfig,
  SshSignResult,
  SshCredsResult,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "ca" | "roles" | "sign" | "creds";

// Default-roles helper. Mirrors the engine's `RoleEntry::default()` —
// we render fresh role forms in this shape so toggling between modes
// doesn't strand the operator with leftover values from a previous
// edit.
function blankRole(): SshRoleConfig {
  return {
    key_type: "ca",
    algorithm_signer: "ssh-ed25519",
    cert_type: "user",
    allowed_users: "",
    default_user: "",
    allowed_extensions: "",
    default_extensions: {},
    allowed_critical_options: "",
    default_critical_options: {},
    ttl: "30m",
    max_ttl: "1h",
    not_before_duration: "30s",
    key_id_format: "vault-{{role}}-{{token_display_name}}",
    cidr_list: "",
    exclude_cidr_list: "",
    port: 22,
    pqc_only: false,
  };
}

export function SshPage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<SshMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState<string>("");
  const [tab, setTab] = useState<TabId>("ca");
  const [showEnable, setShowEnable] = useState(false);
  const [enablePath, setEnablePath] = useState("ssh");

  const refreshMounts = useCallback(async () => {
    try {
      const list = await api.sshListMounts();
      setMounts(list);
      // If no mount selected yet (or the previous one disappeared on
      // refresh), pick the first.
      setActiveMount((prev) => {
        if (prev && list.some((m) => m.path === prev)) return prev;
        return list[0]?.path ?? "";
      });
    } catch (err) {
      toast("error", extractError(err));
    }
  }, [toast]);

  useEffect(() => {
    refreshMounts();
  }, [refreshMounts]);

  const mountOptions = useMemo(
    () => mounts.map((m) => ({ value: m.path, label: m.path })),
    [mounts],
  );

  const onEnable = async () => {
    try {
      await api.sshEnableMount(enablePath);
      toast("success", `Mounted SSH engine at ${enablePath}`);
      setShowEnable(false);
      await refreshMounts();
      setActiveMount(enablePath.replace(/\/+$/, "") + "/");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h1 className="text-xl font-semibold">SSH</h1>
          <Button onClick={() => setShowEnable(true)}>+ Mount SSH engine</Button>
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
              title="No SSH engine mounted"
              description="Mount the SSH engine on a path (typically `ssh/`) to manage the CA, roles, and credential issuance."
              action={
                <Button onClick={() => setShowEnable(true)}>Mount SSH engine</Button>
              }
            />
          </Card>
        ) : (
          <>
            <Card>
              <Tabs
                tabs={[
                  { id: "ca", label: "CA" },
                  { id: "roles", label: "Roles" },
                  { id: "sign", label: "Sign Cert" },
                  { id: "creds", label: "OTP Creds" },
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>

            {tab === "ca" && <CaTab mount={activeMount} />}
            {tab === "roles" && <RolesTab mount={activeMount} />}
            {tab === "sign" && <SignTab mount={activeMount} />}
            {tab === "creds" && <CredsTab mount={activeMount} />}
          </>
        )}

        <Modal open={showEnable} onClose={() => setShowEnable(false)} title="Mount SSH engine" size="sm">
          <div className="space-y-3">
            <Input
              label="Mount path"
              value={enablePath}
              onChange={(e) => setEnablePath(e.target.value)}
              placeholder="ssh"
              hint="Typically `ssh`. Operators with multiple environments can mount at custom paths like `ssh-prod`."
            />
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setShowEnable(false)}>
                Cancel
              </Button>
              <Button onClick={onEnable}>Mount</Button>
            </div>
          </div>
        </Modal>
      </div>
    </Layout>
  );
}

// ── CA Tab ────────────────────────────────────────────────────────

function CaTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [ca, setCa] = useState<SshCaInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [showGenerate, setShowGenerate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [genAlgo, setGenAlgo] = useState("ed25519");
  const [importedKey, setImportedKey] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const info = await api.sshReadCa(mount);
      setCa(info.public_key ? info : null);
    } catch {
      // CA-not-configured surfaces as a 404-ish error from the engine;
      // we treat absence as the empty state rather than a hard failure.
      setCa(null);
    } finally {
      setLoading(false);
    }
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onGenerate = async () => {
    try {
      const info = await api.sshGenerateCa({ mount, algorithm: genAlgo });
      setCa(info);
      setShowGenerate(false);
      toast("success", `Generated ${info.algorithm} CA`);
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onImport = async () => {
    try {
      const info = await api.sshGenerateCa({ mount, private_key: importedKey });
      setCa(info);
      setShowImport(false);
      setImportedKey("");
      toast("success", "Imported CA");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onDelete = async () => {
    try {
      await api.sshDeleteCa(mount);
      setCa(null);
      setConfirmDelete(false);
      toast("success", "CA deleted");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading CA…</p>
      </Card>
    );
  }

  return (
    <>
      <Card>
        {ca ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-medium">CA configured</h2>
                <Badge label={ca.algorithm} />
              </div>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(ca.public_key)}
                >
                  Copy public key
                </Button>
                <Button variant="danger" onClick={() => setConfirmDelete(true)}>
                  Delete CA
                </Button>
              </div>
            </div>
            <Textarea
              label="OpenSSH public key"
              value={ca.public_key}
              readOnly
              rows={3}
            />
            <p className="text-xs text-[var(--color-text-muted)]">
              Append this line to each managed host's `TrustedUserCAKeys` file.
            </p>
          </div>
        ) : (
          <EmptyState
            title="No CA configured"
            description="Generate a fresh CA keypair (Ed25519 or — with the `ssh_pqc` server build — ML-DSA-65), or import an existing OpenSSH private key."
            action={
              <div className="flex gap-2">
                <Button onClick={() => setShowGenerate(true)}>Generate CA</Button>
                <Button variant="ghost" onClick={() => setShowImport(true)}>
                  Import existing
                </Button>
              </div>
            }
          />
        )}
      </Card>

      <Modal
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        title="Generate CA keypair"
        size="sm"
      >
        <div className="space-y-3">
          <Select
            label="Algorithm"
            value={genAlgo}
            onChange={(e) => setGenAlgo(e.target.value)}
            options={[
              { value: "ed25519", label: "Ed25519 (default)" },
              { value: "mldsa65", label: "ML-DSA-65 (PQC, server `ssh_pqc` build)" },
            ]}
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            ML-DSA-65 certificates only verify in clients that have implemented
            the draft `ssh-mldsa65@openssh.com` algorithm. Use Ed25519 for
            compatibility with stock OpenSSH.
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setShowGenerate(false)}>
              Cancel
            </Button>
            <Button onClick={onGenerate}>Generate</Button>
          </div>
        </div>
      </Modal>

      <Modal open={showImport} onClose={() => setShowImport(false)} title="Import CA private key" size="md">
        <div className="space-y-3">
          <Textarea
            label="OpenSSH private key (PEM)"
            value={importedKey}
            onChange={(e) => setImportedKey(e.target.value)}
            rows={10}
            placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----"}
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            Phase 1 accepts unencrypted Ed25519 only. The key is barrier-encrypted on the server and never returned via any read endpoint.
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setShowImport(false)}>
              Cancel
            </Button>
            <Button onClick={onImport} disabled={!importedKey.trim()}>
              Import
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={onDelete}
        title="Delete CA?"
        message="Existing certificates already issued under this CA will become unverifiable on hosts that trust this public key. Do this only when rotating."
        confirmLabel="Delete"
        variant="danger"
      />
    </>
  );
}

// ── Roles Tab ─────────────────────────────────────────────────────

function RolesTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [names, setNames] = useState<string[]>([]);
  const [editing, setEditing] = useState<{ name: string; config: SshRoleConfig } | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newRole, setNewRole] = useState<SshRoleConfig>(blankRole());
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await api.sshListRoles(mount);
      setNames(list);
    } catch (err) {
      // Empty list on error is fine — the engine returns no `keys`
      // when the role catalog is empty.
      setNames([]);
      const msg = extractError(err);
      if (!msg.includes("404") && !msg.toLowerCase().includes("not found")) {
        toast("error", msg);
      }
    }
  }, [mount, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const openEdit = async (name: string) => {
    try {
      const config = await api.sshReadRole(mount, name);
      setEditing({ name, config });
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onSave = async () => {
    if (!editing) return;
    try {
      await api.sshWriteRole(mount, editing.name, editing.config);
      toast("success", `Role ${editing.name} saved`);
      setEditing(null);
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onCreate = async () => {
    if (!newName.trim()) return;
    try {
      await api.sshWriteRole(mount, newName.trim(), newRole);
      toast("success", `Role ${newName} created`);
      setCreating(false);
      setNewName("");
      setNewRole(blankRole());
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onDelete = async (name: string) => {
    try {
      await api.sshDeleteRole(mount, name);
      toast("success", `Role ${name} deleted`);
      setConfirmDelete(null);
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  return (
    <>
      <Card>
        <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
          <h2 className="text-lg font-medium">Roles</h2>
          <Button onClick={() => setCreating(true)}>+ New role</Button>
        </div>
        {names.length === 0 ? (
          <EmptyState
            title="No roles configured"
            description="A role pins what kind of certificate (or OTP) the engine will issue: principals, extensions, TTL caps, and so on."
          />
        ) : (
          <Table
            columns={[
              {
                key: "name",
                header: "Name",
                render: (n: string) => <span className="font-mono text-sm">{n}</span>,
              },
              {
                key: "actions",
                header: "",
                render: (n: string) => (
                  <div className="flex gap-2 justify-end">
                    <Button variant="ghost" onClick={() => openEdit(n)}>
                      Edit
                    </Button>
                    <Button variant="danger" onClick={() => setConfirmDelete(n)}>
                      Delete
                    </Button>
                  </div>
                ),
              },
            ]}
            data={names}
            rowKey={(n) => n}
          />
        )}
      </Card>

      {editing && (
        <Modal open onClose={() => setEditing(null)} title={`Edit role: ${editing.name}`} size="lg">
          <RoleForm
            config={editing.config}
            onChange={(c) => setEditing({ ...editing, config: c })}
            onSave={onSave}
            onCancel={() => setEditing(null)}
          />
        </Modal>
      )}

      <Modal open={creating} onClose={() => setCreating(false)} title="New role" size="lg">
        <div className="space-y-3">
          <Input
            label="Role name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="e.g. devs"
          />
          <RoleForm
            config={newRole}
            onChange={setNewRole}
            onSave={onCreate}
            onCancel={() => setCreating(false)}
            saveLabel="Create"
          />
        </div>
      </Modal>

      <ConfirmModal
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && onDelete(confirmDelete)}
        title={`Delete role ${confirmDelete}?`}
        message="Existing certificates already issued under this role remain valid until their TTL expires; this only stops new ones."
        confirmLabel="Delete"
        variant="danger"
      />
    </>
  );
}

function RoleForm({
  config,
  onChange,
  onSave,
  onCancel,
  saveLabel = "Save",
}: {
  config: SshRoleConfig;
  onChange: (c: SshRoleConfig) => void;
  onSave: () => void;
  onCancel: () => void;
  saveLabel?: string;
}) {
  const set = <K extends keyof SshRoleConfig>(k: K, v: SshRoleConfig[K]) =>
    onChange({ ...config, [k]: v });
  const isOtp = config.key_type === "otp";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <Select
          label="Mode"
          value={config.key_type}
          onChange={(e) => set("key_type", e.target.value)}
          options={[
            { value: "ca", label: "CA (sign client certs)" },
            { value: "otp", label: "OTP (one-time passwords)" },
          ]}
        />
        {!isOtp && (
          <Select
            label="Cert type"
            value={config.cert_type}
            onChange={(e) => set("cert_type", e.target.value)}
            options={[
              { value: "user", label: "User" },
              { value: "host", label: "Host" },
            ]}
          />
        )}

        {!isOtp && (
          <>
            <Input
              label="Allowed users"
              value={config.allowed_users}
              onChange={(e) => set("allowed_users", e.target.value)}
              placeholder="alice,bob — or `*` for any"
              hint="Comma-separated principals the cert may declare. `*` allows any."
            />
            <Input
              label="Default user"
              value={config.default_user}
              onChange={(e) => set("default_user", e.target.value)}
              placeholder="alice"
              hint="Used when the caller omits valid_principals."
            />
            <Input
              label="Allowed extensions"
              value={config.allowed_extensions}
              onChange={(e) => set("allowed_extensions", e.target.value)}
              placeholder="permit-pty,permit-port-forwarding"
            />
            <Input
              label="Allowed critical options"
              value={config.allowed_critical_options}
              onChange={(e) => set("allowed_critical_options", e.target.value)}
              placeholder="force-command,source-address"
            />
          </>
        )}

        <Input
          label="TTL"
          value={config.ttl}
          onChange={(e) => set("ttl", e.target.value)}
          placeholder="30m"
        />
        <Input
          label="Max TTL"
          value={config.max_ttl}
          onChange={(e) => set("max_ttl", e.target.value)}
          placeholder="1h"
        />

        {!isOtp && (
          <>
            <Input
              label="Not-before backdate"
              value={config.not_before_duration}
              onChange={(e) => set("not_before_duration", e.target.value)}
              placeholder="30s"
              hint="Compensates for clock skew between BastionVault and target hosts."
            />
            <Input
              label="Key ID format"
              value={config.key_id_format}
              onChange={(e) => set("key_id_format", e.target.value)}
              placeholder="vault-{{role}}-{{token_display_name}}"
            />
          </>
        )}

        {isOtp && (
          <>
            <Input
              label="CIDR list"
              value={config.cidr_list}
              onChange={(e) => set("cidr_list", e.target.value)}
              placeholder="10.0.0.0/24"
              hint="Comma-separated CIDRs the OTP is valid for. Required for OTP roles."
            />
            <Input
              label="Exclude CIDR list"
              value={config.exclude_cidr_list}
              onChange={(e) => set("exclude_cidr_list", e.target.value)}
              placeholder="10.0.0.42/32"
            />
            <Input
              label="Default user"
              value={config.default_user}
              onChange={(e) => set("default_user", e.target.value)}
              placeholder="alice"
            />
            <Input
              label="Port"
              type="number"
              value={String(config.port)}
              onChange={(e) => set("port", Number(e.target.value) || 22)}
            />
          </>
        )}
      </div>

      {!isOtp && (
        <div className="flex items-center gap-2">
          <input
            id="pqc_only"
            type="checkbox"
            checked={config.pqc_only}
            onChange={(e) => set("pqc_only", e.target.checked)}
          />
          <label htmlFor="pqc_only" className="text-sm">
            PQC-only — reject classical client public keys (requires a PQC CA)
          </label>
        </div>
      )}

      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button onClick={onSave}>{saveLabel}</Button>
      </div>
    </div>
  );
}

// ── Sign Tab ──────────────────────────────────────────────────────

function SignTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [role, setRole] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [validPrincipals, setValidPrincipals] = useState("");
  const [ttl, setTtl] = useState("");
  const [keyId, setKeyId] = useState("");
  const [result, setResult] = useState<SshSignResult | null>(null);

  useEffect(() => {
    api.sshListRoles(mount).then(setRoles).catch(() => setRoles([]));
  }, [mount]);

  const onSign = async () => {
    if (!role || !publicKey.trim()) return;
    try {
      const r = await api.sshSign({
        mount,
        role,
        public_key: publicKey.trim(),
        valid_principals: validPrincipals || undefined,
        ttl: ttl || undefined,
        key_id: keyId || undefined,
      });
      setResult(r);
      toast("success", "Certificate signed");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  return (
    <Card>
      <div className="space-y-3">
        <h2 className="text-lg font-medium">Sign client public key</h2>
        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            options={[{ value: "", label: "— pick role —" }, ...roles.map((r) => ({ value: r, label: r }))]}
          />
          <Input
            label="Valid principals (optional)"
            value={validPrincipals}
            onChange={(e) => setValidPrincipals(e.target.value)}
            placeholder="alice,bob"
            hint="Falls back to role's default_user when empty."
          />
          <Input
            label="TTL (optional)"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="30m"
          />
          <Input
            label="Key ID (optional)"
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            placeholder="overrides role.key_id_format"
          />
        </div>
        <Textarea
          label="Client public key (OpenSSH format)"
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          rows={3}
          placeholder="ssh-ed25519 AAAA…  (or ssh-mldsa65@openssh.com … for PQC)"
        />
        <div className="flex justify-end">
          <Button onClick={onSign} disabled={!role || !publicKey.trim()}>
            Sign
          </Button>
        </div>

        {result && (
          <div className="space-y-2 border-t border-[var(--color-border)] pt-3">
            <div className="flex items-center gap-2">
              <Badge label={result.algorithm || "signed"} />
              <span className="text-xs text-[var(--color-text-muted)]">
                serial {result.serial_number}
              </span>
              <Button
                variant="ghost"
                onClick={() => navigator.clipboard.writeText(result.signed_key)}
              >
                Copy
              </Button>
            </div>
            <Textarea
              label="Signed certificate"
              value={result.signed_key}
              readOnly
              rows={5}
            />
            <p className="text-xs text-[var(--color-text-muted)]">
              Save as `id_&lt;key&gt;-cert.pub` next to the matching private
              key — `ssh` picks it up automatically.
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}

// ── OTP Creds Tab ─────────────────────────────────────────────────

function CredsTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [role, setRole] = useState("");
  const [ip, setIp] = useState("");
  const [username, setUsername] = useState("");
  const [ttl, setTtl] = useState("");
  const [result, setResult] = useState<SshCredsResult | null>(null);
  const [lookupRoles, setLookupRoles] = useState<string[] | null>(null);

  useEffect(() => {
    // List roles and (optimistically) drop CA-only roles client-side
    // by reading each — but that's an N-call; we accept a list with
    // both modes and let the server reject CA-mode roles if the user
    // picks one by mistake. Cheap and honest.
    api.sshListRoles(mount).then(setRoles).catch(() => setRoles([]));
  }, [mount]);

  const onMint = async () => {
    if (!role || !ip.trim()) return;
    try {
      const r = await api.sshCreds({
        mount,
        role,
        ip: ip.trim(),
        username: username || undefined,
        ttl: ttl || undefined,
      });
      setResult(r);
      toast("success", "OTP minted");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onLookup = async () => {
    if (!ip.trim()) return;
    try {
      const r = await api.sshLookup({
        mount,
        ip: ip.trim(),
        username: username || undefined,
      });
      setLookupRoles(r.roles);
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  return (
    <Card>
      <div className="space-y-3">
        <h2 className="text-lg font-medium">Mint OTP for SSH session</h2>
        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            options={[{ value: "", label: "— pick role —" }, ...roles.map((r) => ({ value: r, label: r }))]}
          />
          <Input
            label="Target IP"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="10.0.0.5"
          />
          <Input
            label="Username (optional)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="alice"
          />
          <Input
            label="TTL (optional)"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="2m"
          />
        </div>
        <div className="flex gap-2 justify-end">
          <Button variant="ghost" onClick={onLookup} disabled={!ip.trim()}>
            Which roles cover this?
          </Button>
          <Button onClick={onMint} disabled={!role || !ip.trim()}>
            Mint OTP
          </Button>
        </div>

        {lookupRoles !== null && (
          <div className="text-sm border-t border-[var(--color-border)] pt-3">
            <span className="text-[var(--color-text-muted)]">Matching roles: </span>
            {lookupRoles.length === 0 ? (
              <span className="italic">none</span>
            ) : (
              <span className="font-mono">{lookupRoles.join(", ")}</span>
            )}
          </div>
        )}

        {result && (
          <div className="space-y-2 border-t border-[var(--color-border)] pt-3">
            <div className="flex items-center gap-2">
              <Badge label={result.key_type} />
              <span className="text-xs text-[var(--color-text-muted)]">
                {result.username}@{result.ip}:{result.port} · TTL {result.ttl}s
              </span>
              <Button
                variant="ghost"
                onClick={() => navigator.clipboard.writeText(result.key)}
              >
                Copy OTP
              </Button>
            </div>
            <Input label="One-time password" value={result.key} readOnly />
            <p className="text-xs text-[var(--color-text-muted)]">
              Paste this when prompted by `ssh {result.username}@{result.ip}` on a
              host running `bv-ssh-helper`. Single-use; expires in {result.ttl}s.
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}
