import { useState, useEffect, useCallback, useMemo } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Tabs,
  Modal,
  ConfirmModal,
  EmptyState,
  Badge,
  MaskedValue,
  useToast,
} from "../components/ui";
import type {
  LdapMountInfo,
  LdapConfigInfo,
  LdapStaticCred,
  LdapLibraryStatus,
  LdapCheckOutResult,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "connection" | "static-roles" | "library";

export function LdapPage() {
  const { toast } = useToast();
  const [mounts, setMounts] = useState<LdapMountInfo[]>([]);
  const [activeMount, setActiveMount] = useState<string>("");
  const [tab, setTab] = useState<TabId>("connection");
  const [showEnable, setShowEnable] = useState(false);
  const [enablePath, setEnablePath] = useState("openldap");

  const refreshMounts = useCallback(async () => {
    try {
      const list = await api.ldapListMounts();
      setMounts(list);
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
      await api.ldapEnableMount(enablePath);
      toast("success", `Mounted OpenLDAP engine at ${enablePath}`);
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
          <h1 className="text-xl font-semibold">OpenLDAP / AD</h1>
          <Button onClick={() => setShowEnable(true)}>+ Mount OpenLDAP engine</Button>
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
              title="No OpenLDAP engine mounted"
              description="Mount the OpenLDAP engine on a path (typically `openldap/`) to manage directory password rotation."
              action={
                <Button onClick={() => setShowEnable(true)}>Mount OpenLDAP engine</Button>
              }
            />
          </Card>
        ) : (
          <>
            <Card>
              <Tabs
                tabs={[
                  { id: "connection", label: "Connection" },
                  { id: "static-roles", label: "Static Roles" },
                  { id: "library", label: "Library" },
                ]}
                active={tab}
                onChange={(t) => setTab(t as TabId)}
              />
            </Card>

            {tab === "connection" && <ConnectionTab mount={activeMount} />}
            {tab === "static-roles" && <StaticRolesTab mount={activeMount} />}
            {tab === "library" && <LibraryTab mount={activeMount} />}
          </>
        )}

        <Modal
          open={showEnable}
          onClose={() => setShowEnable(false)}
          title="Mount OpenLDAP engine"
          size="sm"
        >
          <div className="space-y-3">
            <Input
              label="Mount path"
              value={enablePath}
              onChange={(e) => setEnablePath(e.target.value)}
              placeholder="openldap"
              hint="Typically `openldap`. Operators with multiple environments can mount at custom paths like `openldap-prod`."
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

// ── Connection tab ────────────────────────────────────────────────

function ConnectionTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<LdapConfigInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [showEdit, setShowEdit] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmRotateRoot, setConfirmRotateRoot] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<api.LdapCheckConnectionResult | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setCfg(await api.ldapReadConfig(mount));
    } catch {
      // Config-not-set surfaces as null on most paths but errors on
      // some — treat both as the empty state.
      setCfg(null);
    } finally {
      setLoading(false);
    }
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onDelete = async () => {
    try {
      await api.ldapDeleteConfig(mount);
      setCfg(null);
      setConfirmDelete(false);
      toast("success", "Connection deleted");
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onTestConnection = async () => {
    setChecking(true);
    setCheckResult(null);
    try {
      const r = await api.ldapCheckConnection(mount);
      setCheckResult(r);
      if (r.ok) {
        toast("success", `Connection OK (${r.latency_ms} ms)`);
      } else {
        toast("error", r.error || "Connection failed");
      }
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setChecking(false);
    }
  };

  const onRotateRoot = async () => {
    try {
      await api.ldapRotateRoot(mount);
      setConfirmRotateRoot(false);
      toast("success", "Bind password rotated");
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading connection…</p>
      </Card>
    );
  }

  return (
    <>
      <Card>
        {cfg && cfg.url ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-medium">Connection configured</h2>
                <Badge label={cfg.directory_type || "openldap"} />
                {cfg.starttls && <Badge label="StartTLS" />}
                {cfg.insecure_tls && <Badge label="insecure_tls" variant="warning" />}
              </div>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={() => setShowEdit(true)}>
                  Edit
                </Button>
                <Button variant="ghost" onClick={onTestConnection} disabled={checking}>
                  {checking ? "Testing…" : "Test connection"}
                </Button>
                <Button onClick={() => setConfirmRotateRoot(true)}>
                  Rotate bind password
                </Button>
                <Button variant="danger" onClick={() => setConfirmDelete(true)}>
                  Delete config
                </Button>
              </div>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              <dt className="text-[var(--color-text-muted)]">URL</dt>
              <dd className="font-mono min-w-0 truncate">{cfg.url}</dd>
              <dt className="text-[var(--color-text-muted)]">Bind DN</dt>
              <dd className="font-mono min-w-0 truncate">{cfg.binddn}</dd>
              <dt className="text-[var(--color-text-muted)]">User search base</dt>
              <dd className="font-mono min-w-0 truncate">{cfg.userdn || "—"}</dd>
              <dt className="text-[var(--color-text-muted)]">User attribute</dt>
              <dd className="font-mono">{cfg.userattr}</dd>
              <dt className="text-[var(--color-text-muted)]">Request timeout</dt>
              <dd>{cfg.request_timeout}s</dd>
              <dt className="text-[var(--color-text-muted)]">TLS min version</dt>
              <dd>{cfg.tls_min_version}</dd>
            </dl>
            <p className="text-xs text-[var(--color-text-muted)]">
              `bindpass` is barrier-encrypted at rest and never re-disclosed.
              Use <strong>Rotate bind password</strong> to mint a fresh value
              for the engine's own service account.
            </p>
            {checkResult && (
              <div
                className={
                  "rounded border px-3 py-2 text-sm " +
                  (checkResult.ok
                    ? "border-green-700 bg-green-950/40 text-green-200"
                    : "border-red-700 bg-red-950/40 text-red-200")
                }
              >
                {checkResult.ok ? (
                  <span>
                    <strong>Connection OK</strong> — bound as{" "}
                    <span className="font-mono">{checkResult.binddn}</span> in{" "}
                    {checkResult.latency_ms} ms.
                  </span>
                ) : (
                  <span>
                    <strong>Connection failed</strong> ({checkResult.latency_ms} ms):{" "}
                    <span className="font-mono break-all">{checkResult.error}</span>
                  </span>
                )}
              </div>
            )}
          </div>
        ) : (
          <EmptyState
            title="No connection configured"
            description="Configure the directory connection. TLS is required by default — either `ldaps://` or `ldap://` with StartTLS."
            action={<Button onClick={() => setShowEdit(true)}>Configure connection</Button>}
          />
        )}
      </Card>

      {showEdit && (
        <ConnectionModal
          mount={mount}
          existing={cfg}
          onClose={() => setShowEdit(false)}
          onSaved={() => {
            setShowEdit(false);
            refresh();
          }}
        />
      )}

      <ConfirmModal
        open={confirmDelete}
        title="Delete connection config"
        message="This drops the engine's directory connection. Static-role rotations and library check-outs will fail until the connection is reconfigured. Persisted role + library data is preserved."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={onDelete}
        onClose={() => setConfirmDelete(false)}
      />

      <ConfirmModal
        open={confirmRotateRoot}
        title="Rotate bind password"
        message="Generate a fresh password, write it to the directory under the bind DN, and persist as the engine's bind password. Use this on a schedule to rotate the engine's own service account."
        confirmLabel="Rotate"
        onConfirm={onRotateRoot}
        onClose={() => setConfirmRotateRoot(false)}
      />
    </>
  );
}

function ConnectionModal({
  mount,
  existing,
  onClose,
  onSaved,
}: {
  mount: string;
  existing: LdapConfigInfo | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [url, setUrl] = useState(existing?.url ?? "ldaps://");
  const [binddn, setBinddn] = useState(existing?.binddn ?? "");
  const [bindpass, setBindpass] = useState("");
  const [userdn, setUserdn] = useState(existing?.userdn ?? "");
  const [directoryType, setDirectoryType] = useState(
    existing?.directory_type || "openldap",
  );
  const [requestTimeout, setRequestTimeout] = useState(existing?.request_timeout ?? 10);
  const [starttls, setStarttls] = useState(existing?.starttls ?? false);
  const [tlsMinVersion, setTlsMinVersion] = useState(existing?.tls_min_version || "tls12");
  const [insecureTls, setInsecureTls] = useState(existing?.insecure_tls ?? false);
  const [acknowledgeInsecure, setAcknowledgeInsecure] = useState(false);
  const [userattr, setUserattr] = useState(existing?.userattr || "cn");
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async () => {
    if (!url.trim() || !binddn.trim()) {
      toast("error", "URL and Bind DN are required");
      return;
    }
    if (!existing && !bindpass) {
      toast("error", "Bind password is required for the initial config");
      return;
    }
    setSubmitting(true);
    try {
      await api.ldapWriteConfig({
        mount,
        url: url.trim(),
        binddn: binddn.trim(),
        bindpass: bindpass || undefined,
        userdn: userdn.trim() || undefined,
        directory_type: directoryType,
        request_timeout: requestTimeout,
        starttls,
        tls_min_version: tlsMinVersion,
        insecure_tls: insecureTls,
        acknowledge_insecure_tls: insecureTls ? acknowledgeInsecure : undefined,
        userattr: userattr.trim() || undefined,
      });
      toast("success", "Connection saved");
      onSaved();
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal open={true} onClose={onClose} title="Configure connection" size="lg">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="ldaps://dc01.corp.example.com:636"
          />
          <Select
            label="Directory type"
            value={directoryType}
            onChange={(e) => setDirectoryType(e.target.value)}
            options={[
              { value: "openldap", label: "OpenLDAP" },
              { value: "active_directory", label: "Active Directory" },
            ]}
          />
          <Input
            label="Bind DN"
            value={binddn}
            onChange={(e) => setBinddn(e.target.value)}
            placeholder="CN=admin,DC=corp,DC=example,DC=com"
          />
          <Input
            label={existing ? "Bind password (leave empty to keep)" : "Bind password"}
            type="password"
            value={bindpass}
            onChange={(e) => setBindpass(e.target.value)}
          />
          <Input
            label="User DN (search base)"
            value={userdn}
            onChange={(e) => setUserdn(e.target.value)}
            placeholder="OU=Service Accounts,DC=corp,DC=example,DC=com"
          />
          <Input
            label="User attribute"
            value={userattr}
            onChange={(e) => setUserattr(e.target.value)}
            hint="`cn` / `uid` for OpenLDAP, `samAccountName` for AD."
          />
          <Input
            label="Request timeout (s)"
            type="number"
            value={String(requestTimeout)}
            onChange={(e) => setRequestTimeout(Number(e.target.value) || 10)}
          />
          <Select
            label="TLS min version"
            value={tlsMinVersion}
            onChange={(e) => setTlsMinVersion(e.target.value)}
            options={[
              { value: "tls12", label: "TLS 1.2" },
              { value: "tls13", label: "TLS 1.3" },
            ]}
          />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={starttls}
            onChange={(e) => setStarttls(e.target.checked)}
          />
          StartTLS (required for plain `ldap://` URLs)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={insecureTls}
            onChange={(e) => setInsecureTls(e.target.checked)}
          />
          insecure_tls — disable certificate validation
        </label>
        {insecureTls && (
          <label className="flex items-start gap-2 text-sm pl-6">
            <input
              type="checkbox"
              checked={acknowledgeInsecure}
              onChange={(e) => setAcknowledgeInsecure(e.target.checked)}
            />
            <span className="text-[var(--color-warning)]">
              I acknowledge that disabling certificate validation removes a
              load-bearing security guarantee. Use only for self-signed dev DCs.
            </span>
          </label>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={submitting}>
            {submitting ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ── Static roles tab ──────────────────────────────────────────────

function StaticRolesTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [names, setNames] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [credModal, setCredModal] = useState<{
    name: string;
    cred: LdapStaticCred;
  } | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setNames(await api.ldapListStaticRoles(mount));
    } catch {
      setNames([]);
    } finally {
      setLoading(false);
    }
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onShowCred = async (name: string) => {
    try {
      const cred = await api.ldapReadStaticCred(mount, name);
      setCredModal({ name, cred });
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onRotate = async (name: string) => {
    try {
      const r = await api.ldapRotateRole(mount, name);
      toast("success", `Rotated ${name}`);
      setCredModal({
        name,
        cred: {
          username: r.username,
          dn: r.dn,
          password: r.password,
          last_vault_rotation_unix: r.last_vault_rotation_unix,
          ttl_secs: null,
        },
      });
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onDelete = async (name: string) => {
    try {
      await api.ldapDeleteStaticRole(mount, name);
      toast("success", `Deleted ${name}`);
      setConfirmDelete(null);
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading roles…</p>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
          <h2 className="text-lg font-medium">Static roles</h2>
          <Button onClick={() => setShowCreate(true)}>+ Create role</Button>
        </div>
        {names.length === 0 ? (
          <EmptyState
            title="No static roles"
            description="Create a role pinning a single DN to a rotation cadence. The engine writes a fresh password to the directory and serves it on `static-cred` reads."
            action={<Button onClick={() => setShowCreate(true)}>Create role</Button>}
          />
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {names.map((name) => (
              <li
                key={name}
                className="py-2 flex items-center justify-between gap-2 flex-wrap"
              >
                <span className="font-mono text-sm">{name}</span>
                <div className="flex gap-2">
                  <Button variant="ghost" onClick={() => onShowCred(name)}>
                    Read password
                  </Button>
                  <Button onClick={() => onRotate(name)}>Rotate now</Button>
                  <Button variant="danger" onClick={() => setConfirmDelete(name)}>
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {showCreate && (
        <RoleEditModal
          mount={mount}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            setShowCreate(false);
            refresh();
          }}
        />
      )}

      {credModal && (
        <CredViewModal
          name={credModal.name}
          cred={credModal.cred}
          onClose={() => setCredModal(null)}
        />
      )}

      <ConfirmModal
        open={!!confirmDelete}
        title="Delete static role"
        message={
          confirmDelete
            ? `Delete \`${confirmDelete}\`? The cached password is dropped; the directory's password is left as-is. Re-create the role + rotate to mint a new value.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => confirmDelete && onDelete(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
      />
    </>
  );
}

function RoleEditModal({
  mount,
  onClose,
  onSaved,
}: {
  mount: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [dn, setDn] = useState("");
  const [username, setUsername] = useState("");
  const [rotationPeriod, setRotationPeriod] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async () => {
    if (!name.trim() || !dn.trim() || !username.trim()) {
      toast("error", "Name, DN, and username are required");
      return;
    }
    setSubmitting(true);
    try {
      await api.ldapWriteStaticRole(mount, name.trim(), {
        dn: dn.trim(),
        username: username.trim(),
        rotation_period: rotationPeriod,
        password_policy: "",
      });
      toast("success", `Role ${name} saved`);
      onSaved();
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal open={true} onClose={onClose} title="Create static role" size="md">
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="svc-jenkins"
          />
          <Input
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="svc_jenkins"
            hint="Short login name. Surfaced in `static-cred` and audit."
          />
          <Input
            label="DN"
            value={dn}
            onChange={(e) => setDn(e.target.value)}
            placeholder="CN=svc_jenkins,OU=Service Accounts,DC=corp,DC=example,DC=com"
            className="col-span-2"
          />
          <Input
            label="Rotation period (s)"
            type="number"
            value={String(rotationPeriod)}
            onChange={(e) => setRotationPeriod(Number(e.target.value) || 0)}
            hint="0 = manual rotation only. Non-zero hands off to the auto-rotation scheduler (60s tick)."
          />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={submitting}>
            {submitting ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function CredViewModal({
  name,
  cred,
  onClose,
}: {
  name: string;
  cred: LdapStaticCred;
  onClose: () => void;
}) {
  const lastRotated = cred.last_vault_rotation_unix
    ? new Date(cred.last_vault_rotation_unix * 1000).toLocaleString()
    : "—";
  return (
    <Modal open={true} onClose={onClose} title={`Credential: ${name}`} size="md">
      <div className="space-y-3">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          <dt className="text-[var(--color-text-muted)]">Username</dt>
          <dd className="font-mono">{cred.username}</dd>
          <dt className="text-[var(--color-text-muted)]">DN</dt>
          <dd className="font-mono min-w-0 truncate">{cred.dn}</dd>
          <dt className="text-[var(--color-text-muted)]">Last rotated</dt>
          <dd>{lastRotated}</dd>
          {cred.ttl_secs !== null && cred.ttl_secs !== undefined && (
            <>
              <dt className="text-[var(--color-text-muted)]">Next auto-rotation</dt>
              <dd>{cred.ttl_secs > 0 ? `in ${cred.ttl_secs}s` : "due now"}</dd>
            </>
          )}
        </dl>
        <div>
          <label className="text-sm font-medium">Password</label>
          <MaskedValue value={cred.password} />
        </div>
        <div className="flex justify-end">
          <Button onClick={onClose}>Close</Button>
        </div>
      </div>
    </Modal>
  );
}

// ── Library tab ───────────────────────────────────────────────────

function LibraryTab({ mount }: { mount: string }) {
  const { toast } = useToast();
  const [sets, setSets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedSet, setSelectedSet] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [checkOutResult, setCheckOutResult] = useState<LdapCheckOutResult | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setSets(await api.ldapListLibraries(mount));
    } catch {
      setSets([]);
    } finally {
      setLoading(false);
    }
  }, [mount]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onCheckOut = async (set: string) => {
    try {
      const r = await api.ldapCheckOut(mount, set);
      setCheckOutResult(r);
      toast("success", `Checked out ${r.service_account_name}`);
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  const onDelete = async (set: string) => {
    try {
      await api.ldapDeleteLibrary(mount, set);
      toast("success", `Deleted library ${set}`);
      setConfirmDelete(null);
      if (selectedSet === set) setSelectedSet(null);
      await refresh();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading libraries…</p>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
          <h2 className="text-lg font-medium">Libraries</h2>
          <Button onClick={() => setShowCreate(true)}>+ Create set</Button>
        </div>
        {sets.length === 0 ? (
          <EmptyState
            title="No library sets"
            description="A library is a pool of pre-provisioned accounts. Check-out leases an account and rotates its password; check-in rotates again and releases."
            action={<Button onClick={() => setShowCreate(true)}>Create set</Button>}
          />
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {sets.map((set) => (
              <li
                key={set}
                className="py-2 flex items-center justify-between gap-2 flex-wrap"
              >
                <span className="font-mono text-sm">{set}</span>
                <div className="flex gap-2">
                  <Button variant="ghost" onClick={() => setSelectedSet(set)}>
                    Status
                  </Button>
                  <Button onClick={() => onCheckOut(set)}>Check out</Button>
                  <Button variant="danger" onClick={() => setConfirmDelete(set)}>
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {selectedSet && (
        <LibraryStatusCard
          mount={mount}
          set={selectedSet}
          onClose={() => setSelectedSet(null)}
          onChange={refresh}
        />
      )}

      {showCreate && (
        <LibraryEditModal
          mount={mount}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            setShowCreate(false);
            refresh();
          }}
        />
      )}

      {checkOutResult && (
        <Modal
          open={true}
          onClose={() => setCheckOutResult(null)}
          title={`Checked out: ${checkOutResult.service_account_name}`}
          size="md"
        >
          <div className="space-y-3">
            <p className="text-xs text-[var(--color-text-muted)]">
              The password is shown once. Lease ID is the handle the engine
              uses for revocation; pass it to <code>check-in</code> when done.
            </p>
            <div>
              <label className="text-sm font-medium">Password</label>
              <MaskedValue value={checkOutResult.password} />
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              <dt className="text-[var(--color-text-muted)]">Lease ID</dt>
              <dd className="font-mono min-w-0 truncate">
                {checkOutResult.lease_id}
              </dd>
              <dt className="text-[var(--color-text-muted)]">TTL</dt>
              <dd>{checkOutResult.ttl_secs}s</dd>
            </dl>
            <div className="flex justify-end">
              <Button onClick={() => setCheckOutResult(null)}>Close</Button>
            </div>
          </div>
        </Modal>
      )}

      <ConfirmModal
        open={!!confirmDelete}
        title="Delete library set"
        message={
          confirmDelete
            ? `Delete library set \`${confirmDelete}\`? Any in-flight check-outs are cleared. The accounts' passwords in the directory are left as-is.`
            : ""
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => confirmDelete && onDelete(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
      />
    </>
  );
}

function LibraryStatusCard({
  mount,
  set,
  onClose,
  onChange,
}: {
  mount: string;
  set: string;
  onClose: () => void;
  onChange: () => void;
}) {
  const { toast } = useToast();
  const [status, setStatus] = useState<LdapLibraryStatus | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.ldapLibraryStatus(mount, set));
    } catch (err) {
      toast("error", extractError(err));
    }
  }, [mount, set, toast]);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 5000);
    return () => window.clearInterval(id);
  }, [refresh]);

  const onCheckIn = async (account: string) => {
    try {
      await api.ldapCheckIn(mount, set, account);
      toast("success", `Checked in ${account}`);
      await refresh();
      onChange();
    } catch (err) {
      toast("error", extractError(err));
    }
  };

  if (!status) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading status…</p>
      </Card>
    );
  }

  return (
    <Card>
      <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
        <h3 className="font-medium">Status — {set}</h3>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={refresh}>
            Refresh
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
      <div className="space-y-3">
        <div>
          <h4 className="text-sm text-[var(--color-text-muted)]">
            Checked out ({status.checked_out.length})
          </h4>
          {status.checked_out.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">None.</p>
          ) : (
            <ul className="divide-y divide-[var(--color-border)]/40">
              {status.checked_out.map((e) => (
                <li
                  key={e.account}
                  className="py-2 flex items-center justify-between gap-2 flex-wrap"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-sm truncate">{e.account}</div>
                    <div className="text-xs text-[var(--color-text-muted)] truncate">
                      Lease {e.lease_id} · expires{" "}
                      {new Date(e.expires_at_unix * 1000).toLocaleString()}
                    </div>
                  </div>
                  <Button onClick={() => onCheckIn(e.account)}>Check in</Button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h4 className="text-sm text-[var(--color-text-muted)]">
            Available ({status.available.length})
          </h4>
          {status.available.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">
              All accounts are checked out.
            </p>
          ) : (
            <ul className="text-sm font-mono">
              {status.available.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}

function LibraryEditModal({
  mount,
  onClose,
  onSaved,
}: {
  mount: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [accountsRaw, setAccountsRaw] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [maxTtl, setMaxTtl] = useState(86400);
  const [disableEnforcement, setDisableEnforcement] = useState(false);
  const [affinityTtl, setAffinityTtl] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async () => {
    if (!name.trim() || !accountsRaw.trim()) {
      toast("error", "Name and at least one account are required");
      return;
    }
    const accounts = accountsRaw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (accounts.length === 0) {
      toast("error", "At least one account is required");
      return;
    }
    if (maxTtl < ttl) {
      toast("error", "max_ttl must be >= ttl");
      return;
    }
    setSubmitting(true);
    try {
      await api.ldapWriteLibrary(mount, name.trim(), {
        service_account_names: accounts,
        ttl,
        max_ttl: maxTtl,
        disable_check_in_enforcement: disableEnforcement,
        affinity_ttl: affinityTtl,
      });
      toast("success", `Library ${name} saved`);
      onSaved();
    } catch (err) {
      toast("error", extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal open={true} onClose={onClose} title="Create library set" size="lg">
      <div className="space-y-3">
        <Input
          label="Set name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="warehouse-etl"
        />
        <div>
          <label className="text-sm font-medium">Service account DNs</label>
          <textarea
            className="mt-1 w-full rounded border border-[var(--color-border)] bg-transparent p-2 font-mono text-xs"
            rows={4}
            value={accountsRaw}
            onChange={(e) => setAccountsRaw(e.target.value)}
            placeholder="CN=svc_etl_a,OU=...&#10;CN=svc_etl_b,OU=..."
          />
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            One DN per line, or comma-separated.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="TTL (s)"
            type="number"
            value={String(ttl)}
            onChange={(e) => setTtl(Number(e.target.value) || 3600)}
            hint="Default check-out duration."
          />
          <Input
            label="Max TTL (s)"
            type="number"
            value={String(maxTtl)}
            onChange={(e) => setMaxTtl(Number(e.target.value) || 86400)}
          />
          <Input
            label="Affinity TTL (s)"
            type="number"
            value={String(affinityTtl)}
            onChange={(e) => setAffinityTtl(Number(e.target.value) || 0)}
            hint="0 = off. When set, the same entity checking out within this many seconds of its last check-in gets the same account back (still freshly rotated)."
          />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={disableEnforcement}
            onChange={(e) => setDisableEnforcement(e.target.checked)}
          />
          Disable check-in identity enforcement (any caller can check in)
        </label>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={submitting}>
            {submitting ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
