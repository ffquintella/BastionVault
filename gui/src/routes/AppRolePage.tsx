import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  PolicySelect,
  useToast,
} from "../components/ui";
import type { AppRoleInfo, SecretIdAccessorInfo, FerroGateMachine, MachineBinding } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { useEntityDirectoryStore } from "../stores/entityDirectoryStore";

export function AppRolePage() {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountEnabled, setMountEnabled] = useState<boolean | null>(null);
  const [enabling, setEnabling] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [roleInfo, setRoleInfo] = useState<AppRoleInfo | null>(null);
  const [roleId, setRoleId] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // Create form
  const [newName, setNewName] = useState("");
  const [newPolicies, setNewPolicies] = useState<string[]>([]);
  const [newBindSecretId, setNewBindSecretId] = useState(true);
  // Namespace login-restriction (empty ⇒ unrestricted). Hidden single-tenant.
  const [newNamespaces, setNewNamespaces] = useState<string[]>([]);
  const [availableNamespaces, setAvailableNamespaces] = useState<string[]>([]);

  // Known policy names for the create-modal autocomplete. When the list can't be
  // fetched (caller lacks admin on the policies path) the selector degrades to a
  // free-text field rather than locking the operator out.
  const [availablePolicies, setAvailablePolicies] = useState<string[]>([]);
  const [policiesListable, setPoliciesListable] = useState(true);

  useEffect(() => {
    loadRoles();
    loadPolicies();
    loadNamespaces();
  }, []);

  async function loadNamespaces() {
    try {
      const result = await api.listNamespaces();
      setAvailableNamespaces(result.namespaces);
    } catch {
      setAvailableNamespaces([]);
    }
  }

  async function loadPolicies() {
    try {
      const pol = await api.listPolicies();
      setAvailablePolicies(pol.policies);
      setPoliciesListable(true);
    } catch {
      setAvailablePolicies([]);
      setPoliciesListable(false);
    }
  }

  async function loadRoles() {
    setLoading(true);
    try {
      const methods = await api.listAuthMethods().catch(() => []);
      const enabled = methods.some((m) => m.mount_type === "approle");
      setMountEnabled(enabled);
      if (!enabled) {
        setRoles([]);
        return;
      }
      const result = await api.listAppRoles();
      setRoles(result.roles);
    } catch {
      setRoles([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleEnableMount() {
    setEnabling(true);
    try {
      await api.enableAuthMethod("approle/", "approle", "AppID auth method");
      toast("success", "AppID auth method enabled");
      await loadRoles();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setEnabling(false);
    }
  }

  async function selectRole(name: string) {
    try {
      const [info, rid] = await Promise.all([
        api.readAppRole(name),
        api.readRoleId(name),
      ]);
      setSelected(name);
      setRoleInfo(info);
      setRoleId(rid.role_id);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newName) return;
    try {
      await api.writeAppRole(newName, newBindSecretId, newPolicies.join(","), 0, "", "", "");
      // Persist the namespace login-restriction (empty ⇒ unrestricted).
      await api.setNsAssignment("approle/", newName, newNamespaces);
      toast("success", `ID ${newName} created`);
      setShowCreate(false);
      setNewName("");
      setNewPolicies([]);
      setNewNamespaces([]);
      loadRoles();
      selectRole(newName);
      // approle write_role pre-provisions an entity alias on first
      // create — refresh the share-picker cache so the new role
      // shows up immediately.
      useEntityDirectoryStore.getState().refresh().catch(() => {});
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteAppRole(deleteTarget);
      toast("success", `ID ${deleteTarget} deleted`);
      if (selected === deleteTarget) {
        setSelected(null);
        setRoleInfo(null);
      }
      setDeleteTarget(null);
      loadRoles();
      // Drop the deleted role from the picker cache.
      useEntityDirectoryStore.getState().refresh().catch(() => {});
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    toast("success", `${label} copied to clipboard`);
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">AppID</h1>
          {mountEnabled && (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              Create ID
            </Button>
          )}
        </div>

        {mountEnabled === false && !loading && (
          <Card>
            <EmptyState
              title="AppID auth method not enabled"
              description="The AppID auth backend must be mounted before you can create IDs."
              action={
                <Button onClick={handleEnableMount} disabled={enabling}>
                  {enabling ? "Enabling..." : "Enable AppID"}
                </Button>
              }
            />
          </Card>
        )}

        {mountEnabled && (
        <div className="flex gap-4">
          {/* ID list */}
          <Card className="w-56 shrink-0" title="IDs">
            {loading ? (
              <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
            ) : roles.length === 0 ? (
              <EmptyState title="No IDs" />
            ) : (
              <div className="space-y-0.5 -mx-1">
                {roles.map((name) => (
                  <div key={name} className="flex items-center group">
                    <button
                      onClick={() => selectRole(name)}
                      className={`flex-1 text-left px-3 py-1.5 rounded text-sm transition-colors ${
                        selected === name
                          ? "bg-[var(--color-primary)] text-white"
                          : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                      }`}
                    >
                      {name}
                    </button>
                    <button
                      onClick={() => setDeleteTarget(name)}
                      className="opacity-0 group-hover:opacity-100 px-1 text-[var(--color-danger)] text-xs transition-opacity"
                    >
                      &times;
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* ID detail */}
          <div className="flex-1 space-y-4">
            {selected && roleInfo ? (
              <RoleDetail
                roleInfo={roleInfo}
                roleId={roleId}
                availablePolicies={availablePolicies}
                policiesListable={policiesListable}
                availableNamespaces={availableNamespaces}
                onCopy={copyToClipboard}
                onRefresh={() => selectRole(roleInfo.name)}
                toast={toast}
              />
            ) : (
              <Card>
                <EmptyState
                  title="No ID selected"
                  description="Select an ID from the list to view details"
                />
              </Card>
            )}
          </div>
        </div>
        )}

        {/* Create ID modal */}
        <Modal
          open={showCreate}
          onClose={() => setShowCreate(false)}
          title="Create AppID"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!newName}>
                Create
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="ID Name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="my-app"
            />
            <PolicySelect
              label="Token Policies"
              selected={newPolicies}
              options={availablePolicies}
              onChange={setNewPolicies}
              fallbackFreeText={!policiesListable}
              placeholder="type to search policies…"
              helpText="Only existing policies can be selected"
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={newBindSecretId}
                onChange={(e) => setNewBindSecretId(e.target.checked)}
                className="rounded"
              />
              <span className="text-[var(--color-text-muted)]">
                Require Secret ID for login
              </span>
            </label>
            {availableNamespaces.length > 0 && (
              <div>
                <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                  Allowed namespaces
                </label>
                <div className="flex flex-wrap gap-2">
                  {["", ...availableNamespaces].map((ns) => {
                    const sel = newNamespaces.includes(ns);
                    return (
                      <button
                        key={ns || "__root__"}
                        type="button"
                        onClick={() =>
                          setNewNamespaces((prev) =>
                            prev.includes(ns) ? prev.filter((p) => p !== ns) : [...prev, ns],
                          )
                        }
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          sel
                            ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                            : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                        }`}
                      >
                        {ns === "" ? "root" : ns}
                      </button>
                    );
                  })}
                </div>
                <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
                  {newNamespaces.length === 0
                    ? "No restriction — this ID may log in to any namespace."
                    : `Login restricted to: ${newNamespaces.map((n) => n || "root").join(", ")} (and descendants).`}
                </p>
              </div>
            )}
          </div>
        </Modal>

        <ConfirmModal
          open={deleteTarget !== null}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete ID"
          message={`Are you sure you want to delete ID "${deleteTarget}"? All associated secret IDs will be invalidated.`}
          confirmLabel="Delete"
        />
      </div>
    </Layout>
  );
}

// ── Role Detail Component ──────────────────────────────────────────

interface RoleDetailProps {
  roleInfo: AppRoleInfo;
  roleId: string;
  availablePolicies: string[];
  policiesListable: boolean;
  availableNamespaces: string[];
  onCopy: (text: string, label: string) => void;
  onRefresh: () => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}

function RoleDetail({
  roleInfo,
  roleId,
  availablePolicies,
  policiesListable,
  availableNamespaces,
  onCopy,
  onRefresh,
  toast,
}: RoleDetailProps) {
  const [tab, setTab] = useState("overview");
  const [showEdit, setShowEdit] = useState(false);
  const noMachines = roleInfo.bound_machines.length === 0;

  return (
    <>
      {noMachines && (
        <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
          This ID has no bound machines. AppID logins require a FerroGate machine token bound to
          the ID — until a machine is bound under the <strong>Machines</strong> tab, no client can
          authenticate with this ID.
        </div>
      )}
      <Card title={`ID: ${roleInfo.name}`}>
        <Tabs
          tabs={[
            { id: "overview", label: "Overview" },
            { id: "machines", label: `Machines (${roleInfo.bound_machines.length})` },
            { id: "secret-ids", label: "Secret IDs" },
          ]}
          active={tab}
          onChange={setTab}
        />
      </Card>

      {tab === "overview" && (
        <Card
          title="Overview"
          actions={
            <Button size="sm" variant="secondary" onClick={() => setShowEdit(true)}>
              Edit
            </Button>
          }
        >
          <div className="space-y-4">
            {/* App ID */}
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                App ID
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono truncate">
                  {roleId}
                </code>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onCopy(roleId, "App ID")}
                >
                  Copy
                </Button>
              </div>
            </div>

            {/* Config grid */}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <ConfigRow label="Bind Secret ID" value={roleInfo.bind_secret_id ? "Yes" : "No"} />
              <ConfigRow label="Secret ID Uses" value={roleInfo.secret_id_num_uses === 0 ? "Unlimited" : String(roleInfo.secret_id_num_uses)} />
              <ConfigRow label="Secret ID TTL" value={roleInfo.secret_id_ttl === 0 ? "System default" : `${roleInfo.secret_id_ttl}s`} />
              <ConfigRow label="Token TTL" value={roleInfo.token_ttl === 0 ? "System default" : `${roleInfo.token_ttl}s`} />
              <ConfigRow label="Token Max TTL" value={roleInfo.token_max_ttl === 0 ? "System default" : `${roleInfo.token_max_ttl}s`} />
              <ConfigRow label="Token Uses" value={roleInfo.token_num_uses === 0 ? "Unlimited" : String(roleInfo.token_num_uses)} />
            </div>

            {/* Policies */}
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                Token Policies
              </label>
              <div className="flex flex-wrap gap-1">
                {roleInfo.token_policies.length > 0 ? (
                  roleInfo.token_policies.map((p) => (
                    <Badge key={p} label={p} variant="info" />
                  ))
                ) : (
                  <span className="text-sm text-[var(--color-text-muted)]">None</span>
                )}
              </div>
            </div>

            {/* CIDRs */}
            {roleInfo.secret_id_bound_cidrs.length > 0 && (
              <div>
                <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                  Secret ID Bound CIDRs
                </label>
                <div className="flex flex-wrap gap-1">
                  {roleInfo.secret_id_bound_cidrs.map((c) => (
                    <Badge key={c} label={c} variant="neutral" />
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {tab === "machines" && (
        <MachinesPanel roleInfo={roleInfo} onRefresh={onRefresh} toast={toast} />
      )}

      {tab === "secret-ids" && (
        <SecretIdPanel roleName={roleInfo.name} onCopy={onCopy} toast={toast} />
      )}

      <EditRoleModal
        open={showEdit}
        roleInfo={roleInfo}
        availablePolicies={availablePolicies}
        policiesListable={policiesListable}
        availableNamespaces={availableNamespaces}
        onClose={() => setShowEdit(false)}
        onSaved={() => {
          setShowEdit(false);
          onRefresh();
        }}
        toast={toast}
      />
    </>
  );
}

// ── Edit Role Modal ────────────────────────────────────────────────

// The AppRole write is an upsert, so editing reuses the same write path as
// create — we just pre-fill from the current config. TTLs come back from the
// server as seconds; render them as a `<n>s` string the operator can rewrite
// (empty ⇒ system default), and 0-uses ⇒ unlimited.
interface EditRoleModalProps {
  open: boolean;
  roleInfo: AppRoleInfo;
  availablePolicies: string[];
  policiesListable: boolean;
  availableNamespaces: string[];
  onClose: () => void;
  onSaved: () => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}

function EditRoleModal({
  open,
  roleInfo,
  availablePolicies,
  policiesListable,
  availableNamespaces,
  onClose,
  onSaved,
  toast,
}: EditRoleModalProps) {
  const secondsToField = (n: number) => (n === 0 ? "" : `${n}s`);

  const [policies, setPolicies] = useState<string[]>(roleInfo.token_policies);
  const [bindSecretId, setBindSecretId] = useState(roleInfo.bind_secret_id);
  const [secretIdNumUses, setSecretIdNumUses] = useState(String(roleInfo.secret_id_num_uses));
  const [secretIdTtl, setSecretIdTtl] = useState(secondsToField(roleInfo.secret_id_ttl));
  const [tokenTtl, setTokenTtl] = useState(secondsToField(roleInfo.token_ttl));
  const [tokenMaxTtl, setTokenMaxTtl] = useState(secondsToField(roleInfo.token_max_ttl));
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  // Re-seed the form each time it opens for a role, and pull the current
  // namespace login-restriction (empty ⇒ unrestricted).
  useEffect(() => {
    if (!open) return;
    setPolicies(roleInfo.token_policies);
    setBindSecretId(roleInfo.bind_secret_id);
    setSecretIdNumUses(String(roleInfo.secret_id_num_uses));
    setSecretIdTtl(secondsToField(roleInfo.secret_id_ttl));
    setTokenTtl(secondsToField(roleInfo.token_ttl));
    setTokenMaxTtl(secondsToField(roleInfo.token_max_ttl));
    api
      .getNsAssignment("approle/", roleInfo.name)
      .then((r) => setNamespaces(r.namespaces))
      .catch(() => setNamespaces([]));
  }, [open, roleInfo]);

  async function handleSave() {
    setSaving(true);
    try {
      const numUses = parseInt(secretIdNumUses, 10);
      await api.writeAppRole(
        roleInfo.name,
        bindSecretId,
        policies.join(","),
        Number.isNaN(numUses) ? 0 : numUses,
        secretIdTtl.trim(),
        tokenTtl.trim(),
        tokenMaxTtl.trim(),
      );
      await api.setNsAssignment("approle/", roleInfo.name, namespaces);
      toast("success", `ID ${roleInfo.name} updated`);
      onSaved();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Edit ID: ${roleInfo.name}`}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? "Saving..." : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <PolicySelect
          label="Token Policies"
          selected={policies}
          options={availablePolicies}
          onChange={setPolicies}
          fallbackFreeText={!policiesListable}
          placeholder="type to search policies…"
          helpText="Only existing policies can be selected"
        />
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={bindSecretId}
            onChange={(e) => setBindSecretId(e.target.checked)}
            className="rounded"
          />
          <span className="text-[var(--color-text-muted)]">Require Secret ID for login</span>
        </label>
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Secret ID Uses (0 = unlimited)"
            type="number"
            value={secretIdNumUses}
            onChange={(e) => setSecretIdNumUses(e.target.value)}
            placeholder="0"
          />
          <Input
            label="Secret ID TTL (empty = default)"
            value={secretIdTtl}
            onChange={(e) => setSecretIdTtl(e.target.value)}
            placeholder="24h"
          />
          <Input
            label="Token TTL (empty = default)"
            value={tokenTtl}
            onChange={(e) => setTokenTtl(e.target.value)}
            placeholder="1h"
          />
          <Input
            label="Token Max TTL (empty = default)"
            value={tokenMaxTtl}
            onChange={(e) => setTokenMaxTtl(e.target.value)}
            placeholder="24h"
          />
        </div>
        {availableNamespaces.length > 0 && (
          <div>
            <label className="block text-sm text-[var(--color-text-muted)] mb-1">
              Allowed namespaces
            </label>
            <div className="flex flex-wrap gap-2">
              {["", ...availableNamespaces].map((ns) => {
                const sel = namespaces.includes(ns);
                return (
                  <button
                    key={ns || "__root__"}
                    type="button"
                    onClick={() =>
                      setNamespaces((prev) =>
                        prev.includes(ns) ? prev.filter((p) => p !== ns) : [...prev, ns],
                      )
                    }
                    className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                      sel
                        ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                        : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                    }`}
                  >
                    {ns === "" ? "root" : ns}
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
              {namespaces.length === 0
                ? "No restriction — this role may log in to any namespace."
                : `Login restricted to: ${namespaces.map((n) => n || "root").join(", ")} (and descendants).`}
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}

// ── Machines Panel ─────────────────────────────────────────────────

interface MachinesPanelProps {
  roleInfo: AppRoleInfo;
  onRefresh: () => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}

function MachinesPanel({ roleInfo, onRefresh, toast }: MachinesPanelProps) {
  const [showAdd, setShowAdd] = useState(false);
  const [available, setAvailable] = useState<FerroGateMachine[]>([]);
  const [pickMachineId, setPickMachineId] = useState("");
  const [envInput, setEnvInput] = useState("");
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);

  async function openAdd() {
    setPickMachineId("");
    setEnvInput("");
    try {
      const machines = await api.ferrogateListMachines();
      // Only approved machines are usable, and hide those already bound.
      const bound = new Set(roleInfo.bound_machines.map((m) => m.machine_id));
      setAvailable(machines.filter((m) => m.status === "approved" && !bound.has(m.id)));
    } catch {
      setAvailable([]);
    }
    setShowAdd(true);
  }

  async function handleAdd() {
    if (!pickMachineId) return;
    const environments = envInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    try {
      await api.addRoleMachine(roleInfo.name, pickMachineId, "", environments);
      toast("success", "Machine bound to ID");
      setShowAdd(false);
      onRefresh();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRemove() {
    if (!removeTarget) return;
    try {
      await api.deleteRoleMachine(roleInfo.name, removeTarget);
      toast("success", "Machine binding removed");
      setRemoveTarget(null);
      onRefresh();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  const columns = [
    {
      key: "machine",
      header: "Machine",
      className: "min-w-0",
      render: (m: MachineBinding) => (
        <div className="min-w-0">
          <div className="font-mono text-xs truncate">{m.spiffe_id || m.machine_id}</div>
          {m.spiffe_id && (
            <div className="font-mono text-[10px] text-[var(--color-text-muted)] truncate">
              {m.machine_id}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "environments",
      header: "Environments",
      render: (m: MachineBinding) =>
        m.environments.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {m.environments.map((e) => (
              <Badge key={e} label={e} variant="info" />
            ))}
          </div>
        ) : (
          <span className="text-xs text-[var(--color-text-muted)]">All environments</span>
        ),
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-24",
      render: (m: MachineBinding) => (
        <Button variant="danger" size="sm" onClick={() => setRemoveTarget(m.machine_id)}>
          Remove
        </Button>
      ),
    },
  ];

  return (
    <>
      <Card
        title="Bound Machines"
        actions={
          <Button size="sm" onClick={openAdd}>
            Bind Machine
          </Button>
        }
      >
        <Table
          columns={columns}
          data={roleInfo.bound_machines}
          rowKey={(m) => m.machine_id}
          emptyMessage="No machines bound. This ID cannot authenticate until a machine is bound."
        />
      </Card>

      <Modal
        open={showAdd}
        onClose={() => setShowAdd(false)}
        title="Bind Machine to ID"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowAdd(false)}>
              Cancel
            </Button>
            <Button onClick={handleAdd} disabled={!pickMachineId}>
              Bind
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {available.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">
              No approved FerroGate machines available to bind. Approve machines under Admin →
              Machines (FerroGate) first.
            </p>
          ) : (
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">Machine</label>
              <select
                value={pickMachineId}
                onChange={(e) => setPickMachineId(e.target.value)}
                className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm"
              >
                <option value="">Select a machine…</option>
                {available.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.spiffe_id}
                  </option>
                ))}
              </select>
            </div>
          )}
          <Input
            label="Environments (comma separated, wildcards allowed)"
            value={envInput}
            onChange={(e) => setEnvInput(e.target.value)}
            placeholder="prod, staging, prod-*  (empty = all environments)"
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            Leave empty to let this machine access all environments for this ID. Wildcards like{" "}
            <code>prod-*</code> are supported.
          </p>
        </div>
      </Modal>

      <ConfirmModal
        open={removeTarget !== null}
        onClose={() => setRemoveTarget(null)}
        onConfirm={handleRemove}
        title="Remove Machine Binding"
        message="Remove this machine from the ID? Clients using it will no longer be able to authenticate with this ID."
        confirmLabel="Remove"
      />
    </>
  );
}

function ConfigRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-[var(--color-border)]">
      <span className="text-[var(--color-text-muted)]">{label}</span>
      <span className="font-mono text-xs">{value}</span>
    </div>
  );
}

// ── Secret ID Panel ────────────────────────────────────────────────

interface SecretIdPanelProps {
  roleName: string;
  onCopy: (text: string, label: string) => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}

function SecretIdPanel({ roleName, onCopy, toast }: SecretIdPanelProps) {
  const [accessors, setAccessors] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [destroyTarget, setDestroyTarget] = useState<string | null>(null);
  const [detailTarget, setDetailTarget] = useState<SecretIdAccessorInfo | null>(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [genEnvInput, setGenEnvInput] = useState("");

  useEffect(() => {
    loadAccessors();
  }, [roleName]);

  async function loadAccessors() {
    setLoading(true);
    try {
      const result = await api.listSecretIdAccessors(roleName);
      setAccessors(result.accessors);
    } catch {
      setAccessors([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerate() {
    const environments = genEnvInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    try {
      const result = await api.generateSecretId(roleName, "", environments);
      setShowGenerate(false);
      setGenEnvInput("");
      setGeneratedSecret(result.secret_id);
      toast("success", "Secret ID generated");
      loadAccessors();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDestroy() {
    if (!destroyTarget) return;
    try {
      await api.destroySecretIdAccessor(roleName, destroyTarget);
      toast("success", "Secret ID destroyed");
      setDestroyTarget(null);
      loadAccessors();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleLookup(accessor: string) {
    try {
      const info = await api.lookupSecretIdAccessor(roleName, accessor);
      setDetailTarget(info);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  const columns = [
    {
      key: "accessor",
      header: "Accessor",
      className: "font-mono text-xs",
      render: (a: string) => a.substring(0, 16) + "...",
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-40",
      render: (a: string) => (
        <div className="flex gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => handleLookup(a)}>
            Lookup
          </Button>
          <Button variant="danger" size="sm" onClick={() => setDestroyTarget(a)}>
            Destroy
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <Card
        title="Secret IDs"
        actions={
          <Button size="sm" onClick={() => { setGenEnvInput(""); setShowGenerate(true); }}>
            Generate
          </Button>
        }
      >
        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
        ) : (
          <Table
            columns={columns}
            data={accessors}
            rowKey={(a) => a}
            emptyMessage="No secret IDs generated for this ID"
          />
        )}
      </Card>

      {/* Generate secret ID (choose environment scope) */}
      <Modal
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        title="Generate Secret ID"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowGenerate(false)}>
              Cancel
            </Button>
            <Button onClick={handleGenerate}>Generate</Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input
            label="Environments (comma separated, wildcards allowed)"
            value={genEnvInput}
            onChange={(e) => setGenEnvInput(e.target.value)}
            placeholder="prod, staging, prod-*  (empty = all environments)"
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            Scope this secret ID to specific environments. Leave empty to allow all environments.
            The issued token's effective scope is the intersection of this and the bound machine's
            environment scope.
          </p>
        </div>
      </Modal>

      {/* Generated secret display */}
      <Modal
        open={generatedSecret !== null}
        onClose={() => setGeneratedSecret(null)}
        title="Secret ID Generated"
        actions={
          <Button onClick={() => setGeneratedSecret(null)}>Done</Button>
        }
      >
        <div className="space-y-3">
          <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
            Copy this secret ID now. It will not be displayed again.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono break-all">
              {generatedSecret}
            </code>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onCopy(generatedSecret!, "Secret ID")}
            >
              Copy
            </Button>
          </div>
        </div>
      </Modal>

      {/* Accessor detail */}
      <Modal
        open={detailTarget !== null}
        onClose={() => setDetailTarget(null)}
        title="Secret ID Details"
        actions={
          <Button variant="ghost" onClick={() => setDetailTarget(null)}>
            Close
          </Button>
        }
      >
        {detailTarget && (
          <div className="space-y-2 text-sm">
            <DetailRow label="Accessor" value={detailTarget.secret_id_accessor} mono />
            <DetailRow label="Uses Remaining" value={detailTarget.secret_id_num_uses === 0 ? "Unlimited" : String(detailTarget.secret_id_num_uses)} />
            <DetailRow label="TTL" value={detailTarget.secret_id_ttl === 0 ? "System default" : `${detailTarget.secret_id_ttl}s`} />
            <DetailRow label="Created" value={detailTarget.creation_time || "N/A"} />
            <DetailRow label="Expires" value={detailTarget.expiration_time || "Never"} />
            {detailTarget.cidr_list.length > 0 && (
              <DetailRow label="CIDR List" value={detailTarget.cidr_list.join(", ")} />
            )}
            <DetailRow
              label="Environments"
              value={detailTarget.environments.length > 0 ? detailTarget.environments.join(", ") : "All"}
            />
            {Object.keys(detailTarget.metadata).length > 0 && (
              <div>
                <span className="text-[var(--color-text-muted)]">Metadata:</span>
                <pre className="mt-1 bg-[var(--color-bg)] border border-[var(--color-border)] rounded p-2 text-xs font-mono">
                  {JSON.stringify(detailTarget.metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </Modal>

      <ConfirmModal
        open={destroyTarget !== null}
        onClose={() => setDestroyTarget(null)}
        onConfirm={handleDestroy}
        title="Destroy Secret ID"
        message="Are you sure you want to destroy this secret ID? Applications using it will no longer be able to authenticate."
        confirmLabel="Destroy"
      />
    </>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between items-start py-1.5 border-b border-[var(--color-border)]">
      <span className="text-[var(--color-text-muted)] shrink-0 mr-4">{label}</span>
      <span className={`text-right break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
