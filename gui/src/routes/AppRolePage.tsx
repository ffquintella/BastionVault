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
  useToast,
} from "../components/ui";
import type { AppRoleInfo, SecretIdAccessorInfo } from "../lib/types";
import * as api from "../lib/api";

export function AppRolePage() {
  const { toast } = useToast();
  const [roles, setRoles] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [roleInfo, setRoleInfo] = useState<AppRoleInfo | null>(null);
  const [roleId, setRoleId] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // Create form
  const [newName, setNewName] = useState("");
  const [newPolicies, setNewPolicies] = useState("");
  const [newBindSecretId, setNewBindSecretId] = useState(true);

  useEffect(() => {
    loadRoles();
  }, []);

  async function loadRoles() {
    setLoading(true);
    try {
      const result = await api.listAppRoles();
      setRoles(result.roles);
    } catch {
      setRoles([]);
    } finally {
      setLoading(false);
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
      toast("error", String(e));
    }
  }

  async function handleCreate() {
    if (!newName) return;
    try {
      await api.writeAppRole(newName, newBindSecretId, newPolicies, 0, "", "", "");
      toast("success", `Role ${newName} created`);
      setShowCreate(false);
      setNewName("");
      setNewPolicies("");
      loadRoles();
      selectRole(newName);
    } catch (e: unknown) {
      toast("error", String(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteAppRole(deleteTarget);
      toast("success", `Role ${deleteTarget} deleted`);
      if (selected === deleteTarget) {
        setSelected(null);
        setRoleInfo(null);
      }
      setDeleteTarget(null);
      loadRoles();
    } catch (e: unknown) {
      toast("error", String(e));
    }
  }

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    toast("success", `${label} copied to clipboard`);
  }

  return (
    <Layout>
      <div className="max-w-5xl space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">AppRole</h1>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            Create Role
          </Button>
        </div>

        <div className="flex gap-4">
          {/* Role list */}
          <Card className="w-56 shrink-0" title="Roles">
            {loading ? (
              <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
            ) : roles.length === 0 ? (
              <EmptyState title="No roles" />
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

          {/* Role detail */}
          <div className="flex-1 space-y-4">
            {selected && roleInfo ? (
              <RoleDetail
                roleInfo={roleInfo}
                roleId={roleId}
                onCopy={copyToClipboard}
                toast={toast}
              />
            ) : (
              <Card>
                <EmptyState
                  title="No role selected"
                  description="Select a role from the list to view details"
                />
              </Card>
            )}
          </div>
        </div>

        {/* Create role modal */}
        <Modal
          open={showCreate}
          onClose={() => setShowCreate(false)}
          title="Create AppRole"
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
              label="Role Name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="my-app"
            />
            <Input
              label="Token Policies"
              value={newPolicies}
              onChange={(e) => setNewPolicies(e.target.value)}
              hint="Comma-separated policy names"
              placeholder="default, my-policy"
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
          </div>
        </Modal>

        <ConfirmModal
          open={deleteTarget !== null}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete Role"
          message={`Are you sure you want to delete role "${deleteTarget}"? All associated secret IDs will be invalidated.`}
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
  onCopy: (text: string, label: string) => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}

function RoleDetail({ roleInfo, roleId, onCopy, toast }: RoleDetailProps) {
  const [tab, setTab] = useState("overview");

  return (
    <>
      <Card title={`Role: ${roleInfo.name}`}>
        <Tabs
          tabs={[
            { id: "overview", label: "Overview" },
            { id: "secret-ids", label: "Secret IDs" },
          ]}
          active={tab}
          onChange={setTab}
        />
      </Card>

      {tab === "overview" && (
        <Card>
          <div className="space-y-4">
            {/* Role ID */}
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                Role ID
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono truncate">
                  {roleId}
                </code>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onCopy(roleId, "Role ID")}
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

      {tab === "secret-ids" && (
        <SecretIdPanel roleName={roleInfo.name} onCopy={onCopy} toast={toast} />
      )}
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
    try {
      const result = await api.generateSecretId(roleName, "");
      setGeneratedSecret(result.secret_id);
      toast("success", "Secret ID generated");
      loadAccessors();
    } catch (e: unknown) {
      toast("error", String(e));
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
      toast("error", String(e));
    }
  }

  async function handleLookup(accessor: string) {
    try {
      const info = await api.lookupSecretIdAccessor(roleName, accessor);
      setDetailTarget(info);
    } catch (e: unknown) {
      toast("error", String(e));
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
          <Button size="sm" onClick={handleGenerate}>
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
            emptyMessage="No secret IDs generated for this role"
          />
        )}
      </Card>

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
