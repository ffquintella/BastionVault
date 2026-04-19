import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Textarea,
  Badge,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  GroupHistoryPanel,
  useToast,
} from "../components/ui";
import type {
  AssetGroupInfo,
  AssetGroupHistoryEntry,
  GroupHistoryEntry,
} from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

// Asset Groups page: named collections of resources + KV secrets. The
// backend is the "resource-group" mount — see features/resource-groups.md.
// Distinct from Identity Groups (which bundle principals, not objects).

export function AssetGroupsPage() {
  const { toast } = useToast();
  const [groups, setGroups] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountEnabled, setMountEnabled] = useState<boolean | null>(null);

  const [selected, setSelected] = useState<string | null>(null);
  const [selectedInfo, setSelectedInfo] = useState<AssetGroupInfo | null>(null);

  const [showEdit, setShowEdit] = useState(false);
  const [editMode, setEditMode] = useState<"create" | "update">("create");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // Available resources to pick from in the form (sourced from the
  // resources mount). Secrets are free-form since KV paths span the
  // full path space.
  const [availableResources, setAvailableResources] = useState<string[]>([]);

  // Form state
  const [formName, setFormName] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formMembers, setFormMembers] = useState<string[]>([]);
  const [freeformMembers, setFreeformMembers] = useState("");
  const [formSecrets, setFormSecrets] = useState<string[]>([]);
  const [freeformSecret, setFreeformSecret] = useState("");

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    setSelected(null);
    setSelectedInfo(null);
    try {
      const mounts = await api.listMounts().catch(() => []);
      const enabled = mounts.some((m) => m.path === "resource-group/");
      setMountEnabled(enabled);
      if (!enabled) {
        setGroups([]);
        return;
      }
      const result = await api.listAssetGroups();
      setGroups(result.groups);
    } catch {
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadAuxLists() {
    try {
      const r = await api.listResources();
      setAvailableResources(r.resources);
    } catch {
      setAvailableResources([]);
    }
  }

  async function selectGroup(name: string) {
    try {
      const info = await api.readAssetGroup(name);
      setSelected(name);
      setSelectedInfo(info);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openCreate() {
    resetForm();
    setEditMode("create");
    setShowEdit(true);
    await loadAuxLists();
  }

  async function openEdit() {
    if (!selectedInfo) return;
    setEditMode("update");
    setFormName(selectedInfo.name);
    setFormDescription(selectedInfo.description);
    setFormMembers(selectedInfo.members);
    setFormSecrets(selectedInfo.secrets);
    setFreeformMembers("");
    setFreeformSecret("");
    setShowEdit(true);
    await loadAuxLists();
  }

  function resetForm() {
    setFormName("");
    setFormDescription("");
    setFormMembers([]);
    setFreeformMembers("");
    setFormSecrets([]);
    setFreeformSecret("");
  }

  function toggleMember(m: string) {
    setFormMembers((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m],
    );
  }

  function addSecretFromFreeform() {
    const s = freeformSecret.trim();
    if (!s) return;
    setFormSecrets((prev) => (prev.includes(s) ? prev : [...prev, s]));
    setFreeformSecret("");
  }

  function removeSecret(s: string) {
    setFormSecrets((prev) => prev.filter((x) => x !== s));
  }

  async function handleSubmit() {
    const name = formName.trim().toLowerCase();
    if (!name) return;

    // Merge chip-selected members with any freeform entries.
    const extra = freeformMembers
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const mergedMembers = Array.from(new Set([...formMembers, ...extra]));

    // Any pending freeform secret in the input gets committed on save.
    const pendingSecret = freeformSecret.trim();
    const mergedSecrets = Array.from(
      new Set(pendingSecret ? [...formSecrets, pendingSecret] : formSecrets),
    );

    try {
      await api.writeAssetGroup(
        name,
        formDescription,
        mergedMembers.join(","),
        mergedSecrets.join(","),
      );
      toast(
        "success",
        editMode === "create"
          ? `Asset group ${name} created`
          : `Asset group ${name} updated`,
      );
      setShowEdit(false);
      resetForm();
      await loadAll();
      await selectGroup(name);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteAssetGroup(deleteTarget);
      toast("success", `Asset group ${deleteTarget} deleted`);
      if (selected === deleteTarget) {
        setSelected(null);
        setSelectedInfo(null);
      }
      setDeleteTarget(null);
      await loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Asset Groups</h1>
          {mountEnabled && (
            <Button size="sm" onClick={openCreate}>
              Create Group
            </Button>
          )}
        </div>

        <p className="text-sm text-[var(--color-text-muted)]">
          Named collections of resources and KV-secret paths. Policies can
          reference a group via <code className="font-mono">groups = [...]</code>{" "}
          to gate capabilities on membership — an operator edits group members,
          not policies, to grant or revoke access.
        </p>

        {mountEnabled === false && !loading ? (
          <Card>
            <EmptyState
              title="Asset-group backend not mounted"
              description="The resource-group/ mount is added to new deployments on unseal. On older deployments, reseal and unseal the vault to auto-mount it."
            />
          </Card>
        ) : (
          <div className="flex gap-4">
            {/* Group list */}
            <Card className="w-56 shrink-0" title="Groups">
              {loading ? (
                <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
              ) : groups.length === 0 ? (
                <EmptyState title="No groups" description="Create your first group" />
              ) : (
                <div className="space-y-0.5 -mx-1">
                  {groups.map((name) => (
                    <div key={name} className="flex items-center group">
                      <button
                        onClick={() => selectGroup(name)}
                        className={`flex-1 text-left px-3 py-1.5 rounded text-sm transition-colors min-w-0 truncate ${
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

            {/* Detail */}
            <div className="flex-1 space-y-4 min-w-0">
              {selected && selectedInfo ? (
                <AssetGroupDetail
                  info={selectedInfo}
                  onEdit={openEdit}
                  onDelete={() => setDeleteTarget(selected)}
                />
              ) : (
                <Card>
                  <EmptyState
                    title="No group selected"
                    description="Select a group from the list to view details"
                  />
                </Card>
              )}
            </div>
          </div>
        )}

        {/* Create/edit modal */}
        <Modal
          open={showEdit}
          onClose={() => { setShowEdit(false); resetForm(); }}
          title={editMode === "create" ? "Create Asset Group" : `Edit Group: ${formName}`}
          size="lg"
          actions={
            <>
              <Button variant="ghost" onClick={() => { setShowEdit(false); resetForm(); }}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={!formName.trim()}>
                {editMode === "create" ? "Create" : "Save"}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="Name"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              disabled={editMode === "update"}
              placeholder="project-phoenix"
              hint="Lowercase; no '/' or '..'"
            />
            <Textarea
              label="Description"
              value={formDescription}
              onChange={(e) => setFormDescription(e.target.value)}
              rows={2}
            />

            {/* Resource members */}
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                Resources
              </label>
              <p className="text-xs text-[var(--color-text-muted)] mb-2">
                Resource names from the resources mount that belong to this group.
              </p>
              {availableResources.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {availableResources.map((m) => {
                    const sel = formMembers.includes(m);
                    return (
                      <button
                        key={m}
                        type="button"
                        onClick={() => toggleMember(m)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          sel
                            ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                            : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                        }`}
                      >
                        {m}
                      </button>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-[var(--color-text-muted)]">
                  No resources available. Create resources first from the Resources page.
                </p>
              )}
              {formMembers.filter((m) => !availableResources.includes(m)).length > 0 && (
                <div className="mt-2">
                  <p className="text-xs text-[var(--color-text-muted)] mb-1">
                    Other resources (not in the current resources mount):
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {formMembers
                      .filter((m) => !availableResources.includes(m))
                      .map((m) => (
                        <button
                          key={m}
                          type="button"
                          onClick={() => toggleMember(m)}
                          className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs border bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] border-[var(--color-border)] hover:text-[var(--color-danger)]"
                          title="Remove"
                        >
                          {m}
                          <span>&times;</span>
                        </button>
                      ))}
                  </div>
                </div>
              )}
              <Input
                label=""
                value={freeformMembers}
                onChange={(e) => setFreeformMembers(e.target.value)}
                placeholder="Add extra resources, comma-separated"
              />
            </div>

            {/* KV secrets */}
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                Secrets
              </label>
              <p className="text-xs text-[var(--color-text-muted)] mb-2">
                KV-secret paths. The KV-v2 <code className="font-mono">data/</code> /{" "}
                <code className="font-mono">metadata/</code> segments are stripped server-side;
                either form (<code className="font-mono">secret/foo/bar</code> or{" "}
                <code className="font-mono">secret/data/foo/bar</code>) works.
              </p>
              {formSecrets.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-2">
                  {formSecrets.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => removeSecret(s)}
                      className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs border bg-[var(--color-primary)] text-white border-[var(--color-primary)] hover:bg-[var(--color-danger)] hover:border-[var(--color-danger)]"
                      title="Remove"
                    >
                      <span className="font-mono">{s}</span>
                      <span>&times;</span>
                    </button>
                  ))}
                </div>
              )}
              <div className="flex gap-2">
                <div className="flex-1">
                  <Input
                    label=""
                    value={freeformSecret}
                    onChange={(e) => setFreeformSecret(e.target.value)}
                    placeholder="secret/foo/bar"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addSecretFromFreeform();
                      }
                    }}
                  />
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={addSecretFromFreeform}
                  disabled={!freeformSecret.trim()}
                >
                  Add
                </Button>
              </div>
            </div>
          </div>
        </Modal>

        <ConfirmModal
          open={deleteTarget !== null}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete Asset Group"
          message={`Are you sure you want to delete group "${deleteTarget}"? Policies referencing this group via 'groups = [...]' will stop granting access to its former members.`}
          confirmLabel="Delete"
        />
      </div>
    </Layout>
  );
}

interface AssetGroupDetailProps {
  info: AssetGroupInfo;
  onEdit: () => void;
  onDelete: () => void;
}

function AssetGroupDetail({ info, onEdit, onDelete }: AssetGroupDetailProps) {
  const [tab, setTab] = useState("overview");
  const [history, setHistory] = useState<AssetGroupHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    if (tab !== "history") return;
    let cancelled = false;
    setHistoryLoading(true);
    api
      .listAssetGroupHistory(info.name)
      .then((r) => {
        if (!cancelled) setHistory(r.entries);
      })
      .catch(() => {
        if (!cancelled) setHistory([]);
      })
      .finally(() => {
        if (!cancelled) setHistoryLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tab, info.name]);

  const resourceCols = [
    { key: "name", header: "Resource", render: (m: string) => m },
  ];
  const secretCols = [
    {
      key: "path",
      header: "Path",
      render: (s: string) => <span className="font-mono text-xs">{s}</span>,
    },
  ];

  return (
    <>
      <Card
        title={info.name}
        actions={
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={onEdit}>
              Edit
            </Button>
            <Button variant="danger" size="sm" onClick={onDelete}>
              Delete
            </Button>
          </div>
        }
      >
        <Tabs
          tabs={[
            { id: "overview", label: "Overview" },
            { id: "history", label: "History" },
          ]}
          active={tab}
          onChange={setTab}
        />
      </Card>

      {tab === "overview" && (
        <>
          <Card>
            <div className="space-y-4">
              {info.description && (
                <p className="text-sm text-[var(--color-text-muted)]">{info.description}</p>
              )}

              <div className="grid grid-cols-2 gap-4 text-sm">
                <DetailRow label="Resources" value={String(info.members.length)} />
                <DetailRow label="Secrets" value={String(info.secrets.length)} />
                <DetailRow label="Created" value={info.created_at || "-"} />
                <DetailRow label="Updated" value={info.updated_at || "-"} />
              </div>

              {info.members.length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                    Resources
                  </label>
                  <div className="flex flex-wrap gap-1">
                    {info.members.map((m) => (
                      <Badge key={m} label={m} variant="info" />
                    ))}
                  </div>
                </div>
              )}

              {info.secrets.length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                    Secrets
                  </label>
                  <div className="flex flex-wrap gap-1">
                    {info.secrets.map((s) => (
                      <Badge key={s} label={s} variant="info" />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>

          <Card title="Resources">
            <Table
              columns={resourceCols}
              data={info.members}
              rowKey={(m) => m}
              emptyMessage="No resources in this group"
            />
          </Card>

          <Card title="Secrets">
            <Table
              columns={secretCols}
              data={info.secrets}
              rowKey={(s) => s}
              emptyMessage="No secrets in this group"
            />
          </Card>
        </>
      )}

      {tab === "history" && (
        <Card title="Change History">
          <GroupHistoryPanel
            entries={history as unknown as GroupHistoryEntry[]}
            loading={historyLoading}
          />
        </Card>
      )}
    </>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-[var(--color-border)]">
      <span className="text-[var(--color-text-muted)]">{label}</span>
      <span className="font-mono text-xs truncate ml-2">{value}</span>
    </div>
  );
}
