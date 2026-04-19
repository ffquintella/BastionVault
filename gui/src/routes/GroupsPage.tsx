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
import type { GroupKind, GroupInfo, GroupHistoryEntry } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function GroupsPage() {
  const { toast } = useToast();
  const [kind, setKind] = useState<GroupKind>("user");
  const [groups, setGroups] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [mountEnabled, setMountEnabled] = useState<boolean | null>(null);

  const [selected, setSelected] = useState<string | null>(null);
  const [selectedInfo, setSelectedInfo] = useState<GroupInfo | null>(null);

  const [showEdit, setShowEdit] = useState(false);
  const [editMode, setEditMode] = useState<"create" | "update">("create");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // Available policies and source members (usernames or role names) for multi-select.
  const [availablePolicies, setAvailablePolicies] = useState<string[]>([]);
  const [availableMembers, setAvailableMembers] = useState<string[]>([]);

  // Form state
  const [formName, setFormName] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formMembers, setFormMembers] = useState<string[]>([]);
  const [formPolicies, setFormPolicies] = useState<string[]>([]);
  const [freeformMembers, setFreeformMembers] = useState("");

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind]);

  async function loadAll() {
    setLoading(true);
    setSelected(null);
    setSelectedInfo(null);
    try {
      const mounts = await api.listMounts().catch(() => []);
      const enabled = mounts.some((m) => m.path === "identity/");
      setMountEnabled(enabled);
      if (!enabled) {
        setGroups([]);
        return;
      }
      const result = await api.listGroups(kind);
      setGroups(result.groups);
    } catch {
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadAuxLists() {
    try {
      const p = await api.listPolicies();
      setAvailablePolicies(p.policies.filter((x) => x !== "root"));
    } catch {
      setAvailablePolicies([]);
    }

    if (kind === "user") {
      try {
        const u = await api.listUsers("userpass/");
        setAvailableMembers(u.users);
      } catch {
        setAvailableMembers([]);
      }
    } else {
      try {
        const r = await api.listAppRoles();
        setAvailableMembers(r.roles);
      } catch {
        setAvailableMembers([]);
      }
    }
  }

  async function selectGroup(name: string) {
    try {
      const info = await api.readGroup(kind, name);
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
    setFormPolicies(selectedInfo.policies);
    setFreeformMembers("");
    setShowEdit(true);
    await loadAuxLists();
  }

  function resetForm() {
    setFormName("");
    setFormDescription("");
    setFormMembers([]);
    setFormPolicies([]);
    setFreeformMembers("");
  }

  function toggleMember(m: string) {
    setFormMembers((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m],
    );
  }

  function togglePolicy(p: string) {
    setFormPolicies((prev) =>
      prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p],
    );
  }

  async function handleSubmit() {
    const name = formName.trim().toLowerCase();
    if (!name) return;

    // Merge selected members with any freeform entries.
    const extra = freeformMembers
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const mergedMembers = Array.from(new Set([...formMembers, ...extra]));

    try {
      await api.writeGroup(
        kind,
        name,
        formDescription,
        mergedMembers.join(","),
        formPolicies.join(","),
      );
      toast(
        "success",
        editMode === "create"
          ? `Group ${name} created`
          : `Group ${name} updated`,
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
      await api.deleteGroup(kind, deleteTarget);
      toast("success", `Group ${deleteTarget} deleted`);
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

  const memberLabel = kind === "user" ? "Users" : "App Roles";
  const memberHint =
    kind === "user"
      ? "UserPass usernames in this group"
      : "AppRole role names in this group";

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Identity Groups</h1>
          {mountEnabled && (
            <Button size="sm" onClick={openCreate}>
              Create Group
            </Button>
          )}
        </div>

        <Tabs
          tabs={[
            { id: "user", label: "User Groups" },
            { id: "app", label: "Application Groups" },
          ]}
          active={kind}
          onChange={(t) => setKind(t as GroupKind)}
        />

        {mountEnabled === false && !loading ? (
          <Card>
            <EmptyState
              title="Identity backend not mounted"
              description="The identity/ mount is added to new deployments on unseal. On older deployments, reseal and unseal the vault to auto-mount it."
            />
          </Card>
        ) : (
          <div className="flex gap-4">
            {/* Group list */}
            <Card className="w-56 shrink-0" title={kind === "user" ? "User Groups" : "App Groups"}>
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
                <GroupDetail
                  kind={kind}
                  info={selectedInfo}
                  memberLabel={memberLabel}
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
          title={editMode === "create" ? `Create ${kind === "user" ? "User" : "App"} Group` : `Edit Group: ${formName}`}
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
              placeholder="platform-engineers"
              hint="Lowercase; no '/' or '..'"
            />
            <Textarea
              label="Description"
              value={formDescription}
              onChange={(e) => setFormDescription(e.target.value)}
              rows={2}
            />

            {/* Members selector */}
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                {memberLabel}
              </label>
              <p className="text-xs text-[var(--color-text-muted)] mb-2">{memberHint}</p>
              {availableMembers.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {availableMembers.map((m) => {
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
                  No {kind === "user" ? "users" : "app roles"} available.
                </p>
              )}
              {formMembers.filter((m) => !availableMembers.includes(m)).length > 0 && (
                <div className="mt-2">
                  <p className="text-xs text-[var(--color-text-muted)] mb-1">
                    Other members (not in the current {kind === "user" ? "userpass" : "approle"} mount):
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {formMembers
                      .filter((m) => !availableMembers.includes(m))
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
                placeholder="Add extra members, comma-separated"
                hint="Useful when members live in another auth mount"
              />
            </div>

            {/* Policies selector */}
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">Policies</label>
              {availablePolicies.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {availablePolicies.map((p) => {
                    const sel = formPolicies.includes(p);
                    return (
                      <button
                        key={p}
                        type="button"
                        onClick={() => togglePolicy(p)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          sel
                            ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                            : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                        }`}
                      >
                        {p}
                      </button>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-[var(--color-text-muted)]">
                  No policies available. Create policies first from the Policies page.
                </p>
              )}
            </div>
          </div>
        </Modal>

        <ConfirmModal
          open={deleteTarget !== null}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete Group"
          message={`Are you sure you want to delete group "${deleteTarget}"? Members will lose any policies inherited from this group on their next login/renewal.`}
          confirmLabel="Delete"
        />
      </div>
    </Layout>
  );
}

interface GroupDetailProps {
  kind: GroupKind;
  info: GroupInfo;
  memberLabel: string;
  onEdit: () => void;
  onDelete: () => void;
}

function GroupDetail({ kind, info, memberLabel, onEdit, onDelete }: GroupDetailProps) {
  const [tab, setTab] = useState("overview");
  const [history, setHistory] = useState<GroupHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    if (tab !== "history") return;
    let cancelled = false;
    setHistoryLoading(true);
    api
      .listGroupHistory(kind, info.name)
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
  }, [tab, kind, info.name]);

  const memberCols = [
    { key: "name", header: "Name", render: (m: string) => m },
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
                <DetailRow label="Kind" value={info.kind} />
                <DetailRow label="Members" value={String(info.members.length)} />
                <DetailRow label="Policies" value={String(info.policies.length)} />
                <DetailRow label="Created" value={info.created_at || "-"} />
                <DetailRow label="Updated" value={info.updated_at || "-"} />
              </div>

              <div>
                <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                  Policies
                </label>
                <div className="flex flex-wrap gap-1">
                  {info.policies.length > 0 ? (
                    info.policies.map((p) => <Badge key={p} label={p} variant="info" />)
                  ) : (
                    <span className="text-sm text-[var(--color-text-muted)]">None</span>
                  )}
                </div>
              </div>
            </div>
          </Card>

          <Card title={memberLabel}>
            <Table
              columns={memberCols}
              data={info.members}
              rowKey={(m) => m}
              emptyMessage="No members in this group"
            />
          </Card>
        </>
      )}

      {tab === "history" && (
        <Card title="Change History">
          <GroupHistoryPanel entries={history} loading={historyLoading} />
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
