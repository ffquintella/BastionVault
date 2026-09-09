import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import { ObjectSharingCard } from "../components/ObjectSharingCard";
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
  EntityLabel,
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
import { hasLiteralAdminPolicy } from "../lib/access";
import { RustionPolicyTierEditor } from "../components/RustionPolicyTierEditor";

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
  const [availSearch, setAvailSearch] = useState("");
  const [selectedSearch, setSelectedSearch] = useState("");
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
                  onReload={() => selectGroup(selected)}
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
            <ResourcePicker
              available={availableResources}
              selected={formMembers}
              setSelected={setFormMembers}
              availSearch={availSearch}
              setAvailSearch={setAvailSearch}
              selectedSearch={selectedSearch}
              setSelectedSearch={setSelectedSearch}
              freeform={freeformMembers}
              setFreeform={setFreeformMembers}
            />

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
  /** Refetch the group after an owner transfer so the badge updates. */
  onReload?: () => void;
}

function AssetGroupDetail({ info, onEdit, onDelete, onReload }: AssetGroupDetailProps) {
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
            { id: "sharing", label: "Sharing" },
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
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--color-border)]">
                  <span className="text-[var(--color-text-muted)]">Owner</span>
                  {info.owner_entity_id ? (
                    <EntityLabel entityId={info.owner_entity_id} />
                  ) : (
                    <span className="text-xs text-[var(--color-text-muted)] italic">
                      (unowned)
                    </span>
                  )}
                </div>
                <DetailRow label="Created" value={info.created_at || "-"} />
                <DetailRow label="Updated" value={info.updated_at || "-"} />
              </div>

              {info.members.length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
                    Resources
                  </label>
                  <div className="flex flex-wrap gap-1">
                    {info.members.map((m, i) => (
                      <Badge
                        key={`${i}-${m}`}
                        label={m === "<hidden>" ? "hidden" : m}
                        variant={m === "<hidden>" ? "neutral" : "info"}
                      />
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
                    {info.secrets.map((s, i) => (
                      <Badge
                        key={`${i}-${s}`}
                        label={s === "<hidden>" ? "hidden" : s}
                        variant={s === "<hidden>" ? "neutral" : "info"}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>

          <Card title="Resources">
            <Table
              columns={resourceCols}
              data={info.members.filter((m) => m !== "<hidden>")}
              rowKey={(m) => m}
              emptyMessage="No resources in this group"
            />
            {info.members.filter((m) => m === "<hidden>").length > 0 && (
              <p className="text-xs text-[var(--color-text-muted)] mt-2 italic">
                {info.members.filter((m) => m === "<hidden>").length} hidden
                resource(s) you don't have read access to.
              </p>
            )}
          </Card>

          <Card title="Secrets">
            <Table
              columns={secretCols}
              data={info.secrets.filter((s) => s !== "<hidden>")}
              rowKey={(s) => s}
              emptyMessage="No secrets in this group"
            />
            {info.secrets.filter((s) => s === "<hidden>").length > 0 && (
              <p className="text-xs text-[var(--color-text-muted)] mt-2 italic">
                {info.secrets.filter((s) => s === "<hidden>").length} hidden
                secret(s) you don't have read access to.
              </p>
            )}
          </Card>

          {/* Phase 7.3 — per-asset-group Rustion policy editor. The
              underlying handler is admin/owner-gated on the API side. */}
          <RustionPolicyTierEditor tier="asset-group" id={info.name} />
        </>
      )}

      {tab === "sharing" && (
        <AssetGroupSharingCard
          info={info}
          onOwnerChange={() => onReload?.()}
        />
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

/**
 * Owner + shares + admin-transfer affordances for an asset group.
 * Targets the `asset-group` share kind: a single share here grants
 * access to every current and future member of the group.
 *
 * Everything but the bindings below lives in `ObjectSharingCard`,
 * shared with resources, file resources and KV secrets. Two of those
 * bindings are asset-group-only:
 *
 *  - The owner is not behind an endpoint. It rides on the
 *    `AssetGroupInfo` this page already loaded, so it is handed over as
 *    `ownerOverride` and a transfer asks the parent to refetch through
 *    `onOwnerChange` rather than re-reading here — one source for the
 *    header and this tab.
 *  - Asset groups are the one kind that offers group grantees on grant.
 *    Revoking a group share works on every kind; only creating one is
 *    scoped here.
 */
export function AssetGroupSharingCard({
  info,
  onOwnerChange,
}: {
  info: AssetGroupInfo;
  onOwnerChange: () => void;
}) {
  const { toast } = useToast();
  return (
    <ObjectSharingCard
      kind="asset-group"
      target={info.name}
      label={`group "${info.name}"`}
      noun="group"
      ownerOverride={{
        target_kind: "asset-group",
        target: info.name,
        entity_id: info.owner_entity_id,
        owned: info.owner_entity_id !== "",
        // The group record carries no separate ownership timestamp —
        // `created_at` on it is the group's, not the owner record's.
        created_at: "",
      }}
      onOwnerChange={onOwnerChange}
      // No `sys/asset-group-owner/claim` endpoint, so Claim rides the
      // admin transfer endpoint — see `OwnerAdapter`.
      owner={{ transfer: api.transferAssetGroupOwner }}
      capabilities={["read", "list", "update", "delete", "create"]}
      capabilityHint="These capabilities apply to every current and future member of the group — both resources and KV secrets."
      granteeKinds={["entity", "group_user", "group_app"]}
      // Unlike the other kinds, a later write never captures ownership:
      // the group takes its owner on create and keeps it.
      unownedDescription="This group was created by a root token or by a caller without an entity_id. An admin can claim it or assign an owner."
      toast={toast}
      // Long-standing asset-group behavior: only a literal `root`/`admin`
      // policy sees the ownership controls, not the wider delegated-admin
      // set. GUI gating only.
      isAdminPolicy={hasLiteralAdminPolicy}
    />
  );
}

interface ResourcePickerProps {
  available: string[];
  selected: string[];
  setSelected: React.Dispatch<React.SetStateAction<string[]>>;
  availSearch: string;
  setAvailSearch: (v: string) => void;
  selectedSearch: string;
  setSelectedSearch: (v: string) => void;
  freeform: string;
  setFreeform: (v: string) => void;
}

function ResourcePicker({
  available,
  selected,
  setSelected,
  availSearch,
  setAvailSearch,
  selectedSearch,
  setSelectedSearch,
  freeform,
  setFreeform,
}: ResourcePickerProps) {
  const [availActive, setAvailActive] = useState<string[]>([]);
  const [selectedActive, setSelectedActive] = useState<string[]>([]);

  const selectedSet = new Set(selected);
  const availFiltered = available
    .filter((r) => !selectedSet.has(r))
    .filter((r) => r.toLowerCase().includes(availSearch.toLowerCase()));
  const selectedFiltered = selected.filter((r) =>
    r.toLowerCase().includes(selectedSearch.toLowerCase()),
  );
  const availableSet = new Set(available);

  function toggleActive(
    item: string,
    list: string[],
    setter: React.Dispatch<React.SetStateAction<string[]>>,
    e: React.MouseEvent,
  ) {
    if (e.shiftKey && list.length > 0) {
      // Range select within the current filtered view
      const view =
        list === availActive ? availFiltered : selectedFiltered;
      const last = list[list.length - 1];
      const a = view.indexOf(last);
      const b = view.indexOf(item);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        setter(view.slice(lo, hi + 1));
        return;
      }
    }
    if (e.metaKey || e.ctrlKey) {
      setter(
        list.includes(item) ? list.filter((x) => x !== item) : [...list, item],
      );
      return;
    }
    setter([item]);
  }

  function moveToSelected() {
    if (availActive.length === 0) return;
    setSelected((prev) => Array.from(new Set([...prev, ...availActive])));
    setAvailActive([]);
  }

  function moveToAvailable() {
    if (selectedActive.length === 0) return;
    const toRemove = new Set(selectedActive);
    setSelected((prev) => prev.filter((x) => !toRemove.has(x)));
    setSelectedActive([]);
  }

  function moveAllToSelected() {
    setSelected((prev) => Array.from(new Set([...prev, ...availFiltered])));
    setAvailActive([]);
  }

  function moveAllToAvailable() {
    const toRemove = new Set(selectedFiltered);
    setSelected((prev) => prev.filter((x) => !toRemove.has(x)));
    setSelectedActive([]);
  }

  function addFreeformNow() {
    const extras = freeform
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (extras.length === 0) return;
    setSelected((prev) => Array.from(new Set([...prev, ...extras])));
    setFreeform("");
  }

  return (
    <div>
      <label className="block text-sm text-[var(--color-text-muted)] mb-1">
        Resources
      </label>
      <p className="text-xs text-[var(--color-text-muted)] mb-2">
        Resource names from the resources mount that belong to this group.
        Cmd/Ctrl-click or Shift-click for multi-select.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-2 items-stretch">
        {/* Available list */}
        <div className="flex flex-col min-w-0 border border-[var(--color-border)] rounded-lg bg-[var(--color-bg)]">
          <div className="px-2 py-1.5 text-xs text-[var(--color-text-muted)] border-b border-[var(--color-border)] flex items-center justify-between">
            <span>Available ({availFiltered.length})</span>
          </div>
          <div className="p-2 border-b border-[var(--color-border)]">
            <Input
              label=""
              value={availSearch}
              onChange={(e) => setAvailSearch(e.target.value)}
              placeholder="Search available…"
            />
          </div>
          <ul className="overflow-y-auto max-h-64 min-h-32 text-sm">
            {availFiltered.length === 0 ? (
              <li className="px-2 py-2 text-xs text-[var(--color-text-muted)]">
                {available.length === 0 ? "No resources available." : "No matches."}
              </li>
            ) : (
              availFiltered.map((r) => {
                const active = availActive.includes(r);
                return (
                  <li
                    key={r}
                    onClick={(e) => toggleActive(r, availActive, setAvailActive, e)}
                    onDoubleClick={() => {
                      setSelected((prev) => Array.from(new Set([...prev, r])));
                      setAvailActive([]);
                    }}
                    className={`px-2 py-1 cursor-pointer truncate ${
                      active
                        ? "bg-[var(--color-primary)] text-white"
                        : "hover:bg-[var(--color-surface-hover)]"
                    }`}
                    title={r}
                  >
                    {r}
                  </li>
                );
              })
            )}
          </ul>
        </div>

        {/* Move buttons */}
        <div className="flex sm:flex-col gap-2 items-center justify-center px-1">
          <button
            type="button"
            onClick={moveToSelected}
            disabled={availActive.length === 0}
            className="px-2 py-1 rounded border border-[var(--color-border)] text-sm hover:border-[var(--color-primary)] disabled:opacity-40 disabled:cursor-not-allowed"
            title="Add selected"
          >
            &gt;
          </button>
          <button
            type="button"
            onClick={moveAllToSelected}
            disabled={availFiltered.length === 0}
            className="px-2 py-1 rounded border border-[var(--color-border)] text-sm hover:border-[var(--color-primary)] disabled:opacity-40 disabled:cursor-not-allowed"
            title="Add all (filtered)"
          >
            &gt;&gt;
          </button>
          <button
            type="button"
            onClick={moveToAvailable}
            disabled={selectedActive.length === 0}
            className="px-2 py-1 rounded border border-[var(--color-border)] text-sm hover:border-[var(--color-primary)] disabled:opacity-40 disabled:cursor-not-allowed"
            title="Remove selected"
          >
            &lt;
          </button>
          <button
            type="button"
            onClick={moveAllToAvailable}
            disabled={selectedFiltered.length === 0}
            className="px-2 py-1 rounded border border-[var(--color-border)] text-sm hover:border-[var(--color-primary)] disabled:opacity-40 disabled:cursor-not-allowed"
            title="Remove all (filtered)"
          >
            &lt;&lt;
          </button>
        </div>

        {/* Selected list */}
        <div className="flex flex-col min-w-0 border border-[var(--color-border)] rounded-lg bg-[var(--color-bg)]">
          <div className="px-2 py-1.5 text-xs text-[var(--color-text-muted)] border-b border-[var(--color-border)]">
            Selected ({selectedFiltered.length}
            {selectedFiltered.length !== selected.length ? ` of ${selected.length}` : ""})
          </div>
          <div className="p-2 border-b border-[var(--color-border)]">
            <Input
              label=""
              value={selectedSearch}
              onChange={(e) => setSelectedSearch(e.target.value)}
              placeholder="Search selected…"
            />
          </div>
          <ul className="overflow-y-auto max-h-64 min-h-32 text-sm">
            {selectedFiltered.length === 0 ? (
              <li className="px-2 py-2 text-xs text-[var(--color-text-muted)]">
                {selected.length === 0 ? "Nothing selected yet." : "No matches."}
              </li>
            ) : (
              selectedFiltered.map((r) => {
                const active = selectedActive.includes(r);
                const orphan = !availableSet.has(r);
                return (
                  <li
                    key={r}
                    onClick={(e) =>
                      toggleActive(r, selectedActive, setSelectedActive, e)
                    }
                    onDoubleClick={() => {
                      setSelected((prev) => prev.filter((x) => x !== r));
                      setSelectedActive([]);
                    }}
                    className={`px-2 py-1 cursor-pointer truncate ${
                      active
                        ? "bg-[var(--color-primary)] text-white"
                        : "hover:bg-[var(--color-surface-hover)]"
                    } ${orphan && !active ? "italic text-[var(--color-text-muted)]" : ""}`}
                    title={orphan ? `${r} (not in resources mount)` : r}
                  >
                    {r}
                    {orphan && <span className="ml-1 text-xs">*</span>}
                  </li>
                );
              })
            )}
          </ul>
        </div>
      </div>
      {selected.some((r) => !availableSet.has(r)) && (
        <p className="text-xs text-[var(--color-text-muted)] mt-1">
          <span className="font-mono">*</span> Not present in the current resources mount.
        </p>
      )}
      <div className="flex gap-2 mt-2">
        <div className="flex-1">
          <Input
            label=""
            value={freeform}
            onChange={(e) => setFreeform(e.target.value)}
            placeholder="Add extra resources, comma-separated"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addFreeformNow();
              }
            }}
          />
        </div>
        <Button type="button" variant="secondary" onClick={addFreeformNow}>
          Add
        </Button>
      </div>
    </div>
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
