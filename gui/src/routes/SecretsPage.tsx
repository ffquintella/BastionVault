import { useState, useEffect, useCallback } from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  Input,
  MaskedValue,
  Breadcrumb,
  EmptyState,
  EntityPicker,
  GroupsSection,
  Modal,
  SecretPairsEditor,
  SecretHistoryPanel,
  Table,
  pairsFromData,
  dataFromPairs,
  type SecretPair,
  type SecretHistoryVersion,
  useToast,
} from "../components/ui";
import type { OwnerInfo, ShareEntry } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { useAuthStore } from "../stores/authStore";
import { useAssetGroupMap, canonicalizeSecretPath } from "../hooks/useAssetGroupMap";

type KvMount = { path: string; mount_type: string };

export function SecretsPage() {
  const { toast } = useToast();
  const [currentPath, setCurrentPath] = useState("");
  const [mountBase, setMountBase] = useState(""); // e.g. "secret/"
  const [mountType, setMountType] = useState(""); // "kv" or "kv-v2"
  const [keys, setKeys] = useState<string[]>([]);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [secretData, setSecretData] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [createPairs, setCreatePairs] = useState<SecretPair[]>([
    { key: "", value: "" },
  ]);

  // In-place edit of the currently-selected secret.
  const [editingSecret, setEditingSecret] = useState(false);
  const [editPairs, setEditPairs] = useState<SecretPair[]>([]);
  const [savingEdit, setSavingEdit] = useState(false);

  // Sharing: modal and target key for the currently-selected secret.
  // `shareTarget` is the leaf key name (same as `selectedKey`) — we
  // hold a separate piece of state so closing the modal doesn't reset
  // the rest of the detail view, and so the shares-subsection can
  // show a stable target even if the user navigates away.
  const [shareTarget, setShareTarget] = useState<string | null>(null);

  // History view (KV-v2 version timeline) of the currently-selected secret.
  const [showHistory, setShowHistory] = useState(false);
  const [versions, setVersions] = useState<SecretHistoryVersion[]>([]);
  const [loadingVersions, setLoadingVersions] = useState(false);

  // null = still loading, [] = no KV engines, non-empty = available KV mounts
  const [kvMounts, setKvMounts] = useState<KvMount[] | null>(null);

  const assetGroups = useAssetGroupMap();
  const [filterGroup, setFilterGroup] = useState<string | null>(null);

  // Resolve the asset-groups a given leaf key belongs to. Checks both
  // the full logical path (mountBase + currentPath + key) and the bare
  // key name — a user who typed just "test1" into the group editor
  // without the "secret/" prefix should still see the chip here.
  function groupsForKey(key: string): string[] {
    if (key.endsWith("/")) return [];
    const fullPath = canonicalizeSecretPath(mountBase + currentPath + key);
    const keyOnly = canonicalizeSecretPath(currentPath + key);
    const out = new Set<string>();
    for (const g of assetGroups.map.bySecret[fullPath] || []) out.add(g);
    if (keyOnly !== fullPath) {
      for (const g of assetGroups.map.bySecret[keyOnly] || []) out.add(g);
    }
    return Array.from(out).sort();
  }

  // Group cards above the key list: one per group that contains at
  // least one of the currently-listed leaf keys.
  const groupCounts = new Map<string, number>();
  for (const k of keys) {
    for (const g of groupsForKey(k)) {
      groupCounts.set(g, (groupCounts.get(g) || 0) + 1);
    }
  }
  const groupOptions = Array.from(groupCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const visibleKeys = filterGroup
    ? keys.filter((k) => groupsForKey(k).includes(filterGroup))
    : keys;

  // Load the list of KV mounts once. Used both for auto-selecting a single
  // mount (skipping the picker) and for rendering the picker when there is
  // more than one.
  useEffect(() => {
    api
      .listMounts()
      .then((ms) =>
        setKvMounts(
          ms.filter((m) => m.mount_type === "kv" || m.mount_type === "kv-v2"),
        ),
      )
      .catch(() => setKvMounts([]));
  }, []);

  // Auto-select when there is exactly one KV mount: jump straight into it
  // instead of showing a single-card picker.
  useEffect(() => {
    if (kvMounts && kvMounts.length === 1 && !mountBase) {
      const only = kvMounts[0];
      setMountBase(only.path);
      setMountType(only.mount_type);
      setCurrentPath(only.path);
    }
  }, [kvMounts, mountBase]);

  const hasMultipleMounts = (kvMounts?.length ?? 0) > 1;

  const loadKeys = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.listSecrets(currentPath, mountBase, mountType);
      setKeys(result.keys);
    } catch {
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }, [currentPath, mountBase, mountType]);

  useEffect(() => {
    if (currentPath) {
      loadKeys();
      setSelectedKey(null);
      setSecretData({});
      setEditingSecret(false);
    }
  }, [currentPath, loadKeys]);

  async function handleSelectKey(key: string) {
    if (key.endsWith("/")) {
      setCurrentPath(currentPath + key);
      return;
    }
    try {
      const result = await api.readSecret(currentPath + key, mountBase, mountType);
      setSelectedKey(key);
      setSecretData(result.data);
      setEditingSecret(false);
      setShowHistory(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openHistory() {
    if (!selectedKey) return;
    setShowHistory(true);
    setLoadingVersions(true);
    try {
      const result = await api.listSecretVersions(
        currentPath + selectedKey,
        mountBase,
        mountType,
      );
      setVersions(result.versions);
    } catch (e: unknown) {
      toast("error", extractError(e));
      setVersions([]);
    } finally {
      setLoadingVersions(false);
    }
  }

  async function loadSecretVersionData(version: number) {
    if (!selectedKey) throw new Error("No secret selected");
    const result = await api.readSecretVersion(
      currentPath + selectedKey,
      version,
      mountBase,
      mountType,
    );
    return result.data;
  }

  async function handleRestoreVersion(version: number, data: Record<string, unknown>) {
    if (!selectedKey) return;
    // Vault writes require string values; stringify non-string values rather
    // than crashing on e.g. numbers that slipped into a legacy entry.
    const stringData: Record<string, string> = {};
    for (const [k, v] of Object.entries(data)) stringData[k] = String(v ?? "");
    try {
      await api.writeSecret(currentPath + selectedKey, stringData, mountBase, mountType);
      toast("success", `Restored ${selectedKey} from version ${version}`);
      // Reload the current value and the history after restore.
      const refreshed = await api.readSecret(
        currentPath + selectedKey,
        mountBase,
        mountType,
      );
      setSecretData(refreshed.data);
      await openHistory();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete(key: string) {
    try {
      await api.deleteSecret(currentPath + key, mountBase, mountType);
      toast("success", `Deleted ${key}`);
      setSelectedKey(null);
      setSecretData({});
      setEditingSecret(false);
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newKey) return;
    try {
      await api.writeSecret(
        currentPath + newKey,
        dataFromPairs(createPairs),
        mountBase,
        mountType,
      );
      toast("success", `Created ${newKey}`);
      setShowCreate(false);
      setNewKey("");
      setCreatePairs([{ key: "", value: "" }]);
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function startEdit() {
    setEditPairs(pairsFromData(secretData));
    setEditingSecret(true);
  }

  async function handleSaveEdit() {
    if (!selectedKey) return;
    const data = dataFromPairs(editPairs);
    if (Object.keys(data).length === 0) {
      toast("error", "At least one key-value pair is required.");
      return;
    }
    setSavingEdit(true);
    try {
      await api.writeSecret(currentPath + selectedKey, data, mountBase, mountType);
      toast("success", `Updated ${selectedKey}`);
      const refreshed = await api.readSecret(
        currentPath + selectedKey,
        mountBase,
        mountType,
      );
      setSecretData(refreshed.data);
      setEditingSecret(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSavingEdit(false);
    }
  }

  // Build breadcrumb segments. The "Mounts" root is only clickable/shown
  // when there are multiple KV mounts — with a single mount it is a dead
  // link (clicking it would just auto-select that same mount again).
  const pathParts = currentPath.split("/").filter(Boolean);
  const breadcrumbs = [
    ...(hasMultipleMounts
      ? [
          {
            label: "Mounts",
            onClick: () => {
              setCurrentPath("");
              setMountBase("");
              setMountType("");
            },
          },
        ]
      : []),
    ...pathParts.map((part, i) => ({
      label: part,
      onClick:
        i < pathParts.length - 1
          ? () => setCurrentPath(pathParts.slice(0, i + 1).join("/") + "/")
          : undefined,
    })),
  ];

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Secrets</h1>
          {currentPath && (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              New Secret
            </Button>
          )}
        </div>

        <Breadcrumb segments={breadcrumbs} />

        {!currentPath ? (
          kvMounts === null ? (
            <p className="text-sm text-[var(--color-text-muted)]">Loading mounts...</p>
          ) : kvMounts.length === 0 ? (
            <EmptyState
              title="No KV engines mounted"
              description="Mount a KV secret engine from the Mounts page to start managing secrets"
            />
          ) : (
            <MountSelector
              mounts={kvMounts}
              onSelect={(path, type_) => {
                setMountBase(path);
                setMountType(type_);
                setCurrentPath(path);
              }}
            />
          )
        ) : (
          <div className="flex flex-col gap-4">
            <GroupsSection
              groups={groupOptions}
              selected={filterGroup}
              onSelect={setFilterGroup}
              itemKindPlural="secrets"
            />

            <div className="flex gap-4">
            {/* Key list */}
            <Card className="w-72 shrink-0" title="Keys">
              {loading ? (
                <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
              ) : visibleKeys.length === 0 ? (
                <EmptyState
                  title={filterGroup ? "No secrets in this group" : "No secrets"}
                  description={
                    filterGroup
                      ? "Clear the group filter to see all secrets"
                      : "Create your first secret"
                  }
                />
              ) : (
                <div className="space-y-0.5 -mx-1">
                  {visibleKeys.map((key) => {
                    const groups = groupsForKey(key);
                    return (
                      <div key={key}>
                        <button
                          onClick={() => handleSelectKey(key)}
                          className={`w-full text-left px-3 py-1.5 rounded text-sm transition-colors ${
                            selectedKey === key
                              ? "bg-[var(--color-primary)] text-white"
                              : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                          }`}
                        >
                          {key}
                        </button>
                        {groups.length > 0 && (
                          <div className="flex flex-wrap gap-1 px-3 pb-1">
                            {groups.map((g) => (
                              <span
                                key={g}
                                className="px-1.5 py-0.5 bg-[var(--color-primary)] text-white rounded text-[10px]"
                                title={`Member of asset group "${g}"`}
                              >
                                {g}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>

            {/* Secret detail */}
            <Card className="flex-1" title={selectedKey || "Select a secret"}>
              {selectedKey ? (
                showHistory ? (
                  <SecretHistoryPanel
                    versions={versions}
                    loading={loadingVersions}
                    loadVersion={loadSecretVersionData}
                    onRestore={
                      mountType === "kv-v2" ? handleRestoreVersion : undefined
                    }
                    onClose={() => setShowHistory(false)}
                  />
                ) : editingSecret ? (
                  <div className="space-y-3">
                    <SecretPairsEditor pairs={editPairs} onChange={setEditPairs} />
                    <div className="flex gap-2 pt-2">
                      <Button
                        size="sm"
                        onClick={handleSaveEdit}
                        loading={savingEdit}
                        disabled={savingEdit}
                      >
                        Save
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setEditingSecret(false)}
                        disabled={savingEdit}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-[var(--color-text-muted)] text-left">
                          <th className="pb-2 font-medium">Key</th>
                          <th className="pb-2 font-medium">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(secretData).map(([k, v]) => (
                          <tr key={k} className="border-t border-[var(--color-border)]">
                            <td className="py-2 font-mono text-[var(--color-primary)]">{k}</td>
                            <td className="py-2 font-mono">
                              <MaskedValue value={String(v)} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <div className="flex gap-2 pt-2">
                      <Button size="sm" onClick={startEdit}>
                        Edit
                      </Button>
                      {mountType === "kv-v2" && (
                        <Button size="sm" variant="secondary" onClick={openHistory}>
                          History
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setShareTarget(selectedKey)}
                      >
                        Share
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => handleDelete(selectedKey)}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                )
              ) : (
                <EmptyState
                  title="No secret selected"
                  description="Select a key from the list to view its contents"
                />
              )}
            </Card>
            </div>
          </div>
        )}

        {/* Create secret modal */}
        <Modal
          open={showCreate}
          onClose={() => setShowCreate(false)}
          title="Create Secret"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!newKey}>
                Create
              </Button>
            </>
          }
        >
          <div className="space-y-4">
            <Input
              label="Key Name"
              value={newKey}
              onChange={(e) => setNewKey(e.target.value)}
              placeholder="my-secret"
            />
            <SecretPairsEditor pairs={createPairs} onChange={setCreatePairs} />
          </div>
        </Modal>

        {/* Share secret modal */}
        <Modal
          open={shareTarget !== null}
          onClose={() => setShareTarget(null)}
          title={`Share ${shareTarget ?? ""}`}
          size="lg"
        >
          {shareTarget && (
            <SecretSharingPanel
              fullPath={canonicalizeSecretPath(mountBase + currentPath + shareTarget)}
              displayPath={mountBase + currentPath + shareTarget}
              onClose={() => setShareTarget(null)}
            />
          )}
        </Modal>
      </div>
    </Layout>
  );
}

/**
 * Owner card + shares table + grant/revoke + admin transfer, all
 * scoped to a single KV-secret path. `fullPath` is the canonical
 * logical path (`secret/foo/bar`, NOT the KV-v2 `secret/data/foo/bar`
 * form) — `ShareStore::canonicalize_kv_path` accepts either, but we
 * pass the canonical form so UI-side comparisons to the returned
 * share records line up.
 */
function SecretSharingPanel({
  fullPath,
  displayPath,
  onClose,
}: {
  fullPath: string;
  displayPath: string;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [owner, setOwner] = useState<OwnerInfo | null>(null);
  const [shares, setShares] = useState<ShareEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const policies = useAuthStore((s) => s.policies);
  const entityId = useAuthStore((s) => s.entityId);
  const isAdmin = policies.some((p) => p === "root" || p === "admin");
  const isOwner =
    owner?.owned === true && owner.entity_id === entityId && entityId !== "";
  const canGrant = isOwner || isAdmin;

  const [grantee, setGrantee] = useState("");
  const [caps, setCaps] = useState<string[]>(["read"]);
  const [expires, setExpires] = useState("");

  const [showTransfer, setShowTransfer] = useState(false);
  const [newOwner, setNewOwner] = useState("");

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fullPath]);

  async function load() {
    setLoading(true);
    try {
      const [o, s] = await Promise.all([
        api.getKvOwner(fullPath).catch(() => null),
        api.listSharesForTarget("kv-secret", fullPath).catch(() => [] as ShareEntry[]),
      ]);
      setOwner(o);
      setShares(s);
    } finally {
      setLoading(false);
    }
  }

  async function handleGrant() {
    try {
      await api.putShare("kv-secret", fullPath, grantee.trim(), caps, expires.trim());
      toast("success", "Share granted");
      setGrantee("");
      setCaps(["read"]);
      setExpires("");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke(s: ShareEntry) {
    try {
      await api.deleteShare("kv-secret", s.target_path, s.grantee_entity_id);
      toast("success", "Share revoked");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleTransfer() {
    try {
      await api.transferKvOwner(fullPath, newOwner.trim());
      toast("success", "Ownership transferred");
      setShowTransfer(false);
      setNewOwner("");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function toggleCap(c: string) {
    setCaps((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]));
  }

  if (loading) {
    return (
      <p className="text-sm text-[var(--color-text-muted)] py-4">Loading...</p>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
          Secret path
        </label>
        <code className="font-mono text-xs break-all">{displayPath}</code>
      </div>

      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="text-xs font-medium text-[var(--color-text-muted)]">
            Owner
          </label>
          {isAdmin && (
            <Button size="sm" variant="ghost" onClick={() => setShowTransfer(true)}>
              Transfer
            </Button>
          )}
        </div>
        {owner?.owned ? (
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs">{owner.entity_id}</span>
            {isOwner && <Badge label="You" variant="success" />}
          </div>
        ) : (
          <p className="text-xs text-[var(--color-text-muted)] italic">
            Unowned. The next authenticated write to this path captures ownership.
          </p>
        )}
      </div>

      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="text-xs font-medium text-[var(--color-text-muted)]">
            Shares
          </label>
        </div>
        {shares.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)] italic">
            Nobody else has access via an explicit share.
          </p>
        ) : (
          <Table
            columns={[
              {
                key: "grantee",
                header: "Grantee",
                render: (s: ShareEntry) => (
                  <span className="font-mono text-xs truncate">
                    {s.grantee_entity_id}
                  </span>
                ),
              },
              {
                key: "caps",
                header: "Capabilities",
                render: (s: ShareEntry) => (
                  <div className="flex flex-wrap gap-1">
                    {s.capabilities.map((c) => (
                      <Badge key={c} label={c} variant="info" />
                    ))}
                  </div>
                ),
              },
              {
                key: "expires",
                header: "Expires",
                render: (s: ShareEntry) =>
                  s.expires_at ? (
                    <span
                      className={`text-xs ${
                        s.expired
                          ? "text-[var(--color-danger)]"
                          : "text-[var(--color-text-muted)]"
                      }`}
                    >
                      {s.expires_at}
                      {s.expired && " (expired)"}
                    </span>
                  ) : (
                    <span className="text-xs text-[var(--color-text-muted)]">never</span>
                  ),
              },
              {
                key: "revoke",
                header: "",
                className: "text-right w-24",
                render: (s: ShareEntry) =>
                  canGrant ? (
                    <Button variant="danger" size="sm" onClick={() => handleRevoke(s)}>
                      Revoke
                    </Button>
                  ) : null,
              },
            ]}
            data={shares}
            rowKey={(s: ShareEntry) => s.grantee_entity_id}
          />
        )}
      </div>

      {canGrant && (
        <div className="border-t border-[var(--color-border)] pt-3 space-y-3">
          <h4 className="text-sm font-medium">Grant access</h4>
          <EntityPicker
            label="Grantee"
            value={grantee}
            onChange={(id) => setGrantee(id)}
            placeholder="Search by login or paste entity_id"
          />
          <div>
            <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
              Capabilities
            </label>
            <div className="flex flex-wrap gap-2">
              {(["read", "list", "update", "delete", "create"] as const).map((c) => {
                const selected = caps.includes(c);
                return (
                  <button
                    key={c}
                    type="button"
                    onClick={() => toggleCap(c)}
                    className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                      selected
                        ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                        : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                    }`}
                  >
                    {c}
                  </button>
                );
              })}
            </div>
          </div>
          <Input
            label="Expires at (optional)"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            placeholder="2026-12-31T23:59:59Z"
            hint="RFC3339 timestamp. Leave empty for no expiry."
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Close
            </Button>
            <Button
              size="sm"
              onClick={handleGrant}
              disabled={!grantee.trim() || caps.length === 0}
            >
              Grant
            </Button>
          </div>
        </div>
      )}

      {!canGrant && (
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      )}

      <Modal
        open={showTransfer}
        onClose={() => setShowTransfer(false)}
        title={`Transfer ownership of ${displayPath}`}
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowTransfer(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleTransfer}
              disabled={!newOwner.trim()}
            >
              Transfer
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            Overwrite the owner record for this KV path. Admin-only. The new
            entity will pass the <code>scopes = ["owner"]</code> check on every
            subsequent request.
          </p>
          <EntityPicker
            label="New owner"
            value={newOwner}
            onChange={(id) => setNewOwner(id)}
            placeholder="Search by login or paste entity_id"
          />
        </div>
      </Modal>
    </div>
  );
}

function MountSelector({
  mounts,
  onSelect,
}: {
  mounts: KvMount[];
  onSelect: (path: string, mountType: string) => void;
}) {
  return (
    <div className="grid grid-cols-3 gap-3">
      {mounts.map((m) => (
        <button
          key={m.path}
          onClick={() => onSelect(m.path, m.mount_type)}
          className="p-4 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl text-left
            hover:border-[var(--color-primary)] hover:bg-[var(--color-surface-hover)] transition-colors"
        >
          <div className="font-mono text-[var(--color-primary)] font-medium">{m.path}</div>
          <div className="text-xs text-[var(--color-text-muted)] mt-1">{m.mount_type}</div>
        </button>
      ))}
    </div>
  );
}
