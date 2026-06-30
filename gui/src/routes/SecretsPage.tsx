import { useState, useEffect, useCallback, useMemo } from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  Input,
  MaskedValue,
  Breadcrumb,
  EmptyState,
  EntityLabel,
  EntityPicker,
  GroupsSection,
  Modal,
  Select,
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

  // Per-environment view (KV v2). `selectedEnv === null` means the base
  // (shared) set; otherwise the merged base+overrides for that environment.
  // `availableEnvs` comes from the read response, `engineEnvs` from the mount's
  // config registry, and `baseData` lets us flag inherited vs overridden keys.
  const [selectedEnv, setSelectedEnv] = useState<string | null>(null);
  const [availableEnvs, setAvailableEnvs] = useState<string[]>([]);
  const [engineEnvs, setEngineEnvs] = useState<string[]>([]);
  const [baseData, setBaseData] = useState<Record<string, unknown>>({});
  // Optional environment for a brand-new secret (blank = base/shared).
  const [newEnv, setNewEnv] = useState("");

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
  // Stack of group filters applied as an AND chain. Empty means "no
  // filter, show every group with secrets under the current prefix".
  // Each entry deeper drills further into the faceted intersection.
  const [groupFilters, setGroupFilters] = useState<string[]>([]);

  // Resolve the asset-groups a given leaf key belongs to. Checks both
  // the full logical path (currentPath + key) and the bare
  // key name — a user who typed just "test1" into the group editor
  // without the "secret/" prefix should still see the chip here.
  function groupsForKey(key: string): string[] {
    if (key.endsWith("/")) return [];
    const fullPath = canonicalizeSecretPath(currentPath + key);
    const keyOnly = canonicalizeSecretPath(currentPath + key);
    const out = new Set<string>();
    for (const g of assetGroups.map.bySecret[fullPath] || []) out.add(g);
    if (keyOnly !== fullPath) {
      for (const g of assetGroups.map.bySecret[keyOnly] || []) out.add(g);
    }
    return Array.from(out).sort();
  }

  // Set of canonical secret paths under the current path prefix that
  // belong to ALL currently-active group filters. This is the working
  // set used to (a) decide which sibling groups still have material to
  // offer as a next drill-down step and (b) filter the keys list.
  const currentPrefix = canonicalizeSecretPath(currentPath);
  const matchingSecrets = new Set<string>();
  for (const [secretPath, groups] of Object.entries(assetGroups.map.bySecret)) {
    const underPrefix =
      !currentPrefix ||
      secretPath === currentPrefix ||
      secretPath.startsWith(currentPrefix + "/");
    if (!underPrefix) continue;
    if (groupFilters.every((g) => groups.includes(g))) {
      matchingSecrets.add(secretPath);
    }
  }

  // Group cards above the key list: at the root level (no filter)
  // every group with secrets under the prefix; once one or more
  // filters are active, every OTHER group whose secrets intersect the
  // current working set, so the user can drill further into the
  // facet. Counts are intersection sizes against the working set.
  const groupCounts = new Map<string, number>();
  for (const secretPath of matchingSecrets) {
    for (const g of assetGroups.map.bySecret[secretPath] || []) {
      if (groupFilters.includes(g)) continue;
      groupCounts.set(g, (groupCounts.get(g) || 0) + 1);
    }
  }
  const groupOptions = Array.from(groupCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.name.localeCompare(b.name));

  // True when the listing entry is or contains a secret in the working
  // set. Folders match if any descendant is in the set.
  function keyMatchesFilters(key: string): boolean {
    if (groupFilters.length === 0) return true;
    if (!key.endsWith("/")) {
      const full = canonicalizeSecretPath(currentPath + key);
      return matchingSecrets.has(full);
    }
    const folderPrefix = canonicalizeSecretPath(currentPath + key);
    for (const p of matchingSecrets) {
      if (p === folderPrefix || p.startsWith(folderPrefix + "/")) return true;
    }
    return false;
  }

  const visibleKeys = keys.filter(keyMatchesFilters);

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

  // Map from leaf key name -> owner entity_id ("" for unowned). Used
  // to render an owner badge next to each secret in the listing.
  // Folder entries are not present.
  const [ownerByKey, setOwnerByKey] = useState<Record<string, string>>({});
  const callerEntityId = useAuthStore((s) => s.entityId);

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

  // After the key list refreshes, fetch ownership for every leaf in
  // parallel. Best-effort: any individual failure leaves that key
  // without a badge rather than blocking the whole listing.
  useEffect(() => {
    if (!keys || keys.length === 0) {
      setOwnerByKey({});
      return;
    }
    let cancelled = false;
    const leaves = keys.filter((k) => !k.endsWith("/"));
    Promise.all(
      leaves.map(async (k) => {
        // `currentPath` already carries the mount prefix (it is seeded
        // from the mount path and folder clicks append to it), so do NOT
        // prepend `mountBase` again — that would double it
        // (e.g. "secret/secret/tests/...") and the owner lookup would
        // miss, mislabelling every owned secret as "unowned". Mirrors the
        // path built for the owner/share detail panel.
        const full = canonicalizeSecretPath(currentPath + k);
        try {
          const o = await api.getKvOwner(full);
          return [k, o?.owned ? o.entity_id : ""] as const;
        } catch {
          return [k, ""] as const;
        }
      }),
    ).then((rows) => {
      if (cancelled) return;
      const next: Record<string, string> = {};
      for (const [k, v] of rows) next[k] = v;
      setOwnerByKey(next);
    });
    return () => {
      cancelled = true;
    };
  }, [keys, currentPath, mountBase]);

  useEffect(() => {
    if (currentPath) {
      loadKeys();
      setSelectedKey(null);
      setSecretData({});
      setEditingSecret(false);
    }
  }, [currentPath, loadKeys]);

  // Load the mount's advisory environment list (KV v2 only) so the env
  // selector can offer it as a dropdown. Failures are non-fatal — the
  // selector still surfaces any envs a secret already declares.
  useEffect(() => {
    if (mountType !== "kv-v2" || !mountBase) {
      setEngineEnvs([]);
      return;
    }
    api
      .readKvV2EngineConfig(mountBase)
      .then((cfg) => setEngineEnvs(cfg.environments ?? []))
      .catch(() => setEngineEnvs([]));
  }, [mountBase, mountType]);

  // Base (shared) + the union of registry and secret-declared environments.
  const envOptions = useMemo(() => {
    const set = new Set<string>([...engineEnvs, ...availableEnvs]);
    return [
      { value: "__base__", label: "Base (shared)" },
      ...Array.from(set).sort().map((e) => ({ value: e, label: e })),
    ];
  }, [engineEnvs, availableEnvs]);

  async function handleSelectKey(key: string) {
    if (key.endsWith("/")) {
      setCurrentPath(currentPath + key);
      return;
    }
    try {
      const result = await api.readSecret(currentPath + key, mountBase, mountType);
      setSelectedKey(key);
      setSecretData(result.data);
      setBaseData(result.data);
      setAvailableEnvs(result.available_envs ?? []);
      setSelectedEnv(null);
      setEditingSecret(false);
      setShowHistory(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  /** Switch the detail view to a different environment (or `null` for the
   *  shared base) by re-reading the secret with the env selector. */
  async function selectEnv(env: string | null) {
    if (!selectedKey) return;
    try {
      const result = await api.readSecret(
        currentPath + selectedKey,
        mountBase,
        mountType,
        env ?? undefined,
      );
      setSelectedEnv(env);
      setSecretData(result.data);
      if (env === null) setBaseData(result.data);
      if (result.available_envs) setAvailableEnvs(result.available_envs);
      setEditingSecret(false);
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

  /** Soft-delete a single version. The data stays in storage so the
   *  operator can recover it via `undelete`. */
  async function handleSoftDeleteVersion(version: number) {
    if (!selectedKey) return;
    await api.softDeleteSecretVersions(
      currentPath + selectedKey,
      [version],
      mountBase,
      mountType,
    );
    toast("success", `Soft-deleted v${version} of ${selectedKey}`);
    await openHistory();
  }

  /** Recover a soft-deleted version (clears its `deletion_time`). No-op
   *  on a destroyed version — the underlying data is already gone. */
  async function handleUndeleteVersion(version: number) {
    if (!selectedKey) return;
    await api.undeleteSecretVersions(
      currentPath + selectedKey,
      [version],
      mountBase,
      mountType,
    );
    toast("success", `Undeleted v${version} of ${selectedKey}`);
    await openHistory();
  }

  /** Irreversible — wipes the version's data from storage and flips its
   *  `destroyed` flag on metadata. Once destroyed, the version cannot be
   *  recovered even via `undelete`. */
  async function handleDestroyVersion(version: number) {
    if (!selectedKey) return;
    await api.destroySecretVersions(
      currentPath + selectedKey,
      [version],
      mountBase,
      mountType,
    );
    toast("success", `Destroyed v${version} of ${selectedKey}`);
    await openHistory();
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
      const env = newEnv.trim();
      if (env && mountType === "kv-v2") {
        await api.writeSecretEnv(
          currentPath + newKey,
          env,
          dataFromPairs(createPairs),
          mountBase,
          mountType,
        );
      } else {
        await api.writeSecret(
          currentPath + newKey,
          dataFromPairs(createPairs),
          mountBase,
          mountType,
        );
      }
      toast("success", `Created ${newKey}${env ? ` (${env})` : ""}`);
      setShowCreate(false);
      setNewKey("");
      setNewEnv("");
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
      if (selectedEnv) {
        // Env view: persist the edited pairs as this environment's overrides.
        await api.writeSecretEnv(currentPath + selectedKey, selectedEnv, data, mountBase, mountType);
      } else {
        await api.writeSecret(currentPath + selectedKey, data, mountBase, mountType);
      }
      toast("success", `Updated ${selectedKey}${selectedEnv ? ` (${selectedEnv})` : ""}`);
      const refreshed = await api.readSecret(
        currentPath + selectedKey,
        mountBase,
        mountType,
        selectedEnv ?? undefined,
      );
      setSecretData(refreshed.data);
      if (!selectedEnv) setBaseData(refreshed.data);
      if (refreshed.available_envs) setAvailableEnvs(refreshed.available_envs);
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
            {groupFilters.length > 0 && (
              <div className="flex flex-wrap items-center gap-1 text-sm">
                <button
                  type="button"
                  onClick={() => setGroupFilters([])}
                  className="text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
                >
                  All groups
                </button>
                {groupFilters.map((g, i) => (
                  <span key={g} className="flex items-center gap-1">
                    <span className="text-[var(--color-text-muted)]">/</span>
                    <button
                      type="button"
                      onClick={() => setGroupFilters(groupFilters.slice(0, i + 1))}
                      className={
                        i === groupFilters.length - 1
                          ? "text-[var(--color-text)] font-medium"
                          : "text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
                      }
                    >
                      {g}
                    </button>
                  </span>
                ))}
              </div>
            )}
            <GroupsSection
              groups={groupOptions}
              selected={null}
              onSelect={(name) => {
                if (name) setGroupFilters([...groupFilters, name]);
              }}
              itemKindPlural="secrets"
            />

            <div className="flex gap-4">
            {/* Key list */}
            <Card className="w-72 shrink-0" title="Keys">
              {loading ? (
                <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
              ) : visibleKeys.length === 0 ? (
                <EmptyState
                  title={groupFilters.length > 0 ? "No secrets in this group" : "No secrets"}
                  description={
                    groupFilters.length > 0
                      ? "Clear the group filter to see all secrets"
                      : "Create your first secret"
                  }
                />
              ) : (
                <div className="space-y-0.5 -mx-1">
                  {visibleKeys.map((key) => {
                    const groups = groupsForKey(key);
                    const isFolder = key.endsWith("/");
                    const ownerId = isFolder ? undefined : ownerByKey[key];
                    const ownerKnown = ownerId !== undefined;
                    const ownerSelf =
                      ownerKnown &&
                      ownerId !== "" &&
                      callerEntityId !== "" &&
                      ownerId === callerEntityId;
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
                          <div className="flex items-center justify-between gap-2 min-w-0">
                            <span className="truncate">{key}</span>
                            {!isFolder && ownerKnown && (
                              <span
                                className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] ${
                                  ownerId === ""
                                    ? "bg-[var(--color-warning)] text-black"
                                    : ownerSelf
                                      ? "bg-[var(--color-success)] text-white"
                                      : "bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]"
                                }`}
                                title={
                                  ownerId === ""
                                    ? "Unowned — next write captures ownership"
                                    : ownerSelf
                                      ? "Owned by you"
                                      : `Owned by ${ownerId}`
                                }
                              >
                                {ownerId === ""
                                  ? "unowned"
                                  : ownerSelf
                                    ? "you"
                                    : "owned"}
                              </span>
                            )}
                          </div>
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
                    onSoftDelete={
                      mountType === "kv-v2" ? handleSoftDeleteVersion : undefined
                    }
                    onUndelete={
                      mountType === "kv-v2" ? handleUndeleteVersion : undefined
                    }
                    onDestroy={
                      mountType === "kv-v2" ? handleDestroyVersion : undefined
                    }
                    onClose={() => setShowHistory(false)}
                  />
                ) : editingSecret ? (
                  <div className="space-y-3">
                    {mountType === "kv-v2" && (
                      <p className="text-sm text-[var(--color-text-muted)]">
                        Editing{" "}
                        <span className="font-medium text-[var(--color-text)]">
                          {selectedEnv ? `environment "${selectedEnv}"` : "base (shared)"}
                        </span>
                        {selectedEnv &&
                          " — saved keys become overrides for this environment."}
                      </p>
                    )}
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
                    {mountType === "kv-v2" && envOptions.length > 1 && (
                      <div className="flex items-end gap-2">
                        <Select
                          label="Environment"
                          className="max-w-[14rem]"
                          options={envOptions}
                          value={selectedEnv ?? "__base__"}
                          onChange={(e) =>
                            selectEnv(e.target.value === "__base__" ? null : e.target.value)
                          }
                        />
                        {selectedEnv && (
                          <span className="pb-2">
                            <Badge variant="info" label={`base + ${selectedEnv} overrides`} />
                          </span>
                        )}
                      </div>
                    )}
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-[var(--color-text-muted)] text-left">
                          <th className="pb-2 font-medium">Key</th>
                          <th className="pb-2 font-medium">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(secretData).map(([k, v]) => {
                          const overridden =
                            selectedEnv != null &&
                            (!(k in baseData) || String(baseData[k]) !== String(v));
                          return (
                            <tr key={k} className="border-t border-[var(--color-border)]">
                              <td className="py-2 font-mono text-[var(--color-primary)]">
                                <span className="min-w-0 truncate">{k}</span>
                                {selectedEnv && (
                                  <span
                                    className={`ml-2 text-[10px] uppercase tracking-wide ${
                                      overridden
                                        ? "text-[var(--color-primary)]"
                                        : "text-[var(--color-text-muted)]"
                                    }`}
                                  >
                                    {overridden ? "override" : "inherited"}
                                  </span>
                                )}
                              </td>
                              <td className="py-2 font-mono">
                                <MaskedValue value={String(v)} />
                              </td>
                            </tr>
                          );
                        })}
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
            {mountType === "kv-v2" && (
              <Input
                label="Environment (optional)"
                value={newEnv}
                onChange={(e) => setNewEnv(e.target.value)}
                placeholder="leave blank for base / shared"
              />
            )}
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
              fullPath={canonicalizeSecretPath(currentPath + shareTarget)}
              displayPath={currentPath + shareTarget}
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

  async function handleClaim() {
    try {
      await api.claimKvOwner(fullPath);
      toast("success", "Ownership claimed");
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
          <div className="flex items-center gap-2">
            {!owner?.owned && (
              <Button size="sm" variant="secondary" onClick={handleClaim}>
                Claim ownership
              </Button>
            )}
            {isAdmin && (
              <Button size="sm" variant="ghost" onClick={() => setShowTransfer(true)}>
                {owner?.owned ? "Transfer" : "Assign owner"}
              </Button>
            )}
          </div>
        </div>
        {owner?.owned ? (
          <div className="flex items-center gap-2">
            <EntityLabel entityId={owner.entity_id} callerEntityId={entityId} />
            {isOwner && <Badge label="You" variant="success" />}
          </div>
        ) : (
          <p className="text-xs text-[var(--color-text-muted)] italic">
            Unowned. Click <strong>Claim ownership</strong> to capture this
            path, or wait for the next authenticated write.
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
                  <EntityLabel entityId={s.grantee_entity_id} />
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
