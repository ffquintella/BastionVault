import { useState, useEffect, useCallback } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Input, SecretInput, MaskedValue, Breadcrumb, EmptyState, Modal, useToast } from "../components/ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

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
  const [editPairs, setEditPairs] = useState<{ key: string; value: string }[]>([
    { key: "", value: "" },
  ]);

  // null = still loading, [] = no KV engines, non-empty = available KV mounts
  const [kvMounts, setKvMounts] = useState<KvMount[] | null>(null);

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
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newKey) return;
    const data: Record<string, string> = {};
    for (const pair of editPairs) {
      if (pair.key) data[pair.key] = pair.value;
    }
    try {
      await api.writeSecret(currentPath + newKey, data, mountBase, mountType);
      toast("success", `Created ${newKey}`);
      setShowCreate(false);
      setNewKey("");
      setEditPairs([{ key: "", value: "" }]);
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
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
          <div className="flex gap-4">
            {/* Key list */}
            <Card className="w-72 shrink-0" title="Keys">
              {loading ? (
                <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
              ) : keys.length === 0 ? (
                <EmptyState title="No secrets" description="Create your first secret" />
              ) : (
                <div className="space-y-0.5 -mx-1">
                  {keys.map((key) => (
                    <button
                      key={key}
                      onClick={() => handleSelectKey(key)}
                      className={`w-full text-left px-3 py-1.5 rounded text-sm transition-colors ${
                        selectedKey === key
                          ? "bg-[var(--color-primary)] text-white"
                          : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                      }`}
                    >
                      {key.endsWith("/") ? `${key}` : key}
                    </button>
                  ))}
                </div>
              )}
            </Card>

            {/* Secret detail */}
            <Card className="flex-1" title={selectedKey || "Select a secret"}>
              {selectedKey ? (
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
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => handleDelete(selectedKey)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No secret selected"
                  description="Select a key from the list to view its contents"
                />
              )}
            </Card>
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
            <div className="space-y-2">
              <label className="block text-sm font-medium text-[var(--color-text-muted)]">
                Key-Value Pairs
              </label>
              {editPairs.map((pair, i) => (
                <div key={i} className="flex gap-2">
                  <Input
                    placeholder="key"
                    value={pair.key}
                    onChange={(e) => {
                      const updated = [...editPairs];
                      updated[i] = { ...pair, key: e.target.value };
                      setEditPairs(updated);
                    }}
                  />
                  <SecretInput
                    placeholder="value"
                    value={pair.value}
                    onChange={(e) => {
                      const updated = [...editPairs];
                      updated[i] = { ...pair, value: e.target.value };
                      setEditPairs(updated);
                    }}
                    className="flex-1"
                  />
                  {editPairs.length > 1 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditPairs(editPairs.filter((_, j) => j !== i))}
                    >
                      &times;
                    </Button>
                  )}
                </div>
              ))}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setEditPairs([...editPairs, { key: "", value: "" }])}
              >
                + Add pair
              </Button>
            </div>
          </div>
        </Modal>
      </div>
    </Layout>
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

