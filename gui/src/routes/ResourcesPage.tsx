import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Textarea,
  Badge,
  Tabs,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type { ResourceMetadata, MountInfo } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const BUILT_IN_TYPES = [
  { value: "server", label: "Server" },
  { value: "network_device", label: "Network Device" },
  { value: "website", label: "Website" },
  { value: "database", label: "Database" },
  { value: "application", label: "Application" },
  { value: "_custom", label: "Custom..." },
];

const TYPE_LABELS: Record<string, string> = {
  server: "Server",
  network_device: "Network Device",
  website: "Website",
  database: "Database",
  application: "Application",
};

const TYPE_BADGE_VARIANT: Record<string, "info" | "success" | "warning" | "error" | "neutral"> = {
  server: "info",
  network_device: "warning",
  website: "success",
  database: "error",
  application: "neutral",
};

function emptyResource(): ResourceMetadata {
  return {
    _resource: true,
    name: "",
    type: "server",
    hostname: "",
    ip_address: "",
    port: 0,
    os: "",
    location: "",
    owner: "",
    tags: [],
    notes: "",
    created_at: "",
    updated_at: "",
  };
}

export function ResourcesPage() {
  const { toast } = useToast();
  const [mount, setMount] = useState("");
  const [resources, setResources] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [resourceInfo, setResourceInfo] = useState<ResourceMetadata | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [filterType, setFilterType] = useState("");
  const [search, setSearch] = useState("");

  // Store loaded metadata for filtering
  const [allMeta, setAllMeta] = useState<ResourceMetadata[]>([]);

  useEffect(() => {
    if (mount) loadResources();
  }, [mount]);

  async function loadResources() {
    setLoading(true);
    try {
      const result = await api.listResources(mount);
      setResources(result.resources);

      // Load all metadata for cards
      const metas = await Promise.all(
        result.resources.map((name) =>
          api.readResource(mount, name).catch(() => null),
        ),
      );
      setAllMeta(metas.filter((m): m is ResourceMetadata => m !== null));
    } catch {
      setResources([]);
      setAllMeta([]);
    } finally {
      setLoading(false);
    }
  }

  async function selectResource(name: string) {
    try {
      const info = await api.readResource(mount, name);
      setSelected(name);
      setResourceInfo(info);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteResource(mount, deleteTarget);
      toast("success", `Resource ${deleteTarget} deleted`);
      if (selected === deleteTarget) {
        setSelected(null);
        setResourceInfo(null);
      }
      setDeleteTarget(null);
      loadResources();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  // Filter resources
  const filteredMeta = allMeta.filter((m) => {
    if (filterType && m.type !== filterType) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        m.name.toLowerCase().includes(q) ||
        m.hostname.toLowerCase().includes(q) ||
        m.ip_address.includes(q) ||
        m.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  if (!mount) {
    return (
      <Layout>
        <div className="max-w-4xl space-y-4">
          <h1 className="text-2xl font-bold">Resources</h1>
          <MountSelector onSelect={setMount} />
        </div>
      </Layout>
    );
  }

  if (selected && resourceInfo) {
    return (
      <Layout>
        <div className="max-w-5xl space-y-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setSelected(null);
                setResourceInfo(null);
              }}
              className="text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
            >
              &larr; Back
            </button>
            <h1 className="text-2xl font-bold">{resourceInfo.name}</h1>
            <Badge
              label={TYPE_LABELS[resourceInfo.type] || resourceInfo.type}
              variant={TYPE_BADGE_VARIANT[resourceInfo.type] || "neutral"}
            />
          </div>
          <ResourceDetail
            mount={mount}
            resource={resourceInfo}
            onUpdate={() => selectResource(selected)}
            onDelete={() => setDeleteTarget(selected)}
            toast={toast}
          />
          <ConfirmModal
            open={deleteTarget !== null}
            onClose={() => setDeleteTarget(null)}
            onConfirm={handleDelete}
            title="Delete Resource"
            message={`Delete "${deleteTarget}" and ALL its secrets? This cannot be undone.`}
            confirmLabel="Delete"
          />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="max-w-5xl space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Resources</h1>
          <div className="flex gap-2">
            <button
              onClick={() => setMount("")}
              className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
            >
              Change mount
            </button>
            <Button size="sm" onClick={() => setShowCreate(true)}>
              Add Resource
            </Button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-3">
          <Input
            placeholder="Search by name, hostname, IP, or tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1"
          />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All types</option>
            {BUILT_IN_TYPES.filter((t) => t.value !== "_custom").map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        {/* Resource grid */}
        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)] py-8 text-center">Loading...</p>
        ) : filteredMeta.length === 0 ? (
          <EmptyState
            title={resources.length === 0 ? "No resources" : "No matching resources"}
            description={
              resources.length === 0
                ? "Add your first resource to start organizing secrets by infrastructure"
                : "Try a different search or filter"
            }
            action={
              resources.length === 0 ? (
                <Button size="sm" onClick={() => setShowCreate(true)}>
                  Add Resource
                </Button>
              ) : undefined
            }
          />
        ) : (
          <div className="grid grid-cols-2 gap-3">
            {filteredMeta.map((meta) => (
              <ResourceCard
                key={meta.name}
                meta={meta}
                onClick={() => selectResource(meta.name)}
              />
            ))}
          </div>
        )}

        <CreateResourceModal
          open={showCreate}
          onClose={() => setShowCreate(false)}
          mount={mount}
          onCreated={(name) => {
            setShowCreate(false);
            loadResources();
            selectResource(name);
          }}
          toast={toast}
        />
      </div>
    </Layout>
  );
}

// ── Resource Card ──────────────────────────────────────────────────

function ResourceCard({
  meta,
  onClick,
}: {
  meta: ResourceMetadata;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="p-4 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl text-left
        hover:border-[var(--color-primary)] hover:bg-[var(--color-surface-hover)] transition-colors"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-[var(--color-text)]">{meta.name}</span>
        <Badge
          label={TYPE_LABELS[meta.type] || meta.type}
          variant={TYPE_BADGE_VARIANT[meta.type] || "neutral"}
        />
      </div>
      {(meta.hostname || meta.ip_address) && (
        <p className="text-xs font-mono text-[var(--color-text-muted)] mb-2">
          {meta.hostname || meta.ip_address}
          {meta.port > 0 ? `:${meta.port}` : ""}
        </p>
      )}
      {meta.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {meta.tags.slice(0, 4).map((tag) => (
            <span
              key={tag}
              className="px-1.5 py-0.5 bg-[var(--color-bg)] rounded text-[10px] text-[var(--color-text-muted)]"
            >
              {tag}
            </span>
          ))}
          {meta.tags.length > 4 && (
            <span className="text-[10px] text-[var(--color-text-muted)]">
              +{meta.tags.length - 4}
            </span>
          )}
        </div>
      )}
    </button>
  );
}

// ── Mount Selector ─────────────────────────────────────────────────

function MountSelector({ onSelect }: { onSelect: (path: string) => void }) {
  const [mounts, setMounts] = useState<MountInfo[]>([]);

  useEffect(() => {
    api.listMounts().then(setMounts).catch(() => {});
  }, []);

  const kvMounts = mounts.filter(
    (m) => m.mount_type === "kv" || m.mount_type === "kv-v2",
  );

  if (kvMounts.length === 0) {
    return (
      <EmptyState
        title="No KV engines mounted"
        description="Mount a KV secret engine from the Mounts page to use Resources"
      />
    );
  }

  return (
    <div className="grid grid-cols-3 gap-3">
      {kvMounts.map((m) => (
        <button
          key={m.path}
          onClick={() => onSelect(m.path)}
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

// ── Resource Detail ────────────────────────────────────────────────

function ResourceDetail({
  mount,
  resource,
  onUpdate,
  onDelete,
  toast,
}: {
  mount: string;
  resource: ResourceMetadata;
  onUpdate: () => void;
  onDelete: () => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [tab, setTab] = useState("info");

  return (
    <>
      <Card>
        <Tabs
          tabs={[
            { id: "info", label: "Info" },
            { id: "secrets", label: "Secrets" },
          ]}
          active={tab}
          onChange={setTab}
        />
      </Card>

      {tab === "info" && (
        <ResourceInfoTab
          mount={mount}
          resource={resource}
          onUpdate={onUpdate}
          onDelete={onDelete}
          toast={toast}
        />
      )}

      {tab === "secrets" && (
        <ResourceSecretsTab mount={mount} resourceName={resource.name} toast={toast} />
      )}
    </>
  );
}

// ── Info Tab ───────────────────────────────────────────────────────

function ResourceInfoTab({
  mount,
  resource,
  onUpdate,
  onDelete,
  toast,
}: {
  mount: string;
  resource: ResourceMetadata;
  onUpdate: () => void;
  onDelete: () => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState(resource);

  function updateField(field: string, value: string | number | string[]) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSave() {
    try {
      await api.writeResource(mount, resource.name, form);
      toast("success", "Resource updated");
      setEditing(false);
      onUpdate();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  if (!editing) {
    return (
      <Card
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => setEditing(true)}>
              Edit
            </Button>
            <Button size="sm" variant="danger" onClick={onDelete}>
              Delete
            </Button>
          </div>
        }
      >
        <div className="grid grid-cols-2 gap-4 text-sm">
          <InfoRow label="Type" value={TYPE_LABELS[resource.type] || resource.type} />
          <InfoRow label="Hostname" value={resource.hostname} />
          <InfoRow label="IP Address" value={resource.ip_address} />
          <InfoRow label="Port" value={resource.port > 0 ? String(resource.port) : "-"} />
          <InfoRow label="OS" value={resource.os} />
          <InfoRow label="Location" value={resource.location} />
          <InfoRow label="Owner" value={resource.owner} />
          <div className="col-span-2">
            <span className="text-[var(--color-text-muted)]">Tags</span>
            <div className="flex flex-wrap gap-1 mt-1">
              {resource.tags.length > 0
                ? resource.tags.map((t) => <Badge key={t} label={t} variant="neutral" />)
                : <span className="text-[var(--color-text-muted)]">-</span>}
            </div>
          </div>
          {resource.notes && (
            <div className="col-span-2">
              <span className="text-[var(--color-text-muted)]">Notes</span>
              <p className="mt-1 whitespace-pre-wrap">{resource.notes}</p>
            </div>
          )}
          <InfoRow label="Created" value={resource.created_at ? new Date(resource.created_at).toLocaleString() : "-"} />
          <InfoRow label="Updated" value={resource.updated_at ? new Date(resource.updated_at).toLocaleString() : "-"} />
        </div>
      </Card>
    );
  }

  return (
    <Card
      actions={
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSave}>
            Save
          </Button>
        </div>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <Input label="Hostname" value={form.hostname} onChange={(e) => updateField("hostname", e.target.value)} />
        <Input label="IP Address" value={form.ip_address} onChange={(e) => updateField("ip_address", e.target.value)} />
        <Input label="Port" type="number" value={String(form.port || "")} onChange={(e) => updateField("port", parseInt(e.target.value) || 0)} />
        <Input label="OS" value={form.os} onChange={(e) => updateField("os", e.target.value)} />
        <Input label="Location" value={form.location} onChange={(e) => updateField("location", e.target.value)} />
        <Input label="Owner" value={form.owner} onChange={(e) => updateField("owner", e.target.value)} />
        <div className="col-span-2">
          <Input
            label="Tags"
            value={form.tags.join(", ")}
            onChange={(e) => updateField("tags", e.target.value.split(",").map((t) => t.trim()).filter(Boolean))}
            hint="Comma-separated"
          />
        </div>
        <div className="col-span-2">
          <Textarea label="Notes" value={form.notes} onChange={(e) => updateField("notes", e.target.value)} />
        </div>
      </div>
    </Card>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-[var(--color-text-muted)] text-xs">{label}</span>
      <p className="font-mono text-sm">{value || "-"}</p>
    </div>
  );
}

// ── Secrets Tab ────────────────────────────────────────────────────

function ResourceSecretsTab({
  mount,
  resourceName,
  toast,
}: {
  mount: string;
  resourceName: string;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [secretData, setSecretData] = useState<Record<string, unknown>>({});
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newPairs, setNewPairs] = useState([{ key: "", value: "" }]);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  useEffect(() => {
    loadKeys();
  }, [resourceName]);

  async function loadKeys() {
    setLoading(true);
    try {
      const result = await api.listResourceSecrets(mount, resourceName);
      setKeys(result.keys);
    } catch {
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSelect(key: string) {
    try {
      const result = await api.readResourceSecret(mount, resourceName, key);
      setSelectedKey(key);
      setSecretData(result.data);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newKey) return;
    const data: Record<string, string> = {};
    for (const p of newPairs) {
      if (p.key) data[p.key] = p.value;
    }
    try {
      await api.writeResourceSecret(mount, resourceName, newKey, data);
      toast("success", `Secret ${newKey} created`);
      setShowCreate(false);
      setNewKey("");
      setNewPairs([{ key: "", value: "" }]);
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteResourceSecret(mount, resourceName, deleteTarget);
      toast("success", `Secret ${deleteTarget} deleted`);
      if (selectedKey === deleteTarget) {
        setSelectedKey(null);
        setSecretData({});
      }
      setDeleteTarget(null);
      loadKeys();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <>
      <Card
        title="Secrets"
        actions={
          <Button size="sm" onClick={() => setShowCreate(true)}>
            Add Secret
          </Button>
        }
      >
        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
        ) : keys.length === 0 ? (
          <EmptyState title="No secrets" description="Add credentials for this resource" />
        ) : (
          <div className="space-y-1">
            {keys.map((key) => (
              <div key={key} className="flex items-center group">
                <button
                  onClick={() => handleSelect(key)}
                  className={`flex-1 text-left px-3 py-1.5 rounded text-sm transition-colors ${
                    selectedKey === key
                      ? "bg-[var(--color-primary)] text-white"
                      : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
                  }`}
                >
                  {key}
                </button>
                <button
                  onClick={() => setDeleteTarget(key)}
                  className="opacity-0 group-hover:opacity-100 px-2 text-[var(--color-danger)] text-xs"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {selectedKey && (
        <Card title={selectedKey}>
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
        </Card>
      )}

      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="Add Secret"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={!newKey}>Create</Button>
          </>
        }
      >
        <div className="space-y-3">
          <Input label="Secret Name" value={newKey} onChange={(e) => setNewKey(e.target.value)} placeholder="admin-password" />
          <div className="space-y-2">
            <label className="block text-sm font-medium text-[var(--color-text-muted)]">Key-Value Pairs</label>
            {newPairs.map((pair, i) => (
              <div key={i} className="flex gap-2">
                <Input placeholder="key" value={pair.key} onChange={(e) => {
                  const u = [...newPairs]; u[i] = { ...pair, key: e.target.value }; setNewPairs(u);
                }} />
                <Input placeholder="value" type="password" value={pair.value} onChange={(e) => {
                  const u = [...newPairs]; u[i] = { ...pair, value: e.target.value }; setNewPairs(u);
                }} />
                {newPairs.length > 1 && (
                  <Button variant="ghost" size="sm" onClick={() => setNewPairs(newPairs.filter((_, j) => j !== i))}>&times;</Button>
                )}
              </div>
            ))}
            <Button variant="ghost" size="sm" onClick={() => setNewPairs([...newPairs, { key: "", value: "" }])}>+ Add pair</Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete Secret"
        message={`Delete secret "${deleteTarget}"?`}
        confirmLabel="Delete"
      />
    </>
  );
}

function MaskedValue({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <span className="inline-flex items-center gap-2">
      <span className={visible ? "" : "blur-sm select-none"}>{value}</span>
      <button onClick={() => setVisible(!visible)} className="text-xs text-[var(--color-primary)] hover:underline shrink-0">
        {visible ? "Hide" : "Show"}
      </button>
    </span>
  );
}

// ── Create Resource Modal ──────────────────────────────────────────

function CreateResourceModal({
  open,
  onClose,
  mount,
  onCreated,
  toast,
}: {
  open: boolean;
  onClose: () => void;
  mount: string;
  onCreated: (name: string) => void;
  toast: (type: "success" | "error" | "info", message: string) => void;
}) {
  const [form, setForm] = useState(emptyResource());
  const [customType, setCustomType] = useState("");
  const [typeSelect, setTypeSelect] = useState("server");

  function updateField(field: string, value: string | number | string[]) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleCreate() {
    if (!form.name) return;
    const meta = {
      ...form,
      type: typeSelect === "_custom" ? customType : typeSelect,
    };
    try {
      await api.writeResource(mount, form.name, meta);
      toast("success", `Resource ${form.name} created`);
      setForm(emptyResource());
      setTypeSelect("server");
      setCustomType("");
      onCreated(form.name);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add Resource"
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={handleCreate} disabled={!form.name || (typeSelect === "_custom" && !customType)}>Create</Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <Input label="Name" value={form.name} onChange={(e) => updateField("name", e.target.value)} placeholder="web-server-01" />
        <div className="space-y-1">
          <Select label="Type" value={typeSelect} onChange={(e) => setTypeSelect(e.target.value)} options={BUILT_IN_TYPES} />
          {typeSelect === "_custom" && (
            <Input placeholder="Custom type name" value={customType} onChange={(e) => setCustomType(e.target.value)} />
          )}
        </div>
        <Input label="Hostname" value={form.hostname} onChange={(e) => updateField("hostname", e.target.value)} placeholder="web01.example.com" />
        <Input label="IP Address" value={form.ip_address} onChange={(e) => updateField("ip_address", e.target.value)} placeholder="10.0.1.50" />
        <Input label="Port" type="number" value={String(form.port || "")} onChange={(e) => updateField("port", parseInt(e.target.value) || 0)} placeholder="22" />
        <Input label="OS" value={form.os} onChange={(e) => updateField("os", e.target.value)} placeholder="Ubuntu 24.04" />
        <Input label="Location" value={form.location} onChange={(e) => updateField("location", e.target.value)} placeholder="us-east-1" />
        <Input label="Owner" value={form.owner} onChange={(e) => updateField("owner", e.target.value)} placeholder="infra-team" />
        <div className="col-span-2">
          <Input
            label="Tags"
            value={form.tags.join(", ")}
            onChange={(e) => updateField("tags", e.target.value.split(",").map((t) => t.trim()).filter(Boolean))}
            placeholder="production, web, linux"
            hint="Comma-separated"
          />
        </div>
        <div className="col-span-2">
          <Textarea label="Notes" value={form.notes} onChange={(e) => updateField("notes", e.target.value)} placeholder="Additional information about this resource..." />
        </div>
      </div>
    </Modal>
  );
}
