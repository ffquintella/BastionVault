import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import type { NamespaceInfo, NamespaceQuotas } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { useNamespaceStore } from "../stores/namespaceStore";

const EMPTY_QUOTAS: NamespaceQuotas = {
  max_storage_bytes: 0,
  max_leases: 0,
  request_rate: 0,
  max_mounts: 0,
  max_entities: 0,
  max_child_namespaces: 0,
};

const QUOTA_FIELDS: { key: keyof NamespaceQuotas; label: string; hint: string }[] = [
  { key: "max_mounts", label: "Max mounts", hint: "Enforced at mount creation." },
  { key: "max_child_namespaces", label: "Max child namespaces", hint: "Enforced at create." },
  { key: "request_rate", label: "Request rate (req/s)", hint: "Token-bucket; 429 when exceeded." },
  { key: "max_storage_bytes", label: "Max storage bytes", hint: "Accounting follow-up." },
  { key: "max_leases", label: "Max leases", hint: "Accounting follow-up." },
  { key: "max_entities", label: "Max entities", hint: "Accounting follow-up." },
];

export function NamespacesPage() {
  const { toast } = useToast();
  // Keep the sidebar switcher's cached list in sync after create/delete.
  const refreshNamespaces = useNamespaceStore((s) => s.refresh);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [details, setDetails] = useState<Record<string, NamespaceInfo>>({});
  const [rootInfo, setRootInfo] = useState<NamespaceInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const [showEdit, setShowEdit] = useState(false);
  const [editMode, setEditMode] = useState<"create" | "update">("create");
  // True when the modal is editing the root namespace (path ""), which is
  // reachable only through the dedicated self-config route, not the by-path
  // catch-all. Root can never be created or deleted.
  const [formIsRoot, setFormIsRoot] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const [formPath, setFormPath] = useState("");
  const [formQuotas, setFormQuotas] = useState<NamespaceQuotas>(EMPTY_QUOTAS);
  const [formChildVisible, setFormChildVisible] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      // Root namespace config is fetched separately: it is not part of the
      // child list, and is reached via the dedicated self-config route (empty
      // path). A failure here should not blank the whole page.
      try {
        setRootInfo(await api.readNamespace(""));
      } catch {
        setRootInfo(null);
      }
      const result = await api.listNamespaces();
      setNamespaces(result.namespaces);
      const map: Record<string, NamespaceInfo> = {};
      await Promise.all(
        result.namespaces.map(async (p) => {
          try {
            map[p] = await api.readNamespace(p);
          } catch {
            /* ignore individual read failures */
          }
        }),
      );
      setDetails(map);
    } catch (e) {
      toast("error", extractError(e));
      setNamespaces([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditMode("create");
    setFormIsRoot(false);
    setFormPath("");
    setFormQuotas(EMPTY_QUOTAS);
    setFormChildVisible(false);
    setShowEdit(true);
  }

  function openEdit(path: string) {
    const info = details[path];
    setEditMode("update");
    setFormIsRoot(false);
    setFormPath(path);
    setFormQuotas(info ? info.quotas : EMPTY_QUOTAS);
    setFormChildVisible(info ? info.child_visible_default : false);
    setShowEdit(true);
  }

  function openEditRoot() {
    setEditMode("update");
    setFormIsRoot(true);
    setFormPath("");
    setFormQuotas(rootInfo ? rootInfo.quotas : EMPTY_QUOTAS);
    setFormChildVisible(rootInfo ? rootInfo.child_visible_default : false);
    setShowEdit(true);
  }

  async function save() {
    // Root (formIsRoot) is addressed by the empty path; every other namespace
    // requires a non-empty path.
    const path = formIsRoot ? "" : formPath.trim().replace(/^\/+|\/+$/g, "");
    if (!formIsRoot && !path) {
      toast("error", "Namespace path is required");
      return;
    }
    setSaving(true);
    try {
      await api.writeNamespace(path, formQuotas, formChildVisible);
      const label = formIsRoot ? "root" : `"${path}"`;
      toast(
        "success",
        editMode === "create" ? `Namespace "${path}" created` : `Namespace ${label} updated`,
      );
      setShowEdit(false);
      await loadAll();
      void refreshNamespaces();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteNamespace(deleteTarget);
      toast("success", `Namespace "${deleteTarget}" deleted`);
      setDeleteTarget(null);
      await loadAll();
      void refreshNamespaces();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  const cap = (n: number | undefined) => (n && n > 0 ? String(n) : "∞");

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold">Namespaces</h1>
            <p className="text-sm text-zinc-400">
              Isolated tenants with their own mounts, policies, identities, and quotas.
            </p>
          </div>
          <Button onClick={openCreate}>New namespace</Button>
        </div>

        <Card>
          <div className="flex items-center justify-between gap-3 p-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm">root</span>
                <span className="text-xs rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-400">
                  implicit
                </span>
                {rootInfo?.child_visible_default && (
                  <span className="text-xs rounded bg-amber-900/50 px-1.5 py-0.5 text-amber-300">
                    child-visible
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs text-zinc-500">
                {rootInfo?.child_visible_default
                  ? "Tokens minted at a root login can operate in EVERY descendant namespace."
                  : "Tokens minted at a root login are confined to root unless they log in to a child namespace directly."}
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={openEditRoot} disabled={!rootInfo}>
              Configure root
            </Button>
          </div>
        </Card>

        <Card>
          {loading ? (
            <div className="p-6 text-sm text-zinc-400">Loading…</div>
          ) : namespaces.length === 0 ? (
            <EmptyState
              title="No namespaces yet"
              description="Create a child namespace to isolate a team or customer."
            />
          ) : (
            <Table<string>
              data={namespaces}
              rowKey={(p) => p}
              columns={[
                {
                  key: "path",
                  header: "Path",
                  render: (p) => <span className="font-mono truncate">{p}</span>,
                },
                {
                  key: "mounts",
                  header: "Mounts cap",
                  render: (p) => cap(details[p]?.quotas.max_mounts),
                },
                {
                  key: "children",
                  header: "Children cap",
                  render: (p) => cap(details[p]?.quotas.max_child_namespaces),
                },
                {
                  key: "rate",
                  header: "Rate (req/s)",
                  render: (p) => cap(details[p]?.quotas.request_rate),
                },
                {
                  key: "created",
                  header: "Created",
                  render: (p) => (
                    <span className="text-zinc-400 truncate">
                      {details[p]?.created_at ? details[p].created_at.split("T")[0] : "—"}
                    </span>
                  ),
                },
                {
                  key: "actions",
                  header: "",
                  render: (p) => (
                    <div className="flex gap-2 justify-end">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(p)}>
                        Edit
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(p)}>
                        Delete
                      </Button>
                    </div>
                  ),
                },
              ]}
            />
          )}
        </Card>
      </div>

      <Modal
        open={showEdit}
        onClose={() => setShowEdit(false)}
        title={
          formIsRoot
            ? "Configure root namespace"
            : editMode === "create"
              ? "Create namespace"
              : `Edit ${formPath}`
        }
        size="md"
      >
        <div className="grid grid-cols-2 gap-3">
          {!formIsRoot && (
            <div className="col-span-2">
              <label className="block text-sm mb-1">Path</label>
              <Input
                value={formPath}
                onChange={(e) => setFormPath(e.target.value)}
                placeholder="engineering/platform"
                disabled={editMode === "update"}
              />
              <p className="text-xs text-zinc-500 mt-1">
                Slash-delimited. The parent namespace must already exist.
              </p>
            </div>
          )}

          {QUOTA_FIELDS.map((f) => (
            <div key={f.key}>
              <label className="block text-sm mb-1">{f.label}</label>
              <Input
                type="number"
                min={0}
                value={String(formQuotas[f.key])}
                onChange={(e) =>
                  setFormQuotas({ ...formQuotas, [f.key]: Number(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-zinc-500 mt-1">0 = unlimited. {f.hint}</p>
            </div>
          ))}

          <label className="col-span-2 flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={formChildVisible}
              onChange={(e) => setFormChildVisible(e.target.checked)}
            />
            Default <span className="font-mono">child_visible</span> for tokens minted here
          </label>
          {formIsRoot && formChildVisible && (
            <p className="col-span-2 rounded border border-amber-800 bg-amber-900/30 p-2 text-xs text-amber-300">
              Warning: with this enabled on <span className="font-mono">root</span>, every token
              minted at a root login (e.g. a userpass user who logs in with no namespace selected)
              can operate in <strong>every</strong> descendant namespace. Leave off unless you
              intend root-bound admins to reach all tenants.
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-4">
          <Button variant="ghost" onClick={() => setShowEdit(false)}>
            Cancel
          </Button>
          <Button onClick={save} disabled={saving}>
            {saving ? "Saving…" : editMode === "create" ? "Create" : "Save"}
          </Button>
        </div>
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={confirmDelete}
        title="Delete namespace"
        message={`Delete namespace "${deleteTarget}"? This is refused if it still has child namespaces or mounts.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Layout>
  );
}
