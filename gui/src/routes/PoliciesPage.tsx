import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Textarea,
  Modal,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const DEFAULT_POLICY = `# Example policy
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`;

export function PoliciesPage() {
  const { toast } = useToast();
  const [policies, setPolicies] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [policyContent, setPolicyContent] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newContent, setNewContent] = useState(DEFAULT_POLICY);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    loadPolicies();
  }, []);

  async function loadPolicies() {
    setLoading(true);
    try {
      const result = await api.listPolicies();
      setPolicies(result.policies);
    } catch {
      setPolicies([]);
    } finally {
      setLoading(false);
    }
  }

  async function selectPolicy(name: string) {
    try {
      const result = await api.readPolicy(name);
      setSelected(name);
      setPolicyContent(result.policy);
      setDirty(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleSave() {
    if (!selected) return;
    try {
      await api.writePolicy(selected, policyContent);
      toast("success", `Policy ${selected} saved`);
      setDirty(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newName) return;
    try {
      await api.writePolicy(newName, newContent);
      toast("success", `Policy ${newName} created`);
      setShowCreate(false);
      setNewName("");
      setNewContent(DEFAULT_POLICY);
      loadPolicies();
      selectPolicy(newName);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deletePolicy(deleteTarget);
      toast("success", `Policy ${deleteTarget} deleted`);
      if (selected === deleteTarget) {
        setSelected(null);
        setPolicyContent("");
      }
      setDeleteTarget(null);
      loadPolicies();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <Layout>
      <div className="max-w-5xl space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Policies</h1>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            Create Policy
          </Button>
        </div>

        <div className="flex gap-4">
          {/* Policy list */}
          <Card className="w-56 shrink-0" title="ACL Policies">
            {loading ? (
              <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
            ) : policies.length === 0 ? (
              <EmptyState title="No policies" />
            ) : (
              <div className="space-y-0.5 -mx-1">
                {policies.map((name) => (
                  <div key={name} className="flex items-center group">
                    <button
                      onClick={() => selectPolicy(name)}
                      className={`flex-1 text-left px-3 py-1.5 rounded text-sm transition-colors ${
                        selected === name
                          ? "bg-[var(--color-primary)] text-white"
                          : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                      }`}
                    >
                      {name}
                    </button>
                    {name !== "root" && name !== "default" && (
                      <button
                        onClick={() => setDeleteTarget(name)}
                        className="opacity-0 group-hover:opacity-100 px-1 text-[var(--color-danger)] text-xs transition-opacity"
                      >
                        &times;
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Policy editor */}
          <Card
            className="flex-1"
            title={selected ? `Policy: ${selected}` : "Select a policy"}
            actions={
              selected && dirty ? (
                <Button size="sm" onClick={handleSave}>
                  Save
                </Button>
              ) : null
            }
          >
            {selected ? (
              <Textarea
                value={policyContent}
                onChange={(e) => {
                  setPolicyContent(e.target.value);
                  setDirty(true);
                }}
                className="min-h-[400px]"
              />
            ) : (
              <EmptyState
                title="No policy selected"
                description="Select a policy from the list to view and edit it"
              />
            )}
          </Card>
        </div>

        {/* Create policy modal */}
        <Modal
          open={showCreate}
          onClose={() => setShowCreate(false)}
          title="Create Policy"
          size="lg"
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
              label="Policy Name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="my-policy"
            />
            <Textarea
              label="Policy (HCL)"
              value={newContent}
              onChange={(e) => setNewContent(e.target.value)}
              className="min-h-[200px]"
            />
          </div>
        </Modal>

        {/* Delete confirmation */}
        <ConfirmModal
          open={deleteTarget !== null}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete Policy"
          message={`Are you sure you want to delete policy "${deleteTarget}"?`}
          confirmLabel="Delete"
        />
      </div>
    </Layout>
  );
}
