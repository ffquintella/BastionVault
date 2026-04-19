import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Tabs,
  Textarea,
  Modal,
  ConfirmModal,
  EmptyState,
  PolicyHistoryPanel,
  useToast,
} from "../components/ui";
import type { PolicyHistoryEntry } from "../lib/types";
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
  const [tab, setTab] = useState<"editor" | "history">("editor");
  const [history, setHistory] = useState<PolicyHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

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
      setTab("editor");
      setHistory([]);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function loadHistory(name: string) {
    setHistoryLoading(true);
    try {
      const r = await api.listPolicyHistory(name);
      setHistory(r.entries);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }

  useEffect(() => {
    if (selected && tab === "history") {
      loadHistory(selected);
    }
  }, [selected, tab]);

  async function handleRestore(raw: string) {
    if (!selected) return;
    try {
      await api.writePolicy(selected, raw);
      toast("success", `Policy ${selected} restored`);
      setPolicyContent(raw);
      setDirty(false);
      await loadHistory(selected);
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
      <div className="space-y-4">
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

          {/* Policy detail */}
          <div className="flex-1 min-w-0 space-y-4">
            {selected ? (
              <>
                <Card
                  title={`Policy: ${selected}`}
                  actions={
                    tab === "editor" && dirty ? (
                      <Button size="sm" onClick={handleSave}>
                        Save
                      </Button>
                    ) : null
                  }
                >
                  <Tabs
                    tabs={[
                      { id: "editor", label: "Editor" },
                      { id: "history", label: "History" },
                    ]}
                    active={tab}
                    onChange={(t) => setTab(t as "editor" | "history")}
                  />
                </Card>

                {tab === "editor" && (
                  <Card>
                    <Textarea
                      value={policyContent}
                      onChange={(e) => {
                        setPolicyContent(e.target.value);
                        setDirty(true);
                      }}
                      className="min-h-[400px]"
                    />
                  </Card>
                )}

                {tab === "history" && (
                  <Card title="Change History">
                    <PolicyHistoryPanel
                      entries={history}
                      loading={historyLoading}
                      onRestore={selected !== "root" ? handleRestore : undefined}
                    />
                  </Card>
                )}
              </>
            ) : (
              <Card>
                <EmptyState
                  title="No policy selected"
                  description="Select a policy from the list to view and edit it"
                />
              </Card>
            )}
          </div>
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
