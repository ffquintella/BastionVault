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
import { PolicyBlockEditor } from "../components/PolicyBlockEditor";
import { PolicyValidatorPanel } from "../components/PolicyValidatorPanel";
import type { PolicyHistoryEntry, PolicyTestCase } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type PolicyTab = "editor" | "builder" | "validate" | "history";

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
  const [tab, setTab] = useState<PolicyTab>("editor");
  const [history, setHistory] = useState<PolicyHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [savedCases, setSavedCases] = useState<PolicyTestCase[]>([]);
  // When saved test cases fail against the draft, the save is blocked and
  // this holds the failure summary so the operator can override.
  const [gatePrompt, setGatePrompt] = useState<{ failed: number; total: number } | null>(null);

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
      // Load any saved effectivity test cases (used as the save-time gate).
      try {
        setSavedCases(await api.readPolicyTests(name));
      } catch {
        setSavedCases([]);
      }
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

  /**
   * Run the saved test cases against the current draft via the
   * authoritative backend dry-run. Returns the number of failing cases
   * (a case fails when its verdict disagrees with its `expect`). A parse
   * failure is reported as all cases failing so save is gated.
   */
  async function runRegressionGate(): Promise<{ failed: number; total: number }> {
    if (savedCases.length === 0) return { failed: 0, total: 0 };
    const res = await api.policyTest(
      policyContent,
      savedCases.map((c) => ({ path: c.path, capability: c.capability })),
    );
    if (!res.parse_ok) return { failed: savedCases.length, total: savedCases.length };
    let failed = 0;
    res.results.forEach((r, i) => {
      const expectAllow = savedCases[i]?.expect === "allow";
      if (r.allowed !== expectAllow) failed++;
    });
    return { failed, total: savedCases.length };
  }

  async function doSave() {
    if (!selected) return;
    try {
      await api.writePolicy(selected, policyContent);
      toast("success", `Policy ${selected} saved`);
      setDirty(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleSave() {
    if (!selected) return;
    try {
      const gate = await runRegressionGate();
      if (gate.failed > 0) {
        setGatePrompt(gate);
        return;
      }
    } catch (e: unknown) {
      // A gate evaluation failure must not silently let a bad policy save.
      toast("error", `Could not evaluate test cases: ${extractError(e)}`);
      return;
    }
    await doSave();
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
                      { id: "builder", label: "Visual builder" },
                      { id: "editor", label: "HCL source" },
                      { id: "validate", label: "Validate & test" },
                      { id: "history", label: "History" },
                    ]}
                    active={tab}
                    onChange={(t) => setTab(t as PolicyTab)}
                  />
                </Card>

                {tab === "builder" && (
                  <PolicyBlockEditor
                    value={policyContent}
                    onChange={(hcl) => {
                      setPolicyContent(hcl);
                      setDirty(true);
                    }}
                  />
                )}

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

                {tab === "validate" && (
                  <PolicyValidatorPanel
                    name={selected}
                    hcl={policyContent}
                    savedCases={savedCases}
                    onSavedCasesChange={setSavedCases}
                    toast={toast}
                  />
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

        {/* Save-time regression gate: saved test cases fail against the draft */}
        <ConfirmModal
          open={gatePrompt !== null}
          onClose={() => setGatePrompt(null)}
          onConfirm={() => {
            setGatePrompt(null);
            void doSave();
          }}
          title="Saved test cases fail"
          message={
            gatePrompt
              ? `${gatePrompt.failed} of ${gatePrompt.total} saved test case${
                  gatePrompt.total === 1 ? "" : "s"
                } do not match this draft. Save anyway?`
              : ""
          }
          confirmLabel="Save anyway"
        />
      </div>
    </Layout>
  );
}
