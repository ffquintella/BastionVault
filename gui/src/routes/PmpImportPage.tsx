// Settings → Resources → Import from PMP. Three-step wizard hidden
// when the `pmp-import` plugin isn't registered. Walks the plan
// returned by `plugins_invoke("pmp-import")` against the existing
// Resource / KV / Asset Group Tauri commands. The plugin parses
// + structures only; every write here runs under the operator's
// identity, so the host's `OwnerStore` records the operator as
// owner automatically — see features/pmp-import.md § Resource
// ownership.

import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  Select,
  useToast,
} from "../components/ui";
import * as api from "../lib/api";
import type { ResourceMetadata, ResourceTypeConfig } from "../lib/types";
import { DEFAULT_RESOURCE_TYPES, mergeTypeConfig } from "../lib/resourceTypes";
import { extractError } from "../lib/error";
import { ResourceTypeIcon } from "../components/ui";
import { useAuthStore } from "../stores/authStore";

interface ValidateReport {
  ok: boolean;
  format: string;
  sheet: string;
  row_count: number;
  columns: string[];
  missing_required: string[];
  unknown_columns: string[];
}

interface ResourceSecret {
  name: string;
  value_b64: string;
  metadata: Record<string, string>;
}

interface ResourcePlan {
  name: string;
  type: string;
  metadata: Record<string, string>;
  asset_groups: string[];
  tags: string[];
  secrets: ResourceSecret[];
}

interface KvBlobPlan {
  kind: string;
  path: string;
  data: Record<string, unknown>;
}

interface AssetGroupPlan {
  name: string;
  display_name: string;
  description: string;
  members: string[];
  secrets: string[];
  exists: boolean;
}

interface PlanSummary {
  resource_count: number;
  secret_count: number;
  kv_blob_count: number;
  asset_group_count: number;
  skipped: { row: number; reason: string }[];
  type_distribution: Record<string, number>;
  kv_distribution: Record<string, number>;
  asset_groups_new: string[];
  asset_groups_existing: string[];
}

interface ImportPlan {
  batch_id: string;
  summary: PlanSummary;
  asset_groups: AssetGroupPlan[];
  resources: ResourcePlan[];
  kv_blobs: KvBlobPlan[];
}

type CollisionPolicy = "skip" | "overwrite" | "rename";

type Step = "pick" | "review" | "run";

interface RunProgress {
  total: number;
  done: number;
  errors: { target: string; message: string }[];
  current: string;
}

const PLUGIN_NAME = "pmp-import";

function decodeUtf8B64(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

function encodeUtf8B64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function invokePmp<T>(input: object): Promise<T> {
  const result = await api.pluginsInvoke(PLUGIN_NAME, encodeUtf8B64(JSON.stringify(input)));
  if (result.status !== "success") {
    throw new Error(`plugin returned error (status code ${result.plugin_status_code})`);
  }
  const body = JSON.parse(decodeUtf8B64(result.response_b64));
  if (body && typeof body === "object" && "error" in body) {
    throw new Error(String((body as { error: unknown }).error));
  }
  return body as T;
}

export function PmpImportPage() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const principal = useAuthStore((s) => s.principal);

  const [pluginPresent, setPluginPresent] = useState<boolean | null>(null);
  const [step, setStep] = useState<Step>("pick");
  const [filePath, setFilePath] = useState("");
  const [batchId, setBatchId] = useState(() =>
    new Date()
      .toISOString()
      .replace(/[:.]/g, "")
      .slice(0, 15),
  );
  const [collision, setCollision] = useState<CollisionPolicy>("skip");
  // KV mount tracking. Convention from SecretsPage: `mountBase`
  // includes the trailing slash (e.g. `"secret/"`) and `mountType`
  // is `"kv"` or `"kv-v2"`. Both are required to build the
  // `data/`-vs-bare path the host's `adjust_kv_path` expects.
  const [kvMount, setKvMount] = useState("secret/");
  const [kvMountType, setKvMountType] = useState<"kv" | "kv-v2">("kv-v2");
  const [kvMountChoices, setKvMountChoices] = useState<{ path: string; type: "kv" | "kv-v2" }[]>([
    { path: "secret/", type: "kv-v2" },
  ]);
  const [validateReport, setValidateReport] = useState<ValidateReport | null>(null);
  const [tagColumns, setTagColumns] = useState<string[]>([]);
  const [preserveUnknown, setPreserveUnknown] = useState(true);
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [resourceSelection, setResourceSelection] = useState<Record<string, boolean>>({});
  const [kvSelection, setKvSelection] = useState<Record<string, boolean>>({});
  const [progress, setProgress] = useState<RunProgress | null>(null);
  const [typeConfig, setTypeConfig] = useState<ResourceTypeConfig>(DEFAULT_RESOURCE_TYPES);

  // ── Plugin presence + KV mount probe ───────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const list = await api.pluginsList();
        setPluginPresent(list.some((p) => p.name === PLUGIN_NAME));
      } catch {
        setPluginPresent(false);
      }
      try {
        const mounts = await api.listMounts();
        const kvs = mounts
          .filter((m) => m.mount_type === "kv" || m.mount_type === "kv-v2")
          .map((m) => ({
            path: m.path.endsWith("/") ? m.path : `${m.path}/`,
            type: m.mount_type as "kv" | "kv-v2",
          }));
        if (kvs.length > 0) {
          setKvMountChoices(kvs);
          // Prefer a mount literally called `secret/`; otherwise
          // pick the first one.
          const preferred = kvs.find((k) => k.path === "secret/") ?? kvs[0];
          setKvMount(preferred.path);
          setKvMountType(preferred.type);
        }
      } catch {
        // keep the default `secret/` + kv-v2
      }
      try {
        const saved = await api.resourceTypesRead();
        setTypeConfig(mergeTypeConfig(saved as ResourceTypeConfig | null));
      } catch {
        setTypeConfig(DEFAULT_RESOURCE_TYPES);
      }
    })();
  }, []);

  // ── Step 1: pick file + validate ───────────────────────────────
  async function pickFile() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const picked = await open({
        title: "Select Password Manager Pro export",
        multiple: false,
        directory: false,
        filters: [
          { name: "PMP Export", extensions: ["xls", "xlsx"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof picked === "string" && picked.length > 0) {
        setFilePath(picked);
        runValidate(picked);
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function runValidate(p: string) {
    setBusy(true);
    setValidateReport(null);
    try {
      const r = await invokePmp<ValidateReport>({ op: "validate", file_path: p });
      setValidateReport(r);
      if (!r.ok) {
        toast(
          "error",
          `Spreadsheet is missing required columns: ${r.missing_required.join(", ")}`,
        );
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  // ── Step 2: preview (build the plan) ───────────────────────────
  async function runPreview() {
    if (!filePath) return;
    setBusy(true);
    try {
      const existing = await api.listAssetGroups().then((r) => r.groups).catch(() => []);
      const p = await invokePmp<ImportPlan>({
        op: "preview",
        file_path: filePath,
        batch_id: batchId,
        preserve_unknown_columns: preserveUnknown,
        tag_columns: tagColumns,
        existing_asset_groups: existing,
        name_collision_policy: collision,
      });
      setPlan(p);
      // Default selection: every row enabled.
      const rs: Record<string, boolean> = {};
      p.resources.forEach((r) => (rs[r.name] = true));
      setResourceSelection(rs);
      const ks: Record<string, boolean> = {};
      p.kv_blobs.forEach((b) => (ks[b.path] = true));
      setKvSelection(ks);
      setStep("review");
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  // ── Step 3: walk the plan ──────────────────────────────────────
  async function runImport() {
    if (!plan) return;
    setStep("run");
    const selectedResources = plan.resources.filter((r) => resourceSelection[r.name]);
    const selectedKv = plan.kv_blobs.filter((b) => kvSelection[b.path]);
    const selectedResourceNames = new Set(selectedResources.map((r) => r.name));
    const selectedKvPaths = new Set(selectedKv.map((b) => b.path));

    // Asset groups whose memberships still have at least one
    // selected target. Empty groups (every member deselected) are
    // skipped — no point creating an empty container.
    const groupsToWrite = plan.asset_groups
      .map((g) => {
        const members = g.members.filter((m) => selectedResourceNames.has(m));
        const secrets = g.secrets.filter((s) => selectedKvPaths.has(s));
        return { ...g, members, secrets };
      })
      .filter((g) => g.members.length > 0 || g.secrets.length > 0);

    const total =
      groupsToWrite.length +
      selectedResources.length +
      selectedResources.reduce((acc, r) => acc + r.secrets.length, 0) +
      selectedKv.length;

    const prog: RunProgress = { total, done: 0, errors: [], current: "" };
    setProgress({ ...prog });

    // ── Pass 1: asset groups (read-merge-write per group). ──────
    for (const g of groupsToWrite) {
      prog.current = `asset group ${g.name}`;
      setProgress({ ...prog });
      try {
        if (g.exists) {
          const existing = await api.readAssetGroup(g.name);
          const mergedMembers = unique([...existing.members, ...g.members]);
          const mergedSecrets = unique([...existing.secrets, ...g.secrets]);
          if (collision === "skip" && existing.members.length > 0) {
            // Skip mode for an existing group still appends new
            // members — Skip applies to row collisions, not group
            // updates. Documented in the spec.
          }
          await api.writeAssetGroup(
            g.name,
            existing.description || g.description,
            mergedMembers.join(","),
            mergedSecrets.join(","),
          );
        } else {
          const desc = `${g.description}${
            principal ? ` — created by ${principal}` : ""
          } on ${new Date().toISOString().slice(0, 10)}`;
          await api.writeAssetGroup(
            g.name,
            desc,
            g.members.join(","),
            g.secrets.join(","),
          );
        }
      } catch (e: unknown) {
        prog.errors.push({ target: `asset-group/${g.name}`, message: extractError(e) });
      }
      prog.done += 1;
      setProgress({ ...prog });
    }

    // ── Pass 2: resources + their secrets. ──────────────────────
    const existingResources = await api.listResources().catch(() => ({ resources: [] }));
    const existingResourceSet = new Set(existingResources.resources);
    for (const r of selectedResources) {
      const finalName = await resolveCollision(r.name, existingResourceSet, collision, async (n) =>
        existingResourceSet.has(n),
      );
      if (finalName === null) {
        prog.done += 1 + r.secrets.length;
        setProgress({ ...prog });
        continue;
      }
      prog.current = `resource ${finalName} (+ ${r.secrets.length} account secret(s))`;
      setProgress({ ...prog });
      try {
        const tags = unique([
          ...r.tags,
          `pmp-import:${plan.batch_id}`,
        ]).join(",");
        const meta = {
          ...r.metadata,
          name: finalName,
          type: r.type,
          tags,
          notes: r.metadata.notes ?? "",
        } as unknown as ResourceMetadata;
        await api.writeResource(finalName, meta);
        existingResourceSet.add(finalName);
      } catch (e: unknown) {
        prog.errors.push({ target: `resource/${finalName}`, message: extractError(e) });
        prog.done += 1 + r.secrets.length;
        setProgress({ ...prog });
        continue;
      }
      prog.done += 1;
      setProgress({ ...prog });
      // Write every account from this PMP resource as a
      // resource-secret under the BV resource we just created.
      // Skipping this loop would leave a resource without
      // credentials, defeating the migration.
      for (const s of r.secrets) {
        prog.current = `${finalName} / account ${s.name}`;
        setProgress({ ...prog });
        try {
          await api.writeResourceSecret(finalName, s.name, {
            value: decodeUtf8B64(s.value_b64),
            ...s.metadata,
          });
        } catch (e: unknown) {
          prog.errors.push({
            target: `resource/${finalName}/${s.name}`,
            message: extractError(e),
          });
        }
        prog.done += 1;
        setProgress({ ...prog });
      }
    }

    // ── Pass 3: KV blobs. ───────────────────────────────────────
    // Plugin-emitted paths use a literal `secret/` prefix as a
    // placeholder. We strip it and rebase under whatever KV mount
    // the operator picked. The mount path already ends in `/` per
    // SecretsPage's convention; writeSecret takes `path` as the
    // bit *after* the mount.
    for (const b of selectedKv) {
      const relative = b.path.replace(/^secret\//, "");
      const fullPath = `${kvMount}${relative}`;
      prog.current = fullPath;
      setProgress({ ...prog });
      try {
        const flat: Record<string, string> = {};
        for (const [k, v] of Object.entries(b.data)) {
          if (Array.isArray(v)) flat[k] = (v as unknown[]).join(",");
          else if (v === null || v === undefined) flat[k] = "";
          else flat[k] = String(v);
        }
        await api.writeSecret(relative, flat, kvMount, kvMountType);
      } catch (e: unknown) {
        prog.errors.push({ target: fullPath, message: extractError(e) });
      }
      prog.done += 1;
      setProgress({ ...prog });
    }

    prog.current = "done";
    setProgress({ ...prog });
    if (prog.errors.length === 0) {
      toast("success", `Imported ${selectedResources.length} resources + ${selectedKv.length} KV entries`);
    } else {
      toast("error", `Import finished with ${prog.errors.length} error(s)`);
    }
  }

  // ── Render ─────────────────────────────────────────────────────
  if (pluginPresent === null) {
    return (
      <Layout>
        <div className="p-6 text-sm text-[var(--color-text-muted)]">Loading…</div>
      </Layout>
    );
  }
  if (pluginPresent === false) {
    return (
      <Layout>
        <div className="space-y-4 p-2 max-w-3xl">
          <h1 className="text-2xl font-bold">Import from Password Manager Pro</h1>
          <EmptyState
            title="Plugin not installed"
            description="The pmp-import plugin isn't registered with this vault. Upload it via Plugins first, then return here."
          />
          <Link to="/plugins" className="underline text-sm">Open Plugins page →</Link>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Import from Password Manager Pro</h1>
          <Button variant="ghost" size="sm" onClick={() => navigate("/resources")}>
            Back to Resources
          </Button>
        </div>

        <div className="text-sm bg-[var(--color-primary)]/10 border border-[var(--color-primary)]/30 text-[var(--color-text)] rounded p-3">
          <strong>Owner.</strong> All imported resources and KV entries will be owned by{" "}
          <strong>{principal || "the current operator"}</strong>. PMP's <em>Department</em> column
          maps to an asset group, not an owner.
        </div>

        <StepBar step={step} />

        {step === "pick" && (
          <PickStep
            filePath={filePath}
            onPick={pickFile}
            validateReport={validateReport}
            busy={busy}
            tagColumns={tagColumns}
            setTagColumns={setTagColumns}
            preserveUnknown={preserveUnknown}
            setPreserveUnknown={setPreserveUnknown}
            batchId={batchId}
            setBatchId={setBatchId}
            kvMount={kvMount}
            setKvMount={(v) => {
              setKvMount(v);
              const m = kvMountChoices.find((c) => c.path === v);
              if (m) setKvMountType(m.type);
            }}
            kvMountChoices={kvMountChoices}
            collision={collision}
            setCollision={setCollision}
            onNext={runPreview}
          />
        )}
        {step === "review" && plan && (
          <ReviewStep
            plan={plan}
            resourceSelection={resourceSelection}
            setResourceSelection={setResourceSelection}
            kvSelection={kvSelection}
            setKvSelection={setKvSelection}
            kvMount={kvMount}
            collision={collision}
            typeConfig={typeConfig}
            onBack={() => setStep("pick")}
            onRun={runImport}
            busy={busy}
          />
        )}
        {step === "run" && plan && (
          <RunStep plan={plan} progress={progress} onBack={() => setStep("review")} />
        )}
      </div>
    </Layout>
  );
}

// ── Step bar ─────────────────────────────────────────────────────
function StepBar({ step }: { step: Step }) {
  const steps: { id: Step; label: string }[] = [
    { id: "pick", label: "1. Pick file" },
    { id: "review", label: "2. Review" },
    { id: "run", label: "3. Run" },
  ];
  return (
    <div className="flex items-center gap-2 text-sm">
      {steps.map((s, i) => (
        <span key={s.id} className="flex items-center gap-2">
          <span
            className={`px-2 py-1 rounded ${
              s.id === step
                ? "bg-[var(--color-primary)] text-white"
                : "bg-[var(--color-surface)] text-[var(--color-text-muted)] border border-[var(--color-border)]"
            }`}
          >
            {s.label}
          </span>
          {i < steps.length - 1 && <span className="text-[var(--color-text-muted)]">→</span>}
        </span>
      ))}
    </div>
  );
}

// ── Step 1 ───────────────────────────────────────────────────────
function PickStep(props: {
  filePath: string;
  onPick: () => void;
  validateReport: ValidateReport | null;
  busy: boolean;
  tagColumns: string[];
  setTagColumns: (v: string[]) => void;
  preserveUnknown: boolean;
  setPreserveUnknown: (v: boolean) => void;
  batchId: string;
  setBatchId: (v: string) => void;
  kvMount: string;
  setKvMount: (v: string) => void;
  kvMountChoices: { path: string; type: "kv" | "kv-v2" }[];
  collision: CollisionPolicy;
  setCollision: (v: CollisionPolicy) => void;
  onNext: () => void;
}) {
  const v = props.validateReport;
  return (
    <Card title="Pick file">
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Input
            label="Spreadsheet path"
            value={props.filePath}
            placeholder="No file selected"
            onChange={() => {}}
            disabled
            className="flex-1"
          />
          <div className="self-end">
            <Button onClick={props.onPick} loading={props.busy}>
              Browse…
            </Button>
          </div>
        </div>

        {v && (
          <div className="text-sm space-y-2">
            <div>
              Sheet: <strong>{v.sheet}</strong> · Format:{" "}
              <Badge label={v.format.toUpperCase()} variant="neutral" /> · Rows:{" "}
              <strong>{v.row_count}</strong>{" "}
              {v.ok ? (
                <Badge label="ok" variant="success" />
              ) : (
                <Badge label="missing required columns" variant="error" />
              )}
            </div>
            {!v.ok && v.missing_required.length > 0 && (
              <div>Missing: {v.missing_required.join(", ")}</div>
            )}
            {v.unknown_columns.length > 0 && (
              <div>
                <div className="font-semibold mb-1">Custom columns detected</div>
                <label className="flex items-center gap-2 mb-2">
                  <input
                    type="checkbox"
                    checked={props.preserveUnknown}
                    onChange={(e) => props.setPreserveUnknown(e.target.checked)}
                  />
                  Preserve as resource metadata / KV envelope fields
                </label>
                <div className="space-y-1">
                  {v.unknown_columns.map((c) => (
                    <label key={c} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={props.tagColumns.includes(c)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            props.setTagColumns([...props.tagColumns, c]);
                          } else {
                            props.setTagColumns(props.tagColumns.filter((x) => x !== c));
                          }
                        }}
                      />
                      Use <code>{c}</code> as a tag
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Batch ID"
            value={props.batchId}
            onChange={(e) => props.setBatchId(e.target.value)}
            placeholder="20260505T1530"
          />
          <Select
            label="KV mount"
            options={props.kvMountChoices.map((m) => ({
              value: m.path,
              label: `${m.path} (${m.type})`,
            }))}
            value={props.kvMount}
            onChange={(e) => props.setKvMount(e.target.value)}
          />
          <Select
            label="Collision policy"
            options={[
              { value: "skip", label: "Skip — leave existing entries alone" },
              { value: "overwrite", label: "Overwrite — replace existing entries" },
              { value: "rename", label: "Rename — append -2, -3, …" },
            ]}
            value={props.collision}
            onChange={(e) => props.setCollision(e.target.value as CollisionPolicy)}
          />
        </div>

        <div className="flex justify-end">
          <Button onClick={props.onNext} disabled={!v?.ok || props.busy} loading={props.busy}>
            Build plan →
          </Button>
        </div>
      </div>
    </Card>
  );
}

// ── Step 2 ───────────────────────────────────────────────────────
function ReviewStep(props: {
  plan: ImportPlan;
  resourceSelection: Record<string, boolean>;
  setResourceSelection: (v: Record<string, boolean>) => void;
  kvSelection: Record<string, boolean>;
  setKvSelection: (v: Record<string, boolean>) => void;
  kvMount: string;
  collision: CollisionPolicy;
  typeConfig: ResourceTypeConfig;
  onBack: () => void;
  onRun: () => void;
  busy: boolean;
}) {
  const { plan } = props;
  const grouped = useMemo(() => {
    const m = new Map<string, ResourcePlan[]>();
    for (const r of plan.resources) {
      if (!m.has(r.type)) m.set(r.type, []);
      m.get(r.type)!.push(r);
    }
    return Array.from(m.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [plan.resources]);
  const kvGrouped = useMemo(() => {
    const m = new Map<string, KvBlobPlan[]>();
    for (const b of plan.kv_blobs) {
      if (!m.has(b.kind)) m.set(b.kind, []);
      m.get(b.kind)!.push(b);
    }
    return Array.from(m.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [plan.kv_blobs]);

  const selectedResources = Object.values(props.resourceSelection).filter(Boolean).length;
  const selectedKv = Object.values(props.kvSelection).filter(Boolean).length;

  function setAllResources(on: boolean) {
    const next: Record<string, boolean> = {};
    plan.resources.forEach((r) => (next[r.name] = on));
    props.setResourceSelection(next);
  }
  function setAllKv(on: boolean) {
    const next: Record<string, boolean> = {};
    plan.kv_blobs.forEach((b) => (next[b.path] = on));
    props.setKvSelection(next);
  }

  return (
    <div className="space-y-4">
      <Card title="Summary">
        <div className="text-sm grid grid-cols-2 md:grid-cols-4 gap-3">
          <Metric label="Resources" value={plan.summary.resource_count} />
          <Metric label="Account secrets" value={plan.summary.secret_count} />
          <Metric label="KV entries" value={plan.summary.kv_blob_count} />
          <Metric label="Asset groups" value={plan.summary.asset_group_count} />
        </div>
        <div className="text-sm mt-3">
          <div>
            <strong>Type distribution:</strong>{" "}
            {Object.entries(plan.summary.type_distribution)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ") || "(none)"}
          </div>
          <div>
            <strong>KV distribution:</strong>{" "}
            {Object.entries(plan.summary.kv_distribution)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ") || "(none)"}
          </div>
          {plan.summary.skipped.length > 0 && (
            <div className="text-[var(--color-warning)]">
              Skipped {plan.summary.skipped.length} row(s): {plan.summary.skipped
                .slice(0, 3)
                .map((s) => `row ${s.row} (${s.reason})`)
                .join("; ")}
              {plan.summary.skipped.length > 3 && "…"}
            </div>
          )}
        </div>
      </Card>

      <Card
        title={`Asset groups (${plan.asset_groups.length})`}
        actions={null}
      >
        <div className="text-sm space-y-1">
          {plan.asset_groups.map((g) => (
            <div key={g.name} className="flex items-center gap-2">
              <Badge
                label={g.exists ? "will update" : "will create"}
                variant={g.exists ? "neutral" : "success"}
              />
              <code>{g.name}</code>
              <span className="text-[var(--color-text-muted)]">
                ({g.display_name}) · +{g.members.length} members · +{g.secrets.length} secrets
              </span>
            </div>
          ))}
          {plan.asset_groups.length === 0 && (
            <div className="text-[var(--color-text-muted)]">
              No asset groups derived (no Department values in the spreadsheet).
            </div>
          )}
        </div>
      </Card>

      <Card
        title={`Resources (${selectedResources}/${plan.resources.length} selected)`}
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => setAllResources(true)}>
              Select all
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setAllResources(false)}>
              None
            </Button>
          </div>
        }
      >
        <div className="space-y-3 text-sm">
          {grouped.map(([type, rs]) => {
            const td = props.typeConfig[type] ?? {
              id: type, label: type, color: "neutral" as const, fields: [],
            };
            return (
            <details key={type} open className="border border-[var(--color-border)] rounded">
              <summary className="px-3 py-2 cursor-pointer flex items-center gap-2">
                <ResourceTypeIcon typeDef={td} withLabel />
                <span className="font-semibold">{rs.length}</span>
              </summary>
              <div className="p-2 space-y-1">
                {rs.map((r) => (
                  <details key={r.name} className="border border-[var(--color-border)] rounded">
                    <summary className="px-2 py-1 cursor-pointer flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={!!props.resourceSelection[r.name]}
                        onChange={(e) =>
                          props.setResourceSelection({
                            ...props.resourceSelection,
                            [r.name]: e.target.checked,
                          })
                        }
                        onClick={(e) => e.stopPropagation()}
                      />
                      <code>{r.name}</code>
                      <span className="text-[var(--color-text-muted)]">
                        {r.metadata.hostname ? ` · ${r.metadata.hostname}` : ""} ·{" "}
                        <strong>{r.secrets.length} account(s)</strong> will be written under this
                        resource
                      </span>
                      {r.asset_groups.map((g) => (
                        <Badge key={g} label={g} variant="neutral" />
                      ))}
                    </summary>
                    <ul className="px-4 py-2 text-xs space-y-1 bg-[var(--color-bg)] border-t border-[var(--color-border)]">
                      {r.secrets.map((s) => (
                        <li key={s.name} className="flex items-center gap-2">
                          <Badge label="account" variant="info" />
                          <code>{s.name}</code>
                          <span className="text-[var(--color-text-muted)]">
                            password (masked) ·{" "}
                            {s.metadata?.pmp_last_accessed ?? "no last-accessed timestamp"}
                          </span>
                        </li>
                      ))}
                      {r.secrets.length === 0 && (
                        <li className="text-[var(--color-warning)]">
                          No accounts — this row would create a resource without credentials and
                          will be skipped at run time.
                        </li>
                      )}
                    </ul>
                  </details>
                ))}
              </div>
            </details>
            );
          })}
          {grouped.length === 0 && (
            <div className="text-[var(--color-text-muted)]">No resources in this plan.</div>
          )}
        </div>
      </Card>

      <Card
        title={`KV entries (${selectedKv}/${plan.kv_blobs.length} selected)`}
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => setAllKv(true)}>
              Select all
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setAllKv(false)}>
              None
            </Button>
          </div>
        }
      >
        <div className="text-sm space-y-3">
          <div className="text-[var(--color-text-muted)]">
            Mount: <code>{props.kvMount}</code>
          </div>
          {kvGrouped.map(([kind, blobs]) => (
            <details key={kind} open className="border border-[var(--color-border)] rounded">
              <summary className="px-3 py-2 cursor-pointer flex items-center gap-2">
                <Badge label={kind} variant="warning" />
                <span className="font-semibold">{blobs.length}</span>
              </summary>
              <div className="p-2 space-y-1">
                {blobs.map((b) => (
                  <label key={b.path} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={!!props.kvSelection[b.path]}
                      onChange={(e) =>
                        props.setKvSelection({
                          ...props.kvSelection,
                          [b.path]: e.target.checked,
                        })
                      }
                    />
                    <code className="truncate">
                      {b.path.replace(/^secret\//, props.kvMount)}
                    </code>
                  </label>
                ))}
              </div>
            </details>
          ))}
          {kvGrouped.length === 0 && (
            <div className="text-[var(--color-text-muted)]">
              No KV-bound rows (Generic Keys / Application Passwords / License Store) in this
              spreadsheet.
            </div>
          )}
        </div>
      </Card>

      <div className="flex justify-between">
        <Button variant="ghost" onClick={props.onBack} disabled={props.busy}>
          ← Back
        </Button>
        <Button
          onClick={props.onRun}
          disabled={selectedResources + selectedKv === 0 || props.busy}
        >
          Run import →
        </Button>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-[var(--color-border)] rounded p-2">
      <div className="text-[var(--color-text-muted)] text-xs">{label}</div>
      <div className="font-semibold text-lg">{value}</div>
    </div>
  );
}

// ── Step 3 ───────────────────────────────────────────────────────
function RunStep({
  plan,
  progress,
  onBack,
}: {
  plan: ImportPlan;
  progress: RunProgress | null;
  onBack: () => void;
}) {
  const pct = progress && progress.total > 0
    ? Math.round((progress.done / progress.total) * 100)
    : 0;
  const done = progress?.done ?? 0;
  const total = progress?.total ?? 0;
  const errors = progress?.errors ?? [];
  const finished = progress != null && progress.current === "done";

  return (
    <Card title="Running import">
      <div className="space-y-3 text-sm">
        <div>
          Batch: <code>{plan.batch_id}</code>
        </div>
        <div className="w-full bg-[var(--color-surface)] border border-[var(--color-border)] rounded h-2 overflow-hidden">
          <div
            className="bg-[var(--color-primary)] h-full transition-all"
            style={{ width: `${pct}%` }}
          />
        </div>
        <div>
          {done} / {total} steps · {pct}% · {progress?.current ?? ""}
        </div>
        {errors.length > 0 && (
          <details open className="border border-[var(--color-danger)]/40 rounded p-2 bg-[var(--color-danger)]/10 text-[var(--color-text)]">
            <summary className="cursor-pointer font-semibold text-[var(--color-danger)]">
              {errors.length} error(s)
            </summary>
            <ul className="mt-2 list-disc pl-5 max-h-64 overflow-y-auto text-xs space-y-1">
              {errors.map((e, i) => (
                <li key={i}>
                  <code className="text-[var(--color-text)]">{e.target}</code>:{" "}
                  <span className="text-[var(--color-text-muted)]">{e.message}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
        {finished && (
          <div className="flex gap-3">
            <Link to={`/resources?tag=pmp-import:${plan.batch_id}`}>
              <Button variant="secondary">View imported resources</Button>
            </Link>
            <Link to={`/secrets`}>
              <Button variant="secondary">View KV browser</Button>
            </Link>
            <Link to={`/asset-groups`}>
              <Button variant="secondary">View asset groups</Button>
            </Link>
            <Button variant="ghost" onClick={onBack}>
              Back to review
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

// ── helpers ──────────────────────────────────────────────────────
function unique<T>(xs: T[]): T[] {
  return Array.from(new Set(xs));
}

async function resolveCollision(
  desired: string,
  existing: Set<string>,
  policy: CollisionPolicy,
  exists: (n: string) => Promise<boolean>,
): Promise<string | null> {
  const collides = existing.has(desired) || (await exists(desired));
  if (!collides) return desired;
  if (policy === "skip") return null;
  if (policy === "overwrite") return desired;
  // rename
  for (let i = 2; i < 1000; i++) {
    const candidate = `${desired}-${i}`;
    if (!existing.has(candidate) && !(await exists(candidate))) return candidate;
  }
  return null;
}
