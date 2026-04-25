import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Tabs, Input, Select, ConfirmModal, useToast } from "../components/ui";
import * as api from "../lib/api";
import type {
  ExchangeScopeSelector,
  ExchangePreviewResult,
  ExchangePreviewItem,
  Schedule,
  ScheduleInput,
  RunRecord,
} from "../lib/api";
import { extractError } from "../lib/error";

/**
 * Exchange page: portable JSON / password-encrypted `.bvx` import + export.
 *
 * Distinct from `operator backup`:
 *   - operator backup = full-vault BVBK binary, restorable only on the
 *     same vault's barrier.
 *   - exchange = scope-selectable JSON + Argon2id-encrypted `.bvx`, portable
 *     across vault instances.
 *
 * See `features/import-export-module.md`.
 */
export function ExchangePage() {
  const { toast } = useToast();
  const [tab, setTab] = useState<string>("export");

  return (
    <Layout>
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Import / Export</h1>
        <p className="text-sm text-[var(--color-text-muted)]">
          Portable JSON exports with optional Argon2id +
          XChaCha20-Poly1305 password encryption (`.bvx`). Different from
          operator backup, which is full-vault and restorable only on the
          same vault.
        </p>

        <Tabs
          tabs={[
            { id: "export", label: "Export" },
            { id: "import", label: "Import" },
            { id: "schedules", label: "Scheduled backups" },
          ]}
          active={tab}
          onChange={setTab}
        />

        {tab === "export" && <ExportTab toast={toast} />}
        {tab === "import" && <ImportTab toast={toast} />}
        {tab === "schedules" && <SchedulesTab toast={toast} />}
      </div>
    </Layout>
  );
}

type ToastFn = (kind: "success" | "error" | "info", message: string) => void;

function ExportTab({ toast }: { toast: ToastFn }) {
  const [scopes, setScopes] = useState<ExchangeScopeSelector[]>([
    { type: "kv_path", mount: "secret/", path: "" },
  ]);
  const [format, setFormat] = useState<"bvx" | "json">("bvx");
  const [password, setPassword] = useState("");
  const [allowPlaintext, setAllowPlaintext] = useState(false);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);

  function updateScope(idx: number, patch: Partial<ExchangeScopeSelector>) {
    setScopes((prev) => prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  }

  function addScope() {
    setScopes((prev) => [...prev, { type: "kv_path", mount: "secret/", path: "" }]);
  }
  function removeScope(idx: number) {
    setScopes((prev) => prev.filter((_, i) => i !== idx));
  }

  async function handleExport() {
    if (format === "bvx" && password.length < 12) {
      toast("error", "Password must be at least 12 characters.");
      return;
    }
    setBusy(true);
    try {
      const result = await api.exchangeExport(
        scopes,
        format,
        format === "bvx" ? password : undefined,
        format === "json" ? allowPlaintext : false,
        comment || undefined,
      );
      // Trigger a browser download.
      const bytes = atob(result.file_b64);
      const arr = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
      const blob = new Blob([arr], {
        type: format === "bvx" ? "application/octet-stream" : "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = format === "bvx" ? "exchange.bvx" : "exchange.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast("success", `Exported ${result.size_bytes} bytes.`);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
      // Best-effort: blank the input so the password isn't sitting in
      // React state any longer than necessary.
      setPassword("");
    }
  }

  return (
    <Card title="Export">
      <div className="space-y-4">
        <div className="space-y-2">
          <p className="text-sm font-medium">Scope</p>
          <ScopeTypeHelp />
          {scopes.map((s, idx) => (
            <div key={idx} className="grid grid-cols-12 gap-2 items-end">
              <div className="col-span-3">
                <Select
                  label={idx === 0 ? "Type" : undefined}
                  value={s.type}
                  onChange={(e) =>
                    updateScope(idx, { type: e.target.value as ExchangeScopeSelector["type"] })
                  }
                  options={[
                    { value: "kv_path", label: "KV path" },
                    { value: "resource", label: "Resource (by id)" },
                    { value: "asset_group", label: "Asset group (by name)" },
                    { value: "resource_group", label: "Resource group (by name)" },
                  ]}
                />
              </div>
              {s.type === "kv_path" ? (
                <>
                  <div className="col-span-4">
                    <Input
                      label={idx === 0 ? "Mount" : undefined}
                      value={s.mount ?? ""}
                      onChange={(e) => updateScope(idx, { mount: e.target.value })}
                      placeholder="secret/"
                    />
                  </div>
                  <div className="col-span-4">
                    <Input
                      label={idx === 0 ? "Path prefix" : undefined}
                      value={s.path ?? ""}
                      onChange={(e) => updateScope(idx, { path: e.target.value })}
                      placeholder="myapp/"
                    />
                  </div>
                </>
              ) : (
                <div className="col-span-8">
                  <Input
                    label={idx === 0 ? "Id" : undefined}
                    value={s.id ?? ""}
                    onChange={(e) => updateScope(idx, { id: e.target.value })}
                    placeholder={
                      s.type === "resource"
                        ? "resource id (e.g. t12)"
                        : "group name (lowercased)"
                    }
                  />
                </div>
              )}
              <div className="col-span-1">
                <Button variant="danger" size="sm" onClick={() => removeScope(idx)}>
                  ×
                </Button>
              </div>
            </div>
          ))}
          <Button size="sm" variant="secondary" onClick={addScope}>
            + Add scope
          </Button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Format"
            value={format}
            onChange={(e) => setFormat(e.target.value as "bvx" | "json")}
            options={[
              { value: "bvx", label: ".bvx (password-encrypted)" },
              { value: "json", label: "JSON (plaintext)" },
            ]}
          />
          {format === "bvx" ? (
            <Input
              label="Password (≥ 12 chars)"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Argon2id-derived key encrypts the export"
            />
          ) : (
            <label className="flex items-center gap-2 text-sm pt-7">
              <input
                type="checkbox"
                checked={allowPlaintext}
                onChange={(e) => setAllowPlaintext(e.target.checked)}
              />
              Allow plaintext export (refused by default)
            </label>
          )}
        </div>

        <Input
          label="Comment (optional, embedded in envelope)"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="weekly snapshot"
        />

        {format === "bvx" && password.length > 0 && password.length < 12 && (
          <p className="text-xs text-[var(--color-danger)]">
            Password must be at least 12 characters.
          </p>
        )}

        <div className="flex justify-end">
          <Button onClick={handleExport} loading={busy} disabled={scopes.length === 0}>
            Export & download
          </Button>
        </div>
      </div>
    </Card>
  );
}

function ImportTab({ toast }: { toast: ToastFn }) {
  const [fileB64, setFileB64] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [format, setFormat] = useState<"bvx" | "json">("bvx");
  const [password, setPassword] = useState("");
  const [allowPlaintext, setAllowPlaintext] = useState(false);
  const [preview, setPreview] = useState<ExchangePreviewResult | null>(null);
  const [conflictPolicy, setConflictPolicy] = useState<"skip" | "overwrite" | "rename">("skip");
  const [busy, setBusy] = useState(false);

  async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const buf = await f.arrayBuffer();
    let bin = "";
    const arr = new Uint8Array(buf);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    setFileB64(btoa(bin));
    setFileName(f.name);
    setFormat(f.name.endsWith(".json") ? "json" : "bvx");
    setPreview(null);
  }

  async function handlePreview() {
    if (!fileB64) {
      toast("error", "Pick a file first.");
      return;
    }
    setBusy(true);
    try {
      const result = await api.exchangePreview(
        fileB64,
        format,
        format === "bvx" ? password : undefined,
        format === "json" ? allowPlaintext : false,
      );
      setPreview(result);
    } catch (e) {
      toast("error", extractError(e));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  async function handleApply() {
    if (!preview) return;
    setBusy(true);
    try {
      const result = await api.exchangeApply(preview.token, conflictPolicy);
      toast(
        "success",
        `Applied: ${result.written} written, ${result.unchanged} unchanged, ${result.skipped} skipped, ${result.renamed} renamed.`,
      );
      setPreview(null);
      setFileB64("");
      setFileName("");
      setPassword("");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Import">
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="text-sm font-medium block mb-1">File</label>
            <input
              type="file"
              accept=".bvx,.json,application/json,application/octet-stream"
              onChange={handleFile}
              className="text-sm"
            />
            {fileName && (
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Loaded: {fileName}
              </p>
            )}
          </div>
          <Select
            label="Format"
            value={format}
            onChange={(e) => setFormat(e.target.value as "bvx" | "json")}
            options={[
              { value: "bvx", label: ".bvx (password-encrypted)" },
              { value: "json", label: "JSON (plaintext)" },
            ]}
          />
          {format === "bvx" ? (
            <Input
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          ) : (
            <label className="flex items-center gap-2 text-sm pt-7">
              <input
                type="checkbox"
                checked={allowPlaintext}
                onChange={(e) => setAllowPlaintext(e.target.checked)}
              />
              Allow plaintext import
            </label>
          )}
        </div>

        <div className="flex gap-2">
          <Button onClick={handlePreview} loading={busy && !preview} disabled={!fileB64}>
            Preview
          </Button>
          {preview && (
            <Button onClick={() => { setPreview(null); }} variant="secondary">
              Cancel preview
            </Button>
          )}
        </div>

        {preview && (
          <div className="space-y-3">
            <div className="rounded-md border border-[var(--color-border)] p-3 text-sm">
              <p>
                <strong>{preview.total}</strong> items —{" "}
                <span className="text-emerald-500">{preview.new} new</span> /{" "}
                <span className="text-[var(--color-text-muted)]">{preview.identical} identical</span> /{" "}
                <span className="text-amber-500">{preview.conflict} conflict</span>
              </p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Token expires in {preview.expires_in_secs}s.
              </p>
            </div>

            <PreviewTable items={preview.items} />

            <div className="grid grid-cols-2 gap-3">
              <Select
                label="Conflict policy"
                value={conflictPolicy}
                onChange={(e) => setConflictPolicy(e.target.value as "skip" | "overwrite" | "rename")}
                options={[
                  { value: "skip", label: "Skip (keep existing)" },
                  { value: "overwrite", label: "Overwrite" },
                  { value: "rename", label: "Rename (write to <path>.imported.<timestamp>)" },
                ]}
              />
            </div>

            <div className="flex justify-end">
              <Button onClick={handleApply} loading={busy}>
                Apply import
              </Button>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

function PreviewTable({ items }: { items: ExchangePreviewItem[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-[var(--color-text-muted)]">No items.</p>;
  }
  return (
    <div className="max-h-64 overflow-auto border border-[var(--color-border)] rounded-md">
      <table className="w-full text-xs">
        <thead className="bg-[var(--color-surface)] sticky top-0">
          <tr>
            <th className="text-left px-2 py-1">Mount</th>
            <th className="text-left px-2 py-1">Path</th>
            <th className="text-left px-2 py-1">Classification</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it, idx) => (
            <tr key={idx} className="odd:bg-[var(--color-surface)]/40">
              <td className="px-2 py-1 font-mono">{it.mount}</td>
              <td className="px-2 py-1 font-mono truncate max-w-xs">{it.path}</td>
              <td className="px-2 py-1">
                <ClassificationBadge classification={it.classification} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Inline reference for what each scope-selector type actually does.
 * Rendered above the scope picker on both the Export tab and the
 * Schedule editor. Mirrors `crate::exchange::scope::export_to_document`.
 */
function ScopeTypeHelp() {
  return (
    <details className="text-xs text-[var(--color-text-muted)] border border-[var(--color-border)] rounded-md px-3 py-2">
      <summary className="cursor-pointer select-none">
        What do the scope types mean?
      </summary>
      <ul className="list-disc pl-5 mt-2 space-y-1">
        <li>
          <strong>KV path</strong> — every key under{" "}
          <code className="font-mono">&lt;mount&gt;&lt;path-prefix&gt;</code>,
          recursive. The most common selector. Emits each leaf as a{" "}
          <code className="font-mono">kv</code> item with its mount and
          relative path preserved.
        </li>
        <li>
          <strong>Resource (by id)</strong> — one resource record from the
          first <code className="font-mono">resource</code>-typed mount.
          Pulls in the resource&rsquo;s metadata, history, and every per-key
          secret value + metadata + version log under it.
        </li>
        <li>
          <strong>Asset group / Resource group (by name)</strong> — these
          are the same concept (one storage prefix:{" "}
          <code className="font-mono">sys/resource-group/group/&lt;name&gt;</code>).
          Emits the group record itself <em>and</em> drags in every
          referenced member: the listed resources, the listed KV-secret
          paths, and the listed file-resource ids. Items the actor cannot
          read are silently skipped — the count appears in the document&rsquo;s{" "}
          <code className="font-mono">warnings</code> field.
        </li>
      </ul>
      <p className="mt-2">
        Multiple selectors compose. Add as many as you need; duplicates
        across selectors are deduplicated server-side before the document
        is signed.
      </p>
    </details>
  );
}

function ClassificationBadge({ classification }: { classification: string }) {
  const color =
    classification === "new"
      ? "text-emerald-500"
      : classification === "conflict"
        ? "text-amber-500"
        : "text-[var(--color-text-muted)]";
  return <span className={color}>{classification}</span>;
}

// ── Scheduled backups tab ────────────────────────────────────────────────
//
// Lets the operator define cron-driven `.bvx` (or plaintext JSON) backups
// that the embedded scheduler fires on a recurring cadence. The schedule
// record itself is persisted barrier-encrypted; the password lives via
// reference (`literal` or `static_secret` KV path) -- see
// `features/scheduled-exports.md`.

function SchedulesTab({ toast }: { toast: ToastFn }) {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [runHistory, setRunHistory] = useState<{ id: string; runs: RunRecord[] } | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      const list = await api.scheduledExportsList();
      setSchedules(list);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { refresh(); }, []);

  async function handleDelete() {
    if (!deletingId) return;
    try {
      await api.scheduledExportsDelete(deletingId);
      toast("success", "Schedule deleted.");
      setDeletingId(null);
      refresh();
    } catch (e) { toast("error", extractError(e)); }
  }

  async function handleRunNow(id: string) {
    try {
      const result = await api.scheduledExportsRunNow(id);
      if (result.status === "success") {
        toast("success", `Ran. Wrote ${result.bytes_written} bytes.`);
      } else {
        toast("error", `Run failed: ${result.error ?? "unknown"}`);
      }
    } catch (e) { toast("error", extractError(e)); }
  }

  async function handleViewRuns(id: string) {
    try {
      const runs = await api.scheduledExportsRuns(id);
      setRunHistory({ id, runs });
    } catch (e) { toast("error", extractError(e)); }
  }

  return (
    <Card
      title="Scheduled backups"
      actions={<Button size="sm" onClick={() => setEditing("new")}>+ New schedule</Button>}
    >
      {loading ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
      ) : schedules.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">
          No schedules yet. Click <strong>New schedule</strong> to define a recurring backup.
        </p>
      ) : (
        <div className="space-y-2">
          {schedules.map((s) => (
            <div
              key={s.id}
              className="flex items-start justify-between p-3 border border-[var(--color-border)] rounded-md gap-3"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="font-medium truncate">{s.name}</p>
                  <span className={`text-xs px-2 py-0.5 rounded ${s.enabled ? "bg-emerald-500/20 text-emerald-400" : "bg-[var(--color-surface)] text-[var(--color-text-muted)]"}`}>
                    {s.enabled ? "enabled" : "disabled"}
                  </span>
                  <span className="text-xs uppercase tracking-wider text-[var(--color-text-muted)]">{s.format}</span>
                </div>
                <p className="text-xs text-[var(--color-text-muted)] mt-1 font-mono">cron: {s.cron}</p>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5 truncate">
                  {s.destination.kind === "local_path" ? `local: ${s.destination.path}` : ""}
                </p>
              </div>
              <div className="flex flex-col gap-1 shrink-0">
                <Button size="sm" variant="ghost" onClick={() => handleViewRuns(s.id)}>Runs</Button>
                <Button size="sm" variant="ghost" onClick={() => handleRunNow(s.id)}>Run now</Button>
                <Button size="sm" variant="secondary" onClick={() => setEditing(s)}>Edit</Button>
                <Button size="sm" variant="danger" onClick={() => setDeletingId(s.id)}>Delete</Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {editing && (
        <ScheduleEditorModal
          schedule={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); refresh(); }}
          toast={toast}
        />
      )}

      <ConfirmModal
        open={deletingId !== null}
        onClose={() => setDeletingId(null)}
        onConfirm={handleDelete}
        title="Delete schedule"
        message="Run records for this schedule will also be removed. This cannot be undone."
        confirmLabel="Delete"
      />

      {runHistory && (
        <RunHistoryModal
          scheduleId={runHistory.id}
          runs={runHistory.runs}
          onClose={() => setRunHistory(null)}
        />
      )}
    </Card>
  );
}

function ScheduleEditorModal({
  schedule,
  onClose,
  onSaved,
  toast,
}: {
  schedule: Schedule | null;
  onClose: () => void;
  onSaved: () => void;
  toast: ToastFn;
}) {
  const isEdit = schedule !== null;
  const [name, setName] = useState(schedule?.name ?? "");
  const [cron, setCron] = useState(schedule?.cron ?? "0 0 3 * * *");
  const [format, setFormat] = useState<"bvx" | "json">(schedule?.format ?? "bvx");
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
  const [allowPlaintext, setAllowPlaintext] = useState(schedule?.allow_plaintext ?? false);
  const [comment, setComment] = useState(schedule?.comment ?? "");
  const [destPath, setDestPath] = useState(
    schedule?.destination.kind === "local_path" ? schedule.destination.path : "",
  );
  const [scopes, setScopes] = useState<ExchangeScopeSelector[]>(
    schedule?.scope.include ?? [{ type: "kv_path", mount: "secret/", path: "" }],
  );
  const [pwMode, setPwMode] = useState<"literal" | "static_secret">(
    schedule?.password_ref?.kind ?? "literal",
  );
  const [pwLiteral, setPwLiteral] = useState(
    schedule?.password_ref?.kind === "literal" ? schedule.password_ref.password : "",
  );
  const [pwSsMount, setPwSsMount] = useState(
    schedule?.password_ref?.kind === "static_secret" ? schedule.password_ref.mount : "secret/",
  );
  const [pwSsPath, setPwSsPath] = useState(
    schedule?.password_ref?.kind === "static_secret" ? schedule.password_ref.path : "",
  );
  const [busy, setBusy] = useState(false);

  function updateScope(idx: number, patch: Partial<ExchangeScopeSelector>) {
    setScopes((prev) => prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  }
  function addScope() {
    setScopes((prev) => [...prev, { type: "kv_path", mount: "secret/", path: "" }]);
  }
  function removeScope(idx: number) {
    setScopes((prev) => prev.filter((_, i) => i !== idx));
  }

  async function handleSave() {
    if (format === "bvx" && pwMode === "literal" && pwLiteral.length < 12) {
      toast("error", "Literal password must be at least 12 characters.");
      return;
    }
    setBusy(true);
    try {
      const input: ScheduleInput = {
        name,
        cron,
        format,
        scope: { kind: "selective", include: scopes },
        destination: { kind: "local_path", path: destPath },
        password_ref:
          format === "bvx"
            ? pwMode === "literal"
              ? { kind: "literal", password: pwLiteral }
              : { kind: "static_secret", mount: pwSsMount, path: pwSsPath }
            : null,
        allow_plaintext: format === "json" ? allowPlaintext : false,
        comment: comment || null,
        enabled,
      };
      if (isEdit && schedule) {
        await api.scheduledExportsUpdate(schedule.id, input);
      } else {
        await api.scheduledExportsCreate(input);
      }
      toast("success", isEdit ? "Schedule updated." : "Schedule created.");
      onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg w-full max-w-2xl max-h-[90vh] overflow-auto p-6 space-y-4">
        <div className="flex justify-between items-start">
          <h2 className="text-lg font-bold">{isEdit ? "Edit schedule" : "New schedule"}</h2>
          <button className="text-[var(--color-text-muted)] hover:text-[var(--color-text)]" onClick={onClose}>x</button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <Input
            label="Cron expression"
            value={cron}
            onChange={(e) => setCron(e.target.value)}
            hint="6 fields: sec min hour day-of-month month day-of-week"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Format"
            value={format}
            onChange={(e) => setFormat(e.target.value as "bvx" | "json")}
            options={[
              { value: "bvx", label: ".bvx (password-encrypted)" },
              { value: "json", label: "JSON (plaintext)" },
            ]}
          />
          <label className="flex items-center gap-2 text-sm pt-7">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled
          </label>
        </div>

        <div className="space-y-2">
          <p className="text-sm font-medium">Scope</p>
          <ScopeTypeHelp />
          {scopes.map((s, idx) => (
            <div key={idx} className="grid grid-cols-12 gap-2 items-end">
              <div className="col-span-3">
                <Select
                  label={idx === 0 ? "Type" : undefined}
                  value={s.type}
                  onChange={(e) => updateScope(idx, { type: e.target.value as ExchangeScopeSelector["type"] })}
                  options={[
                    { value: "kv_path", label: "KV path" },
                    { value: "resource", label: "Resource (by id)" },
                    { value: "asset_group", label: "Asset group (by name)" },
                    { value: "resource_group", label: "Resource group (by name)" },
                  ]}
                />
              </div>
              {s.type === "kv_path" ? (
                <>
                  <div className="col-span-4">
                    <Input
                      label={idx === 0 ? "Mount" : undefined}
                      value={s.mount ?? ""}
                      onChange={(e) => updateScope(idx, { mount: e.target.value })}
                      placeholder="secret/"
                    />
                  </div>
                  <div className="col-span-4">
                    <Input
                      label={idx === 0 ? "Path prefix" : undefined}
                      value={s.path ?? ""}
                      onChange={(e) => updateScope(idx, { path: e.target.value })}
                      placeholder="myapp/"
                    />
                  </div>
                </>
              ) : (
                <div className="col-span-8">
                  <Input
                    label={idx === 0 ? "Id" : undefined}
                    value={s.id ?? ""}
                    onChange={(e) => updateScope(idx, { id: e.target.value })}
                    placeholder={
                      s.type === "resource"
                        ? "resource id (e.g. t12)"
                        : "group name (lowercased)"
                    }
                  />
                </div>
              )}
              <div className="col-span-1">
                <Button variant="danger" size="sm" onClick={() => removeScope(idx)}>x</Button>
              </div>
            </div>
          ))}
          <Button size="sm" variant="secondary" onClick={addScope}>+ Add scope</Button>
        </div>

        <Input
          label="Destination directory (local path)"
          value={destPath}
          onChange={(e) => setDestPath(e.target.value)}
          placeholder="/var/backups/bvault/nightly"
        />

        {format === "bvx" && (
          <div className="space-y-2">
            <Select
              label="Password source"
              value={pwMode}
              onChange={(e) => setPwMode(e.target.value as "literal" | "static_secret")}
              options={[
                { value: "literal", label: "Literal (stored in schedule, barrier-encrypted)" },
                { value: "static_secret", label: "KV path (read at run time)" },
              ]}
            />
            {pwMode === "literal" ? (
              <Input
                label="Password (>= 12 chars)"
                type="password"
                value={pwLiteral}
                onChange={(e) => setPwLiteral(e.target.value)}
              />
            ) : (
              <div className="grid grid-cols-2 gap-3">
                <Input label="KV mount" value={pwSsMount} onChange={(e) => setPwSsMount(e.target.value)} />
                <Input
                  label="KV path"
                  value={pwSsPath}
                  onChange={(e) => setPwSsPath(e.target.value)}
                  hint="Value must be JSON with a password field"
                />
              </div>
            )}
          </div>
        )}

        {format === "json" && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={allowPlaintext} onChange={(e) => setAllowPlaintext(e.target.checked)} />
            Allow plaintext export (refused by default)
          </label>
        )}

        <Input
          label="Comment (optional, embedded in envelope)"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} loading={busy}>{isEdit ? "Save" : "Create"}</Button>
        </div>
      </div>
    </div>
  );
}

function RunHistoryModal({
  scheduleId,
  runs,
  onClose,
}: {
  scheduleId: string;
  runs: RunRecord[];
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg w-full max-w-3xl max-h-[80vh] overflow-auto p-6 space-y-3">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-lg font-bold">Run history</h2>
            <p className="text-xs text-[var(--color-text-muted)] font-mono">{scheduleId}</p>
          </div>
          <button className="text-[var(--color-text-muted)] hover:text-[var(--color-text)]" onClick={onClose}>x</button>
        </div>
        {runs.length === 0 ? (
          <p className="text-sm text-[var(--color-text-muted)]">No runs yet.</p>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-[var(--color-bg)] text-[var(--color-text-muted)]">
              <tr>
                <th className="text-left px-2 py-1">When</th>
                <th className="text-left px-2 py-1">Status</th>
                <th className="text-left px-2 py-1">Bytes</th>
                <th className="text-left px-2 py-1">Detail</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r, idx) => (
                <tr key={idx} className="odd:bg-[var(--color-bg)]/40">
                  <td className="px-2 py-1 font-mono">{r.run_at}</td>
                  <td className={`px-2 py-1 ${r.status === "success" ? "text-emerald-500" : "text-red-500"}`}>
                    {r.status}
                  </td>
                  <td className="px-2 py-1">{r.bytes_written}</td>
                  <td className="px-2 py-1 text-[var(--color-text-muted)] truncate max-w-md">
                    {r.error ?? (r.destination.kind === "local_path" ? r.destination.path : "")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
