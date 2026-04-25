import { useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Tabs, Input, Select, useToast } from "../components/ui";
import * as api from "../lib/api";
import type {
  ExchangeScopeSelector,
  ExchangePreviewResult,
  ExchangePreviewItem,
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
          ]}
          active={tab}
          onChange={setTab}
        />

        {tab === "export" && <ExportTab toast={toast} />}
        {tab === "import" && <ImportTab toast={toast} />}
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
                    { value: "resource", label: "Resource (reserved)" },
                    { value: "asset_group", label: "Asset group (reserved)" },
                    { value: "resource_group", label: "Resource group (reserved)" },
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
                    placeholder="(reserved — full resolution lands in a follow-up phase)"
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

function ClassificationBadge({ classification }: { classification: string }) {
  const color =
    classification === "new"
      ? "text-emerald-500"
      : classification === "conflict"
        ? "text-amber-500"
        : "text-[var(--color-text-muted)]";
  return <span className={color}>{classification}</span>;
}
