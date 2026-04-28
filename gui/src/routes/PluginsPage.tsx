import React, { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, Input, Select, Modal, ConfirmModal, Badge, useToast } from "../components/ui";
import * as api from "../lib/api";
import type {
  PluginManifest,
  PluginInvokeResult,
  PluginConfigField,
  PluginConfigResult,
} from "../lib/api";
import { extractError } from "../lib/error";

/**
 * Admin page for the WASM plugin catalog.
 *
 * Listed under Admin → Plugins (sidebar). Lets operators register
 * `.wasm` plugins, inspect manifests, invoke for a quick test, and
 * delete. The page computes SHA-256 + size client-side so the operator
 * doesn't have to populate those fields on the manifest by hand.
 *
 * See `features/plugin-system.md` and `crate::plugins`.
 */
export function PluginsPage() {
  const { toast } = useToast();
  const [plugins, setPlugins] = useState<PluginManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [deletingName, setDeletingName] = useState<string | null>(null);
  const [invoking, setInvoking] = useState<PluginManifest | null>(null);
  const [configuring, setConfiguring] = useState<PluginManifest | null>(null);
  const [versioning, setVersioning] = useState<PluginManifest | null>(null);
  const [reloading, setReloading] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      setPlugins(await api.pluginsList());
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { refresh(); }, []);

  async function handleDelete() {
    if (!deletingName) return;
    try {
      await api.pluginsDelete(deletingName);
      toast("success", `Plugin "${deletingName}" deleted.`);
      setDeletingName(null);
      refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Plugins</h1>
          <Button onClick={() => setShowRegister(true)}>+ Register plugin</Button>
        </div>
        <p className="text-sm text-[var(--color-text-muted)]">
          WASM plugins run in a wasmtime sandbox with capability-gated host
          imports (storage scoped to a declared prefix, audit emit, log).
          See the{" "}
          <code className="font-mono text-xs">crate::plugins</code> module
          for the ABI.
        </p>

        <Card title="Registered plugins">
          {loading ? (
            <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
          ) : plugins.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">
              No plugins registered. Click <strong>Register plugin</strong> to
              upload a <code className="font-mono">.wasm</code> module.
            </p>
          ) : (
            <div className="space-y-2">
              {plugins.map((p) => (
                <PluginRow
                  key={p.name}
                  plugin={p}
                  reloading={reloading === p.name}
                  onInvoke={() => setInvoking(p)}
                  onConfigure={() => setConfiguring(p)}
                  onVersions={() => setVersioning(p)}
                  onReload={async () => {
                    setReloading(p.name);
                    try {
                      const r = await api.pluginsReload(p.name);
                      toast(
                        "success",
                        `Reloaded ${p.name} (active v${r.active_version}, evicted ${r.cache_entries_evicted} cache entry${r.cache_entries_evicted === 1 ? "" : "ies"}).`,
                      );
                    } catch (e) {
                      toast("error", extractError(e));
                    } finally {
                      setReloading(null);
                    }
                  }}
                  onDelete={() => setDeletingName(p.name)}
                />
              ))}
            </div>
          )}
        </Card>

        <PluginMetricsPanel />
      </div>

      {showRegister && (
        <RegisterModal
          onClose={() => setShowRegister(false)}
          onRegistered={() => { setShowRegister(false); refresh(); }}
        />
      )}

      {invoking && (
        <InvokeModal plugin={invoking} onClose={() => setInvoking(null)} />
      )}

      {configuring && (
        <ConfigureModal
          plugin={configuring}
          onClose={() => setConfiguring(null)}
          onSaved={() => setConfiguring(null)}
        />
      )}

      {versioning && (
        <VersionsModal
          plugin={versioning}
          onClose={() => setVersioning(null)}
          onChanged={() => {
            setVersioning(null);
            refresh();
          }}
        />
      )}

      <ConfirmModal
        open={deletingName !== null}
        onClose={() => setDeletingName(null)}
        onConfirm={handleDelete}
        title="Delete plugin"
        message={`Remove "${deletingName}" from the catalog? Stored manifest + binary will be deleted from the barrier.`}
        confirmLabel="Delete"
      />
    </Layout>
  );
}

function PluginRow({
  plugin,
  reloading,
  onInvoke,
  onConfigure,
  onVersions,
  onReload,
  onDelete,
}: {
  plugin: PluginManifest;
  reloading: boolean;
  onInvoke: () => void;
  onConfigure: () => void;
  onVersions: () => void;
  onReload: () => void;
  onDelete: () => void;
}) {
  const hasConfig = (plugin.config_schema?.length ?? 0) > 0;
  return (
    <div className="flex items-start justify-between p-3 border border-[var(--color-border)] rounded-md gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="font-medium truncate">{plugin.name}</p>
          <Badge label={`v${plugin.version}`} variant="info" />
          <Badge label={plugin.runtime} variant="neutral" />
          <Badge label={plugin.plugin_type || "—"} variant="neutral" />
        </div>
        <p className="text-xs text-[var(--color-text-muted)] mt-1 font-mono truncate">
          sha256: {plugin.sha256.slice(0, 16)}… · {plugin.size} bytes · ABI v{plugin.abi_version}
        </p>
        {plugin.description && (
          <p className="text-xs text-[var(--color-text-muted)] mt-1 truncate">
            {plugin.description}
          </p>
        )}
        <CapabilityBadges capabilities={plugin.capabilities} />
      </div>
      <div className="flex flex-col gap-1 shrink-0">
        <Button size="sm" variant="ghost" onClick={onInvoke}>Invoke</Button>
        {hasConfig && (
          <Button size="sm" variant="secondary" onClick={onConfigure}>Configure</Button>
        )}
        <Button size="sm" variant="ghost" onClick={onVersions}>Versions</Button>
        <Button size="sm" variant="ghost" onClick={onReload} loading={reloading}>
          Reload
        </Button>
        <Button size="sm" variant="danger" onClick={onDelete}>Delete</Button>
      </div>
    </div>
  );
}

function CapabilityBadges({ capabilities }: { capabilities: PluginManifest["capabilities"] }) {
  const items: { label: string; on: boolean; hint?: string }[] = [
    { label: "log", on: capabilities.log_emit, hint: "bv.log" },
    {
      label: capabilities.storage_prefix !== null
        ? `storage:${capabilities.storage_prefix === "" ? "*" : capabilities.storage_prefix}`
        : "storage",
      on: capabilities.storage_prefix !== null,
      hint: "bv.storage_*",
    },
    { label: "audit", on: capabilities.audit_emit, hint: "bv.audit_emit" },
  ];
  return (
    <div className="flex gap-1 mt-1.5 flex-wrap">
      {items.map((it) => (
        <span
          key={it.label}
          title={it.hint}
          className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
            it.on
              ? "bg-emerald-500/20 text-emerald-400"
              : "bg-[var(--color-surface)] text-[var(--color-text-muted)] line-through"
          }`}
        >
          {it.label}
        </span>
      ))}
    </div>
  );
}

function RegisterModal({
  onClose,
  onRegistered,
}: {
  onClose: () => void;
  onRegistered: () => void;
}) {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);

  // Manifest fields (operator-supplied).
  const [name, setName] = useState("");
  const [version, setVersion] = useState("0.1.0");
  const [pluginType, setPluginType] = useState("secret-engine");
  const [runtime, setRuntime] = useState<"wasm" | "process">("wasm");
  const [description, setDescription] = useState("");
  const [logEmit, setLogEmit] = useState(true);
  const [auditEmit, setAuditEmit] = useState(false);
  const [storageEnabled, setStorageEnabled] = useState(false);
  const [storagePrefix, setStoragePrefix] = useState("");

  // File-derived fields (computed client-side).
  const [fileBytes, setFileBytes] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState("");
  const [sha256, setSha256] = useState("");
  const [fromBundle, setFromBundle] = useState(false);
  const [configSchema, setConfigSchema] = useState<
    api.PluginConfigField[] | undefined
  >(undefined);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  /// Parse a `.bvplugin` container if the bytes start with the magic
  /// header; otherwise return null and treat the bytes as a raw `.wasm`.
  /// Format documented in `crates/bv-plugin-pack/src/main.rs`.
  function parseBundle(
    buf: Uint8Array,
  ): { manifest: api.PluginManifest; wasm: Uint8Array } | null {
    if (
      buf.length < 12 ||
      buf[0] !== 0x42 || // 'B'
      buf[1] !== 0x56 || // 'V'
      buf[2] !== 0x50 || // 'P'
      buf[3] !== 0x4c    // 'L'
    ) {
      return null;
    }
    const formatVersion = buf[4];
    if (formatVersion !== 1) {
      throw new Error(
        `unsupported bundle format version: ${formatVersion} (this build supports v1)`,
      );
    }
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const manifestLen = dv.getUint32(8, true);
    if (12 + manifestLen > buf.length) {
      throw new Error("bundle truncated: manifest length exceeds file size");
    }
    const manifestBytes = buf.subarray(12, 12 + manifestLen);
    const manifestText = new TextDecoder("utf-8", { fatal: true }).decode(
      manifestBytes,
    );
    const manifest = JSON.parse(manifestText) as api.PluginManifest;
    const wasm = buf.subarray(12 + manifestLen);
    return { manifest, wasm };
  }

  async function ingestFile(buf: Uint8Array, displayName: string) {
    let wasm = buf;
    let bundleManifest: api.PluginManifest | null = null;
    try {
      const parsed = parseBundle(buf);
      if (parsed) {
        bundleManifest = parsed.manifest;
        wasm = parsed.wasm;
      }
    } catch (e) {
      toast("error", `Bundle is invalid: ${(e as Error).message}`);
      return;
    }

    // sha256 is always over the WASM payload — never over the bundle
    // header — so re-registering after extracting from the bundle
    // produces the same hash as a raw .wasm upload.
    const digest = await crypto.subtle.digest("SHA-256", wasm as BufferSource);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    setFileBytes(wasm);
    setFileName(displayName);
    setSha256(hex);
    setFromBundle(bundleManifest !== null);

    if (bundleManifest) {
      // Sanity-check the embedded sha256 against what we just computed
      // — catches tampering between pack and upload.
      if (bundleManifest.sha256 && bundleManifest.sha256 !== hex) {
        toast(
          "error",
          `Bundle sha256 (${bundleManifest.sha256.slice(0, 16)}…) does not match the embedded WASM (${hex.slice(0, 16)}…). Refusing.`,
        );
        setFileBytes(null);
        setFromBundle(false);
        return;
      }
      // Prefill every field the manifest declared. Operators can still
      // tweak before clicking Register; we don't lock them out.
      setName(bundleManifest.name ?? "");
      setVersion(bundleManifest.version ?? "0.1.0");
      setPluginType(bundleManifest.plugin_type ?? "secret-engine");
      setRuntime(
        bundleManifest.runtime === "process" ? "process" : "wasm",
      );
      setDescription(bundleManifest.description ?? "");
      setLogEmit(bundleManifest.capabilities?.log_emit ?? false);
      setAuditEmit(bundleManifest.capabilities?.audit_emit ?? false);
      const sp = bundleManifest.capabilities?.storage_prefix ?? null;
      setStorageEnabled(sp !== null && sp !== undefined);
      setStoragePrefix(sp ?? "");
      setConfigSchema(bundleManifest.config_schema);
      toast(
        "success",
        `Loaded ${bundleManifest.config_schema?.length ?? 0} config field${
          (bundleManifest.config_schema?.length ?? 0) === 1 ? "" : "s"
        } from bundle "${bundleManifest.name}".`,
      );
    } else {
      // Raw `.wasm` — fall back to a name derived from the filename so
      // the operator at least gets a starting point. Runtime is always
      // wasm in the raw-file case (process plugins never use a .wasm
      // extension; if you have a process plugin, pack it).
      setConfigSchema(undefined);
      setRuntime("wasm");
      if (!name) {
        const leaf = displayName.split(/[\\/]/).pop() ?? displayName;
        setName(leaf.replace(/\.(wasm|bvplugin)$/i, ""));
      }
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const buf = new Uint8Array(await f.arrayBuffer());
    await ingestFile(buf, f.name);
  }

  /// Trigger the hidden <input type="file"> via a styled button. The
  /// WebView2 picker honours the `accept=".wasm"` filter so the
  /// operator gets a `.wasm`-filtered native dialog without needing a
  /// separate fs-plugin round-trip to read the bytes back into memory.
  function pickFile() {
    fileInputRef.current?.click();
  }

  async function handleRegister() {
    if (!fileBytes) {
      toast("error", "Pick a .wasm file first.");
      return;
    }
    if (!name.trim()) {
      toast("error", "Plugin name is required.");
      return;
    }
    setBusy(true);
    try {
      const manifest: PluginManifest = {
        name: name.trim(),
        version: version.trim() || "0.1.0",
        plugin_type: pluginType.trim() || "secret-engine",
        runtime,
        abi_version: "1.0",
        sha256,
        size: fileBytes.length,
        capabilities: {
          log_emit: logEmit,
          storage_prefix: storageEnabled ? storagePrefix : null,
          audit_emit: auditEmit,
          allowed_keys: [],
          allowed_hosts: [],
        },
        description: description.trim(),
        // Carry the bundle's config_schema through unchanged so the
        // GUI's Configure modal can render the same form the plugin
        // author declared.
        ...(configSchema && configSchema.length > 0
          ? { config_schema: configSchema }
          : {}),
      };
      // Base64-encode the binary for the Tauri command boundary.
      let bin = "";
      for (let i = 0; i < fileBytes.length; i++) bin += String.fromCharCode(fileBytes[i]);
      const binaryB64 = btoa(bin);
      await api.pluginsRegister(manifest, binaryB64);
      toast("success", `Registered "${manifest.name}".`);
      onRegistered();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={true} onClose={onClose} title="Register plugin" size="lg">
      <div className="space-y-4">
        <div>
          <label className="text-sm font-medium block mb-1">
            Plugin file
            <span className="ml-2 text-xs font-normal text-[var(--color-text-muted)]">
              .bvplugin (recommended) or raw .wasm
            </span>
          </label>
          <div className="flex items-center gap-2">
            <Button type="button" variant="secondary" onClick={pickFile}>
              Select file…
            </Button>
            <span className="text-xs text-[var(--color-text-muted)] font-mono truncate min-w-0">
              {fileName ? fileName : "(no file selected)"}
            </span>
            {fromBundle && <Badge variant="success" label="from bundle" />}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".wasm,.bvplugin,application/wasm,application/octet-stream"
            onChange={onFile}
            className="hidden"
          />
          {fileName && (
            <p className="text-xs text-[var(--color-text-muted)] mt-1 font-mono">
              {fileBytes?.length ?? 0} bytes · sha256 {sha256.slice(0, 16)}…
              {fromBundle && (
                <>
                  {" · "}
                  <span className="text-[var(--color-success)]">
                    manifest auto-filled from bundle
                  </span>
                </>
              )}
            </p>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="bv-plugin-totp" />
          <Input label="Version" value={version} onChange={(e) => setVersion(e.target.value)} />
          <Select
            label="Type"
            value={pluginType}
            onChange={(e) => setPluginType(e.target.value)}
            options={[
              { value: "secret-engine", label: "secret-engine" },
              { value: "auth-backend", label: "auth-backend" },
              { value: "database", label: "database" },
              { value: "transform", label: "transform" },
              { value: "other", label: "other" },
            ]}
          />
          <Select
            label="Runtime"
            value={runtime}
            onChange={(e) => setRuntime(e.target.value as "wasm" | "process")}
            options={[
              { value: "wasm", label: "wasm (sandboxed)" },
              { value: "process", label: "process (native subprocess)" },
            ]}
          />
          <Input
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <div className="space-y-2 border border-[var(--color-border)] rounded-md p-3">
          <p className="text-sm font-medium">Capabilities</p>
          <p className="text-xs text-[var(--color-text-muted)]">
            Each capability gates a host-import family. The wasmtime
            linker refuses to instantiate a plugin that imports symbols
            we did not register, so a plugin cannot accidentally rely on
            something it didn't declare.
          </p>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={logEmit} onChange={(e) => setLogEmit(e.target.checked)} />
            <span>
              <code className="font-mono text-xs">bv.log</code> — log lines
            </span>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={auditEmit} onChange={(e) => setAuditEmit(e.target.checked)} />
            <span>
              <code className="font-mono text-xs">bv.audit_emit</code> — emit audit events
            </span>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={storageEnabled}
              onChange={(e) => setStorageEnabled(e.target.checked)}
            />
            <span>
              <code className="font-mono text-xs">bv.storage_*</code> — get / put / list / delete
            </span>
          </label>
          {storageEnabled && (
            <div className="ml-6">
              <Input
                label="Storage prefix"
                value={storagePrefix}
                onChange={(e) => setStoragePrefix(e.target.value)}
                placeholder="(empty = anywhere under this plugin's data slot)"
                hint="Plugin keys must start with this prefix. Stored under core/plugins/{name}/data/{prefix}/{key}."
              />
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={handleRegister} loading={busy} disabled={!fileBytes}>Register</Button>
        </div>
      </div>
    </Modal>
  );
}

function InvokeModal({ plugin, onClose }: { plugin: PluginManifest; onClose: () => void }) {
  const { toast } = useToast();
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PluginInvokeResult | null>(null);

  async function handleInvoke() {
    setBusy(true);
    setResult(null);
    try {
      let inputB64: string | undefined = undefined;
      if (input) {
        let bin = "";
        for (let i = 0; i < input.length; i++) bin += String.fromCharCode(input.charCodeAt(i));
        inputB64 = btoa(bin);
      }
      const r = await api.pluginsInvoke(plugin.name, inputB64);
      setResult(r);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  function decodeResponse(r: PluginInvokeResult): string {
    try {
      const bin = atob(r.response_b64);
      // Try UTF-8; fall back to a hex preview if non-text.
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      return text;
    } catch {
      return "(non-utf8 response)";
    }
  }

  return (
    <Modal open={true} onClose={onClose} title={`Invoke ${plugin.name}`} size="lg">
      <div className="space-y-3">
        <Input
          label="Input (UTF-8 string)"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Bytes handed to the plugin's bv_run; what they mean is up to the plugin."
        />

        <div className="flex justify-end">
          <Button onClick={handleInvoke} loading={busy}>Invoke</Button>
        </div>

        {result && (
          <div className="border border-[var(--color-border)] rounded-md p-3 space-y-2">
            <div className="flex gap-2 items-center">
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  result.status === "success"
                    ? "bg-emerald-500/20 text-emerald-400"
                    : "bg-amber-500/20 text-amber-400"
                }`}
              >
                {result.status}
              </span>
              {result.status === "plugin_error" && (
                <span className="text-xs text-[var(--color-text-muted)] font-mono">
                  code {result.plugin_status_code}
                </span>
              )}
              <span className="text-xs text-[var(--color-text-muted)] font-mono ml-auto">
                fuel: {result.fuel_consumed.toLocaleString()}
              </span>
            </div>
            <p className="text-xs font-medium">Response</p>
            <pre className="text-xs font-mono bg-[var(--color-bg)] p-2 rounded max-h-64 overflow-auto whitespace-pre-wrap break-all">
              {decodeResponse(result) || "(empty)"}
            </pre>
          </div>
        )}
      </div>
    </Modal>
  );
}

/**
 * Renders a form from the plugin's `config_schema` and lets the
 * operator save values that the plugin reads at run time via
 * `bv.config_get`. Secret-kind fields show as a masked input that
 * displays `<set>` when populated; submitting the form with that
 * placeholder unchanged keeps the existing secret value (the host
 * recognises the placeholder and skips the overwrite).
 */
function ConfigureModal({
  plugin,
  onClose,
  onSaved,
}: {
  plugin: PluginManifest;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [loaded, setLoaded] = useState<PluginConfigResult | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await api.pluginsGetConfig(plugin.name);
        if (!alive) return;
        setLoaded(r);
        // Seed input state from current values, falling back to schema defaults.
        const seeded: Record<string, string> = {};
        for (const f of r.schema) {
          seeded[f.name] = r.values[f.name] ?? f.default ?? "";
        }
        setValues(seeded);
      } catch (e) {
        toast("error", extractError(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [plugin.name, toast]);

  function setField(name: string, value: string) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  async function handleSave() {
    if (!loaded) return;
    // Required-field check (the host validates too; this is a UX nicety
    // so the operator gets feedback before the round-trip).
    for (const f of loaded.schema) {
      if (f.required && !values[f.name]) {
        toast("error", `${f.label ?? f.name} is required`);
        return;
      }
    }
    setBusy(true);
    try {
      await api.pluginsSetConfig(plugin.name, values);
      toast("success", "Configuration saved.");
      onSaved();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={true} onClose={onClose} title={`Configure ${plugin.name}`} size="md">
      {!loaded ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : loaded.schema.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">
          This plugin declares no configuration knobs.
        </p>
      ) : (
        <div className="space-y-3">
          {loaded.schema.map((f) => (
            <ConfigInput
              key={f.name}
              field={f}
              value={values[f.name] ?? ""}
              onChange={(v) => setField(f.name, v)}
            />
          ))}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={handleSave} loading={busy}>
              Save
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/** One row in the ConfigureModal — picks the right input by `field.kind`. */
function ConfigInput({
  field,
  value,
  onChange,
}: {
  field: PluginConfigField;
  value: string;
  onChange: (v: string) => void;
}) {
  const label =
    (field.label ?? field.name) + (field.required ? " *" : "");
  const hint = field.description ?? undefined;

  switch (field.kind) {
    case "select":
      return (
        <Select
          label={label}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          options={[
            { value: "", label: "—" },
            ...(field.options ?? []).map((o) => ({ value: o, label: o })),
          ]}
        />
      );
    case "bool":
      return (
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={value === "true"}
            onChange={(e) => onChange(e.target.checked ? "true" : "false")}
          />
          <span>{label}</span>
          {hint && (
            <span className="text-xs text-[var(--color-text-muted)] ml-2">{hint}</span>
          )}
        </label>
      );
    case "int":
      return (
        <Input
          label={label}
          type="number"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          hint={hint}
        />
      );
    case "secret":
      return (
        <Input
          label={label}
          type="password"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          hint={hint ?? "Stored barrier-encrypted; <set> means a value is already saved."}
          placeholder={value === "<set>" ? "<set>" : ""}
        />
      );
    case "string":
    default:
      return (
        <Input
          label={label}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          hint={hint}
        />
      );
  }
}

/**
 * Versions panel: lists every registered version of a plugin, marks
 * the active one, lets the operator activate or delete non-active
 * versions. Activation invalidates the module-compilation cache so
 * the next invoke compiles the newly-active binary.
 */
function VersionsModal({
  plugin,
  onClose,
  onChanged,
}: {
  plugin: PluginManifest;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [versions, setVersions] = useState<PluginManifest[] | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function refresh() {
    try {
      const r = await api.pluginsVersions(plugin.name);
      setVersions(r.versions);
      setActive(r.active);
    } catch (e) {
      toast("error", extractError(e));
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    refresh();
  }, [plugin.name]);

  async function activate(version: string) {
    setBusy(version);
    try {
      await api.pluginsActivateVersion(plugin.name, version);
      toast("success", `Activated v${version}.`);
      await refresh();
      onChanged();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(null);
    }
  }

  async function remove(version: string) {
    setBusy(version);
    try {
      await api.pluginsDeleteVersion(plugin.name, version);
      toast("success", `Removed v${version}.`);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Modal open={true} onClose={onClose} title={`${plugin.name} — versions`} size="md">
      {!versions ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : versions.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">No versions registered.</p>
      ) : (
        <div className="space-y-2">
          {versions.map((m) => {
            const isActive = m.version === active;
            return (
              <div
                key={m.version}
                className={`flex items-center justify-between p-3 border rounded-md gap-3 ${
                  isActive
                    ? "border-emerald-500/40 bg-emerald-500/5"
                    : "border-[var(--color-border)]"
                }`}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">v{m.version}</p>
                    {isActive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">
                        active
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[var(--color-text-muted)] mt-1 font-mono truncate">
                    sha256: {m.sha256.slice(0, 16)}… · {m.size} bytes
                  </p>
                </div>
                <div className="flex gap-1 shrink-0">
                  {!isActive && (
                    <>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => activate(m.version)}
                        loading={busy === m.version}
                      >
                        Activate
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => remove(m.version)}
                        loading={busy === m.version}
                      >
                        Delete
                      </Button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      <p className="text-xs text-[var(--color-text-muted)] mt-3">
        Activating a different version invalidates the wasmtime
        compilation cache for this plugin. The next invoke recompiles
        the newly-active binary; subsequent invocations reuse the
        cached compile.
      </p>
    </Modal>
  );
}

// ── Phase 5.12 — per-plugin metrics panel ─────────────────────────
//
// Polls `plugins_metrics` (which projects the per-plugin slices of
// `bvault_plugin_invokes_total`, `bvault_plugin_fuel_consumed_total`,
// `bvault_plugin_invoke_duration_seconds` from the host's Prometheus
// registry) on a 5-second cadence. The full Prometheus surface stays
// available at `/sys/metrics`; this panel is a quick at-a-glance
// view for desktop operators who don't run a separate scrape.

function PluginMetricsPanel() {
  const { toast } = useToast();
  const [snapshots, setSnapshots] = useState<api.PluginMetricsSnapshot[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const list = await api.pluginsMetrics();
        if (!cancelled) {
          setSnapshots(list);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          toast("error", extractError(e));
          setLoading(false);
        }
      }
    }
    tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [toast]);

  return (
    <Card title="Per-plugin metrics">
      {loading ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : snapshots.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">
          No invokes recorded since boot. Mount a plugin and invoke it to
          populate counters.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-[var(--color-text-muted)] border-b border-[var(--color-border)]">
                <th className="py-1 pr-4">Plugin</th>
                <th className="py-1 pr-4">Success</th>
                <th className="py-1 pr-4">Plugin error</th>
                <th className="py-1 pr-4">Runtime error</th>
                <th className="py-1 pr-4">Fuel consumed</th>
                <th className="py-1 pr-4">Avg latency</th>
              </tr>
            </thead>
            <tbody>
              {snapshots.map((s) => {
                const avgMs =
                  s.invoke_duration_count === 0
                    ? null
                    : (s.invoke_duration_sum_secs / s.invoke_duration_count) *
                      1000;
                return (
                  <tr
                    key={s.plugin}
                    className="border-b border-[var(--color-border)]/40"
                  >
                    <td className="py-1 pr-4 font-mono">{s.plugin}</td>
                    <td className="py-1 pr-4">{s.invokes_success}</td>
                    <td className="py-1 pr-4">{s.invokes_plugin_error}</td>
                    <td className="py-1 pr-4">{s.invokes_runtime_error}</td>
                    <td className="py-1 pr-4">
                      {s.fuel_consumed_total.toLocaleString()}
                    </td>
                    <td className="py-1 pr-4">
                      {avgMs === null ? "—" : `${avgMs.toFixed(1)} ms`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-xs text-[var(--color-text-muted)] mt-2">
        Refreshes every 5 seconds. The full Prometheus surface — including
        latency-bucket histograms — is available at{" "}
        <code className="font-mono">/sys/metrics</code>.
      </p>
    </Card>
  );
}
