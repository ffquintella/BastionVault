import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Select,
  Table,
  Modal,
  ConfirmModal,
  Tabs,
  useToast,
} from "../components/ui";
import type { MountInfo } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const BUILTIN_ENGINE_TYPES = [
  { value: "kv", label: "KV (Version 1)" },
  { value: "kv-v2", label: "KV (Version 2)" },
];

/// Well-known engines that the GUI surfaces as one-click "Default
/// Engines" toggles. Each entry pairs the conventional mount path
/// (e.g. `pki/`) with the logical-type the backend expects when the
/// admin flips the toggle on. The `gates` field documents which
/// sidebar features depend on the mount: when the mount is absent
/// the corresponding nav links auto-hide (see `Layout.tsx`).
///
/// `system: true` marks mounts the operator should not unmount
/// (sys, identity, etc.) — the toggle renders disabled with an
/// explanation. We surface them so admins see a complete picture
/// of what's enabled, not so they can break their install.
type DefaultEngineSpec = {
  path: string;
  label: string;
  logicalType: string;
  description: string;
  gates: string;
  system?: boolean;
};

const DEFAULT_ENGINE_SPECS: DefaultEngineSpec[] = [
  {
    path: "secret/",
    label: "KV (key/value secrets)",
    logicalType: "kv-v2",
    description: "Encrypted key/value secret storage with versioning.",
    gates: "Secrets nav, secret/data/* paths",
  },
  {
    path: "resources/",
    label: "Resources",
    logicalType: "resource",
    description: "Infrastructure-resource inventory (hosts, accounts, ...).",
    gates: "Resources nav, Asset-Group resource picker",
  },
  {
    path: "files/",
    label: "Files",
    logicalType: "files",
    description: "Binary file blobs (keys, certs, configs).",
    gates: "Files nav",
  },
  {
    path: "pki/",
    label: "PKI",
    logicalType: "pki",
    description:
      "X.509 certificate authority (classical + post-quantum signatures).",
    gates: "PKI nav (also requires pki-user / pki-admin policy)",
  },
  {
    path: "ssh/",
    label: "SSH",
    logicalType: "ssh",
    description:
      "SSH CA + OTP credentials (Ed25519, ML-DSA-65 with `ssh_pqc` build).",
    gates: "SSH nav (CA / Roles / Sign / Creds tabs)",
  },
  {
    path: "totp/",
    label: "TOTP",
    logicalType: "totp",
    description:
      "Time-based one-time passwords (RFC 6238). Generate or import seeds, fetch live codes, validate.",
    gates: "TOTP nav (also requires totp-user / totp-admin policy)",
  },
  {
    path: "transit/",
    label: "Transit",
    logicalType: "transit",
    description:
      "Encryption-as-a-service. ChaCha20-Poly1305 + Ed25519 + ML-KEM-768 + ML-DSA-44/65/87. Versioned keys, rotate, datakey wrap/unwrap.",
    gates: "Requires transit-user / transit-admin policy. No GUI page yet — drive via API or CLI.",
  },
  {
    path: "identity/",
    label: "Identity",
    logicalType: "identity",
    description: "Entity / group store backing the auth system.",
    gates: "Identity Groups nav, all token issuance",
    system: true,
  },
  {
    path: "resource-group/",
    label: "Asset Groups",
    logicalType: "resource-group",
    description: "Named collections of resources for sharing/RBAC.",
    gates: "Asset Groups nav",
  },
  {
    path: "sys/",
    label: "System",
    logicalType: "system",
    description: "Internal control plane endpoints. Cannot be disabled.",
    gates: "Every admin feature",
    system: true,
  },
];

/// Plugin types a mount can be backed by. The host's
/// `MountsRouter::get_backend` resolves `plugin:<name>` strings
/// dynamically, so we just need to surface the registered plugins
/// of the right kind in the dropdown — no per-plugin dropdown entry
/// needs to be hard-coded.
const MOUNTABLE_PLUGIN_TYPES = new Set<string>([
  "secret-engine",
  "secret",
  "database",
  "transform",
]);

const AUTH_TYPES = [
  { value: "userpass", label: "Username & Password" },
  { value: "approle", label: "AppRole" },
  { value: "cert", label: "TLS Certificate" },
];

export function MountsPage() {
  const { toast } = useToast();
  const [tab, setTab] = useState("engines");
  const [mounts, setMounts] = useState<MountInfo[]>([]);
  const [authMethods, setAuthMethods] = useState<MountInfo[]>([]);
  const [loading, setLoading] = useState(true);

  // Mount engine form
  const [showMountEngine, setShowMountEngine] = useState(false);
  const [enginePath, setEnginePath] = useState("");
  const [engineType, setEngineType] = useState("kv");
  const [engineDesc, setEngineDesc] = useState("");

  // Enable auth form
  const [showEnableAuth, setShowEnableAuth] = useState(false);
  const [authPath, setAuthPath] = useState("");
  const [authType, setAuthType] = useState("userpass");
  const [authDesc, setAuthDesc] = useState("");

  // Delete targets
  const [deleteMount, setDeleteMount] = useState<string | null>(null);
  const [deleteAuth, setDeleteAuth] = useState<string | null>(null);

  // Plugin-as-mount: registered plugins of mountable kinds appear in
  // the Engine Type dropdown as `plugin:<name>` so an operator can
  // mount them the same way they'd mount KV.
  const [pluginEngineOptions, setPluginEngineOptions] = useState<
    { value: string; label: string }[]
  >([]);
  const engineTypeOptions = [...BUILTIN_ENGINE_TYPES, ...pluginEngineOptions];

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const [m, a, plugins] = await Promise.all([
        api.listMounts().catch(() => [] as MountInfo[]),
        api.listAuthMethods().catch(() => [] as MountInfo[]),
        api.pluginsList().catch(() => []),
      ]);
      setMounts(m);
      setAuthMethods(a);
      setPluginEngineOptions(
        plugins
          .filter((p) => MOUNTABLE_PLUGIN_TYPES.has(p.plugin_type))
          .map((p) => ({
            value: `plugin:${p.name}`,
            label: `${p.name} v${p.version} (plugin · ${p.plugin_type})`,
          })),
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleMountEngine() {
    try {
      await api.mountEngine(enginePath, engineType, engineDesc);
      toast("success", `Mounted ${engineType} at ${enginePath}`);
      setShowMountEngine(false);
      setEnginePath("");
      setEngineDesc("");
      loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleUnmountEngine() {
    if (!deleteMount) return;
    try {
      await api.unmountEngine(deleteMount);
      toast("success", `Unmounted ${deleteMount}`);
      setDeleteMount(null);
      loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  // One-click enable/disable for a well-known engine. Operates on the
  // conventional path (`pki/`, `secret/`, …) and uses the spec's
  // `logicalType`. We don't try to guess the path: if an admin wants
  // a custom layout (`pki-corp/`, `pki-internal/`) they can use the
  // free-form Mount Engine button on the Secret Engines tab.
  const [togglingDefault, setTogglingDefault] = useState<string | null>(null);
  async function handleToggleDefault(spec: DefaultEngineSpec, enabled: boolean) {
    if (spec.system) return;
    setTogglingDefault(spec.path);
    try {
      if (enabled) {
        await api.unmountEngine(spec.path);
        toast("success", `Disabled ${spec.label} (${spec.path})`);
      } else {
        await api.mountEngine(spec.path, spec.logicalType, spec.description);
        toast("success", `Enabled ${spec.label} at ${spec.path}`);
      }
      await loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setTogglingDefault(null);
    }
  }

  async function handleEnableAuth() {
    try {
      await api.enableAuthMethod(authPath, authType, authDesc);
      toast("success", `Enabled ${authType} at ${authPath}`);
      setShowEnableAuth(false);
      setAuthPath("");
      setAuthDesc("");
      loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDisableAuth() {
    if (!deleteAuth) return;
    try {
      await api.disableAuthMethod(deleteAuth);
      toast("success", `Disabled ${deleteAuth}`);
      setDeleteAuth(null);
      loadAll();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  const engineColumns = [
    {
      key: "path",
      header: "Path",
      className: "font-mono text-[var(--color-primary)]",
      render: (m: MountInfo) => m.path,
    },
    { key: "mount_type", header: "Type", render: (m: MountInfo) => m.mount_type },
    {
      key: "description",
      header: "Description",
      className: "text-[var(--color-text-muted)]",
      render: (m: MountInfo) => m.description || "-",
    },
    {
      key: "actions",
      header: "",
      className: "text-right w-24",
      render: (m: MountInfo) =>
        m.path !== "sys/" ? (
          <Button variant="danger" size="sm" onClick={() => setDeleteMount(m.path)}>
            Unmount
          </Button>
        ) : null,
    },
  ];

  const authColumns = [
    {
      key: "path",
      header: "Path",
      className: "font-mono text-[var(--color-primary)]",
      render: (m: MountInfo) => m.path,
    },
    { key: "mount_type", header: "Type", render: (m: MountInfo) => m.mount_type },
    {
      key: "actions",
      header: "",
      className: "text-right w-24",
      render: (m: MountInfo) =>
        m.path !== "token/" ? (
          <Button variant="danger" size="sm" onClick={() => setDeleteAuth(m.path)}>
            Disable
          </Button>
        ) : null,
    },
  ];

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Mounts</h1>
          <div className="flex gap-2">
            {tab === "engines" && (
              <Button size="sm" onClick={() => setShowMountEngine(true)}>
                Mount Engine
              </Button>
            )}
            {tab === "auth" && (
              <Button size="sm" onClick={() => setShowEnableAuth(true)}>
                Enable Auth
              </Button>
            )}
          </div>
        </div>

        <Tabs
          tabs={[
            { id: "engines", label: "Secret Engines" },
            { id: "defaults", label: "Default Engines" },
            { id: "auth", label: "Auth Methods" },
          ]}
          active={tab}
          onChange={setTab}
        />

        <Card>
          {loading ? (
            <p className="text-sm text-[var(--color-text-muted)] py-4">Loading...</p>
          ) : tab === "engines" ? (
            <Table
              columns={engineColumns}
              data={mounts}
              rowKey={(m) => m.path}
              emptyMessage="No secret engines mounted"
            />
          ) : tab === "defaults" ? (
            <DefaultEngines
              mounts={mounts}
              onToggle={handleToggleDefault}
              busyPath={togglingDefault}
            />
          ) : (
            <Table
              columns={authColumns}
              data={authMethods}
              rowKey={(m) => m.path}
              emptyMessage="No auth methods enabled"
            />
          )}
        </Card>

        {/* Mount engine modal */}
        <Modal
          open={showMountEngine}
          onClose={() => setShowMountEngine(false)}
          title="Mount Secret Engine"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowMountEngine(false)}>
                Cancel
              </Button>
              <Button onClick={handleMountEngine} disabled={!enginePath}>
                Mount
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="Path"
              value={enginePath}
              onChange={(e) => setEnginePath(e.target.value)}
              placeholder="kv/"
              hint='Path where the engine will be accessible (e.g., "kv/")'
            />
            <Select
              label="Engine Type"
              value={engineType}
              onChange={(e) => setEngineType(e.target.value)}
              options={engineTypeOptions}
            />
            <Input
              label="Description"
              value={engineDesc}
              onChange={(e) => setEngineDesc(e.target.value)}
              placeholder="Optional description"
            />
          </div>
        </Modal>

        {/* Enable auth modal */}
        <Modal
          open={showEnableAuth}
          onClose={() => setShowEnableAuth(false)}
          title="Enable Auth Method"
          actions={
            <>
              <Button variant="ghost" onClick={() => setShowEnableAuth(false)}>
                Cancel
              </Button>
              <Button onClick={handleEnableAuth} disabled={!authPath}>
                Enable
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input
              label="Path"
              value={authPath}
              onChange={(e) => setAuthPath(e.target.value)}
              placeholder="userpass/"
            />
            <Select
              label="Auth Type"
              value={authType}
              onChange={(e) => setAuthType(e.target.value)}
              options={AUTH_TYPES}
            />
            <Input
              label="Description"
              value={authDesc}
              onChange={(e) => setAuthDesc(e.target.value)}
              placeholder="Optional description"
            />
          </div>
        </Modal>

        {/* Delete confirmations */}
        <ConfirmModal
          open={deleteMount !== null}
          onClose={() => setDeleteMount(null)}
          onConfirm={handleUnmountEngine}
          title="Unmount Engine"
          message={`Are you sure you want to unmount "${deleteMount}"? All data in this engine will be lost.`}
          confirmLabel="Unmount"
        />
        <ConfirmModal
          open={deleteAuth !== null}
          onClose={() => setDeleteAuth(null)}
          onConfirm={handleDisableAuth}
          title="Disable Auth Method"
          message={`Are you sure you want to disable "${deleteAuth}"?`}
          confirmLabel="Disable"
        />
      </div>
    </Layout>
  );
}

/// Rendered as the body of the "Default Engines" tab. Each spec from
/// `DEFAULT_ENGINE_SPECS` becomes a card with a status pill and a
/// toggle button. The "enabled" determination is purely path-based:
/// we look up `spec.path` in the live mount list. Mounts with the
/// matching path but a *different* logical_type still show as
/// enabled — the admin can fix that up via the free-form Secret
/// Engines tab; we don't want this surface to silently re-mount and
/// destroy their data.
function DefaultEngines({
  mounts,
  onToggle,
  busyPath,
}: {
  mounts: MountInfo[];
  onToggle: (spec: DefaultEngineSpec, currentlyEnabled: boolean) => void;
  busyPath: string | null;
}) {
  const byPath = new Map(mounts.map((m) => [m.path, m]));
  return (
    <div className="space-y-2">
      <p className="text-xs text-[var(--color-text-muted)] pb-2">
        Toggle the well-known engines on or off. Sidebar links auto-hide
        when the corresponding mount is disabled.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {DEFAULT_ENGINE_SPECS.map((spec) => {
          const live = byPath.get(spec.path);
          const enabled = !!live;
          const typeMatches = !live || live.mount_type === spec.logicalType;
          const busy = busyPath === spec.path;
          return (
            <div
              key={spec.path}
              className="border border-[var(--color-border)] rounded-md p-3 flex flex-col gap-2 bg-[var(--color-surface)]"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="font-semibold text-sm truncate">
                    {spec.label}
                  </div>
                  <div className="text-[11px] text-[var(--color-text-muted)] font-mono truncate">
                    {spec.path}
                    {" · "}
                    {spec.logicalType}
                  </div>
                </div>
                <span
                  className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded shrink-0 ${
                    enabled
                      ? "bg-green-500/15 text-green-400"
                      : "bg-zinc-500/15 text-[var(--color-text-muted)]"
                  }`}
                >
                  {enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
              <p className="text-xs text-[var(--color-text-muted)]">
                {spec.description}
              </p>
              <p className="text-[11px] text-[var(--color-text-muted)] italic">
                Gates: {spec.gates}
              </p>
              {!typeMatches && (
                <p className="text-[11px] text-[var(--color-warning)]">
                  Mounted at {spec.path} with type{" "}
                  <span className="font-mono">{live?.mount_type}</span> —
                  manage manually.
                </p>
              )}
              <div className="flex justify-end pt-1">
                {spec.system ? (
                  <span className="text-[11px] text-[var(--color-text-muted)] italic">
                    System mount — always on
                  </span>
                ) : (
                  <Button
                    size="sm"
                    variant={enabled ? "danger" : "primary"}
                    disabled={busy}
                    onClick={() => onToggle(spec, enabled)}
                  >
                    {busy ? "…" : enabled ? "Disable" : "Enable"}
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
