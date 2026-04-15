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

const ENGINE_TYPES = [
  { value: "kv", label: "KV (Version 1)" },
  { value: "kv-v2", label: "KV (Version 2)" },
];

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

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const [m, a] = await Promise.all([
        api.listMounts().catch(() => [] as MountInfo[]),
        api.listAuthMethods().catch(() => [] as MountInfo[]),
      ]);
      setMounts(m);
      setAuthMethods(a);
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
      toast("error", String(e));
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
      toast("error", String(e));
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
      toast("error", String(e));
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
      toast("error", String(e));
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
      <div className="max-w-4xl space-y-4">
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
              options={ENGINE_TYPES}
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
