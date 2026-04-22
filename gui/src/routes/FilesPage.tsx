import { useState, useEffect, useRef } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Table,
  Modal,
  ConfirmModal,
  Tabs,
  useToast,
} from "../components/ui";
import type { FileMeta, FileSyncTarget, FileVersionInfo } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function FilesPage() {
  const { toast } = useToast();
  const [metas, setMetas] = useState<FileMeta[]>([]);
  const [selected, setSelected] = useState<FileMeta | null>(null);
  const [showUpload, setShowUpload] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<FileMeta | null>(null);

  async function refresh() {
    try {
      const result = await api.listFiles();
      const loaded: FileMeta[] = [];
      for (const id of result.ids) {
        try {
          loaded.push(await api.readFileMeta(id));
        } catch {
          /* ignore individual read failures so the list still renders */
        }
      }
      loaded.sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
      setMetas(loaded);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function doDelete(m: FileMeta) {
    try {
      await api.deleteFile(m.id);
      toast("success", `Deleted ${m.name || m.id}`);
      if (selected?.id === m.id) setSelected(null);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setConfirmDelete(null);
    }
  }

  async function doDownload(m: FileMeta) {
    try {
      const c = await api.readFileContent(m.id);
      const bytes = fromBase64(c.content_base64);
      // Copy into a fresh ArrayBuffer so TS's BlobPart accepts it even
      // under strict `ArrayBufferLike ≠ ArrayBuffer` typings.
      const copy = new Uint8Array(bytes.length);
      copy.set(bytes);
      const blob = new Blob([copy.buffer], {
        type: c.mime_type || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = m.name || m.id;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Layout>
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">Files</h1>
          <Button size="sm" onClick={() => setShowUpload(true)}>
            Upload File
          </Button>
        </div>

        <Card title="All Files">
          <Table<FileMeta>
            columns={[
              {
                key: "name",
                header: "Name",
                render: (m) =>
                  m.name ? m.name : <span className="opacity-60">{m.id}</span>,
              },
              {
                key: "mime_type",
                header: "Type",
                render: (m) => m.mime_type || "—",
              },
              {
                key: "size_bytes",
                header: "Size",
                render: (m) => fmtBytes(m.size_bytes),
              },
              {
                key: "updated_at",
                header: "Updated",
                render: (m) =>
                  m.updated_at ? new Date(m.updated_at).toLocaleString() : "—",
              },
              {
                key: "actions",
                header: "",
                render: (m) => (
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => setSelected(m)}
                    >
                      Details
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => doDownload(m)}
                    >
                      Download
                    </Button>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => setConfirmDelete(m)}
                    >
                      Delete
                    </Button>
                  </div>
                ),
              },
            ]}
            data={metas}
            rowKey={(m) => m.id}
            emptyMessage="No files yet. Upload one to get started."
          />
        </Card>
      </div>

      <UploadModal
        open={showUpload}
        onClose={() => setShowUpload(false)}
        onCreated={async () => {
          setShowUpload(false);
          await refresh();
        }}
      />

      {selected && (
        <FileDetailModal
          meta={selected}
          onClose={() => setSelected(null)}
          onChanged={async () => {
            await refresh();
            if (selected) {
              try {
                setSelected(await api.readFileMeta(selected.id));
              } catch {
                setSelected(null);
              }
            }
          }}
        />
      )}

      <ConfirmModal
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        title="Delete file?"
        message={
          confirmDelete
            ? `This will permanently remove "${
                confirmDelete.name || confirmDelete.id
              }", its content, and all sync-target configurations. Already-synced copies on remote hosts are not touched.`
            : ""
        }
        confirmLabel="Delete"
        onConfirm={() => confirmDelete && doDelete(confirmDelete)}
      />
    </Layout>
  );
}

// ── Upload modal ──────────────────────────────────────────────────

function UploadModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [resource, setResource] = useState("");
  const [mimeType, setMimeType] = useState("");
  const [notes, setNotes] = useState("");
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  async function handleFileChoose(f: File | undefined) {
    if (!f) return;
    if (!name) setName(f.name);
    if (!mimeType && f.type) setMimeType(f.type);
    const buf = new Uint8Array(await f.arrayBuffer());
    setBytes(buf);
  }

  async function submit() {
    if (!bytes) {
      toast("error", "Choose a file first");
      return;
    }
    if (!name.trim()) {
      toast("error", "Name is required");
      return;
    }
    setBusy(true);
    try {
      await api.createFile({
        name,
        content_base64: toBase64(bytes),
        resource: resource || undefined,
        mime_type: mimeType || undefined,
        notes: notes || undefined,
      });
      toast("success", "File uploaded");
      onCreated();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Upload File"
      size="md"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Uploading…" : "Upload"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div>
          <label className="text-xs text-[var(--color-text-muted)]">File</label>
          <div className="flex items-center gap-2 mt-1">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => fileInput.current?.click()}
            >
              Choose file…
            </Button>
            <span className="text-sm">
              {bytes ? `${fmtBytes(bytes.length)} selected` : "No file selected"}
            </span>
            <input
              ref={fileInput}
              type="file"
              style={{ display: "none" }}
              onChange={(e) => handleFileChoose(e.target.files?.[0])}
            />
          </div>
        </div>
        <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Resource (optional)"
            value={resource}
            onChange={(e) => setResource(e.target.value)}
          />
          <Input
            label="MIME type (optional)"
            value={mimeType}
            onChange={(e) => setMimeType(e.target.value)}
          />
        </div>
        <Input
          label="Notes (optional)"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </div>
    </Modal>
  );
}

// ── Detail modal (Info + Sync tabs) ───────────────────────────────

function FileDetailModal({
  meta,
  onClose,
  onChanged,
}: {
  meta: FileMeta;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [active, setActive] = useState("info");
  return (
    <Modal open={true} onClose={onClose} title={meta.name || meta.id} size="lg">
      <Tabs
        tabs={[
          { id: "info", label: "Info" },
          { id: "sync", label: "Sync" },
          { id: "versions", label: "Versions" },
        ]}
        active={active}
        onChange={setActive}
      />
      <div className="mt-4">
        {active === "info" && <InfoTab meta={meta} />}
        {active === "sync" && <SyncTab meta={meta} onChanged={onChanged} />}
        {active === "versions" && (
          <VersionsTab meta={meta} onChanged={onChanged} />
        )}
      </div>
    </Modal>
  );
}

function VersionsTab({
  meta,
  onChanged,
}: {
  meta: FileMeta;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [currentVersion, setCurrentVersion] = useState(0);
  const [versions, setVersions] = useState<FileVersionInfo[]>([]);
  const [confirmRestore, setConfirmRestore] = useState<FileVersionInfo | null>(
    null,
  );

  async function refresh() {
    try {
      const r = await api.listFileVersions(meta.id);
      setCurrentVersion(r.current_version);
      setVersions(r.versions);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [meta.id]);

  async function downloadVersion(v: FileVersionInfo) {
    try {
      const c = await api.readFileVersionContent(meta.id, v.version);
      const bytes = fromBase64(c.content_base64);
      const copy = new Uint8Array(bytes.length);
      copy.set(bytes);
      const blob = new Blob([copy.buffer], {
        type: c.mime_type || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${v.name || meta.name || meta.id}.v${v.version}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function restore(v: FileVersionInfo) {
    try {
      await api.restoreFileVersion(meta.id, v.version);
      toast("success", `Restored v${v.version}`);
      await refresh();
      onChanged();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setConfirmRestore(null);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="text-sm text-[var(--color-text-muted)]">
        Historical content versions (most recent first). The live content is
        version {currentVersion || "—"}; retention keeps the most recent 5
        prior versions.
      </div>
      <Table<FileVersionInfo>
        columns={[
          { key: "version", header: "Version", render: (v) => `v${v.version}` },
          {
            key: "size_bytes",
            header: "Size",
            render: (v) => fmtBytes(v.size_bytes),
          },
          {
            key: "sha256",
            header: "SHA-256",
            render: (v) => (
              <span className="font-mono text-xs break-all">
                {v.sha256.slice(0, 16)}…
              </span>
            ),
          },
          { key: "user", header: "By", render: (v) => v.user || "—" },
          {
            key: "created_at",
            header: "Displaced at",
            render: (v) =>
              v.created_at ? new Date(v.created_at).toLocaleString() : "—",
          },
          {
            key: "actions",
            header: "",
            render: (v) => (
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => downloadVersion(v)}
                >
                  Download
                </Button>
                <Button size="sm" onClick={() => setConfirmRestore(v)}>
                  Restore
                </Button>
              </div>
            ),
          },
        ]}
        data={[...versions].reverse()}
        rowKey={(v) => String(v.version)}
        emptyMessage="No historical versions yet. They accumulate as the file's content is updated."
      />

      <ConfirmModal
        open={!!confirmRestore}
        onClose={() => setConfirmRestore(null)}
        title="Restore version?"
        message={
          confirmRestore
            ? `Replace the current content with version ${confirmRestore.version}. The displaced content is snapshotted as a new version, so restore is reversible.`
            : ""
        }
        confirmLabel="Restore"
        variant="primary"
        onConfirm={() => confirmRestore && restore(confirmRestore)}
      />
    </div>
  );
}

function InfoTab({ meta }: { meta: FileMeta }) {
  const Row = ({ k, v }: { k: string; v: string }) => (
    <div className="flex gap-4 text-sm py-1">
      <span className="w-32 text-[var(--color-text-muted)]">{k}</span>
      <span className="font-mono break-all">{v || "—"}</span>
    </div>
  );
  return (
    <div className="flex flex-col gap-1">
      <Row k="id" v={meta.id} />
      <Row k="resource" v={meta.resource} />
      <Row k="mime_type" v={meta.mime_type} />
      <Row k="size" v={fmtBytes(meta.size_bytes)} />
      <Row k="sha256" v={meta.sha256} />
      <Row k="tags" v={meta.tags.join(", ")} />
      <Row k="notes" v={meta.notes} />
      <Row
        k="created_at"
        v={meta.created_at ? new Date(meta.created_at).toLocaleString() : ""}
      />
      <Row
        k="updated_at"
        v={meta.updated_at ? new Date(meta.updated_at).toLocaleString() : ""}
      />
    </div>
  );
}

function SyncTab({
  meta,
  onChanged,
}: {
  meta: FileMeta;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [targets, setTargets] = useState<FileSyncTarget[]>([]);
  const [showAdd, setShowAdd] = useState(false);

  async function refresh() {
    try {
      const r = await api.listFileSyncTargets(meta.id);
      setTargets(r.targets);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [meta.id]);

  async function push(t: FileSyncTarget) {
    try {
      await api.pushFileSyncTarget(meta.id, t.name);
      toast("success", `Pushed to ${t.name}`);
      await refresh();
      onChanged();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  async function remove(t: FileSyncTarget) {
    try {
      await api.deleteFileSyncTarget(meta.id, t.name);
      await refresh();
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-between items-center">
        <div className="text-sm text-[var(--color-text-muted)]">
          Sync targets push this file's content to another location. Only
          <code className="mx-1">local-fs</code>is supported in Phase 3; SMB /
          SFTP / SCP land in later phases.
        </div>
        <Button size="sm" onClick={() => setShowAdd(true)}>
          Add target
        </Button>
      </div>
      <Table<FileSyncTarget>
        columns={[
          { key: "name", header: "Name", render: (t) => t.name },
          { key: "kind", header: "Kind", render: (t) => t.kind },
          {
            key: "target_path",
            header: "Target",
            render: (t) => (
              <span className="font-mono text-xs">{t.target_path}</span>
            ),
          },
          {
            key: "last",
            header: "Last push",
            render: (t) =>
              t.state.last_error
                ? `⚠ ${t.state.last_failure_at || ""}`
                : t.state.last_success_at
                  ? new Date(t.state.last_success_at).toLocaleString()
                  : "never",
          },
          {
            key: "actions",
            header: "",
            render: (t) => (
              <div className="flex gap-2">
                <Button size="sm" onClick={() => push(t)}>
                  Push
                </Button>
                <Button size="sm" variant="danger" onClick={() => remove(t)}>
                  Remove
                </Button>
              </div>
            ),
          },
        ]}
        data={targets}
        rowKey={(t) => t.name}
        emptyMessage="No sync targets configured."
      />

      <AddSyncTargetModal
        open={showAdd}
        fileId={meta.id}
        onClose={() => setShowAdd(false)}
        onCreated={async () => {
          setShowAdd(false);
          await refresh();
        }}
      />
    </div>
  );
}

function AddSyncTargetModal({
  open,
  fileId,
  onClose,
  onCreated,
}: {
  open: boolean;
  fileId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("primary");
  const [targetPath, setTargetPath] = useState("");
  const [mode, setMode] = useState("0600");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!name || !targetPath) {
      toast("error", "Name and target path are required");
      return;
    }
    setBusy(true);
    try {
      await api.writeFileSyncTarget({
        id: fileId,
        name,
        kind: "local-fs",
        target_path: targetPath,
        mode: mode || undefined,
      });
      toast("success", "Sync target configured");
      onCreated();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add local-fs sync target"
      size="sm"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="text-sm text-[var(--color-text-muted)]">
          The target host is trusted with the plaintext content.
        </div>
        <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <Input
          label="Target path"
          placeholder="/etc/ssl/private/gateway.pem"
          value={targetPath}
          onChange={(e) => setTargetPath(e.target.value)}
        />
        <Input label="Mode (octal)" value={mode} onChange={(e) => setMode(e.target.value)} />
      </div>
    </Modal>
  );
}
