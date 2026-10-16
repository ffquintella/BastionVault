/**
 * Resource Connect — SFTP session window (features/sftp-connect.md).
 *
 * Loaded into the WebviewWindow `session_open_sftp` builds
 * (`sftp-<token>`). Two file panes side by side — this machine on the left,
 * the resource on the right — and a transfer list underneath. URL params:
 *   token  — the session id every `sftp_*` command names
 *   closed — the event the host emits when the connection drops
 *   label  — operator-visible title (`sftp felipe@host:22`, with
 *            ` via rustion[<bastion>]` when brokered)
 *
 * A session brokered through a Rustion bastion (T141) shows the same
 * lifecycle chip as an SSH window: bastion name, time left, renew and
 * terminate. A direct session's chip renders nothing.
 *
 * Every file operation goes through the host, which refuses it unless this
 * window holds the session. Remote names are untrusted and filtered by the
 * host; this page never builds a path from anything but a listing it was
 * given, a breadcrumb, or a name the operator typed (validated on both
 * sides).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MouseEvent, ReactNode } from "react";
import { useSearchParams } from "react-router";
import { listen } from "@tauri-apps/api/event";
import {
  ArrowLeftRight,
  ArrowRight,
  ArrowLeft,
  FolderPlus,
  Pencil,
  Plug,
  Trash2,
  X,
} from "lucide-react";

import {
  sessionClose,
  sftpCancelTransfer,
  sftpHome,
  sftpLocalHome,
  sftpLocalMkdir,
  sftpMkdir,
  sftpRemove,
  sftpRename,
  sftpTransfer,
} from "../lib/api";
import type { SftpDirection, SftpTransferProgress } from "../lib/api";
import { extractError } from "../lib/error";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";
import { useWindowCloseGuard } from "../lib/sessionWindowClose";
import { existsConflict, formatSize, isValidEntryName, newTransferId } from "../lib/sftpPanes";
import type { PaneSide } from "../lib/sftpPanes";
import { RustionSessionChip } from "../components/RustionSessionChip";
import { WindowCloseConfirm } from "../components/session/CloseConfirm";
import { SftpFilePane } from "../components/session/SftpFilePane";
import type { PaneRow, SftpDragPayload } from "../components/session/SftpFilePane";

interface TransferRow {
  id: string;
  direction: SftpDirection;
  label: string;
  progress: SftpTransferProgress | null;
  result: "running" | "completed" | "cancelled" | "failed";
  error: string;
  skipped: number;
}

type Dialog =
  | { kind: "overwrite"; name: string; run: () => void }
  | { kind: "delete"; paths: string[] }
  | { kind: "name"; title: string; initial: string; submit: (name: string) => Promise<void> }
  | null;

interface Menu {
  x: number;
  y: number;
  side: PaneSide;
  row: PaneRow | null;
}

const other = (s: PaneSide): PaneSide => (s === "local" ? "remote" : "local");

function baseName(path: string): string {
  const t = path.replace(/[\\/]+$/, "");
  return t.slice(Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\")) + 1) || t;
}

export function SessionSftpWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const closedEvent = params.get("closed") ?? "";
  const label = params.get("label") ?? "sftp session";

  const [closedReason, setClosedReason] = useState<string | null>(null);
  const [paths, setPaths] = useState<Record<PaneSide, string>>({ local: "", remote: "" });
  const [selection, setSelection] = useState<Record<PaneSide, Set<string>>>({
    local: new Set(),
    remote: new Set(),
  });
  const [refresh, setRefresh] = useState<Record<PaneSide, number>>({ local: 0, remote: 0 });
  const [active, setActive] = useState<PaneSide>("local");
  const [transfers, setTransfers] = useState<TransferRow[]>([]);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [menu, setMenu] = useState<Menu | null>(null);
  const [notice, setNotice] = useState("");
  const pathsRef = useRef(paths);
  pathsRef.current = paths;

  const live = token !== "" && closedReason === null;
  useSessionHeartbeat(token !== "");
  const closeGuard = useWindowCloseGuard(() => (live ? [label] : []), token !== "");

  // Where each pane starts.
  useEffect(() => {
    if (!token) return;
    sftpLocalHome(token)
      .then((p) => setPaths((s) => ({ ...s, local: s.local || p })))
      .catch((e: unknown) => setNotice(extractError(e)));
    sftpHome(token)
      .then((p) => setPaths((s) => ({ ...s, remote: s.remote || p })))
      .catch((e: unknown) => setNotice(extractError(e)));
  }, [token]);

  // The connection dropping underneath the window.
  useEffect(() => {
    if (!closedEvent) return;
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<{ reason: string }>(closedEvent, (e) => setClosedReason(e.payload.reason || "disconnected")).then(
      (u) => {
        if (disposed) u();
        else unlisten = u;
      },
    );
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [closedEvent]);

  // Transfer progress.
  useEffect(() => {
    if (!token) return;
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<SftpTransferProgress>(`sftp-progress-${token}`, (e) => {
      const p = e.payload;
      setTransfers((list) => list.map((t) => (t.id === p.transfer_id ? { ...t, progress: p } : t)));
    }).then((u) => {
      if (disposed) u();
      else unlisten = u;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [token]);

  const bump = (side: PaneSide) => setRefresh((r) => ({ ...r, [side]: r[side] + 1 }));

  const navigate = useCallback((side: PaneSide, path: string) => {
    setPaths((s) => ({ ...s, [side]: path }));
    setSelection((s) => ({ ...s, [side]: new Set() }));
    // Navigating to the current folder is a refresh.
    if (pathsRef.current[side] === path) setRefresh((r) => ({ ...r, [side]: r[side] + 1 }));
  }, []);

  // ── Transfers ─────────────────────────────────────────────────────

  const startTransfer = useCallback(
    (from: PaneSide, sources: string[], destDir: string, overwrite = false) => {
      if (!live || sources.length === 0 || !destDir) return;
      const direction: SftpDirection = from === "local" ? "upload" : "download";
      const id = newTransferId();
      const what = sources.length === 1 ? baseName(sources[0]) : `${sources.length} items`;
      setTransfers((list) => [
        { id, direction, label: `${what} → ${destDir}`, progress: null, result: "running", error: "", skipped: 0 },
        ...list.filter((t) => t.result === "running").concat(list.filter((t) => t.result !== "running").slice(0, 20)),
      ]);
      sftpTransfer({ token, transfer_id: id, direction, sources, dest_dir: destDir, overwrite })
        .then((o) => {
          const conflict = o.outcome === "failed" && o.error ? existsConflict(o.error) : null;
          if (conflict) {
            setTransfers((list) => list.filter((t) => t.id !== id));
            setDialog({
              kind: "overwrite",
              name: conflict,
              run: () => startTransfer(from, sources, destDir, true),
            });
            return;
          }
          setTransfers((list) =>
            list.map((t) =>
              t.id === id ? { ...t, result: o.outcome, error: o.error ?? "", skipped: o.skipped } : t,
            ),
          );
          bump(other(from));
        })
        .catch((e: unknown) => {
          setTransfers((list) =>
            list.map((t) => (t.id === id ? { ...t, result: "failed", error: extractError(e) } : t)),
          );
        });
    },
    [live, token],
  );

  const copySelected = (from: PaneSide, sources?: string[], destDir?: string) => {
    const src = sources ?? [...selection[from]];
    startTransfer(from, src, destDir ?? paths[other(from)]);
  };

  const onDrop = (to: PaneSide) => (payload: SftpDragPayload, destDir: string) => {
    if (payload.side !== other(to)) return;
    startTransfer(payload.side, payload.paths, destDir);
  };

  // ── File actions ──────────────────────────────────────────────────

  const askNewFolder = (side: PaneSide) => {
    const dir = paths[side];
    if (!dir) return;
    setDialog({
      kind: "name",
      title: side === "local" ? "New folder on this machine" : "New folder on the server",
      initial: "",
      submit: async (name) => {
        if (side === "local") await sftpLocalMkdir(token, dir, name);
        else await sftpMkdir(token, dir, name);
        bump(side);
      },
    });
  };

  const askRename = () => {
    const sel = [...selection.remote];
    if (active !== "remote" || sel.length !== 1) return;
    setDialog({
      kind: "name",
      title: "Rename",
      initial: baseName(sel[0]),
      submit: async (name) => {
        await sftpRename(token, sel[0], name);
        setSelection((s) => ({ ...s, remote: new Set() }));
        bump("remote");
      },
    });
  };

  const askDelete = () => {
    const sel = [...selection.remote];
    if (active !== "remote" || sel.length === 0) return;
    setDialog({ kind: "delete", paths: sel });
  };

  const runDelete = async (targets: string[]) => {
    setDialog(null);
    const failed: string[] = [];
    for (const p of targets) {
      try {
        await sftpRemove(token, p);
      } catch (e: unknown) {
        failed.push(extractError(e));
      }
    }
    setSelection((s) => ({ ...s, remote: new Set() }));
    bump("remote");
    if (failed.length > 0) setNotice(failed.join("\n"));
  };

  const onKeyAction = (side: PaneSide) => (action: "delete" | "rename" | "mkdir" | "switch") => {
    if (action === "switch") setActive(other(side));
    else if (action === "mkdir") askNewFolder(side);
    else if (action === "rename") askRename();
    else askDelete();
  };

  const disconnect = () => {
    if (live) void sessionClose(token).catch(() => undefined);
    setClosedReason("operator closed the session");
  };

  const runningCount = transfers.filter((t) => t.result === "running").length;
  const activeSel = selection[active];
  const copyLabel = active === "local" ? "Upload" : "Download";
  const CopyIcon = active === "local" ? ArrowRight : ArrowLeft;
  const host = useMemo(() => label.replace(/^sftp\s+/, ""), [label]);
  const remoteTitle = host.split("@").pop()?.split(":")[0] ?? "remote";

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    window.addEventListener("click", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("blur", close);
    };
  }, [menu]);

  const pane = (side: PaneSide) => (
    <SftpFilePane
      side={side}
      token={token}
      title={side === "local" ? "This computer" : remoteTitle}
      path={paths[side]}
      active={active === side}
      refreshKey={refresh[side]}
      selected={selection[side]}
      onActivate={() => setActive(side)}
      onNavigate={(p) => navigate(side, p)}
      onSelect={(s) => setSelection((cur) => ({ ...cur, [side]: s }))}
      onCopy={(srcs, dest) => copySelected(side, srcs, dest)}
      onDrop={onDrop(side)}
      onContextMenu={(e: MouseEvent, row) => {
        e.preventDefault();
        setActive(side);
        setMenu({ x: e.clientX, y: e.clientY, side, row });
      }}
      onKeyAction={onKeyAction(side)}
      onListed={(canonical) => setPaths((s) => ({ ...s, [side]: canonical }))}
    />
  );

  return (
    <div className="flex h-screen flex-col bg-[var(--color-bg)] text-[var(--color-text)]">
      {/* Toolbar */}
      <header className="flex items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2">
        <span
          className={`h-2.5 w-2.5 shrink-0 rounded-full ${live ? "bg-[var(--color-success)]" : "bg-[var(--color-danger)]"}`}
          aria-hidden
        />
        <span className="min-w-0 truncate text-sm font-medium" title={label}>
          {host}
        </span>
        {!live && <span className="shrink-0 text-xs text-[var(--color-danger)]">Disconnected — {closedReason}</span>}
        <div className="ml-auto flex items-center gap-1">
          <RustionSessionChip token={token} />
          <ToolButton
            onClick={() => copySelected(active)}
            disabled={!live || activeSel.size === 0}
            title={`${copyLabel} the selection to the other pane (F5)`}
          >
            <CopyIcon size={15} />
            <span>{copyLabel}</span>
          </ToolButton>
          <ToolButton onClick={() => askNewFolder(active)} disabled={!live} title="New folder (F7)">
            <FolderPlus size={15} />
          </ToolButton>
          <ToolButton
            onClick={askRename}
            disabled={!live || active !== "remote" || selection.remote.size !== 1}
            title="Rename on the server (F2)"
          >
            <Pencil size={14} />
          </ToolButton>
          <ToolButton
            onClick={askDelete}
            disabled={!live || active !== "remote" || selection.remote.size === 0}
            title="Delete on the server (Delete)"
          >
            <Trash2 size={14} />
          </ToolButton>
          <span className="mx-1 h-5 w-px bg-[var(--color-border)]" />
          <ToolButton onClick={disconnect} disabled={!live} title="Disconnect">
            <Plug size={14} />
            <span>Disconnect</span>
          </ToolButton>
        </div>
      </header>

      {notice && (
        <div className="flex items-start gap-2 border-b border-[var(--color-danger)]/40 bg-[var(--color-danger)]/10 px-3 py-1.5 text-xs text-[var(--color-danger)]">
          <span className="min-w-0 flex-1 whitespace-pre-wrap">{notice}</span>
          <button type="button" onClick={() => setNotice("")} aria-label="Dismiss">
            <X size={13} />
          </button>
        </div>
      )}

      {/* The two panes */}
      <main className={`flex min-h-0 flex-1 ${live ? "" : "pointer-events-none opacity-60"}`}>
        {pane("local")}
        <div className="w-px shrink-0 bg-[var(--color-border)]" />
        {pane("remote")}
      </main>

      {/* Transfers */}
      {transfers.length > 0 && (
        <section className="max-h-44 shrink-0 overflow-auto border-t border-[var(--color-border)] bg-[var(--color-surface)]">
          <div className="flex items-center gap-2 px-3 py-1 text-xs font-semibold text-[var(--color-text-muted)]">
            <ArrowLeftRight size={13} />
            Transfers{runningCount > 0 ? ` (${runningCount} running)` : ""}
            <button
              type="button"
              className="ml-auto font-normal hover:text-[var(--color-text)]"
              onClick={() => setTransfers((l) => l.filter((t) => t.result === "running"))}
            >
              Clear finished
            </button>
          </div>
          {transfers.map((t) => (
            <TransferLine key={t.id} t={t} onCancel={() => void sftpCancelTransfer(token, t.id)} />
          ))}
        </section>
      )}

      {menu && (
        <ContextMenu
          menu={menu}
          live={live}
          selectionSize={selection[menu.side].size}
          onCopy={() => copySelected(menu.side)}
          onOpen={() => menu.row && navigate(menu.side, menu.row.path)}
          onNewFolder={() => askNewFolder(menu.side)}
          onRename={askRename}
          onDelete={askDelete}
        />
      )}

      {dialog?.kind === "overwrite" && (
        <ConfirmDialog
          title="Replace existing item?"
          body={`“${dialog.name}” already exists in the destination. Replace it? Folders are merged; files with the same name are replaced.`}
          confirm="Replace"
          danger
          onCancel={() => setDialog(null)}
          onConfirm={() => {
            const run = dialog.run;
            setDialog(null);
            run();
          }}
        />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog
          title={dialog.paths.length === 1 ? "Delete on the server?" : `Delete ${dialog.paths.length} items on the server?`}
          body={`${dialog.paths.map(baseName).join(", ")} will be removed from the server. Only files and empty folders can be deleted. This cannot be undone.`}
          confirm="Delete"
          danger
          onCancel={() => setDialog(null)}
          onConfirm={() => void runDelete(dialog.paths)}
        />
      )}
      {dialog?.kind === "name" && (
        <NameDialog
          title={dialog.title}
          initial={dialog.initial}
          onCancel={() => setDialog(null)}
          onSubmit={dialog.submit}
          onDone={() => setDialog(null)}
        />
      )}

      <WindowCloseConfirm guard={closeGuard} labels={live ? [label] : []} />
    </div>
  );
}

function ToolButton(props: { onClick: () => void; disabled?: boolean; title: string; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title}
      aria-label={props.title}
      className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {props.children}
    </button>
  );
}

function TransferLine({ t, onCancel }: { t: TransferRow; onCancel: () => void }) {
  const p = t.progress;
  const pct = p && p.bytes_total > 0 ? Math.min(100, Math.round((p.bytes_done / p.bytes_total) * 100)) : 0;
  const status =
    t.result === "running"
      ? p?.state === "planning" || !p
        ? "Preparing…"
        : `${p.files_done}/${p.files_total} files · ${formatSize(p.bytes_done)} of ${formatSize(p.bytes_total)}`
      : t.result === "completed"
        ? `Done${p ? ` · ${p.files_done} file${p.files_done === 1 ? "" : "s"}, ${formatSize(p.bytes_done)}` : ""}${
            t.skipped > 0 ? ` · ${t.skipped} skipped (symlinked folders or special files)` : ""
          }`
        : t.result === "cancelled"
          ? "Cancelled"
          : t.error || "Failed";
  return (
    <div className="flex items-center gap-3 px-3 py-1 text-xs">
      {t.direction === "upload" ? (
        <ArrowRight size={13} className="shrink-0 text-[var(--color-text-muted)]" aria-label="Upload" />
      ) : (
        <ArrowLeft size={13} className="shrink-0 text-[var(--color-text-muted)]" aria-label="Download" />
      )}
      <span className="w-1/3 min-w-0 truncate" title={t.label}>
        {t.label}
      </span>
      <div className="h-1.5 w-32 shrink-0 overflow-hidden rounded bg-[var(--color-border)]">
        <div
          className={`h-full ${
            t.result === "failed"
              ? "bg-[var(--color-danger)]"
              : t.result === "completed"
                ? "bg-[var(--color-success)]"
                : "bg-[var(--color-primary)]"
          }`}
          style={{ width: `${t.result === "completed" ? 100 : pct}%` }}
        />
      </div>
      <span
        className={`min-w-0 flex-1 truncate ${t.result === "failed" ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}
        title={status}
      >
        {status}
      </span>
      {t.result === "running" && (
        <button type="button" className="shrink-0 hover:text-[var(--color-danger)]" onClick={onCancel} aria-label="Cancel transfer">
          <X size={13} />
        </button>
      )}
    </div>
  );
}

function ContextMenu(props: {
  menu: Menu;
  live: boolean;
  selectionSize: number;
  onCopy: () => void;
  onOpen: () => void;
  onNewFolder: () => void;
  onRename: () => void;
  onDelete: () => void;
}) {
  const { menu } = props;
  const remote = menu.side === "remote";
  const items: { label: string; run: () => void; disabled?: boolean; danger?: boolean }[] = [];
  if (menu.row && menu.row.entry.kind !== "file" && menu.row.entry.target_kind === "dir") {
    items.push({ label: "Open", run: props.onOpen });
  }
  if (props.selectionSize > 0) {
    items.push({ label: remote ? "Download to the left pane" : "Upload to the right pane", run: props.onCopy });
  }
  items.push({ label: "New folder", run: props.onNewFolder });
  if (remote && props.selectionSize === 1) items.push({ label: "Rename", run: props.onRename });
  if (remote && props.selectionSize > 0) items.push({ label: "Delete", run: props.onDelete, danger: true });
  return (
    <div
      role="menu"
      className="fixed z-50 min-w-48 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] py-1 text-xs shadow-lg"
      style={{ left: Math.min(menu.x, window.innerWidth - 200), top: Math.min(menu.y, window.innerHeight - 160) }}
    >
      {items.map((it) => (
        <button
          key={it.label}
          type="button"
          role="menuitem"
          disabled={!props.live || it.disabled}
          onClick={it.run}
          className={`block w-full px-3 py-1.5 text-left hover:bg-[var(--color-surface-hover)] disabled:opacity-40 ${
            it.danger ? "text-[var(--color-danger)]" : ""
          }`}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}

function DialogFrame(props: { title: string; children: ReactNode; onCancel: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal aria-label={props.title}>
      <div className="w-full max-w-md rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-xl">
        <h2 className="mb-2 text-sm font-semibold">{props.title}</h2>
        {props.children}
      </div>
    </div>
  );
}

function ConfirmDialog(props: {
  title: string;
  body: string;
  confirm: string;
  danger?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <DialogFrame title={props.title} onCancel={props.onCancel}>
      <p className="mb-4 break-words text-xs text-[var(--color-text-muted)]">{props.body}</p>
      <div className="flex justify-end gap-2">
        <button type="button" className="rounded-md px-3 py-1.5 text-xs hover:bg-[var(--color-surface-hover)]" onClick={props.onCancel}>
          Cancel
        </button>
        <button
          type="button"
          autoFocus
          className={`rounded-md px-3 py-1.5 text-xs text-white ${
            props.danger ? "bg-[var(--color-danger)]" : "bg-[var(--color-primary)]"
          }`}
          onClick={props.onConfirm}
        >
          {props.confirm}
        </button>
      </div>
    </DialogFrame>
  );
}

function NameDialog(props: {
  title: string;
  initial: string;
  onCancel: () => void;
  onSubmit: (name: string) => Promise<void>;
  onDone: () => void;
}) {
  const [name, setName] = useState(props.initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const valid = isValidEntryName(name.trim());
  const submit = async () => {
    if (!valid || busy) return;
    setBusy(true);
    setError("");
    try {
      await props.onSubmit(name.trim());
      props.onDone();
    } catch (e: unknown) {
      setError(extractError(e));
      setBusy(false);
    }
  };
  return (
    <DialogFrame title={props.title} onCancel={props.onCancel}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <input
          autoFocus
          className="mb-2 w-full rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1.5 text-sm focus:border-[var(--color-primary)] focus:outline-none"
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-label="Name"
        />
        {name !== "" && !valid && (
          <p className="mb-2 text-xs text-[var(--color-danger)]">A name cannot be empty, “.”, “..”, or contain / or \.</p>
        )}
        {error && <p className="mb-2 text-xs text-[var(--color-danger)]">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="rounded-md px-3 py-1.5 text-xs hover:bg-[var(--color-surface-hover)]" onClick={props.onCancel}>
            Cancel
          </button>
          <button
            type="submit"
            disabled={!valid || busy}
            className="rounded-md bg-[var(--color-primary)] px-3 py-1.5 text-xs text-white disabled:opacity-40"
          >
            {busy ? "Working…" : "OK"}
          </button>
        </div>
      </form>
    </DialogFrame>
  );
}
