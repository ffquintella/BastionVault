/**
 * One side of the SFTP dual-pane window (features/sftp-connect.md): a
 * folder listing with a breadcrumb, sortable Name / Size / Date columns,
 * inline folder expansion, multi-selection, keyboard navigation and drag
 * and drop to the other pane.
 *
 * The pane owns its listing; the window owns where it is, what is
 * selected, and every action that changes a file.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent, KeyboardEvent, MouseEvent } from "react";
import {
  ArrowUp,
  ChevronDown,
  ChevronRight,
  File as FileIcon,
  Folder,
  FolderSymlink,
  HardDrive,
  Link2,
  RefreshCw,
  Search,
  Server,
} from "lucide-react";

import { sftpList, sftpLocalList } from "../../lib/api";
import type { SftpEntry } from "../../lib/api";
import { extractError } from "../../lib/error";
import {
  filterEntries,
  formatDate,
  formatPermissions,
  formatSize,
  isNavigable,
  joinPath,
  parentPath,
  pathSegments,
  sortEntries,
} from "../../lib/sftpPanes";
import type { PaneSide, SortKey, SortState } from "../../lib/sftpPanes";

/** dataTransfer type of a drag between the two panes. */
export const SFTP_DRAG_TYPE = "application/x-bv-sftp";

export interface SftpDragPayload {
  side: PaneSide;
  paths: string[];
}

/** One visible row: an entry at some depth of the inline tree. */
export interface PaneRow {
  entry: SftpEntry;
  path: string;
  depth: number;
}

export interface SftpFilePaneProps {
  side: PaneSide;
  token: string;
  /** Operator-visible name of this side (`felipe`, `apldc1vds0044`). */
  title: string;
  path: string;
  active: boolean;
  /** Bumped by the window after anything changed this side. */
  refreshKey: number;
  selected: Set<string>;
  onActivate: () => void;
  onNavigate: (path: string) => void;
  onSelect: (paths: Set<string>, rows: PaneRow[]) => void;
  /** Copy these paths of this side to `destDir` on the other side. */
  onCopy: (paths: string[], destDir?: string) => void;
  /** Files dropped from the other pane onto `destDir` of this one. */
  onDrop: (payload: SftpDragPayload, destDir: string) => void;
  onContextMenu: (e: MouseEvent, row: PaneRow | null) => void;
  /** Keyboard actions the window implements. */
  onKeyAction: (action: "delete" | "rename" | "mkdir" | "switch") => void;
  /** The canonical path the side reported, once listed. */
  onListed: (canonical: string) => void;
}

const SORT_LABELS: Record<SortKey, string> = { name: "Name", size: "Size", date: "Date" };

export function SftpFilePane(props: SftpFilePaneProps) {
  const { side, token, path, refreshKey, selected, onSelect, onListed } = props;
  const [entries, setEntries] = useState<SftpEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [skipped, setSkipped] = useState(0);
  const [sort, setSort] = useState<SortState>({ key: "name", asc: true });
  const [query, setQuery] = useState("");
  const [showHidden, setShowHidden] = useState(false);
  /** Inline-expanded folders and their loaded children, by path. */
  const [expanded, setExpanded] = useState<Map<string, SftpEntry[] | "loading">>(new Map());
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const anchor = useRef<string | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  const list = useCallback(
    (p: string) => (side === "local" ? sftpLocalList(token, p) : sftpList(token, p)),
    [side, token],
  );

  useEffect(() => {
    if (!token || !path) return;
    let cancelled = false;
    setLoading(true);
    setError("");
    list(path)
      .then((l) => {
        if (cancelled) return;
        setEntries(l.entries);
        setSkipped(l.skipped_unsafe);
        setExpanded(new Map());
        if (l.path !== path) onListed(l.path);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setEntries([]);
          setError(extractError(e));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // `onListed` is a callback from the window; re-listing on its identity
    // would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list, path, refreshKey, token]);

  const rows = useMemo(() => {
    const out: PaneRow[] = [];
    const add = (items: SftpEntry[], dir: string, depth: number) => {
      for (const entry of sortEntries(filterEntries(items, depth === 0 ? query : "", showHidden), sort)) {
        const p = joinPath(dir, entry.name);
        out.push({ entry, path: p, depth });
        const children = expanded.get(p);
        if (Array.isArray(children)) add(children, p, depth + 1);
      }
    };
    add(entries, path, 0);
    return out;
  }, [entries, expanded, path, query, showHidden, sort]);

  const toggleExpand = (row: PaneRow) => {
    const next = new Map(expanded);
    if (next.has(row.path)) {
      for (const k of [...next.keys()]) if (k === row.path || k.startsWith(row.path + "/") || k.startsWith(row.path + "\\")) next.delete(k);
      setExpanded(next);
      return;
    }
    next.set(row.path, "loading");
    setExpanded(next);
    list(row.path)
      .then((l) => setExpanded((m) => (m.has(row.path) ? new Map(m).set(row.path, l.entries) : m)))
      .catch((e: unknown) => {
        setExpanded((m) => {
          const n = new Map(m);
          n.delete(row.path);
          return n;
        });
        setError(extractError(e));
      });
  };

  const open = (row: PaneRow) => {
    if (isNavigable(row.entry)) props.onNavigate(row.path);
    else props.onCopy([row.path]);
  };

  const clickRow = (e: MouseEvent, row: PaneRow) => {
    props.onActivate();
    const next = new Set(selected);
    if (e.shiftKey && anchor.current) {
      const a = rows.findIndex((r) => r.path === anchor.current);
      const b = rows.findIndex((r) => r.path === row.path);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        const range = new Set(e.metaKey || e.ctrlKey ? selected : []);
        for (let i = lo; i <= hi; i++) range.add(rows[i].path);
        onSelect(range, rows);
        return;
      }
    }
    if (e.metaKey || e.ctrlKey) {
      if (next.has(row.path)) next.delete(row.path);
      else next.add(row.path);
      anchor.current = row.path;
      onSelect(next, rows);
      return;
    }
    anchor.current = row.path;
    onSelect(new Set([row.path]), rows);
  };

  const moveSelection = (delta: number, extend: boolean) => {
    if (rows.length === 0) return;
    const current = anchor.current ? rows.findIndex((r) => r.path === anchor.current) : -1;
    const idx = Math.max(0, Math.min(rows.length - 1, current < 0 ? 0 : current + delta));
    const target = rows[idx].path;
    anchor.current = target;
    onSelect(extend ? new Set([...selected, target]) : new Set([target]), rows);
    bodyRef.current?.querySelector(`[data-row="${CSS.escape(target)}"]`)?.scrollIntoView({ block: "nearest" });
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if ((e.target as HTMLElement).tagName === "INPUT") return;
    const selectedRows = rows.filter((r) => selected.has(r.path));
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        moveSelection(1, e.shiftKey);
        return;
      case "ArrowUp":
        e.preventDefault();
        moveSelection(-1, e.shiftKey);
        return;
      case "ArrowRight":
        if (selectedRows.length === 1 && isNavigable(selectedRows[0].entry) && !expanded.has(selectedRows[0].path)) {
          e.preventDefault();
          toggleExpand(selectedRows[0]);
        }
        return;
      case "ArrowLeft":
        if (selectedRows.length === 1 && expanded.has(selectedRows[0].path)) {
          e.preventDefault();
          toggleExpand(selectedRows[0]);
        }
        return;
      case "Enter":
        if (selectedRows.length === 1) {
          e.preventDefault();
          open(selectedRows[0]);
        }
        return;
      case "Backspace": {
        const up = parentPath(path);
        if (up) {
          e.preventDefault();
          props.onNavigate(up);
        }
        return;
      }
      case "F5":
        e.preventDefault();
        if (selectedRows.length > 0) props.onCopy(selectedRows.map((r) => r.path));
        return;
      case "F2":
        e.preventDefault();
        props.onKeyAction("rename");
        return;
      case "F7":
        e.preventDefault();
        props.onKeyAction("mkdir");
        return;
      case "Delete":
        e.preventDefault();
        props.onKeyAction("delete");
        return;
      case "Tab":
        e.preventDefault();
        props.onKeyAction("switch");
        return;
      case "a":
        if (e.metaKey || e.ctrlKey) {
          e.preventDefault();
          onSelect(new Set(rows.map((r) => r.path)), rows);
        }
        return;
      default:
        return;
    }
  };

  // ── Drag and drop between the panes ────────────────────────────────

  const dragStart = (e: DragEvent, row: PaneRow) => {
    const paths = selected.has(row.path) ? rows.filter((r) => selected.has(r.path)).map((r) => r.path) : [row.path];
    if (!selected.has(row.path)) onSelect(new Set([row.path]), rows);
    const payload: SftpDragPayload = { side, paths };
    e.dataTransfer.setData(SFTP_DRAG_TYPE, JSON.stringify(payload));
    e.dataTransfer.effectAllowed = "copy";
  };

  const acceptsDrag = (e: DragEvent) => e.dataTransfer.types.includes(SFTP_DRAG_TYPE);

  const dragOver = (e: DragEvent, dest: string) => {
    if (!acceptsDrag(e)) return;
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = "copy";
    if (dropTarget !== dest) setDropTarget(dest);
  };

  const drop = (e: DragEvent, dest: string) => {
    if (!acceptsDrag(e)) return;
    e.preventDefault();
    e.stopPropagation();
    setDropTarget(null);
    try {
      const payload = JSON.parse(e.dataTransfer.getData(SFTP_DRAG_TYPE)) as SftpDragPayload;
      // Within one side a drop would be a move, which this window does not do.
      if (payload.side === side || !Array.isArray(payload.paths) || payload.paths.length === 0) return;
      props.onDrop(payload, dest);
    } catch {
      // Not ours.
    }
  };

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, asc: !s.asc } : { key, asc: true }));

  const segments = pathSegments(path);
  const up = parentPath(path);
  const SideIcon = side === "local" ? HardDrive : Server;

  return (
    <section
      className={`flex min-w-0 flex-1 flex-col bg-[var(--color-bg)] ${
        props.active ? "" : "opacity-[0.97]"
      }`}
      onMouseDown={props.onActivate}
      aria-label={`${side === "local" ? "Local" : "Remote"} files`}
    >
      {/* Header: side, breadcrumb, filter */}
      <div
        className={`flex items-center gap-2 border-b px-3 py-2 ${
          props.active ? "border-[var(--color-primary)]" : "border-[var(--color-border)]"
        }`}
      >
        <SideIcon size={15} className="shrink-0 text-[var(--color-text-muted)]" aria-hidden />
        <span className="shrink-0 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
          {props.title}
        </span>
        <span className="text-[var(--color-border)]">|</span>
        <nav className="flex min-w-0 flex-1 items-center overflow-hidden text-sm" aria-label="Path">
          {segments.map((seg, i) => (
            <span key={seg.path} className="flex min-w-0 items-center">
              {i > 0 && <ChevronRight size={13} className="mx-0.5 shrink-0 text-[var(--color-text-muted)]" />}
              <button
                type="button"
                className={`truncate rounded px-1 hover:bg-[var(--color-surface-hover)] ${
                  i === segments.length - 1 ? "font-semibold text-[var(--color-text)]" : "text-[var(--color-text-muted)]"
                }`}
                title={seg.path}
                onClick={() => props.onNavigate(seg.path)}
                onDragOver={(e) => dragOver(e, seg.path)}
                onDrop={(e) => drop(e, seg.path)}
              >
                {seg.label}
              </button>
            </span>
          ))}
        </nav>
        <button
          type="button"
          className="rounded p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:opacity-40"
          onClick={() => up && props.onNavigate(up)}
          disabled={!up}
          title="Parent folder (Backspace)"
          aria-label="Parent folder"
        >
          <ArrowUp size={15} />
        </button>
        <button
          type="button"
          className="rounded p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
          onClick={() => props.onNavigate(path)}
          title="Refresh"
          aria-label="Refresh"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
        </button>
        <label className="relative hidden w-36 shrink-0 md:block">
          <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
          <input
            className="w-full rounded border border-[var(--color-border)] bg-[var(--color-surface)] py-0.5 pl-7 pr-2 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-primary)] focus:outline-none"
            placeholder={side === "local" ? "Filter local" : "Filter remote"}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filter"
          />
        </label>
      </div>

      {/* Column headers */}
      <div className="grid grid-cols-[minmax(0,1fr)_6rem_9.5rem] border-b border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text)]">
        {(["name", "size", "date"] as const).map((key) => (
          <button
            key={key}
            type="button"
            className={`flex items-center gap-1 ${key === "name" ? "pl-6" : key === "size" ? "justify-end pr-3" : "pl-3"}`}
            onClick={() => toggleSort(key)}
            aria-sort={sort.key === key ? (sort.asc ? "ascending" : "descending") : "none"}
          >
            {SORT_LABELS[key]}
            {sort.key === key &&
              (sort.asc ? <ChevronDown size={12} className="rotate-180" /> : <ChevronDown size={12} />)}
          </button>
        ))}
      </div>

      {/* Rows */}
      <div
        ref={bodyRef}
        tabIndex={0}
        role="grid"
        aria-multiselectable
        className={`min-h-0 flex-1 overflow-auto outline-none ${
          dropTarget === path ? "bg-[var(--color-primary)]/10 ring-2 ring-inset ring-[var(--color-primary)]" : ""
        }`}
        onKeyDown={onKeyDown}
        onFocus={props.onActivate}
        onDragOver={(e) => dragOver(e, path)}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropTarget(null);
        }}
        onDrop={(e) => drop(e, path)}
        onContextMenu={(e) => {
          if (e.target === e.currentTarget) props.onContextMenu(e, null);
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget) onSelect(new Set(), rows);
        }}
      >
        {error && (
          <div className="m-3 rounded border border-[var(--color-danger)]/40 bg-[var(--color-danger)]/10 px-3 py-2 text-xs text-[var(--color-danger)]">
            {error}
          </div>
        )}
        {!error && !loading && rows.length === 0 && (
          <div className="p-6 text-center text-xs text-[var(--color-text-muted)]">
            {query ? "No matches" : "Empty folder"}
          </div>
        )}
        {rows.map((row) => {
          const isSel = selected.has(row.path);
          const nav = isNavigable(row.entry);
          const exp = expanded.get(row.path);
          const Icon =
            row.entry.kind === "symlink"
              ? nav
                ? FolderSymlink
                : Link2
              : nav
                ? Folder
                : FileIcon;
          return (
            <div
              key={row.path}
              data-row={row.path}
              role="row"
              aria-selected={isSel}
              draggable
              onDragStart={(e) => dragStart(e, row)}
              onDragOver={nav ? (e) => dragOver(e, row.path) : undefined}
              onDrop={nav ? (e) => drop(e, row.path) : undefined}
              onClick={(e) => clickRow(e, row)}
              onDoubleClick={() => open(row)}
              onContextMenu={(e) => {
                e.preventDefault();
                if (!isSel) onSelect(new Set([row.path]), rows);
                props.onContextMenu(e, row);
              }}
              title={[row.entry.name, formatPermissions(row.entry.permissions)].filter(Boolean).join("  ")}
              className={`grid cursor-default select-none grid-cols-[minmax(0,1fr)_6rem_9.5rem] items-center px-3 py-[3px] text-[13px] ${
                isSel
                  ? props.active
                    ? "bg-[var(--color-primary)] text-white"
                    : "bg-[var(--color-surface-hover)] text-[var(--color-text)]"
                  : dropTarget === row.path
                    ? "bg-[var(--color-primary)]/20 text-[var(--color-text)]"
                    : "text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
              }`}
            >
              <span className="flex min-w-0 items-center gap-1.5" style={{ paddingLeft: row.depth * 18 }}>
                {nav ? (
                  <button
                    type="button"
                    className="flex h-4 w-4 shrink-0 items-center justify-center opacity-70 hover:opacity-100"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleExpand(row);
                    }}
                    onDoubleClick={(e) => e.stopPropagation()}
                    aria-label={exp ? "Collapse" : "Expand"}
                    tabIndex={-1}
                  >
                    {exp ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                  </button>
                ) : (
                  <span className="w-4 shrink-0" />
                )}
                <Icon
                  size={15}
                  className={`shrink-0 ${isSel && props.active ? "" : nav ? "text-sky-400" : "text-[var(--color-text-muted)]"}`}
                  aria-hidden
                />
                <span className="truncate">{row.entry.name}</span>
                {exp === "loading" && <RefreshCw size={11} className="shrink-0 animate-spin opacity-60" />}
              </span>
              <span className={`truncate pr-3 text-right tabular-nums ${isSel && props.active ? "" : "text-[var(--color-text-muted)]"}`}>
                {nav ? "•" : formatSize(row.entry.size)}
              </span>
              <span className={`truncate pl-3 tabular-nums ${isSel && props.active ? "" : "text-[var(--color-text-muted)]"}`}>
                {formatDate(row.entry.mtime)}
              </span>
            </div>
          );
        })}
      </div>

      {/* Status line */}
      <div className="flex items-center gap-3 border-t border-[var(--color-border)] px-3 py-1 text-[11px] text-[var(--color-text-muted)]">
        <span>
          {entries.length} item{entries.length === 1 ? "" : "s"}
          {selected.size > 0 && `, ${selected.size} selected`}
        </span>
        {skipped > 0 && (
          <span className="text-[var(--color-warning)]" title="The server listed names that could escape a folder; they are hidden and cannot be transferred.">
            {skipped} unsafe name{skipped === 1 ? "" : "s"} hidden
          </span>
        )}
        <label className="ml-auto flex items-center gap-1">
          <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} />
          Hidden files
        </label>
      </div>
    </section>
  );
}
