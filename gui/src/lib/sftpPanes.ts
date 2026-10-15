/**
 * Pure helpers for the SFTP dual-pane window (features/sftp-connect.md):
 * path arithmetic for both sides, sorting, formatting and the host's
 * `exists:` refusal. Kept free of React so the rules are unit-tested.
 *
 * Remote paths are always POSIX. Local paths are POSIX, or Windows drive
 * paths (`C:\Users\op`) when the host runs on Windows.
 */

import type { SftpEntry } from "./api";

export type PaneSide = "local" | "remote";

export type SortKey = "name" | "size" | "date";

export interface SortState {
  key: SortKey;
  asc: boolean;
}

/** True for a Windows drive path (`C:\…` or `C:/…`). */
export function isWindowsPath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(path);
}

function separator(path: string): string {
  return isWindowsPath(path) ? "\\" : "/";
}

/** Join a folder and one entry name on the side the folder belongs to. */
export function joinPath(dir: string, name: string): string {
  const sep = separator(dir);
  if (dir === "") return name;
  return dir.endsWith(sep) ? `${dir}${name}` : `${dir}${sep}${name}`;
}

/** The parent folder, or null at a root. */
export function parentPath(path: string): string | null {
  if (isWindowsPath(path)) {
    const root = path.slice(0, 3);
    const rest = path.slice(3).replace(/[\\/]+$/, "");
    if (rest === "") return null;
    const i = rest.lastIndexOf("\\");
    return i < 0 ? root : root + rest.slice(0, i);
  }
  const trimmed = path.replace(/\/+$/, "");
  if (trimmed === "") return null;
  const i = trimmed.lastIndexOf("/");
  if (i < 0) return null;
  return i === 0 ? "/" : trimmed.slice(0, i);
}

export interface PathSegment {
  label: string;
  path: string;
}

/** Breadcrumb segments, root first. */
export function pathSegments(path: string): PathSegment[] {
  if (isWindowsPath(path)) {
    const root = path.slice(0, 2) + "\\";
    const parts = path.slice(3).split(/[\\/]/).filter(Boolean);
    const out: PathSegment[] = [{ label: path.slice(0, 2), path: root }];
    let acc = root;
    for (const p of parts) {
      acc = joinPath(acc, p);
      out.push({ label: p, path: acc });
    }
    return out;
  }
  const parts = path.split("/").filter(Boolean);
  const out: PathSegment[] = [{ label: "/", path: "/" }];
  let acc = "/";
  for (const p of parts) {
    acc = joinPath(acc, p);
    out.push({ label: p, path: acc });
  }
  return out;
}

/** A folder, or a symlink to one: double-click opens it. */
export function isNavigable(e: SftpEntry): boolean {
  return e.kind === "dir" || (e.kind === "symlink" && e.target_kind === "dir");
}

/** Folders first, then by the chosen column; names compare naturally. */
export function sortEntries(entries: SftpEntry[], sort: SortState): SftpEntry[] {
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
  const dir = sort.asc ? 1 : -1;
  return [...entries].sort((a, b) => {
    const fa = isNavigable(a) ? 0 : 1;
    const fb = isNavigable(b) ? 0 : 1;
    if (fa !== fb) return fa - fb;
    let c = 0;
    if (sort.key === "size") c = a.size - b.size;
    else if (sort.key === "date") c = (a.mtime ?? 0) - (b.mtime ?? 0);
    if (c === 0) c = collator.compare(a.name, b.name);
    return c * dir;
  });
}

/** Case-insensitive substring filter on the name. */
export function filterEntries(entries: SftpEntry[], query: string, showHidden: boolean): SftpEntry[] {
  const q = query.trim().toLowerCase();
  return entries.filter(
    (e) => (showHidden || !e.name.startsWith(".")) && (q === "" || e.name.toLowerCase().includes(q)),
  );
}

const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** `60 KB`, `7.6 MB`. Folders show a dot, as file managers do. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u += 1;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${UNITS[u]}`;
}

/** Short locale date and time, e.g. `09/10/26, 14:35`. */
export function formatDate(mtime: number | null): string {
  if (mtime === null) return "";
  return new Date(mtime * 1000).toLocaleString(undefined, {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** `rwxr-xr-x` from mode bits; empty when the side does not report them. */
export function formatPermissions(mode: number | null): string {
  if (mode === null) return "";
  const bits = "rwxrwxrwx";
  let out = "";
  for (let i = 0; i < 9; i++) out += mode & (1 << (8 - i)) ? bits[i] : "-";
  return out;
}

/** The entry name a host `exists: <name>` refusal names, else null. */
export function existsConflict(error: string): string | null {
  const m = /(?:^|\s)exists: (.+)$/.exec(error.trim());
  return m ? m[1] : null;
}

/** A name the host will accept for a new folder or a rename. */
export function isValidEntryName(name: string): boolean {
  return name !== "" && name !== "." && name !== ".." && !/[\\/\0]/.test(name);
}

let transferSeq = 0;

/** A transfer id the host accepts (`[A-Za-z0-9_-]{1,64}`). */
export function newTransferId(): string {
  transferSeq += 1;
  return `tx_${Date.now().toString(36)}_${transferSeq}`;
}
