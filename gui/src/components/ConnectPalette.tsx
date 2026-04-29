import { useEffect, useMemo, useRef, useState } from "react";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import {
  protocolForOsType,
  readProfiles,
  defaultPort,
} from "../lib/connectionProfiles";
import {
  DEFAULT_RESOURCE_TYPES,
  getTypeDef,
  mergeTypeConfig,
} from "../lib/resourceTypes";
import type {
  ConnectionProfile,
  ResourceMetadata,
  ResourceTypeConfig,
} from "../lib/types";
import { useAuthStore } from "../stores/authStore";
import { Badge } from "./ui/Badge";
import { useToast } from "./ui/Toast";

/**
 * Cmd-K Connect palette (Phase 7 polish).
 *
 * Global hotkey ⌘K (Ctrl+K on Linux/Windows) opens a fuzzy-searchable
 * picker that lists every launchable {resource × profile} pair across
 * the vault. Picking one fires the same `session_open_*` command the
 * Connection tab fires — bypassing the resources list when the
 * operator already knows what they want to connect to.
 *
 * Inclusion rule: the resource type must have `connect.enabled !==
 * false`, the resource must have an `os_type` mapping to a protocol,
 * and the profile's protocol+credential combo must be one we
 * actually launch today (Secret / LDAP / PKI; SSH-engine still TODO).
 *
 * Out-of-scope here: LDAP operator-bind needs a typed credential, so
 * those entries are listed but launching them sends the operator
 * back to the Resources page where the inline prompt lives. Keeps
 * the palette focused on one-keystroke connects.
 */
interface PaletteEntry {
  resource: ResourceMetadata;
  profile: ConnectionProfile;
  protocol: "ssh" | "rdp";
  /** Lower-cased haystack assembled once for fuzzy matching. */
  haystack: string;
  /** Display strings precomputed so render stays cheap. */
  resourceLabel: string;
  targetLabel: string;
  needsOperatorPrompt: boolean;
}

export function ConnectPalette() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<PaletteEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [connecting, setConnecting] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Global ⌘K / Ctrl+K listener. Only armed once authenticated —
  // before login there's nothing to connect to.
  useEffect(() => {
    if (!isAuthenticated) return;
    const handler = (e: KeyboardEvent) => {
      const isCmdK =
        (e.metaKey || e.ctrlKey) &&
        !e.altKey &&
        !e.shiftKey &&
        (e.key === "k" || e.key === "K");
      if (isCmdK) {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape" && open) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [isAuthenticated, open]);

  // Lazy-load on first open. Refreshing on every open keeps the
  // list in sync with profile edits without polling.
  useEffect(() => {
    if (!open) {
      setQuery("");
      setActive(0);
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const [savedTypes, listing] = await Promise.all([
          api.resourceTypesRead().catch(() => null),
          api.listResources(),
        ]);
        const typeConfig: ResourceTypeConfig = mergeTypeConfig(
          savedTypes as ResourceTypeConfig | null,
        ) ?? DEFAULT_RESOURCE_TYPES;
        const metas = await Promise.all(
          listing.resources.map((n) => api.readResource(n).catch(() => null)),
        );
        if (cancelled) return;

        const next: PaletteEntry[] = [];
        for (const meta of metas) {
          if (!meta) continue;
          const typeDef = getTypeDef(typeConfig, String(meta.type || ""));
          if (typeDef.connect?.enabled === false) continue;
          const osType = String(meta["os_type"] ?? "");
          const protocol = protocolForOsType(osType);
          if (!protocol) continue;
          const profiles = readProfiles(meta as Record<string, unknown>);
          for (const p of profiles) {
            if (p.protocol !== protocol) continue;
            // Only the kinds the host actually launches today.
            const kind = p.credential_source.kind;
            if (kind === "ssh-engine") continue;
            const needsOperatorPrompt =
              kind === "ldap" &&
              "bind_mode" in p.credential_source &&
              p.credential_source.bind_mode === "operator";
            const host =
              p.target_host ||
              String(meta.hostname || "") ||
              String(meta.ip_address || "") ||
              "—";
            const port = p.target_port ?? defaultPort(p.protocol);
            const resourceLabel = String(meta.name || "");
            const targetLabel = `${host}:${port}`;
            const haystack = [
              resourceLabel,
              p.name,
              p.protocol,
              host,
              String(port),
              p.username || "",
              kind,
              String(meta["tags"] || ""),
            ]
              .join(" ")
              .toLowerCase();
            next.push({
              resource: meta,
              profile: p,
              protocol,
              haystack,
              resourceLabel,
              targetLabel,
              needsOperatorPrompt,
            });
          }
        }
        // Stable alpha sort by resource then profile name, so the
        // palette is predictable when the search box is empty.
        next.sort((a, b) => {
          const r = a.resourceLabel.localeCompare(b.resourceLabel);
          return r !== 0 ? r : a.profile.name.localeCompare(b.profile.name);
        });
        setEntries(next);
      } catch (e) {
        if (!cancelled) toast("error", extractError(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // toast is stable from the provider; eslint can't see that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Focus the input on open. Run after the modal mounts.
  useEffect(() => {
    if (open) {
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return entries;
    // Cheap subsequence scoring: split on whitespace, every term
    // must appear (in order-agnostic substring form) in the
    // haystack. Good-enough for ~thousands of entries; if vaults
    // ever get huge we can swap in fzf.
    const terms = q.split(/\s+/).filter(Boolean);
    return entries.filter((e) => terms.every((t) => e.haystack.includes(t)));
  }, [entries, query]);

  // Clamp active when filter changes.
  useEffect(() => {
    if (active >= filtered.length) setActive(Math.max(0, filtered.length - 1));
  }, [filtered.length, active]);

  async function launch(entry: PaletteEntry) {
    if (entry.needsOperatorPrompt) {
      // Operator-bind LDAP needs a typed credential — palette
      // closes and the operator finishes from the Resources page,
      // where the inline prompt already lives.
      toast(
        "info",
        `Open ${entry.resourceLabel} in Resources to enter LDAP credentials.`,
      );
      setOpen(false);
      return;
    }
    const key = `${entry.resourceLabel}/${entry.profile.id}`;
    setConnecting(key);
    try {
      if (entry.protocol === "ssh") {
        await api.sessionOpenSsh({
          resource_name: entry.resourceLabel,
          profile_id: entry.profile.id,
          operator_credential: undefined,
        });
      } else {
        await api.sessionOpenRdp({
          resource_name: entry.resourceLabel,
          profile_id: entry.profile.id,
          operator_credential: undefined,
        });
      }
      setOpen(false);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setConnecting(null);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(filtered.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = filtered[active];
      if (target && !connecting) launch(target);
    }
  }

  if (!isAuthenticated || !open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/60 backdrop-blur-sm p-4 pt-[10vh]"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
    >
      <div className="w-full max-w-xl rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl overflow-hidden">
        <div className="border-b border-[var(--color-border)] px-3 py-2 flex items-center gap-2">
          <span className="text-[var(--color-text-muted)] text-sm font-mono select-none">⌘K</span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search resources, profiles, hosts…"
            className="flex-1 bg-transparent outline-none text-sm placeholder:text-[var(--color-text-muted)]"
          />
          <span className="text-[10px] uppercase tracking-wide text-[var(--color-text-muted)]">
            Connect to…
          </span>
        </div>

        <div className="max-h-[50vh] overflow-y-auto">
          {loading && (
            <p className="px-3 py-6 text-sm text-center text-[var(--color-text-muted)]">
              Loading resources…
            </p>
          )}
          {!loading && filtered.length === 0 && (
            <p className="px-3 py-6 text-sm text-center text-[var(--color-text-muted)]">
              {entries.length === 0
                ? "No launchable connection profiles. Configure one on a resource's Connection tab."
                : "No matches."}
            </p>
          )}
          {!loading && filtered.length > 0 && (
            <ul>
              {filtered.map((e, i) => {
                const key = `${e.resourceLabel}/${e.profile.id}`;
                const isActive = i === active;
                const isConnecting = connecting === key;
                return (
                  <li key={key}>
                    <button
                      type="button"
                      onMouseEnter={() => setActive(i)}
                      onClick={() => launch(e)}
                      disabled={connecting !== null}
                      className={`w-full text-left px-3 py-2 flex items-center gap-3 ${
                        isActive
                          ? "bg-[var(--color-surface-2)]"
                          : "bg-transparent"
                      } disabled:opacity-50`}
                    >
                      <Badge label={e.protocol.toUpperCase()} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 text-sm">
                          <strong className="truncate">{e.resourceLabel}</strong>
                          <span className="text-[var(--color-text-muted)]">·</span>
                          <span className="truncate">{e.profile.name}</span>
                        </div>
                        <div className="text-xs text-[var(--color-text-muted)] font-mono truncate">
                          {e.profile.username ? `${e.profile.username}@` : ""}
                          {e.targetLabel}
                          {e.needsOperatorPrompt ? " · LDAP operator bind" : ""}
                        </div>
                      </div>
                      {isConnecting && (
                        <span className="text-xs text-[var(--color-text-muted)]">
                          Connecting…
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="border-t border-[var(--color-border)] px-3 py-1.5 text-[10px] text-[var(--color-text-muted)] flex items-center gap-3 select-none">
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">↵</kbd> connect</span>
          <span><kbd className="font-mono">esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
