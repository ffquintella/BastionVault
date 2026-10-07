import { useEffect, useMemo, useRef, useState } from "react";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import {
  protocolForOsType,
  readProfiles,
  defaultPort,
  isLaunchableWebProfile,
  needsOperatorPrompt as profileNeedsOperatorPrompt,
} from "../lib/connectionProfiles";
import {
  DEFAULT_RESOURCE_TYPES,
  connectProtocols,
  getTypeDef,
  mergeTypeConfig,
} from "../lib/resourceTypes";
import { openProfileSession } from "../lib/sessionLaunch";
import { CONNECT_PALETTE_OPEN_EVENT, type ConnectPaletteOpenDetail } from "../lib/connectPaletteEvents";
import type {
  ConnectionProfile,
  ResourceMetadata,
  ResourceTypeConfig,
  SessionProtocol,
} from "../lib/types";
import { useAuthStore } from "../stores/authStore";
import { Badge } from "./ui/Badge";
import { useToast } from "./ui/Toast";
import { useConnectMfa } from "./ConnectMfaPrompt";

/**
 * Cmd-K Connect palette (Phase 7 polish).
 *
 * Global hotkey ⌘K (Ctrl+K on Linux/Windows) opens a fuzzy-searchable
 * picker that lists every launchable {resource × profile} pair across
 * the vault. Picking one fires the same `session_open_*` command the
 * Connection tab fires — bypassing the resources list when the
 * operator already knows what they want to connect to.
 *
 * Inclusion rule: the resource type must offer the profile's protocol
 * (`connectProtocols`, which folds in `connect.enabled`). SSH/RDP
 * profiles additionally need the resource's `os_type` to map to that
 * protocol and a credential combo we launch in one keystroke (Secret /
 * LDAP / PKI; SSH-engine still TODO). Web profiles need the `open` login
 * mode (credential source `none`).
 *
 * Out-of-scope here: LDAP operator-bind needs a typed credential, so
 * those entries are listed but launching them sends the operator
 * back to the Resources page where the inline prompt lives. Keeps
 * the palette focused on one-keystroke connects.
 */
interface PaletteEntry {
  resource: ResourceMetadata;
  profile: ConnectionProfile;
  protocol: SessionProtocol;
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
  // Connect-time MFA gate; the prompt renders over the palette.
  const { gateConnect, mfaPrompt } = useConnectMfa();
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<PaletteEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [connecting, setConnecting] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // Placement for the next launch, set when the Session Workspace opens
  // the palette for a new tab or a split (T38). Cleared on close.
  const [placement, setPlacement] = useState<api.SessionPlacement | undefined>(undefined);

  // Opened by the Session Workspace's ⌘T / ⌘D / ⌘⇧D chords.
  useEffect(() => {
    if (!isAuthenticated) return;
    const onOpen = (e: Event) => {
      const detail = (e as CustomEvent<ConnectPaletteOpenDetail>).detail;
      setPlacement(detail?.placement);
      setOpen(true);
    };
    window.addEventListener(CONNECT_PALETTE_OPEN_EVENT, onOpen);
    return () => window.removeEventListener(CONNECT_PALETTE_OPEN_EVENT, onOpen);
  }, [isAuthenticated]);

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
      setPlacement(undefined);
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
          const offered = connectProtocols(typeDef);
          if (offered.length === 0) continue;
          const osType = String(meta["os_type"] ?? "");
          const osProtocol = protocolForOsType(osType);
          const profiles = readProfiles(meta as Record<string, unknown>);
          for (const p of profiles) {
            if (!offered.includes(p.protocol)) continue;
            if (p.protocol === "web") {
              // `open` (source `none`) and `form` (a recipe plus a server-
              // released source); the host refuses anything else.
              if (!isLaunchableWebProfile(p) || !p.web) continue;
              const resourceLabel = String(meta.name || "");
              let origin = p.web.start_url;
              try {
                origin = new URL(p.web.start_url).origin;
              } catch {
                // Leave the raw value; the host refuses an invalid URL.
              }
              next.push({
                resource: meta,
                profile: p,
                protocol: "web",
                haystack: [resourceLabel, p.name, "web", origin, String(meta["tags"] || "")]
                  .join(" ")
                  .toLowerCase(),
                resourceLabel,
                targetLabel: origin,
                needsOperatorPrompt: false,
              });
              continue;
            }
            if (!osProtocol || p.protocol !== osProtocol) continue;
            // Only the kinds the host actually launches today.
            const kind = p.credential_source.kind;
            if (kind === "ssh-engine") continue;
            // default-account SSH is a brokered engine mint like ssh-engine —
            // not a one-click palette launch. Its RDP form is fine (it just
            // prompts for the password, like LDAP operator-bind).
            if (kind === "default-account" && p.protocol === "ssh") continue;
            const needsOperatorPrompt = profileNeedsOperatorPrompt(p);
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
              protocol: osProtocol,
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
      // These profiles may need a typed credential before opening (LDAP
      // operator-bind, or an RDP default-account with no stored password).
      // The palette can't prompt inline, so it hands off to the Resources
      // page, where the inline prompt + stored-password check already live.
      const detail =
        entry.profile.credential_source.kind === "default-account"
          ? "to complete the connection"
          : "to enter LDAP credentials";
      toast("info", `Open ${entry.resourceLabel} in Resources ${detail}.`);
      setOpen(false);
      return;
    }
    const key = `${entry.resourceLabel}/${entry.profile.id}`;
    setConnecting(key);
    try {
      // Connect-time MFA gate. The server decides whether this profile needs
      // a factor; `{}` on an ungated one keeps the spread a no-op. The prompt
      // renders over the palette, so unlike the operator-bind case above the
      // palette can satisfy it inline.
      const mfa = await gateConnect(
        entry.resourceLabel,
        entry.profile.id,
        entry.profile.name,
      );
      if (!mfa) return; // operator cancelled — leave the palette open
      await openProfileSession(entry.profile, {
        resource_name: entry.resourceLabel,
        profile_id: entry.profile.id,
        operator_credential: undefined,
        placement,
        ...mfa,
      });
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
                          {e.needsOperatorPrompt
                            ? e.profile.credential_source.kind === "default-account"
                              ? " · prompts for password"
                              : " · LDAP operator bind"
                            : ""}
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
      {mfaPrompt}
    </div>
  );
}
