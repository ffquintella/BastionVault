import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { Badge, Button, Card, ConfirmModal, EmptyState, Table, useToast } from "./ui";
import type { McpClientSetup, McpPairing, McpServerStatus } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { namespaceLabel } from "../lib/mcpNamespace";
import { groupPairingsByVault, type PairingGroup } from "../lib/mcpVaults";

/** Broadcast by the Rust host whenever the server starts or stops. */
const MCP_SERVER_STATUS_EVENT = "mcp-server-status";

const CLI_ALTERNATIVE = "bvault mcp serve";

function fmtTime(unix: number | null): string {
  if (!unix) return "—";
  try {
    return new Date(unix * 1000).toLocaleString();
  } catch {
    return String(unix);
  }
}

function stateBadge(p: McpPairing) {
  if (p.expired) return <Badge variant="error" label="Expired" />;
  return <Badge variant="success" label={`Until ${fmtTime(p.expires_at)}`} />;
}

/**
 * Where a pairing's calls run: its live token's namespace as the vault bound
 * it, else the namespace the operator narrowed it to, else the sign-in's
 * (features/mcp-namespace-selection.md).
 */
function NamespaceCell({ p }: { p: McpPairing }) {
  const live = typeof p.token_namespace === "string" ? p.token_namespace : null;
  const pinned = typeof p.namespace === "string" ? p.namespace : null;
  const shown = live ?? pinned;
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span
        className="block min-w-0 truncate font-mono text-xs"
        title={live !== null ? "the live token is bound here" : "no live token yet"}
      >
        {shown === null ? "follows your sign-in" : namespaceLabel(shown)}
      </span>
      {pinned !== null && <Badge variant="info" label="narrowed" />}
    </div>
  );
}

/** A yes/no permission as a badge; `danger` colours a granted one. */
function Flag({ on, danger }: { on: boolean; danger: "warning" | "error" }) {
  return <Badge variant={on ? danger : "neutral"} label={on ? "allowed" : "off"} />;
}

/** The heading of one vault's group, with the active vault highlighted. */
function GroupHeader({ group, activeKnown }: { group: PairingGroup; activeKnown: boolean }) {
  if (group.kind === "unassigned") {
    return (
      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">Unassigned</h3>
          <Badge variant="warning" label="Not used" />
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">
          Approved before pairings were bound to a vault. They are not used with any vault: re-bind one to the vault
          you are signed in to, or revoke it.
        </p>
      </div>
    );
  }
  const active = group.kind === "active";
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <h3 className="text-sm font-semibold">{active ? "This vault" : activeKnown ? "Another vault" : "Vault"}</h3>
      {active && <Badge variant="success" dot label="Signed in" />}
      <span className="block min-w-0 truncate font-mono text-xs text-[var(--color-text-muted)]" title={group.vaultId ?? ""}>
        {group.vaultId}
      </span>
      {!active && activeKnown && (
        <span className="text-xs text-[var(--color-text-muted)]">Used only while you are signed in to that vault.</span>
      )}
    </div>
  );
}

function Snippet({ text, onCopy }: { text: string; onCopy: (text: string) => void }) {
  return (
    <div className="space-y-1">
      <pre className="min-w-0 overflow-x-auto rounded border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-3 font-mono text-xs">
        {text}
      </pre>
      <div className="flex justify-end">
        <Button size="sm" variant="secondary" onClick={() => onCopy(text)}>
          Copy
        </Button>
      </div>
    </div>
  );
}

/**
 * Settings → AI Assistants (MCP). Turns on the local MCP server this app
 * hosts, shows how to point an assistant at it, and lists (and revokes) the
 * clients the operator approved. Approving a client is not done here: it
 * happens in the consent dialog the app shows when that client first
 * connects (or with `bvault mcp pair` at a terminal), so there is no button
 * that could approve one without a live request in front of the operator.
 */
export function McpAssistantsPanel() {
  const [pairings, setPairings] = useState<McpPairing[]>([]);
  const [storePath, setStorePath] = useState("");
  const [loading, setLoading] = useState(true);
  const [revokeTarget, setRevokeTarget] = useState<McpPairing | null>(null);
  const [rebindTarget, setRebindTarget] = useState<McpPairing | null>(null);
  const [activeVault, setActiveVault] = useState<string | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [status, setStatus] = useState<McpServerStatus | null>(null);
  const [setup, setSetup] = useState<McpClientSetup | null>(null);
  const [switching, setSwitching] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, path, vault] = await Promise.all([
        api.mcpListPairings(),
        api.mcpPairingsPath(),
        // Which vault this window is signed in to; the list still shows when
        // the vault cannot say (re-binding then waits until it can).
        api.mcpVaultIdentity().then(
          (id) => ({ id, error: null as string | null }),
          (e: unknown) => ({ id: null as string | null, error: extractError(e) }),
        ),
      ]);
      setPairings(list);
      setStorePath(path);
      setActiveVault(vault.id);
      setVaultError(vault.error);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const loadServer = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([api.mcpServerStatus(), api.mcpClientSetup()]);
      setStatus(s);
      setSetup(c);
    } catch (e) {
      toast("error", extractError(e));
    }
  }, [toast]);

  useEffect(() => {
    void load();
    void loadServer();
  }, [load, loadServer]);

  // The server stops on its own (lock, sign-out, a session that ended); and a
  // new pairing appears when the operator approves one in the dialog.
  useEffect(() => {
    let cancelled = false;
    const unlisten = listen<McpServerStatus>(MCP_SERVER_STATUS_EVENT, (e) => {
      if (cancelled) return;
      setStatus(e.payload);
      void load();
    });
    return () => {
      cancelled = true;
      void unlisten.then((u) => u());
    };
  }, [load]);

  async function setServing(enabled: boolean) {
    setSwitching(true);
    try {
      setStatus(await api.mcpServerSetEnabled(enabled));
      toast("success", enabled ? "Serving AI assistants" : "Stopped serving AI assistants");
    } catch (e) {
      toast("error", extractError(e));
      void loadServer();
    } finally {
      setSwitching(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast("success", "Copied");
    } catch {
      toast("error", "Could not copy to the clipboard");
    }
  }

  async function doRevoke() {
    if (!revokeTarget) return;
    const target = revokeTarget;
    setRevokeTarget(null);
    // A grant for another vault had nothing minted by this one: it is only
    // removed from this machine, and said so.
    const elsewhere = !!target.vault_id && !!activeVault && target.vault_id !== activeVault;
    try {
      await api.mcpRevokePairing(target.id);
      toast("success", elsewhere ? `Removed ${target.client_name} from this machine` : `Revoked ${target.client_name}`);
    } catch (e) {
      // The local record may already be gone even when the vault call failed;
      // reload so the list shows the truth either way.
      toast("error", extractError(e));
    }
    await load();
  }

  async function doRebind() {
    if (!rebindTarget) return;
    const target = rebindTarget;
    setRebindTarget(null);
    try {
      await api.mcpRebindPairing(target.id);
      toast("success", `${target.client_name} is now bound to this vault`);
    } catch (e) {
      toast("error", extractError(e));
    }
    await load();
  }

  const groups = groupPairingsByVault(pairings, activeVault);
  const columns = (group: PairingGroup) => [
    {
      key: "client",
      header: "Client",
      render: (p: McpPairing) => (
        <span className="block min-w-0 truncate text-sm">{`${p.client_name} ${p.client_version}`.trim()}</span>
      ),
    },
    {
      key: "namespace",
      header: "Namespace",
      render: (p: McpPairing) => <NamespaceCell p={p} />,
    },
    {
      key: "transport",
      header: "Transport",
      render: (p: McpPairing) => <Badge variant="neutral" label={p.transport} />,
    },
    {
      key: "scope",
      header: "Scope",
      render: (p: McpPairing) => (
        <span className="block min-w-0 max-w-xs truncate font-mono text-xs" title={p.path_scope.join("\n")}>
          {p.path_scope.length ? p.path_scope.join(", ") : "none (denies all)"}
        </span>
      ),
    },
    {
      key: "tools",
      header: "Tools",
      render: (p: McpPairing) => (
        <span className="block min-w-0 max-w-xs truncate text-xs" title={p.tool_allowlist.join("\n")}>
          {p.tool_allowlist.length ? `${p.tool_allowlist.length}: ${p.tool_allowlist.join(", ")}` : "none"}
        </span>
      ),
    },
    { key: "reveal", header: "Reveal", render: (p: McpPairing) => <Flag on={p.reveal_allowed} danger="warning" /> },
    {
      key: "writes",
      header: "Writes",
      render: (p: McpPairing) => <Flag on={p.destructive_allowed} danger="error" />,
    },
    {
      key: "sessions",
      header: "Sessions",
      render: (p: McpPairing) => <Flag on={!!p.connect_allowed} danger="error" />,
    },
    { key: "state", header: "Approval", render: (p: McpPairing) => stateBadge(p) },
    {
      key: "actions",
      header: "",
      render: (p: McpPairing) => (
        <div className="flex justify-end gap-2">
          {group.kind === "unassigned" && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setRebindTarget(p)}
              disabled={!activeVault}
              title={activeVault ? undefined : "Sign in to the vault this assistant should use first"}
            >
              Re-bind
            </Button>
          )}
          <Button size="sm" variant="danger" onClick={() => setRevokeTarget(p)}>
            Revoke
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <Card title="AI assistants">
        <div className="space-y-2 text-sm">
          <p className="text-[var(--color-text-muted)]">
            An assistant never receives a vault token. This app serves it over a socket only your user can open, acts
            with your permissions narrowed to a scope you approve, and every call is audited. You approve each
            assistant once, in a dialog here, the first time it connects; reveals and changes can ask you again, call
            by call. With nobody to answer — the window closed, the vault locked — pairing and confirmations are
            refused rather than waved through.
          </p>
        </div>
      </Card>

      <Card
        title="Serve AI assistants"
        actions={
          status?.supported === false ? (
            <Badge variant="neutral" label="Not supported on this platform" />
          ) : status?.running ? (
            <Button size="sm" variant="secondary" onClick={() => void setServing(false)} loading={switching}>
              Turn off
            </Button>
          ) : (
            <Button size="sm" onClick={() => void setServing(true)} loading={switching} disabled={!status}>
              Turn on
            </Button>
          )
        }
      >
        <div className="space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            {status?.running ? (
              <Badge variant="success" dot label="Running" />
            ) : (
              <Badge variant="neutral" dot label="Off" />
            )}
            {status?.enabled && !status.running && (
              <Badge variant="info" label="Starts when you sign in" />
            )}
          </div>
          <p className="text-[var(--color-text-muted)]">
            Runs only while your vault is unlocked under a regular sign-in — never a root token — and stops when you
            lock it, sign out or switch vaults, forgetting every token it minted.
          </p>
          {status?.socket_path && (
            <p className="min-w-0 truncate text-xs text-[var(--color-text-muted)]" title={status.socket_path}>
              Socket: <span className="font-mono">{status.socket_path}</span>
            </p>
          )}
          {status?.last_error && (
            <p className="min-w-0 break-words text-xs text-[var(--color-text-muted)]">{status.last_error}</p>
          )}
        </div>
      </Card>

      <Card title="Connect an assistant">
        <div className="space-y-4 text-sm">
          <p className="text-[var(--color-text-muted)]">
            The assistant launches this app&apos;s own binary with <code className="font-mono text-xs">--mcp-stdio</code>,
            which relays to the running app. Nothing secret goes into its configuration, and no{" "}
            <code className="font-mono text-xs">bvault</code> CLI is needed.
          </p>
          <div className="space-y-1">
            <p className="font-medium">Claude Code</p>
            <Snippet text={setup?.claude_code_command ?? ""} onCopy={(t) => void copy(t)} />
          </div>
          <div className="space-y-1">
            <p className="font-medium">Claude Desktop — claude_desktop_config.json</p>
            <Snippet text={setup?.claude_desktop_config ?? ""} onCopy={(t) => void copy(t)} />
          </div>
          <p className="text-[var(--color-text-muted)]">
            Without this app, <code className="font-mono text-xs">{CLI_ALTERNATIVE}</code> runs the same server from a
            terminal (stdio, <code className="font-mono text-xs">--socket</code> or a loopback{" "}
            <code className="font-mono text-xs">--listen</code>).
          </p>
        </div>
      </Card>

      <Card
        title="Paired assistants"
        actions={
          <Button size="sm" variant="secondary" onClick={() => void load()} disabled={loading}>
            Refresh
          </Button>
        }
      >
        {pairings.length === 0 && loading ? (
          <p className="py-8 text-center text-sm text-[var(--color-text-muted)]">Loading…</p>
        ) : pairings.length === 0 ? (
          <EmptyState
            title="No assistants paired"
            description="An assistant is paired the first time it connects, when you approve it in the dialog this app shows."
          />
        ) : (
          <div className="space-y-6">
            {vaultError && (
              <p className="min-w-0 break-words text-xs text-[var(--color-text-muted)]">
                Could not tell which vault you are signed in to, so none is highlighted and nothing can be re-bound:{" "}
                {vaultError}
              </p>
            )}
            {groups.map((group) => (
              <section
                key={group.vaultId ?? "unassigned"}
                aria-label={group.kind === "unassigned" ? "Unassigned assistants" : `Vault ${group.vaultId}`}
                data-active={group.kind === "active" ? "true" : undefined}
                className={
                  group.kind === "active"
                    ? "min-w-0 space-y-2 rounded border border-[var(--color-primary)] p-3"
                    : "min-w-0 space-y-2 rounded border border-[var(--color-border)] p-3"
                }
              >
                <GroupHeader group={group} activeKnown={!!activeVault} />
                {group.pairings.length === 0 ? (
                  <p className="text-xs text-[var(--color-text-muted)]">No assistant is paired with this vault yet.</p>
                ) : (
                  <Table
                    columns={columns(group)}
                    data={group.pairings}
                    rowKey={(p: McpPairing) => p.id}
                    emptyMessage="No assistants paired"
                  />
                )}
              </section>
            ))}
          </div>
        )}
        {storePath && (
          <p className="mt-3 min-w-0 truncate text-xs text-[var(--color-text-muted)]" title={storePath}>
            Pairings are kept in {storePath}. They hold no tokens.
          </p>
        )}
      </Card>

      <ConfirmModal
        open={!!rebindTarget}
        onClose={() => setRebindTarget(null)}
        onConfirm={() => void doRebind()}
        title="Bind to this vault"
        message={`Bind ${rebindTarget?.client_name ?? ""} to the vault you are signed in to (${activeVault ?? ""})? It keeps its scope and expiry, and is then used with this vault only. This cannot be moved to another vault later.`}
        confirmLabel="Bind to this vault"
      />

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => void doRevoke()}
        title="Revoke assistant"
        message={`Revoke ${revokeTarget?.client_name ?? ""}? It is cut off immediately and must be paired again to reconnect.`}
        confirmLabel="Revoke"
        variant="danger"
      />
    </div>
  );
}
