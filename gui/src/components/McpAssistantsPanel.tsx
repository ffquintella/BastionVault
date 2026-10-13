import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { Badge, Button, Card, ConfirmModal, EmptyState, Table, useToast } from "./ui";
import type { McpClientSetup, McpPairing, McpServerStatus } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

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
  const [status, setStatus] = useState<McpServerStatus | null>(null);
  const [setup, setSetup] = useState<McpClientSetup | null>(null);
  const [switching, setSwitching] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, path] = await Promise.all([api.mcpListPairings(), api.mcpPairingsPath()]);
      setPairings(list);
      setStorePath(path);
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
    try {
      await api.mcpRevokePairing(target.id);
      toast("success", `Revoked ${target.client_name}`);
    } catch (e) {
      // The local record may already be gone even when the vault call failed;
      // reload so the list shows the truth either way.
      toast("error", extractError(e));
    }
    await load();
  }

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
          <Table
            columns={[
              {
                key: "client",
                header: "Client",
                render: (p: McpPairing) => (
                  <span className="block min-w-0 truncate text-sm">
                    {`${p.client_name} ${p.client_version}`.trim()}
                  </span>
                ),
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
                  <span
                    className="block min-w-0 max-w-xs truncate font-mono text-xs"
                    title={p.path_scope.join("\n")}
                  >
                    {p.path_scope.length ? p.path_scope.join(", ") : "none (denies all)"}
                  </span>
                ),
              },
              {
                key: "tools",
                header: "Tools",
                render: (p: McpPairing) => <span title={p.tool_allowlist.join(", ")}>{p.tool_allowlist.length}</span>,
              },
              {
                key: "reveal",
                header: "Reveal",
                render: (p: McpPairing) => (
                  <Badge variant={p.reveal_allowed ? "warning" : "neutral"} label={p.reveal_allowed ? "allowed" : "off"} />
                ),
              },
              {
                key: "writes",
                header: "Writes",
                render: (p: McpPairing) => (
                  <Badge
                    variant={p.destructive_allowed ? "error" : "neutral"}
                    label={p.destructive_allowed ? "allowed" : "off"}
                  />
                ),
              },
              { key: "state", header: "Approval", render: (p: McpPairing) => stateBadge(p) },
              {
                key: "actions",
                header: "",
                render: (p: McpPairing) => (
                  <div className="flex justify-end">
                    <Button size="sm" variant="danger" onClick={() => setRevokeTarget(p)}>
                      Revoke
                    </Button>
                  </div>
                ),
              },
            ]}
            data={pairings}
            rowKey={(p: McpPairing) => p.id}
            emptyMessage="No assistants paired"
          />
        )}
        {storePath && (
          <p className="mt-3 min-w-0 truncate text-xs text-[var(--color-text-muted)]" title={storePath}>
            Pairings are kept in {storePath}. They hold no tokens.
          </p>
        )}
      </Card>

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
