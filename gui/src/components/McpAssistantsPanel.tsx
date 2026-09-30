import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, ConfirmModal, EmptyState, Table, useToast } from "./ui";
import type { McpPairing } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

const CLAUDE_DESKTOP_SNIPPET = `{
  "mcpServers": {
    "bastionvault": {
      "command": "bvault",
      "args": ["mcp", "serve"],
      "env": { "VAULT_ADDR": "https://vault.example.com:8200" }
    }
  }
}`;

const CLAUDE_CODE_SNIPPET = "claude mcp add bastionvault -- bvault mcp serve";

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
 * Settings → AI Assistants (MCP). Lists the local clients the operator has
 * approved and lets them revoke one. Approving a client and running the local
 * server are done with `bvault mcp pair` / `bvault mcp serve`: both need a
 * human at a terminal by design (a non-interactive environment cannot pair),
 * and this panel says so rather than offering a button that would have to
 * weaken that.
 */
export function McpAssistantsPanel() {
  const [pairings, setPairings] = useState<McpPairing[]>([]);
  const [storePath, setStorePath] = useState("");
  const [loading, setLoading] = useState(true);
  const [revokeTarget, setRevokeTarget] = useState<McpPairing | null>(null);
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

  useEffect(() => {
    void load();
  }, [load]);

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
            An assistant never receives a vault token. It talks to a local MCP server that acts with your permissions,
            narrowed to a scope you approve, and every call is audited. You approve each assistant once, at a
            terminal; with no terminal available, pairing and per-call confirmations are refused rather than waved
            through.
          </p>
          <ol className="list-decimal space-y-1 pl-5">
            <li>
              Sign in: <code className="font-mono text-xs">bvault login</code>
            </li>
            <li>
              Approve the assistant:{" "}
              <code className="font-mono text-xs">bvault mcp pair --client-name &lt;name the assistant reports&gt;</code>
            </li>
            <li>Point the assistant at the server, below.</li>
          </ol>
        </div>
      </Card>

      <Card title="Connect an assistant">
        <div className="space-y-4 text-sm">
          <div className="space-y-1">
            <p className="font-medium">Claude Desktop — claude_desktop_config.json</p>
            <Snippet text={CLAUDE_DESKTOP_SNIPPET} onCopy={(t) => void copy(t)} />
          </div>
          <div className="space-y-1">
            <p className="font-medium">Claude Code</p>
            <Snippet text={CLAUDE_CODE_SNIPPET} onCopy={(t) => void copy(t)} />
          </div>
          <p className="text-[var(--color-text-muted)]">
            Other clients can use <code className="font-mono text-xs">bvault mcp serve --socket &lt;path&gt;</code> or{" "}
            <code className="font-mono text-xs">bvault mcp serve --listen 127.0.0.1:8250</code>; both bind this machine
            only.
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
            description="Run `bvault mcp pair` in a terminal to approve one."
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
