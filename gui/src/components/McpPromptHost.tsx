import { useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { Badge, Button, Input, Modal, Textarea } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import type { McpCatalogueTool, McpConfirmPrompt, McpPairingPrompt, McpPrompt } from "../lib/types";
import { useAuthStore } from "../stores/authStore";

/** Events the Rust host (`gui/src-tauri/src/mcp_host`) sends the main window. */
export const MCP_PROMPT_EVENT = "mcp-prompt";
export const MCP_PROMPT_CLOSED_EVENT = "mcp-prompt-closed";

function kindVariant(kind: string): "neutral" | "warning" | "error" {
  if (kind === "read") return "neutral";
  if (kind === "reveal") return "warning";
  return "error";
}

/** One path glob per line (or comma) → trimmed, non-empty list. */
function parseLines(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Only a well-formed prompt is shown; anything else is ignored. */
function isPrompt(p: unknown): p is McpPrompt {
  if (!p || typeof p !== "object") return false;
  const { kind, id } = p as { kind?: unknown; id?: unknown };
  return (kind === "pairing" || kind === "confirm") && typeof id === "string" && id.length > 0;
}

/** Seconds left before the host refuses on the operator's behalf. */
function useSecondsLeft(deadlineMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return Math.max(0, Math.ceil((deadlineMs - now) / 1000));
}

function Countdown({ deadlineMs }: { deadlineMs: number }) {
  const left = useSecondsLeft(deadlineMs);
  return (
    <p className="text-xs text-[var(--color-text-muted)]">
      {left > 0 ? `Answer within ${left}s — after that it is refused.` : "Timed out — refused."}
    </p>
  );
}

function transportLabel(prompt: McpPairingPrompt): string {
  if (prompt.transport === "uds") return "this app's socket (owner-only)";
  return prompt.transport;
}

/**
 * The pairing-consent dialog. Approving records which client may connect and
 * what it may do; nothing is pre-approved. Defaults are the narrowest useful
 * grant: read-only tools that never reveal a value, no reveals, no writes,
 * per-call confirmation on. Closing the dialog is a denial.
 */
export function McpPairingModal({ prompt, onDone }: { prompt: McpPairingPrompt; onDone: () => void }) {
  const [tools, setTools] = useState<McpCatalogueTool[]>([]);
  const [selected, setSelected] = useState<string[]>(prompt.default_tools);
  const [scope, setScope] = useState("");
  const [reveal, setReveal] = useState(false);
  const [confirmReveal, setConfirmReveal] = useState(true);
  const [destructive, setDestructive] = useState(false);
  const [confirmDestructive, setConfirmDestructive] = useState(true);
  const maxHours = Math.max(1, Math.floor(prompt.max_ttl_secs / 3600));
  const [hours, setHours] = useState(String(Math.max(1, Math.round(prompt.default_ttl_secs / 3600))));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .mcpCatalogue()
      .then((c) => {
        if (!cancelled) setTools(c.tools ?? []);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const paths = useMemo(() => parseLines(scope), [scope]);
  const hoursNum = Number(hours);
  const hoursValid = Number.isInteger(hoursNum) && hoursNum >= 1 && hoursNum <= maxHours;
  const canApprove = selected.length > 0 && paths.length > 0 && hoursValid && !busy;

  function toggle(name: string) {
    setSelected((cur) => (cur.includes(name) ? cur.filter((t) => t !== name) : [...cur, name]));
  }

  async function answer(approved: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api.mcpPromptAnswer(
        prompt.id,
        approved
          ? {
              kind: "pairing",
              approved: true,
              grant: {
                tool_allowlist: selected,
                path_scope: paths,
                reveal_allowed: reveal,
                destructive_allowed: destructive,
                confirm_reveal: reveal && confirmReveal,
                confirm_destructive: destructive && confirmDestructive,
                ttl_secs: hoursNum * 3600,
              },
            }
          : { kind: "pairing", approved: false },
      );
      onDone();
    } catch (e) {
      // A grant the host refused keeps the request open for a correction. A
      // denial that finds nothing waiting (it timed out) is refused already.
      if (approved) setError(extractError(e));
      else onDone();
    } finally {
      setBusy(false);
    }
  }

  const listed = tools.length > 0 ? tools : prompt.default_tools.map((name) => ({ name, description: "", kind: "read" }));

  return (
    <Modal
      open
      onClose={() => void answer(false)}
      title="Approve an AI assistant?"
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={() => void answer(false)} disabled={busy}>
            Deny
          </Button>
          <Button onClick={() => void answer(true)} disabled={!canApprove} loading={busy}>
            Approve
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <div className="space-y-1">
          <p>
            <span className="font-medium">{`${prompt.client_name} ${prompt.client_version}`.trim()}</span> is asking
            for access to <span className="font-medium break-all">{prompt.vault}</span> through{" "}
            {transportLabel(prompt)}.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            {prompt.peer_uid !== null && <Badge variant="neutral" label={`uid ${prompt.peer_uid}`} />}
            {prompt.same_user ? (
              <Badge variant="success" label="runs as you" />
            ) : (
              <Badge variant="warning" label="user not confirmed" />
            )}
          </div>
          <p className="text-[var(--color-text-muted)]">
            It will act with <strong>your</strong> permissions, narrowed to the scope you choose here. It never sees
            a vault token, and every call it makes is audited. The approval stays with this assistant on this
            computer, whichever vault you are signed in to later — always limited by that session&apos;s own
            permissions. Approve only an assistant you started.
          </p>
          <Countdown deadlineMs={prompt.deadline_unix_ms} />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="mb-1 block text-sm text-[var(--color-text-muted)]">
              Tools it may call (preselected: read-only tools that never reveal a value)
            </label>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
              {listed.map((t) => (
                <label key={t.name} className="flex min-w-0 items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selected.includes(t.name)}
                    onChange={() => toggle(t.name)}
                    aria-label={t.name}
                  />
                  <span className="min-w-0 truncate font-mono text-xs" title={t.description}>
                    {t.name}
                  </span>
                  {t.kind !== "read" && <Badge variant={kindVariant(t.kind)} label={t.kind} />}
                </label>
              ))}
            </div>
          </div>
          <div className="col-span-2">
            <Textarea
              label="Path scope — one glob per line (required)"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder={"secret/metadata/ai/*\nsecret/data/ai/*"}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={reveal}
              onChange={(e) => setReveal(e.target.checked)}
              aria-label="Allow revealing secret values"
            />
            Allow revealing secret values
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmReveal}
              disabled={!reveal}
              onChange={(e) => setConfirmReveal(e.target.checked)}
              aria-label="Ask me before each reveal"
            />
            Ask me before each reveal
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={destructive}
              onChange={(e) => setDestructive(e.target.checked)}
              aria-label="Allow write and delete tools"
            />
            Allow write and delete tools
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmDestructive}
              disabled={!destructive}
              onChange={(e) => setConfirmDestructive(e.target.checked)}
              aria-label="Ask me before each change"
            />
            Ask me before each change
          </label>
          <Input
            label={`Token lifetime (hours, 1 to ${maxHours})`}
            value={hours}
            onChange={(e) => setHours(e.target.value)}
          />
        </div>
        {paths.length === 0 && (
          <p className="text-xs text-[var(--color-text-muted)]">Add at least one path the assistant may touch.</p>
        )}
        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}
      </div>
    </Modal>
  );
}

function confirmVerb(prompt: McpConfirmPrompt): string {
  if (prompt.reveals && prompt.destructive) return "reveal a secret value and make a change";
  if (prompt.reveals) return "reveal a secret value";
  return "make a change";
}

/**
 * The per-call confirmation dialog, for a reveal or a write the client's
 * grant allows but asked to confirm. Deny is the default; closing denies.
 */
export function McpConfirmModal({ prompt, onDone }: { prompt: McpConfirmPrompt; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function answer(allow: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api.mcpPromptAnswer(prompt.id, { kind: "confirm", allow });
      onDone();
    } catch (e) {
      if (allow) setError(extractError(e));
      else onDone();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={() => void answer(false)}
      title="Allow this AI-assistant call?"
      size="md"
      actions={
        <>
          <Button variant="ghost" onClick={() => void answer(false)} disabled={busy} autoFocus>
            Deny
          </Button>
          <Button variant="danger" onClick={() => void answer(true)} loading={busy}>
            Allow once
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <p>
          <span className="font-medium">{prompt.client_name}</span> wants to {confirmVerb(prompt)}:
        </p>
        <div className="space-y-1 rounded border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-3">
          <div className="flex min-w-0 items-center gap-2">
            <span className="min-w-0 truncate font-mono text-xs">{prompt.tool}</span>
            {prompt.reveals && <Badge variant="warning" label="reveals" />}
            {prompt.destructive && <Badge variant="error" label="changes" />}
          </div>
          {prompt.summary && (
            <p className="min-w-0 break-all font-mono text-xs" title={prompt.summary}>
              {prompt.summary}
            </p>
          )}
          {prompt.tool_description && (
            <p className="text-xs text-[var(--color-text-muted)]">{prompt.tool_description}</p>
          )}
        </div>
        <Countdown deadlineMs={prompt.deadline_unix_ms} />
        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}
      </div>
    </Modal>
  );
}

/**
 * Mounted once at the app root. Shows the local MCP server's pairing-consent
 * and per-call confirmation dialogs, one at a time, and starts the server
 * when a session unlocks if the operator turned it on. A prompt nobody
 * answers is refused by the host when it times out; this component only
 * ever reports the operator's explicit choice.
 */
export function McpPromptHost() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const [prompt, setPrompt] = useState<McpPrompt | null>(null);

  useEffect(() => {
    let cancelled = false;
    const unlistenPrompt = listen<McpPrompt>(MCP_PROMPT_EVENT, (e) => {
      if (!cancelled && isPrompt(e.payload)) setPrompt(e.payload);
    });
    const unlistenClosed = listen<string>(MCP_PROMPT_CLOSED_EVENT, (e) => {
      if (!cancelled) setPrompt((cur) => (cur && cur.id === e.payload ? null : cur));
    });
    // A prompt sent before this window (re)mounted.
    api
      .mcpPromptPending()
      .then((p) => {
        if (!cancelled && isPrompt(p)) setPrompt(p);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
      void unlistenPrompt.then((u) => u());
      void unlistenClosed.then((u) => u());
    };
  }, []);

  useEffect(() => {
    if (isAuthenticated) void api.mcpServerAutostart().catch(() => {});
  }, [isAuthenticated]);

  if (!prompt) return null;
  const done = () => setPrompt((cur) => (cur && cur.id === prompt.id ? null : cur));
  return prompt.kind === "pairing" ? (
    <McpPairingModal key={prompt.id} prompt={prompt} onDone={done} />
  ) : (
    <McpConfirmModal key={prompt.id} prompt={prompt} onDone={done} />
  );
}
