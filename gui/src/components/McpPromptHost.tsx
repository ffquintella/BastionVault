import { useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { Badge, Button, Input, Modal, Select, Textarea, useToast } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { namespaceLabel, narrowingOptions } from "../lib/mcpNamespace";
import type {
  McpCatalogueTool,
  McpConfirmPrompt,
  McpMfaAnswer,
  McpPairingPrompt,
  McpPrompt,
  McpSessionPrompt,
} from "../lib/types";
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

/** The pairing-dialog warning when one assistant may both reveal secrets and
 *  open sessions (features/mcp-brokered-sessions.md §9). */
export const TRIFECTA_WARNING =
  "This assistant can read secret values and run commands on servers. A hijacked assistant could send a " +
  "secret to a server. You will approve each command; read them.";

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
  // Brokered sessions: off by default, one checkbox per session tool.
  const [sessions, setSessions] = useState<string[]>([]);
  const maxHours = Math.max(1, Math.floor(prompt.max_ttl_secs / 3600));
  const [hours, setHours] = useState(String(Math.max(1, Math.round(prompt.default_ttl_secs / 3600))));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Namespace narrowing (features/mcp-namespace-selection.md Phase 2): the
  // session's own namespace by default; a descendant only when chosen.
  const ownNamespace = typeof prompt.namespace === "string" ? prompt.namespace : null;
  const [operable, setOperable] = useState<string[]>([]);
  const [target, setTarget] = useState<string>(ownNamespace ?? "");

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

  useEffect(() => {
    if (ownNamespace === null) return;
    let cancelled = false;
    api
      .namespacesSelf()
      .then((r) => {
        if (!cancelled) setOperable(Array.isArray(r?.namespaces) ? r.namespaces : []);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [ownNamespace]);

  const namespaceOptions = useMemo(
    () => (ownNamespace === null ? [] : narrowingOptions(ownNamespace, operable)),
    [ownNamespace, operable],
  );
  const narrowed = ownNamespace !== null && target !== ownNamespace;

  const paths = useMemo(() => parseLines(scope), [scope]);
  const hoursNum = Number(hours);
  const hoursValid = Number.isInteger(hoursNum) && hoursNum >= 1 && hoursNum <= maxHours;
  const canApprove = selected.length > 0 && paths.length > 0 && hoursValid && !busy;

  function toggle(name: string) {
    setSelected((cur) => (cur.includes(name) ? cur.filter((t) => t !== name) : [...cur, name]));
  }

  function toggleSession(name: string) {
    setSessions((cur) => (cur.includes(name) ? cur.filter((t) => t !== name) : [...cur, name]));
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
                tool_allowlist: [...selected, ...sessions],
                path_scope: paths,
                reveal_allowed: reveal,
                destructive_allowed: destructive,
                confirm_reveal: reveal && confirmReveal,
                confirm_destructive: destructive && confirmDestructive,
                connect_allowed: sessions.length > 0,
                ttl_secs: hoursNum * 3600,
                ...(narrowed ? { namespace: target } : {}),
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

  const known = tools.length > 0 ? tools : prompt.default_tools.map((name) => ({ name, description: "", kind: "read" }));
  // Session tools are granted in their own section, never from the list.
  const listed = known.filter((t) => t.kind !== "session");
  const sessionTools = tools.filter((t) => t.kind === "session");

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
          <div className="col-span-2 min-w-0 space-y-1">
            {namespaceOptions.length > 1 ? (
              <Select
                label="Namespace for its tokens"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                options={namespaceOptions.map((ns) => ({
                  value: ns,
                  label: ns === ownNamespace ? `${namespaceLabel(ns)} (your sign-in)` : namespaceLabel(ns),
                }))}
              />
            ) : (
              <p className="min-w-0 truncate">
                Namespace:{" "}
                <span className="font-mono text-xs" data-testid="mcp-pairing-namespace">
                  {ownNamespace === null ? "your sign-in's (could not be read)" : namespaceLabel(ownNamespace)}
                </span>
              </p>
            )}
            <p className="text-xs text-[var(--color-text-muted)]">
              Its calls run in this namespace, under that namespace&apos;s policies. A namespace beneath yours is
              accepted only when your sign-in can reach it; the vault refuses anything else rather than use another
              namespace.
            </p>
          </div>
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
          {sessionTools.length > 0 && (
            <div className="col-span-2 space-y-2 rounded border border-[var(--color-border)] p-3">
              <p className="font-medium">Brokered sessions — lets this assistant open connections to your servers</p>
              <p className="text-xs text-[var(--color-text-muted)]">
                The vault opens the connection and holds the credential; the assistant gets only the output. Every
                call is shown to you for approval, with the exact command, and runs only if you allow it. This
                cannot be turned off.
              </p>
              <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                {sessionTools.map((t) => (
                  <label key={t.name} className="flex min-w-0 items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={sessions.includes(t.name)}
                      onChange={() => toggleSession(t.name)}
                      aria-label={t.name}
                    />
                    <span className="min-w-0 truncate font-mono text-xs" title={t.description}>
                      {t.name}
                    </span>
                    <Badge variant="error" label="session" />
                  </label>
                ))}
              </div>
              {sessions.length > 0 && reveal && (
                <p role="alert" className="text-sm text-[var(--color-danger)]">
                  {TRIFECTA_WARNING}
                </p>
              )}
            </div>
          )}
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
  if (prompt.session) return <McpSessionConfirmModal prompt={prompt} session={prompt.session} onDone={onDone} />;
  return <McpCallConfirmModal prompt={prompt} onDone={onDone} />;
}

/** Where the call runs: the namespace the vault bound the pairing's token to.
 *  Says nothing when the vault did not report it, rather than guess root. */
function CallNamespace({ namespace }: { namespace?: string | null }) {
  if (typeof namespace !== "string") return null;
  return (
    <p className="min-w-0 truncate text-xs text-[var(--color-text-muted)]">
      Runs in namespace{" "}
      <span className="font-mono text-[var(--color-text)]" data-testid="mcp-call-namespace" title={namespace}>
        {namespaceLabel(namespace)}
      </span>
    </p>
  );
}

function McpCallConfirmModal({ prompt, onDone }: { prompt: McpConfirmPrompt; onDone: () => void }) {
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
        <CallNamespace namespace={prompt.namespace} />
        <Countdown deadlineMs={prompt.deadline_unix_ms} />
        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}
      </div>
    </Modal>
  );
}


/** The command as the operator reads it: every line numbered, so each line
 *  break is visible; never truncated (the box scrolls). The host has already
 *  escaped anything that could hide or disguise text. */
function CommandBox({ session }: { session: McpSessionPrompt }) {
  const lines = session.command.split("\n");
  return (
    <div className="space-y-1">
      <p className="text-xs text-[var(--color-text-muted)]">
        {`Command — ${session.command_bytes} bytes, ${lines.length} line${lines.length === 1 ? "" : "s"}`}
      </p>
      <div
        data-testid="mcp-session-command"
        className="max-h-60 overflow-auto rounded border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-2 font-mono text-xs"
      >
        {lines.map((line, i) => (
          <div key={i} className="flex min-w-0 gap-2">
            <span className="select-none text-[var(--color-text-muted)]">{i + 1}</span>
            <span className="min-w-0 whitespace-pre-wrap break-all">{line}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/** A web fetch's request as the operator reads it: the method and the whole
 *  path with its query, never truncated (the box wraps). The host has already
 *  escaped anything that could hide or disguise text. */
function PathBox({ session }: { session: McpSessionPrompt }) {
  return (
    <div className="space-y-1">
      <p className="text-xs text-[var(--color-text-muted)]">{`Request — ${session.path_bytes ?? 0} bytes of path`}</p>
      <div
        data-testid="mcp-session-path"
        className="max-h-60 overflow-auto rounded border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-2 font-mono text-xs"
      >
        <span className="min-w-0 whitespace-pre-wrap break-all">{`${session.method ?? "GET"} ${session.path ?? ""}`}</span>
      </div>
    </div>
  );
}

/**
 * The per-call confirmation of a brokered session (features/mcp-brokered-sessions.md
 * §9): mandatory for every call. It shows the resource, profile, protocol and
 * the exact command, and — on an MFA-gated profile — collects the operator's
 * own factor: "<client> is asking you to complete MFA to access <resource>".
 * Deny is the default; closing, Escape and the timeout deny; a factor the vault
 * refuses denies. The host verifies the factor and keeps the ticket; this
 * dialog never sees it.
 */
function McpSessionConfirmModal({
  prompt,
  session,
  onDone,
}: {
  prompt: McpConfirmPrompt;
  session: McpSessionPrompt;
  onDone: () => void;
}) {
  const { toast } = useToast();
  const methods = prompt.mfa?.methods ?? [];
  const needsMfa = !!prompt.mfa;
  const hasTotp = methods.includes("totp");
  const hasKey = methods.includes("fido2");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<null | "deny" | "allow" | "key">(null);
  const [error, setError] = useState<string | null>(null);
  const [keyStatus, setKeyStatus] = useState<string | null>(null);
  const [pinOpen, setPinOpen] = useState(false);
  const [pin, setPin] = useState("");

  // The security-key ceremony runs in the host while this dialog is open:
  // mirror its progress, and relay the key's PIN when it asks for one.
  useEffect(() => {
    if (!hasKey) return;
    const status = listen<string>("fido2-status", (e) => {
      if (e.payload === "tap-key") setKeyStatus("Tap your security key now…");
      else if (e.payload === "insert-key") setKeyStatus("Insert your security key…");
      else if (e.payload === "processing") setKeyStatus("Checking with the vault…");
    });
    const pinAsk = listen<string>("fido2-pin-request", () => {
      setPin("");
      setPinOpen(true);
    });
    return () => {
      void status.then((u) => u());
      void pinAsk.then((u) => u());
    };
  }, [hasKey]);

  async function send(allow: boolean, mfa?: McpMfaAnswer) {
    setBusy(!allow ? "deny" : mfa?.method === "fido2" ? "key" : "allow");
    setError(null);
    try {
      await api.mcpPromptAnswer(prompt.id, mfa ? { kind: "confirm", allow, mfa } : { kind: "confirm", allow });
      onDone();
    } catch (e) {
      const message = extractError(e);
      if (!allow) {
        onDone();
      } else if (mfa) {
        // The host has already refused the call; say why, wherever this
        // dialog has gone.
        toast("error", message);
        setError(message);
        onDone();
      } else {
        setError(message);
      }
    } finally {
      setBusy(null);
      setKeyStatus(null);
    }
  }

  const submitPin = async () => {
    const value = pin;
    setPin("");
    setPinOpen(false);
    try {
      await api.fido2SubmitPin(value);
    } catch (e) {
      setError(extractError(e));
    }
  };

  const canRunWithCode = hasTotp && /^\d{6,10}$/.test(code.trim());
  const web = session.protocol === "web";
  const act = web ? "fetch" : "run";
  return (
    <Modal
      open
      onClose={() => void send(false)}
      title={web ? `Fetch a page from ${session.resource}?` : `Run a command on ${session.resource}?`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={() => void send(false)} disabled={busy !== null} autoFocus>
            Deny
          </Button>
          {!needsMfa && (
            <Button variant="danger" onClick={() => void send(true)} loading={busy === "allow"}>
              {web ? "Fetch once" : "Run once"}
            </Button>
          )}
          {needsMfa && hasKey && (
            <Button
              variant={hasTotp ? "ghost" : "danger"}
              onClick={() => void send(true, { method: "fido2" })}
              loading={busy === "key"}
              disabled={busy !== null}
            >
              {`Use security key and ${act}`}
            </Button>
          )}
          {needsMfa && hasTotp && (
            <Button
              variant="danger"
              onClick={() => void send(true, { method: "totp", code: code.trim() })}
              disabled={!canRunWithCode || busy !== null}
              loading={busy === "allow"}
            >
              {`Verify code and ${act} once`}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <p>
          <span className="font-medium">{prompt.client_name}</span> wants to{" "}
          {web ? "fetch a page from" : "run a command on"}{" "}
          <span className="font-medium break-all">{session.resource}</span> over{" "}
          {web ? "HTTPS" : session.protocol.toUpperCase()}, through a session the vault opens and closes for this one
          call.
        </p>
        <div className="grid grid-cols-2 gap-3 rounded border border-[var(--color-border)] p-3">
          <div className="min-w-0">
            <p className="text-xs text-[var(--color-text-muted)]">Resource</p>
            <p className="truncate font-mono text-xs" title={session.resource}>
              {session.resource}
            </p>
          </div>
          <div className="min-w-0">
            <p className="text-xs text-[var(--color-text-muted)]">Profile</p>
            <p className="truncate font-mono text-xs" title={session.profile}>
              {session.profile}
            </p>
          </div>
          <div className="min-w-0">
            <p className="text-xs text-[var(--color-text-muted)]">Protocol</p>
            <p className="font-mono text-xs">{session.protocol}</p>
          </div>
          <div className="min-w-0">
            <p className="text-xs text-[var(--color-text-muted)]">Tool</p>
            <p className="truncate font-mono text-xs">{prompt.tool}</p>
          </div>
          {typeof prompt.namespace === "string" && (
            <div className="min-w-0">
              <p className="text-xs text-[var(--color-text-muted)]">Namespace</p>
              <p className="truncate font-mono text-xs" data-testid="mcp-call-namespace" title={prompt.namespace}>
                {namespaceLabel(prompt.namespace)}
              </p>
            </div>
          )}
          {web && (
            <div className="min-w-0">
              <p className="text-xs text-[var(--color-text-muted)]">Method</p>
              <p className="font-mono text-xs">{session.method ?? "GET"}</p>
            </div>
          )}
          <div className="col-span-2">{web ? <PathBox session={session} /> : <CommandBox session={session} />}</div>
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">
          {web
            ? "Read the request: it is sent exactly as shown to the profile's own address. When the site asks for a login, the vault answers with the profile's credential, which the assistant never sees. The page text goes back to the assistant."
            : "Read the command: it runs exactly as shown, with the profile's credential, which the assistant never sees. Its output goes back to the assistant."}
        </p>
        {needsMfa && (
          <div className="space-y-2 rounded border border-[var(--color-border)] p-3">
            <p>
              <span className="font-medium">{prompt.client_name}</span> is asking you to complete MFA to access{" "}
              <span className="font-medium break-all">{session.resource}</span> (profile{" "}
              <span className="font-mono text-xs">{session.profile}</span>).
            </p>
            {methods.length === 0 && (
              <p className="text-[var(--color-danger)]">None of your enrolled factors can be used here.</p>
            )}
            {hasTotp && (
              <Input
                label="Authenticator code"
                value={code}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                disabled={busy !== null}
                onChange={(e) => setCode(e.target.value)}
                hint="The current code from the authenticator app bound to your account."
              />
            )}
            {hasKey && keyStatus && <p className="text-xs text-[var(--color-text-muted)]">{keyStatus}</p>}
            {pinOpen && (
              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2">
                  <Input
                    label="Security key PIN"
                    type="password"
                    autoComplete="off"
                    value={pin}
                    onChange={(e) => setPin(e.target.value)}
                    hint="The PIN of the security key itself. It goes to the key only."
                  />
                </div>
                <Button onClick={() => void submitPin()} disabled={pin.length === 0}>
                  Unlock key
                </Button>
              </div>
            )}
          </div>
        )}
        <Countdown deadlineMs={prompt.deadline_unix_ms} />
        {error && (
          <p role="alert" className="text-sm text-[var(--color-danger)]">
            {error}
          </p>
        )}
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
