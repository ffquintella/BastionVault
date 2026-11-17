// Copy or move one object (a resource or a KV secret) to another
// namespace. Always checks first with a dry run, shows what would be carried
// and everything that would not, then runs for real on a second click.
import { useEffect, useState } from "react";
import { Badge, Button, Input, Modal, Select } from "./ui";
import * as api from "../lib/api";
import type { TransferKind, TransferOnConflict, TransferOp, TransferResult } from "../lib/api";
import { extractError } from "../lib/error";
import { useNamespaceStore } from "../stores/namespaceStore";

/** Warning codes that mean a share is not carried into the destination. */
const SHARE_WARNING_CODES = new Set([
  "grantee-not-in-destination",
  "group-not-in-destination",
  "cannot-grant",
  "share-expired",
  "unknown-grantee-kind",
  "share-not-written",
  "all-shares-dropped",
  "shares-unreadable",
]);

/**
 * A share warning raises the drop banner. The explicit set is the codes the
 * server sends today; the pattern keeps a future share code from slipping
 * past the banner. Group and file codes name neither word.
 */
function isShareWarning(code: string): boolean {
  return SHARE_WARNING_CODES.has(code) || /share|grantee/.test(code);
}

const CONFLICT_OPTIONS: { value: TransferOnConflict; label: string }[] = [
  { value: "refuse", label: "Refuse (stop, change nothing)" },
  { value: "rename", label: "Rename (use the first free name)" },
  { value: "overwrite", label: "Overwrite (replace the destination)" },
];

type Phase = "form" | "checking" | "checked" | "running" | "done";

/** The server's own message; a JSON error body is reduced to its text. */
function serverMessage(err: unknown): string {
  const raw = extractError(err).trim();
  if (raw.startsWith("{")) {
    try {
      const body = JSON.parse(raw) as { error?: unknown; errors?: unknown[] };
      const text = body.error ?? body.errors?.[0];
      if (typeof text === "string" && text) return text;
    } catch {
      /* not JSON after all: show it as is */
    }
  }
  return raw;
}

const nsLabel = (ns: string) => (ns === "" ? "root" : ns);

export function TransferToNamespaceModal({
  kind,
  namespace,
  mount,
  path,
  onClose,
  onTransferred,
}: {
  kind: TransferKind;
  /** The object's current namespace; `""` is root. */
  namespace: string;
  mount: string;
  path: string;
  onClose: () => void;
  /** Called once a real (not dry) run succeeded, so the page can refresh. */
  onTransferred?: (result: TransferResult, op: TransferOp) => void;
}) {
  const namespaces = useNamespaceStore((s) => s.namespaces);
  const ensureLoaded = useNamespaceStore((s) => s.ensureLoaded);
  useEffect(() => {
    void ensureLoaded();
  }, [ensureLoaded]);

  const [op, setOp] = useState<TransferOp>("copy");
  const [destNs, setDestNs] = useState(() => namespaces.find((n) => n !== namespace) ?? namespace);
  const [destMount, setDestMount] = useState(mount);
  const [destPath, setDestPath] = useState(path);
  const [onConflict, setOnConflict] = useState<TransferOnConflict>("refuse");
  const [phase, setPhase] = useState<Phase>("form");
  const [plan, setPlan] = useState<TransferResult | null>(null);
  const [result, setResult] = useState<TransferResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ackDelete, setAckDelete] = useState(false);
  const [ackOverwrite, setAckOverwrite] = useState(false);

  // The list may arrive after the first render; keep the destination valid.
  useEffect(() => {
    if (namespaces.length > 0 && !namespaces.includes(destNs)) {
      setDestNs(namespaces.find((n) => n !== namespace) ?? namespaces[0]);
    }
  }, [namespaces, destNs, namespace]);

  const busy = phase === "checking" || phase === "running";
  // The server reads a resource name without case and a KV path exactly.
  const samePath = (a: string, b: string) => {
    const [x, y] = [a, b].map((p) => p.trim().replace(/^\/+|\/+$/g, ""));
    return kind === "resource" ? x.toLowerCase() === y.toLowerCase() : x === y;
  };
  const sameAsSource =
    destNs === namespace &&
    destMount.trim().replace(/^\/+|\/+$/g, "") === mount.replace(/^\/+|\/+$/g, "") &&
    samePath(destPath, path);
  const incomplete = destMount.trim() === "" || destPath.trim() === "";

  /** Any edit makes a checked plan stale: back to the form, acks cleared. */
  function edit<T>(set: (v: T) => void) {
    return (v: T) => {
      set(v);
      setPlan(null);
      setAckDelete(false);
      setAckOverwrite(false);
      setError(null);
      if (phase === "checked") setPhase("form");
    };
  }

  function request(dryRun: boolean) {
    return api.transferObject({
      op,
      kind,
      source: { namespace, mount, path },
      destination: { namespace: destNs, mount: destMount.trim(), path: destPath.trim() },
      onConflict,
      dryRun,
    });
  }

  async function check() {
    setError(null);
    setPhase("checking");
    try {
      setPlan(await request(true));
      setAckDelete(false);
      setAckOverwrite(false);
      setPhase("checked");
    } catch (err: unknown) {
      setPlan(null);
      setError(serverMessage(err));
      setPhase("form");
    }
  }

  async function run() {
    setError(null);
    setPhase("running");
    try {
      const done = await request(false);
      setResult(done);
      setPhase("done");
      onTransferred?.(done, op);
    } catch (err: unknown) {
      // The error says what was written; the destination may have changed, so
      // the plan is stale and a new check is required.
      setPlan(null);
      setAckDelete(false);
      setAckOverwrite(false);
      setError(serverMessage(err));
      setPhase("form");
    }
  }

  const shown = phase === "done" ? result : plan;
  const locked = busy || phase === "done";
  const runBlocked = (op === "move" && !ackDelete) || (onConflict === "overwrite" && !ackOverwrite);

  return (
    <Modal
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      title="Copy or move to another namespace"
      size="lg"
      actions={
        phase === "done" ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              onClick={check}
              loading={phase === "checking"}
              disabled={busy || sameAsSource || incomplete}
            >
              Check
            </Button>
            {phase === "checked" && (
              <Button
                variant={op === "move" ? "danger" : "primary"}
                onClick={run}
                disabled={runBlocked}
              >
                {op === "move" ? "Move now" : "Copy now"}
              </Button>
            )}
            {phase === "running" && (
              <Button variant={op === "move" ? "danger" : "primary"} loading disabled>
                {op === "move" ? "Move now" : "Copy now"}
              </Button>
            )}
          </>
        )
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-[var(--color-text-muted)] min-w-0 truncate" title={`${nsLabel(namespace)}/${mount}/${path}`}>
          From <span className="font-mono">{nsLabel(namespace)}</span> ·{" "}
          <span className="font-mono">{mount}/{path}</span>
        </p>

        <div className="grid grid-cols-2 gap-3">
          <fieldset className="col-span-2 flex gap-4" disabled={locked}>
            <legend className="sr-only">Operation</legend>
            {(["copy", "move"] as const).map((o) => (
              <label key={o} className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="transfer-op"
                  value={o}
                  checked={op === o}
                  onChange={() => edit(setOp)(o)}
                />
                {o === "copy" ? "Copy" : "Move"}
              </label>
            ))}
          </fieldset>

          <div className="col-span-2 min-w-0">
            <Select
              label="Destination namespace"
              value={destNs}
              disabled={locked}
              onChange={(e) => edit(setDestNs)(e.target.value)}
              options={(namespaces.length > 0 ? namespaces : [namespace]).map((n) => ({
                value: n,
                label: nsLabel(n),
              }))}
            />
          </div>
          <div className="min-w-0">
            <Input
              label="Destination mount"
              value={destMount}
              disabled={locked}
              onChange={(e) => edit(setDestMount)(e.target.value)}
              hint="Without a namespace prefix."
            />
          </div>
          <div className="min-w-0">
            <Input
              label="Destination path"
              value={destPath}
              disabled={locked}
              onChange={(e) => edit(setDestPath)(e.target.value)}
            />
          </div>
          <div className="col-span-2 min-w-0">
            <Select
              label="If the destination exists"
              value={onConflict}
              disabled={locked}
              onChange={(e) => edit(setOnConflict)(e.target.value as TransferOnConflict)}
              options={CONFLICT_OPTIONS}
            />
          </div>
        </div>

        {onConflict === "overwrite" && (
          <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
            Overwrite tries the import first; if the name is taken it deletes the destination and imports
            again. This is not atomic: if that import fails, the destination stays deleted.
          </p>
        )}

        {sameAsSource && (
          <p className="text-xs text-[var(--color-danger)]">The destination is the same as the source.</p>
        )}

        {error && (
          <div
            role="alert"
            className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400 break-words"
          >
            {error}
          </div>
        )}

        {shown && <Outcome result={shown} done={phase === "done"} op={op} />}

        {phase === "checked" && op === "move" && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={ackDelete}
              onChange={(e) => setAckDelete(e.target.checked)}
            />
            <span>I understand the source will be deleted once the copy is written.</span>
          </label>
        )}

        {phase === "checked" && onConflict === "overwrite" && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={ackOverwrite}
              onChange={(e) => setAckOverwrite(e.target.checked)}
            />
            <span>I understand the destination is deleted if the name is taken; this is not atomic.</span>
          </label>
        )}
      </div>
    </Modal>
  );
}

function Outcome({ result, done, op }: { result: TransferResult; done: boolean; op: TransferOp }) {
  const t = result.transferred;
  const dropsShares = result.warnings.some((w) => isShareWarning(w.code));
  const counts: [string, string, number][] = [
    ["secrets", "Secrets", t.secrets],
    ["versions", "Versions", t.versions],
    ["history", "History entries", t.history],
    ["shares", "Shares", t.shares],
  ];
  return (
    <section className="space-y-3">
      <h4 className="text-sm font-semibold text-[var(--color-text)]">
        {done
          ? `Transfer complete (${op === "move" ? "moved" : "copied"}) to ${nsLabel(result.destination.namespace)} · ${result.destination.mount}/${result.destination.path}`
          : "Check result: nothing has been written yet"}
      </h4>
      <dl className="grid grid-cols-4 gap-3 text-sm">
        {counts.map(([key, label, n]) => (
          <div key={key} className="min-w-0">
            <dt className="text-xs text-[var(--color-text-muted)] truncate">{label}</dt>
            <dd data-testid={`count-${key}`} className="font-mono">
              {n}
            </dd>
          </div>
        ))}
      </dl>

      {dropsShares && (
        <div
          role="status"
          className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm font-medium text-amber-400"
        >
          {done ? "Some or all shares were dropped." : "Some or all shares will be dropped."}
        </div>
      )}

      {result.warnings.length > 0 && (
        <ul className="space-y-2">
          {result.warnings.map((w, i) => (
            <li key={`${w.code}-${w.subject}-${i}`} className="flex items-start gap-3">
              <div className="shrink-0 pt-0.5">
                <Badge label={w.code} variant={isShareWarning(w.code) ? "warning" : "info"} />
              </div>
              <div className="min-w-0">
                <div className="font-mono text-xs text-[var(--color-text)] truncate" title={w.subject}>
                  {w.subject}
                </div>
                <div className="text-xs text-[var(--color-text-muted)] break-words">{w.message}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
