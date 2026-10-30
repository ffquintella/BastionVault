import { useEffect, useState } from "react";

import { sqlStepUpBegin, sqlStepUpVerify, type ConnectMfaChallenge } from "../../lib/api";
import { describeSqlError, stepUpActions } from "../../lib/sqlWorkspace";
import { CapChip } from "./SqlDialog";

/**
 * Per-action step-up (features/sql-browser.md §8.3). The host runs the
 * ceremony for this session's resource and profile, bound to `action`, and
 * keeps the ticket for the retried request; this dialog never sees it.
 */
export function SqlStepUpDialog({
  token,
  action,
  onDone,
}: {
  token: string;
  action: string;
  /** true once a ticket is held for the retry; false when cancelled. */
  onDone: (verified: boolean) => void;
}) {
  const [challenge, setChallenge] = useState<ConnectMfaChallenge | null>(null);
  const [method, setMethod] = useState<"totp" | "fido2">("totp");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    sqlStepUpBegin(token, action).then(
      (c) => {
        if (!alive) return;
        setChallenge(c);
        setMethod(c.methods.includes("fido2") ? "fido2" : "totp");
      },
      (e: unknown) => alive && setError(describeSqlError(e)),
    );
    return () => {
      alive = false;
    };
  }, [token, action]);

  const methods = challenge?.methods ?? [];
  const canVerify = !busy && methods.includes(method) && (method === "fido2" || code.trim().length > 0);

  const verify = async () => {
    if (!canVerify) return;
    setBusy(true);
    setError("");
    try {
      await sqlStepUpVerify(token, action, method, method === "totp" ? { code: code.trim() } : { challenge: challenge?.fido2 });
      onDone(true);
    } catch (e) {
      setError(describeSqlError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-label="Step-up required"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onKeyDown={(e) => {
        if (e.key === "Escape") onDone(false);
      }}
    >
      <form
        className="w-full max-w-md rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-2xl"
        onSubmit={(e) => {
          e.preventDefault();
          void verify();
        }}
      >
        <h2 className="mb-2 text-sm font-semibold text-[var(--color-text)]">Step-up required</h2>
        <div className="space-y-2 text-sm text-[var(--color-text-muted)]">
          <p>This SQL profile asks for a fresh second factor before a request uses:</p>
          <div className="flex flex-wrap gap-1" data-testid="sql-step-up-actions">
            {stepUpActions(action).map((a) => (
              <CapChip key={a} cap={a} tone="warn" />
            ))}
          </div>
          <p className="text-[11px]">The ticket is bound to exactly this action and spent by the request you are retrying.</p>
          {!challenge && !error && <p>Asking the server…</p>}
          {challenge && methods.length > 1 && (
            <label className="flex items-center gap-2">
              <span>Factor</span>
              <select
                aria-label="Factor"
                value={method}
                onChange={(e) => setMethod(e.target.value as "totp" | "fido2")}
                className="rounded border border-[var(--color-border)] bg-transparent px-1 text-[var(--color-text)]"
              >
                {methods.includes("fido2") && <option value="fido2">Security key</option>}
                {methods.includes("totp") && <option value="totp">Authenticator code</option>}
              </select>
            </label>
          )}
          {challenge && method === "totp" && methods.includes("totp") && (
            <input
              aria-label="Authenticator code"
              autoFocus
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="w-full rounded border border-[var(--color-border)] bg-transparent px-2 py-1 font-mono text-[var(--color-text)] outline-none"
            />
          )}
          {challenge && method === "fido2" && <p>Touch your security key when it asks.</p>}
          {error && (
            <p role="alert" className="break-words text-red-400">
              {error}
            </p>
          )}
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => onDone(false)}
            className="rounded-md border border-[var(--color-border)] px-3 py-1 text-xs text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!canVerify}
            className="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
          >
            {busy ? "Verifying…" : "Verify and retry"}
          </button>
        </div>
      </form>
    </div>
  );
}
