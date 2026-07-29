/**
 * Connect-time MFA re-validation prompt
 * (features/connect-mfa-and-fido2-ssh.md).
 *
 * Every Connect path funnels through {@link runConnectMfa}: it asks the
 * server whether the profile is gated and, when it is, drives the factor
 * ceremony and returns the single-use ticket the session open must carry.
 *
 * The frontend never inspects `require_mfa` itself. The server owns that
 * decision, and this component's whole job is to render whatever it says —
 * so a stale or tampered local copy of the resource record changes nothing.
 */

import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import * as api from "../lib/api";
import { Button, Input, Modal } from "./ui";

/** Resolved once per Connect click. `null` = the operator cancelled. */
export type ConnectMfaOutcome = { connect_ticket?: string } | null;

type PendingPrompt = {
  resourceName: string;
  profileId: string;
  profileName: string;
  challenge: api.ConnectMfaChallenge;
  resolve: (outcome: ConnectMfaOutcome) => void;
};

export function ConnectMfaPrompt({ pending }: { pending: PendingPrompt | null }) {
  const methods = pending?.challenge.methods ?? [];
  const hasFido2 = methods.includes("fido2");
  const hasTotp = methods.includes("totp");

  const [method, setMethod] = useState<"fido2" | "totp">("fido2");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyStatus, setKeyStatus] = useState<string | null>(null);

  // Reset per prompt, and default to the strongest factor the operator
  // actually has (the server already ordered `methods` that way).
  useEffect(() => {
    if (!pending) return;
    setMethod(hasFido2 ? "fido2" : "totp");
    setCode("");
    setError(null);
    setKeyStatus(null);
    setBusy(false);
  }, [pending, hasFido2]);

  // Mirror the authenticator's own progress so a security-key prompt says
  // what the key is waiting for ("tap it now", "PIN required") instead of
  // sitting on a generic spinner. Same event stream the login page uses.
  useEffect(() => {
    if (!pending) return;
    const unlisten = listen<string>("fido2-status", (event) => {
      switch (event.payload) {
        case "insert-key":
          setKeyStatus("Insert your security key\u2026");
          break;
        case "tap-key":
          setKeyStatus("Tap your security key now\u2026");
          break;
        case "pin-required":
          setKeyStatus("Your key is asking for its PIN\u2026");
          break;
        case "pin-auth-blocked":
          setKeyStatus(
            "Too many failed PIN attempts. Unplug and re-insert your key.",
          );
          break;
        case "pin-blocked":
          setKeyStatus("This key's PIN is blocked and must be reset.");
          break;
        case "processing":
          setKeyStatus("Checking with the server\u2026");
          break;
        default:
          setKeyStatus(null);
      }
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, [pending]);

  if (!pending) return null;

  const cancel = () => {
    if (busy) return;
    pending.resolve(null);
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const ticket =
        method === "totp"
          ? await api.connectMfaVerifyTotp(
              pending.resourceName,
              pending.profileId,
              code,
            )
          : await api.connectMfaVerifyFido2(
              pending.resourceName,
              pending.profileId,
              pending.challenge.fido2,
            );
      pending.resolve({ connect_ticket: ticket.connect_ticket });
    } catch (e) {
      // Stay open on failure: a mistyped code or a missed touch should be
      // retryable without re-clicking Connect. The ticket is only minted on
      // success, so there is nothing to clean up.
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      setKeyStatus(null);
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      onClose={cancel}
      size="sm"
      title="Confirm it's you"
      actions={
        <>
          <Button variant="ghost" onClick={cancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={busy || (method === "totp" && code.trim().length === 0)}
          >
            {busy
              ? method === "fido2"
                ? "Waiting for your key…"
                : "Verifying…"
              : "Verify and connect"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-[var(--color-text-muted)]">
          <strong className="text-[var(--color-text)]">
            {pending.profileName}
          </strong>{" "}
          on{" "}
          <strong className="text-[var(--color-text)]">
            {pending.resourceName}
          </strong>{" "}
          requires you to re-confirm a second factor before the session opens.
        </p>

        {hasFido2 && hasTotp && (
          <div className="flex gap-2 text-sm">
            <button
              type="button"
              className={`rounded-md border px-3 py-1.5 ${
                method === "fido2"
                  ? "border-[var(--color-accent)] text-[var(--color-text)]"
                  : "border-[var(--color-border)] text-[var(--color-text-muted)]"
              }`}
              onClick={() => setMethod("fido2")}
              disabled={busy}
            >
              Security key
            </button>
            <button
              type="button"
              className={`rounded-md border px-3 py-1.5 ${
                method === "totp"
                  ? "border-[var(--color-accent)] text-[var(--color-text)]"
                  : "border-[var(--color-border)] text-[var(--color-text-muted)]"
              }`}
              onClick={() => setMethod("totp")}
              disabled={busy}
            >
              Authenticator code
            </button>
          </div>
        )}

        {method === "totp" ? (
          <Input
            label="Authenticator code"
            value={code}
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            disabled={busy}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && code.trim()) void submit();
            }}
            hint="The current code from the authenticator app bound to your account."
          />
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            {keyStatus ??
              "Insert your security key and touch it when it lights up."}
          </p>
        )}

        {error && (
          <p className="text-xs text-[var(--color-danger)]" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

/**
 * The connect-time MFA gate, packaged for a launcher component.
 *
 * ```tsx
 * const { gateConnect, mfaPrompt } = useConnectMfa();
 * // …
 * const mfa = await gateConnect(resourceName, profile.id, profile.name);
 * if (!mfa) return;                       // operator cancelled
 * await api.sessionOpenSsh({ …, ...mfa }); // spreads connect_ticket when gated
 * // …
 * return <>{…}{mfaPrompt}</>;
 * ```
 *
 * `gateConnect` returns `{}` for an ungated profile (so the spread is a
 * no-op), `{connect_ticket}` once a factor is proved, and `null` when the
 * operator cancels — abandon the connect silently in that case, a cancel is
 * not an error.
 */
export function useConnectMfa() {
  const [pending, setPending] = useState<PendingPrompt | null>(null);

  const gateConnect = async (
    resourceName: string,
    profileId: string,
    profileName: string,
  ): Promise<ConnectMfaOutcome> => {
    // The server decides whether a factor is needed. An ungated profile
    // costs one round trip and never shows a modal.
    const challenge = await api.connectMfaBegin(resourceName, profileId);
    if (!challenge.required) return {};

    return new Promise<ConnectMfaOutcome>((resolve) => {
      setPending({
        resourceName,
        profileId,
        profileName,
        challenge,
        resolve: (outcome) => {
          setPending(null);
          resolve(outcome);
        },
      });
    });
  };

  return { gateConnect, mfaPrompt: <ConnectMfaPrompt pending={pending} /> };
}

export type { PendingPrompt };
