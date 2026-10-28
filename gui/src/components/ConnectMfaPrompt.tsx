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
import { extractError } from "../lib/error";
// Not the `./ui` barrel: this file is in the session-only bundle
// (session.html, T110), whose import graph `sessionBundle.test.ts` keeps
// free of the barrel's vault-admin components.
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { Modal } from "./ui/Modal";

/** Resolved once per Connect click. `null` = the operator cancelled. */
export type ConnectMfaOutcome = { connect_ticket?: string } | null;

type PendingPrompt = {
  resourceName: string;
  profileId: string;
  profileName: string;
  challenge: api.ConnectMfaChallenge;
  resolve: (outcome: ConnectMfaOutcome) => void;
};

/** Relays a security-key PIN to the host's waiting CTAP ceremony (`""`
 *  aborts it). Only the main window may: `fido2_submit_pin` is outside every
 *  session window's capability set, so session windows pass none. */
export type SubmitPin = (pin: string) => Promise<void>;

export function ConnectMfaPrompt({
  pending,
  submitPin,
}: {
  pending: PendingPrompt | null;
  submitPin?: SubmitPin;
}) {
  const methods = pending?.challenge.methods ?? [];
  const hasFido2 = methods.includes("fido2");
  const hasTotp = methods.includes("totp");

  const [method, setMethod] = useState<"fido2" | "totp">("fido2");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyStatus, setKeyStatus] = useState<string | null>(null);
  // The authenticator's PIN, collected while the host's CTAP ceremony waits
  // on `fido2_submit_pin`. Never stored beyond this field.
  const [pinOpen, setPinOpen] = useState(false);
  const [pin, setPin] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const [pinUnavailable, setPinUnavailable] = useState(false);

  // Reset per prompt, and default to the strongest factor the operator
  // actually has (the server already ordered `methods` that way).
  useEffect(() => {
    if (!pending) return;
    setMethod(hasFido2 ? "fido2" : "totp");
    setCode("");
    setError(null);
    setKeyStatus(null);
    setBusy(false);
    setPinOpen(false);
    setPin("");
    setPinError(null);
    setPinUnavailable(false);
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
        // On Windows the OS dialog drives insert / tap / PIN itself, so this
        // is the last progress step we hear about before the result.
        case "os-prompt":
          setKeyStatus("Follow the Windows security prompt\u2026");
          break;
        case "tap-key":
          setKeyStatus("Tap your security key now\u2026");
          break;
        case "pin-required":
          setKeyStatus("Your key is asking for its PIN\u2026");
          break;
        case "pin-not-set":
          setKeyStatus("This key has no PIN set. Set one in your authenticator first.");
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
          setPinOpen(false);
          break;
        case "complete":
          setPinOpen(false);
          break;
        default:
          if (event.payload.startsWith("invalid-pin")) setKeyStatus("Wrong PIN\u2026");
          else setKeyStatus(null);
      }
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, [pending]);

  // The ceremony blocks on this: `request_pin_from_frontend` emits
  // `fido2-pin-request` and waits up to two minutes for `fido2_submit_pin`.
  // Without this listener a PIN-protected key stalls the prompt with Cancel
  // disabled until that timeout.
  useEffect(() => {
    if (!pending) return;
    const unlisten = listen<string>("fido2-pin-request", (event) => {
      const payload = event.payload;
      setPin("");
      if (!submitPin) {
        setPinUnavailable(true);
        setError(
          "This security key needs its PIN, which can only be entered in the main BastionVault window. " +
            "Cancel and connect from there, or use an authenticator code.",
        );
        return;
      }
      if (payload.startsWith("invalid-pin")) {
        const attempts = payload.split(":")[1];
        setPinError(attempts ? `Wrong PIN. ${attempts} attempts remaining.` : "Wrong PIN. Try again.");
      } else {
        setPinError(null);
      }
      setPinOpen(true);
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, [pending, submitPin]);

  if (!pending) return null;

  // Relay the PIN (or "" to abort) to the waiting ceremony. A refused relay
  // means this window may not submit PINs, or the ceremony already gave up;
  // say so rather than leaving the key prompt hanging.
  const relayPin = async (value: string) => {
    if (!submitPin) return;
    try {
      await submitPin(value);
    } catch (e) {
      setPinOpen(false);
      setError(
        `Your security key's PIN could not be passed on (${extractError(e)}). ` +
          "Connect from the main BastionVault window, or use an authenticator code.",
      );
    }
  };

  const unlockKey = () => {
    if (!pin) return;
    const value = pin;
    setPin("");
    setPinError(null);
    setPinOpen(false);
    void relayPin(value);
  };

  // Cancelling the PIN aborts the ceremony at once; the verify call then
  // fails and the prompt stays open for a retry or the TOTP tab.
  const cancelPin = () => {
    setPin("");
    setPinError(null);
    setPinOpen(false);
    void relayPin("");
  };

  // Busy normally locks the prompt while the key works; a PIN this window
  // cannot relay would hold it there for the host's two-minute timeout, so
  // Cancel stays live in that case.
  const cancel = () => {
    if (busy && !pinUnavailable) return;
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
      setError(extractError(e));
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
        pinOpen ? (
          <>
            <Button variant="ghost" onClick={cancelPin}>
              Cancel
            </Button>
            <Button onClick={unlockKey} disabled={pin.length === 0}>
              Unlock key
            </Button>
          </>
        ) : (
        <>
          <Button variant="ghost" onClick={cancel} disabled={busy && !pinUnavailable}>
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
        )
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

        {method === "fido2" && pinOpen && (
          <Input
            autoFocus
            label="Security key PIN"
            type="password"
            autoComplete="off"
            value={pin}
            error={pinError ?? undefined}
            onChange={(e) => setPin(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && pin) unlockKey();
            }}
            hint="The PIN of the security key itself, not your BastionVault password. It goes to the key only."
          />
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
export function useConnectMfa(submitPin?: SubmitPin) {
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

  return { gateConnect, mfaPrompt: <ConnectMfaPrompt pending={pending} submitPin={submitPin} /> };
}

export type { PendingPrompt };
