/**
 * SSH security-key enrolment
 * (features/connect-mfa-and-fido2-ssh.md).
 *
 * Registers a FIDO2 credential under the OpenSSH `ssh:` application and shows
 * the resulting `sk-` public key so the operator can install it on target
 * hosts. Nothing here is secret — the private half never leaves the
 * authenticator, and the record holds a public key plus a credential handle.
 *
 * This is a *different* credential from the operator's WebAuthn passkey, even
 * on the same physical key, because the relying-party id differs. Enrolling
 * here does not change how they log in to BastionVault.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { Badge, Button, Card, ConfirmModal, Input, Modal, useToast } from "./ui";

export function SshSecurityKeyCard() {
  const { toast } = useToast();
  const [info, setInfo] = useState<api.SshSecurityKeyInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [pinOpen, setPinOpen] = useState(false);
  const [pin, setPin] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const pinInputRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setInfo(await api.sshSecurityKeySelfRead());
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Mirror the authenticator's progress during enrolment — the ceremony can
  // sit for many seconds waiting for a touch or a PIN, and a bare spinner
  // gives the operator no idea which.
  useEffect(() => {
    const unlisten = listen<string>("fido2-status", (event) => {
      const s = event.payload;
      if (s === "insert-key") setStatus("Insert your security key…");
      // On Windows the OS dialog drives insert / tap / PIN itself, so no
      // in-app PIN modal will ever open.
      else if (s === "os-prompt") setStatus("Follow the Windows security prompt…");
      else if (s === "tap-key") setStatus("Tap your security key now…");
      else if (s === "pin-required") setStatus("Your key is asking for its PIN…");
      else if (s.startsWith("invalid-pin")) setStatus("Wrong PIN…");
      // Blocked states end the ceremony: say so rather than leaving the
      // operator staring at "Working…" until the 60 s timeout.
      else if (s === "pin-auth-blocked")
        setStatus("Too many wrong PINs — unplug the key and retry.");
      else if (s === "pin-blocked")
        setStatus("Key locked — it must be reset before it can be enrolled.");
      else if (s === "pin-not-set")
        setStatus("This key has no PIN set — set one in your authenticator first.");
      else if (s === "processing") {
        setStatus("Saving the enrolment…");
        setPinOpen(false);
      } else if (s === "complete") {
        setStatus(null);
        setPinOpen(false);
      } else setStatus(null);
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, []);

  // The ceremony blocks on this: `request_pin_from_frontend` emits
  // `fido2-pin-request` and then waits up to two minutes for
  // `fido2_submit_pin`. Without this listener the enrolment silently stalls
  // on any PIN-protected authenticator.
  useEffect(() => {
    const unlisten = listen<string>("fido2-pin-request", (event) => {
      const payload = event.payload;
      setPin("");
      if (payload.startsWith("invalid-pin")) {
        const attempts = payload.split(":")[1];
        setPinError(
          attempts
            ? `Wrong PIN. ${attempts} attempts remaining.`
            : "Wrong PIN. Try again.",
        );
      } else {
        setPinError(null);
      }
      setPinOpen(true);
      setTimeout(() => pinInputRef.current?.focus(), 50);
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, []);

  async function submitPin() {
    if (!pin) return;
    setPinOpen(false);
    setPinError(null);
    const value = pin;
    setPin("");
    // A relay failure means the ceremony already gave up; it surfaces as the
    // enrolment error rather than a second toast here.
    try {
      await api.fido2SubmitPin(value);
    } catch {
      /* ceremony reports */
    }
  }

  // Cancelling relays an empty PIN, which drops the CTAP sender and aborts
  // the ceremony immediately instead of letting it sit for two minutes.
  async function cancelPin() {
    setPinOpen(false);
    setPinError(null);
    setPin("");
    try {
      await api.fido2SubmitPin("");
    } catch {
      /* ignore */
    }
  }

  async function enroll() {
    setBusy(true);
    try {
      const next = await api.sshSecurityKeyEnroll(
        info?.name || "bastionvault",
        undefined,
        comment.trim(),
      );
      setInfo(next);
      setComment("");
      toast(
        "success",
        "Security key enrolled. Add the public key below to each host's authorized_keys.",
      );
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setStatus(null);
      setBusy(false);
    }
  }

  async function remove() {
    setConfirmRemove(false);
    setBusy(true);
    try {
      await api.sshSecurityKeySelfDelete();
      await refresh();
      toast(
        "info",
        "Enrolment removed. Remember to delete the public key from your hosts' authorized_keys too.",
      );
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }

  async function copyPublicKey() {
    if (!info?.public_key) return;
    try {
      await navigator.clipboard.writeText(info.public_key);
      toast("success", "Public key copied");
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card
      title="SSH security key"
      actions={
        info?.enrolled ? <Badge label={info.algorithm} /> : undefined
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-[var(--color-text-muted)]">
          Enrol a FIDO2 key as an SSH login credential. Connection profiles
          using the{" "}
          <strong className="text-[var(--color-text)]">
            Connecting user&rsquo;s FIDO2 security key
          </strong>{" "}
          source authenticate with it, and every connect needs a physical
          touch. The private key never leaves the authenticator &mdash; it
          cannot be copied off, and it is not stored here or on the server.
        </p>

        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
        ) : info?.enrolled ? (
          <div className="space-y-3">
            <div className="space-y-1">
              <p className="text-xs font-medium text-[var(--color-text)]">
                Public key &mdash; add this line to{" "}
                <code>~/.ssh/authorized_keys</code> on every host you want to
                reach
              </p>
              <div className="flex items-start gap-2">
                <code className="min-w-0 flex-1 break-all rounded bg-[var(--color-bg)] border border-[var(--color-border)] px-2 py-1.5 text-[11px]">
                  {info.public_key}
                </code>
                <Button variant="ghost" onClick={copyPublicKey}>
                  Copy
                </Button>
              </div>
            </div>

            <dl className="grid grid-cols-2 gap-2 text-xs">
              <div className="min-w-0">
                <dt className="text-[var(--color-text-muted)]">Application</dt>
                <dd className="truncate font-mono">{info.application}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-[var(--color-text-muted)]">Enrolled</dt>
                <dd className="truncate font-mono">
                  {info.updated_at.replace("T", " ").replace("Z", "")}
                </dd>
              </div>
              {info.comment && (
                <div className="col-span-2 min-w-0">
                  <dt className="text-[var(--color-text-muted)]">Label</dt>
                  <dd className="truncate">{info.comment}</dd>
                </div>
              )}
            </dl>

            <div className="flex flex-wrap items-center gap-2">
              <Button variant="ghost" onClick={enroll} disabled={busy}>
                {busy ? status ?? "Working…" : "Replace with a different key"}
              </Button>
              <Button
                variant="danger"
                onClick={() => setConfirmRemove(true)}
                disabled={busy}
              >
                Remove enrolment
              </Button>
            </div>
            <p className="text-xs text-[var(--color-text-muted)]">
              Removing the enrolment only stops BastionVault from offering this
              key. It does not revoke your access to any host &mdash; for that,
              delete the public key from that host&rsquo;s{" "}
              <code>authorized_keys</code>.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Label (optional)"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="YubiKey 5C — desk"
                disabled={busy}
                hint="Shown next to the enrolment so you can tell two keys apart."
              />
            </div>
            <Button onClick={enroll} disabled={busy}>
              {busy ? status ?? "Working…" : "Enrol SSH security key"}
            </Button>
            {busy && status && (
              <p className="text-xs text-[var(--color-text-muted)]">{status}</p>
            )}
          </div>
        )}
      </div>

      <Modal
        open={pinOpen}
        onClose={cancelPin}
        title="Security key PIN"
        size="sm"
        actions={
          <>
            <Button variant="ghost" onClick={cancelPin}>
              Cancel
            </Button>
            <Button onClick={submitPin} disabled={!pin}>
              Submit
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            Your security key requires its PIN before it will create the SSH
            credential. The PIN is verified by the authenticator itself &mdash;
            it is not sent to the server or stored.
          </p>
          {pinError && (
            <p className="text-sm font-medium text-[var(--color-danger)]">
              {pinError}
            </p>
          )}
          <input
            ref={pinInputRef}
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && pin) void submitPin();
            }}
            placeholder="Enter PIN"
            autoComplete="off"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
          />
        </div>
      </Modal>

      <ConfirmModal
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        onConfirm={remove}
        title="Remove SSH security key"
        message="Connection profiles using the FIDO2 credential source will stop working for you until you enrol another key. This does not remove the public key from any host."
        confirmLabel="Remove"
        variant="danger"
      />
    </Card>
  );
}
