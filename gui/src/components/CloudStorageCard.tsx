/**
 * Cloud Storage Targets card — Settings subsection that runs the
 * OAuth consent flow for OneDrive / Google Drive / Dropbox and
 * persists the resulting refresh token to a configurable location.
 *
 * Mirrors the CLI's `bvault operator cloud-target connect` flow,
 * but splits the browser-open step so the user sees the real
 * system browser rather than a Tauri popup:
 *
 *   1. Call `cloudTargetStartConnect` → `{sessionId, consentUrl}`.
 *   2. Open the URL via the Tauri `shell` plugin.
 *   3. Call `cloudTargetCompleteConnect` (blocks up to 5 min while
 *      the loopback listener waits for the callback).
 *   4. Success toast + form reset; on error or cancel the card
 *      sends `cloudTargetCancelConnect` to release the listener.
 *
 * No new target is activated here — the vault's storage config is
 * still authored in HCL and requires a restart to switch. What
 * this card does is bind the identity (refresh token) so that when
 * the operator flips their config over, the resulting target has
 * everything it needs to authenticate.
 */
import { useState } from "react";
import { Button, Card, Input, Select, useToast } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { open as shellOpen } from "@tauri-apps/plugin-shell";

type Target = "onedrive" | "gdrive" | "dropbox";

const TARGET_LABELS: Record<Target, string> = {
  onedrive: "Microsoft OneDrive",
  gdrive: "Google Drive",
  dropbox: "Dropbox",
};

export function CloudStorageCard() {
  const { toast } = useToast();
  const [target, setTarget] = useState<Target>("onedrive");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [credentialsRef, setCredentialsRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<"idle" | "consent" | "exchange">("idle");

  async function connect() {
    if (!clientId.trim()) {
      toast("error", "Client ID is required");
      return;
    }
    if (!credentialsRef.trim()) {
      toast("error", "Credentials ref is required (e.g. file:/path/to/refresh-token)");
      return;
    }
    setBusy(true);
    setPhase("consent");
    let sessionId: string | null = null;
    try {
      // Step 1: bind the loopback listener + get the consent URL.
      const start = await api.cloudTargetStartConnect({
        target,
        clientId: clientId.trim(),
        clientSecret: clientSecret.trim() || undefined,
        credentialsRef: credentialsRef.trim(),
      });
      sessionId = start.sessionId;

      // Step 2: open the URL in the real system browser so the user
      // sees the provider's consent screen in their existing signed-
      // in session (rather than Tauri's blank webview).
      await shellOpen(start.consentUrl);
      toast("info", "Opened consent page in your browser — waiting for callback…");

      // Step 3: block until the loopback callback + token exchange
      // + refresh-token persistence complete.
      setPhase("exchange");
      await api.cloudTargetCompleteConnect({ sessionId });

      toast(
        "success",
        `Connected to ${TARGET_LABELS[target]} — refresh token saved to ${credentialsRef.trim()}.`,
      );
      setPhase("idle");
      sessionId = null;
      // Reset the sensitive fields; leave target + credentialsRef
      // so the operator can re-run quickly if they need to.
      setClientSecret("");
    } catch (e: unknown) {
      toast("error", extractError(e));
      // If the failure landed between start and complete, release
      // the listener so the OS port isn't held for 5 minutes.
      if (sessionId) {
        try {
          await api.cloudTargetCancelConnect(sessionId);
        } catch {
          /* best-effort cleanup — log noise isn't helpful here */
        }
      }
      setPhase("idle");
    } finally {
      setBusy(false);
    }
  }

  const status = phase === "consent"
    ? "Preparing consent URL…"
    : phase === "exchange"
      ? "Waiting for browser callback…"
      : null;

  return (
    <Card title="Cloud Storage Targets">
      <div className="space-y-3">
        <p className="text-sm text-[var(--color-text-muted)]">
          Connect a cloud storage provider so the Encrypted File backend can
          back up or serve vault data from it. This step persists the
          provider's refresh token only — switching the active storage
          target still happens in server config + restart. You must register
          your own OAuth application with the provider; BastionVault does
          not ship consumer-provider client secrets.
        </p>

        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Provider"
            value={target}
            onChange={(e) => setTarget(e.target.value as Target)}
            options={[
              { value: "onedrive", label: TARGET_LABELS.onedrive },
              { value: "gdrive", label: TARGET_LABELS.gdrive },
              { value: "dropbox", label: TARGET_LABELS.dropbox },
            ]}
          />
          <Input
            label="Client ID"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="OAuth application client id"
          />
        </div>

        <Input
          label="Client Secret (optional)"
          type="password"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          placeholder="Only for confidential clients; leave blank for PKCE-only apps"
        />

        <Input
          label="Credentials ref"
          value={credentialsRef}
          onChange={(e) => setCredentialsRef(e.target.value)}
          placeholder="file:/etc/bvault/onedrive-refresh"
        />
        <p className="text-xs text-[var(--color-text-muted)] -mt-2">
          <code>file:</code> writes to disk (0600 perms on Unix).{" "}
          <code>keychain:</code> writes to the OS keychain
          (<code>{'<service>/<user>'}</code> label); requires a server build
          with the <code>cloud_keychain</code> feature. <code>env:</code> and{" "}
          <code>inline:</code> are read-only.
        </p>

        <div className="flex items-center gap-3">
          <Button onClick={connect} loading={busy}>
            {busy ? "Connecting…" : `Connect ${TARGET_LABELS[target]}`}
          </Button>
          {status && (
            <span className="text-sm text-[var(--color-text-muted)]">{status}</span>
          )}
        </div>
      </div>
    </Card>
  );
}
