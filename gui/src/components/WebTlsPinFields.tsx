/**
 * TLS certificate pins for a `web` connection profile
 * (features/web-application-connect.md §8, T96 Phase 4): the pin list and
 * the trust-on-first-use fingerprint helper.
 *
 * A pin is only consulted when the webview rejects a certificate (self-signed
 * or private-CA appliances) on one of the profile's https origins; it never
 * restricts a certificate the system already trusts. The helper shows what
 * answered from this machine and adds a pin only after the operator ticks
 * the confirmation.
 */

import { useState } from "react";
import { Button, Textarea } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { canonicalTlsPins, normalizeTlsPin } from "../lib/webTlsPin";
import type { WebProfileSettings } from "../lib/types";

function parseLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function formatDate(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000);
  return Number.isNaN(d.getTime()) ? "unknown" : d.toISOString().slice(0, 10);
}

type FetchState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "done"; result: api.WebTlsFingerprintResponse };

export function WebTlsPinFields({
  web,
  onChange,
}: {
  web: WebProfileSettings;
  /** The new list; `undefined` when it is empty. */
  onChange: (pins: string[] | undefined) => void;
}) {
  // The textarea keeps its own text so a trailing newline survives typing.
  const [text, setText] = useState(() => (web.tls_pin_sha256 ?? []).join("\n"));
  const [fetchState, setFetchState] = useState<FetchState>({ kind: "idle" });
  const [confirmed, setConfirmed] = useState(false);

  const pins = web.tls_pin_sha256 ?? [];
  const pinned = new Set(canonicalTlsPins(pins));
  const firstError = pins.map((p) => normalizeTlsPin(p)).find((r) => "error" in r);
  const startIsHttps = /^\s*https:\/\//i.test(web.start_url);

  function setPins(next: string[]) {
    setText(next.join("\n"));
    onChange(next.length > 0 ? next : undefined);
  }

  async function fetchFingerprint() {
    setConfirmed(false);
    setFetchState({ kind: "loading" });
    try {
      setFetchState({ kind: "done", result: await api.webTlsFingerprint(web.start_url.trim()) });
    } catch (e: unknown) {
      setFetchState({ kind: "error", message: extractError(e) });
    }
  }

  return (
    <div className="col-span-2 min-w-0 space-y-2">
      <Textarea
        label="TLS certificate pins (one per line)"
        value={text}
        rows={2}
        className="min-h-[64px]"
        onChange={(e) => {
          setText(e.target.value);
          const next = parseLines(e.target.value);
          onChange(next.length > 0 ? next : undefined);
        }}
        placeholder="sha256:3b4c…  or  sha256/O0Rk…="
        error={firstError && "error" in firstError ? firstError.error : undefined}
      />
      <p className="text-xs text-[var(--color-text-muted)]">
        Only for appliances whose certificate the session window rejects (self-signed, or issued by a private CA).
        Each pin is the SHA-256 of a certificate&rsquo;s public key (<code>sha256:&lt;hex&gt;</code>, or the{" "}
        <code>sha256/&lt;base64&gt;</code> form curl prints). A rejected certificate on this profile&rsquo;s https
        origins is accepted only when its key &mdash; or the key of a CA it presents and is valid under, for this
        host &mdash; is pinned; every other rejection stands. A certificate the system already trusts is used as
        before. There is no &ldquo;accept any certificate&rdquo; option.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={() => void fetchFingerprint()}
          disabled={!startIsHttps || fetchState.kind === "loading"}
          loading={fetchState.kind === "loading"}
        >
          Fetch certificate fingerprint (trust on first use)
        </Button>
        {!startIsHttps && (
          <span className="text-xs text-[var(--color-text-muted)]">Needs an https start URL.</span>
        )}
      </div>

      {fetchState.kind === "error" && (
        <p role="alert" className="text-xs text-[var(--color-danger)] min-w-0 break-words">
          {fetchState.message}
        </p>
      )}

      {fetchState.kind === "done" && (
        <div
          role="region"
          aria-label="Presented certificates"
          className="rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2 text-xs min-w-0 space-y-2"
        >
          <p className="font-medium">Trust on first use.</p>
          <p className="min-w-0 break-words">
            This is the certificate chain that answered at <span className="font-mono">{fetchState.result.origin}</span>{" "}
            from this computer just now. Anything on the network path could have answered instead. Before pinning,
            compare the fingerprint with the one the appliance shows on its console or in its certificate settings.
          </p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>I have checked this fingerprint against the appliance, or accept it on first use.</span>
          </label>
          <ul className="space-y-2">
            {fetchState.result.chain.map((c) => {
              const isLeaf = c.depth === 0;
              const already = pinned.has(c.pin);
              return (
                <li key={`${c.depth}-${c.pin}`} className="rounded border border-[var(--color-border)] p-2 min-w-0">
                  <p className="font-medium">
                    {isLeaf ? "Server certificate" : c.ca ? `Issuing CA (chain position ${c.depth})` : `Certificate ${c.depth}`}
                    {c.self_issued && " — self-signed"}
                  </p>
                  <p className="truncate" title={c.subject}>
                    Subject: {c.subject || "(empty)"}
                  </p>
                  <p className="truncate" title={c.issuer}>
                    Issuer: {c.issuer || "(empty)"}
                  </p>
                  <p>
                    Valid {formatDate(c.not_before)} to {formatDate(c.not_after)}
                  </p>
                  <p className="font-mono break-all" data-testid={`presented-pin-${c.depth}`}>
                    {c.pin}
                  </p>
                  <p className="font-mono break-all text-[var(--color-text-muted)]">sha256/{c.pin_base64}</p>
                  {!isLeaf && c.ca && (
                    <p className="text-[var(--color-text-muted)]">
                      Pinning the CA that issued the appliance&rsquo;s certificate (for example this vault&rsquo;s own
                      PKI engine) survives certificate renewal. The server must keep sending this CA certificate, and
                      its certificate must then be valid and name this host.
                    </p>
                  )}
                  <div className="mt-1">
                    <Button
                      type="button"
                      size="sm"
                      variant="secondary"
                      disabled={!confirmed || already}
                      onClick={() => setPins([...pins, c.pin])}
                    >
                      {already ? "Pinned" : isLeaf ? "Pin this certificate's key" : "Pin this CA's key"}
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
