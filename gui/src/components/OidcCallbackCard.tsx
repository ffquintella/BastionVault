/**
 * Settings → General → SSO login callback.
 *
 * The GUI receives the identity provider's redirect on a loopback port.
 * Providers that pre-register redirect URIs need that port to be stable, so
 * the default is a fixed port (8473); up to three can be listed, tried in
 * order when one is busy, and `dynamic` lets the OS pick one per login for
 * providers that accept any loopback port. Every listed port must be
 * registered at the provider, and in the mount's `allowed_redirect_uris`.
 */

import { useEffect, useState } from "react";

import { Button, Card, Input, useToast } from "./ui";
import { getOidcCallbackPrefs, setOidcCallbackPrefs, type OidcCallbackPrefs } from "../lib/api";
import { extractError } from "../lib/error";

const MAX_PORTS = 3;

/** "8473, 8474" → [8473, 8474]; throws a message naming what is wrong. */
export function parsePorts(text: string): number[] {
  const parts = text
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) throw new Error("Enter at least one port.");
  if (parts.length > MAX_PORTS) throw new Error(`At most ${MAX_PORTS} ports.`);
  const ports = parts.map((p) => {
    if (!/^\d+$/.test(p)) throw new Error(`“${p}” is not a port number.`);
    const n = Number(p);
    if (n < 1024 || n > 65535) throw new Error(`Port ${n} is outside 1024–65535.`);
    return n;
  });
  const dup = ports.find((p, i) => ports.indexOf(p) !== i);
  if (dup !== undefined) throw new Error(`Port ${dup} is listed twice.`);
  return ports;
}

export function OidcCallbackCard() {
  const { toast } = useToast();
  const [prefs, setPrefs] = useState<OidcCallbackPrefs | null>(null);
  const [mode, setMode] = useState<"fixed" | "dynamic">("fixed");
  const [portsText, setPortsText] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getOidcCallbackPrefs()
      .then((p) => {
        setPrefs(p);
        setMode(p.mode);
        setPortsText(p.ports.join(", "));
      })
      .catch((e) => setLoadError(extractError(e)));
  }, []);

  async function save() {
    let ports: number[];
    try {
      ports = parsePorts(portsText);
    } catch (e) {
      toast("error", (e as Error).message);
      return;
    }
    setSaving(true);
    try {
      await setOidcCallbackPrefs({ mode, ports });
      setPrefs({ mode, ports });
      setPortsText(ports.join(", "));
      toast("success", "SSO callback saved. It applies to the next login.");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  const registered = (prefs?.ports ?? []).map((p) => `http://127.0.0.1:${p}/callback`);

  return (
    <Card title="SSO login callback">
      {loadError ? (
        <p className="text-sm text-[var(--color-danger)] break-words">{loadError}</p>
      ) : !prefs ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : (
        <fieldset className="space-y-3" disabled={saving}>
          <legend className="sr-only">SSO login callback</legend>
          <label className="flex items-start gap-3 cursor-pointer min-w-0">
            <input type="radio" name="oidc-callback-mode" checked={mode === "fixed"} onChange={() => setMode("fixed")} />
            <span className="min-w-0 text-sm">
              <span className="font-medium">Fixed port</span>
              <span className="block text-[var(--color-text-muted)]">
                Register the address(es) below at your identity provider. When a port is busy the next one is
                tried; if all are busy, login fails.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3 cursor-pointer min-w-0">
            <input type="radio" name="oidc-callback-mode" checked={mode === "dynamic"} onChange={() => setMode("dynamic")} />
            <span className="min-w-0 text-sm">
              <span className="font-medium">Dynamic port</span>
              <span className="block text-[var(--color-text-muted)]">
                The system picks a free port at every login. Only for providers that accept any port on
                127.0.0.1.
              </span>
            </span>
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Input
              label="Ports (1 to 3, comma separated)"
              value={portsText}
              disabled={mode === "dynamic"}
              onChange={(e) => setPortsText(e.target.value)}
            />
          </div>
          {mode === "fixed" && registered.length > 0 && (
            <div className="text-sm min-w-0">
              <p className="text-[var(--color-text-muted)]">Register at the provider and in allowed_redirect_uris:</p>
              <ul className="font-mono text-xs space-y-0.5">
                {registered.map((u) => (
                  <li key={u} className="truncate">
                    {u}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <Button onClick={() => void save()} loading={saving}>
            Save
          </Button>
        </fieldset>
      )}
    </Card>
  );
}
