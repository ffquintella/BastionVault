import { useEffect, useState } from "react";
import { Badge, Button, MaskedValue, Modal } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { formatDuration, secondsLeft, useNow } from "../lib/leases";
import { useLeaseStore } from "../stores/leaseStore";

/**
 * "Generate credential" for one role of a dynamic-secret mount (T62). The
 * credential lives in this component's state only: shown once, dropped on
 * close or when its lease runs out, never logged, cached or persisted. Only
 * the lease's metadata goes to the in-memory lease store.
 */
export function DynamicCredsModal({
  mount,
  role,
  onClose,
}: {
  mount: string;
  role: string;
  onClose: () => void;
}) {
  const recordLease = useLeaseStore((s) => s.record);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creds, setCreds] = useState<api.DynamicCredsResult | null>(null);
  const [deadline, setDeadline] = useState<number | null>(null);
  const [expired, setExpired] = useState(false);
  const now = useNow(1000);
  const left = deadline === null ? null : secondsLeft(deadline, now);

  // The credential is useless once its lease ends; do not keep it around.
  useEffect(() => {
    if (creds && left === 0) {
      setCreds(null);
      setExpired(true);
    }
  }, [creds, left]);

  function close() {
    setCreds(null);
    setDeadline(null);
    onClose();
  }

  async function generate() {
    setBusy(true);
    setError(null);
    setExpired(false);
    try {
      const result = await api.dynamicGenerateCreds(mount, role);
      const issuedAt = Date.now();
      setCreds(result);
      setDeadline(result.lease_duration !== null ? issuedAt + result.lease_duration * 1000 : null);
      if (result.lease_id) {
        recordLease({
          lease_id: result.lease_id,
          mount,
          role,
          since: issuedAt,
          lease_duration: result.lease_duration,
          renewable: result.renewable === true,
          shared: result.cache_hit,
        });
      }
    } catch (e) {
      setError(extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const fields = creds ? credentialFields(creds.data) : [];
  const credsPath = `${mount.replace(/\/+$/, "")}/creds/${role}`;

  return (
    <Modal
      open
      onClose={close}
      title={`Generate credential: ${role}`}
      size="md"
      actions={
        <>
          <Button variant="ghost" onClick={close}>
            Close
          </Button>
          {!creds && (
            <Button onClick={generate} loading={busy}>
              {expired ? "Generate another" : "Generate credential"}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-[var(--color-text-muted)] font-mono min-w-0 truncate" title={credsPath}>
          {credsPath}
        </p>
        <div className="rounded-md border border-[var(--color-warning)] bg-[var(--color-warning)]/10 p-3 text-xs">
          The credential is shown once. BastionVault keeps no copy you can read again: copy it
          now. It is cleared from this window when you close this dialog or its lease ends.
        </div>

        {error && (
          <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
        {expired && !creds && (
          <p className="text-sm text-[var(--color-text-muted)]" role="status">
            The lease ended; the credential was cleared from this window.
          </p>
        )}

        {creds && (
          <>
            {creds.cache_hit && (
              <div
                className="rounded-md border border-[var(--color-warning)] bg-[var(--color-warning)]/10 p-3 text-xs space-y-1"
                role="alert"
              >
                <p className="font-medium text-[var(--color-warning)]">Served from the credential cache</p>
                <p>
                  This is the credential an earlier request of your identity received, on a shared
                  lease. Renewing or revoking that lease affects every holder of this credential.
                </p>
              </div>
            )}
            <dl className="grid grid-cols-2 gap-3 text-sm">
              {fields.map(([key, value]) => (
                <div key={key} className="col-span-2 min-w-0">
                  <dt className="text-xs font-medium text-[var(--color-text-muted)] mb-1">{key}</dt>
                  <dd className="font-mono min-w-0">
                    <MaskedValue value={value} />
                  </dd>
                </div>
              ))}
            </dl>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="col-span-2 min-w-0 flex items-center gap-1">
                <span className="text-[var(--color-text-muted)] shrink-0">Lease</span>
                <span className="font-mono truncate min-w-0" title={creds.lease_id ?? ""}>
                  {creds.lease_id ?? "none returned"}
                </span>
              </div>
              <div data-testid="dynamic-creds-countdown">
                <span className="text-[var(--color-text-muted)]">Expires in </span>
                {left === null ? "unknown" : formatDuration(left)}
              </div>
              <div className="flex items-center gap-2 justify-end">
                <Badge
                  label={creds.renewable ? "renewable" : "not renewable"}
                  variant={creds.renewable ? "success" : "neutral"}
                />
                {creds.cache_hit && <Badge label="shared lease" variant="warning" />}
              </div>
            </div>
            {creds.warnings.length > 0 && (
              <ul className="text-xs text-[var(--color-text-muted)] list-disc pl-4 space-y-1">
                {creds.warnings.map((w) => (
                  <li key={w} className="break-words">{w}</li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

/** `username` and `password` first, then any plugin extras, as strings. */
function credentialFields(data: Record<string, unknown>): [string, string][] {
  const order = (k: string) => (k === "username" ? 0 : k === "password" ? 1 : 2);
  return Object.entries(data)
    .sort(([a], [b]) => order(a) - order(b) || a.localeCompare(b))
    .map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]);
}
