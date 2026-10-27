import { useCallback, useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Badge, Button, Card, ConfirmModal, Input, Table, useToast } from "../components/ui";
import * as api from "../lib/api";
import type { RevokeFailedLease } from "../lib/api";
import { extractError, isPermissionDenied } from "../lib/error";
import { formatDuration, parseTime, secondsLeft, useNow } from "../lib/leases";
import { useLeaseStore, type IssuedLease } from "../stores/leaseStore";

const RENEW_MAY_BE_REFUSED =
  "Renew may be refused: the host renews only leases whose backend really renews them, never past their max TTL.";

/**
 * Leases (T62, features/dynamic-secrets.md Phase 5, docs/api.md § Leases).
 * The host lists only leases whose revoke failed; it has no listing of live
 * leases, so the live ones shown are those this window issued, plus renew /
 * revoke by lease id. Lease data (the credentials) is never read or shown.
 */
export function LeasesPage() {
  const { toast } = useToast();
  const now = useNow(1000);
  const issued = useLeaseStore((s) => s.issued);
  const forget = useLeaseStore((s) => s.forget);
  const renewedInStore = useLeaseStore((s) => s.renewed);

  const [failed, setFailed] = useState<RevokeFailedLease[] | null>(null);
  const [failedError, setFailedError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [clearing, setClearing] = useState<RevokeFailedLease | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [lookupId, setLookupId] = useState("");
  const [lookupIncrement, setLookupIncrement] = useState("");

  const refresh = useCallback(async () => {
    setFailedError(null);
    try {
      setFailed(await api.leasesListRevokeFailed());
    } catch (e) {
      setFailed([]);
      setFailedError(
        isPermissionDenied(e)
          ? "Listing leases whose revoke failed needs sudo: `list` with `sudo` on sys/leases/revoke-failed. Your token does not have it."
          : extractError(e),
      );
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** A refusal stays on the page; a 403 says which capability is missing. */
  function report(e: unknown, what: string, needs: string) {
    const message = isPermissionDenied(e)
      ? `${what} was refused: it needs ${needs}, which your token does not have.`
      : `${what} failed: ${extractError(e)}`;
    setActionError(message);
    toast("error", message);
  }

  async function renew(leaseId: string, increment?: number) {
    setBusy(leaseId);
    setActionError(null);
    try {
      const r = await api.leasesRenew(leaseId, increment);
      renewedInStore(leaseId, r.lease_duration, r.renewable);
      toast(
        "success",
        r.lease_duration === null
          ? "Lease renewed (the server did not report the new TTL)."
          : `Lease renewed for ${formatDuration(r.lease_duration)}.`,
      );
    } catch (e) {
      report(e, "Renew", "`update` on sys/renew/<lease id>");
    } finally {
      setBusy(null);
    }
  }

  async function revoke(leaseId: string) {
    setBusy(leaseId);
    setActionError(null);
    try {
      await api.leasesRevoke(leaseId);
      forget(leaseId);
      toast("success", "Lease revoked.");
    } catch (e) {
      report(e, "Revoke", "`update` on sys/revoke/<lease id>");
    } finally {
      setBusy(null);
      setRevoking(null);
      void refresh();
    }
  }

  async function forceClear() {
    if (!clearing) return;
    const leaseId = clearing.lease_id;
    setBusy(leaseId);
    setActionError(null);
    try {
      await api.leasesForceClearRevokeFailed(leaseId);
      forget(leaseId);
      toast("success", "Lease record cleared.");
    } catch (e) {
      report(e, "Force-clear", "`delete` with `sudo` on sys/leases/revoke-failed/<lease id>");
    } finally {
      setBusy(null);
      setClearing(null);
      void refresh();
    }
  }

  const lookupIncrementSecs = lookupIncrement.trim() === "" ? undefined : Number(lookupIncrement);
  const lookupValid =
    lookupId.trim() !== "" &&
    (lookupIncrementSecs === undefined || (Number.isInteger(lookupIncrementSecs) && lookupIncrementSecs >= 0));

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-2xl font-bold">Leases</h1>
          <Button variant="secondary" onClick={() => void refresh()}>
            Refresh
          </Button>
        </div>
        <p className="text-sm text-[var(--color-text-muted)]">
          The server lists only the leases it failed to revoke. Live leases appear here when this
          window issued them; renew or revoke any other lease by its id. Credentials are never shown.
        </p>
        {actionError && (
          <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
            {actionError}
          </p>
        )}

        <Card title="Revoke failed">
          {failed === null ? (
            <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
          ) : failedError ? (
            <p className="text-sm text-[var(--color-danger)] break-words" data-testid="revoke-failed-error">
              {failedError}
            </p>
          ) : (
            <Table
              tableClassName="table-fixed"
              data={failed}
              rowKey={(l) => l.lease_id}
              emptyMessage="No lease is waiting on a failed revoke."
              columns={[
                {
                  key: "lease",
                  header: "Lease",
                  className: "w-1/4",
                  render: (l) => (
                    <div className="min-w-0">
                      <div className="font-mono text-xs truncate" title={l.lease_id}>{l.lease_id}</div>
                      <div className="text-xs text-[var(--color-text-muted)] truncate" title={l.origin}>
                        origin: {l.origin || "unknown"}
                      </div>
                    </div>
                  ),
                },
                {
                  key: "attempts",
                  header: "Attempts",
                  className: "w-24",
                  render: (l) => (
                    <div className="flex flex-col gap-1 items-start">
                      <span>{`${l.attempts} / ${l.max_attempts}`}</span>
                      {l.exhausted && <Badge label="exhausted" variant="error" />}
                    </div>
                  ),
                },
                {
                  key: "error",
                  header: "Last error",
                  render: (l) => (
                    <div className="text-xs truncate min-w-0" title={l.last_error}>{l.last_error || "—"}</div>
                  ),
                },
                {
                  key: "next",
                  header: "Next retry",
                  className: "w-28",
                  render: (l) => <span className="text-xs">{nextRetry(l, now)}</span>,
                },
                {
                  key: "ttl",
                  header: "Lease TTL",
                  className: "w-28",
                  render: (l) => <span className="text-xs">{countdown(parseTime(l.expire_time), now)}</span>,
                },
                {
                  key: "actions",
                  header: "",
                  className: "w-52",
                  render: (l) => (
                    <div className="flex gap-1 justify-end flex-wrap">
                      <Button
                        size="sm"
                        variant="secondary"
                        loading={busy === l.lease_id}
                        onClick={() => void revoke(l.lease_id)}
                        title="Ask the backend to revoke it again now"
                      >
                        Retry revoke
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => setClearing(l)}>
                        Force-clear
                      </Button>
                    </div>
                  ),
                },
              ]}
            />
          )}
        </Card>

        <Card title="Issued in this window">
          <Table
            tableClassName="table-fixed"
            data={issued}
            rowKey={(l) => l.lease_id}
            emptyMessage="No lease issued from this window yet. Generate a credential under Secrets → Dynamic."
            columns={[
              {
                key: "lease",
                header: "Lease",
                className: "w-1/3",
                render: (l) => (
                  <div className="font-mono text-xs truncate min-w-0" title={l.lease_id}>{l.lease_id}</div>
                ),
              },
              {
                key: "role",
                header: "Mount / role",
                render: (l) => (
                  <div className="text-xs truncate min-w-0" title={`${l.mount} ${l.role}`}>
                    {l.mount} · {l.role}
                  </div>
                ),
              },
              {
                key: "ttl",
                header: "TTL",
                className: "w-28",
                render: (l) => <span className="text-xs">{issuedCountdown(l, now)}</span>,
              },
              {
                key: "flags",
                header: "",
                className: "w-36",
                render: (l) => (
                  <div className="flex gap-1 flex-wrap">
                    <Badge label={l.renewable ? "renewable" : "not renewable"} variant={l.renewable ? "success" : "neutral"} />
                    {l.shared && <Badge label="shared" variant="warning" />}
                  </div>
                ),
              },
              {
                key: "actions",
                header: "",
                className: "w-44",
                render: (l) => (
                  <div className="flex gap-1 justify-end">
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={!l.renewable}
                      loading={busy === l.lease_id}
                      title={l.renewable ? RENEW_MAY_BE_REFUSED : "This lease was issued non-renewable."}
                      onClick={() => void renew(l.lease_id)}
                    >
                      Renew
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => setRevoking(l.lease_id)}>
                      Revoke
                    </Button>
                  </div>
                ),
              },
            ]}
          />
          {issued.some((l) => l.renewable) && (
            <p className="text-xs text-[var(--color-text-muted)] mt-2">{RENEW_MAY_BE_REFUSED}</p>
          )}
        </Card>

        <Card title="Renew or revoke by lease id">
          <form
            className="grid grid-cols-2 gap-3"
            onSubmit={(e) => {
              e.preventDefault();
            }}
          >
            <div className="col-span-2">
              <Input
                label="Lease id"
                value={lookupId}
                onChange={(e) => setLookupId(e.target.value)}
                placeholder="database/creds/readonly/0f3c…"
              />
            </div>
            <Input
              label="Renew increment (seconds, optional)"
              value={lookupIncrement}
              onChange={(e) => setLookupIncrement(e.target.value)}
              placeholder="the backend's TTL"
              inputMode="numeric"
            />
            <div className="flex items-end gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={!lookupValid}
                loading={busy === lookupId.trim()}
                onClick={() => void renew(lookupId.trim(), lookupIncrementSecs)}
              >
                Renew
              </Button>
              <Button
                type="button"
                variant="danger"
                disabled={lookupId.trim() === ""}
                onClick={() => setRevoking(lookupId.trim())}
              >
                Revoke
              </Button>
            </div>
            <p className="col-span-2 text-xs text-[var(--color-text-muted)]">{RENEW_MAY_BE_REFUSED}</p>
          </form>
        </Card>
      </div>

      <ConfirmModal
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && void revoke(revoking)}
        title="Revoke lease"
        message={`Revoke ${revoking ?? ""}? Its backend removes the credential now. If the backend fails, the lease is kept as revoke_failed and retried.`}
        confirmLabel="Revoke"
        loading={revoking !== null && busy === revoking}
      />

      <ConfirmModal
        open={clearing !== null}
        onClose={() => setClearing(null)}
        onConfirm={() => void forceClear()}
        title="Force-clear a revoke-failed lease"
        message={`Force-clear drops the record of ${clearing?.lease_id ?? ""} WITHOUT revoking its credential. Use it only after you removed that credential from the target system by hand: otherwise it stays live and nothing will revoke it. Needs sudo. The clear is audited.`}
        confirmLabel="Force-clear"
        confirmPhrase="force-clear"
        loading={clearing !== null && busy === clearing.lease_id}
      />
    </Layout>
  );
}

function countdown(deadline: number | null, now: number): string {
  if (deadline === null) return "unknown";
  const left = secondsLeft(deadline, now);
  return left === 0 ? "expired" : formatDuration(left);
}

function issuedCountdown(lease: IssuedLease, now: number): string {
  if (lease.lease_duration === null) return "not reported";
  return countdown(lease.since + lease.lease_duration * 1000, now);
}

function nextRetry(lease: RevokeFailedLease, now: number): string {
  if (lease.exhausted) return "none (exhausted)";
  const at = parseTime(lease.next_attempt_at);
  if (at === null) return "unknown";
  const left = secondsLeft(at, now);
  return left === 0 ? "due" : `in ${formatDuration(left)}`;
}
