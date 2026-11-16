import { useState } from "react";
import { Button, ConfirmModal, Input, Modal, Select } from "../ui";
import * as idp from "../../lib/idp";

export interface EntitlementTarget {
  entity_id: string;
  login: string;
  environment: string;
  /** Roles the environment defines. */
  roles: string[];
  existing: idp.IdpEntitlement | null;
}

/** `datetime-local` value for an RFC 3339 instant, in the viewer's zone. */
function toLocalInput(rfc3339: string | null | undefined): string {
  if (!rfc3339) return "";
  const d = new Date(rfc3339);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Grant, replace or revoke one identity's entitlement to one environment. */
export function EntitlementModal({
  target,
  onClose,
  onChanged,
}: {
  target: EntitlementTarget;
  onClose: () => void;
  onChanged: (message: string) => void;
}) {
  const [roles, setRoles] = useState<string[]>(target.existing?.roles ?? []);
  const [notAfter, setNotAfter] = useState(toLocalInput(target.existing?.not_after));
  const [source, setSource] = useState<"manual" | "external">(
    target.existing?.source === "external" ? "external" : "manual",
  );
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = (role: string) =>
    setRoles((prev) => (prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]));

  async function save() {
    setError(null);
    if (roles.length === 0) {
      setError("Grant at least one role, or revoke the entitlement.");
      return;
    }
    const expiry = idp.localInputToRfc3339(notAfter);
    if (notAfter && !expiry) {
      setError("The expiry is not a valid date.");
      return;
    }
    setBusy(true);
    try {
      await idp.idpWriteEntitlement(target.entity_id, target.environment, { roles, not_after: expiry, source });
      onChanged(`${target.login} entitled to ${target.environment} as ${roles.join(", ")}`);
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    setBusy(true);
    try {
      await idp.idpRevokeEntitlement(target.entity_id, target.environment);
      setRevoking(false);
      onChanged(`Revoked ${target.login}'s entitlement to ${target.environment}`);
    } catch (e) {
      setRevoking(false);
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Modal
        open={!revoking}
        onClose={onClose}
        title={`${target.login} in ${target.environment}`}
        size="md"
        actions={
          <>
            {target.existing && (
              <Button variant="danger" onClick={() => setRevoking(true)}>
                Revoke
              </Button>
            )}
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={() => void save()} loading={busy}>
              {target.existing ? "Replace grant" : "Grant"}
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-3">
          <fieldset className="col-span-2 space-y-1">
            <legend className="text-sm font-medium text-[var(--color-text-muted)]">Roles</legend>
            {target.roles.length === 0 && (
              <p className="text-xs text-[var(--color-text-muted)]">This environment defines no roles yet.</p>
            )}
            <div className="flex flex-wrap gap-3">
              {target.roles.map((role) => (
                <label key={role} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={roles.includes(role)} onChange={() => toggle(role)} />
                  {role}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="col-span-2 sm:col-span-1">
            <Input
              label="Expires (optional)"
              type="datetime-local"
              value={notAfter}
              onChange={(e) => setNotAfter(e.target.value)}
              hint="Time-boxed access: the gate refuses issues after this instant."
            />
          </div>
          <div className="col-span-2 sm:col-span-1">
            <Select
              label="Source"
              value={source}
              onChange={(e) => setSource(e.target.value as "manual" | "external")}
              options={[
                { value: "manual", label: "manual" },
                { value: "external", label: "external" },
              ]}
            />
          </div>
          {target.existing && (
            <p className="col-span-2 text-xs text-[var(--color-text-muted)] min-w-0 truncate" title={target.existing.granted_by}>
              Granted {idp.formatTime(target.existing.granted_at)} by {target.existing.granted_by || "—"}
            </p>
          )}
          {error && (
            <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
              {error}
            </p>
          )}
        </div>
      </Modal>
      <ConfirmModal
        open={revoking}
        onClose={() => setRevoking(false)}
        onConfirm={() => void revoke()}
        loading={busy}
        title={`Revoke ${target.login} in ${target.environment}`}
        message={
          `Revoke ${target.login}'s entitlement to ${target.environment}? Every provider refuses new issues for ` +
          "it at once. SSH certificates already issued stay valid until they expire (at most the SSH max TTL); " +
          "disable the identity to revoke them now."
        }
        confirmLabel="Revoke entitlement"
      />
    </>
  );
}
