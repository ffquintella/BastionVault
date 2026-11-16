import { useEffect, useState } from "react";
import { Button, Input, Modal } from "../ui";
import * as idp from "../../lib/idp";

export interface StateChange {
  entity_id: string;
  login: string;
  uid: number;
  to: idp.IdpIdentityState;
}

function consequence(c: StateChange): { title: string; message: string; confirm: string } {
  switch (c.to) {
    case "disabled":
      return {
        title: `Disable ${c.login}`,
        message:
          `Disable ${c.login} (uid ${c.uid})? Every outstanding SSH certificate of this identity is marked ` +
          "revoked and listed in the KRL and the deny feed, and SSH, RADIUS, SAML, OIDC and LDAP refuse it " +
          "until it is reinstated.",
        confirm: "Disable",
      };
    case "active":
      return {
        title: `Reinstate ${c.login}`,
        message:
          `Reinstate ${c.login} (uid ${c.uid})? Credentials can be issued again; certificates issued before ` +
          "the disable stay revoked.",
        confirm: "Reinstate",
      };
    case "removed":
      return {
        title: `Remove ${c.login} permanently`,
        message:
          `Removal is permanent. uid ${c.uid} and its primary gid are retired and the login "${c.login}" stays ` +
          "reserved: none is ever reused, and the identity can never be reinstated. Its certificates are revoked.",
        confirm: "Remove permanently",
      };
  }
}

/**
 * Confirmation for a lifecycle change. It names the identity and what the
 * change does; removal also requires typing the login, as other permanent
 * deletions in the app do.
 */
export function IdentityStateModal({
  change,
  onClose,
  onDone,
}: {
  change: StateChange | null;
  onClose: () => void;
  onDone: (result: idp.IdpResponse<idp.IdpIdentity>) => void;
}) {
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setReason("");
    setTyped("");
    setError(null);
  }, [change]);

  if (!change) return null;
  const text = consequence(change);
  const needsPhrase = change.to === "removed";
  const unlocked = !needsPhrase || typed === change.login;

  async function confirm() {
    if (!change || !unlocked) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await idp.idpSetIdentityState(change.entity_id, change.to, reason));
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={text.title}
      size="md"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={change.to === "active" ? "primary" : "danger"}
            onClick={() => void confirm()}
            loading={busy}
            disabled={!unlocked}
          >
            {text.confirm}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-[var(--color-text-muted)]">{text.message}</p>
        <Input
          label="Reason (optional, recorded on the identity)"
          value={reason}
          maxLength={256}
          onChange={(e) => setReason(e.target.value)}
        />
        {needsPhrase && (
          <Input
            label={`Type "${change.login}" to confirm`}
            value={typed}
            placeholder={change.login}
            onChange={(e) => setTyped(e.target.value)}
          />
        )}
        {error && (
          <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
