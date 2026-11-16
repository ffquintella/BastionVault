import { useEffect, useState } from "react";
import { Card } from "../ui";
import { CopyValue, Snippet } from "./IdpShared";
import * as idp from "../../lib/idp";

/**
 * The deny feed's verification key (Ed25519 + ML-DSA-65 composite), which
 * hosts pin. Only the public halves exist on this route; the signing key
 * never leaves the barrier.
 */
export function DenyFeedKeyCard() {
  const [key, setKey] = useState<idp.IdpDenyFeedKey | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    idp
      .idpReadDenyFeedKey()
      .then((r) => !cancelled && setKey(r.data))
      .catch((e) => !cancelled && setError(idp.describeIdpError(e)));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Card title="Deny feed verification key">
      {error && (
        <p className="text-sm text-[var(--color-danger)]" role="alert">
          {error}
        </p>
      )}
      {key && (
        <div className="space-y-2">
          <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
            <CopyValue label="key id" value={key.key_id} />
            <CopyValue label="algorithm" value={key.algorithm} />
            <CopyValue label="ed25519" value={key.ed25519} />
            <CopyValue label="ml-dsa-65" value={key.mldsa65} />
          </div>
          <Snippet title="/etc/bv-idp/feed-key.json (pin on every host)" text={JSON.stringify(key, null, 2)} />
        </div>
      )}
    </Card>
  );
}
