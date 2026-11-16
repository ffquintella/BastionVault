import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, ConfirmModal, Input, Table, useToast } from "../ui";
import { CopyValue } from "./IdpShared";
import * as idp from "../../lib/idp";

const WHAT: Record<idp.IdpKeyRing, { title: string; signs: string; published: string }> = {
  oidc: { title: "OIDC signing keys (RS256)", signs: "ID tokens", published: "JWKS" },
  saml: { title: "SAML signing keys (RSA-SHA256)", signs: "assertions", published: "IdP metadata" },
};

/** A key ring's public keys, and rotation behind a confirmation. */
export function KeyRingCard({ ring }: { ring: idp.IdpKeyRing }) {
  const { toast } = useToast();
  const what = WHAT[ring];
  const [keys, setKeys] = useState<idp.IdpSigningKey[]>([]);
  const [overlap, setOverlap] = useState("24h");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setKeys((await idp.idpReadKeys(ring)).data?.keys ?? []);
      setError(null);
    } catch (e) {
      setError(idp.describeIdpError(e));
    }
  }, [ring]);

  useEffect(() => {
    void load();
  }, [load]);

  async function rotate() {
    setBusy(true);
    try {
      setKeys((await idp.idpRotateKeys(ring, overlap)).data?.keys ?? []);
      toast("success", `${ring.toUpperCase()} signing key rotated`);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  return (
    <Card
      title={what.title}
      actions={
        <div className="flex items-end gap-2">
          <Input aria-label="Overlap" value={overlap} onChange={(e) => setOverlap(e.target.value)} className="w-24" />
          <Button size="sm" variant="danger" onClick={() => setConfirming(true)}>
            Rotate key
          </Button>
        </div>
      }
    >
      {error && (
        <p className="text-sm text-[var(--color-danger)]" role="alert">
          {error}
        </p>
      )}
      <Table<idp.IdpSigningKey>
        tableClassName="table-fixed"
        data={keys}
        rowKey={(k) => k.kid}
        emptyMessage="No key yet: one is created on first use."
        columns={[
          { key: "kid", header: "kid", render: (k) => <CopyValue label="kid" value={k.kid} /> },
          {
            key: "state",
            header: "State",
            className: "w-48",
            render: (k) => (
              <div className="flex flex-wrap gap-1">
                {k.current && <Badge variant="success" label="current" />}
                {!k.current && <Badge variant="neutral" label="retired" />}
                {k.published && <Badge variant="info" label="published" />}
              </div>
            ),
          },
          {
            key: "until",
            header: "Published until",
            className: "w-48",
            render: (k) => <span className="text-xs">{k.current ? "—" : idp.formatTime(k.publish_until)}</span>,
          },
        ]}
      />
      <ConfirmModal
        open={confirming}
        onClose={() => setConfirming(false)}
        onConfirm={() => void rotate()}
        loading={busy}
        title={`Rotate the ${ring.toUpperCase()} signing key`}
        message={
          `A new RSA-3072 key becomes current and signs every ${what.signs} from now on. The current key stays ` +
          `in the ${what.published} for ${overlap || "24h"}; a relying party that caches it longer, or pins the ` +
          `certificate, rejects new ${what.signs} until it fetches the new key.`
        }
        confirmLabel="Rotate"
      />
    </Card>
  );
}
