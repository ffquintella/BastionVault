import { useState } from "react";
import { Button, Input, Modal, SecretInput, Select } from "../ui";
import { TransportWarning, environmentOptions } from "./IdpShared";
import * as idp from "../../lib/idp";

/**
 * Register or update one NAS. Transport and environment are fixed at
 * creation. A UDP shared secret is write-only: the field starts empty and an
 * empty field keeps the stored one.
 */
export function RadiusClientModal({
  client,
  environments,
  profiles,
  onClose,
  onSaved,
}: {
  client: idp.IdpRadiusClient | null;
  environments: string[];
  profiles: { name: string; environment: string }[];
  onClose: () => void;
  onSaved: (resp: idp.IdpResponse<idp.IdpRadiusClient>, secretSent: string | null) => void;
}) {
  const creating = client === null;
  const [name, setName] = useState(client?.name ?? "");
  const [transport, setTransport] = useState<"radsec" | "udp">(client?.transport ?? "radsec");
  const [environment, setEnvironment] = useState(client?.environment ?? "");
  const [profile, setProfile] = useState(client?.profile ?? "");
  const [address, setAddress] = useState(client?.address ?? "");
  const [certSha256, setCertSha256] = useState(client?.cert_sha256 ?? "");
  const [secret, setSecret] = useState("");
  const [description, setDescription] = useState(client?.description ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const profileOptions = [
    { value: "", label: "Select a profile" },
    ...profiles.filter((p) => p.environment === environment).map((p) => ({ value: p.name, label: p.name })),
  ];

  async function save() {
    setError(null);
    const body: Record<string, unknown> = { profile, description: description.trim() };
    if (creating) {
      body.transport = transport;
      body.environment = environment;
    }
    if (transport === "udp") {
      body.address = address.trim();
      if (secret) body.secret = secret;
    } else {
      body.cert_sha256 = certSha256.trim().toLowerCase();
    }
    setBusy(true);
    try {
      const resp = await idp.idpWrite<idp.IdpRadiusClient>("radius_client", creating ? name.trim() : client.name, body);
      onSaved(resp, transport === "udp" && secret ? secret : null);
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
      title={creating ? "Register a NAS" : `NAS ${client.name}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => void save()} loading={busy}>
            {creating ? "Register" : "Save"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        {transport === "udp" && (
          <div className="col-span-2">
            <TransportWarning title="Classic UDP RADIUS">
              The password is protected only by an MD5 construction keyed by the shared secret. Use it on a trusted
              segment only; prefer RadSec.
            </TransportWarning>
          </div>
        )}
        <div className="col-span-2 sm:col-span-1">
          <Input label="Name" value={name} disabled={!creating} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select
            label="Transport"
            value={transport}
            disabled={!creating}
            onChange={(e) => setTransport(e.target.value as "radsec" | "udp")}
            options={[
              { value: "radsec", label: "RadSec (TLS, pinned certificate)" },
              { value: "udp", label: "UDP (shared secret)" },
            ]}
          />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select
            label="Environment"
            value={environment}
            disabled={!creating}
            onChange={(e) => {
              setEnvironment(e.target.value);
              setProfile("");
            }}
            options={environmentOptions(creating ? environments : [environment])}
          />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select label="Attribute profile" value={profile} onChange={(e) => setProfile(e.target.value)} options={profileOptions} />
        </div>
        {transport === "udp" ? (
          <>
            <div className="col-span-2 sm:col-span-1">
              <Input label="NAS source address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.20" />
            </div>
            <div className="col-span-2 sm:col-span-1">
              <SecretInput
                label="Shared secret"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                showGenerator
                onGenerate={setSecret}
                hint={client?.secret_set ? "A secret is set; leave empty to keep it. Write-only." : "16–128 printable characters. Write-only."}
              />
            </div>
          </>
        ) : (
          <div className="col-span-2">
            <Input
              label="NAS certificate SHA-256 (hex, DER)"
              value={certSha256}
              onChange={(e) => setCertSha256(e.target.value)}
              className="font-mono"
              hint="The certificate must also chain to the configured client CA."
            />
          </div>
        )}
        <div className="col-span-2">
          <Input label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {error && (
          <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
