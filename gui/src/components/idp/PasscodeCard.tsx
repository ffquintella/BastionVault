import { useState } from "react";
import { Button, Card, Input, Select } from "../ui";
import { OneTimeSecretModal, useOneTimeSecret } from "./OneTimeSecretModal";
import { environmentOptions } from "./IdpShared";
import { useAuthStore } from "../../stores/authStore";
import * as idp from "../../lib/idp";

/**
 * Self-service: mint a one-time passcode for the signed-in person's own
 * identity. The session token is used as is; a token with no entity (the
 * root token) is refused by the vault and the refusal is explained.
 */
export function PasscodeCard({ provider, environments }: { provider: "radius" | "ldap"; environments: string[] }) {
  const isRootToken = useAuthStore((s) => s.policies.includes("root"));
  const [environment, setEnvironment] = useState("");
  const [ttl, setTtl] = useState("");
  const [roles, setRoles] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const secret = useOneTimeSecret();
  const name = provider === "radius" ? "RADIUS" : "LDAP bind";

  async function mint() {
    setError(null);
    setBusy(true);
    try {
      const resp =
        provider === "radius"
          ? await idp.idpRadiusPasscode(environment, ttl, idp.splitList(roles))
          : await idp.idpLdapPasscode(environment, ttl);
      const d = resp.data;
      const details: [string, string][] = [
        ["Login", d.login],
        ["Environment", d.environment],
      ];
      if (d.bind_dn) details.push(["Bind DN", d.bind_dn]);
      if (d.roles && d.roles.length > 0) details.push(["Roles", d.roles.join(", ")]);
      details.push(["Expires", idp.formatTime(d.expires_at)]);
      secret.show({
        title: `${name} passcode`,
        label: "Passcode",
        value: d.passcode,
        details,
        notice:
          provider === "radius"
            ? "Type it as the password at the device. It works once, for this environment only, until it expires; the vault keeps only a hash."
            : "Bind with it once, as the bind DN below, before it expires; the vault keeps only a hash.",
      });
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title={`My ${name} passcode`}>
      <div className="grid grid-cols-2 gap-3">
        <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
          Mints a single-use passcode for your own workforce identity, if you are entitled to the environment.
        </p>
        {isRootToken && (
          <p className="col-span-2 text-xs text-[var(--color-warning)]" role="note">
            You are signed in with a root token, which is bound to no identity: the vault will refuse this.
          </p>
        )}
        <div className="col-span-2 sm:col-span-1">
          <Select
            label="Environment"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            options={environmentOptions(environments)}
          />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Input label="Lifetime (optional)" placeholder="2m" value={ttl} onChange={(e) => setTtl(e.target.value)} />
        </div>
        {provider === "radius" && (
          <div className="col-span-2">
            <Input
              label="Roles (optional)"
              placeholder="all entitled roles"
              value={roles}
              onChange={(e) => setRoles(e.target.value)}
            />
          </div>
        )}
        {error && (
          <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
        <div className="col-span-2 flex justify-end">
          <Button onClick={() => void mint()} loading={busy} disabled={!environment}>
            Mint passcode
          </Button>
        </div>
      </div>
      <OneTimeSecretModal secret={secret.secret} onClose={secret.clear} />
    </Card>
  );
}
