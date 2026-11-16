import { useState } from "react";
import { Tabs } from "../ui";
import { IdpSshPanel } from "./IdpSshPanel";
import { IdpRadiusPanel } from "./IdpRadiusPanel";
import { IdpOidcPanel } from "./IdpOidcPanel";
import { IdpSamlPanel } from "./IdpSamlPanel";
import { IdpLdapPanel } from "./IdpLdapPanel";
import type { IdpDirectory } from "./directory";

const PROVIDERS = [
  { id: "ssh", label: "SSH" },
  { id: "radius", label: "RADIUS" },
  { id: "oidc", label: "OIDC" },
  { id: "saml", label: "SAML" },
  { id: "ldap", label: "LDAP" },
];

/** One sub-tab per downstream provider; each loads its own settings. */
export function IdpProvidersTab({ directory }: { directory: IdpDirectory }) {
  const [provider, setProvider] = useState("ssh");
  return (
    <div className="space-y-4">
      <Tabs tabs={PROVIDERS} active={provider} onChange={setProvider} />
      {provider === "ssh" && <IdpSshPanel directory={directory} />}
      {provider === "radius" && <IdpRadiusPanel directory={directory} />}
      {provider === "oidc" && <IdpOidcPanel directory={directory} />}
      {provider === "saml" && <IdpSamlPanel directory={directory} />}
      {provider === "ldap" && <IdpLdapPanel directory={directory} />}
    </div>
  );
}
