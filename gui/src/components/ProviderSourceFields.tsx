/**
 * The connection-profile editor's `provider` credential source
 * (features/self-accounts.md §6, T103 Phase 4): which providers the source
 * select offers, and what the editor says about the one chosen.
 *
 * Only providers the server reports as approved and active
 * (`connect_credential_providers`) are offered, and only for protocols they
 * declare. A profile that already names a provider this server does not
 * offer keeps it — the select shows it as unavailable instead of silently
 * switching the profile to another source.
 */

import type { CredentialProviderInfo } from "../lib/api";
import { providerOptionValue, providersForProtocol } from "../lib/credentialProviders";
import { providerMfaHint } from "../lib/connectionProfiles";
import type { ConnectionProfile, CredentialSource, SessionProtocol } from "../lib/types";

/** The `<select>` options for the providers that can serve `protocol`, plus
 *  the profile's current provider when this server does not offer it. */
export function providerSourceOptions(
  providers: CredentialProviderInfo[],
  protocol: SessionProtocol,
  current: CredentialSource,
): { value: string; label: string }[] {
  const offered = providersForProtocol(providers, protocol);
  const options = offered.map((p) => ({
    value: providerOptionValue(p.name),
    label: `${p.display_name} (pick at connect)`,
  }));
  if (current.kind === "provider" && current.provider && !offered.some((p) => p.name === current.provider)) {
    options.push({ value: providerOptionValue(current.provider), label: `${current.provider} (not available here)` });
  }
  return options;
}

/** The select value of a credential source: the kind, or `provider:<name>`. */
export function credentialSourceSelectValue(cs: CredentialSource): string {
  return cs.kind === "provider" ? providerOptionValue(cs.provider) : cs.kind;
}

export function ProviderSourceNotice({
  profile,
  providers,
  loaded,
  error,
}: {
  profile: ConnectionProfile;
  providers: CredentialProviderInfo[];
  loaded: boolean;
  error: string | null;
}) {
  const cs = profile.credential_source;
  if (cs.kind !== "provider") return null;
  const offered = providersForProtocol(providers, profile.protocol).find((p) => p.name === cs.provider);
  const mfaHint = providerMfaHint(profile);
  return (
    <div className="space-y-2 min-w-0">
      <p className="text-xs text-[var(--color-text-muted)]">
        At Connect, the operator picks one of <em>their own</em>{" "}
        {offered ? offered.display_name : "credential-provider"} accounts that match this resource,
        protocol and target. The server releases it only for that connect: to this computer for a
        direct session, sealed for the bastion on a Rustion route, or into the sign-in of a web form
        login. The login name comes from the account; this profile carries no username or secret.
      </p>
      {loaded && !offered && (
        <p className="text-xs text-[var(--color-danger)] break-words" role="alert">
          {error
            ? `The approved credential providers could not be read (${error}).`
            : `“${cs.provider || "(none)"}” is not an approved credential provider for ${profile.protocol.toUpperCase()} on this server.`}{" "}
          Connects with this profile are refused until an administrator approves it under Plugins.
        </p>
      )}
      {mfaHint && (
        <p
          className="rounded-md border border-[var(--color-warning-border,var(--color-border))] bg-[var(--color-warning-bg,transparent)] p-2 text-xs"
          role="note"
        >
          {mfaHint}
        </p>
      )}
    </div>
  );
}
