/**
 * The Connect sequence every launcher runs once a profile is chosen
 * (features/self-accounts.md §6 steps 2–5, features/connect-mfa-and-fido2-ssh.md).
 *
 *   1. a `provider` profile: the host-rendered account picker
 *      (`useProviderAccountPicker`) — cancelling here ends the connect and
 *      costs no factor ceremony;
 *   2. the connect-time MFA gate (`useConnectMfa().gateConnect`), which the
 *      server decides — `{}` for an ungated profile;
 *   3. `session_open_*` through the one dispatch (`openProfileSession`),
 *      carrying the ticket and the picked `provider_account_id`.
 *
 * The Connection tab, the resource-card quick-Connect, the ⌘K palette and a
 * Session Workspace layout restore all go through here, so the order cannot
 * differ between them.
 */

import type { ConnectMfaOutcome } from "../components/ConnectMfaPrompt";
import { describeProviderError } from "./credentialProviders";
import { openProfileSession, type SessionLaunchRequest } from "./sessionLaunch";
import type { ConnectionProfile } from "./types";

export interface ConnectFlowDeps {
  /** The provider account picker; the picked account id, or null when the
   *  operator cancelled. Throws (operator text) when the list is refused. */
  pickProviderAccount: (resourceName: string, profile: ConnectionProfile) => Promise<string | null>;
  /** The connect-time MFA gate; null when the operator cancelled. */
  gateConnect: (resourceName: string, profileId: string, profileName: string) => Promise<ConnectMfaOutcome>;
}

/** `cancelled` is not an error: the operator closed the picker or the MFA
 *  prompt, and the launcher should simply stop. */
export type ConnectFlowOutcome = "opened" | "cancelled";

/** What the launcher supplies; the flow adds the ticket and the account. */
export type ConnectFlowRequest = Omit<SessionLaunchRequest, "connect_ticket" | "provider_account_id">;

export async function connectProfile(
  deps: ConnectFlowDeps,
  profile: ConnectionProfile,
  request: ConnectFlowRequest,
): Promise<ConnectFlowOutcome> {
  const isProvider = profile.credential_source.kind === "provider";
  let providerAccountId: string | undefined;
  if (isProvider) {
    const picked = await deps.pickProviderAccount(request.resource_name, profile);
    if (picked === null) return "cancelled";
    providerAccountId = picked;
  }
  const mfa = await deps.gateConnect(request.resource_name, profile.id, profile.name);
  if (!mfa) return "cancelled";
  try {
    await openProfileSession(profile, {
      ...request,
      ...mfa,
      ...(providerAccountId !== undefined ? { provider_account_id: providerAccountId } : {}),
    });
  } catch (e) {
    // The server's provider refusals carry a stable `<reason>: ` code; say
    // what it means. Any other error passes through unchanged.
    if (isProvider) throw new Error(describeProviderError(e));
    throw e;
  }
  return "opened";
}
