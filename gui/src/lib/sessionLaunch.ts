/**
 * The one place a connection profile is dispatched to a `session_open_*`
 * command.
 *
 * Every launcher (Connection tab, resource-card quick-Connect, ⌘K palette)
 * goes through here so the protocol switch exists once, and is strict:
 * an unknown protocol throws. The launchers used to branch with
 * `protocol === "ssh" ? openSsh : openRdp`, which would have opened any
 * third protocol as RDP. See features/web-application-connect.md §1,
 * "Strict parsing / old clients".
 */

import * as api from "./api";
import { parseSessionProtocol } from "./connectionProfiles";
import type { ConnectionProfile } from "./types";

export interface SessionLaunchRequest {
  resource_name: string;
  profile_id: string;
  operator_credential?: api.OperatorCredential;
  connect_ticket?: string;
  /** A `provider` profile: the account the operator picked in the
   *  host-rendered picker. Required for such a profile, refused for any
   *  other (see `lib/connectFlow.ts`). */
  provider_account_id?: string;
  /** SSH/RDP only: where the session renders (T38). Absent = the
   *  operator's default. A web session always opens its own window. */
  placement?: api.SessionPlacement;
  /** SSH/RDP only: set when re-opening a pane of a saved layout (T38
   *  Phase 5). Restoring goes through this same dispatch, so it gets the
   *  same open path as a Connect click. */
  restore?: api.SessionRestoreRef;
}

export async function openProfileSession(
  profile: Pick<ConnectionProfile, "protocol">,
  request: SessionLaunchRequest,
): Promise<void> {
  const protocol = parseSessionProtocol(profile.protocol);
  switch (protocol) {
    case "ssh":
      await api.sessionOpenSsh(request);
      return;
    case "rdp":
      await api.sessionOpenRdp(request);
      return;
    case "web":
      // No placement: a web session is never pooled into the workspace.
      // Never forward an operator credential: `open` releases none, and a
      // `form` login gets its credential from the server inside the host.
      await api.sessionOpenWeb({
        resource_name: request.resource_name,
        profile_id: request.profile_id,
        connect_ticket: request.connect_ticket,
        provider_account_id: request.provider_account_id,
      });
      return;
    case null:
      throw new Error(
        `Unknown connection protocol "${String(profile.protocol)}" — refusing to guess.`,
      );
  }
}
