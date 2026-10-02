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
      // `open` mode releases no credential; never forward one.
      await api.sessionOpenWeb({
        resource_name: request.resource_name,
        profile_id: request.profile_id,
        connect_ticket: request.connect_ticket,
      });
      return;
    case null:
      throw new Error(
        `Unknown connection protocol "${String(profile.protocol)}" — refusing to guess.`,
      );
  }
}
