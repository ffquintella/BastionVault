/**
 * Re-opening one pane of a saved Session Workspace layout (T38 Phase 5,
 * features/session-workspace.md §5).
 *
 * Restore resumes nothing. Each pane is opened exactly as a Connect click
 * opens it: the profile is re-read from the resource (so a deleted or
 * changed profile is noticed, not assumed), a credential-provider profile
 * asks the operator to pick an account again (`pickProviderAccount`), the
 * server decides whether a connect-time factor is needed (`gateConnect`),
 * and the open goes through the one launcher sequence, `connectProfile`, to
 * `session_open_*` — the connect gate, transport tier and MFA ticket check
 * all apply.
 *
 * The only additions are `placement: workspace-tab` and the `restore`
 * context: the host refuses the open before reading anything if the active
 * namespace is not the one the pane was saved in, and tags the session
 * with the placeholder it fills.
 */

import * as api from "./api";
import { connectProfile, type ConnectFlowDeps } from "./connectFlow";
import { needsOperatorPrompt, readProfiles } from "./connectionProfiles";
import type { PendingPane } from "./sessionLayout";

/** The connect-time MFA gate (`useConnectMfa().gateConnect`) and the
 *  provider account picker (`useProviderAccountPicker().pickProviderAccount`). */
export type ReopenDeps = ConnectFlowDeps;

/** Re-open one saved pane. Throws a reason an operator can act on. */
export async function reopenSavedPane(pane: PendingPane, deps: ReopenDeps): Promise<void> {
  const meta = await api.readResource(pane.resource_name);
  const profile = readProfiles(meta as unknown as Record<string, unknown>).find((p) => p.id === pane.profile_id);
  if (!profile) throw new Error(`profile \`${pane.profile_id}\` no longer exists on this resource`);
  if (profile.protocol !== pane.protocol) {
    throw new Error(`the profile is now a ${String(profile.protocol)} profile, not ${pane.protocol}`);
  }
  if (needsOperatorPrompt(profile)) {
    // Same hand-off as the ⌘K palette: a typed credential is prompted for
    // on the Resources page, not here.
    throw new Error("this profile needs a typed credential; open it from Resources");
  }
  const outcome = await connectProfile(deps, profile, {
    resource_name: pane.resource_name,
    profile_id: profile.id,
    placement: "workspace-tab",
    restore: { namespace: pane.namespace, pane_ref: pane.ref },
  });
  if (outcome === "cancelled") throw new Error("connect cancelled");
}
