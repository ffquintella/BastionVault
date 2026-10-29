/**
 * Opening the SQL browser (features/sql-browser.md §10): from a resource's
 * Connect menu, its SQL profile row, or the ⌘K palette. One sequence for
 * all of them: the connect-time MFA gate for a named profile (the server
 * decides whether it needs a factor), then `sql_session_open`.
 */

import type { ConnectMfaOutcome } from "../components/ConnectMfaPrompt";
import { sqlSessionOpen, type SessionPlacement, type SqlOpenResponse } from "./api";
import { readUnknownProfiles } from "./connectionProfiles";
import { describeSqlError } from "./sqlWorkspace";
import { isSqlProfileEntry, readSqlProfile, sqlEngineOf } from "./sqlProfile";

export interface SqlLaunchProfile {
  id: string;
  name: string;
  requireMfa: boolean;
}

/** The resource's `sql` profiles the server would accept (an invalid one is
 *  never offered; the profile editor shows why). */
export function launchableSqlProfiles(meta: Record<string, unknown>): SqlLaunchProfile[] {
  const engine = sqlEngineOf(meta);
  if (!engine) return [];
  return readUnknownProfiles(meta)
    .filter(isSqlProfileEntry)
    .map((raw) => readSqlProfile(raw, engine.id))
    .filter((r) => r.problems.length === 0 && r.form.id !== "")
    .map((r) => ({ id: r.form.id, name: r.form.name || r.form.id, requireMfa: r.form.requireMfa }));
}

export type GateConnect = (resourceName: string, profileId: string, profileName: string) => Promise<ConnectMfaOutcome>;

/**
 * Open a SQL session. With a profile, the MFA gate runs first; without one
 * the plugin picks the smallest profile covering the caller's grant, and a
 * profile that needs a factor is refused there with a hint to pick it.
 * Returns null when the operator cancelled the factor prompt.
 */
export async function openSqlBrowser(
  gateConnect: GateConnect,
  resourceName: string,
  profile: SqlLaunchProfile | null,
  placement?: SessionPlacement,
): Promise<SqlOpenResponse | null> {
  let ticket: string | undefined;
  if (profile) {
    const mfa = await gateConnect(resourceName, profile.id, profile.name);
    if (!mfa) return null;
    ticket = mfa.connect_ticket;
  }
  try {
    return await sqlSessionOpen({
      resource_name: resourceName,
      ...(profile ? { profile_id: profile.id } : {}),
      ...(ticket ? { connect_ticket: ticket } : {}),
      ...(placement ? { placement } : {}),
    });
  } catch (e) {
    throw new Error(describeSqlError(e));
  }
}

/** The profile a one-click launch uses: the only one, else let the plugin choose. */
export function defaultSqlProfile(profiles: readonly SqlLaunchProfile[]): SqlLaunchProfile | null {
  return profiles.length === 1 ? profiles[0] : null;
}
