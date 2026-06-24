// Typed wrappers for the SSH login-broker policy.
// See features/ssh-resource-login-brokering.md.
//
// The four-tier policy (global / type / asset-group / resource) is
// managed via the `ssh-broker/policy/*` logical API + the
// `bvault ssh-broker policy` CLI; this module exposes the one piece the
// Connection-tab UI needs at render time: the *resolved* effective login
// class for a resource, which drives the brokered badge / resolution chip
// and gates the profile editor's credential-source choices.

import { invoke } from "@tauri-apps/api/core";
import type { EffectiveLoginClass } from "./types";

/**
 * Resolve the effective SSH login class for a resource (walks the four
 * tiers server-side). Defaults to `shared-credential` when the broker
 * policy is unset, so a deployment that never configures brokering reads
 * back as unrestricted.
 */
export async function resourceLoginClass(
  resourceName: string,
): Promise<EffectiveLoginClass> {
  const info = await invoke<{
    login_class: string;
    login_class_source: string;
    login_class_chain: string[];
    locked_at_tier: string | null;
  }>("resource_login_class", { request: { resource_name: resourceName } });
  return {
    login_class: info.login_class === "brokered" ? "brokered" : "shared-credential",
    login_class_source: info.login_class_source,
    login_class_chain: info.login_class_chain ?? [],
    locked_at_tier: info.locked_at_tier ?? null,
  };
}

/** Human-readable resolution chip text, e.g.
 *  "brokered ← resource-type (locked)". */
export function loginClassChipLabel(e: EffectiveLoginClass): string {
  const base = `${e.login_class} ← ${e.login_class_source}`;
  return e.locked_at_tier ? `${base} (locked)` : base;
}
