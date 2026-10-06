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

/**
 * Mirror of the server's `static_ssh_credential_shape`
 * (`bv-engine-resource`): a secret is a static SSH credential iff it
 * carries a non-blank `private_key` or `password`. This is exactly what the
 * attach-time `409 brokered_resource_no_static_credential` guard refuses, so
 * the banner flags only what the server would have refused.
 */
export function isStaticSshCredential(data: Record<string, unknown>): boolean {
  const nonEmpty = (k: string) => {
    const v = data[k];
    return typeof v === "string" && v.trim() !== "";
  };
  return nonEmpty("private_key") || nonEmpty("password");
}

/** Upper bound on secrets inspected, so a resource with a huge secret list
 *  can't turn opening the Connection tab into a read storm. */
export const STATIC_CREDENTIAL_SCAN_LIMIT = 50;

/**
 * Names of the resource's secrets that are static SSH credentials. Only the
 * names leave this function — values are dropped as soon as the shape check
 * has run, and are never stored in component state.
 */
export async function findStaticSshSecrets(
  keys: string[],
  read: (key: string) => Promise<Record<string, unknown>>,
): Promise<string[]> {
  const found: string[] = [];
  for (const key of keys.slice(0, STATIC_CREDENTIAL_SCAN_LIMIT)) {
    try {
      if (isStaticSshCredential(await read(key))) found.push(key);
    } catch {
      // An unreadable secret can't be offered to the dialler either.
    }
  }
  return found;
}
