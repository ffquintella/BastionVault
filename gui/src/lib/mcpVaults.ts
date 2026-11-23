/**
 * How the AI Assistants page groups pairings by the vault they were approved
 * for (T548, features/mcp-access.md §3). The store is per workstation user, so
 * it can hold grants for several vaults; each is used only with its own, and a
 * grant from before vault binding is used with none.
 */
import type { McpPairing } from "./types";

/**
 * `active`: the vault this window is signed in to. `vault`: any other (or any,
 * while the active one is unknown). `unassigned`: approved before binding.
 */
export type PairingGroupKind = "active" | "vault" | "unassigned";

export interface PairingGroup {
  kind: PairingGroupKind;
  /** The vault's identity; `null` for the unassigned group. */
  vaultId: string | null;
  pairings: McpPairing[];
}

/**
 * The active vault's group first (present, possibly empty, whenever the active
 * vault is known and anything is paired), then every other vault by id, then
 * the unassigned grants. Never moves a pairing between groups by guessing: an
 * unassigned one stays unassigned until the operator re-binds it.
 */
export function groupPairingsByVault(pairings: readonly McpPairing[], activeVaultId: string | null): PairingGroup[] {
  if (pairings.length === 0) return [];
  const byVault = new Map<string, McpPairing[]>();
  const unassigned: McpPairing[] = [];
  for (const p of pairings) {
    const vault = typeof p.vault_id === "string" && p.vault_id !== "" ? p.vault_id : null;
    if (vault === null) {
      unassigned.push(p);
    } else {
      byVault.set(vault, [...(byVault.get(vault) ?? []), p]);
    }
  }
  const groups: PairingGroup[] = [];
  if (activeVaultId) {
    groups.push({ kind: "active", vaultId: activeVaultId, pairings: byVault.get(activeVaultId) ?? [] });
    byVault.delete(activeVaultId);
  }
  for (const vaultId of Array.from(byVault.keys()).sort()) {
    groups.push({ kind: "vault", vaultId, pairings: byVault.get(vaultId) ?? [] });
  }
  if (unassigned.length > 0) groups.push({ kind: "unassigned", vaultId: null, pairings: unassigned });
  return groups;
}
