import { describe, expect, it } from "vitest";

import { groupPairingsByVault } from "./mcpVaults";
import type { McpPairing } from "./types";

const A = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0";
const B = "11111111-2222-4333-8444-555555555555";
const C = "22222222-2222-4333-8444-555555555555";

function pairing(id: string, vault_id: string | null | undefined): McpPairing {
  return {
    id,
    client_name: id,
    client_version: "1",
    transport: "stdio",
    peer_uid: null,
    tool_allowlist: [],
    path_scope: [],
    reveal_allowed: false,
    destructive_allowed: false,
    confirm_reveal: false,
    confirm_destructive: false,
    ttl_secs: 60,
    approved_at: 0,
    expires_at: null,
    last_used_at: 0,
    expired: false,
    vault_id,
  };
}

const ids = (g: { pairings: McpPairing[] }) => g.pairings.map((p) => p.id);

describe("groupPairingsByVault (T548)", () => {
  it("puts the active vault first, then other vaults by id, then the unassigned", () => {
    const groups = groupPairingsByVault(
      [pairing("c1", C), pairing("legacy", null), pairing("a1", A), pairing("b1", B), pairing("a2", A)],
      A,
    );
    expect(groups.map((g) => [g.kind, g.vaultId])).toEqual([
      ["active", A],
      ["vault", B],
      ["vault", C],
      ["unassigned", null],
    ]);
    expect(ids(groups[0])).toEqual(["a1", "a2"]);
    expect(ids(groups[3])).toEqual(["legacy"]);
  });

  it("never files an unassigned grant under the active vault", () => {
    const groups = groupPairingsByVault([pairing("old", undefined), pairing("empty", "")], A);
    expect(groups.map((g) => g.kind)).toEqual(["active", "unassigned"]);
    expect(groups[0].pairings).toEqual([]);
    expect(ids(groups[1])).toEqual(["old", "empty"]);
  });

  it("highlights nothing while the active vault is unknown", () => {
    const groups = groupPairingsByVault([pairing("a1", A), pairing("legacy", null)], null);
    expect(groups.map((g) => g.kind)).toEqual(["vault", "unassigned"]);
  });

  it("has no groups when nothing is paired", () => {
    expect(groupPairingsByVault([], A)).toEqual([]);
  });
});
