import { describe, it, expect } from "vitest";
import { keyRefPolicy } from "../components/PkiKeyRefPicker";
import type { PkiManagedKey, PkiRoleConfig } from "../lib/types";

function key(key_id: string, name: string, key_type: string, key_bits: number): PkiManagedKey {
  return {
    key_id,
    name,
    key_type,
    key_bits,
    public_key: "",
    source: "generated",
    exported: false,
    created_at: 0,
    issuer_ref_count: 0,
    cert_ref_count: 0,
  };
}

function role(overrides: Partial<PkiRoleConfig>): PkiRoleConfig {
  return {
    key_type: "ec",
    key_bits: 0,
    allow_key_reuse: true,
    allowed_key_refs: [],
    ...overrides,
  } as PkiRoleConfig;
}

const keys = [
  key("id-ec256", "web-ec", "ec", 256),
  key("id-ec384", "web-ec384", "ec", 384),
  key("id-rsa", "web-rsa", "rsa", 2048),
  key("id-ed", "", "ed25519", 0),
];

describe("keyRefPolicy", () => {
  it("is unknown until the role is loaded", () => {
    expect(keyRefPolicy(null, keys).kind).toBe("unknown");
  });

  it("offers nothing when the role does not allow key reuse", () => {
    expect(keyRefPolicy(role({ allow_key_reuse: false }), keys).kind).toBe("reuse-disabled");
  });

  it("keeps only keys whose algorithm matches, treating bits=0 as the default size", () => {
    const p = keyRefPolicy(role({ key_type: "ec", key_bits: 0 }), keys);
    expect(p.kind === "ok" && p.compatible.map((k) => k.key_id)).toEqual(["id-ec256"]);
    expect(p.kind === "ok" && p.incompatible).toBe(3);

    const rsa = keyRefPolicy(role({ key_type: "rsa", key_bits: 2048 }), keys);
    expect(rsa.kind === "ok" && rsa.compatible.map((k) => k.key_id)).toEqual(["id-rsa"]);
  });

  it("honours allowed_key_refs by id or name", () => {
    const byName = keyRefPolicy(role({ key_type: "ec", key_bits: 384, allowed_key_refs: ["web-ec384"] }), keys);
    expect(byName.kind === "ok" && byName.compatible.map((k) => k.key_id)).toEqual(["id-ec384"]);

    const miss = keyRefPolicy(role({ allowed_key_refs: ["something-else"] }), keys);
    expect(miss.kind === "ok" && miss.compatible).toEqual([]);

    const byId = keyRefPolicy(role({ key_type: "ed25519", allowed_key_refs: ["id-ed"] }), keys);
    expect(byId.kind === "ok" && byId.compatible.map((k) => k.key_id)).toEqual(["id-ed"]);
  });
});
