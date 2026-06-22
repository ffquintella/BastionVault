import { describe, it, expect } from "vitest";
import {
  parsePolicyHcl,
  serializePolicyModel,
  lintPolicyModel,
  previewCapability,
  CAPABILITIES,
  type PolicyModel,
} from "../lib/policyHcl";

// A corpus of realistic policies, including stand-ins for the built-in
// `administrator`, `default`, and `totp-admin` documents the spec calls
// out for round-trip coverage.
const CORPUS: Record<string, string> = {
  administrator: `
# Full access — every path, every capability.
path "*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
`,
  default: `
path "secret/data/*" {
    capabilities = ["read", "list"]
    scopes = ["owner", "shared"]
}
path "auth/token/lookup-self" {
    capabilities = ["read"]
}
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
`,
  "totp-admin": `
path "totp/keys/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "totp/code/+" {
    capabilities = ["read"]
}
`,
  "with-everything": `
name = "kitchen-sink"
metadata {
    group_shared_resources = "true"
}
path "secret/data/team/+/config" {
    capabilities = ["read", "update"]
    min_wrapping_ttl = "1h"
    max_wrapping_ttl = "24h"
    required_parameters = ["env"]
    allowed_parameters = {
        "env" = ["prod", "stage"]
    }
    denied_parameters = {
        "force" = []
    }
    groups = ["sre"]
}
path "secret/data/locked/*" {
    capabilities = ["deny"]
}
`,
};

describe("policyHcl — parse / serialize round-trip", () => {
  for (const [name, hcl] of Object.entries(CORPUS)) {
    it(`is round-trip stable for "${name}"`, () => {
      const first = parsePolicyHcl(hcl);
      expect(first.ok).toBe(true);
      const serialized = serializePolicyModel(first.model);
      const second = parsePolicyHcl(serialized);
      expect(second.ok).toBe(true);
      // Parsing the serialized form yields a semantically identical model.
      expect(second.model).toEqual(first.model);
    });
  }

  it("preserves all rule fields through a round-trip", () => {
    const { model } = parsePolicyHcl(CORPUS["with-everything"]);
    const b = model.blocks.find((x) => x.path === "secret/data/team/+/config")!;
    expect(b.capabilities).toEqual(["read", "update"]);
    expect(b.minWrappingTtl).toBe("1h");
    expect(b.maxWrappingTtl).toBe("24h");
    expect(b.requiredParameters).toEqual(["env"]);
    expect(b.allowedParameters).toEqual({ env: ["prod", "stage"] });
    expect(b.deniedParameters).toEqual({ force: [] });
    expect(b.groups).toEqual(["sre"]);
    expect(model.name).toBe("kitchen-sink");
    expect(model.metadata).toEqual({ group_shared_resources: "true" });
  });

  it("tolerates `#` and `//` comments", () => {
    const r = parsePolicyHcl(`
      # leading comment
      path "secret/*" { // trailing comment
        capabilities = ["read"]
      }
    `);
    expect(r.ok).toBe(true);
    expect(r.model.blocks).toHaveLength(1);
  });
});

describe("policyHcl — parse errors", () => {
  it("reports a syntax error without throwing", () => {
    const r = parsePolicyHcl(`path "x" { capabilities = [`);
    expect(r.ok).toBe(false);
    expect(r.errors.length).toBeGreaterThan(0);
  });

  it("rejects the forbidden `+*` wildcard combination", () => {
    const r = parsePolicyHcl(`path "secret/+*" { capabilities = ["read"] }`);
    expect(r.ok).toBe(false);
    expect(r.errors[0].message).toMatch(/\+\*/);
  });
});

describe("policyHcl — lint", () => {
  it("flags an unknown capability as an error", () => {
    const { model } = parsePolicyHcl(`path "x" { capabilities = ["reed"] }`);
    const findings = lintPolicyModel(model);
    expect(findings.some((f) => f.severity === "error" && /unknown capability/.test(f.message))).toBe(true);
  });

  it("warns on an empty capability list", () => {
    const { model } = parsePolicyHcl(`path "x" { capabilities = [] }`);
    const findings = lintPolicyModel(model);
    expect(findings.some((f) => f.severity === "warning" && /grants nothing/.test(f.message))).toBe(true);
  });

  it("warns when deny is combined with other capabilities", () => {
    const { model } = parsePolicyHcl(`path "x" { capabilities = ["deny", "read"] }`);
    const findings = lintPolicyModel(model);
    expect(findings.some((f) => /deny overrides/.test(f.message))).toBe(true);
  });

  it("warns on an overly broad `*` grant", () => {
    const { model } = parsePolicyHcl(`path "*" { capabilities = ["read"] }`);
    const findings = lintPolicyModel(model);
    expect(findings.some((f) => /every path/.test(f.message))).toBe(true);
  });

  it("flags an invalid TTL format", () => {
    const { model } = parsePolicyHcl(`path "x" { capabilities = ["read"] max_wrapping_ttl = "soon" }`);
    const findings = lintPolicyModel(model);
    expect(findings.some((f) => f.severity === "error" && /max_wrapping_ttl/.test(f.message))).toBe(true);
  });

  it("accepts valid TTL formats", () => {
    const { model } = parsePolicyHcl(`path "x" { capabilities = ["read"] min_wrapping_ttl = "1h" max_wrapping_ttl = "30m" }`);
    expect(lintPolicyModel(model).some((f) => /ttl/.test(f.message))).toBe(false);
  });
});

describe("policyHcl — preview matcher precedence", () => {
  const model: PolicyModel = parsePolicyHcl(`
    path "secret/data/exact" { capabilities = ["read"] }
    path "secret/data/team/*" { capabilities = ["read", "create"] }
    path "secret/data/team/+/config" { capabilities = ["update"] }
    path "secret/data/locked/*" { capabilities = ["deny"] }
  `).model;

  it("matches an exact rule", () => {
    const v = previewCapability(model, "secret/data/exact", "read");
    expect(v.allowed).toBe(true);
    expect(v.matchKind).toBe("exact");
    expect(v.matchedPath).toBe("secret/data/exact");
  });

  it("denies a capability the exact rule does not grant", () => {
    expect(previewCapability(model, "secret/data/exact", "delete").allowed).toBe(false);
  });

  it("matches a prefix rule", () => {
    const v = previewCapability(model, "secret/data/team/anything", "create");
    expect(v.allowed).toBe(true);
    expect(v.matchKind).toBe("prefix");
  });

  it("matches a segment-wildcard rule", () => {
    const v = previewCapability(model, "secret/data/team/alpha/config", "update");
    expect(v.allowed).toBe(true);
    expect(v.matchKind).toBe("segment_wildcard");
  });

  it("honors explicit deny", () => {
    const v = previewCapability(model, "secret/data/locked/thing", "read");
    expect(v.allowed).toBe(false);
    expect(v.deniedByDeny).toBe(true);
  });

  it("returns none when nothing matches", () => {
    const v = previewCapability(model, "nowhere", "read");
    expect(v.matchKind).toBe("none");
    expect(v.matchedPath).toBeNull();
  });

  it("marks every verdict as a non-authoritative preview", () => {
    expect(previewCapability(model, "secret/data/exact", "read").preview).toBe(true);
  });
});

describe("policyHcl — capability set", () => {
  it("matches the backend's ten capabilities", () => {
    expect([...CAPABILITIES].sort()).toEqual(
      ["connect", "create", "delete", "deny", "list", "patch", "read", "root", "sudo", "update"].sort(),
    );
  });
});
