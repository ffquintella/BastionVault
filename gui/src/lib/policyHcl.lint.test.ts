import { describe, expect, it } from "vitest";
import { lintPolicyModel, parsePolicyHcl } from "./policyHcl";

/**
 * A rule authored inside a namespace without that namespace's prefix is dead:
 * `rewrite_request_for_namespace` turns `secret/data/x` into
 * `<ns>/secret/data/x` before the ACL ever sees it, so the bare rule matches
 * nothing. That shape used to lint clean — "No lint findings — the policy
 * looks well-formed" — for a policy whose every rule was unreachable.
 */
describe("lintPolicyModel: unreachable namespace rules", () => {
  function lint(hcl: string, ns: string) {
    const parsed = parsePolicyHcl(hcl);
    expect(parsed.ok).toBe(true);
    return lintPolicyModel(parsed.model, ns);
  }

  it("flags a rule missing the enclosing namespace prefix", () => {
    const findings = lint(`path "secret/data/docker/hub" { capabilities = ["read"] }`, "dti/esi");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("error");
    expect(findings[0].message).toContain("unreachable");
    expect(findings[0].message).toContain("dti/esi/secret/data/docker/hub");
  });

  it("accepts a correctly prefixed rule", () => {
    const findings = lint(`path "dti/esi/secret/data/docker/*" { capabilities = ["read"] }`, "dti/esi");
    expect(findings).toHaveLength(0);
  });

  it("flags a rule prefixed with a different namespace", () => {
    const findings = lint(`path "dti/other/secret/data/x" { capabilities = ["read"] }`, "dti/esi");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("error");
  });

  it("leaves header-scoped mounts alone — the router never rewrites them", () => {
    const hcl = `
path "sys/capabilities-self"   { capabilities = ["update"] }
path "auth/token/lookup-self"  { capabilities = ["read"] }
path "identity/entity/self"    { capabilities = ["read"] }
path "rustion/policy/effective"{ capabilities = ["update"] }
path "notifications/inbox"     { capabilities = ["read"] }
`;
    expect(lint(hcl, "dti/esi")).toHaveLength(0);
  });

  it("says nothing at root, where no prefix is in play", () => {
    expect(lint(`path "secret/data/docker/hub" { capabilities = ["read"] }`, "")).toHaveLength(0);
  });

  it("flags every unreachable rule in the policy from the incident", () => {
    // The shipped policy, written mount-relative: what an operator produces
    // when they copy a path out of a client instead of the Secrets page.
    const hcl = `
path "secret/data/github/*"     { capabilities = ["read"] }
path "secret/data/docker/*"     { capabilities = ["read"] }
path "secret/data/docker/hub/*" { capabilities = ["read"] }
`;
    const findings = lint(hcl, "dti/esi");
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.severity === "error")).toBe(true);
  });
});
