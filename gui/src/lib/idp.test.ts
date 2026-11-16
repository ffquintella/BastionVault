/**
 * Request shapes of the Identity Provider wrappers (T52 Phase 7): the
 * command name and the exact arguments each sends to the Tauri layer, and
 * the helpers that classify the engine's answers.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import * as idp from "./idp";

beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockResolvedValue({ data: {}, warnings: [] });
});

describe("idp wrappers", () => {
  it("probe, mount and settings name the document, never a path", async () => {
    await idp.idpEnableMount();
    await idp.idpReadSettings("core");
    await idp.idpWriteSettings("radius", { enabled: true });
    expect(mockInvoke.mock.calls).toEqual([
      ["idp_enable_mount", undefined],
      ["idp_read_settings", { settings: "core" }],
      ["idp_write_settings", { settings: "radius", body: { enabled: true } }],
    ]);
  });

  it("named records go through kind + name", async () => {
    await idp.idpList("radius_client");
    await idp.idpRead("environment", "prod");
    await idp.idpWrite("oidc_client", "grafana", { redirect_uris: ["https://g/cb"] });
    await idp.idpDelete("saml_sp", "fortigate");
    expect(mockInvoke.mock.calls).toEqual([
      ["idp_list", { kind: "radius_client" }],
      ["idp_read", { kind: "environment", name: "prod" }],
      ["idp_write", { kind: "oidc_client", name: "grafana", body: { redirect_uris: ["https://g/cb"] } }],
      ["idp_delete", { kind: "saml_sp", name: "fortigate" }],
    ]);
  });

  it("a state change carries the target and a trimmed reason (or none)", async () => {
    await idp.idpSetIdentityState("e-1", "removed", "  left the company ");
    await idp.idpSetIdentityState("e-1", "active", "   ");
    expect(mockInvoke).toHaveBeenNthCalledWith(1, "idp_set_identity_state", {
      entityId: "e-1",
      target: "removed",
      reason: "left the company",
    });
    expect(mockInvoke).toHaveBeenNthCalledWith(2, "idp_set_identity_state", {
      entityId: "e-1",
      target: "active",
      reason: null,
    });
  });

  it("an entitlement sends roles and only the optional fields that are set", async () => {
    await idp.idpWriteEntitlement("e-1", "prod", { roles: ["dba"] });
    await idp.idpWriteEntitlement("e-1", "prod", { roles: ["dba"], not_after: "2027-01-01T00:00:00.000Z", source: "external" });
    await idp.idpRevokeEntitlement("e-1", "prod");
    expect(mockInvoke.mock.calls).toEqual([
      ["idp_write_entitlement", { entityId: "e-1", environment: "prod", body: { roles: ["dba"] } }],
      [
        "idp_write_entitlement",
        { entityId: "e-1", environment: "prod", body: { roles: ["dba"], not_after: "2027-01-01T00:00:00.000Z", source: "external" } },
      ],
      ["idp_revoke_entitlement", { entityId: "e-1", environment: "prod" }],
    ]);
  });

  it("self-service calls send nulls for blanks, never an entity id", async () => {
    await idp.idpSshSign("prod", "ssh-ed25519 AAAA", " ", []);
    await idp.idpRadiusPasscode("prod", "2m", ["netadmin"]);
    await idp.idpLdapPasscode("prod");
    expect(mockInvoke.mock.calls).toEqual([
      ["idp_ssh_sign", { environment: "prod", publicKey: "ssh-ed25519 AAAA", ttl: null, roles: null }],
      ["idp_radius_passcode", { environment: "prod", ttl: "2m", roles: ["netadmin"] }],
      ["idp_ldap_passcode", { environment: "prod", ttl: null }],
    ]);
    for (const [, args] of mockInvoke.mock.calls) {
      expect(JSON.stringify(args)).not.toMatch(/entity/i);
    }
  });

  it("keys, KRL, feed and metadata are fixed reads", async () => {
    await idp.idpReadKeys("oidc");
    await idp.idpRotateKeys("saml", "48h");
    await idp.idpReadKrl();
    await idp.idpReadDenyFeed();
    await idp.idpReadDenyFeedKey();
    await idp.idpReadSamlMetadata();
    expect(mockInvoke.mock.calls.map((c) => c[0])).toEqual([
      "idp_read_keys",
      "idp_rotate_keys",
      "idp_ssh_krl",
      "idp_deny_feed",
      "idp_deny_feed_key",
      "idp_saml_metadata",
    ]);
    expect(mockInvoke.mock.calls[1][1]).toEqual({ ring: "saml", overlap: "48h" });
  });
});

describe("idp helpers", () => {
  it("recognises a missing mount in both backends' wording", () => {
    expect(idp.isIdpNotMounted({ message: "Router mount not found." })).toBe(true);
    expect(idp.isIdpNotMounted({ message: "HTTP 404: Router mount not found." })).toBe(true);
    expect(idp.isIdpNotMounted({ message: "HTTP 403: permission denied" })).toBe(false);
  });

  it("explains the self-service refusal of a token with no entity", () => {
    const e = {
      message: "Some error happend, status: 403, response text: RADIUS passcodes are self-service and the calling token is not bound to an entity",
    };
    expect(idp.isNoEntityRefusal(e)).toBe(true);
    expect(idp.describeIdpError(e)).toMatch(/root token never is/);
    expect(idp.describeIdpError({ message: "HTTP 409: exhausted" })).toBe("HTTP 409: exhausted");
  });

  it("decodes the deny feed payload and refuses garbage", () => {
    const payload = {
      format: "bv-idp-deny-feed",
      format_version: 1,
      feed_version: 7,
      generated_at: 1_790_000_000,
      identities: [{ entity_id: "e-1", login: "alice", uid: 80017, state: "disabled", since: 1_790_000_000 }],
      revoked_serials: ["00000000000000ff"],
    };
    const b64 = btoa(JSON.stringify(payload));
    expect(idp.decodeDenyFeed(b64)?.identities[0].login).toBe("alice");
    expect(idp.decodeDenyFeed("not base64!")).toBeNull();
    expect(idp.decodeDenyFeed(btoa("{}"))).toBeNull();
  });

  it("splits lists and converts local times", () => {
    expect(idp.splitList("a, b\n c,,")).toEqual(["a", "b", "c"]);
    expect(idp.localInputToRfc3339("")).toBeNull();
    expect(idp.localInputToRfc3339("2027-01-01T10:00")).toMatch(/^2027-01-01T/);
    expect(idp.formatSeconds(1800)).toBe("30m");
  });
});
