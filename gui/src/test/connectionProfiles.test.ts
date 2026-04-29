import { describe, it, expect } from "vitest";
import {
  blankProfile,
  defaultPort,
  detectSecretShape,
  newProfileId,
  profilesForOsType,
  protocolForOsType,
  readProfiles,
  validateProfile,
} from "../lib/connectionProfiles";
import type { ConnectionProfile } from "../lib/types";

describe("protocolForOsType", () => {
  it("maps *nix os_type values to ssh", () => {
    expect(protocolForOsType("linux")).toBe("ssh");
    expect(protocolForOsType("macos")).toBe("ssh");
    expect(protocolForOsType("bsd")).toBe("ssh");
    expect(protocolForOsType("unix")).toBe("ssh");
  });
  it("maps windows to rdp", () => {
    expect(protocolForOsType("windows")).toBe("rdp");
  });
  it("returns null for `other` and unrecognized values", () => {
    expect(protocolForOsType("other")).toBeNull();
    expect(protocolForOsType("")).toBeNull();
    expect(protocolForOsType("freedos")).toBeNull();
  });
});

describe("defaultPort", () => {
  it("uses 22 for ssh, 3389 for rdp", () => {
    expect(defaultPort("ssh")).toBe(22);
    expect(defaultPort("rdp")).toBe(3389);
  });
});

describe("newProfileId", () => {
  it("returns a stable shape and is unique per call", () => {
    const a = newProfileId();
    const b = newProfileId();
    expect(a).toMatch(/^p_[0-9a-f]{16}$/);
    expect(b).toMatch(/^p_[0-9a-f]{16}$/);
    expect(a).not.toBe(b);
  });
});

describe("detectSecretShape", () => {
  it("returns credential when username + password present", () => {
    const s = detectSecretShape({ username: "alice", password: "hunter2" });
    expect(s.kind).toBe("credential");
    if (s.kind === "credential") {
      expect(s.username).toBe("alice");
      expect(s.has_password).toBe(true);
      expect(s.has_private_key).toBe(false);
    }
  });
  it("returns credential when username + private_key present", () => {
    const s = detectSecretShape({
      username: "felipe",
      private_key: "-----BEGIN OPENSSH PRIVATE KEY-----…",
    });
    expect(s.kind).toBe("credential");
    if (s.kind === "credential") {
      expect(s.has_private_key).toBe(true);
      expect(s.has_password).toBe(false);
    }
  });
  it("returns kv when username is missing", () => {
    const s = detectSecretShape({ token: "abc", api_key: "xyz" });
    expect(s.kind).toBe("kv");
    if (s.kind === "kv") {
      expect(s.keys.sort()).toEqual(["api_key", "token"]);
    }
  });
  it("returns kv when only username is present (no password / key)", () => {
    const s = detectSecretShape({ username: "alice" });
    expect(s.kind).toBe("kv");
  });
  it("ignores empty-string secret values when deciding shape", () => {
    const s = detectSecretShape({ username: "alice", password: "" });
    expect(s.kind).toBe("kv");
  });
});

describe("readProfiles", () => {
  it("returns [] when the field is missing", () => {
    expect(readProfiles({})).toEqual([]);
  });
  it("returns [] when the field carries a non-array", () => {
    expect(readProfiles({ connection_profiles: "not-an-array" })).toEqual([]);
  });
  it("filters out malformed entries and keeps the valid ones", () => {
    const out = readProfiles({
      connection_profiles: [
        { id: "p_1", name: "ok", protocol: "ssh", credential_source: { kind: "secret", secret_id: "s" } },
        { id: 5, name: "bad-id", protocol: "ssh", credential_source: { kind: "secret", secret_id: "s" } },
        { id: "p_2", name: "no-cred", protocol: "rdp" },
        { id: "p_3", name: "bad-protocol", protocol: "telnet", credential_source: { kind: "secret", secret_id: "s" } },
      ],
    });
    expect(out.map((p) => p.id)).toEqual(["p_1"]);
  });
});

describe("blankProfile", () => {
  it("uses ssh default for linux + the supplied secret", () => {
    const p = blankProfile("linux", "root-key");
    expect(p.protocol).toBe("ssh");
    expect(p.credential_source).toEqual({
      kind: "secret",
      secret_id: "root-key",
    });
  });
  it("uses rdp default for windows + an empty secret_id when none supplied", () => {
    const p = blankProfile("windows");
    expect(p.protocol).toBe("rdp");
    expect(p.credential_source).toEqual({ kind: "secret", secret_id: "" });
  });
  it("falls back to ssh when os_type is unrecognized", () => {
    const p = blankProfile("freedos");
    expect(p.protocol).toBe("ssh");
  });
});

describe("validateProfile", () => {
  const base: ConnectionProfile = {
    id: "p_1",
    name: "Default",
    protocol: "ssh",
    credential_source: { kind: "secret", secret_id: "rootpw" },
  };
  it("accepts a clean profile", () => {
    expect(validateProfile(base)).toBeNull();
  });
  it("rejects a missing name", () => {
    expect(validateProfile({ ...base, name: "  " })).toMatch(/name is required/);
  });
  it("rejects an out-of-range port", () => {
    expect(validateProfile({ ...base, target_port: 0 })).toMatch(/Port must be/);
    expect(validateProfile({ ...base, target_port: 65536 })).toMatch(/Port must be/);
  });
  it("rejects a Secret source with no secret_id", () => {
    expect(
      validateProfile({
        ...base,
        credential_source: { kind: "secret", secret_id: "  " },
      }),
    ).toMatch(/credential secret/);
  });
  it("rejects an LDAP source with empty mount", () => {
    expect(
      validateProfile({
        ...base,
        credential_source: {
          kind: "ldap",
          ldap_mount: "",
          bind_mode: "operator",
        },
      }),
    ).toMatch(/LDAP mount/);
  });
  it("rejects an LDAP static-role source without a static_role", () => {
    expect(
      validateProfile({
        ...base,
        credential_source: {
          kind: "ldap",
          ldap_mount: "openldap/",
          bind_mode: "static_role",
        },
      }),
    ).toMatch(/static_role required/);
  });
  it("rejects an SSH-engine source missing the role", () => {
    expect(
      validateProfile({
        ...base,
        credential_source: {
          kind: "ssh-engine",
          ssh_mount: "ssh/",
          ssh_role: "",
          mode: "ca",
        },
      }),
    ).toMatch(/SSH role/);
  });
  it("rejects a PKI source missing the role", () => {
    expect(
      validateProfile({
        ...base,
        credential_source: {
          kind: "pki",
          pki_mount: "pki/",
          pki_role: "",
        },
      }),
    ).toMatch(/PKI role/);
  });
});

describe("profilesForOsType", () => {
  const sshP: ConnectionProfile = {
    id: "p_ssh",
    name: "ssh-prof",
    protocol: "ssh",
    credential_source: { kind: "secret", secret_id: "s" },
  };
  const rdpP: ConnectionProfile = {
    id: "p_rdp",
    name: "rdp-prof",
    protocol: "rdp",
    credential_source: { kind: "secret", secret_id: "s" },
  };
  it("filters to ssh profiles for linux", () => {
    expect(profilesForOsType([sshP, rdpP], "linux")).toEqual([sshP]);
  });
  it("filters to rdp profiles for windows", () => {
    expect(profilesForOsType([sshP, rdpP], "windows")).toEqual([rdpP]);
  });
  it("returns [] when os_type doesn't have a Connect protocol", () => {
    expect(profilesForOsType([sshP, rdpP], "other")).toEqual([]);
  });
});
