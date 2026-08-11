import { describe, it, expect } from "vitest";
import {
  blankProfile,
  defaultPort,
  detectSecretShape,
  hasLaunchableProfile,
  isLaunchableForCaller,
  isLaunchableProfile,
  loginClassGate,
  needsOperatorPrompt,
  newProfileId,
  pickDefaultProfile,
  profileConnectHints,
  profilesForOsType,
  protocolForOsType,
  readProfiles,
  validateProfile,
  validateProfileForLoginClass,
} from "../lib/connectionProfiles";
import type { ConnectionProfile } from "../lib/types";

function sshEngineProfile(
  mode: "ca" | "otp" | "pqc" = "ca",
): ConnectionProfile {
  return {
    id: "p_test",
    name: "brokered",
    protocol: "ssh",
    username: "deploy",
    credential_source: { kind: "ssh-engine", ssh_mount: "ssh", ssh_role: "ops", mode },
  };
}

function secretProfile(): ConnectionProfile {
  return {
    id: "p_secret",
    name: "static",
    protocol: "ssh",
    credential_source: { kind: "secret", secret_id: "ssh" },
  };
}

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

describe("isLaunchableProfile (ssh-engine brokered)", () => {
  it("launches ca and otp ssh-engine modes", () => {
    expect(isLaunchableProfile(sshEngineProfile("ca"))).toBe(true);
    expect(isLaunchableProfile(sshEngineProfile("otp"))).toBe(true);
  });
  it("does not launch pqc mode (no in-app ML-DSA cert auth)", () => {
    expect(isLaunchableProfile(sshEngineProfile("pqc"))).toBe(false);
  });
});

describe("loginClassGate", () => {
  it("brokered allows only the brokered mints (ssh-engine + default-account)", () => {
    const g = loginClassGate("brokered");
    expect(g.brokered).toBe(true);
    expect(g.allowedKinds).toEqual(["ssh-engine", "default-account"]);
    expect(g.forcedKind).toBe("ssh-engine");
  });
  it("shared-credential (and unset) allows every source", () => {
    for (const lc of ["shared-credential", undefined] as const) {
      const g = loginClassGate(lc);
      expect(g.brokered).toBe(false);
      expect(g.allowedKinds).toContain("secret");
      expect(g.allowedKinds).toContain("ssh-engine");
      expect(g.allowedKinds).toContain("default-account");
      expect(g.forcedKind).toBeNull();
    }
  });
});

describe("validateProfileForLoginClass", () => {
  it("rejects a static (secret) source on a brokered resource", () => {
    expect(validateProfileForLoginClass(secretProfile(), "brokered")).toMatch(
      /brokered/i,
    );
  });
  it("accepts an ssh-engine source on a brokered resource", () => {
    expect(validateProfileForLoginClass(sshEngineProfile("ca"), "brokered")).toBeNull();
  });
  it("is a no-op for shared-credential resources", () => {
    expect(validateProfileForLoginClass(secretProfile(), "shared-credential")).toBeNull();
    expect(validateProfileForLoginClass(secretProfile(), undefined)).toBeNull();
  });
  it("accepts a default-account source on a brokered resource", () => {
    expect(
      validateProfileForLoginClass(defaultAccountSshProfile(), "brokered"),
    ).toBeNull();
  });
});

function defaultAccountSshProfile(): ConnectionProfile {
  return {
    id: "p_da_ssh",
    name: "my account",
    protocol: "ssh",
    credential_source: {
      kind: "default-account",
      ssh_mount: "ssh",
      ssh_role: "ops",
      mode: "ca",
    },
  };
}

function defaultAccountRdpProfile(): ConnectionProfile {
  return {
    id: "p_da_rdp",
    name: "my account",
    protocol: "rdp",
    credential_source: { kind: "default-account" },
  };
}

describe("default-account credential source", () => {
  it("validates: SSH needs an engine mount + role", () => {
    expect(validateProfile(defaultAccountSshProfile())).toBeNull();
    expect(
      validateProfile({
        ...defaultAccountSshProfile(),
        credential_source: { kind: "default-account", ssh_mount: "", ssh_role: "ops", mode: "ca" },
      }),
    ).toMatch(/mount is required/);
    expect(
      validateProfile({
        ...defaultAccountSshProfile(),
        credential_source: { kind: "default-account", ssh_mount: "ssh", ssh_role: "", mode: "ca" },
      }),
    ).toMatch(/role is required/);
  });

  it("validates: RDP needs no extra fields (password prompted at connect)", () => {
    expect(validateProfile(defaultAccountRdpProfile())).toBeNull();
  });

  it("is launchable for SSH (ca/otp) and RDP, but not SSH pqc", () => {
    expect(isLaunchableProfile(defaultAccountSshProfile())).toBe(true);
    expect(
      isLaunchableProfile({
        ...defaultAccountSshProfile(),
        credential_source: { kind: "default-account", ssh_mount: "ssh", ssh_role: "ops", mode: "otp" },
      }),
    ).toBe(true);
    expect(
      isLaunchableProfile({
        ...defaultAccountSshProfile(),
        credential_source: { kind: "default-account", ssh_mount: "ssh", ssh_role: "ops", mode: "pqc" },
      }),
    ).toBe(false);
    expect(isLaunchableProfile(defaultAccountRdpProfile())).toBe(true);
  });

  it("prompts for an operator credential only for RDP (password)", () => {
    expect(needsOperatorPrompt(defaultAccountRdpProfile())).toBe(true);
    expect(needsOperatorPrompt(defaultAccountSshProfile())).toBe(false);
  });
});

// ── FIDO2 credential source + MFA gate ───────────────────────────
// features/connect-mfa-and-fido2-ssh.md

function fido2Profile(protocol: "ssh" | "rdp" = "ssh"): ConnectionProfile {
  return {
    id: "p_sk",
    name: "security key",
    protocol,
    username: "deploy",
    credential_source: { kind: "fido2" },
  };
}

describe("fido2 credential source", () => {
  it("validates on SSH profiles", () => {
    expect(validateProfile(fido2Profile("ssh"))).toBeNull();
  });

  it("is refused on RDP profiles, pointing at the alternatives", () => {
    const err = validateProfile(fido2Profile("rdp"));
    expect(err).toBeTruthy();
    // The message has to name what to do instead, not just say no.
    expect(err).toMatch(/PKI/);
    expect(err).toMatch(/Require MFA re-validation/);
  });

  it("is launchable on SSH and not on RDP", () => {
    expect(isLaunchableProfile(fido2Profile("ssh"))).toBe(true);
    expect(isLaunchableProfile(fido2Profile("rdp"))).toBe(false);
  });

  it("needs no interactive operator prompt", () => {
    // The touch happens inside the session open, not as a GUI pre-prompt,
    // so the card-level quick-Connect can launch these directly.
    expect(needsOperatorPrompt(fido2Profile("ssh"))).toBe(false);
  });

  it("is offered on unbrokered resources but not brokered ones", () => {
    expect(loginClassGate(undefined).allowedKinds).toContain("fido2");
    expect(loginClassGate("shared-credential").allowedKinds).toContain("fido2");
    // A brokered resource must mint per-connect from the SSH engine; the
    // operator's key is on their desk, not on the bastion.
    expect(loginClassGate("brokered").allowedKinds).not.toContain("fido2");
  });

  it("is rejected against a brokered resource with a reason", () => {
    const err = validateProfileForLoginClass(fido2Profile("ssh"), "brokered");
    expect(err).toBeTruthy();
    expect(err).toMatch(/bastion/);
  });

  it("does not block a brokered RDP profile (the gate is SSH-only)", () => {
    expect(validateProfileForLoginClass(fido2Profile("rdp"), "brokered")).toBeNull();
  });
});

describe("require_mfa", () => {
  it("defaults to absent on a blank profile", () => {
    // Every profile written before this feature must keep its old behaviour.
    expect(blankProfile("linux").require_mfa).toBeUndefined();
  });

  it("does not affect validation or launchability either way", () => {
    // The gate is enforced server-side at connect; it is not a save-time or
    // launch-time property of the profile.
    const gated: ConnectionProfile = { ...secretProfile(), require_mfa: true };
    expect(validateProfile(gated)).toBeNull();
    expect(isLaunchableProfile(gated)).toBe(true);
    expect(needsOperatorPrompt(gated)).toBe(false);
  });

  it("survives a round trip through readProfiles", () => {
    const parsed = readProfiles({
      connection_profiles: [
        { ...secretProfile(), require_mfa: true },
        { ...fido2Profile("ssh") },
      ],
    });
    expect(parsed).toHaveLength(2);
    expect(parsed[0].require_mfa).toBe(true);
    expect(parsed[1].credential_source.kind).toBe("fido2");
    expect(parsed[1].require_mfa).toBeUndefined();
  });
});

describe("connect-only launchability", () => {
  const brokered = (): ConnectionProfile => ({
    ...secretProfile(),
    id: "p_brokered",
    kind: "rustion",
  });

  it("lets a caller who can read credentials launch either transport", () => {
    expect(isLaunchableForCaller(secretProfile(), false)).toBe(true);
    expect(isLaunchableForCaller(brokered(), false)).toBe(true);
  });

  it("blocks direct dials for a connect-only caller, allows brokered ones", () => {
    // A `direct` dial resolves the credential into the GUI process, which is
    // exactly what connect-only access exists to prevent.
    expect(isLaunchableForCaller(secretProfile(), true)).toBe(false);
    expect(isLaunchableForCaller(brokered(), true)).toBe(true);
  });

  it("treats an absent transport as direct", () => {
    const legacy = secretProfile();
    expect(legacy.kind).toBeUndefined();
    expect(isLaunchableForCaller(legacy, true)).toBe(false);
  });

  it("still applies the phase matrix on top of the access gate", () => {
    // Brokered transport doesn't rescue a combination the client can't drive.
    const pqc: ConnectionProfile = { ...sshEngineProfile("pqc"), kind: "rustion" };
    expect(isLaunchableForCaller(pqc, true)).toBe(false);
    expect(isLaunchableForCaller(pqc, false)).toBe(false);
  });

  it("hasLaunchableProfile answers the card-level question", () => {
    expect(hasLaunchableProfile([], false)).toBe(false);
    expect(hasLaunchableProfile([secretProfile()], true)).toBe(false);
    expect(hasLaunchableProfile([secretProfile(), brokered()], true)).toBe(true);
  });

  it("pickDefaultProfile skips a direct default for a connect-only caller", () => {
    const direct: ConnectionProfile = { ...secretProfile(), is_default: true };
    const profiles = [direct, brokered()];
    // With full access the flagged default wins…
    expect(pickDefaultProfile(profiles, false)?.id).toBe("p_secret");
    // …and connect-only falls through to the sole brokered profile rather
    // than firing a dial the server would refuse.
    expect(pickDefaultProfile(profiles, true)?.id).toBe("p_brokered");
    expect(pickDefaultProfile([direct], true)).toBeNull();
  });

  it("defaults to full access when connectOnly is omitted", () => {
    expect(pickDefaultProfile([secretProfile()])?.id).toBe("p_secret");
  });
});

describe("connect-only launchability under a brokered transport tier", () => {
  // The regression this covers: a resource pinned to `rustion-required` by a
  // policy tier brokers every session on it through a bastion, so the
  // credential is resolved server-side and never reaches this process. Gating
  // on the profile's own `kind` field alone refused exactly the caller the
  // brokered transport exists to protect — and `kind` defaults to `direct` on
  // every profile minted before that field landed.
  it("launches a server-resolvable SSH profile that the policy tier brokers", () => {
    expect(isLaunchableForCaller(secretProfile(), true, true)).toBe(true);
    expect(isLaunchableForCaller(sshEngineProfile("ca"), true, true)).toBe(true);
    expect(isLaunchableForCaller(defaultAccountSshProfile(), true, true)).toBe(
      true,
    );
  });

  it("still refuses it when the tier does not broker", () => {
    expect(isLaunchableForCaller(secretProfile(), true, false)).toBe(false);
    expect(isLaunchableForCaller(defaultAccountSshProfile(), true, false)).toBe(
      false,
    );
  });

  it("refuses kinds the server cannot resolve, brokered tier or not", () => {
    // LDAP / PKI / FIDO2 still resolve client-side even under a brokered
    // transport, so the credential would land here anyway.
    const ldap: ConnectionProfile = {
      id: "p_ldap",
      name: "ldap",
      protocol: "ssh",
      credential_source: {
        kind: "ldap",
        ldap_mount: "openldap",
        bind_mode: "static_role",
        static_role: "svc",
      },
    };
    const pki: ConnectionProfile = {
      id: "p_pki",
      name: "pki",
      protocol: "ssh",
      username: "deploy",
      credential_source: { kind: "pki", pki_mount: "pki", pki_role: "ops" },
    };
    for (const p of [ldap, pki, fido2Profile("ssh")]) {
      expect(isLaunchableForCaller(p, true, true)).toBe(false);
    }
  });

  it("does not extend the policy route to RDP", () => {
    // Brokered RDP goes through v1 `rustion/session/open` with a
    // client-resolved credential, so the tier can't rescue it.
    const rdp: ConnectionProfile = {
      ...secretProfile(),
      id: "p_rdp",
      protocol: "rdp",
    };
    expect(isLaunchableForCaller(rdp, true, true)).toBe(false);
  });

  it("changes nothing for a caller who can read the credentials", () => {
    for (const brokeredTier of [false, true]) {
      expect(isLaunchableForCaller(secretProfile(), false, brokeredTier)).toBe(
        true,
      );
    }
  });

  it("threads through hasLaunchableProfile and pickDefaultProfile", () => {
    const direct: ConnectionProfile = { ...secretProfile(), is_default: true };
    expect(hasLaunchableProfile([direct], true, false)).toBe(false);
    expect(hasLaunchableProfile([direct], true, true)).toBe(true);
    expect(pickDefaultProfile([direct], true, false)).toBeNull();
    expect(pickDefaultProfile([direct], true, true)?.id).toBe("p_secret");
  });

  it("defaults brokeredByPolicy to false so existing callers are unchanged", () => {
    expect(isLaunchableForCaller(secretProfile(), true)).toBe(false);
    expect(hasLaunchableProfile([secretProfile()], true)).toBe(false);
  });
});

describe("profileConnectHints", () => {
  it("keeps only the fields launchability reads", () => {
    expect(profileConnectHints([sshEngineProfile("otp")])).toEqual([
      {
        protocol: "ssh",
        kind: undefined,
        credential_source: { kind: "ssh-engine", mode: "otp" },
      },
    ]);
  });

  it("carries the transport through", () => {
    const hints = profileConnectHints([
      { ...secretProfile(), kind: "rustion" },
    ]);
    expect(hints[0].kind).toBe("rustion");
    expect(hints[0].credential_source.mode).toBeUndefined();
  });

  it("round-trips through the same verdict as the full profile", () => {
    // The card gates on hints while the Connection tab gates on full
    // profiles — they must never disagree.
    const profiles: ConnectionProfile[] = [
      secretProfile(),
      { ...secretProfile(), id: "p_b", kind: "rustion" },
      sshEngineProfile("pqc"),
      fido2Profile("rdp"),
    ];
    for (const connectOnly of [false, true]) {
      const hints = profileConnectHints(profiles);
      expect(hints.map((h) => isLaunchableForCaller(h, connectOnly))).toEqual(
        profiles.map((p) => isLaunchableForCaller(p, connectOnly)),
      );
    }
  });
});
