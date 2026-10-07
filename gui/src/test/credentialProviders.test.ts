/**
 * The `provider` credential source on the GUI side (features/self-accounts.md
 * §6 and §10, T103 Phase 4): the connection-profile helpers, the hardened
 * `isKnownProfile` (a credential source this build does not know is hidden
 * but never lost), the web-form checks, and the picker's pure helpers.
 */
import { describe, expect, it } from "vitest";

import type { ActiveSurfaceBundle, CredentialProviderInfo } from "../lib/api";
import {
  blankCredentialSource,
  isKnownCredentialSource,
  isLaunchableForCaller,
  isLaunchableProfile,
  isLaunchableWebProfile,
  loginClassGate,
  needsOperatorPrompt,
  pickDefaultProfile,
  profilesForWrite,
  providerMfaHint,
  readProfiles,
  readUnknownProfiles,
  setWebLoginMode,
  validateProfile,
  validateProfileForLoginClass,
} from "../lib/connectionProfiles";
import {
  accountNoun,
  addAccountLabel,
  describeProviderError,
  describeTarget,
  firstUseBadgeLabel,
  firstUseHint,
  isProviderName,
  lastUsedLabel,
  loginLabel,
  parseProviderOption,
  preselectedCandidate,
  providerAccountsRoute,
  providerOptionValue,
  providerReason,
  providersForProtocol,
} from "../lib/credentialProviders";
import { credentialSourceSelectValue, providerSourceOptions } from "../components/ProviderSourceFields";
import type { ConnectionProfile, WebLoginRecipe } from "../lib/types";

function providerProfile(extra: Partial<ConnectionProfile> = {}): ConnectionProfile {
  return {
    id: "p_sa",
    name: "Self-account",
    protocol: "rdp",
    credential_source: { kind: "provider", provider: "self-accounts" },
    require_mfa: true,
    ...extra,
  };
}

const RECIPE: WebLoginRecipe = {
  version: 1,
  steps: [
    {
      when_url: "https://fw01.example.com/login*",
      actions: [{ fill: "#user", value: "username" }, { fill: "#pass", value: "password" }, { submit: "form" }],
    },
  ],
  success_when: { url: "https://fw01.example.com/ng/*" },
} as unknown as WebLoginRecipe;

function webProviderProfile(): ConnectionProfile {
  return {
    id: "p_web",
    name: "Firewall",
    protocol: "web",
    credential_source: { kind: "provider", provider: "self-accounts" },
    require_mfa: true,
    web: { start_url: "https://fw01.example.com/login", allowed_origins: [], login_mode: "form", recipe: RECIPE },
  };
}

describe("connectionProfiles: the provider source", () => {
  it("validates the provider name and nothing else on SSH / RDP", () => {
    expect(validateProfile(providerProfile())).toBeNull();
    expect(validateProfile(providerProfile({ protocol: "ssh" }))).toBeNull();
    for (const provider of ["", "../x", "a b", "x".repeat(129)]) {
      expect(validateProfile(providerProfile({ credential_source: { kind: "provider", provider } }))).toMatch(
        /credential provider/,
      );
    }
    // The profile's username is irrelevant (the released one wins).
    expect(validateProfile(providerProfile({ username: undefined }))).toBeNull();
  });

  it("is launchable on every transport, and for a connect-only caller", () => {
    for (const protocol of ["ssh", "rdp"] as const) {
      for (const kind of ["direct", "rustion"] as const) {
        const p = providerProfile({ protocol, kind });
        expect(isLaunchableProfile(p)).toBe(true);
        // The operator's own account, never a resource secret.
        expect(isLaunchableForCaller(p, true, false)).toBe(true);
      }
    }
    expect(pickDefaultProfile([providerProfile({ is_default: true })], true)).not.toBeNull();
  });

  it("needs no operator prompt: the picker renders over any launcher", () => {
    expect(needsOperatorPrompt(providerProfile())).toBe(false);
  });

  it("blanks to an unnamed provider, which validation then refuses", () => {
    const cs = blankCredentialSource("provider");
    expect(cs).toEqual({ kind: "provider", provider: "" });
    expect(validateProfile(providerProfile({ credential_source: cs }))).not.toBeNull();
  });

  it("is refused on a brokered SSH resource, like every non-engine source", () => {
    expect(loginClassGate("shared-credential").allowedKinds).toContain("provider");
    expect(loginClassGate("brokered").allowedKinds).not.toContain("provider");
    expect(validateProfileForLoginClass(providerProfile({ protocol: "ssh" }), "brokered")).toMatch(/brokered/);
  });

  it("hints at require_mfa only for a provider profile without it", () => {
    expect(providerMfaHint(providerProfile({ require_mfa: undefined }))).toMatch(/Require MFA re-validation/);
    expect(providerMfaHint(providerProfile())).toBeNull();
    expect(
      providerMfaHint({ ...providerProfile(), credential_source: { kind: "secret", secret_id: "s" }, require_mfa: false }),
    ).toBeNull();
  });

  it("signs in a web `form` login, never an http-auth or open one", () => {
    const p = webProviderProfile();
    expect(validateProfile(p)).toBeNull();
    expect(isLaunchableWebProfile(p)).toBe(true);
    expect(isLaunchableForCaller(p, true)).toBe(true);
    // TOTP parameters are read like a `secret` source's.
    const bad = { ...p, credential_source: { kind: "provider" as const, provider: "self-accounts", totp: { digits: 7 as 6 } } };
    expect(validateProfile(bad)).toMatch(/digits/);

    const httpAuth: ConnectionProfile = { ...p, web: { ...p.web!, login_mode: "http-auth", recipe: undefined } };
    expect(validateProfile(httpAuth)).toMatch(/form login mode only/);
    // Switching modes moves the source with them.
    expect(setWebLoginMode(p, "http-auth").credential_source.kind).toBe("secret");
    expect(setWebLoginMode(p, "open").credential_source.kind).toBe("none");
    expect(setWebLoginMode(p, "form").credential_source).toEqual(p.credential_source);
  });
});

describe("isKnownProfile hardening (spec §10, T102 rule)", () => {
  const secret = (id: string): ConnectionProfile => ({
    id,
    name: id,
    protocol: "rdp",
    credential_source: { kind: "secret", secret_id: "s" },
  });
  // A profile from a *newer* client: a known protocol, a credential source
  // this build has never heard of.
  const futureSource = {
    id: "p_future_src",
    name: "Vault bridge",
    protocol: "rdp",
    is_default: true,
    credential_source: { kind: "password-manager", vault: "corp", item: 42 },
    some_new_field: ["x"],
  };
  const providerWithoutName = {
    id: "p_noname",
    name: "broken",
    protocol: "ssh",
    credential_source: { kind: "provider" },
  };

  it("requires a known credential-source kind", () => {
    expect(isKnownCredentialSource({ kind: "provider", provider: "self-accounts" })).toBe(true);
    expect(isKnownCredentialSource({ kind: "provider", provider: "" })).toBe(true);
    for (const cs of [{ kind: "password-manager" }, { kind: 1 }, {}, [], null, "secret", { kind: "provider" }]) {
      expect(isKnownCredentialSource(cs)).toBe(false);
    }
  });

  it("hides a profile with an unknown source from the list and from launching", () => {
    const meta = { connection_profiles: [secret("p_a"), futureSource, providerWithoutName] };
    expect(readProfiles(meta).map((p) => p.id)).toEqual(["p_a"]);
    expect(readUnknownProfiles(meta)).toEqual([futureSource, providerWithoutName]);
    // The hidden default is never launched in place of the visible profile.
    expect(pickDefaultProfile(readProfiles(meta))?.id).toBe("p_a");
  });

  it("round-trips the unknown entries byte-for-byte through an edit, a delete and a re-default", () => {
    const meta = { connection_profiles: [secret("p_a"), futureSource, secret("p_b")] };
    const unknown = readUnknownProfiles(meta);

    const edited = readProfiles(meta).map((p) => (p.id === "p_a" ? { ...p, name: "renamed" } : p));
    const out = profilesForWrite(edited, unknown) as Array<Record<string, unknown>>;
    expect(out).toHaveLength(3);
    // It held the default and no known profile is flagged: it keeps it.
    expect(out[2]).toBe(futureSource);
    expect(JSON.stringify(out[2])).toBe(JSON.stringify(futureSource));

    const afterDelete = profilesForWrite([], unknown);
    expect(afterDelete).toEqual([futureSource]);

    // Re-defaulting a known profile only clears the unknown entry's flag.
    const redefault = readProfiles(meta).map((p) => ({ ...p, is_default: p.id === "p_b" }));
    const out2 = profilesForWrite(redefault, unknown) as Array<Record<string, unknown>>;
    expect(out2[2]).toEqual({ ...futureSource, is_default: false });
  });

  it("reads this build's provider profiles as known", () => {
    const meta = { connection_profiles: [providerProfile(), webProviderProfile()] };
    expect(readProfiles(meta).map((p) => p.id)).toEqual(["p_sa", "p_web"]);
    expect(readUnknownProfiles(meta)).toEqual([]);
  });
});

describe("credential-provider helpers", () => {
  const providers: CredentialProviderInfo[] = [
    { name: "self-accounts", display_name: "Self-account", protocols: ["ssh", "rdp", "web"], secret_kinds: ["password", "ssh-key"] },
    { name: "vault-bridge", display_name: "Vault bridge", protocols: ["web"], secret_kinds: ["password"] },
  ];

  it("offers only the providers that serve the protocol, by display name", () => {
    expect(providersForProtocol(providers, "rdp").map((p) => p.name)).toEqual(["self-accounts"]);
    expect(providersForProtocol(providers, "web").map((p) => p.name)).toEqual(["self-accounts", "vault-bridge"]);
    expect(providerSourceOptions(providers, "rdp", { kind: "secret", secret_id: "" })).toEqual([
      { value: "provider:self-accounts", label: "Self-account (pick at connect)" },
    ]);
  });

  it("keeps a profile's provider this server does not offer, marked unavailable", () => {
    const options = providerSourceOptions(providers, "rdp", { kind: "provider", provider: "vault-bridge" });
    expect(options).toContainEqual({ value: "provider:vault-bridge", label: "vault-bridge (not available here)" });
    expect(providerSourceOptions([], "ssh", { kind: "provider", provider: "self-accounts" })).toEqual([
      { value: "provider:self-accounts", label: "self-accounts (not available here)" },
    ]);
  });

  it("encodes the provider in the select value and reads it back strictly", () => {
    expect(credentialSourceSelectValue({ kind: "provider", provider: "self-accounts" })).toBe("provider:self-accounts");
    expect(credentialSourceSelectValue({ kind: "ldap", ldap_mount: "l", bind_mode: "operator" })).toBe("ldap");
    expect(parseProviderOption(providerOptionValue("self-accounts"))).toBe("self-accounts");
    expect(parseProviderOption("provider:../x")).toBeNull();
    expect(parseProviderOption("secret")).toBeNull();
    expect(isProviderName("self-accounts")).toBe(true);
    expect(isProviderName("-x")).toBe(false);
  });

  it("words the picker's text from the display name", () => {
    expect(accountNoun("Self-account")).toBe("self-accounts");
    expect(addAccountLabel("Self-account")).toBe("Add a self-account");
    expect(accountNoun("Vault bridge")).toBe("Vault bridge accounts");
    expect(addAccountLabel("Vault bridge")).toBe("Add an account");
    expect(describeTarget({ kind: "host", host: "dc01.corp.example.com", port: 3389 })).toBe("dc01.corp.example.com:3389");
    expect(describeTarget({ kind: "host", host: "fe80::1", port: 22 })).toBe("[fe80::1]:22");
    expect(describeTarget({ kind: "origins", origins: ["https://a.example", "https://b.example"] })).toBe(
      "https://a.example (+1 more origin)",
    );
    expect(loginLabel({ username: "felipe.adm", domain: "CORP" })).toBe("CORP\\felipe.adm");
    expect(loginLabel({ username: "root", domain: null })).toBe("root");
    const now = Date.parse("2026-10-07T12:00:00Z");
    expect(lastUsedLabel(null, now)).toBe("Never used");
    expect(lastUsedLabel("2026-10-07T11:59:30Z", now)).toBe("Used just now");
    expect(lastUsedLabel("2026-10-04T12:00:00Z", now)).toBe("Used 3 days ago");
    expect(lastUsedLabel("2026-01-01T00:00:00Z", now)).toBe("Used on 2026-01-01");
  });

  it("preselects the most recent use on this target, else a single candidate, else none", () => {
    expect(preselectedCandidate([])).toBeNull();
    expect(preselectedCandidate([{ id: "a" }])).toBe("a");
    expect(preselectedCandidate([{ id: "a" }, { id: "b" }])).toBeNull();
    expect(
      preselectedCandidate([
        { id: "a", last_used_on_target: "2026-10-01T00:00:00Z" },
        { id: "b", last_used_on_target: "2026-10-05T00:00:00Z" },
        { id: "c", last_used_on_target: null },
      ]),
    ).toBe("b");
    // An unreadable time is ignored rather than trusted.
    expect(preselectedCandidate([{ id: "a", last_used_on_target: "dc01.corp" }, { id: "b" }])).toBeNull();
    expect(preselectedCandidate([{ id: "a", last_used_on_target: "garbage" }])).toBe("a");
  });

  it("words the first-use badge and caution by target kind", () => {
    const host = { kind: "host" as const, host: "dc01.corp.example.com", port: 3389 };
    const site = { kind: "origins" as const, origins: ["https://grafana.example.com"] };
    expect(firstUseBadgeLabel(host)).toBe("First use on this host");
    expect(firstUseBadgeLabel(site)).toBe("First use on this site");
    expect(firstUseHint(host)).toContain("dc01.corp.example.com:3389");
    expect(firstUseHint(site)).toContain("on this site before");
  });

  it("turns the server's stable refusal codes into operator text, keeping the code", () => {
    const e = { message: "HTTP 403: mfa_required: the credential provider requires connect-time MFA" };
    expect(providerReason(e)).toBe("mfa_required");
    expect(describeProviderError(e)).toMatch(/Require MFA re-validation.*\(mfa_required\)$/);
    expect(describeProviderError(new Error("Response status: 404, no_match: no account"))).toMatch(/\(no_match\)$/);
    expect(describeProviderError("not_granted: credential provider `x` is not approved")).toMatch(/approve it under Plugins/);
    expect(describeProviderError("transport_policy: x")).toMatch(/bastion/);
    expect(
      describeProviderError({ message: "HTTP 403: brokered_requires_ssh_engine: this resource is brokered (login class via tier `type`)" }),
    ).toMatch(/minted by the SSH engine.*\(brokered_requires_ssh_engine\)$/);
    expect(describeProviderError("invalid_profile: the resource has no `type`")).toBe(
      "This connection profile cannot use a credential provider: the resource has no `type` (invalid_profile)",
    );
    // Anything else passes through unchanged.
    expect(describeProviderError(new Error("tcp connect: refused"))).toBe("tcp connect: refused");
  });

  it("links to the provider's own page only when its surface registers one", () => {
    const bundle = {
      etag: "e",
      entries: [
        {
          plugin: "self-accounts",
          version: "1",
          mount: "self-accounts/",
          assets: [],
          surface: {
            schema_version: 1,
            title: "Self-accounts",
            menus: [{ id: "m", label: "My accounts", section: "secrets", route: "/plugin/self-accounts/accounts" }],
            pages: [{ route: "/plugin/self-accounts/accounts", title: "My accounts", components: [] }],
          },
        },
        {
          plugin: "evil",
          version: "1",
          mount: "evil/",
          assets: [],
          surface: {
            schema_version: 1,
            title: "x",
            // A menu outside its own prefix, and a page not registered.
            menus: [{ id: "m", label: "x", section: "secrets", route: "/settings" }, { id: "n", label: "y", section: "secrets", route: "/plugin/evil/unregistered" }],
            pages: [],
          },
        },
      ],
    } as unknown as ActiveSurfaceBundle;
    expect(providerAccountsRoute(bundle, "self-accounts")).toBe("/plugin/self-accounts/accounts");
    expect(providerAccountsRoute(bundle, "evil")).toBeNull();
    expect(providerAccountsRoute(bundle, "absent")).toBeNull();
    expect(providerAccountsRoute(null, "self-accounts")).toBeNull();
  });
});
