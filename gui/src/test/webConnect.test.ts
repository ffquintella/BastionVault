/**
 * Web Application Connect, Phase 1 (features/web-application-connect.md,
 * T96): the additive type-config merge with tombstones, the protocol gate,
 * strict protocol parsing, and `web` profile validation.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import {
  DEFAULT_RESOURCE_TYPES,
  PRE_TOMBSTONE_BUILTIN_IDS,
  TYPE_CONFIG_META_KEY,
  connectProtocols,
  mergeTypeConfig,
  parseTypeConfig,
  serializeTypeConfig,
  typeSupportsConnect,
  typeSupportsProtocol,
} from "../lib/resourceTypes";
import {
  blankWebProfile,
  isLaunchableForCaller,
  isLaunchableProfile,
  isLaunchableWebProfile,
  normalizeWebOrigin,
  parseSessionProtocol,
  readProfiles,
  setWebLoginMode,
  validateProfile,
  webOriginSet,
} from "../lib/connectionProfiles";
import { evaluateWebExposure, requiredExposureForLoginMode } from "../lib/webExposure";
import { openProfileSession } from "../lib/sessionLaunch";
import { webRecipeTest } from "../lib/api";
import type { ConnectionProfile, ResourceTypeDef, WebProfileSettings } from "../lib/types";

function webProfile(
  web: Partial<WebProfileSettings> = {},
  over: Partial<ConnectionProfile> = {},
): ConnectionProfile {
  return {
    id: "p_web",
    name: "Console",
    protocol: "web",
    credential_source: { kind: "none" },
    web: {
      start_url: "https://fw01.example.com/login",
      allowed_origins: [],
      login_mode: "open",
      ...web,
    },
    ...over,
  };
}

// ── Type config merge ─────────────────────────────────────────────────

describe("parseTypeConfig / mergeTypeConfig — additive merge with tombstones", () => {
  it("never-saved config yields every builtin, web_application included", () => {
    const { types, removedBuiltins } = parseTypeConfig(null);
    expect(Object.keys(types).sort()).toEqual(Object.keys(DEFAULT_RESOURCE_TYPES).sort());
    expect(types.web_application).toBeDefined();
    expect(removedBuiltins).toEqual([]);
  });

  it("adds a new builtin to a config saved before it existed, and leaves saved types verbatim", () => {
    // What an older GUI wrote: every pre-tombstone builtin, one of them
    // customised, plus an operator type. No tombstone entry.
    const saved: Record<string, unknown> = {};
    for (const id of PRE_TOMBSTONE_BUILTIN_IDS) saved[id] = DEFAULT_RESOURCE_TYPES[id];
    const customServer: ResourceTypeDef = {
      id: "server",
      label: "Box",
      color: "neutral",
      fields: [{ key: "hostname", label: "Host", type: "fqdn" }],
    };
    saved.server = customServer;
    saved.vm = { id: "vm", label: "VM", color: "info", fields: [] };

    const types = mergeTypeConfig(saved as never);
    expect(types.web_application).toEqual(DEFAULT_RESOURCE_TYPES.web_application);
    expect(types.server).toEqual(customServer); // saved wins per key
    expect(types.vm).toBeDefined();
  });

  it("a builtin missing from a pre-tombstone save was deleted by the operator and stays deleted", () => {
    const saved: Record<string, unknown> = {};
    for (const id of PRE_TOMBSTONE_BUILTIN_IDS) {
      if (id !== "application") saved[id] = DEFAULT_RESOURCE_TYPES[id];
    }
    const { types, removedBuiltins } = parseTypeConfig(saved);
    expect(types.application).toBeUndefined();
    expect(types.web_application).toBeDefined();
    // Carried forward as an explicit tombstone on the next save.
    expect(removedBuiltins).toEqual(["application"]);
  });

  it("a saved website without `connect` is not altered — it gains no web protocol", () => {
    const saved: Record<string, unknown> = {};
    for (const id of PRE_TOMBSTONE_BUILTIN_IDS) saved[id] = DEFAULT_RESOURCE_TYPES[id];
    const { connect: _c, ...legacyWebsite } = DEFAULT_RESOURCE_TYPES.website;
    void _c;
    saved.website = legacyWebsite;
    const types = mergeTypeConfig(saved as never);
    expect(types.website.connect).toBeUndefined();
    expect(connectProtocols(types.website)).toEqual([]);
  });

  it("an explicit tombstone keeps a deleted new builtin deleted", () => {
    const types = { ...DEFAULT_RESOURCE_TYPES };
    delete types.web_application;
    const blob = serializeTypeConfig(types, ["web_application"]);
    const parsed = parseTypeConfig(blob);
    expect(parsed.types.web_application).toBeUndefined();
    expect(parsed.removedBuiltins).toEqual(["web_application"]);
    // The tombstone entry is never shown as a type.
    expect(parsed.types[TYPE_CONFIG_META_KEY]).toBeUndefined();
  });

  it("with a tombstone entry present, an un-tombstoned missing builtin is added", () => {
    const types = { ...DEFAULT_RESOURCE_TYPES };
    delete types.web_application;
    delete types.database;
    const blob = serializeTypeConfig(types, ["web_application"]);
    expect(parseTypeConfig(blob).types.database).toBeDefined();
  });

  it("writes the tombstone entry only when needed, last, and shaped like a type for older GUIs", () => {
    expect(serializeTypeConfig(DEFAULT_RESOURCE_TYPES, [])).not.toHaveProperty(TYPE_CONFIG_META_KEY);

    const types = { ...DEFAULT_RESOURCE_TYPES };
    delete types.application;
    const blob = serializeTypeConfig(types, ["application", "application", "not_a_builtin"]);
    const keys = Object.keys(blob);
    expect(keys[keys.length - 1]).toBe(TYPE_CONFIG_META_KEY);
    // Older GUIs iterate every value and read id / label / color /
    // fields.length — none of them may throw.
    for (const v of Object.values(blob)) {
      const t = v as ResourceTypeDef;
      expect(typeof t.id).toBe("string");
      expect(typeof t.label).toBe("string");
      expect(typeof t.color).toBe("string");
      expect(Array.isArray(t.fields)).toBe(true);
    }
    const meta = blob[TYPE_CONFIG_META_KEY] as ResourceTypeDef & { removed_builtins: string[] };
    expect(meta.removed_builtins).toEqual(["application"]);
    expect(meta.connect?.enabled).toBe(false);
  });

  it("drops a tombstone once the builtin's id is saved again", () => {
    const blob = serializeTypeConfig(DEFAULT_RESOURCE_TYPES, ["application"]);
    expect(blob).not.toHaveProperty(TYPE_CONFIG_META_KEY);
  });

  it("the reserved key is one Settings can never mint as a type id", () => {
    // Settings sanitises new ids with this exact replacement.
    const minted = TYPE_CONFIG_META_KEY.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    expect(minted).not.toBe(TYPE_CONFIG_META_KEY);
  });

  it("round-trips types and tombstones", () => {
    const types = { ...DEFAULT_RESOURCE_TYPES };
    delete types.switch;
    const parsed = parseTypeConfig(serializeTypeConfig(types, ["switch"]));
    expect(parsed.types).toEqual(types);
    expect(parsed.removedBuiltins).toEqual(["switch"]);
  });
});

// ── Protocol gate ─────────────────────────────────────────────────────

describe("connectProtocols — the single Connect gate", () => {
  it("keeps today's SSH/RDP behaviour exactly", () => {
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.server)).toEqual(["ssh", "rdp"]);
    // firewall / switch carry `connect.enabled: true` but never had a
    // Connect chip (it was gated on `type === "server"`); still none.
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.firewall)).toEqual([]);
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.switch)).toEqual([]);
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.database)).toEqual([]);
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.application)).toEqual([]);
  });

  it("offers web on website and web_application", () => {
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.website)).toEqual(["web"]);
    expect(connectProtocols(DEFAULT_RESOURCE_TYPES.web_application)).toEqual(["web"]);
    expect(typeSupportsProtocol(DEFAULT_RESOURCE_TYPES.web_application, "web")).toBe(true);
    expect(typeSupportsProtocol(DEFAULT_RESOURCE_TYPES.web_application, "ssh")).toBe(false);
    expect(typeSupportsConnect(DEFAULT_RESOURCE_TYPES.website)).toBe(true);
  });

  it("opts the built-in web types in to form-mode logins, and nothing else", () => {
    // The server denies form mode unless the saved type sets a cap, so a
    // freshly saved type config must carry it for the web types.
    expect(DEFAULT_RESOURCE_TYPES.website.connect?.web_exposure_max).toBe("dom");
    expect(DEFAULT_RESOURCE_TYPES.web_application.connect?.web_exposure_max).toBe("dom");
    const saved = serializeTypeConfig(DEFAULT_RESOURCE_TYPES, []) as Record<string, ResourceTypeDef>;
    expect(saved.web_application.connect?.web_exposure_max).toBe("dom");
    for (const [id, def] of Object.entries(DEFAULT_RESOURCE_TYPES)) {
      if (id === "website" || id === "web_application") continue;
      expect(def.connect?.web_exposure_max, id).toBeUndefined();
    }
    // A saved type still wins as saved: no cap is added to one saved before.
    const { connect: _c, ...rest } = DEFAULT_RESOURCE_TYPES.web_application;
    const legacy: ResourceTypeDef = { ...rest, connect: { protocols: ["web"] } };
    const { types } = parseTypeConfig({ ...DEFAULT_RESOURCE_TYPES, web_application: legacy });
    expect(types.web_application.connect?.web_exposure_max).toBeUndefined();
  });

  it("the enabled toggle wins over the protocol list", () => {
    const t: ResourceTypeDef = {
      ...DEFAULT_RESOURCE_TYPES.web_application,
      connect: { enabled: false, protocols: ["web"] },
    };
    expect(connectProtocols(t)).toEqual([]);
    const s: ResourceTypeDef = { ...DEFAULT_RESOURCE_TYPES.server, connect: { enabled: false } };
    expect(typeSupportsConnect(s)).toBe(false);
  });

  it("an explicit list replaces the legacy default, unknown entries are dropped, a non-array means none", () => {
    expect(
      connectProtocols({ ...DEFAULT_RESOURCE_TYPES.server, connect: { protocols: ["ssh"] } }),
    ).toEqual(["ssh"]);
    expect(
      connectProtocols({
        id: "x",
        label: "X",
        color: "info",
        fields: [],
        connect: { protocols: ["telnet", "web", "web"] as never },
      }),
    ).toEqual(["web"]);
    expect(
      connectProtocols({
        id: "server",
        label: "S",
        color: "info",
        fields: [],
        connect: { protocols: "ssh" as never },
      }),
    ).toEqual([]);
  });

  it("an unknown type id resolves through the same rule", () => {
    expect(connectProtocols(undefined)).toEqual([]);
    expect(connectProtocols({ id: "server", label: "server", color: "neutral", fields: [] })).toEqual([
      "ssh",
      "rdp",
    ]);
  });
});

// ── Strict protocol parsing ───────────────────────────────────────────

describe("strict protocol parsing — unknown never becomes ssh", () => {
  beforeEach(() => mockInvoke.mockReset());

  it("parseSessionProtocol accepts exactly ssh / rdp / web", () => {
    expect(parseSessionProtocol("ssh")).toBe("ssh");
    expect(parseSessionProtocol("rdp")).toBe("rdp");
    expect(parseSessionProtocol("web")).toBe("web");
    for (const bad of ["telnet", "SSH", "", undefined, null, 22, {}]) {
      expect(parseSessionProtocol(bad)).toBeNull();
    }
  });

  it("readProfiles keeps web profiles and drops unknown protocols", () => {
    const out = readProfiles({
      connection_profiles: [
        { id: "p_w", name: "web", protocol: "web", credential_source: { kind: "none" }, web: {} },
        { id: "p_x", name: "x", protocol: "vnc", credential_source: { kind: "secret", secret_id: "s" } },
        { id: "p_y", name: "y", credential_source: { kind: "secret", secret_id: "s" } },
      ],
    });
    expect(out.map((p) => p.id)).toEqual(["p_w"]);
  });

  it("an unknown protocol is never launchable or valid", () => {
    expect(
      isLaunchableProfile({ protocol: "vnc" as never, credential_source: { kind: "secret" } }),
    ).toBe(false);
    expect(
      validateProfile({
        id: "p",
        name: "n",
        protocol: "vnc" as never,
        credential_source: { kind: "secret", secret_id: "s" },
      }),
    ).toBe("Invalid protocol");
  });

  it("openProfileSession throws on an unknown protocol without invoking any session command", async () => {
    await expect(
      openProfileSession({ protocol: "vnc" as never }, { resource_name: "r", profile_id: "p" }),
    ).rejects.toThrow(/Unknown connection protocol/);
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("openProfileSession dispatches each protocol to its own command", async () => {
    mockInvoke.mockResolvedValue({});
    await openProfileSession({ protocol: "ssh" }, { resource_name: "r", profile_id: "p" });
    await openProfileSession({ protocol: "rdp" }, { resource_name: "r", profile_id: "p" });
    await openProfileSession(
      { protocol: "web" },
      {
        resource_name: "r",
        profile_id: "p",
        connect_ticket: "t",
        operator_credential: { username: "u", password: "never-forwarded" },
      },
    );
    expect(mockInvoke.mock.calls.map((c) => c[0])).toEqual([
      "session_open_ssh",
      "session_open_rdp",
      "session_open_web",
    ]);
    // `open` mode releases no credential, so none is ever sent to the host.
    expect(mockInvoke.mock.calls[2][1]).toEqual({
      request: { resource_name: "r", profile_id: "p", connect_ticket: "t" },
    });
  });
});

// ── Web profile validation ────────────────────────────────────────────

describe("validateProfile — web profiles", () => {
  it("accepts an open-mode profile", () => {
    expect(validateProfile(webProfile())).toBeNull();
    expect(
      validateProfile(
        webProfile({
          allowed_origins: ["https://login.microsoftonline.com", "https://sso.example.com:8443/"],
          allow_downloads: true,
          clipboard: "bidirectional",
          window: { width: 1600, height: 900 },
        }),
      ),
    ).toBeNull();
  });

  it("refuses later login modes as not available yet", () => {
    expect(validateProfile(webProfile({ login_mode: "sso" }))).toMatch(/not available yet/);
    expect(validateProfile(webProfile({ login_mode: "magic" as never }))).toMatch(/Unknown login mode/);
  });

  it("refuses credential sources that can't authenticate a web session", () => {
    for (const cs of [
      { kind: "ssh-engine", ssh_mount: "ssh", ssh_role: "r", mode: "ca" },
      { kind: "pki", pki_mount: "pki", pki_role: "r" },
      { kind: "fido2" },
    ] as const) {
      expect(validateProfile(webProfile({}, { credential_source: cs }))).toMatch(
        /can't authenticate a web session/,
      );
    }
  });

  it("open mode needs the `none` source", () => {
    expect(
      validateProfile(webProfile({}, { credential_source: { kind: "secret", secret_id: "web" } })),
    ).toMatch(/releases no credential/);
  });

  it("refuses the Rustion transport and the isolated transport; reads TLS pins strictly (Phase 4)", () => {
    expect(validateProfile(webProfile({}, { kind: "rustion" }))).toMatch(/Rustion/);
    expect(validateProfile(webProfile({ transport: "rustion-isolated" }))).toMatch(/not available yet/);
    expect(validateProfile(webProfile({ tls_pin_sha256: ["abc"] }))).toMatch(/not a SHA-256 public-key pin/);
    expect(validateProfile(webProfile({ tls_pin_sha256: ["sha256:" + "ab".repeat(32)] }))).toBeNull();
  });

  it("enforces the start URL rules", () => {
    expect(validateProfile(webProfile({ start_url: "" }))).toMatch(/required/);
    expect(validateProfile(webProfile({ start_url: "nope" }))).toMatch(/not a valid URL/);
    expect(validateProfile(webProfile({ start_url: "http://fw01.example.com" }))).toMatch(
      /insecure HTTP/,
    );
    expect(
      validateProfile(webProfile({ start_url: "http://fw01.example.com", allow_insecure_http: true })),
    ).toBeNull();
    expect(validateProfile(webProfile({ start_url: "https://admin:pw@fw01.example.com" }))).toMatch(
      /user@/,
    );
    expect(validateProfile(webProfile({ start_url: "https://localhost:8443/" }))).toMatch(/reserved/);
    expect(validateProfile(webProfile({ start_url: "https://ipc.localhost/" }))).toMatch(/reserved/);
    expect(validateProfile(webProfile({ start_url: "file:///etc/passwd" }))).toMatch(/https only/);
  });

  it("enforces the allowed-origin rules", () => {
    const bad = (o: string) => validateProfile(webProfile({ allowed_origins: [o] }));
    expect(bad("https://sso.example.com/saml")).toMatch(/not a bare origin/);
    expect(bad("https://sso.example.com/?x=1")).toMatch(/not a bare origin/);
    expect(bad("https://a@sso.example.com")).toMatch(/userinfo/);
    expect(bad("http://sso.example.com")).toMatch(/insecure HTTP/);
    expect(bad("https://sso.example.com.")).toMatch(/trailing dot/);
    expect(bad("ftp://files.example.com")).toMatch(/https only/);
    expect(bad("*.example.com")).toMatch(/not a valid origin/);
  });

  it("bounds the window size", () => {
    expect(validateProfile(webProfile({ window: { width: 100 } }))).toMatch(/Window width/);
    expect(validateProfile(webProfile({ window: { height: 20000 } }))).toMatch(/Window height/);
    expect(validateProfile(webProfile({ window: { width: 1000.5 } }))).toMatch(/whole number/);
  });

  it("refuses the `none` source on SSH and RDP", () => {
    for (const protocol of ["ssh", "rdp"] as const) {
      expect(
        validateProfile({ id: "p", name: "n", protocol, credential_source: { kind: "none" } }),
      ).toMatch(/need a credential source/);
    }
  });
});

describe("web origin normalisation", () => {
  it("normalises default ports, case and IDNs; keeps explicit ports", () => {
    const ok = (raw: string) => {
      const r = normalizeWebOrigin(raw, false);
      if ("error" in r) throw new Error(r.error);
      return r.origin;
    };
    expect(ok("https://APP.Example.com:443")).toBe("https://app.example.com");
    expect(ok("https://app.example.com/")).toBe("https://app.example.com");
    expect(ok("https://app.example.com:8443")).toBe("https://app.example.com:8443");
    expect(ok("https://bücher.example")).toBe("https://xn--bcher-kva.example");
  });

  it("builds the effective origin set from the start URL plus extras, de-duplicated", () => {
    expect(
      webOriginSet({
        start_url: "https://fw01.example.com/ng/login?next=/",
        allowed_origins: ["https://FW01.example.com:443", "https://sso.example.com"],
        login_mode: "open",
      }),
    ).toEqual(["https://fw01.example.com", "https://sso.example.com"]);
    expect(
      webOriginSet({ start_url: "https://a.example", allowed_origins: ["nope"], login_mode: "open" }),
    ).toBeNull();
  });
});

describe("web profile launchability", () => {
  it("open-mode web profiles launch, including for connect-only callers", () => {
    const p = webProfile();
    expect(isLaunchableProfile(p)).toBe(true);
    // Nothing is resolved anywhere, so connect-only access has nothing to
    // protect; the server's `connect` gate is the check.
    expect(isLaunchableForCaller(p, true, false)).toBe(true);
  });

  it("form-mode web profiles launch with a server-released source", () => {
    for (const kind of ["secret", "ldap", "default-account"] as const) {
      const hint = { protocol: "web" as const, credential_source: { kind } };
      expect(isLaunchableProfile(hint)).toBe(true);
      // The credential is released to the host by the server, never resolved
      // in the GUI, so connect-only callers launch too.
      expect(isLaunchableForCaller(hint, true, false)).toBe(true);
    }
    const form = webProfile(
      {
        login_mode: "form",
        recipe: {
          version: 1,
          steps: [{ when_url: "https://a.example/login*", actions: [{ fill: "#u", value: "username" }] }],
          success_when: { url: "https://a.example/home*" },
        },
      },
      { credential_source: { kind: "secret", secret_id: "web" } },
    );
    expect(isLaunchableWebProfile(form)).toBe(true);
    // No recipe, the `none` source, or a later transport: not launchable.
    expect(isLaunchableWebProfile({ ...form, web: { ...form.web!, recipe: undefined } })).toBe(false);
    expect(isLaunchableWebProfile({ ...form, credential_source: { kind: "none" } })).toBe(false);
    expect(isLaunchableWebProfile({ ...form, web: { ...form.web!, transport: "rustion-isolated" } })).toBe(false);
    expect(isLaunchableWebProfile(webProfile())).toBe(true);
    expect(isLaunchableWebProfile(webProfile({}, { credential_source: { kind: "secret", secret_id: "x" } }))).toBe(
      false,
    );
  });

  it("web profiles with a source that can't sign in, or a Rustion transport, don't launch", () => {
    for (const kind of ["ssh-engine", "pki", "fido2"] as const) {
      expect(isLaunchableProfile({ protocol: "web", credential_source: { kind } })).toBe(false);
    }
    expect(
      isLaunchableProfile({ protocol: "web", kind: "rustion", credential_source: { kind: "none" } }),
    ).toBe(false);
    expect(
      isLaunchableProfile({ protocol: "web", kind: "rustion", credential_source: { kind: "secret" } }),
    ).toBe(false);
  });

  it("webRecipeTest calls the dry-run command with the recipe and no credential", async () => {
    mockInvoke.mockResolvedValue({ recipe_hash: "sha256:x", report: {} });
    const recipe = {
      version: 1 as const,
      steps: "auto" as const,
      success_when: { url: "https://a.example/home*" },
    };
    await webRecipeTest({ url: "https://a.example/login", recipe, allowed_origins: [] });
    expect(mockInvoke).toHaveBeenLastCalledWith("web_recipe_test", {
      request: { url: "https://a.example/login", recipe, allowed_origins: [] },
    });
  });

  it("blankWebProfile pre-fills the start URL from the resource's url field", () => {
    const p = blankWebProfile("  https://grafana.example.com/  ");
    expect(p.protocol).toBe("web");
    expect(p.credential_source).toEqual({ kind: "none" });
    expect(p.web?.start_url).toBe("https://grafana.example.com/");
    expect(p.web?.login_mode).toBe("open");
    expect(validateProfile(p)).toBeNull();
  });
});

// ── http-auth (Phase 3) ───────────────────────────────────────────────

describe("http-auth web profiles", () => {
  const secret = { kind: "secret", secret_id: "admin" } as const;
  const httpAuth = (web: Partial<WebProfileSettings> = {}, over: Partial<ConnectionProfile> = {}) =>
    webProfile({ start_url: "https://bmc.example.com/", login_mode: "http-auth", ...web }, {
      credential_source: secret,
      ...over,
    });

  it("saves with a secret or a releasing LDAP source and no recipe", () => {
    expect(validateProfile(httpAuth())).toBeNull();
    expect(
      validateProfile(
        httpAuth({}, { credential_source: { kind: "ldap", ldap_mount: "openldap", bind_mode: "static_role", static_role: "bmc" } }),
      ),
    ).toBeNull();
    expect(
      validateProfile(
        httpAuth(
          {},
          { credential_source: { kind: "ldap", ldap_mount: "openldap", bind_mode: "library_set", library_set: "bmc-admins" } },
        ),
      ),
    ).toBeNull();
    expect(isLaunchableWebProfile(httpAuth())).toBe(true);
  });

  it("refuses what the server refuses", () => {
    expect(validateProfile(httpAuth({}, { credential_source: { kind: "default-account" } }))).toMatch(
      /username only/,
    );
    expect(validateProfile(httpAuth({}, { credential_source: { kind: "none" } }))).toMatch(/releases nothing/);
    expect(
      validateProfile(httpAuth({}, { credential_source: { kind: "ldap", ldap_mount: "openldap", bind_mode: "operator" } })),
    ).toMatch(/operator/);
    expect(validateProfile(httpAuth({}, { credential_source: { kind: "secret", secret_id: "" } }))).toMatch(
      /Pick a credential secret/,
    );
    const recipe = {
      version: 1 as const,
      steps: "auto" as const,
      success_when: { selector: "#ok" },
    };
    expect(validateProfile(httpAuth({ recipe }))).toMatch(/only applies to the form login mode/);
    expect(isLaunchableWebProfile(httpAuth({ recipe }))).toBe(false);
    expect(isLaunchableWebProfile(httpAuth({}, { credential_source: { kind: "default-account" } }))).toBe(false);
    // The shared rules hold: https only unless opted in, pins read strictly.
    expect(validateProfile(httpAuth({ start_url: "http://bmc.example.com/" }))).toMatch(/insecure HTTP/);
    expect(validateProfile(httpAuth({ tls_pin_sha256: ["abc"] }))).toMatch(/not a SHA-256 public-key pin/);
    expect(validateProfile(httpAuth({ tls_pin_sha256: ["sha256:" + "cd".repeat(32)] }))).toBeNull();
    // The server's strict origin reading (no percent-encoded hosts).
    expect(validateProfile(httpAuth({ allowed_origins: ["https://bmc%2Eexample.com"] }))).not.toBeNull();
  });

  it("switching to http-auth drops the recipe and keeps only a source with a password", () => {
    const form = webProfile(
      {
        login_mode: "form",
        recipe: { version: 1, steps: "auto", success_when: { selector: "#ok" } },
      },
      { credential_source: secret },
    );
    const toHttp = setWebLoginMode(form, "http-auth");
    expect(toHttp.web?.login_mode).toBe("http-auth");
    expect(toHttp.web?.recipe).toBeUndefined();
    expect(toHttp.credential_source).toEqual(secret);
    const fromDefault = setWebLoginMode(
      webProfile({ login_mode: "form" }, { credential_source: { kind: "default-account" } }),
      "http-auth",
    );
    expect(fromDefault.credential_source).toEqual({ kind: "secret", secret_id: "" });
    expect(setWebLoginMode(webProfile(), "http-auth").credential_source).toEqual({ kind: "secret", secret_id: "" });
  });

  it("needs a `handler` cap, and `dom` over plain http", () => {
    const required = requiredExposureForLoginMode("http-auth");
    expect(required).toBe("handler");
    const verdict = (cap: string | undefined, allowInsecureHttp = false) =>
      evaluateWebExposure({
        typeDef: cap === undefined ? null : { connect: { web_exposure_max: cap } },
        resource: {},
        required: required!,
        heuristic: false,
        allowInsecureHttp,
      }).refusal?.code ?? null;
    for (const cap of ["handler", "proxy", "dom"]) expect(verdict(cap)).toBeNull();
    for (const cap of ["none", "isolated"]) expect(verdict(cap)).toBe("exposure_cap_exceeded");
    expect(verdict(undefined)).toBe("exposure_not_permitted");
    expect(verdict("handler", true)).toBe("insecure_http_not_allowed");
    expect(verdict("proxy", true)).toBe("insecure_http_not_allowed");
    expect(verdict("dom", true)).toBeNull();
  });
});
