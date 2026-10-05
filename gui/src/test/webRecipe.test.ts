/**
 * Web Application Connect, Phase 2 (features/web-application-connect.md,
 * T96): the GUI's port of the server's recipe reader, the vendor presets, the
 * strict JSON import, the form-profile save checks and the exposure policy
 * mirror. The cases follow the Rust tests in
 * crates/bv-engine-resource/src/connect_web/{recipe,profile,exposure}.rs.
 */
import { describe, it, expect } from "vitest";
import {
  MAX_ACTIONS_PER_STEP,
  MAX_LITERAL_LEN,
  MAX_RECIPE_JSON_BYTES,
  MAX_SELECTOR_LEN,
  MAX_STEPS,
  MAX_URL_PATTERN_LEN,
  blankRecipe,
  checkRecipeOrigins,
  heuristicRecipe,
  originKey,
  parseRecipeJson,
  recipeError,
  recipeNeeds,
  recipeToJson,
  splitUrl,
  validateWebRecipe,
} from "../lib/webRecipe";
import { WEB_RECIPE_PRESETS, findPreset, presetLabel } from "../lib/webRecipePresets";
import { formCredentialSourceError, recipeBaseOrigin, strictOriginSet } from "../lib/webFormProfile";
import { evaluateWebExposure, savedTypeEntry } from "../lib/webExposure";
import { setWebLoginMode, validateProfile } from "../lib/connectionProfiles";
import type { ConnectionProfile, WebLoginRecipe, WebProfileSettings } from "../lib/types";

const O = "https://fw01.example.com";

function fortigate(): Record<string, unknown> {
  return {
    version: 1,
    vendor: "fortigate",
    steps: [
      {
        when_url: `${O}/login*`,
        actions: [
          { fill: "input[name=username]", value: "username" },
          { fill: "input[name=secretkey]", value: "password" },
          { click: "button#login_button" },
        ],
      },
      {
        when_url: `${O}/login/2fa*`,
        actions: [
          { fill: "input[autocomplete=one-time-code]", value: "totp" },
          { submit: "form" },
        ],
      },
    ],
    success_when: { url: `${O}/ng/*` },
    failure_when: { selector: ".error-message, .login-error" },
    timeout_secs: 30,
    pause_for_operator: ["captcha"],
  };
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function at(v: unknown): string | null {
  const r = validateWebRecipe(v);
  return r.ok ? null : r.issue.at;
}

describe("validateWebRecipe — mirrors WebLoginRecipe::parse", () => {
  it("accepts the spec example and reports what it needs", () => {
    const r = validateWebRecipe(fortigate());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const n = recipeNeeds(r.recipe);
    expect(n).toEqual({
      heuristic: false,
      username: true,
      password: true,
      totp: true,
      totpSteps: [1],
      stepCount: 2,
    });
  });

  it("recognises heuristic mode", () => {
    const r = validateWebRecipe({ version: 1, steps: "auto", success_when: { selector: "#dashboard" } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(recipeNeeds(r.recipe)).toMatchObject({ heuristic: true, totpSteps: [0], stepCount: 1 });
    // The generated heuristic recipe is itself valid.
    expect(validateWebRecipe(heuristicRecipe(O)).ok).toBe(true);
  });

  it("refuses unknown versions, a missing version and unknown keys at every level, naming the field", () => {
    const v2 = fortigate();
    v2.version = 2;
    expect(at(v2)).toBe("version");
    expect(recipeError(v2)).toMatch(/version 2 is not supported/);

    const v15 = fortigate();
    v15.version = 1.5;
    expect(at(v15)).toBe("version");

    const none = fortigate();
    delete none.version;
    expect(at(none)).toBe("version");

    const script = fortigate();
    script.script = "alert(1)";
    expect(at(script)).toBe("script");

    const frame = clone(fortigate()) as { steps: Record<string, unknown>[] };
    frame.steps[0].frame_origin = "https://x";
    expect(at(frame)).toBe("steps[0].frame_origin");

    const ev = clone(fortigate()) as { steps: { actions: Record<string, unknown>[] }[] };
    ev.steps[0].actions[0].eval = "x";
    expect(at(ev)).toBe("steps[0].actions[0].eval");

    const title = clone(fortigate()) as { success_when: Record<string, unknown> };
    title.success_when.title = "x";
    expect(at(title)).toBe("success_when.title");
  });

  it("refuses malformed values", () => {
    const ok = { version: 1, steps: "auto", success_when: { selector: "x" } };
    const cases: [unknown, string][] = [
      ["not an object", ""],
      [null, ""],
      [[], ""],
      [{ version: 1, steps: "manual", success_when: { selector: "x" } }, "steps"],
      [{ version: 1, steps: [], success_when: { selector: "x" } }, "steps"],
      [{ version: 1, steps: "auto" }, "success_when"],
      [{ version: 1, steps: "auto", success_when: {} }, "success_when"],
      [{ version: 1, steps: "auto", success_when: null }, "success_when"],
      [{ ...ok, vendor: "acme" }, "vendor"],
      [{ ...ok, vendor: null }, "vendor"],
      [{ ...ok, timeout_secs: 0 }, "timeout_secs"],
      [{ ...ok, timeout_secs: 61 }, "timeout_secs"],
      [{ ...ok, timeout_secs: -1 }, "timeout_secs"],
      [{ ...ok, timeout_secs: 2.5 }, "timeout_secs"],
      [{ ...ok, timeout_secs: "30" }, "timeout_secs"],
      [{ ...ok, timeout_secs: null }, "timeout_secs"],
      [{ ...ok, pause_for_operator: ["sms"] }, "pause_for_operator[0]"],
      [{ ...ok, pause_for_operator: "captcha" }, "pause_for_operator"],
      [{ ...ok, failure_when: null }, "failure_when"],
      [{ ...ok, failure_when: {} }, "failure_when"],
    ];
    for (const [v, where] of cases) expect(at(v), JSON.stringify(v)).toBe(where);
  });

  it("holds timeout_secs to 1..=60 and defaults when absent", () => {
    const base = { version: 1, steps: "auto", success_when: { selector: "x" } };
    expect(validateWebRecipe(base).ok).toBe(true);
    for (const n of [1, 30, 60]) expect(validateWebRecipe({ ...base, timeout_secs: n }).ok, String(n)).toBe(true);
    for (const n of [0, 61, 1000]) expect(at({ ...base, timeout_secs: n }), String(n)).toBe("timeout_secs");
  });

  it("holds the step and action counts", () => {
    const step = { when_url: `${O}/l`, actions: [{ click: "a" }] };
    const base = (steps: unknown) => ({ version: 1, steps, success_when: { selector: "x" } });
    expect(validateWebRecipe(base(Array(MAX_STEPS).fill(step))).ok).toBe(true);
    expect(at(base(Array(MAX_STEPS + 1).fill(step)))).toBe("steps");
    const many = (n: number) => base([{ when_url: `${O}/l`, actions: Array(n).fill({ click: "a" }) }]);
    expect(validateWebRecipe(many(MAX_ACTIONS_PER_STEP)).ok).toBe(true);
    expect(at(many(MAX_ACTIONS_PER_STEP + 1))).toBe("steps[0].actions");
    expect(at(many(0))).toBe("steps[0].actions");
    expect(at(base([{ when_url: `${O}/l` }]))).toBe("steps[0].actions");
  });

  it("requires exactly one known verb per action and an enum fill value", () => {
    const withAction = (a: unknown) => {
      const v = clone(fortigate()) as { steps: { actions: unknown[] }[] };
      v.steps[0].actions = [a];
      return v;
    };
    // Two verbs, none, and `value` on a non-fill.
    expect(at(withAction({ fill: "a", click: "b", value: "username" }))).toBe("steps[0].actions[0]");
    expect(at(withAction({ value: "username" }))).toBe("steps[0].actions[0]");
    expect(at(withAction({ click: "a", value: "username" }))).toBe("steps[0].actions[0].value");
    expect(at(withAction("fill"))).toBe("steps[0].actions[0]");
    // `value` is an enum.
    expect(at(withAction({ fill: "a", value: "hunter2" }))).toBe("steps[0].actions[0].value");
    expect(at(withAction({ fill: "a", value: "totp_seed" }))).toBe("steps[0].actions[0].value");
    expect(at(withAction({ fill: "a", value: "literal:" }))).toBe("steps[0].actions[0].value");
    expect(at(withAction({ fill: "a" }))).toBe("steps[0].actions[0].value");
    expect(at(withAction({ fill: "a", value: 7 }))).toBe("steps[0].actions[0].value");
    expect(at(withAction({ fill: "a", value: "literal:x".padEnd(MAX_LITERAL_LEN + 10, "x") }))).toBe(
      "steps[0].actions[0].value",
    );
    expect(validateWebRecipe(withAction({ fill: "#realm", value: "literal:CORP" })).ok).toBe(true);
    expect(validateWebRecipe(withAction({ wait: "#ready" })).ok).toBe(true);
    // Selectors are bounded data.
    expect(at(withAction({ click: "" }))).toBe("steps[0].actions[0].click");
    expect(at(withAction({ click: "   " }))).toBe("steps[0].actions[0].click");
    expect(at(withAction({ click: "a\nb" }))).toBe("steps[0].actions[0].click");
    expect(at(withAction({ click: "a\u0085b" }))).toBe("steps[0].actions[0].click");
    expect(at(withAction({ click: "a".repeat(MAX_SELECTOR_LEN + 1) }))).toBe("steps[0].actions[0].click");
    expect(at(withAction({ click: "a".repeat(MAX_SELECTOR_LEN) }))).toBeNull();
    expect(at(withAction({ click: 7 }))).toBe("steps[0].actions[0].click");
  });

  it("counts selector and URL lengths in UTF-8 bytes like the server", () => {
    const sel = (s: string) => ({ version: 1, steps: "auto", success_when: { selector: s } });
    // 171 three-byte characters = 513 bytes, 171 characters.
    expect(at(sel("€".repeat(171)))).toBe("success_when.selector");
    expect(at(sel("€".repeat(170)))).toBeNull();
    const longUrl = `${O}/${"a".repeat(MAX_URL_PATTERN_LEN)}`;
    expect(at({ version: 1, steps: "auto", success_when: { url: longUrl } })).toBe("success_when.url");
  });

  it("requires a literal origin in every URL pattern", () => {
    const withUrl = (u: unknown) => {
      const v = clone(fortigate()) as { steps: { when_url: unknown }[] };
      v.steps[0].when_url = u;
      return validateWebRecipe(v);
    };
    for (const bad of [
      "https://*.example.com/login",
      "https://user@fw01.example.com/login",
      "https:\\\\evil.example/",
      "javascript:alert(1)",
      "ftp://fw01.example.com/",
      "https://fw01.example.com /x",
      "https://fw01.example.com/\tx",
      "HTTPS://fw01.example.com/",
      "/relative",
      "",
      7,
    ]) {
      expect(withUrl(bad).ok, String(bad)).toBe(false);
    }
    expect(withUrl("https://fw01.example.com/login?next=*").ok).toBe(true);
    expect(withUrl("http://fw01.example.com/login").ok).toBe(true); // scheme is the origin check's job
  });

  it("treats undefined as absent but null as a present, wrong value", () => {
    const base = { version: 1, steps: "auto", success_when: { selector: "x" } };
    expect(validateWebRecipe({ ...base, failure_when: undefined, vendor: undefined }).ok).toBe(true);
    expect(at({ ...base, vendor: null })).toBe("vendor");
  });

  it("does not trust inherited properties or a hostile __proto__ key", () => {
    // JSON.parse makes `__proto__` an own data property; it is an unknown key.
    const hostile = JSON.parse(
      '{"version":1,"steps":"auto","success_when":{"selector":"x"},"__proto__":{"polluted":true}}',
    );
    expect(at(hostile)).toBe("__proto__");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    // An inherited `steps` does not count as the object's own.
    const inherited = Object.create({ version: 1, steps: "auto", success_when: { selector: "x" } });
    expect(at(inherited)).toBe("version");
  });
});

describe("originKey / splitUrl — mirror origin_key and split_url", () => {
  const key = (s: string, a: string, http = false) => {
    const r = originKey(s, a, http);
    return "origin" in r ? r.origin : null;
  };

  it("normalises and drops default ports", () => {
    expect(key("https", "FW01.Example.com:443")).toBe("https://fw01.example.com");
    expect(key("https", "fw01.example.com:0443")).toBe("https://fw01.example.com");
    expect(key("https", "fw01.example.com:8443")).toBe("https://fw01.example.com:8443");
    expect(key("https", "[::1]:8443")).toBe("https://[::1]:8443");
    expect(key("http", "app:80", true)).toBe("http://app");
  });

  it("refuses every ambiguous shape the server refuses", () => {
    for (const bad of [
      "fw01.example.com.",
      "bücher.example",
      "exa%6dple.com",
      "a@b",
      "*.x",
      "h:",
      "h:99999",
      "h:12a",
      "[::1",
      "[]",
      "a b",
      "",
      ":443",
    ]) {
      expect(key("https", bad), bad).toBeNull();
    }
    expect(key("http", "app")).toBeNull(); // needs allow_insecure_http
    expect(key("ftp", "app", true)).toBeNull();
  });

  it("splits a URL without interpreting it", () => {
    expect(splitUrl("https://a.example/x?y#z")).toEqual({ scheme: "https", authority: "a.example", rest: "/x?y#z" });
    expect(splitUrl("https://a.example?x")).toEqual({ scheme: "https", authority: "a.example", rest: "?x" });
    expect(typeof splitUrl("a.example")).toBe("string");
    expect(typeof splitUrl("https://a b")).toBe("string");
    expect(typeof splitUrl("https://a\\b")).toBe("string");
    expect(typeof splitUrl("")).toBe("string");
  });
});

describe("checkRecipeOrigins — mirrors check_origins", () => {
  const recipe = (v: unknown): WebLoginRecipe => {
    const r = validateWebRecipe(v);
    if (!r.ok) throw new Error(JSON.stringify(r.issue));
    return r.recipe;
  };

  it("enforces the profile's origin set and scheme", () => {
    const r = recipe(fortigate());
    expect(checkRecipeOrigins(r, [O], false)).toBeNull();
    expect(checkRecipeOrigins(r, ["https://fw02.example.com"], false)?.at).toBe("steps[0].when_url");

    const v = fortigate();
    (v.success_when as Record<string, unknown>).url = "http://fw01.example.com/ng/*";
    const plain = recipe(v);
    // Plain http is refused without allow_insecure_http ...
    expect(checkRecipeOrigins(plain, [O], false)?.at).toBe("success_when.url");
    // ... and with it, the http origin must itself be in the set.
    expect(checkRecipeOrigins(plain, [O], true)).not.toBeNull();
    expect(checkRecipeOrigins(plain, [O, "http://fw01.example.com"], true)).toBeNull();
  });

  it("names failure_when.url too, and ignores selectors", () => {
    const v = fortigate();
    v.failure_when = { url: "https://other.example.com/err" };
    expect(checkRecipeOrigins(recipe(v), [O], false)?.at).toBe("failure_when.url");
    expect(checkRecipeOrigins(recipe(heuristicRecipe(O)), [O], false)).toBeNull();
  });
});

describe("vendor presets", () => {
  it("covers the seven documented vendors, all marked unverified", () => {
    expect(WEB_RECIPE_PRESETS.map((p) => p.id).sort()).toEqual(
      ["fortigate", "grafana", "idrac", "ilo", "jenkins", "pfsense", "vcenter"].sort(),
    );
    for (const p of WEB_RECIPE_PRESETS) {
      expect(p.unverified, p.id).toBe(true);
      expect(presetLabel(p), p.id).toMatch(/unverified against a live appliance/);
      expect(p.note.length, p.id).toBeGreaterThan(20);
      expect(findPreset(p.id)).toBe(p);
    }
  });

  it("every preset passes the validator and the origin check, on several origins", () => {
    for (const origin of [
      "https://fw01.example.com",
      "https://fw01.example.com:8443",
      "https://[2001:db8::1]:9443",
      "https://10.0.0.5",
    ]) {
      // The origin a profile reads from its start URL is the one presets use.
      expect(recipeBaseOrigin({ start_url: `${origin}/` })).toBe(origin);
      for (const p of WEB_RECIPE_PRESETS) {
        const built = p.build(origin);
        const parsed = validateWebRecipe(built);
        expect(parsed.ok, `${p.id} @ ${origin}: ${recipeError(built)}`).toBe(true);
        if (!parsed.ok) continue;
        expect(parsed.recipe.vendor, p.id).toBe(p.id);
        expect(checkRecipeOrigins(parsed.recipe, [origin], false), `${p.id} @ ${origin}`).toBeNull();
        // Explicit steps that fill a username and a password, no TOTP.
        const needs = recipeNeeds(parsed.recipe);
        expect(needs, p.id).toMatchObject({ heuristic: false, username: true, password: true, totp: false });
      }
    }
  });

  it("every preset saves as a form profile on a secret source", () => {
    for (const p of WEB_RECIPE_PRESETS) {
      const profile: ConnectionProfile = {
        id: "p",
        name: p.label,
        protocol: "web",
        credential_source: { kind: "secret", secret_id: "admin" },
        web: {
          start_url: "https://fw01.example.com/",
          allowed_origins: [],
          login_mode: "form",
          recipe: p.build("https://fw01.example.com"),
        },
      };
      expect(validateProfile(profile), p.id).toBeNull();
    }
  });
});

describe("recipe import — strict, data only", () => {
  it("round-trips an exported recipe", () => {
    const text = recipeToJson(fortigate());
    const r = parseRecipeJson(text);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.recipe).toEqual(fortigate());
  });

  it("refuses malformed and hostile text with a message, never throws", () => {
    for (const text of ["", "{", "not json", "[1,2", "undefined", "{'version':1}"]) {
      const r = parseRecipeJson(text);
      expect(r.ok, text).toBe(false);
    }
    const arr = parseRecipeJson("[]");
    expect(arr.ok).toBe(false);
    const nul = parseRecipeJson("null");
    expect(nul.ok).toBe(false);
    const str = parseRecipeJson('"alert(1)"');
    expect(str.ok).toBe(false);
  });

  it("refuses script-shaped, prototype-shaped and unknown content", () => {
    const hostile = [
      '{"version":1,"steps":"auto","success_when":{"selector":"x"},"on_load":"alert(1)"}',
      '{"version":1,"steps":"auto","success_when":{"selector":"x"},"__proto__":{"x":1}}',
      '{"version":1,"steps":"auto","success_when":{"selector":"x"},"constructor":{"prototype":{}}}',
      '{"version":1,"steps":[{"when_url":"https://a.example/","actions":[{"eval":"alert(1)"}]}],"success_when":{"selector":"x"}}',
      '{"version":1,"steps":[{"when_url":"javascript:alert(1)","actions":[{"click":"a"}]}],"success_when":{"selector":"x"}}',
      '{"version":1,"steps":[{"when_url":"https://a.example/","actions":[{"fill":"a","value":"${process.env}"}]}],"success_when":{"selector":"x"}}',
      '{"version":2,"steps":"auto","success_when":{"selector":"x"}}',
    ];
    for (const text of hostile) {
      const r = parseRecipeJson(text);
      expect(r.ok, text).toBe(false);
    }
    // Text is never evaluated: a function-looking string is just a refused value.
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });

  it("refuses oversize text before parsing it", () => {
    const r = parseRecipeJson(" ".repeat(MAX_RECIPE_JSON_BYTES + 1));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issue.reason).toMatch(/larger than/);
  });
});

// ── form profiles ────────────────────────────────────────────────────────────

function formProfile(over: Partial<WebProfileSettings> = {}, cs: ConnectionProfile["credential_source"] = { kind: "secret", secret_id: "admin" }): ConnectionProfile {
  return {
    id: "p_web",
    name: "Console",
    protocol: "web",
    credential_source: cs,
    web: {
      start_url: `${O}/login`,
      allowed_origins: [],
      login_mode: "form",
      recipe: validateWebRecipe(fortigate()).ok ? (fortigate() as unknown as WebLoginRecipe) : undefined,
      ...over,
    },
  };
}

describe("validateProfile — form-mode web profiles now save", () => {
  it("accepts a form profile with a recipe and a secret source", () => {
    expect(validateProfile(formProfile())).toBeNull();
  });

  it("accepts every source the server accepts for form", () => {
    const noTotp = blankRecipe(O);
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "openldap/", bind_mode: "static_role", static_role: "fw-admin" })),
    ).toBeNull();
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "openldap", bind_mode: "library_set", library_set: "fw-admins" })),
    ).toBeNull();
    // default-account supplies a username only.
    const userOnly: WebLoginRecipe = {
      version: 1,
      steps: [{ when_url: `${O}/login*`, actions: [{ fill: "#u", value: "username" }, { click: "#next" }] }],
      success_when: { url: `${O}/home*` },
    };
    expect(validateProfile(formProfile({ recipe: userOnly }, { kind: "default-account" }))).toBeNull();
  });

  it("needs a recipe and says so", () => {
    expect(validateProfile(formProfile({ recipe: undefined }))).toMatch(/needs a login recipe/);
  });

  it("names the recipe field the server would refuse", () => {
    const bad = clone(fortigate()) as { steps: { actions: Record<string, unknown>[] }[] };
    bad.steps[0].actions[0].value = "hunter2";
    expect(validateProfile(formProfile({ recipe: bad as unknown as WebLoginRecipe }))).toMatch(
      /steps\[0\]\.actions\[0\]\.value/,
    );
    const slow = { ...(fortigate() as object), timeout_secs: 61 } as unknown as WebLoginRecipe;
    expect(validateProfile(formProfile({ recipe: slow }))).toMatch(/timeout_secs/);
    const v3 = { ...(fortigate() as object), version: 3 } as unknown as WebLoginRecipe;
    expect(validateProfile(formProfile({ recipe: v3 }))).toMatch(/version 3 is not supported/);
  });

  it("refuses a recipe URL off the profile's origins, and plain http", () => {
    expect(validateProfile(formProfile({ start_url: "https://other.example.com/login" }))).toMatch(
      /steps\[0\]\.when_url.*origin is not/,
    );
    // Adding the origin to the allow-list fixes it.
    expect(
      validateProfile(formProfile({ start_url: "https://other.example.com/login", allowed_origins: [O] })),
    ).toBeNull();
    const http = { ...(fortigate() as object), success_when: { url: "http://fw01.example.com/ng/*" } } as unknown as WebLoginRecipe;
    expect(validateProfile(formProfile({ recipe: http }))).toMatch(/success_when\.url.*plain http/);
  });

  it("reads origins the server's way, not the browser's", () => {
    // The browser punycodes a Unicode host; the server refuses it.
    expect(validateProfile(formProfile({ start_url: "https://bücher.example/login" }))).toMatch(/punycode/);
    expect(validateProfile(formProfile({ start_url: `${O}./login` }))).toMatch(/Start URL/);
    expect(validateProfile(formProfile({ allowed_origins: ["https://sso.example.com/path"] }))).toMatch(/bare origin/);
    expect(validateProfile(formProfile({ allowed_origins: ["https://*.example.com"] }))).toMatch(/Allowed origin 1/);
    const set = strictOriginSet({ start_url: `${O}:443/x`, allowed_origins: ["https://SSO.example.com:443/", O], login_mode: "form" });
    expect(set).toEqual({ origins: [O, "https://sso.example.com"] });
    // The server reads the scheme case-sensitively, so an upper-case one is refused here too.
    expect(validateProfile(formProfile({ allowed_origins: ["HTTPS://sso.example.com"] }))).toMatch(/scheme must be/);
  });

  it("holds the credential source to what the server can release", () => {
    expect(validateProfile(formProfile({}, { kind: "none" }))).toMatch(/releases nothing/);
    expect(validateProfile(formProfile({}, { kind: "secret", secret_id: "" }))).toMatch(/Pick a credential secret/);
    expect(validateProfile(formProfile({}, { kind: "secret", secret_id: "a/b" }))).toMatch(/single secret key name/);
    expect(validateProfile(formProfile({}, { kind: "secret", secret_id: ".." }))).toMatch(/single secret key name/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", fields: { totp_seed: "a/b" } })),
    ).toMatch(/fields\.totp_seed/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", fields: { token: "x" } as never })),
    ).toMatch(/fields\.token is not a field/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", totp: { digits: 7 as never } })),
    ).toMatch(/digits must be 6 or 8/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", totp: { period: 45 as never } })),
    ).toMatch(/period must be 30 or 60/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", totp: { algorithm: "MD5" as never } })),
    ).toMatch(/SHA1, SHA256 or SHA512/);
    expect(
      validateProfile(formProfile({}, { kind: "secret", secret_id: "s", totp: { skew: 1 } as never })),
    ).toMatch(/totp\.skew is not a field/);
    const noTotp = blankRecipe(O);
    expect(validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "openldap/", bind_mode: "operator" }))).toMatch(
      /operator.*nothing for the server to release/,
    );
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "/abs", bind_mode: "static_role", static_role: "ab" })),
    ).toMatch(/ldap_mount/);
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "ldap/../x", bind_mode: "static_role", static_role: "ab" })),
    ).toMatch(/ldap_mount/);
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "ldap/", bind_mode: "static_role", static_role: "a" })),
    ).toMatch(/static_role must be an LDAP role/);
    expect(
      validateProfile(formProfile({ recipe: noTotp }, { kind: "ldap", ldap_mount: "ldap/", bind_mode: "library_set", library_set: "-bad" })),
    ).toMatch(/library_set/);
    // Sources a web profile never accepts.
    expect(validateProfile(formProfile({}, { kind: "fido2" }))).toMatch(/can't authenticate a web session/);
  });

  it("refuses a recipe the source can never supply", () => {
    // fortigate() fills a password and a totp.
    expect(validateProfile(formProfile({}, { kind: "default-account" }))).toMatch(/username only/);
    const totpOnly: WebLoginRecipe = {
      version: 1,
      steps: [{ when_url: `${O}/login*`, actions: [{ fill: "#c", value: "totp" }] }],
      success_when: { url: `${O}/home*` },
    };
    const ldap = { kind: "ldap", ldap_mount: "ldap/", bind_mode: "static_role", static_role: "ab" } as const;
    expect(validateProfile(formProfile({ recipe: totpOnly }, ldap))).toMatch(/only a `secret` source/);
    expect(validateProfile(formProfile({ recipe: totpOnly }, { kind: "default-account" }))).toMatch(/only a `secret` source/);
    // Heuristic recipes want each value only if the source has it.
    expect(validateProfile(formProfile({ recipe: heuristicRecipe(O) }, { kind: "default-account" }))).toBeNull();
    expect(
      formCredentialSourceError({ kind: "default-account" }, heuristicRecipe(O)),
    ).toBeNull();
  });

  it("still holds form profiles to the shared web rules", () => {
    expect(validateProfile(formProfile({ tls_pin_sha256: ["aa"] }))).toMatch(/pinning/);
    expect(validateProfile(formProfile({ transport: "rustion-isolated" }))).toMatch(/not available yet/);
    expect(validateProfile(formProfile({ window: { width: 10 } }))).toMatch(/Window width/);
    expect(validateProfile({ ...formProfile(), kind: "rustion" })).toMatch(/Rustion/);
    expect(validateProfile(formProfile({ start_url: "https://localhost/login" }))).toMatch(/reserved/);
  });

  it("keeps a recipe off open-mode profiles", () => {
    const p = formProfile({ login_mode: "open" }, { kind: "none" });
    expect(validateProfile(p)).toMatch(/only applies to the form login mode/);
  });

  it("switching the login mode moves the credential source and recipe with it", () => {
    const open: ConnectionProfile = {
      id: "p",
      name: "x",
      protocol: "web",
      credential_source: { kind: "none" },
      web: { start_url: `${O}/`, allowed_origins: [], login_mode: "open" },
    };
    const toForm = setWebLoginMode(open, "form");
    expect(toForm.web?.login_mode).toBe("form");
    expect(toForm.credential_source).toEqual({ kind: "secret", secret_id: "" });
    // A real source survives a switch to form, and a recipe is dropped going to open.
    const withRecipe = formProfile({}, { kind: "ldap", ldap_mount: "l/", bind_mode: "static_role", static_role: "ab" });
    expect(setWebLoginMode(withRecipe, "form").credential_source.kind).toBe("ldap");
    const back = setWebLoginMode(withRecipe, "open");
    expect(back.credential_source).toEqual({ kind: "none" });
    expect(back.web?.recipe).toBeUndefined();
    expect(withRecipe.web?.recipe).toBeDefined(); // not mutated
  });
});

// ── exposure policy ──────────────────────────────────────────────────────────

describe("evaluateWebExposure — mirrors exposure.rs", () => {
  const domType = { id: "web_application", fields: [], connect: { web_exposure_max: "dom" } };
  const check = (
    typeDef: unknown,
    resource: Record<string, unknown> = {},
    over: { heuristic?: boolean; http?: boolean } = {},
  ) =>
    evaluateWebExposure({
      typeDef,
      resource,
      required: "dom",
      heuristic: over.heuristic ?? false,
      allowInsecureHttp: over.http ?? false,
    });

  it("denies unless the saved type opts in", () => {
    // Unsaved / unknown type.
    const unsaved = check(null);
    expect(unsaved.refusal?.code).toBe("exposure_not_permitted");
    expect(unsaved.refusal?.message).toMatch(/not in the saved resource type configuration/);
    expect(unsaved.refusal?.fixAt).toBe("type");
    // Saved but no cap, or no connect block.
    for (const def of [{ id: "server", fields: [] }, { id: "server", connect: { enabled: true } }]) {
      const v = check(def);
      expect(v.refusal?.code).toBe("exposure_not_permitted");
      expect(v.refusal?.message).toMatch(/does not set `connect.web_exposure_max`/);
    }
    // The resource tier alone cannot opt in.
    expect(check(null, { web_exposure_max: "dom" }).refusal?.code).toBe("exposure_not_permitted");
    // Opted in.
    expect(check(domType)).toEqual({ refusal: null, cap: "dom" });
  });

  it("lets the resource tier only lower the cap", () => {
    const v = check(domType, { web_exposure_max: "handler" });
    expect(v.refusal?.code).toBe("exposure_cap_exceeded");
    expect(v.refusal?.fixAt).toBe("resource");
    expect(v.refusal?.message).toMatch(/resource tier caps web exposure at `handler`/);
    // A type below dom.
    const low = check({ id: "t", connect: { web_exposure_max: "proxy" } });
    expect(low.refusal?.code).toBe("exposure_cap_exceeded");
    expect(low.refusal?.fixAt).toBe("type");
    // A resource cap above the type's changes nothing.
    expect(check({ id: "t", connect: { web_exposure_max: "proxy" } }, { web_exposure_max: "dom" }).refusal?.code).toBe(
      "exposure_cap_exceeded",
    );
    // `open` mode fits under every cap, including the default.
    expect(
      evaluateWebExposure({ typeDef: null, resource: {}, required: "none", heuristic: false, allowInsecureHttp: false })
        .refusal,
    ).toBeNull();
  });

  it("refuses insecure http below dom, never at dom", () => {
    expect(check(domType, {}, { http: true }).refusal).toBeNull();
    expect(check(domType, { web_exposure_max: "none" }, { http: true }).refusal?.code).toBe("exposure_cap_exceeded");
  });

  it("needs a tier to enable heuristics and none to forbid them", () => {
    const heur = (def: Record<string, unknown>, res: Record<string, unknown> = {}) =>
      check({ id: "t", connect: { web_exposure_max: "dom", ...def } }, res, { heuristic: true });
    expect(heur({}).refusal?.code).toBe("heuristic_not_allowed");
    expect(heur({ allow_heuristic_fill: true }).refusal).toBeNull();
    expect(heur({}, { allow_heuristic_fill: true }).refusal).toBeNull();
    // An explicit false at either tier beats a true at the other.
    expect(heur({ allow_heuristic_fill: false }, { allow_heuristic_fill: true }).refusal?.message).toMatch(
      /type tier forbids/,
    );
    const resBlocks = heur({ allow_heuristic_fill: true }, { allow_heuristic_fill: false });
    expect(resBlocks.refusal?.message).toMatch(/resource tier forbids/);
    expect(resBlocks.refusal?.fixAt).toBe("resource");
    // Explicit steps are unaffected.
    expect(check({ id: "t", connect: { web_exposure_max: "dom" } }).refusal).toBeNull();
  });

  it("refuses an unreadable policy instead of reading it as unset", () => {
    expect(check({ id: "t", connect: { web_exposure_max: "DOM" } }).refusal?.code).toBe("exposure_policy_invalid");
    expect(check({ id: "t", connect: { web_exposure_max: 5 } }).refusal?.code).toBe("exposure_policy_invalid");
    expect(check({ id: "t", connect: "dom" }).refusal?.code).toBe("exposure_policy_invalid");
    expect(check("a string").refusal?.code).toBe("exposure_policy_invalid");
    expect(check({ id: "t", connect: { web_exposure_max: "dom", allow_heuristic_fill: "true" } }).refusal?.code).toBe(
      "exposure_policy_invalid",
    );
    const res = check(domType, { web_exposure_max: "everything" });
    expect(res.refusal?.code).toBe("exposure_policy_invalid");
    expect(res.refusal?.fixAt).toBe("resource");
    expect(check(domType, { allow_heuristic_fill: 1 }).refusal?.code).toBe("exposure_policy_invalid");
  });

  it("reads the saved type entry, not the builtins the GUI merges in", () => {
    expect(savedTypeEntry(null, "web_application")).toBeNull();
    expect(savedTypeEntry({ server: {} }, "web_application")).toBeNull();
    expect(savedTypeEntry({ web_application: domType }, "web_application")).toBe(domType);
    expect(savedTypeEntry({ web_application: domType }, "")).toBeNull();
    // Inherited properties are not saved types.
    expect(savedTypeEntry({}, "constructor")).toBeNull();
    expect(savedTypeEntry({}, "toString")).toBeNull();
  });
});
