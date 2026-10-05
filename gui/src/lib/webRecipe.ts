//! The v1 web login recipe (features/web-application-connect.md §2), validated
//! in the GUI the way the server validates it.
//!
//! The authority is `WebLoginRecipe::parse`, `WebLoginRecipe::check_origins`,
//! `origin_key` and `split_url` in
//! crates/bv-engine-resource/src/connect_web/recipe.rs. This module is a
//! line-by-line port, in the same check order, so the editor refuses what
//! `v2/connect/web/launch` would refuse and names the same field (`at` is the
//! server's JSON-path-like location). It can only be *as strict or stricter*
//! than the server: a refusal here costs an edit, a laxity here costs a failed
//! connect. Keep the constants and the order of the checks in step with
//! recipe.rs; `src/test/webRecipe.test.ts` pins each rule.
//!
//! Recipes are data, never script: nothing here evaluates anything, and
//! imported text only ever goes through `JSON.parse` and the strict reader.
//!
//! Known, accepted gaps against the Rust reader:
//!   * JSON numbers: Rust distinguishes `30` from `30.0` (`as_u64`); a JS
//!     number cannot. The GUI always sends `JSON.stringify` output, which
//!     prints an integral value as an integer, so the server sees what this
//!     validator accepted.
//!   * `recipe_hash` (RFC 8785 canonicalisation) is computed by the host and
//!     the server, not here; the dry run reports the hash it would carry.

import type { WebLoginRecipe } from "./types";

export const RECIPE_VERSION = 1;
export const MAX_STEPS = 16;
export const MAX_ACTIONS_PER_STEP = 32;
export const MAX_SELECTOR_LEN = 512;
export const MAX_URL_PATTERN_LEN = 2048;
export const MAX_LITERAL_LEN = 256;
export const MAX_TIMEOUT_SECS = 60;
export const DEFAULT_TIMEOUT_SECS = 30;
/** Upper bound on pasted / imported recipe text. A valid recipe is at most
 *  16 x 32 actions of short strings, far below this; the cap only stops a
 *  hostile file from reaching `JSON.parse`. */
export const MAX_RECIPE_JSON_BYTES = 256 * 1024;

/** The `web_application.vendor` enum. `vendor` on a recipe is informational. */
export const WEB_RECIPE_VENDORS = [
  "generic",
  "fortigate",
  "vcenter",
  "idrac",
  "ilo",
  "pfsense",
  "grafana",
  "jenkins",
  "other",
] as const;

const TOP_LEVEL_KEYS = [
  "version",
  "vendor",
  "steps",
  "success_when",
  "failure_when",
  "timeout_secs",
  "pause_for_operator",
] as const;

/** Why a recipe was refused. `at` is a location such as
 *  `steps[1].actions[0].value`, never the offending value. */
export interface RecipeIssue {
  at: string;
  reason: string;
}

export type RecipeParse =
  | { ok: true; recipe: WebLoginRecipe }
  | { ok: false; issue: RecipeIssue };

/** The server's wording: `recipe `at`: reason`. */
export function formatRecipeIssue(issue: RecipeIssue): string {
  return issue.at ? `recipe \`${issue.at}\`: ${issue.reason}` : `recipe: ${issue.reason}`;
}

class Refusal extends Error {
  constructor(
    readonly at: string,
    readonly reason: string,
  ) {
    super(reason);
  }
}

function err(at: string, reason: string): never {
  throw new Refusal(at, reason);
}

function join(at: string, key: string): string {
  return at === "" ? key : `${at}.${key}`;
}

// ── Reading JSON values the way serde_json's `Value` reads them ─────────────

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** An own property, with `undefined` read as absent (it never survives
 *  `JSON.stringify`). `null` is a present value, as in `Value::Null`. */
function get(obj: Obj, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

function has(obj: Obj, key: string): boolean {
  return get(obj, key) !== undefined;
}

function asU64(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

/** Rust orders `String`s by UTF-8 bytes, i.e. by code point. */
function cmpCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

function rejectUnknown(obj: Obj, at: string, allowed: readonly string[]): void {
  // First unknown key in sorted order, so the error is stable.
  const unknown = Object.keys(obj)
    .filter((k) => !allowed.includes(k))
    .sort(cmpCodePoints);
  if (unknown.length > 0) {
    err(join(at, unknown[0]), "is not a recipe field this server understands");
  }
}

// Rust `char::is_control` (general category Cc) and `char::is_whitespace`
// (Unicode White_Space). Written out rather than `\s`, which also matches
// U+FEFF and is not the same set.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const WHITESPACE = /[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;

function hasControl(s: string): boolean {
  return CONTROL.test(s);
}

/** Byte length in UTF-8, which is what Rust's `str::len` counts. */
export function utf8Len(s: string): number {
  return new TextEncoder().encode(s).length;
}

function trimmedEmpty(s: string): boolean {
  return s.replace(new RegExp(`^${WHITESPACE.source}+|${WHITESPACE.source}+$`, "g"), "") === "";
}

function selector(v: unknown, at: string): string {
  if (typeof v !== "string") err(at, "must be a CSS selector string");
  if (trimmedEmpty(v)) err(at, "must not be empty");
  if (utf8Len(v) > MAX_SELECTOR_LEN) err(at, `is longer than ${MAX_SELECTOR_LEN} bytes`);
  if (hasControl(v)) err(at, "must not contain control characters");
  return v;
}

function fillValue(v: unknown, at: string): string {
  if (typeof v !== "string") {
    err(at, "is required: one of `username`, `password`, `totp` or `literal:<text>`");
  }
  if (v === "username" || v === "password" || v === "totp") return v;
  if (!v.startsWith("literal:")) {
    err(at, "must be one of `username`, `password`, `totp` or `literal:<text>`");
  }
  const text = v.slice("literal:".length);
  if (text === "" || utf8Len(text) > MAX_LITERAL_LEN || hasControl(text)) {
    err(at, `a literal must be 1..=${MAX_LITERAL_LEN} bytes with no control characters`);
  }
  return v;
}

// ── URLs and origins ────────────────────────────────────────────────────────

/** `scheme://authority[/...]` split without interpreting it. Refuses the
 *  shapes a WHATWG parser would read differently from a naive one. Returns an
 *  error string like the Rust `Err(String)`. */
export function splitUrl(
  raw: string,
): { scheme: string; authority: string; rest: string } | string {
  if (raw === "") return "is empty";
  for (const c of raw) {
    if (CONTROL.test(c) || WHITESPACE.test(c) || c === "\\") {
      return "must not contain whitespace, control characters or backslashes";
    }
  }
  const i = raw.indexOf("://");
  if (i < 0) return "must be an absolute https:// URL";
  const scheme = raw.slice(0, i);
  const afterScheme = raw.slice(i + 3);
  const m = afterScheme.search(/[/?#]/);
  const end = m < 0 ? afterScheme.length : m;
  return { scheme, authority: afterScheme.slice(0, end), rest: afterScheme.slice(end) };
}

/** Normalise `(scheme, authority)` to the exact origin key
 *  `scheme://host[:port]`: lower-case host, default port dropped. Narrower
 *  than the URL standard on purpose (see `origin_key` in recipe.rs): a
 *  non-ASCII host, percent-encoding, userinfo, a wildcard, a trailing dot or
 *  a character outside `[a-z0-9._-]` is refused. Returns `{ error }` on
 *  refusal. */
export function originKey(
  scheme: string,
  authority: string,
  allowInsecureHttp: boolean,
): { origin: string } | { error: string } {
  let defaultPort: number;
  if (scheme === "https") defaultPort = 443;
  else if (scheme === "http" && allowInsecureHttp) defaultPort = 80;
  else if (scheme === "http") {
    return { error: "plain http is refused unless the profile sets allow_insecure_http" };
  } else {
    return { error: "scheme must be `https` (or `http` with allow_insecure_http)" };
  }
  if (authority === "") return { error: "has no host" };
  // eslint-disable-next-line no-control-regex
  if (!/^[\u0000-\u007f]*$/.test(authority)) {
    return { error: "has a non-ASCII host; write it in its punycode (`xn--…`) form" };
  }
  if (/[@*%]/.test(authority)) {
    return { error: "origin must be a literal host (no userinfo, wildcard or percent-encoding)" };
  }
  const lower = authority.toLowerCase(); // ASCII-only by the check above
  let host: string;
  let port: string | null;
  if (lower.startsWith("[")) {
    const rest = lower.slice(1);
    const close = rest.indexOf("]");
    if (close < 0) return { error: "has an unterminated IPv6 literal" };
    const inner = rest.slice(0, close);
    if (inner === "" || !/^[0-9a-f:.]+$/.test(inner)) return { error: "has a malformed IPv6 literal" };
    const after = rest.slice(close + 1);
    if (after === "") port = null;
    else if (after.startsWith(":")) port = after.slice(1);
    else return { error: "has junk after the IPv6 literal" };
    host = `[${inner}]`;
  } else {
    const c = lower.lastIndexOf(":");
    host = c < 0 ? lower : lower.slice(0, c);
    port = c < 0 ? null : lower.slice(c + 1);
    if (host === "") return { error: "has no host" };
    if (host.endsWith(".")) {
      return { error: "host has a trailing dot; browsers treat it as a different origin" };
    }
    if (!/^[a-z0-9._-]+$/.test(host)) return { error: "host has characters outside [a-z0-9._-]" };
  }
  let portPart = "";
  if (port !== null) {
    if (port === "" || !/^[0-9]+$/.test(port)) return { error: "has a malformed port" };
    const n = Number(port);
    if (!(n <= 65535)) return { error: "port is out of range" };
    if (n !== defaultPort) portPart = `:${n}`;
  }
  return { origin: `${scheme}://${host}${portPart}` };
}

function urlPattern(v: unknown, at: string): string {
  if (typeof v !== "string") err(at, "must be a URL pattern string");
  if (utf8Len(v) > MAX_URL_PATTERN_LEN) err(at, `is longer than ${MAX_URL_PATTERN_LEN} bytes`);
  const parts = splitUrl(v);
  if (typeof parts === "string") err(at, parts);
  if (parts.scheme !== "https" && parts.scheme !== "http") {
    err(at, "must start with https:// (or http:// with allow_insecure_http)");
  }
  if (parts.authority === "" || /[*@]/.test(parts.authority)) {
    err(at, "its origin must be literal: `*` may appear only after the host, and userinfo is refused");
  }
  return v;
}

// ── The recipe ──────────────────────────────────────────────────────────────

function condition(v: unknown, at: string): void {
  if (!isObj(v)) err(at, "must be an object with `url` and/or `selector`");
  rejectUnknown(v, at, ["url", "selector"]);
  const hasUrl = has(v, "url");
  const hasSelector = has(v, "selector");
  if (hasUrl) urlPattern(get(v, "url"), join(at, "url"));
  if (hasSelector) selector(get(v, "selector"), join(at, "selector"));
  if (!hasUrl && !hasSelector) err(at, "needs a `url`, a `selector`, or both");
}

const VERBS = ["fill", "click", "submit", "wait"] as const;

function action(v: unknown, at: string): void {
  if (!isObj(v)) err(at, "must be an object");
  const verbs = VERBS.filter((k) => has(v, k));
  if (verbs.length !== 1) err(at, "must carry exactly one of `fill`, `click`, `submit` or `wait`");
  const verb = verbs[0];
  if (verb === "fill") {
    rejectUnknown(v, at, ["fill", "value"]);
    selector(get(v, "fill"), join(at, "fill"));
    fillValue(get(v, "value"), join(at, "value"));
  } else {
    rejectUnknown(v, at, [verb]);
    selector(get(v, verb), join(at, verb));
  }
}

function step(v: unknown, at: string): void {
  if (!isObj(v)) err(at, "must be an object");
  rejectUnknown(v, at, ["when_url", "actions"]);
  urlPattern(get(v, "when_url"), join(at, "when_url"));
  const actionsAt = join(at, "actions");
  const list = get(v, "actions");
  if (!Array.isArray(list)) err(actionsAt, "is required and must be an array");
  if (list.length === 0 || list.length > MAX_ACTIONS_PER_STEP) {
    err(actionsAt, `must hold 1..=${MAX_ACTIONS_PER_STEP} actions`);
  }
  list.forEach((a, i) => action(a, `${actionsAt}[${i}]`));
}

function parseOrThrow(value: unknown): WebLoginRecipe {
  if (!isObj(value)) err("", "must be a JSON object");
  // The version is read before anything else, so a later format never
  // half-parses as this one.
  const version = asU64(get(value, "version"));
  if (version === null) err("version", "is required and must be an integer");
  if (version !== RECIPE_VERSION) {
    err(
      "version",
      `recipe version ${version} is not supported; this server understands version ${RECIPE_VERSION} only`,
    );
  }
  rejectUnknown(value, "", TOP_LEVEL_KEYS);

  if (has(value, "vendor")) {
    const vendor = get(value, "vendor");
    if (typeof vendor !== "string" || !(WEB_RECIPE_VENDORS as readonly string[]).includes(vendor)) {
      err("vendor", `must be one of ${WEB_RECIPE_VENDORS.join(", ")}`);
    }
  }

  const steps = get(value, "steps");
  if (steps === "auto") {
    // heuristic mode: no steps to read
  } else if (Array.isArray(steps)) {
    if (steps.length === 0 || steps.length > MAX_STEPS) err("steps", `must hold 1..=${MAX_STEPS} steps`);
    steps.forEach((s, i) => step(s, `steps[${i}]`));
  } else {
    err("steps", 'is required: an array of steps, or the string "auto"');
  }

  if (!has(value, "success_when")) err("success_when", "is required");
  condition(get(value, "success_when"), "success_when");
  if (has(value, "failure_when")) condition(get(value, "failure_when"), "failure_when");

  if (has(value, "timeout_secs")) {
    const n = asU64(get(value, "timeout_secs"));
    if (n === null || n < 1 || n > MAX_TIMEOUT_SECS) {
      err("timeout_secs", `must be an integer in 1..=${MAX_TIMEOUT_SECS}`);
    }
  }

  if (has(value, "pause_for_operator")) {
    const pause = get(value, "pause_for_operator");
    if (!Array.isArray(pause)) err("pause_for_operator", "must be an array");
    pause.forEach((p, i) => {
      if (p !== "captcha" && p !== "push_mfa") {
        err(`pause_for_operator[${i}]`, "must be `captcha` or `push_mfa`");
      }
    });
  }
  return value as unknown as WebLoginRecipe;
}

/** Strictly validate a recipe value, exactly as `WebLoginRecipe::parse` does.
 *  Does not check origins (see {@link checkRecipeOrigins}): the server checks
 *  those against the profile. */
export function validateWebRecipe(value: unknown): RecipeParse {
  try {
    return { ok: true, recipe: parseOrThrow(value) };
  } catch (e) {
    if (e instanceof Refusal) return { ok: false, issue: { at: e.at, reason: e.reason } };
    throw e;
  }
}

/** `null` when the recipe is valid, else the server-worded message. */
export function recipeError(value: unknown): string | null {
  const r = validateWebRecipe(value);
  return r.ok ? null : formatRecipeIssue(r.issue);
}

/** True for `"steps": "auto"` (heuristic fill, policy-gated, spec §6). */
export function isHeuristicRecipe(recipe: { steps?: unknown } | null | undefined): boolean {
  return recipe?.steps === "auto";
}

/** Every URL pattern in a recipe, with the location the server names it by. */
function recipeUrls(recipe: WebLoginRecipe): { at: string; url: string }[] {
  const out: { at: string; url: string }[] = [];
  if (Array.isArray(recipe.steps)) {
    recipe.steps.forEach((s, i) => out.push({ at: `steps[${i}].when_url`, url: s.when_url }));
  }
  if (recipe.success_when.url !== undefined) out.push({ at: "success_when.url", url: recipe.success_when.url });
  if (recipe.failure_when?.url !== undefined) out.push({ at: "failure_when.url", url: recipe.failure_when.url });
  return out;
}

/**
 * Spec §2 / `check_origins`: every URL the recipe matches on must sit on an
 * origin of the profile's set, over https unless the profile allows plain
 * http. `origins` holds keys produced by {@link originKey}. Expects a recipe
 * that already passed {@link validateWebRecipe}.
 */
export function checkRecipeOrigins(
  recipe: WebLoginRecipe,
  origins: readonly string[],
  allowInsecureHttp: boolean,
): RecipeIssue | null {
  for (const { at, url } of recipeUrls(recipe)) {
    const parts = splitUrl(url);
    if (typeof parts === "string") return { at, reason: parts };
    const key = originKey(parts.scheme, parts.authority, allowInsecureHttp);
    if ("error" in key) return { at, reason: key.error };
    if (!origins.includes(key.origin)) {
      return { at, reason: "its origin is not the start URL's origin or one of allowed_origins" };
    }
  }
  return null;
}

/** Which parts of a credential a recipe consumes (`RecipeNeeds`). */
export interface RecipeNeeds {
  heuristic: boolean;
  username: boolean;
  password: boolean;
  totp: boolean;
  /** Step indexes that fill `totp`. Heuristic mode has the single step 0. */
  totpSteps: number[];
  stepCount: number;
}

export function recipeNeeds(recipe: WebLoginRecipe): RecipeNeeds {
  if (recipe.steps === "auto") {
    return { heuristic: true, username: true, password: true, totp: true, totpSteps: [0], stepCount: 1 };
  }
  const needs: RecipeNeeds = {
    heuristic: false,
    username: false,
    password: false,
    totp: false,
    totpSteps: [],
    stepCount: recipe.steps.length,
  };
  recipe.steps.forEach((s, i) => {
    let fillsTotp = false;
    for (const a of s.actions) {
      if ("fill" in a) {
        if (a.value === "username") needs.username = true;
        else if (a.value === "password") needs.password = true;
        else if (a.value === "totp") fillsTotp = true;
      }
    }
    if (fillsTotp) {
      needs.totp = true;
      needs.totpSteps.push(i);
    }
  });
  return needs;
}

// ── Import / export ─────────────────────────────────────────────────────────

/**
 * Parse recipe text typed, pasted or read from a file. The text goes through
 * `JSON.parse` and the strict reader and nowhere else; a recipe is data and
 * is never evaluated. `__proto__` and any other unknown key is an unknown
 * field and refused.
 */
export function parseRecipeJson(text: string): RecipeParse {
  if (utf8Len(text) > MAX_RECIPE_JSON_BYTES) {
    return {
      ok: false,
      issue: { at: "", reason: `the text is larger than ${MAX_RECIPE_JSON_BYTES / 1024} KiB; a recipe is far smaller` },
    };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    const detail = e instanceof Error ? e.message : "invalid JSON";
    return { ok: false, issue: { at: "", reason: `is not valid JSON (${detail})` } };
  }
  return validateWebRecipe(value);
}

/** Pretty JSON for the raw view, the clipboard and the file export. */
export function recipeToJson(recipe: unknown): string {
  return JSON.stringify(recipe, null, 2);
}

/** File name offered for an exported recipe. */
export function recipeFileName(recipe: { vendor?: string } | null | undefined): string {
  const v = recipe?.vendor && /^[a-z]+$/.test(recipe.vendor) ? recipe.vendor : "web";
  return `${v}-login-recipe.json`;
}

// ── Blank recipes and edit helpers ──────────────────────────────────────────

/** A new explicit recipe for a login page at `origin`: one step that fills a
 *  username and password and clicks submit. The selectors are placeholders
 *  the operator replaces; the validator accepts them, the dry run tells the
 *  truth. */
export function blankRecipe(origin: string): WebLoginRecipe {
  return {
    version: 1,
    steps: [
      {
        when_url: `${origin}/login*`,
        actions: [
          { fill: "input[name=username]", value: "username" },
          { fill: "input[type=password]", value: "password" },
          { click: "button[type=submit]" },
        ],
      },
    ],
    success_when: { url: `${origin}/` },
    failure_when: { selector: ".error, .alert-danger" },
    timeout_secs: DEFAULT_TIMEOUT_SECS,
  };
}

/** A heuristic recipe. Policy-gated; the success condition is still
 *  explicit, because the host judges the outcome from it. */
export function heuristicRecipe(origin: string): WebLoginRecipe {
  return {
    version: 1,
    steps: "auto",
    success_when: { url: `${origin}/` },
    timeout_secs: DEFAULT_TIMEOUT_SECS,
  };
}
