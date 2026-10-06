//! Save-time validation of a `form`- or `http-auth`-mode web profile,
//! mirroring the checks `parse_launch_profile` makes in
//! crates/bv-engine-resource/src/connect_web/profile.rs: the origin set (read
//! with the server's strict `origin_key`, not the browser's URL parser), the
//! recipe and its URLs, the credential source, and whether the source can
//! supply what the recipe fills.
//!
//! The server stays the control. These checks exist so the editor refuses
//! what the launch would refuse, naming the field, instead of letting the
//! operator find out at connect time. Every message here corresponds to a
//! server refusal (`invalid_profile`, `invalid_recipe`,
//! `credential_source_unsupported`, `credential_unavailable`,
//! `totp_not_configured`).

import type { ConnectionProfile, WebLoginRecipe, WebProfileSettings } from "./types";
import {
  checkRecipeOrigins,
  formatRecipeIssue,
  originKey,
  recipeNeeds,
  splitUrl,
  utf8Len,
  validateWebRecipe,
} from "./webRecipe";

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** The origin set the *server* computes for a form launch: the start URL's
 *  origin first, then `allowed_origins`, as `origin_key` reads them. Stricter
 *  than the browser-style set the open-mode editor shows (no Unicode hosts,
 *  no percent-encoding, no trailing dot). */
export function strictOriginSet(web: WebProfileSettings): { origins: string[] } | { error: string } {
  const allowHttp = web.allow_insecure_http === true;
  const start = splitUrl(web.start_url);
  if (typeof start === "string") return { error: `Start URL ${start}` };
  const startKey = originKey(start.scheme, start.authority, allowHttp);
  if ("error" in startKey) return { error: `Start URL ${startKey.error}` };
  const origins = [startKey.origin];
  const list = web.allowed_origins ?? [];
  for (let i = 0; i < list.length; i++) {
    const parts = splitUrl(list[i].trim());
    if (typeof parts === "string") return { error: `Allowed origin ${i + 1} ${parts}` };
    if (!(parts.rest === "" || parts.rest === "/")) {
      return { error: `Allowed origin ${i + 1} is not a bare origin (no path, query or fragment)` };
    }
    const key = originKey(parts.scheme, parts.authority, allowHttp);
    if ("error" in key) return { error: `Allowed origin ${i + 1} ${key.error}` };
    if (!origins.includes(key.origin)) origins.push(key.origin);
  }
  return { origins };
}

/** The origin recipes for this profile should be written against: the start
 *  URL's strict origin key, or null when the start URL does not read. */
export function recipeBaseOrigin(web: Pick<WebProfileSettings, "start_url" | "allow_insecure_http">): string | null {
  const start = splitUrl(web.start_url.trim());
  if (typeof start === "string") return null;
  const key = originKey(start.scheme, start.authority, web.allow_insecure_http === true);
  return "error" in key ? null : key.origin;
}

function secretKeyError(v: unknown, field: string): string | null {
  const s = typeof v === "string" ? v : "";
  if (s === "" || utf8Len(s) > 256 || s.includes("/") || s === "." || s === ".." || CONTROL.test(s)) {
    return `credential_source.${field} must be a single secret key name`;
  }
  return null;
}

function ldapNameError(v: unknown, field: string): string | null {
  const s = (typeof v === "string" ? v : "").trim();
  const ok = s.length >= 2 && s.length <= 128 && /^[A-Za-z0-9_][A-Za-z0-9_-]*[A-Za-z0-9_]$/.test(s);
  return ok ? null : `credential_source.${field} must be an LDAP role/set name (\\w[\\w-]*\\w)`;
}

function ldapMountError(v: unknown): string | null {
  const raw = (typeof v === "string" ? v : "").trim();
  const m = raw.replace(/\/+$/, "");
  const ok =
    m !== "" &&
    !m.startsWith("/") &&
    utf8Len(m) <= 256 &&
    m.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..") &&
    /^[A-Za-z0-9_\-/.]+$/.test(m);
  return ok ? null : "credential_source.ldap_mount must be a mount path such as `openldap/`";
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function totpParamsError(v: unknown): string | null {
  if (v === undefined) return null;
  if (!isRecord(v)) return "credential_source.totp must be an object";
  for (const k of Object.keys(v)) {
    if (k !== "algorithm" && k !== "digits" && k !== "period") {
      return `credential_source.totp.${k} is not a field this server understands`;
    }
  }
  if (v.algorithm !== undefined && !["SHA1", "SHA256", "SHA512"].includes(String(v.algorithm))) {
    return "credential_source.totp.algorithm must be SHA1, SHA256 or SHA512";
  }
  if (v.digits !== undefined && v.digits !== 6 && v.digits !== 8) {
    return "credential_source.totp.digits must be 6 or 8";
  }
  if (v.period !== undefined && v.period !== 30 && v.period !== 60) {
    return "credential_source.totp.period must be 30 or 60";
  }
  return null;
}

/** The field checks a `secret` or `ldap` source gets in either mode, in the
 *  server's order. `undefined` for any other kind. */
function releasingSourceError(cs: ConnectionProfile["credential_source"]): string | null | undefined {
  switch (cs.kind) {
    case "secret": {
      if (!cs.secret_id.trim()) return "Pick a credential secret on this resource";
      const idErr = secretKeyError(cs.secret_id, "secret_id");
      if (idErr) return idErr;
      if (cs.fields !== undefined) {
        if (!isRecord(cs.fields)) return "credential_source.fields must be an object";
        for (const [k, val] of Object.entries(cs.fields)) {
          if (k !== "username" && k !== "password" && k !== "totp_seed") {
            return `credential_source.fields.${k} is not a field this server understands`;
          }
          const e = secretKeyError(val, `fields.${k}`);
          if (e) return e;
        }
      }
      return totpParamsError(cs.totp);
    }
    case "ldap": {
      const mountErr = ldapMountError(cs.ldap_mount);
      if (mountErr) return mountErr;
      if (cs.bind_mode === "static_role") {
        const e = ldapNameError(cs.static_role, "static_role");
        if (e) return e;
      } else if (cs.bind_mode === "library_set") {
        const e = ldapNameError(cs.library_set, "library_set");
        if (e) return e;
      } else if (cs.bind_mode === "operator") {
        return (
          "ldap bind_mode `operator` means the operator types their own credential, so there is nothing " +
          "for the server to release; use `open` mode or a `default-account` source"
        );
      } else {
        return "credential_source.bind_mode must be static_role or library_set";
      }
      return null;
    }
    default:
      return undefined;
  }
}

/**
 * The credential-source half of `parse_launch_profile`: the kind, its fields,
 * and (for an explicit recipe) whether the source can supply what the recipe
 * fills. `recipe` is a recipe that already passed {@link validateWebRecipe}.
 */
export function formCredentialSourceError(
  cs: ConnectionProfile["credential_source"],
  recipe: WebLoginRecipe,
): string | null {
  const needs = recipeNeeds(recipe);
  switch (cs.kind) {
    case "secret":
    case "ldap": {
      const e = releasingSourceError(cs);
      if (e) return e;
      break;
    }
    case "default-account":
      break;
    case "none":
      return "credential_source `none` releases nothing; a form-mode profile needs secret, ldap or default-account";
    case "ssh-engine":
    case "pki":
    case "fido2":
      return "ssh-engine, pki and fido2 sources are not valid on a web profile";
  }
  // What the source can supply is known without reading it. Heuristic
  // recipes want each value only "if the source has it", so they are exempt.
  if (!needs.heuristic) {
    if (cs.kind === "default-account" && needs.password) {
      return (
        "a default-account source supplies a username only; remove the recipe's password fill and let the " +
        "operator type it"
      );
    }
    if ((cs.kind === "default-account" || cs.kind === "ldap") && needs.totp) {
      return "the recipe fills `totp`, but only a `secret` source carrying a TOTP seed can supply one";
    }
  }
  return null;
}

/**
 * Everything a `form` web profile must satisfy beyond the checks it shares
 * with `open` mode (transport, TLS pin, start URL, window size). Returns the
 * first problem, worded for the operator, or null.
 */
export function validateFormWebProfile(p: ConnectionProfile, web: WebProfileSettings): string | null {
  const set = strictOriginSet(web);
  if ("error" in set) return set.error;

  if (web.recipe === undefined || web.recipe === null) {
    return "A form login needs a login recipe. Start from a vendor preset, a blank recipe or an import.";
  }
  const parsed = validateWebRecipe(web.recipe);
  if (!parsed.ok) return formatRecipeIssue(parsed.issue);
  const originIssue = checkRecipeOrigins(parsed.recipe, set.origins, web.allow_insecure_http === true);
  if (originIssue) return formatRecipeIssue(originIssue);

  return formCredentialSourceError(p.credential_source, parsed.recipe);
}

/**
 * The credential-source half of `parse_launch_profile` for `http-auth`: a
 * `secret` or a releasing `ldap` source. A default account supplies a
 * username only, and a challenge needs a username and a password. TOTP
 * settings on a secret source are still checked (the server reads them) but
 * release nothing in this mode.
 */
export function httpAuthCredentialSourceError(cs: ConnectionProfile["credential_source"]): string | null {
  switch (cs.kind) {
    case "secret":
    case "ldap":
      return releasingSourceError(cs) ?? null;
    case "default-account":
      return (
        "a default-account source supplies a username only, and an HTTP authentication challenge needs a " +
        "username and a password; use a secret or ldap source, or `open` mode and let the operator type it"
      );
    case "none":
      return "credential_source `none` releases nothing; an http-auth profile needs a secret or ldap source";
    case "ssh-engine":
    case "pki":
    case "fido2":
      return "ssh-engine, pki and fido2 sources are not valid on a web profile";
  }
}

/**
 * Everything an `http-auth` web profile must satisfy beyond the checks it
 * shares with the other modes: the server's strict reading of its origins
 * (the only origins whose challenges the host will answer) and a source that
 * supplies a username and a password. No recipe (checked by the caller).
 */
export function validateHttpAuthWebProfile(p: ConnectionProfile, web: WebProfileSettings): string | null {
  const set = strictOriginSet(web);
  if ("error" in set) return set.error;
  return httpAuthCredentialSourceError(p.credential_source);
}
