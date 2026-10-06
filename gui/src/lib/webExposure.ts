//! The Web Connect exposure policy (features/web-application-connect.md §6),
//! mirrored from crates/bv-engine-resource/src/connect_web/exposure.rs so the
//! profile editor can say, before a connect, that the server will refuse.
//!
//! This is a hint and never the control: `v2/connect/web/launch` enforces the
//! rule again. It is written to be *no looser* than the server — every
//! refusal the server can produce for the policy tiers has a counterpart
//! here, with the server's wording and its stable `code`.
//!
//! The rule, in one paragraph. Deny unless opted in: the effective cap starts
//! at `none`, and only the **type** tier can raise it — the resource's `type`
//! must name an entry in the **saved** `config/types` whose
//! `connect.web_exposure_max` is set. The resource tier (top-level
//! `web_exposure_max` / `allow_heuristic_fill` on the resource record) can
//! only lower the cap. Heuristic fill needs at least one tier to enable it and
//! no tier to forbid it. `allow_insecure_http` is refused below `dom`.
//!
//! "Saved" matters: the GUI shows builtin types merged in from its own
//! defaults (`mergeTypeConfig`), but the server sees only what was written to
//! `config/types`. Pass the raw `resource_types_read` payload here, never the
//! merged config.

import type { WebExposure } from "./types";

/** Least to most exposed; the index is the policy order. */
const ORDER: readonly WebExposure[] = ["none", "isolated", "handler", "proxy", "dom"];

export const WEB_EXPOSURE_LEVELS: readonly WebExposure[] = ORDER;

export function parseWebExposure(v: unknown): WebExposure | null {
  return typeof v === "string" && (ORDER as readonly string[]).includes(v) ? (v as WebExposure) : null;
}

function rank(e: WebExposure): number {
  return ORDER.indexOf(e);
}

/** The exposure a login mode needs: `form` is `dom`, `http-auth` is
 *  `handler`, `open` and `sso` none. (`allow_insecure_http` is refused below a
 *  `dom` cap whatever the mode — `evaluateWebExposure` checks that.) */
export function requiredExposureForLoginMode(mode: string): WebExposure | null {
  switch (mode) {
    case "form":
      return "dom";
    case "open":
    case "sso":
      return "none";
    case "http-auth":
      return "handler";
    default:
      return null;
  }
}

type Tier = "type" | "resource";

/** Stable codes, identical to `ExposureRefusal::code` on the server. */
export type ExposureRefusalCode =
  | "exposure_policy_invalid"
  | "exposure_not_permitted"
  | "exposure_cap_exceeded"
  | "heuristic_not_allowed"
  | "insecure_http_not_allowed";

export interface ExposureRefusal {
  code: ExposureRefusalCode;
  /** The server's message. */
  message: string;
  /** Where an administrator fixes it: the resource type (Settings) or the
   *  resource itself / the recipe. */
  fixAt: "type" | "resource" | "profile";
}

export interface ExposureVerdict {
  /** `null` when the server's policy check would pass. */
  refusal: ExposureRefusal | null;
  /** The effective cap, when the tiers parsed. */
  cap: WebExposure | null;
}

export interface ExposureInput {
  /** The resource's entry in the *saved* `config/types`: the raw value, or
   *  `null`/`undefined` when the configuration was never saved, the resource
   *  has no type, or the type is not in it. */
  typeDef: unknown;
  /** The resource record (for its top-level `web_exposure_max` /
   *  `allow_heuristic_fill`). */
  resource: Record<string, unknown>;
  required: WebExposure;
  heuristic: boolean;
  allowInsecureHttp: boolean;
}

const isNullish = (v: unknown): v is null | undefined => v === null || v === undefined;

function refusal(code: ExposureRefusalCode, message: string, fixAt: ExposureRefusal["fixAt"]): ExposureVerdict {
  return { refusal: { code, message, fixAt }, cap: null };
}

function invalidPolicy(tier: Tier, field: string): ExposureVerdict {
  return refusal(
    "exposure_policy_invalid",
    `the ${tier} tier's \`${field}\` is not a value this server understands; fix it rather than relying on a default`,
    tier,
  );
}

type Read<T> = { ok: true; value: T | null } | { ok: false; field: string };

function readCap(v: unknown): Read<WebExposure> {
  if (isNullish(v)) return { ok: true, value: null };
  const cap = parseWebExposure(v);
  return cap === null ? { ok: false, field: "web_exposure_max" } : { ok: true, value: cap };
}

function readFlag(v: unknown): Read<boolean> {
  if (isNullish(v)) return { ok: true, value: null };
  return typeof v === "boolean" ? { ok: true, value: v } : { ok: false, field: "allow_heuristic_fill" };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Every §6 check `v2/connect/web/launch` makes against the two tiers, in the
 *  server's order. */
export function evaluateWebExposure(input: ExposureInput): ExposureVerdict {
  // Type tier.
  let typeSaved = false;
  let typeConnect: Record<string, unknown> | null = null;
  const def = input.typeDef;
  if (!isNullish(def)) {
    if (!isRecord(def)) return invalidPolicy("type", "connect");
    typeSaved = true;
    const c = Object.prototype.hasOwnProperty.call(def, "connect") ? def["connect"] : undefined;
    if (!isNullish(c)) {
      if (!isRecord(c)) return invalidPolicy("type", "connect");
      typeConnect = c;
    }
  }
  const own = (o: Record<string, unknown> | null, k: string): unknown =>
    o !== null && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;

  const typeCap = readCap(own(typeConnect, "web_exposure_max"));
  if (!typeCap.ok) return invalidPolicy("type", typeCap.field);
  const typeHeuristic = readFlag(own(typeConnect, "allow_heuristic_fill"));
  if (!typeHeuristic.ok) return invalidPolicy("type", typeHeuristic.field);
  const resCap = readCap(own(input.resource, "web_exposure_max"));
  if (!resCap.ok) return invalidPolicy("resource", resCap.field);
  const resHeuristic = readFlag(own(input.resource, "allow_heuristic_fill"));
  if (!resHeuristic.ok) return invalidPolicy("resource", resHeuristic.field);

  // Effective cap: the type tier's, `none` when it has not opted in; the
  // resource tier can only lower it.
  let cap: WebExposure = typeCap.value ?? "none";
  let setBy: Tier | "default" = typeCap.value === null ? "default" : "type";
  if (resCap.value !== null && rank(resCap.value) < rank(cap)) {
    cap = resCap.value;
    setBy = "resource";
  }

  if (rank(input.required) > rank(cap)) {
    if (setBy === "default") {
      return refusal(
        "exposure_not_permitted",
        typeSaved
          ? "web credential release is off by default: this resource's type does not set " +
              "`connect.web_exposure_max`. Set it on the type (`dom` for form mode, `handler` for http-auth) to opt in"
          : "web credential release is off by default: this resource's type is not in the saved " +
              "resource type configuration, so it has not opted in. Save the type with " +
              "`connect.web_exposure_max` set (`dom` for form mode, `handler` for http-auth)",
        "type",
      );
    }
    return refusal(
      "exposure_cap_exceeded",
      `this login mode needs exposure \`${input.required}\` but the ${setBy} tier caps web exposure at \`${cap}\``,
      setBy,
    );
  }
  if (input.allowInsecureHttp && rank(cap) < rank("dom")) {
    return refusal(
      "insecure_http_not_allowed",
      `allow_insecure_http is refused while the effective exposure cap is \`${cap}\`: a credential sent over plain http is DOM-level exposure`,
      "profile",
    );
  }
  if (input.heuristic) {
    if (typeHeuristic.value === false) {
      return refusal(
        "heuristic_not_allowed",
        'the recipe uses heuristic fill (`"steps": "auto"`), which the type tier forbids (`allow_heuristic_fill: false`)',
        "type",
      );
    }
    if (resHeuristic.value === false) {
      return refusal(
        "heuristic_not_allowed",
        'the recipe uses heuristic fill (`"steps": "auto"`), which the resource tier forbids (`allow_heuristic_fill: false`)',
        "resource",
      );
    }
    if (typeHeuristic.value !== true && resHeuristic.value !== true) {
      return refusal(
        "heuristic_not_allowed",
        'the recipe uses heuristic fill (`"steps": "auto"`), which needs `allow_heuristic_fill: true` on the resource or its type',
        "type",
      );
    }
  }
  return { refusal: null, cap };
}

/** The resource's entry in a raw `resource_types_read` payload. `null` when
 *  the config was never saved or has no such type. Own properties only. */
export function savedTypeEntry(saved: Record<string, unknown> | null, typeId: string): unknown {
  if (saved === null || typeId === "") return null;
  return Object.prototype.hasOwnProperty.call(saved, typeId) ? saved[typeId] : null;
}
