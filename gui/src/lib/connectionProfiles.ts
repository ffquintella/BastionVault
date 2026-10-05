//! GUI-side helpers for the Resource Connect feature
//! (`features/resource-connect.md`).
//!
//! Profile storage shape: each resource carries `connection_profiles:
//! ConnectionProfile[]` as a key in its flexible metadata bag. The
//! resource backend accepts this without schema changes — the field
//! is opaque to the host.

import type {
  ConnectionProfile,
  ConnectProfileHint,
  CredentialSource,
  ResourceSecretShape,
  SessionProtocol,
  SshLoginClass,
  WebProfileSettings,
} from "./types";

/** Default port per (protocol). Per-OS-type defaults that override
 *  these live on the operator-side `ResourceTypeDef.connect`
 *  (Phase 7) — for v1 the protocol default is enough. */
export function defaultPort(protocol: SessionProtocol): number {
  switch (protocol) {
    case "ssh":
      return 22;
    case "rdp":
      return 3389;
    case "web":
      return 443;
  }
}

/**
 * Parse a stored profile's `protocol`. Returns null for anything this
 * build doesn't know — callers must treat that as "not launchable", never
 * as SSH. A profile written by a newer GUI (or by hand) can carry any
 * string here. See features/web-application-connect.md §1, "Strict
 * parsing / old clients".
 */
export function parseSessionProtocol(raw: unknown): SessionProtocol | null {
  switch (raw) {
    case "ssh":
    case "rdp":
    case "web":
      return raw;
    default:
      return null;
  }
}

/** Map structured `os_type` to the protocol the Connect button
 *  drives. Returns null for `other` / unset / unknown — the GUI
 *  hides the button in those cases. */
export function protocolForOsType(osType: string): SessionProtocol | null {
  switch (osType) {
    case "linux":
    case "macos":
    case "bsd":
    case "unix":
      return "ssh";
    case "windows":
      return "rdp";
    default:
      return null;
  }
}

/** Mint a stable id for a new profile. UUID-ish but not strictly
 *  RFC4122; just needs to be unique-per-resource. The resource
 *  module never indexes on it; it's only meaningful inside the
 *  profile array on the resource record. */
export function newProfileId(): string {
  // 16 hex chars from crypto.getRandomValues — collision-safe at
  // any plausible deployment scale.
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return "p_" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Detect whether a resource secret looks like a credential
 * (`username` + at least one of `password` / `private_key`) vs. a
 * generic key/value blob. The Connection-tab UI uses this to filter
 * the credential picker and to render the credential-secret editor
 * inline.
 */
export function detectSecretShape(data: Record<string, unknown>): ResourceSecretShape {
  const usernameRaw = data["username"];
  const username = typeof usernameRaw === "string" ? usernameRaw : "";
  const hasPassword =
    typeof data["password"] === "string" &&
    (data["password"] as string).length > 0;
  const hasPrivateKey =
    typeof data["private_key"] === "string" &&
    (data["private_key"] as string).length > 0;
  if (username && (hasPassword || hasPrivateKey)) {
    return {
      kind: "credential",
      username,
      has_password: hasPassword,
      has_private_key: hasPrivateKey,
    };
  }
  return {
    kind: "kv",
    keys: Object.keys(data),
  };
}

/** Whether a raw `connection_profiles` entry is one this build can show and
 *  launch. Strict: an unknown protocol, or a missing id / name /
 *  credential source, makes it not-ours (fail closed — never read as SSH). */
function isKnownProfile(p: unknown): p is ConnectionProfile {
  return (
    typeof p === "object" &&
    p !== null &&
    typeof (p as ConnectionProfile).id === "string" &&
    typeof (p as ConnectionProfile).name === "string" &&
    parseSessionProtocol((p as ConnectionProfile).protocol) !== null &&
    typeof (p as ConnectionProfile).credential_source === "object" &&
    (p as ConnectionProfile).credential_source !== null
  );
}

function rawProfiles(meta: Record<string, unknown>): unknown[] {
  const raw = meta["connection_profiles"];
  return Array.isArray(raw) ? raw : [];
}

/** Pull the profile array off a resource metadata object. Tolerates
 *  the field being absent (returns []) or carrying a non-array (the
 *  caller's read just sees an empty list and the operator can
 *  re-create profiles via the editor). Entries this build does not
 *  understand are excluded here (so they are never launched or listed)
 *  but are NOT lost on write: see {@link readUnknownProfiles}. */
export function readProfiles(meta: Record<string, unknown>): ConnectionProfile[] {
  return rawProfiles(meta).filter(isKnownProfile);
}

/** The raw entries {@link readProfiles} excluded — profiles written by a
 *  newer client (unknown protocol or shape). Writers must hand these back
 *  to {@link profilesForWrite} so saving, deleting or re-defaulting a known
 *  profile never deletes a profile this build merely cannot read. */
export function readUnknownProfiles(meta: Record<string, unknown>): unknown[] {
  return rawProfiles(meta).filter((p) => !isKnownProfile(p));
}

function isDefaultFlagged(p: unknown): boolean {
  return typeof p === "object" && p !== null && (p as { is_default?: unknown }).is_default === true;
}

/**
 * Build the array to persist as `connection_profiles`: the known profiles,
 * default-normalised, with the unknown entries re-appended untouched.
 *
 * The data model keeps exactly one default across the whole stored list
 * (`normalizeProfileDefaults`), and unknown entries count toward it:
 *   - when a known profile carries the default (the operator's explicit
 *     choice, or the first one promoted), an unknown entry flagged
 *     `is_default` is the only thing that is edited — its flag is set to
 *     false so the list never holds two defaults;
 *   - when no known profile is flagged and an unknown one is, the unknown
 *     entry already holds the default, so no known profile is promoted
 *     over it.
 * Unknown entries are otherwise returned byte-for-byte as read, after the
 * known ones. Inputs are not mutated.
 */
export function profilesForWrite(known: ConnectionProfile[], unknown: unknown[]): unknown[] {
  const unknownHoldsDefault = unknown.some(isDefaultFlagged);
  const knownFlagged = known.some((p) => p.is_default);
  if (known.length === 0) return [...unknown];
  if (unknownHoldsDefault && !knownFlagged) {
    return [...known.map((p) => ({ ...p, is_default: false })), ...unknown];
  }
  const normalized = normalizeProfileDefaults(known);
  const keptUnknown = unknown.map((p) =>
    isDefaultFlagged(p) ? { ...(p as Record<string, unknown>), is_default: false } : p,
  );
  return [...normalized, ...keptUnknown];
}

/** Empty profile pre-filled with defaults appropriate for the
 *  resource's `os_type`. Caller fills in `name` + the credential
 *  source through the editor. */
export function blankProfile(
  osType: string,
  defaultSecretId?: string,
): ConnectionProfile {
  const protocol = protocolForOsType(osType) ?? "ssh";
  const credential_source: CredentialSource = defaultSecretId
    ? { kind: "secret", secret_id: defaultSecretId }
    : { kind: "secret", secret_id: "" };
  return {
    id: newProfileId(),
    name: "Default",
    protocol,
    credential_source,
  };
}

/**
 * Validate a profile for save-time errors. Returns null on a clean
 * profile or a human-readable error message. Used by the editor
 * "Save" button enable/disable + the form's inline error display.
 */
export function validateProfile(p: ConnectionProfile): string | null {
  if (!p.name.trim()) return "Profile name is required";
  const protocol = parseSessionProtocol(p.protocol);
  if (protocol === null) return "Invalid protocol";
  if (protocol === "web") return validateWebProfile(p);
  if (p.target_port !== undefined) {
    if (
      !Number.isInteger(p.target_port) ||
      p.target_port < 1 ||
      p.target_port > 65535
    ) {
      return "Port must be between 1 and 65535";
    }
  }
  switch (p.credential_source.kind) {
    case "secret":
      if (!p.credential_source.secret_id.trim()) {
        return "Pick a credential secret on this resource";
      }
      return null;
    case "ldap":
      if (!p.credential_source.ldap_mount.trim()) {
        return "LDAP mount is required";
      }
      if (
        p.credential_source.bind_mode === "static_role" &&
        !p.credential_source.static_role?.trim()
      ) {
        return "static_role required for the static-role bind mode";
      }
      if (
        p.credential_source.bind_mode === "library_set" &&
        !p.credential_source.library_set?.trim()
      ) {
        return "library_set required for the library check-out bind mode";
      }
      return null;
    case "ssh-engine":
      if (!p.credential_source.ssh_mount.trim()) {
        return "SSH-engine mount is required";
      }
      if (!p.credential_source.ssh_role.trim()) {
        return "SSH role is required";
      }
      return null;
    case "pki":
      if (!p.credential_source.pki_mount.trim()) {
        return "PKI mount is required";
      }
      if (!p.credential_source.pki_role.trim()) {
        return "PKI role is required";
      }
      return null;
    case "fido2":
      // RDP has no FIDO2 authentication method at all — the closest thing is
      // smartcard/PKINIT, which is the `pki` source. Blocking the save here
      // mirrors the host's own refusal, so the operator finds out in the
      // editor rather than at 3am on a locked-out connect.
      if (p.protocol !== "ssh") {
        return "FIDO2 security keys can only authenticate SSH sessions. For Windows, use the PKI (smartcard) source, and tick \u201cRequire MFA re-validation\u201d if you want a security-key prompt before the session opens.";
      }
      return null;
    case "default-account":
      // SSH brokers a cert/OTP from the engine, so it needs the same
      // mount/role as `ssh-engine`. RDP carries no extra fields (the
      // password is prompted at connect).
      if (p.protocol === "ssh") {
        if (!p.credential_source.ssh_mount?.trim()) {
          return "SSH-engine mount is required for the default-account source";
        }
        if (!p.credential_source.ssh_role?.trim()) {
          return "SSH role is required for the default-account source";
        }
      }
      return null;
    case "none":
      return "SSH and RDP profiles need a credential source";
  }
}

// ── Web profiles (features/web-application-connect.md, T96) ─────────

/** Login modes this release can launch. */
const LAUNCHABLE_WEB_LOGIN_MODES = ["open"] as const;

/** Credential sources that can never authenticate a web session. */
const NEVER_WEB_SOURCES: CredentialSource["kind"][] = ["ssh-engine", "pki", "fido2"];

/**
 * Normalise an operator-typed origin to `scheme://host[:port]`: lower-case
 * host (punycode for IDNs), default port dropped. Mirrors the host's
 * `WebOrigin::parse_config`, which is the authoritative check — this one
 * only lets the editor say no before the connect does.
 */
export function normalizeWebOrigin(
  raw: string,
  allowInsecureHttp: boolean,
): { origin: string } | { error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { error: "An allowed origin is empty" };
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { error: `\`${trimmed}\` is not a valid origin` };
  }
  if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) {
    return {
      error: `\`${trimmed}\` is not a bare origin: give scheme://host[:port] only (no path, query or fragment)`,
    };
  }
  if (url.username || url.password) {
    return { error: `\`${trimmed}\` carries userinfo (user@host); origins may not` };
  }
  const err = webUrlError(url, allowInsecureHttp);
  if (err) return { error: `\`${trimmed}\`: ${err}` };
  return { origin: url.origin };
}

/** Scheme + host rules shared by the start URL and allowed origins. */
function webUrlError(url: URL, allowInsecureHttp: boolean): string | null {
  if (url.protocol === "http:") {
    if (!allowInsecureHttp) {
      return "plain http is refused unless \u201cAllow insecure HTTP\u201d is set";
    }
  } else if (url.protocol !== "https:") {
    return `scheme ${url.protocol} is not allowed (https only)`;
  }
  const host = url.hostname.toLowerCase();
  if (!host) return "missing host";
  if (host.endsWith(".")) {
    return `host ${host} has a trailing dot; browsers treat it as a different origin \u2014 remove the dot`;
  }
  if (host === "localhost" || host.endsWith(".localhost")) {
    return `host ${host} is reserved for the vault's own UI; web sessions may not open it`;
  }
  return null;
}

/**
 * The exact origin set a web profile allows: the start URL's origin plus
 * `allowed_origins`, normalised and de-duplicated. Null when any entry is
 * invalid.
 */
export function webOriginSet(web: WebProfileSettings): string[] | null {
  const allowHttp = web.allow_insecure_http === true;
  let start: URL;
  try {
    start = new URL(web.start_url.trim());
  } catch {
    return null;
  }
  if (start.username || start.password || webUrlError(start, allowHttp)) return null;
  const out = [start.origin];
  for (const raw of web.allowed_origins ?? []) {
    const r = normalizeWebOrigin(raw, allowHttp);
    if ("error" in r) return null;
    if (!out.includes(r.origin)) out.push(r.origin);
  }
  return out;
}

/** Window-size bounds, matching the host. */
export const WEB_WINDOW_MIN = 400;
export const WEB_WINDOW_MAX = 10_000;

/**
 * Save-time validation of a `web` profile. Refuses everything this release
 * cannot honour rather than letting it look honoured: later login modes,
 * the Rustion transport, TLS pins, credential sources that `open` doesn't
 * use.
 */
export function validateWebProfile(p: ConnectionProfile): string | null {
  const cs = p.credential_source.kind;
  if (NEVER_WEB_SOURCES.includes(cs)) {
    return `The ${cs} credential source can't authenticate a web session.`;
  }
  if (p.kind === "rustion") {
    return "Web sessions can't be brokered through a Rustion bastion yet \u2014 use the direct transport.";
  }
  const web = p.web;
  if (!web) return "Web profiles need web settings (start URL, login mode).";
  if (!(LAUNCHABLE_WEB_LOGIN_MODES as readonly string[]).includes(web.login_mode)) {
    return ["form", "http-auth", "sso"].includes(web.login_mode)
      ? `The ${web.login_mode} login mode is not available yet \u2014 this release supports \u201copen\u201d only.`
      : "Unknown login mode.";
  }
  if (cs !== "none") {
    return "The open login mode releases no credential \u2014 set the credential source to \u201cNone\u201d.";
  }
  if (web.transport !== undefined && web.transport !== "local") {
    return web.transport === "rustion-isolated"
      ? "Rustion browser isolation is not available yet."
      : "Unknown web transport.";
  }
  if ((web.tls_pin_sha256 ?? []).length > 0) {
    return "TLS certificate pinning for web sessions is not available yet \u2014 remove the pin.";
  }
  const allowHttp = web.allow_insecure_http === true;
  if (!web.start_url.trim()) return "Start URL is required.";
  let start: URL;
  try {
    start = new URL(web.start_url.trim());
  } catch {
    return "Start URL is not a valid URL.";
  }
  if (start.username || start.password) {
    return "Start URL may not carry user@ credentials \u2014 never put a credential in a URL.";
  }
  const startErr = webUrlError(start, allowHttp);
  if (startErr) return `Start URL: ${startErr}`;
  for (const raw of web.allowed_origins ?? []) {
    const r = normalizeWebOrigin(raw, allowHttp);
    if ("error" in r) return r.error;
  }
  for (const dim of ["width", "height"] as const) {
    const v = web.window?.[dim];
    if (v === undefined) continue;
    if (!Number.isInteger(v) || v < WEB_WINDOW_MIN || v > WEB_WINDOW_MAX) {
      return `Window ${dim} must be a whole number between ${WEB_WINDOW_MIN} and ${WEB_WINDOW_MAX}.`;
    }
  }
  return null;
}

/**
 * A new `web` profile, its start URL pre-filled from the resource's `url`
 * field when it has one.
 */
export function blankWebProfile(resourceUrl?: string): ConnectionProfile {
  return {
    id: newProfileId(),
    name: "Default",
    protocol: "web",
    credential_source: { kind: "none" },
    web: {
      start_url: (resourceUrl ?? "").trim(),
      allowed_origins: [],
      login_mode: "open",
    },
  };
}

/**
 * True when the Connect button can actually launch this profile
 * today. SSH/RDP × {secret, ldap, pki} ship; the SSH secret-engine
 * source is still pending. Mirrors the per-(protocol, source) matrix
 * the Connection-tab editor enforces. Kept here so the resource-card
 * quick-Connect and the Connection-tab launcher agree on launchability.
 */
export function isLaunchableProfile(p: ConnectProfileHint): boolean {
  const protocol = parseSessionProtocol(p.protocol);
  if (protocol === null) return false;
  if (protocol === "web") {
    // Phase 1 launches the `open` mode only, which is exactly the profiles
    // carrying the `none` source (validation pins the two together). The
    // card hint carries no login mode, so the source stands in for it.
    // Rustion-brokered web sessions don't exist yet.
    return p.credential_source.kind === "none" && p.kind !== "rustion";
  }
  switch (p.credential_source.kind) {
    case "secret":
    case "ldap":
    case "pki":
      return true;
    case "ssh-engine":
      // Brokered minting ships (CA-signed cert + OTP). PQC cert auth is
      // still not launchable from the in-app client (russh can't present
      // an ML-DSA-65 cert); the connect path rejects it with a clear
      // message, but the other modes launch.
      return p.credential_source.mode !== "pqc";
    case "fido2":
      // SSH only; see validateProfile.
      return p.protocol === "ssh";
    case "default-account":
      // SSH brokers via the engine (same pqc caveat as `ssh-engine`); RDP
      // prompts for the password at connect and launches.
      if (p.protocol === "ssh") return p.credential_source.mode !== "pqc";
      return true;
    case "none":
      // Only meaningful on a web profile (handled above).
      return false;
  }
}

/**
 * Credential sources `rustion/v2/session/open` resolves server-side, so the
 * material never reaches this process. `default-account` is an `ssh-engine`
 * mint with the operator's own account as the principal; the connect path
 * rewrites it to `ssh-engine` before it calls the server
 * (`open_rustion_session_v2_ssh`). The remaining kinds (ldap / pki / fido2)
 * still resolve client-side even under a brokered transport, so they can't
 * satisfy a connect-only caller.
 */
const SERVER_RESOLVED_SOURCES: CredentialSource["kind"][] = [
  "secret",
  "ssh-engine",
  "default-account",
];

/**
 * Launchable *for this caller*. On top of the phase matrix
 * (`isLaunchableProfile`), a connect-only caller — one without `read` on the
 * resource's secrets — may only open sessions whose credential is resolved
 * server-side: a `direct` dial would resolve it into the local GUI process,
 * defeating the boundary.
 *
 * Two things can make a session brokered, and both count:
 *   - the profile itself is `kind: "rustion"`, or
 *   - `brokeredByPolicy` — the *effective transport tier* is
 *     `rustion-required` (or `rustion-preferred` with a bastion), which
 *     routes the session through a bastion regardless of what the profile
 *     says. Reading only the profile's `kind` was a real bug: a resource
 *     pinned to `rustion-required` by its policy tier, carrying a profile
 *     minted before that field existed (so `kind` defaults to `direct`),
 *     had its safest caller refused the one connection that never touches
 *     their machine.
 *
 * The policy route only helps for the credential kinds the server can
 * resolve, and only for SSH — brokered RDP still goes through v1
 * `rustion/session/open` with a client-resolved credential.
 *
 * The single source of truth for "would Connect do anything?", shared by the
 * Connection-tab launcher, the resource-card quick-Connect, and the ⌘K
 * palette so all three agree on what is offered.
 */
export function isLaunchableForCaller(
  p: ConnectProfileHint,
  connectOnly: boolean,
  brokeredByPolicy = false,
): boolean {
  if (!isLaunchableProfile(p)) return false;
  if (!connectOnly) return true;
  // An `open` web session resolves no credential anywhere, so there is
  // nothing for connect-only access to protect: the server's `connect`
  // gate (and MFA, when required) is the whole check.
  if (p.protocol === "web") return true;
  if (p.kind === "rustion") return true;
  return (
    brokeredByPolicy &&
    p.protocol === "ssh" &&
    SERVER_RESOLVED_SOURCES.includes(p.credential_source.kind)
  );
}

/** True when at least one profile is launchable for this caller. */
export function hasLaunchableProfile(
  profiles: ConnectProfileHint[],
  connectOnly: boolean,
  brokeredByPolicy = false,
): boolean {
  return profiles.some((p) =>
    isLaunchableForCaller(p, connectOnly, brokeredByPolicy),
  );
}

/**
 * Project full profiles down to the card-level hints. Used by the card
 * paths that already hold complete metadata (share fallback, group filter,
 * recently-accessed) so they gate Connect the same way the server-projected
 * search page does.
 */
export function profileConnectHints(
  profiles: ConnectionProfile[],
): ConnectProfileHint[] {
  return profiles.map((p) => ({
    protocol: p.protocol,
    kind: p.kind,
    credential_source: {
      kind: p.credential_source.kind,
      mode:
        "mode" in p.credential_source ? p.credential_source.mode : undefined,
    },
  }));
}

/**
 * The empty `CredentialSource` the profile editor should switch to when the
 * operator picks a different kind in the dropdown.
 *
 * Lives here, with an explicit return type and no `default` branch, so that
 * adding a variant to `CredentialSource` fails `tsc` instead of silently
 * leaving the new kind unselectable — which is exactly what happened to
 * `fido2`: the editor's inline switch had no case for it, the controlled
 * `<Select>` never saw the state change, and the option snapped back.
 */
export function blankCredentialSource(
  kind: CredentialSource["kind"],
): CredentialSource {
  switch (kind) {
    case "secret":
      return { kind: "secret", secret_id: "" };
    case "ldap":
      return { kind: "ldap", ldap_mount: "", bind_mode: "operator" };
    case "ssh-engine":
      return { kind: "ssh-engine", ssh_mount: "", ssh_role: "", mode: "ca" };
    case "pki":
      return { kind: "pki", pki_mount: "", pki_role: "" };
    case "default-account":
      // SSH brokers via the engine (mount/role/mode); RDP ignores the
      // ssh_* fields (the password is prompted at connect).
      return {
        kind: "default-account",
        ssh_mount: "",
        ssh_role: "",
        mode: "ca",
      };
    case "fido2":
      // Carries no fields — the key is resolved at connect time from the
      // connecting operator's own enrolment, never pinned on the profile.
      return { kind: "fido2" };
    case "none":
      return { kind: "none" };
  }
}

/**
 * Brokered login-class gate for the profile editor. Given the resolved
 * effective login class for the resource, returns whether the `secret`
 * SSH source must be disabled (brokered forbids a static credential) and
 * which credential-source kind the editor should force/pre-select.
 *
 * Pure + synchronous so the editor and unit tests share one source of
 * truth; the authoritative enforcement is server-side
 * (`brokered_requires_ssh_engine` on connect, `409` on credential attach).
 */
export function loginClassGate(loginClass: SshLoginClass | undefined): {
  brokered: boolean;
  /** Credential-source kinds the editor should offer. */
  allowedKinds: CredentialSource["kind"][];
  /** Kind to pre-select when the current one is disallowed. */
  forcedKind: CredentialSource["kind"] | null;
} {
  if (loginClass === "brokered") {
    // `default-account` is a brokered SSH-engine mint (it only swaps the
    // principal for the connecting operator's account), so it is allowed
    // alongside `ssh-engine` for brokered resources.
    return {
      brokered: true,
      allowedKinds: ["ssh-engine", "default-account"],
      forcedKind: "ssh-engine",
    };
  }
  return {
    brokered: false,
    allowedKinds: [
      "secret",
      "ldap",
      "ssh-engine",
      "pki",
      "default-account",
      "fido2",
    ],
    forcedKind: null,
  };
}

/**
 * Validate a profile against a resolved effective login class. Returns
 * null when the profile is allowed, or a human-readable error when a
 * brokered resource is paired with a non-`ssh-engine` (static-capable)
 * source. Mirrors the host's `brokered_requires_ssh_engine` rejection so
 * the editor blocks the save before the connect attempt does.
 */
export function validateProfileForLoginClass(
  p: ConnectionProfile,
  loginClass: SshLoginClass | undefined,
): string | null {
  if (p.protocol !== "ssh") return null;
  if (loginClass !== "brokered") return null;
  if (
    p.credential_source.kind !== "ssh-engine" &&
    p.credential_source.kind !== "default-account"
  ) {
    if (p.credential_source.kind === "fido2") {
      return "This resource is brokered: every SSH login must be minted per-connect from the SSH engine. A FIDO2 security key can't satisfy that \u2014 the key is on your desk, not on the bastion. Use the SSH-engine source, and tick \u201cRequire MFA re-validation\u201d if you want a security-key prompt before the session opens.";
    }
    return "This resource is brokered: SSH logins must use the SSH-engine (or default-account) credential source (no static credential).";
  }
  return null;
}

/**
 * True when launching this profile needs an interactive operator
 * credential prompt before the session can open (LDAP operator-bind).
 * The resource-card quick-Connect can't satisfy this inline, so it
 * routes such profiles to the Connection tab instead of firing
 * blindly.
 */
export function needsOperatorPrompt(p: ConnectionProfile): boolean {
  if (
    p.credential_source.kind === "ldap" &&
    p.credential_source.bind_mode === "operator"
  ) {
    return true;
  }
  // RDP default-account resolves the login name server-side but still needs a
  // password, which a username-only account can't carry — prompt for it.
  if (p.credential_source.kind === "default-account" && p.protocol === "rdp") {
    return true;
  }
  return false;
}

/**
 * Pick the profile a one-click Connect should launch:
 *   1. the launchable profile flagged `is_default`, else
 *   2. the sole launchable profile, else
 *   3. null — the caller should surface the picker (Connection tab)
 *      because there's genuine ambiguity (multiple profiles, none
 *      marked default) or nothing launchable at all.
 *
 * `connectOnly` / `brokeredByPolicy` mirror the Connection tab's own
 * filter: a caller who can't read the resource's credentials only counts
 * brokered profiles as launchable, so a quick-Connect never fires a direct
 * dial the server would refuse.
 */
export function pickDefaultProfile(
  profiles: ConnectionProfile[],
  connectOnly = false,
  brokeredByPolicy = false,
): ConnectionProfile | null {
  const launchable = profiles.filter((p) =>
    isLaunchableForCaller(p, connectOnly, brokeredByPolicy),
  );
  if (launchable.length === 0) return null;
  const flagged = launchable.find((p) => p.is_default);
  if (flagged) return flagged;
  if (launchable.length === 1) return launchable[0];
  return null;
}

/**
 * Enforce the at-most-one-default invariant on a profile list before
 * it is persisted:
 *   - When two or more carry `is_default`, keep the first and clear
 *     the rest (last-write-wins is handled by the caller setting the
 *     flag on the chosen one *before* calling this).
 *   - When none carry it but the list is non-empty, promote the first
 *     profile so every resource with profiles has exactly one default.
 * Returns a new array; inputs are not mutated.
 */
export function normalizeProfileDefaults(
  profiles: ConnectionProfile[],
): ConnectionProfile[] {
  if (profiles.length === 0) return profiles.map((p) => ({ ...p }));
  const flaggedIdx = profiles.findIndex((p) => p.is_default);
  const keepIdx = flaggedIdx >= 0 ? flaggedIdx : 0;
  return profiles.map((p, i) => ({ ...p, is_default: i === keepIdx }));
}

/** Filter a profile list to those whose protocol matches the
 *  Connect button's choice for the current `os_type`. */
export function profilesForOsType(
  profiles: ConnectionProfile[],
  osType: string,
): ConnectionProfile[] {
  const protocol = protocolForOsType(osType);
  if (!protocol) return [];
  return profiles.filter((p) => p.protocol === protocol);
}
