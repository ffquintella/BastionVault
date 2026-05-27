//! GUI-side helpers for the Resource Connect feature
//! (`features/resource-connect.md`).
//!
//! Profile storage shape: each resource carries `connection_profiles:
//! ConnectionProfile[]` as a key in its flexible metadata bag. The
//! resource backend accepts this without schema changes — the field
//! is opaque to the host.

import type {
  ConnectionProfile,
  CredentialSource,
  ResourceSecretShape,
  SessionProtocol,
} from "./types";

/** Default port per (protocol). Per-OS-type defaults that override
 *  these live on the operator-side `ResourceTypeDef.connect`
 *  (Phase 7) — for v1 the protocol default is enough. */
export function defaultPort(protocol: SessionProtocol): number {
  return protocol === "ssh" ? 22 : 3389;
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

/** Pull the profile array off a resource metadata object. Tolerates
 *  the field being absent (returns []) or carrying a non-array (the
 *  caller's read just sees an empty list and the operator can
 *  re-create profiles via the editor). */
export function readProfiles(meta: Record<string, unknown>): ConnectionProfile[] {
  const raw = meta["connection_profiles"];
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (p): p is ConnectionProfile =>
      typeof p === "object" &&
      p !== null &&
      typeof (p as ConnectionProfile).id === "string" &&
      typeof (p as ConnectionProfile).name === "string" &&
      ((p as ConnectionProfile).protocol === "ssh" ||
        (p as ConnectionProfile).protocol === "rdp") &&
      typeof (p as ConnectionProfile).credential_source === "object" &&
      (p as ConnectionProfile).credential_source !== null,
  );
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
  if (p.protocol !== "ssh" && p.protocol !== "rdp") return "Invalid protocol";
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
  }
}

/**
 * True when the Connect button can actually launch this profile
 * today. SSH/RDP × {secret, ldap, pki} ship; the SSH secret-engine
 * source is still pending. Mirrors the per-(protocol, source) matrix
 * the Connection-tab editor enforces. Kept here so the resource-card
 * quick-Connect and the Connection-tab launcher agree on launchability.
 */
export function isLaunchableProfile(p: ConnectionProfile): boolean {
  if (p.protocol !== "ssh" && p.protocol !== "rdp") return false;
  switch (p.credential_source.kind) {
    case "secret":
    case "ldap":
    case "pki":
      return true;
    case "ssh-engine":
      return false;
  }
}

/**
 * True when launching this profile needs an interactive operator
 * credential prompt before the session can open (LDAP operator-bind).
 * The resource-card quick-Connect can't satisfy this inline, so it
 * routes such profiles to the Connection tab instead of firing
 * blindly.
 */
export function needsOperatorPrompt(p: ConnectionProfile): boolean {
  return (
    p.credential_source.kind === "ldap" &&
    p.credential_source.bind_mode === "operator"
  );
}

/**
 * Pick the profile a one-click Connect should launch:
 *   1. the launchable profile flagged `is_default`, else
 *   2. the sole launchable profile, else
 *   3. null — the caller should surface the picker (Connection tab)
 *      because there's genuine ambiguity (multiple profiles, none
 *      marked default) or nothing launchable at all.
 */
export function pickDefaultProfile(
  profiles: ConnectionProfile[],
): ConnectionProfile | null {
  const launchable = profiles.filter(isLaunchableProfile);
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
