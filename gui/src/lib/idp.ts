// Typed wrappers for the Identity Provider Tauri commands (T52 Phase 7,
// features/identity-provider.md; routes in docs/api.md). The commands pin
// every request to `/v2/idp/...` in the root namespace. One-time secrets in
// these responses (client secrets, passcodes) must go straight to the
// one-time-secret modal: never into a store, storage, a URL or the console.
import { invoke } from "./invoke";
import { extractError } from "./error";

export type IdpIdentityState = "active" | "disabled" | "removed";
export type IdpSettingsKind = "core" | "ssh" | "radius" | "oidc" | "saml" | "ldap";
export type IdpKind =
  | "identity"
  | "environment"
  | "radius_client"
  | "radius_profile"
  | "oidc_client"
  | "saml_sp"
  | "ldap_client";
export type IdpKeyRing = "oidc" | "saml";

/** Data plus the engine's warnings (cleartext transports, secret shown once). */
export interface IdpResponse<T> {
  data: T;
  warnings: string[];
}

export interface IdpList<I> {
  keys: string[];
  key_info: Record<string, I>;
}

export interface IdpCoreConfig {
  version?: number;
  uid_min: number;
  uid_max: number;
  gid_min: number;
  gid_max: number;
  pinned: boolean;
  updated_at: string | null;
  uid_high_water: number | null;
  uid_used: number;
  uid_retired: number;
  gid_high_water: number | null;
  gid_used: number;
  gid_retired: number;
}

export interface IdpIdentityInfo {
  login: string;
  uid: number;
  primary_gid: number;
  state: IdpIdentityState;
}

export interface IdpIdentity extends IdpIdentityInfo {
  entity_id: string;
  gids: number[];
  display_name: string | null;
  uid_source: "vault" | "imported";
  allocated_at: string;
  updated_at: string;
  state_changed_at: string | null;
  state_reason: string | null;
  revoked_certificates?: number;
  deny_feed_version?: number;
}

export interface IdpEnvironmentInfo {
  namespace: string;
  state: "active" | "retired";
  roles: string[];
}

export interface IdpEnvironment {
  name: string;
  namespace: string;
  namespace_uuid: string;
  roles: Record<string, string[]>;
  description: string | null;
  state: "active" | "retired";
  created_at: string;
  updated_at: string;
  retired_at: string | null;
}

export interface IdpEntitlement {
  entity_id: string;
  environment: string;
  roles: string[];
  not_after: string | null;
  source: "manual" | "external" | "group";
  granted_by: string;
  granted_at: string;
}

export interface IdpEntitlementSet {
  entity_id: string;
  entitlements: Record<string, IdpEntitlement>;
}

export interface IdpListenerStatus {
  radsec?: string | null;
  udp?: string | null;
  ldaps?: string | null;
  ldap?: string | null;
  last_error: string | null;
}

export interface IdpSshConfig {
  enabled: boolean;
  mount?: string;
  role?: string;
  default_ttl?: number;
  max_ttl?: number;
  ttl_ceiling?: number;
  updated_at?: string;
}

export interface IdpSshCertificate {
  signed_key: string;
  serial_number: string;
  key_id: string;
  principals: string[];
  login: string;
  uid: number;
  gid: number;
  environment: string;
  namespace: string;
  roles: string[];
  valid_after: number;
  valid_before: number;
}

export interface IdpKrl {
  krl: string;
  krl_version: number;
  generated_at: number;
  revoked_serials: string[];
}

export interface IdpDenyFeed {
  feed: string;
  signature: string;
  algorithm: string;
  key_id: string;
  feed_version: number;
}

export interface IdpDenyFeedKey {
  algorithm: string;
  key_id: string;
  ed25519: string;
  mldsa65: string;
}

/** The deny feed's JSON payload (docs/api.md), decoded for display only. */
export interface IdpDenyFeedPayload {
  format: string;
  format_version: number;
  feed_version: number;
  generated_at: number;
  identities: { entity_id: string; login: string; uid: number; state: string; since: number | string }[];
  revoked_serials: string[];
}

export interface IdpRadiusConfig {
  enabled: boolean;
  radsec_listen?: string | null;
  udp_enabled?: boolean;
  udp_listen?: string | null;
  allow_unspecified_bind?: boolean;
  tls_cert_pem?: string | null;
  tls_key_set?: boolean;
  client_ca_pem?: string | null;
  rate_limit_per_minute?: number;
  passcode_default_ttl?: number;
  passcode_max_ttl?: number;
  passcode_ttl_ceiling?: number;
  updated_at?: string;
  listening?: IdpListenerStatus;
}

export interface IdpRadiusClientInfo {
  transport: "radsec" | "udp";
  environment: string;
  profile: string;
}

export interface IdpRadiusClient extends IdpRadiusClientInfo {
  name: string;
  address: string | null;
  secret_set: boolean;
  cert_sha256: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface IdpVendorAttribute {
  attribute: string;
  value: string;
  vendor_id?: number;
  vendor_type?: number;
}

export interface IdpRadiusProfile {
  name: string;
  environment: string;
  roles: Record<string, IdpVendorAttribute[]>;
  description: string | null;
}

export interface IdpPasscode {
  passcode: string;
  login: string;
  environment: string;
  roles?: string[];
  bind_dn?: string;
  expires_at: string;
  ttl: number;
}

export interface IdpOidcConfig {
  enabled: boolean;
  issuer?: string;
  authorization_endpoint?: string;
  id_token_ttl?: number;
  code_ttl?: number;
  updated_at?: string;
}

export interface IdpOidcClientInfo {
  environment: string;
  redirect_uris: string[];
}

export interface IdpOidcClient extends IdpOidcClientInfo {
  client_id: string;
  initiate_login_uri: string | null;
  description: string | null;
  created?: boolean;
  /** Present only on create or `rotate_secret`; shown once, never stored. */
  client_secret?: string;
}

export interface IdpSigningKey {
  kid: string;
  alg: string;
  current: boolean;
  published: boolean;
  created_at: string;
  retired_at: string | null;
  publish_until: string | null;
  certificate: string;
}

export interface IdpSamlConfig {
  enabled: boolean;
  entity_id?: string;
  sso_url?: string;
  assertion_ttl?: number;
  request_max_age?: number;
  updated_at?: string;
}

export interface IdpSamlSpInfo {
  entity_id: string;
  environment: string;
}

export interface IdpSamlSp extends IdpSamlSpInfo {
  name: string;
  acs_urls: string[];
  allow_idp_initiated: boolean;
  description: string | null;
}

export interface IdpSamlMetadata {
  metadata: string;
  entity_id: string;
  sso_url: string;
  certificate: string;
}

export interface IdpLdapConfig {
  enabled: boolean;
  ldaps_listen?: string | null;
  ldap_listen?: string | null;
  plaintext_enabled?: boolean;
  starttls?: boolean;
  allow_unspecified_bind?: boolean;
  tls_cert_pem?: string | null;
  tls_key_set?: boolean;
  client_ca_pem?: string | null;
  base_dn?: string;
  home_directory_base?: string;
  login_shell?: string;
  size_limit?: number;
  time_limit?: number;
  rate_limit_per_minute?: number;
  passcode_default_ttl?: number;
  passcode_max_ttl?: number;
  updated_at?: string;
  listening?: IdpListenerStatus;
}

export interface IdpLdapClientInfo {
  transport: "tls" | "plain";
  environment: string;
}

export interface IdpLdapClient extends IdpLdapClientInfo {
  name: string;
  cert_sha256: string | null;
  address: string | null;
  description: string | null;
}

type Body = Record<string, unknown>;

// ── Mount and settings ──────────────────────────────────────────────

export const idpEnableMount = () => invoke<void>("idp_enable_mount");
export const idpReadSettings = <T>(settings: IdpSettingsKind) =>
  invoke<IdpResponse<T>>("idp_read_settings", { settings });
/** Send only the fields that changed; a write-only key only when typed. */
export const idpWriteSettings = <T>(settings: IdpSettingsKind, body: Body) =>
  invoke<IdpResponse<T>>("idp_write_settings", { settings, body });

// ── Named records ───────────────────────────────────────────────────

export const idpList = <I>(kind: IdpKind) => invoke<IdpList<I>>("idp_list", { kind });
export const idpRead = <T>(kind: IdpKind, name: string) =>
  invoke<IdpResponse<T>>("idp_read", { kind, name });
export const idpWrite = <T>(kind: IdpKind, name: string, body: Body) =>
  invoke<IdpResponse<T>>("idp_write", { kind, name, body });
/** Not for identities: removal goes through `idpSetIdentityState`. */
export const idpDelete = <T>(kind: Exclude<IdpKind, "identity">, name: string) =>
  invoke<IdpResponse<T>>("idp_delete", { kind, name });

// ── Identities and entitlements ─────────────────────────────────────

export const idpSetIdentityState = (entityId: string, target: IdpIdentityState, reason?: string) =>
  invoke<IdpResponse<IdpIdentity>>("idp_set_identity_state", {
    entityId,
    target,
    reason: reason?.trim() || null,
  });
export const idpListEntitlements = (entityId: string) =>
  invoke<IdpResponse<IdpEntitlementSet>>("idp_list_entitlements", { entityId });
export const idpWriteEntitlement = (
  entityId: string,
  environment: string,
  grant: { roles: string[]; not_after?: string | null; source?: "manual" | "external" },
) => {
  const body: Body = { roles: grant.roles };
  if (grant.not_after) body.not_after = grant.not_after;
  if (grant.source) body.source = grant.source;
  return invoke<IdpResponse<IdpEntitlement>>("idp_write_entitlement", { entityId, environment, body });
};
export const idpRevokeEntitlement = (entityId: string, environment: string) =>
  invoke<IdpResponse<IdpEntitlement>>("idp_revoke_entitlement", { entityId, environment });

// ── Keys, revocation, metadata ──────────────────────────────────────

export const idpReadKeys = (ring: IdpKeyRing) =>
  invoke<IdpResponse<{ keys: IdpSigningKey[] }>>("idp_read_keys", { ring });
export const idpRotateKeys = (ring: IdpKeyRing, overlap?: string) =>
  invoke<IdpResponse<{ keys: IdpSigningKey[] }>>("idp_rotate_keys", { ring, overlap: overlap?.trim() || null });
export const idpReadKrl = () => invoke<IdpResponse<IdpKrl>>("idp_ssh_krl");
export const idpReadDenyFeed = () => invoke<IdpResponse<IdpDenyFeed>>("idp_deny_feed");
export const idpReadDenyFeedKey = () => invoke<IdpResponse<IdpDenyFeedKey>>("idp_deny_feed_key");
export const idpReadSamlMetadata = () => invoke<IdpResponse<IdpSamlMetadata>>("idp_saml_metadata");

// ── Self-service (the signed-in user's own token; root is refused) ──

export const idpSshSign = (environment: string, publicKey: string, ttl?: string, roles?: string[]) =>
  invoke<IdpResponse<IdpSshCertificate>>("idp_ssh_sign", {
    environment,
    publicKey,
    ttl: ttl?.trim() || null,
    roles: roles && roles.length > 0 ? roles : null,
  });
export const idpRadiusPasscode = (environment: string, ttl?: string, roles?: string[]) =>
  invoke<IdpResponse<IdpPasscode>>("idp_radius_passcode", {
    environment,
    ttl: ttl?.trim() || null,
    roles: roles && roles.length > 0 ? roles : null,
  });
export const idpLdapPasscode = (environment: string, ttl?: string) =>
  invoke<IdpResponse<IdpPasscode>>("idp_ldap_passcode", { environment, ttl: ttl?.trim() || null });

// ── Helpers ─────────────────────────────────────────────────────────

/** The probe found no `idp` mount (embedded: "Router mount not found."; remote: 404). */
export function isIdpNotMounted(e: unknown): boolean {
  return /mount not found/i.test(extractError(e));
}

/**
 * A self-service route refused a token with no entity (the root token, or a
 * token minted without an auth backend). Shown as an explanation, never
 * worked around: these actions are the caller's own identity by design.
 */
export function isNoEntityRefusal(e: unknown): boolean {
  return /not bound to an entity/i.test(extractError(e));
}

export function describeIdpError(e: unknown): string {
  if (isNoEntityRefusal(e)) {
    return (
      "This action uses your own workforce identity, and the signed-in token is not bound to an " +
      "entity (the root token never is). Sign in with your own user account to use it."
    );
  }
  return extractError(e);
}

/** Decode the deny feed's payload for display. It is NOT verified here. */
export function decodeDenyFeed(feedB64: string): IdpDenyFeedPayload | null {
  try {
    const bin = atob(feedB64.trim());
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.identities)) return null;
    return parsed as IdpDenyFeedPayload;
  } catch {
    return null;
  }
}

/** A comma/newline list as trimmed, non-empty entries. */
export function splitList(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** RFC 3339 (or null) from a `datetime-local` value, in the viewer's zone. */
export function localInputToRfc3339(local: string): string | null {
  if (!local) return null;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function formatTime(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const d = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

export function formatSeconds(secs: number | null | undefined): string {
  if (secs === null || secs === undefined) return "—";
  if (secs % 3600 === 0 && secs >= 3600) return `${secs / 3600}h`;
  if (secs % 60 === 0 && secs >= 60) return `${secs / 60}m`;
  return `${secs}s`;
}
