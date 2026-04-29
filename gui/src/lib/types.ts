export type VaultMode = "Embedded" | "Remote";

export interface VaultStatus {
  initialized: boolean;
  sealed: boolean;
  has_vault: boolean;
}

export interface RemoteProfile {
  name: string;
  address: string;
  tls_skip_verify: boolean;
  ca_cert_path?: string;
  client_cert_path?: string;
  client_key_path?: string;
}

export interface RemoteStatus {
  connected: boolean;
  address: string;
  initialized: boolean;
  sealed: boolean;
}

export interface Preferences {
  mode: VaultMode;
  remote_profile?: RemoteProfile;
  password_policy?: PasswordPolicy;
}

/**
 * Minimum-acceptable password composition enforced by the built-in
 * generator. Stored in the GUI's local preferences.json.
 */
export interface PasswordPolicy {
  min_length: number;
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  min_length: 16,
  require_lowercase: true,
  require_uppercase: true,
  require_digits: true,
  require_symbols: false,
};

export interface InitResponse {
  root_token: string;
  /** Hex-encoded unseal key — the cryptographic master that
   *  unlocks the sealed vault on every open ceremony. The GUI
   *  caches a copy keyed by vault-id, but the InitPage success
   *  screen prompts the operator to back this up out-of-band:
   *  losing it AND the keystore cache means losing the vault. */
  unseal_key_hex: string;
}

export interface LoginResponse {
  token: string;
  policies: string[];
}

export interface MountInfo {
  path: string;
  mount_type: string;
  description: string;
}

// Secrets
export interface SecretData {
  data: Record<string, unknown>;
}

export interface SecretListResult {
  keys: string[];
}

// KV-v2 version history
export interface SecretVersionInfo {
  version: number;
  created_time: string;
  deletion_time: string;
  destroyed: boolean;
  username: string;
  /** "create" | "update" | "restore" | "" for legacy entries without an op */
  operation: string;
}

export interface SecretVersionListResult {
  current_version: number;
  oldest_version: number;
  /** Newest version first. */
  versions: SecretVersionInfo[];
}

export interface SecretVersionData {
  data: Record<string, unknown>;
  version: number;
  created_time: string;
  deletion_time: string;
  destroyed: boolean;
  username: string;
  operation: string;
}

// Users
export interface UserListResult {
  users: string[];
}

export interface UserInfo {
  username: string;
  policies: string[];
}

// Policies
export interface PolicyListResult {
  policies: string[];
}

export interface PolicyContent {
  name: string;
  policy: string;
}

/**
 * Audit entry for a policy change. `before_raw` is the HCL text prior
 * to the change (empty for `create`); `after_raw` is the new HCL text
 * (empty for `delete`). History is retained after delete so the trail
 * remains complete.
 */
export interface PolicyHistoryEntry {
  ts: string;
  user: string;
  /** "create" | "update" | "delete" */
  op: string;
  before_raw: string;
  after_raw: string;
}

export interface PolicyHistoryResult {
  /** Newest entry first. */
  entries: PolicyHistoryEntry[];
}

// Resources
export interface ResourceMetadata {
  name: string;
  type: string;
  tags: string;
  notes: string;
  created_at: string;
  updated_at: string;
  // Flexible fields — any key/value pairs defined by the resource type
  [key: string]: unknown;
}

// Resource type definition (stored in config/types)
export interface ResourceFieldDef {
  key: string;
  label: string;
  type: "text" | "number" | "url" | "ip" | "fqdn" | "select";
  placeholder?: string;
  /** Required when `type === "select"`; ignored otherwise. */
  options?: { value: string; label: string }[];
}

export interface ResourceTypeDef {
  id: string;
  label: string;
  color: "info" | "success" | "warning" | "error" | "neutral";
  fields: ResourceFieldDef[];
  /** Per-type Resource-Connect policy (Phase 7). Optional —
   *  omitted = enabled. When `enabled = false`, the Connect
   *  button + the Connection tab are hidden for every resource
   *  of this type. The default-ports / default-users blocks are
   *  forward-compat for a future "smart defaults" pass; today
   *  the protocol's standard port (22 / 3389) is used. */
  connect?: {
    enabled?: boolean;
    default_ports?: { ssh?: number; rdp?: number };
    default_users?: { linux?: string; macos?: string; windows?: string };
  };
}

export type ResourceTypeConfig = Record<string, ResourceTypeDef>;

// ── Resource Connect — Connection profiles ─────────────────────────
// See features/resource-connect.md. Each server resource carries
// zero or more profiles binding (protocol, target, credential source)
// the Connect button uses. Stored as a flexible JSON array on the
// resource record; the resource module accepts it without any
// backend schema change.

export type SessionProtocol = "ssh" | "rdp";

export type CredentialSource =
  | { kind: "secret"; secret_id: string }
  | {
      kind: "ldap";
      ldap_mount: string;
      bind_mode: "operator" | "static_role" | "library_set";
      static_role?: string;
      library_set?: string;
    }
  | {
      kind: "ssh-engine";
      ssh_mount: string;
      ssh_role: string;
      mode: "ca" | "otp" | "pqc";
    }
  | {
      kind: "pki";
      pki_mount: string;
      pki_role: string;
      cert_ttl_secs?: number;
    };

export interface ConnectionProfile {
  /** Stable per-resource id, generated client-side on create. */
  id: string;
  /** Operator-visible label (e.g. "Default", "Break-glass"). */
  name: string;
  protocol: SessionProtocol;
  /** Overrides the resource's hostname/ip when set. */
  target_host?: string;
  /** Overrides the resource's port / protocol default. */
  target_port?: number;
  /** SSH user / RDP user; some sources supply their own. */
  username?: string;
  credential_source: CredentialSource;
  /** TOFU pin: SSH host-key fingerprint or RDP cert thumbprint. */
  host_key_pin?: string;
  /** Opt-in for legacy auth modes; logged at WARN every connect. */
  allow_legacy_auth?: boolean;
}

/**
 * One recently-opened session. Persisted on the resource record's
 * `recent_sessions` array; the host appends an entry on every
 * successful `session_open_*` call and trims to a fixed cap so
 * the resource record doesn't grow without bound. Surfaced on
 * the Connection tab for quick "open the same one again" clicks.
 */
export interface RecentSession {
  /** RFC3339 UTC timestamp of when the session opened. */
  ts: string;
  /** Profile id used to launch. */
  profile_id: string;
  /** Profile name at the time of launch (cached because the
   *  profile may have been renamed since). */
  profile_name: string;
  /** Operator who opened it. Display name when known, else the
   *  vault entity id, else "unknown". */
  actor: string;
  /** Effective protocol of the session (`ssh` / `rdp`). */
  protocol: SessionProtocol;
}

/**
 * GUI-side detection of credential-shaped resource secrets vs.
 * generic kv secrets. A secret whose JSON carries a `username` field
 * is rendered with the dedicated credential editor (split-input
 * + masked password + paste-PEM private key) instead of the
 * generic key/value editor.
 */
export type ResourceSecretShape =
  | {
      kind: "credential";
      username: string;
      has_password: boolean;
      has_private_key: boolean;
    }
  | { kind: "kv"; keys: string[] };

export interface ResourceListResult {
  resources: string[];
}

export interface ResourceSecretListResult {
  keys: string[];
}

export interface ResourceSecretData {
  data: Record<string, unknown>;
}

// Resource change-history (metadata changes only -- field names, no values)
export interface ResourceHistoryEntry {
  ts: string;
  user: string;
  /** "create" | "update" | "delete" */
  op: string;
  changed_fields: string[];
}

export interface ResourceHistoryResult {
  /** Newest entry first. */
  entries: ResourceHistoryEntry[];
}

// Resource-secret version history
export interface ResourceSecretVersionInfo {
  version: number;
  created_time: string;
  username: string;
  /** "create" | "update" | "restore" */
  operation: string;
}

export interface ResourceSecretVersionListResult {
  current_version: number;
  /** Newest version first. */
  versions: ResourceSecretVersionInfo[];
}

export interface ResourceSecretVersionData {
  data: Record<string, unknown>;
  version: number;
  created_time: string;
  username: string;
  operation: string;
}

// AppRole
export interface AppRoleListResult {
  roles: string[];
}

export interface AppRoleInfo {
  name: string;
  bind_secret_id: boolean;
  secret_id_num_uses: number;
  secret_id_ttl: number;
  token_policies: string[];
  token_ttl: number;
  token_max_ttl: number;
  token_num_uses: number;
  secret_id_bound_cidrs: string[];
  token_bound_cidrs: string[];
}

export interface RoleIdInfo {
  role_id: string;
}

export interface SecretIdResponse {
  secret_id: string;
  secret_id_accessor: string;
  secret_id_ttl: number;
}

export interface SecretIdAccessorList {
  accessors: string[];
}

export interface SecretIdAccessorInfo {
  secret_id_accessor: string;
  secret_id_num_uses: number;
  secret_id_ttl: number;
  creation_time: string;
  expiration_time: string;
  metadata: Record<string, string>;
  cidr_list: string[];
}

// Identity groups
export type GroupKind = "user" | "app";

export interface GroupListResult {
  groups: string[];
}

export interface GroupInfo {
  name: string;
  kind: string;
  description: string;
  members: string[];
  policies: string[];
  created_at: string;
  updated_at: string;
}

/**
 * A single audit entry for a group change. `before` and `after` contain
 * the values of exactly the fields listed in `changed_fields`:
 *   - `description`: string
 *   - `members`, `policies`: string[]
 * `before` is empty for `create`; `after` is empty for `delete`.
 */
export interface GroupHistoryEntry {
  ts: string;
  user: string;
  /** "create" | "update" | "delete" */
  op: string;
  changed_fields: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export interface GroupHistoryResult {
  /** Newest entry first. */
  entries: GroupHistoryEntry[];
}

// Asset groups (resources + KV secrets). The backend mount is
// `resource-group/` for historical reasons; the GUI label is
// "Asset Groups" to distinguish from the principal-oriented
// "Identity Groups".

export interface AssetGroupListResult {
  groups: string[];
}

export interface AssetGroupInfo {
  name: string;
  description: string;
  /** Resource names in the group. */
  members: string[];
  /** KV-secret paths in the group, stored canonicalized (`secret/foo/bar`). */
  secrets: string[];
  /** entity_id of the caller that created the group; empty when created by a
   *  root token. Gates membership edits to (owner ∪ admins). */
  owner_entity_id: string;
  created_at: string;
  updated_at: string;
}

/**
 * A single audit entry for an asset-group change. `before` / `after`
 * carry the values of exactly the fields listed in `changed_fields`:
 *   - `description`: string
 *   - `members`, `secrets`: string[]
 * `before` is empty for `create`; `after` is empty for `delete`.
 */
export interface AssetGroupHistoryEntry {
  ts: string;
  user: string;
  /** "create" | "update" | "delete" */
  op: string;
  changed_fields: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export interface AssetGroupHistoryResult {
  /** Newest entry first. */
  entries: AssetGroupHistoryEntry[];
}

export interface AssetGroupLookupResult {
  /** Group names the object is a member of. */
  groups: string[];
}

// Per-user scoping: entity, owner, sharing.

export interface EntitySelf {
  entity_id: string;
  username: string;
  mount_path: string;
  role_name: string;
  primary_mount: string;
  primary_name: string;
  created_at: string;
}

/** `(mount, principal-name, entity_id)` triple used to populate the
 *  user-picker in share dialogs — operators pick a login instead of
 *  pasting a raw `entity_id`. */
export interface EntityAliasInfo {
  mount: string;
  name: string;
  entity_id: string;
}

/** One row of the admin audit trail. `category` identifies the subsystem
 *  the event came from (`policy`, `identity-group-user`,
 *  `identity-group-app`, `asset-group`). `changed_fields` may be empty
 *  (policies don't track field-level diffs; only raw-HCL before/after). */
export interface AuditEvent {
  ts: string;
  user: string;
  /** "create" | "update" | "delete" */
  op: string;
  category: string;
  target: string;
  changed_fields: string[];
  summary: string;
}

export type ShareTargetKind = "kv-secret" | "resource" | "asset-group";

export interface OwnerInfo {
  target_kind: string;
  target: string;
  /** Empty string when no owner record exists yet. */
  entity_id: string;
  owned: boolean;
  created_at: string;
}

/** A share-pointer — what the `by-grantee` list returns; load the
 *  full record via `getShare` or equivalent if values are needed. */
export interface SharePointer {
  target_kind: string;
  target_path: string;
}

export interface ShareEntry {
  target_kind: string;
  target_path: string;
  grantee_entity_id: string;
  granted_by_entity_id: string;
  /** Subset of "read" | "list" | "update" | "delete" | "create". */
  capabilities: string[];
  granted_at: string;
  /** RFC3339 or empty. */
  expires_at: string;
  expired: boolean;
}

// File Resources
export interface FileMeta {
  id: string;
  name: string;
  resource: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  tags: string[];
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface FileListResult {
  ids: string[];
}

export interface FileContentResult {
  id: string;
  mime_type: string;
  size_bytes: number;
  content_base64: string;
}

export interface FileSyncState {
  last_success_at: string;
  last_success_sha256: string;
  last_failure_at: string;
  last_error: string;
}

export interface FileSyncTarget {
  name: string;
  kind: string;
  target_path: string;
  mode: string;
  sync_on_write: boolean;
  created_at: string;
  updated_at: string;
  state: FileSyncState;
}

export interface FileSyncListResult {
  id: string;
  targets: FileSyncTarget[];
}

export interface FileHistoryEntry {
  ts: string;
  user: string;
  op: string;
  changed_fields: string[];
}

export interface FileVersionInfo {
  version: number;
  size_bytes: number;
  sha256: string;
  name: string;
  mime_type: string;
  created_at: string;
  user: string;
}

export interface FileVersionListResult {
  id: string;
  current_version: number;
  versions: FileVersionInfo[];
}

export interface FileHistoryResult {
  id: string;
  entries: FileHistoryEntry[];
}

// FIDO2
export interface Fido2Config {
  rp_id: string;
  rp_origin: string;
  rp_name: string;
}

export interface Fido2ChallengeResponse {
  data: Record<string, unknown>;
}

export interface Fido2LoginResponse {
  token: string;
  policies: string[];
}

export interface Fido2CredentialInfo {
  username: string;
  registered_keys: number;
  fido2_enabled: boolean;
}

// ── PKI Secret Engine ───────────────────────────────────────────────

export interface PkiMountInfo {
  path: string;
  mount_type: string;
}

export interface PkiIssuerSummary {
  id: string;
  name: string;
  is_default: boolean;
}

export interface PkiIssuerListResult {
  issuers: PkiIssuerSummary[];
}

export interface PkiIssuerDetail {
  id: string;
  name: string;
  certificate: string;
  key_type: string;
  common_name: string;
  not_after: number;
  ca_kind: string;
  is_default: boolean;
  usage: string[];
}

export interface PkiDefaultIssuer {
  default: string;
  default_name: string;
}

export interface PkiGenerateRootRequest {
  mount: string;
  /** "internal" | "exported" */
  mode: "internal" | "exported";
  common_name: string;
  organization?: string;
  /** "rsa" | "ec" | "ed25519" | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "ecdsa-p256+ml-dsa-65" */
  key_type?: string;
  /** RSA: 2048/3072/4096; EC: 256/384; everything else: 0 */
  key_bits?: number;
  ttl?: string;
  issuer_name?: string;
}

export interface PkiRootResult {
  certificate: string;
  issuer_id: string;
  issuer_name: string;
  expiration: number;
  /** Only populated in `exported` mode. */
  private_key?: string;
  private_key_type?: string;
}

export interface PkiGenerateIntermediateRequest {
  mount: string;
  mode: "internal" | "exported";
  common_name: string;
  organization?: string;
  key_type?: string;
  key_bits?: number;
}

export interface PkiIntermediateResult {
  csr: string;
  private_key?: string;
  private_key_type?: string;
}

export interface PkiSetSignedIntermediateRequest {
  mount: string;
  certificate: string;
  issuer_name?: string;
}

export interface PkiSetSignedResult {
  issuer_id: string;
  issuer_name: string;
}

export interface PkiSignIntermediateRequest {
  mount: string;
  csr: string;
  common_name?: string;
  organization?: string;
  ttl?: string;
  /** Negative = unconstrained pathLen. */
  max_path_length?: number;
  issuer_ref?: string;
}

export interface PkiSignIntermediateResult {
  certificate: string;
  issuing_ca: string;
}

export interface PkiImportCaBundleRequest {
  mount: string;
  pem_bundle: string;
  issuer_name?: string;
}

export interface PkiRoleConfig {
  ttl: string;
  max_ttl: string;
  key_type: string;
  key_bits: number;
  allow_localhost: boolean;
  allow_any_name: boolean;
  allow_subdomains: boolean;
  allow_bare_domains: boolean;
  allow_ip_sans: boolean;
  server_flag: boolean;
  client_flag: boolean;
  use_csr_sans: boolean;
  use_csr_common_name: boolean;
  key_usage: string[];
  ext_key_usage: string[];
  country: string;
  province: string;
  locality: string;
  organization: string;
  ou: string;
  no_store: boolean;
  generate_lease: boolean;
  /** Pin issuance to a specific issuer (UUID or name). Empty = mount default. */
  issuer_ref: string;
}

export interface PkiIssueRequest {
  mount: string;
  role: string;
  common_name: string;
  alt_names?: string;
  ip_sans?: string;
  ttl?: string;
  issuer_ref?: string;
}

export interface PkiIssueResult {
  certificate: string;
  issuing_ca: string;
  private_key: string;
  private_key_type: string;
  serial_number: string;
  issuer_id: string;
}

export interface PkiSignCsrRequest {
  mount: string;
  role: string;
  csr: string;
  common_name?: string;
  alt_names?: string;
  ttl?: string;
  issuer_ref?: string;
}

export interface PkiSignVerbatimRequest {
  mount: string;
  csr: string;
  ttl?: string;
  issuer_ref?: string;
}

export interface PkiSignResult {
  certificate: string;
  issuing_ca: string;
  serial_number: string;
  issuer_id: string;
}

export interface PkiCertRecord {
  serial_number: string;
  certificate: string;
  issued_at: number;
  revoked_at?: number | null;
  /** Subject Common Name parsed from the cert. Empty when the cert
   *  has no CN attribute on its Subject (rare; identity would then be
   *  in the SAN). */
  common_name: string;
  /** Unix-seconds NotAfter from the cert's validity. `0` when the
   *  PEM failed to parse — render "—" rather than a wrong date. */
  not_after: number;
}

export interface PkiRevokeResult {
  revocation_time: number;
  serial_number: string;
  issuer_id: string;
}

export interface PkiCaResult {
  certificate: string;
  issuer_id: string;
  issuer_name: string;
}

export interface PkiCrlResult {
  crl: string;
  issuer_id: string;
}

export interface PkiRotateCrlResult {
  crl: string;
  crl_number: number;
  issuer_id: string;
}

export interface PkiTidyRequest {
  mount: string;
  tidy_cert_store?: boolean;
  tidy_revoked_certs?: boolean;
  safety_buffer?: string;
}

export interface PkiTidyResult {
  certs_deleted: number;
  revoked_entries_deleted: number;
  duration_ms: number;
  safety_buffer_seconds: number;
}

export interface PkiTidyStatus {
  last_run_at_unix: number;
  last_run_duration_ms: number;
  certs_deleted: number;
  revoked_entries_deleted: number;
  safety_buffer_seconds: number;
  source: string;
}

export interface PkiAutoTidyConfig {
  enabled: boolean;
  interval: string;
  tidy_cert_store: boolean;
  tidy_revoked_certs: boolean;
  safety_buffer: string;
}

export interface PkiUrlsConfig {
  issuing_certificates: string[];
  crl_distribution_points: string[];
  ocsp_servers: string[];
}

export interface PkiCrlConfig {
  expiry: string;
  disable: boolean;
}

// ── SSH Secret Engine (Phase 4) ─────────────────────────────────

export interface SshMountInfo {
  path: string;
}

export interface SshCaInfo {
  public_key: string;
  algorithm: string;
}

export interface SshGenerateCaRequest {
  mount: string;
  /** `""` / `"ed25519"` → Ed25519 (default), `"mldsa65"` → ML-DSA-65 (requires server `ssh_pqc` build). */
  algorithm?: string;
  /** OpenSSH-format private key to import. Mutually exclusive with `algorithm`. */
  private_key?: string;
}

export interface SshRoleConfig {
  key_type: string;
  algorithm_signer: string;
  cert_type: string;
  allowed_users: string;
  default_user: string;
  allowed_extensions: string;
  default_extensions: Record<string, string>;
  allowed_critical_options: string;
  default_critical_options: Record<string, string>;
  ttl: string;
  max_ttl: string;
  not_before_duration: string;
  key_id_format: string;
  cidr_list: string;
  exclude_cidr_list: string;
  port: number;
  pqc_only: boolean;
}

export interface SshSignRequest {
  mount: string;
  role: string;
  public_key: string;
  valid_principals?: string;
  ttl?: string;
  cert_type?: string;
  key_id?: string;
}

export interface SshSignResult {
  signed_key: string;
  serial_number: string;
  algorithm: string;
}

export interface SshCredsRequest {
  mount: string;
  role: string;
  ip: string;
  username?: string;
  ttl?: string;
}

export interface SshCredsResult {
  key: string;
  key_type: string;
  username: string;
  ip: string;
  port: number;
  ttl: number;
}

export interface SshLookupRequest {
  mount: string;
  ip: string;
  username?: string;
}

export interface SshLookupResult {
  roles: string[];
}

// ── TOTP Secret Engine (Phase 4) ────────────────────────────────

export interface TotpMountInfo {
  path: string;
}

export interface TotpKeyInfo {
  generate: boolean;
  issuer: string;
  account_name: string;
  algorithm: string;
  digits: number;
  period: number;
  skew: number;
  replay_check: boolean;
}

export interface TotpCreateKeyRequest {
  mount: string;
  name: string;
  /** True = engine generates the seed; false = operator imports `key` or `url`. */
  generate: boolean;
  issuer?: string;
  account_name?: string;
  /** SHA1 (default) | SHA256 | SHA512. */
  algorithm?: string;
  /** 6 (default) or 8. */
  digits?: number;
  period?: number;
  skew?: number;
  /** Generate mode: random seed size in bytes (default 20). */
  key_size?: number;
  /** Pixel size of the returned PNG QR. 0 disables PNG rendering. */
  qr_size?: number;
  /** Generate mode: include the seed in the create response (default true). */
  exported?: boolean;
  /** Refuse a second validation of the same step+code (default true). */
  replay_check?: boolean;
  /** Provider mode: base32-encoded seed. Mutually exclusive with `url`. */
  key?: string;
  /** Provider mode: full `otpauth://` URL. Mutually exclusive with `key`. */
  url?: string;
}

export interface TotpCreateKeyResult {
  name: string;
  generate: boolean;
  /** Base32 seed — present only on a generate-mode + exported create. */
  key: string;
  /** `otpauth://` URL — present only on a generate-mode + exported create. */
  url: string;
  /** Base64 PNG. Empty when `qr_size = 0` or in provider mode. */
  barcode: string;
}

export interface TotpCodeResult {
  code: string;
}

export interface TotpValidateResult {
  valid: boolean;
}

// ── OpenLDAP / AD password-rotation engine (Phase 4) ────────────

export interface LdapMountInfo {
  path: string;
}

export interface LdapConfigInfo {
  url: string;
  binddn: string;
  userdn: string;
  /** `openldap` | `active_directory` */
  directory_type: string;
  password_policy: string;
  request_timeout: number;
  starttls: boolean;
  /** `tls12` | `tls13` */
  tls_min_version: string;
  insecure_tls: boolean;
  userattr: string;
  /** Always empty on read — bindpass is redacted server-side. */
  bindpass: string;
}

export interface LdapWriteConfigRequest {
  mount: string;
  url: string;
  binddn: string;
  /** Empty preserves the previous value. Set to a non-empty string to rotate. */
  bindpass?: string;
  userdn?: string;
  /** `openldap` | `active_directory` */
  directory_type?: string;
  password_policy?: string;
  request_timeout?: number;
  starttls?: boolean;
  /** `tls12` | `tls13` */
  tls_min_version?: string;
  insecure_tls?: boolean;
  /** Required true alongside `insecure_tls = true`. */
  acknowledge_insecure_tls?: boolean;
  userattr?: string;
}

export interface LdapStaticRole {
  dn: string;
  username: string;
  /** Auto-rotation cadence in seconds. 0 = manual rotation only. */
  rotation_period: number;
  password_policy: string;
}

export interface LdapStaticCred {
  username: string;
  dn: string;
  password: string;
  last_vault_rotation_unix: number;
  /** Seconds until next auto-rotation. `null` for manual-only roles. */
  ttl_secs: number | null;
}

export interface LdapRotateRoleResult {
  username: string;
  dn: string;
  password: string;
  last_vault_rotation_unix: number;
}

export interface LdapLibrarySet {
  service_account_names: string[];
  ttl: number;
  max_ttl: number;
  disable_check_in_enforcement: boolean;
  /** Phase 5 affinity window in seconds. 0 = affinity off (default). */
  affinity_ttl: number;
}

export interface LdapCheckOutResult {
  service_account_name: string;
  password: string;
  lease_id: string;
  ttl_secs: number;
}

export interface LdapLibraryStatusEntry {
  account: string;
  lease_id: string;
  expires_at_unix: number;
}

export interface LdapLibraryStatus {
  checked_out: LdapLibraryStatusEntry[];
  available: string[];
}
