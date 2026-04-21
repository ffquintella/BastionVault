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
  type: "text" | "number" | "url" | "ip" | "fqdn";
  placeholder?: string;
}

export interface ResourceTypeDef {
  id: string;
  label: string;
  color: "info" | "success" | "warning" | "error" | "neutral";
  fields: ResourceFieldDef[];
}

export type ResourceTypeConfig = Record<string, ResourceTypeDef>;

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
