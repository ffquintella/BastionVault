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
}

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
