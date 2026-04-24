import { invoke } from "@tauri-apps/api/core";
import type {
  VaultMode,
  VaultStatus,
  Preferences,
  InitResponse,
  LoginResponse,
  MountInfo,
  SecretData,
  SecretListResult,
  UserListResult,
  UserInfo,
  PolicyListResult,
  PolicyContent,
  PolicyHistoryResult,
  ResourceMetadata,
  ResourceListResult,
  ResourceSecretListResult,
  ResourceSecretData,
  SecretVersionListResult,
  SecretVersionData,
  ResourceHistoryResult,
  ResourceSecretVersionListResult,
  ResourceSecretVersionData,
  FileMeta,
  FileListResult,
  FileContentResult,
  FileSyncListResult,
  FileHistoryResult,
  FileVersionListResult,
  AppRoleListResult,
  AppRoleInfo,
  RoleIdInfo,
  SecretIdResponse,
  SecretIdAccessorList,
  SecretIdAccessorInfo,
  GroupKind,
  GroupListResult,
  GroupInfo,
  GroupHistoryResult,
  AssetGroupListResult,
  AssetGroupInfo,
  AssetGroupHistoryResult,
  AssetGroupLookupResult,
  EntitySelf,
  EntityAliasInfo,
  AuditEvent,
  OwnerInfo,
  ShareEntry,
  SharePointer,
  ShareTargetKind,
  Fido2Config,
  Fido2ChallengeResponse,
  Fido2LoginResponse,
  Fido2CredentialInfo,
  RemoteProfile,
  RemoteStatus,
  PasswordPolicy,
} from "./types";

// Connection
export const getMode = () => invoke<VaultMode>("get_mode");
export const setMode = (mode: VaultMode) => invoke<void>("set_mode", { mode });
export const isVaultInitialized = () => invoke<boolean>("is_vault_initialized");
export const getRemoteProfile = () => invoke<RemoteProfile | null>("get_remote_profile");
export const connectRemote = (profile: RemoteProfile) =>
  invoke<void>("connect_remote", { profile });
export const disconnectRemote = () => invoke<void>("disconnect_remote");
export const getRemoteStatus = () => invoke<RemoteStatus>("get_remote_status");
export const loadPreferences = () => invoke<Preferences>("load_preferences");
export const savePreferences = (mode: VaultMode, remoteProfile?: RemoteProfile) =>
  invoke<void>("save_preferences", { mode, remoteProfile: remoteProfile ?? null });
export const getPasswordPolicy = () => invoke<PasswordPolicy>("get_password_policy");
export const setPasswordPolicy = (policy: PasswordPolicy) =>
  invoke<void>("set_password_policy", { policy });
export const remoteLoginToken = (token: string) =>
  invoke<void>("remote_login_token", { token });
export const remoteLoginUserpass = (username: string, password: string) =>
  invoke<LoginResponse>("remote_login_userpass", { username, password });

// System
export const initVault = () => invoke<InitResponse>("init_vault");
export const openVault = () => invoke<void>("open_vault");
export const sealVault = () => invoke<void>("seal_vault");
export const resetVault = () => invoke<void>("reset_vault");
/** Close the active embedded vault handle without touching on-disk
 *  data or saved preferences. Used by the Switch-vault flow so the
 *  AppState slot is free for a subsequent `openVault` against a
 *  different profile. */
export const disconnectVault = () => invoke<void>("disconnect_vault");

// ── YubiKey failsafe (Phase 2) ─────────────────────────────────────
//
// Lets the Settings page register additional YubiKeys as spare
// unlock paths for the vault-keys file. See
// `src-tauri/src/local_keystore.rs` for the envelope layout and
// `docs/docs/security-structure.md` for the threat model.

export interface YubiKeyDeviceInfo {
  serial: number;
  slot_occupied: boolean;
}

export interface RegisteredYubiKeyDto {
  serial: number;
  key_id: string;
  registered_at: number;
}

export const yubikeyListDevices = () =>
  invoke<YubiKeyDeviceInfo[]>("yubikey_list_devices");

export const yubikeyListRegistered = () =>
  invoke<RegisteredYubiKeyDto[]>("yubikey_list_registered");

export const yubikeyRegister = (serial: number, pin: string) =>
  invoke<RegisteredYubiKeyDto>("yubikey_register", { serial, pin });

export const yubikeyRemove = (serial: number) =>
  invoke<void>("yubikey_remove", { serial });

export const yubikeySetPin = (pin: string) =>
  invoke<void>("yubikey_set_pin", { pin });

export const yubikeyClearPin = () => invoke<void>("yubikey_clear_pin");
export const getVaultStatus = () => invoke<VaultStatus>("get_vault_status");
export const listMounts = () => invoke<MountInfo[]>("list_mounts");
export const listAuthMethods = () => invoke<MountInfo[]>("list_auth_methods");
export const listAuditEvents = (from: string, to: string, limit?: number) =>
  invoke<AuditEvent[]>("list_audit_events", { from, to, limit });

// Auth
export const loginToken = (token: string) =>
  invoke<LoginResponse>("login_token", { token });
export const loginUserpass = (username: string, password: string) =>
  invoke<LoginResponse>("login_userpass", { username, password });
export const getCurrentToken = () => invoke<string | null>("get_current_token");
export const logout = () => invoke<void>("logout");

// Secrets (mount/mountType passed for kv-v2 path handling)
export const listSecrets = (path: string, mount?: string, mountType?: string) =>
  invoke<SecretListResult>("list_secrets", { path, mount, mountType });
export const readSecret = (path: string, mount?: string, mountType?: string) =>
  invoke<SecretData>("read_secret", { path, mount, mountType });
export const writeSecret = (path: string, data: Record<string, string>, mount?: string, mountType?: string) =>
  invoke<void>("write_secret", { path, data, mount, mountType });
export const deleteSecret = (path: string, mount?: string, mountType?: string) =>
  invoke<void>("delete_secret", { path, mount, mountType });

// KV secret version history (kv-v2 only -- kv-v1 returns empty).
export const listSecretVersions = (path: string, mount?: string, mountType?: string) =>
  invoke<SecretVersionListResult>("list_secret_versions", { path, mount, mountType });
export const readSecretVersion = (
  path: string,
  version: number,
  mount?: string,
  mountType?: string,
) => invoke<SecretVersionData>("read_secret_version", { path, version, mount, mountType });

// Mounts
export const mountEngine = (path: string, engineType: string, description: string) =>
  invoke<void>("mount_engine", { path, engineType, description });
export const unmountEngine = (path: string) =>
  invoke<void>("unmount_engine", { path });
export const enableAuthMethod = (path: string, authType: string, description: string) =>
  invoke<void>("enable_auth_method", { path, authType, description });
export const disableAuthMethod = (path: string) =>
  invoke<void>("disable_auth_method", { path });

// Users
export const listUsers = (mountPath: string) =>
  invoke<UserListResult>("list_users", { mountPath });
export const getUser = (mountPath: string, username: string) =>
  invoke<UserInfo>("get_user", { mountPath, username });
export const createUser = (mountPath: string, username: string, password: string, policies: string) =>
  invoke<void>("create_user", { mountPath, username, password, policies });
export const updateUser = (mountPath: string, username: string, password: string, policies: string) =>
  invoke<void>("update_user", { mountPath, username, password, policies });
export const deleteUser = (mountPath: string, username: string) =>
  invoke<void>("delete_user", { mountPath, username });

// Policies
export const listPolicies = () => invoke<PolicyListResult>("list_policies");
export const readPolicy = (name: string) => invoke<PolicyContent>("read_policy", { name });
export const writePolicy = (name: string, policy: string) =>
  invoke<void>("write_policy", { name, policy });
export const deletePolicy = (name: string) => invoke<void>("delete_policy", { name });
export const listPolicyHistory = (name: string) =>
  invoke<PolicyHistoryResult>("list_policy_history", { name });

// Resource type configuration
export const resourceTypesRead = () =>
  invoke<Record<string, unknown> | null>("resource_types_read");
export const resourceTypesWrite = (types: Record<string, unknown>) =>
  invoke<void>("resource_types_write", { types });

// Resources — uses dedicated resource engine (auto-mounted at resources/)
export const listResources = () =>
  invoke<ResourceListResult>("list_resources", {});
export const readResource = (name: string) =>
  invoke<ResourceMetadata>("read_resource", { name });
export const writeResource = (name: string, metadata: ResourceMetadata) =>
  invoke<void>("write_resource", { name, metadata });
export const deleteResource = (name: string) =>
  invoke<void>("delete_resource", { name });
export const listResourceSecrets = (name: string) =>
  invoke<ResourceSecretListResult>("list_resource_secrets", { name });
export const readResourceSecret = (name: string, key: string) =>
  invoke<ResourceSecretData>("read_resource_secret", { name, key });
export const writeResourceSecret = (name: string, key: string, data: Record<string, string>) =>
  invoke<void>("write_resource_secret", { name, key, data });
export const deleteResourceSecret = (name: string, key: string) =>
  invoke<void>("delete_resource_secret", { name, key });

// Resource change history (metadata edits -- field names only, no values).
export const listResourceHistory = (name: string) =>
  invoke<ResourceHistoryResult>("list_resource_history", { name });

// Resource-secret version history (full value retained per version).
export const listResourceSecretVersions = (name: string, key: string) =>
  invoke<ResourceSecretVersionListResult>("list_resource_secret_versions", { name, key });
export const readResourceSecretVersion = (name: string, key: string, version: number) =>
  invoke<ResourceSecretVersionData>("read_resource_secret_version", { name, key, version });

// AppRole
export const listAppRoles = () => invoke<AppRoleListResult>("list_approles");
export const readAppRole = (name: string) => invoke<AppRoleInfo>("read_approle", { name });
export const writeAppRole = (
  name: string,
  bindSecretId: boolean,
  tokenPolicies: string,
  secretIdNumUses: number,
  secretIdTtl: string,
  tokenTtl: string,
  tokenMaxTtl: string,
) =>
  invoke<void>("write_approle", {
    name,
    bindSecretId,
    tokenPolicies,
    secretIdNumUses,
    secretIdTtl,
    tokenTtl,
    tokenMaxTtl,
  });
export const deleteAppRole = (name: string) => invoke<void>("delete_approle", { name });
export const readRoleId = (name: string) => invoke<RoleIdInfo>("read_role_id", { name });
export const generateSecretId = (name: string, metadata: string) =>
  invoke<SecretIdResponse>("generate_secret_id", { name, metadata });
export const listSecretIdAccessors = (name: string) =>
  invoke<SecretIdAccessorList>("list_secret_id_accessors", { name });
export const lookupSecretIdAccessor = (name: string, accessor: string) =>
  invoke<SecretIdAccessorInfo>("lookup_secret_id_accessor", { name, accessor });
export const destroySecretIdAccessor = (name: string, accessor: string) =>
  invoke<void>("destroy_secret_id_accessor", { name, accessor });

// Identity groups
export const listGroups = (kind: GroupKind) =>
  invoke<GroupListResult>("list_groups", { kind });
export const readGroup = (kind: GroupKind, name: string) =>
  invoke<GroupInfo>("read_group", { kind, name });
export const writeGroup = (
  kind: GroupKind,
  name: string,
  description: string,
  members: string,
  policies: string,
) => invoke<void>("write_group", { kind, name, description, members, policies });
export const deleteGroup = (kind: GroupKind, name: string) =>
  invoke<void>("delete_group", { kind, name });
export const listGroupHistory = (kind: GroupKind, name: string) =>
  invoke<GroupHistoryResult>("list_group_history", { kind, name });

// Asset groups (resources + KV secrets)
export const listAssetGroups = () =>
  invoke<AssetGroupListResult>("list_asset_groups");
export const readAssetGroup = (name: string) =>
  invoke<AssetGroupInfo>("read_asset_group", { name });
export const writeAssetGroup = (
  name: string,
  description: string,
  members: string,
  secrets: string,
) =>
  invoke<void>("write_asset_group", { name, description, members, secrets });
export const deleteAssetGroup = (name: string) =>
  invoke<void>("delete_asset_group", { name });
export const listAssetGroupHistory = (name: string) =>
  invoke<AssetGroupHistoryResult>("list_asset_group_history", { name });
export const assetGroupsForResource = (resource: string) =>
  invoke<AssetGroupLookupResult>("asset_groups_for_resource", { resource });
export const assetGroupsForSecret = (path: string) =>
  invoke<AssetGroupLookupResult>("asset_groups_for_secret", { path });

// Per-user scoping: entity introspection, owner lookup, sharing,
// admin ownership transfer. See features/per-user-scoping.md.
export const getEntitySelf = () => invoke<EntitySelf>("get_entity_self");
export const listEntityAliases = () =>
  invoke<EntityAliasInfo[]>("list_entity_aliases");
export const getKvOwner = (path: string) =>
  invoke<OwnerInfo>("get_kv_owner", { path });
export const getResourceOwner = (name: string) =>
  invoke<OwnerInfo>("get_resource_owner", { name });
export const listSharesForGrantee = (grantee: string) =>
  invoke<SharePointer[]>("list_shares_for_grantee", { grantee });
export const listSharesForTarget = (kind: ShareTargetKind, targetPath: string) =>
  invoke<ShareEntry[]>("list_shares_for_target", { kind, targetPath });
export const putShare = (
  kind: ShareTargetKind,
  targetPath: string,
  grantee: string,
  capabilities: string[],
  expiresAt: string,
) =>
  invoke<ShareEntry>("put_share", {
    kind,
    targetPath,
    grantee,
    capabilities,
    expiresAt,
  });
export const deleteShare = (
  kind: ShareTargetKind,
  targetPath: string,
  grantee: string,
) => invoke<void>("delete_share", { kind, targetPath, grantee });
export const transferKvOwner = (path: string, newOwnerEntityId: string) =>
  invoke<void>("transfer_kv_owner", { path, newOwnerEntityId });
export const transferResourceOwner = (resource: string, newOwnerEntityId: string) =>
  invoke<void>("transfer_resource_owner", { resource, newOwnerEntityId });
export const transferAssetGroupOwner = (name: string, newOwnerEntityId: string) =>
  invoke<void>("transfer_asset_group_owner", { name, newOwnerEntityId });

// FIDO2
export const fido2ConfigRead = () => invoke<Fido2Config | null>("fido2_config_read");
export const fido2ConfigWrite = (rpId: string, rpOrigin: string, rpName: string) =>
  invoke<void>("fido2_config_write", { rpId, rpOrigin, rpName });
export const fido2RegisterBegin = (username: string) =>
  invoke<Fido2ChallengeResponse>("fido2_register_begin", { username });
export const fido2RegisterComplete = (username: string, credential: string) =>
  invoke<void>("fido2_register_complete", { username, credential });
export const fido2LoginBegin = (username: string) =>
  invoke<Fido2ChallengeResponse>("fido2_login_begin", { username });
export const fido2LoginComplete = (username: string, credential: string) =>
  invoke<Fido2LoginResponse>("fido2_login_complete", { username, credential });
export const fido2ListCredentials = (username: string) =>
  invoke<Fido2CredentialInfo | null>("fido2_list_credentials", { username });
export const fido2DeleteCredential = (username: string) =>
  invoke<void>("fido2_delete_credential", { username });

// File Resources
export const listFiles = () => invoke<FileListResult>("list_files");
export const readFileMeta = (id: string) =>
  invoke<FileMeta>("read_file_meta", { id });
export const readFileContent = (id: string) =>
  invoke<FileContentResult>("read_file_content", { id });
export const createFile = (args: {
  name: string;
  contentBase64: string;
  resource?: string;
  mimeType?: string;
  tags?: string[];
  notes?: string;
}) => invoke<FileMeta>("create_file", args);
export const updateFileContent = (args: {
  id: string;
  contentBase64: string;
  name?: string;
  resource?: string;
  mimeType?: string;
  tags?: string[];
  notes?: string;
}) => invoke<FileMeta>("update_file_content", args);
export const deleteFile = (id: string) => invoke<void>("delete_file", { id });
export const listFileHistory = (id: string) =>
  invoke<FileHistoryResult>("list_file_history", { id });

export const listFileSyncTargets = (id: string) =>
  invoke<FileSyncListResult>("list_file_sync_targets", { id });
export const writeFileSyncTarget = (args: {
  id: string;
  name: string;
  kind: string;
  targetPath: string;
  mode?: string;
  syncOnWrite?: boolean;
}) => invoke<void>("write_file_sync_target", args);
export const deleteFileSyncTarget = (id: string, name: string) =>
  invoke<void>("delete_file_sync_target", { id, name });
export const pushFileSyncTarget = (id: string, name: string) =>
  invoke<Record<string, unknown>>("push_file_sync_target", { id, name });

export const listFileVersions = (id: string) =>
  invoke<FileVersionListResult>("list_file_versions", { id });
export const readFileVersionContent = (id: string, version: number) =>
  invoke<FileContentResult>("read_file_version_content", { id, version });
export const restoreFileVersion = (id: string, version: number) =>
  invoke<Record<string, unknown>>("restore_file_version", { id, version });

// Native FIDO2 (CTAP2 over USB, bypasses browser WebAuthn API)
export const fido2NativeRegister = (username: string) =>
  invoke<void>("fido2_native_register", { username });
export const fido2NativeLogin = (username: string) =>
  invoke<Fido2LoginResponse>("fido2_native_login", { username });
export const fido2SubmitPin = (pin: string) =>
  invoke<void>("fido2_submit_pin", { pin });

// ── Cloud Storage Targets ─────────────────────────────────────────
//
// OAuth consent flow for OneDrive / Google Drive / Dropbox. The
// two-step split (start/complete) is so the frontend can drive the
// browser open itself via the Tauri shell plugin between commands —
// keeps the consent URL in the browser chrome a user can see and
// copy, rather than inside a Tauri webview popup.

export interface CloudTargetStartResult {
  sessionId: string;
  consentUrl: string;
}

export const cloudTargetStartConnect = (args: {
  target: "onedrive" | "gdrive" | "dropbox";
  clientId: string;
  clientSecret?: string;
  credentialsRef: string;
}) =>
  invoke<CloudTargetStartResult>("cloud_target_start_connect", args);

export const cloudTargetCompleteConnect = (args: {
  sessionId: string;
  timeoutSecs?: number;
}) => invoke<void>("cloud_target_complete_connect", args);

export const cloudTargetCancelConnect = (sessionId: string) =>
  invoke<void>("cloud_target_cancel_connect", { sessionId });

// Cloud Vault — embedded vault mode backed by a cloud target.

export interface CloudVaultStoredConfig {
  target: string;
  [key: string]: unknown;
}

export const setCloudVaultConfig = (args: {
  target: "s3" | "onedrive" | "gdrive" | "dropbox";
  config: Record<string, unknown>;
}) => invoke<void>("set_cloud_vault_config", { input: args });

export const clearCloudVaultConfig = () =>
  invoke<void>("clear_cloud_vault_config");

export const getCloudVaultConfig = () =>
  invoke<CloudVaultStoredConfig | null>("get_cloud_vault_config");

// ── Saved vault profiles ──────────────────────────────────────────
//
// The preferences file holds a list of saved vault profiles (Local
// / Remote / Cloud). The Get Started screen enumerates them and
// lets the user pick one, add a new one, or remove an existing one.

export type VaultSpec =
  | { kind: "local"; data_dir?: string | null; storage_kind: string }
  | { kind: "remote"; profile: RemoteProfile }
  | { kind: "cloud"; config: { target: string } & Record<string, unknown> };

export interface VaultProfile {
  id: string;
  name: string;
  spec: VaultSpec;
}

export interface VaultProfileList {
  vaults: VaultProfile[];
  lastUsedId: string | null;
}

export const listVaultProfiles = () =>
  invoke<VaultProfileList>("list_vault_profiles");

export const addVaultProfile = (args: {
  name: string;
  spec: VaultSpec;
  setDefault?: boolean;
}) => invoke<string>("add_vault_profile", args);

export const updateVaultProfile = (args: {
  id: string;
  name: string;
  spec: VaultSpec;
}) => invoke<void>("update_vault_profile", args);

export const removeVaultProfile = (id: string) =>
  invoke<void>("remove_vault_profile", { id });

export const setLastUsedVault = (id: string) =>
  invoke<void>("set_last_used_vault", { id });

export const clearLastUsedVault = () =>
  invoke<void>("clear_last_used_vault");

export const getVaultProfile = (id: string) =>
  invoke<VaultProfile>("get_vault_profile", { id });

// Add-vault helpers — suggestion + S3 credential save.

export const suggestCredentialsRefPath = (
  target: "s3" | "onedrive" | "gdrive" | "dropbox",
) => invoke<string>("suggest_credentials_ref_path", { target });

export const saveS3Credentials = (args: {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}) => invoke<string>("save_s3_credentials", { input: args });

export const getOAuthRedirectUri = () =>
  invoke<string>("get_oauth_redirect_uri");

/**
 * Shortcut for users who generated a token directly at the
 * provider's dev console (Dropbox has a "Generate" button for
 * this) — skips the redirect-URI round-trip entirely. Writes the
 * pasted token as the credentials_ref file the target will read.
 */
export const savePastedToken = (args: { target: "s3" | "onedrive" | "gdrive" | "dropbox"; token: string }) =>
  invoke<string>("save_pasted_token", args);

/**
 * Canonical default data directory for a local vault of the given
 * storage engine. Used by the Add Local Vault modal to pre-populate
 * the path field and for the "Reset to default" button.
 */
export const getDefaultLocalDataDir = (kind: "file" | "hiqlite") =>
  invoke<string>("get_default_local_data_dir", { kind });

// ── OIDC login (browser consent flow) ─────────────────────────────
//
// Bridges the system browser to the vault's `oidc` auth backend.
// Three-command shape matches the Cloud Storage Targets flow so the
// frontend can shell-open the auth URL in the real browser between
// the start and complete calls.

export interface OidcLoginStartResult {
  sessionId: string;
  authUrl: string;
}

export const oidcLoginStart = (args: { mount: string; role?: string }) =>
  invoke<OidcLoginStartResult>("oidc_login_start", args);

export const oidcLoginComplete = (args: {
  sessionId: string;
  timeoutSecs?: number;
}) => invoke<LoginResponse>("oidc_login_complete", args);

export const oidcLoginCancel = (sessionId: string) =>
  invoke<void>("oidc_login_cancel", { sessionId });

// ── SSO discovery + admin toggle ───────────────────────────────────
//
// The login page calls `listSsoProviders` unauthenticated — the
// backend's `sys/sso/providers` route is marked unauth. Zero results
// (either disabled or no SSO backends mounted) means the SSO tab
// should be hidden.

export interface SsoProvider {
  mount: string;
  name: string;
  kind: string;
}

export interface SsoProvidersResult {
  enabled: boolean;
  providers: SsoProvider[];
}

export const listSsoProviders = () =>
  invoke<SsoProvidersResult>("list_sso_providers");

export const getSsoSettings = () => invoke<boolean>("get_sso_settings");

export const setSsoSettings = (enabled: boolean) =>
  invoke<void>("set_sso_settings", { enabled });

// ── SSO admin (Settings page — root-token flow) ─────────────────────
//
// Drive mount + config + role as one unit so the admin never has to
// touch the raw `sys/auth/<mount>` / `auth/<mount>/config` /
// `auth/<mount>/role/<name>` surface. `client_secret_set` is the
// redacted-secret presence hint; the actual secret is never returned.

// ── OIDC shapes ─────────────────────────────────────────────────────

export interface OidcAdminConfig {
  kind: "oidc";
  discovery_url: string;
  client_id: string;
  client_secret_set: boolean;
  scopes: string[];
  allowed_redirect_uris: string[];
}

export interface OidcAdminRole {
  kind: "oidc";
  name: string;
  user_claim: string;
  groups_claim: string;
  bound_audiences: string[];
  bound_claims_json: string;
  policies: string[];
  token_ttl_secs: number;
}

export interface OidcAdminInputConfig {
  kind: "oidc";
  discovery_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
  allowed_redirect_uris: string[];
}

// ── SAML shapes ─────────────────────────────────────────────────────

export interface SamlAdminConfig {
  kind: "saml";
  entity_id: string;
  acs_url: string;
  idp_sso_url: string;
  idp_slo_url: string;
  idp_metadata_url: string;
  idp_metadata_xml_set: boolean;
  idp_cert_set: boolean;
  allowed_redirect_uris: string[];
}

export interface SamlAdminRole {
  kind: "saml";
  name: string;
  bound_subjects: string[];
  bound_subjects_type: string;
  bound_attributes_json: string;
  attribute_mappings_json: string;
  groups_attribute: string;
  policies: string[];
  token_ttl_secs: number;
}

export interface SamlAdminInputConfig {
  kind: "saml";
  entity_id: string;
  acs_url: string;
  idp_sso_url: string;
  idp_slo_url: string;
  idp_metadata_url: string;
  idp_metadata_xml: string;
  idp_cert: string;
  allowed_redirect_uris: string[];
}

// ── Unions + provider ──────────────────────────────────────────────
//
// SsoAdminProvider is a discriminated union on `kind` so TS narrows
// both `config` and `role` correctly in consumer code (e.g.
// `p.kind === "oidc" ? p.config.discovery_url : …`). The wire
// format from Rust uses the same tagged-union shape via serde's
// `#[serde(tag = "kind")]` on `SsoProviderConfig` / `SsoAdminRole`,
// so the top-level `kind` and the nested `config.kind` always
// agree.

export type SsoProviderConfig = OidcAdminConfig | SamlAdminConfig;
export type SsoAdminRole = OidcAdminRole | SamlAdminRole;
export type SsoAdminInputConfig = OidcAdminInputConfig | SamlAdminInputConfig;

interface SsoAdminProviderBase {
  mount: string;
  display_name: string;
  default_role: string;
}

export interface SsoAdminProviderOidc extends SsoAdminProviderBase {
  kind: "oidc";
  config: OidcAdminConfig;
  role: OidcAdminRole | null;
}

export interface SsoAdminProviderSaml extends SsoAdminProviderBase {
  kind: "saml";
  config: SamlAdminConfig;
  role: SamlAdminRole | null;
}

export type SsoAdminProvider = SsoAdminProviderOidc | SsoAdminProviderSaml;

interface SsoAdminInputBase {
  mount: string;
  display_name: string;
  default_role: string;
}

export interface SsoAdminInputOidc extends SsoAdminInputBase {
  kind: "oidc";
  config: OidcAdminInputConfig;
  role: OidcAdminRole;
}

export interface SsoAdminInputSaml extends SsoAdminInputBase {
  kind: "saml";
  config: SamlAdminInputConfig;
  role: SamlAdminRole;
}

export type SsoAdminInput = SsoAdminInputOidc | SsoAdminInputSaml;

export interface SsoCallbackHints {
  mode: string;
  suggested: string[];
  notes: string[];
}

export const ssoAdminList = () => invoke<SsoAdminProvider[]>("sso_admin_list");

export const ssoAdminGet = (mount: string) =>
  invoke<SsoAdminProvider>("sso_admin_get", { mount });

export const ssoAdminCreate = (input: SsoAdminInput) =>
  invoke<void>("sso_admin_create", { input });

export const ssoAdminUpdate = (input: SsoAdminInput) =>
  invoke<void>("sso_admin_update", { input });

export const ssoAdminDelete = (mount: string) =>
  invoke<void>("sso_admin_delete", { mount });

export const ssoAdminCallbackHints = (mount: string, kind: "oidc" | "saml") =>
  invoke<SsoCallbackHints>("sso_admin_callback_hints", { mount, kind });
