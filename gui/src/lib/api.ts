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

// Native FIDO2 (CTAP2 over USB, bypasses browser WebAuthn API)
export const fido2NativeRegister = (username: string) =>
  invoke<void>("fido2_native_register", { username });
export const fido2NativeLogin = (username: string) =>
  invoke<Fido2LoginResponse>("fido2_native_login", { username });
export const fido2SubmitPin = (pin: string) =>
  invoke<void>("fido2_submit_pin", { pin });
