import { invoke } from "@tauri-apps/api/core";
import type {
  VaultMode,
  VaultStatus,
  InitResponse,
  LoginResponse,
  MountInfo,
  SecretData,
  SecretListResult,
  UserListResult,
  UserInfo,
  PolicyListResult,
  PolicyContent,
  ResourceMetadata,
  ResourceListResult,
  ResourceSecretListResult,
  ResourceSecretData,
  AppRoleListResult,
  AppRoleInfo,
  RoleIdInfo,
  SecretIdResponse,
  SecretIdAccessorList,
  SecretIdAccessorInfo,
  Fido2Config,
  Fido2ChallengeResponse,
  Fido2LoginResponse,
  Fido2CredentialInfo,
  RemoteProfile,
  RemoteStatus,
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
export const remoteLoginToken = (token: string) =>
  invoke<void>("remote_login_token", { token });
export const remoteLoginUserpass = (username: string, password: string) =>
  invoke<LoginResponse>("remote_login_userpass", { username, password });

// System
export const initVault = () => invoke<InitResponse>("init_vault");
export const openVault = () => invoke<void>("open_vault");
export const sealVault = () => invoke<void>("seal_vault");
export const getVaultStatus = () => invoke<VaultStatus>("get_vault_status");
export const listMounts = () => invoke<MountInfo[]>("list_mounts");
export const listAuthMethods = () => invoke<MountInfo[]>("list_auth_methods");

// Auth
export const loginToken = (token: string) =>
  invoke<LoginResponse>("login_token", { token });
export const loginUserpass = (username: string, password: string) =>
  invoke<LoginResponse>("login_userpass", { username, password });
export const getCurrentToken = () => invoke<string | null>("get_current_token");
export const logout = () => invoke<void>("logout");

// Secrets
export const listSecrets = (path: string) =>
  invoke<SecretListResult>("list_secrets", { path });
export const readSecret = (path: string) =>
  invoke<SecretData>("read_secret", { path });
export const writeSecret = (path: string, data: Record<string, string>) =>
  invoke<void>("write_secret", { path, data });
export const deleteSecret = (path: string) =>
  invoke<void>("delete_secret", { path });

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

// Resources
export const listResources = (mount: string) =>
  invoke<ResourceListResult>("list_resources", { mount });
export const readResource = (mount: string, name: string) =>
  invoke<ResourceMetadata>("read_resource", { mount, name });
export const writeResource = (mount: string, name: string, metadata: ResourceMetadata) =>
  invoke<void>("write_resource", { mount, name, metadata });
export const deleteResource = (mount: string, name: string) =>
  invoke<void>("delete_resource", { mount, name });
export const listResourceSecrets = (mount: string, name: string) =>
  invoke<ResourceSecretListResult>("list_resource_secrets", { mount, name });
export const readResourceSecret = (mount: string, name: string, key: string) =>
  invoke<ResourceSecretData>("read_resource_secret", { mount, name, key });
export const writeResourceSecret = (mount: string, name: string, key: string, data: Record<string, string>) =>
  invoke<void>("write_resource_secret", { mount, name, key, data });
export const deleteResourceSecret = (mount: string, name: string, key: string) =>
  invoke<void>("delete_resource_secret", { mount, name, key });

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
