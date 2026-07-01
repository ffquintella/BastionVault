export type VaultMode = "Embedded" | "Remote";

export interface VaultStatus {
  initialized: boolean;
  sealed: boolean;
  has_vault: boolean;
}

/** Per-node result of a cluster seal/unseal fan-out. */
export interface NodeSealResult {
  address: string;
  /** Post-submit seal state for this node; null when the call errored. */
  sealed: boolean | null;
  /** Shamir shares entered so far on this node (t-of-n setups). */
  progress: number | null;
  /** Shares required to cross the threshold, as the node reported it. */
  threshold: number | null;
  /** Error string when the call to this node failed. */
  error: string | null;
}

/** Outcome of an unseal attempt: aggregate status + per-node breakdown.
 *  In a cluster, the share is fanned out to every node, so `nodes` lists
 *  each member; `status.sealed` stays true until they are all open. */
export interface UnsealOutcome {
  status: VaultStatus;
  nodes: NodeSealResult[];
}

/** Outcome of a seal attempt: aggregate status + per-node breakdown.
 *  Seal is fanned out to every cluster node, so `nodes` lists each
 *  member (including any that failed to seal). */
export interface SealOutcome {
  status: VaultStatus;
  nodes: NodeSealResult[];
}

export interface RemoteProfile {
  name: string;
  address: string;
  tls_skip_verify: boolean;
  ca_cert_path?: string;
  client_cert_path?: string;
  client_key_path?: string;
  /**
   * SRV-based cluster discovery. When `true` (default) and `address`
   * is a bare DNS name, the connect flow queries
   * `_bvault._tcp.<address>` and picks the best node via `/sys/health`.
   * URL-shaped addresses (`https://host:port`) always skip discovery.
   */
  cluster_discovery?: boolean;
  /** Override for the SRV service label (defaults to `_bvault._tcp`). */
  discovery_srv_service?: string;
  /** Per-probe deadline in milliseconds (default 1500). */
  health_probe_timeout_ms?: number;
  /**
   * Internal cached hint: whether the *server* last reported it requires
   * FerroGate machine identity. This is NOT an operator toggle — the
   * authority is the server, discovered via `ferrogateRequirement()` on every
   * connect and refreshed into this field. The connect flow and
   * `finalizeLogin` read it, but a stale/false value can never let a client
   * bypass a server that requires machine identity (the server enforces it at
   * the token layer regardless). Defaults off / unknown.
   */
  require_machine_identity?: boolean;
  /**
   * Internal cached hint: the server's advertised DPoP `expected_audience`
   * (from `ferrogateRequirement()`), captured alongside
   * `require_machine_identity` on every connect. The machine gate and
   * `finalizeLogin` sign the DPoP proof with this rather than assuming the
   * audience equals `address` — a mount whose audience is the trust domain
   * (e.g. `https://ferrogate.dev`) would otherwise fail with an `htu`
   * mismatch. Empty/unset → fall back to `address`.
   */
  expected_audience?: string;
  /**
   * Internal cached hint: the server's advertised MIA environment (from
   * `ferrogateRequirement()`), captured alongside `expected_audience` on
   * every connect. The machine gate and `finalizeLogin` resolve the local
   * MIA socket from this (`mia-<env>.toml`) so the client dials the MIA
   * belonging to the deployment it is connecting to. Empty/unset → the
   * default `mia.toml`.
   */
  mia_environment?: string;
}

export interface RemoteStatus {
  connected: boolean;
  address: string;
  initialized: boolean;
  sealed: boolean;
}

/**
 * Cluster-discovery result for the live connection. `null` when the
 * operator connected to a literal URL or disabled discovery.
 */
export interface SelectedNode {
  cluster_label: string;
  address: string;
  target: string;
  port: number;
  state: string;
  rtt_ms: number;
  cluster_id?: string | null;
  version?: string | null;
}

export interface ProbeRow {
  target: string;
  port: number;
  scheme: string;
  priority: number;
  weight: number;
  state: string;
  rtt_ms: number;
  cluster_id?: string | null;
  version?: string | null;
}

export interface ClusterDiagnostics {
  cluster_label: string;
  chosen: SelectedNode | null;
  candidates: ProbeRow[];
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

/**
 * Liveness probe for the active session (see the `token_status` Tauri
 * command). The session monitor polls this to detect a token that has
 * expired or been revoked out from under the UI.
 */
export interface TokenStatus {
  /** The stored token still authenticates against lookup-self. */
  valid: boolean;
  /**
   * The backend gave a definitive answer. When false the probe could
   * not reach the server (network blip, sealed vault) and `valid` is
   * meaningless — the UI must leave the session untouched.
   */
  reachable: boolean;
  /** Remaining TTL in seconds; 0/null means a non-expiring token. */
  ttl_seconds: number | null;
  /** RFC3339 absolute expiry, when reported. */
  expire_time: string | null;
}

export interface MountInfo {
  path: string;
  mount_type: string;
  description: string;
}

// Secrets
export interface SecretData {
  data: Record<string, unknown>;
  /** KV v2: the environment whose overrides were merged into `data`, or null
   *  when the base (shared) set was returned. */
  resolved_env?: string | null;
  /** KV v2: environments declared on this secret (empty for plain secrets). */
  available_envs?: string[];
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

// Namespaces (multi-tenancy)
export interface NamespaceQuotas {
  max_storage_bytes: number;
  max_leases: number;
  request_rate: number;
  max_mounts: number;
  max_entities: number;
  max_child_namespaces: number;
}

export interface NamespaceInfo {
  uuid: string;
  path: string;
  parent_uuid: string;
  created_at: string;
  child_visible_default: boolean;
  quotas: NamespaceQuotas;
}

export interface NamespaceListResult {
  namespaces: string[];
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

/** The ten ACL capabilities, matching the backend `Capability` enum. */
export type PolicyCapability =
  | "deny"
  | "create"
  | "read"
  | "update"
  | "delete"
  | "list"
  | "patch"
  | "sudo"
  | "connect"
  | "root";

/** A single `(path, capability)` assertion to evaluate against a draft. */
export interface PolicyTestCaseInput {
  path: string;
  capability: string;
}

/** How the rule that decided a verdict related to the evaluated path. */
export type PolicyMatchKind = "exact" | "prefix" | "segment_wildcard" | "none";

/** Per-case verdict from the stateless dry-run endpoint. */
export interface PolicyTestResultRow {
  path: string;
  capability: string;
  allowed: boolean;
  /** The rule that decided the verdict; null when nothing matched. Advisory. */
  matched_path: string | null;
  match_kind: PolicyMatchKind;
  denied_by_deny: boolean;
  /** Present only when the capability name was unrecognized. */
  error?: string;
}

/** Full response from the `policy_test` dry-run command. */
export interface PolicyTestResult {
  /** False when the draft HCL failed to parse. */
  parse_ok: boolean;
  /** Parse/lint errors (with messages) when `parse_ok` is false. */
  errors: string[];
  /** One row per submitted case (empty when `parse_ok` is false). */
  results: PolicyTestResultRow[];
}

/**
 * A savable effectivity test case attached to a policy. Doubles as
 * documentation of operator intent and as a regression gate on save.
 */
export interface PolicyTestCase {
  path: string;
  capability: string;
  /** The expected verdict. */
  expect: "allow" | "deny";
  /** Optional human description. */
  note?: string;
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
  /** Lucide icon name (e.g. `Server`, `Database`, `Shield`). When
   *  unset, the GUI falls back to a text badge. Defaults are baked
   *  into `DEFAULT_RESOURCE_TYPES` per builtin; operator-defined
   *  types pick from a curated list in Settings → Resource Types. */
  icon?: string;
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

/**
 * SSH login class (see features/ssh-resource-login-brokering.md):
 *   - `shared-credential` — a static key/password lives on the resource
 *     (the `secret` source); the historical default.
 *   - `brokered` — every login is minted per-connect from the SSH engine
 *     (`ssh-engine` source). A brokered resource may not hold a static
 *     SSH credential; the editor disables the `secret` source for it.
 */
export type SshLoginClass = "shared-credential" | "brokered";

/** Resolved effective login class for a resource, from
 *  `ssh-broker/policy/effective`. */
export interface EffectiveLoginClass {
  login_class: SshLoginClass;
  login_class_source: string;
  login_class_chain: string[];
  locked_at_tier?: string | null;
}

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
    }
  | {
      /**
       * Use the *connecting operator's* default resource account (set per
       * user under Users → Edit User → Default Resource Account) as the login
       * name, rather than pinning a username on the profile. The login name is
       * resolved per the target's OS family at connect time.
       *
       * SSH: brokers a credential from the SSH engine exactly like
       * `ssh-engine` (carries the same `ssh_mount` / `ssh_role` / `mode`),
       * but `valid_principals` is the connecting operator's account.
       *
       * RDP: the account supplies the login user; the password is prompted at
       * connect time (a username-only account can't carry one). The
       * `ssh_*` fields are unused for RDP profiles.
       */
      kind: "default-account";
      ssh_mount?: string;
      ssh_role?: string;
      mode?: "ca" | "otp" | "pqc";
    };

export interface ConnectionProfile {
  /** Stable per-resource id, generated client-side on create. */
  id: string;
  /** Operator-visible label (e.g. "Default", "Break-glass"). */
  name: string;
  /**
   * When true, this profile is the one the resource-card / ⌘K
   * quick-Connect launches without prompting the operator to choose.
   * At most one profile per resource carries this flag; the
   * Connection-tab editor clears it from the others on save. Optional
   * + defaults to false for profiles minted before this field landed
   * — the launcher then falls back to "the sole profile" or, failing
   * that, opens the Connection tab so the operator picks.
   */
  is_default?: boolean;
  protocol: SessionProtocol;
  /**
   * Transport: `direct` opens an SSH/RDP socket from the GUI host
   * straight to the target (the original Resource Connect path),
   * `rustion` mediates the session through one of the operator's
   * enrolled PQC bastions per features/rustion-integration.md.
   * Optional + defaults to `direct` for backwards-compatibility with
   * profiles minted before this field landed.
   */
  kind?: "direct" | "rustion";
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
  /**
   * RDP only — opt-in to aggressive performance flags (disable
   * wallpaper / theming / cursor shadow / cursor settings on top of
   * the ironrdp defaults). Off by default; enabling trades a more
   * basic-looking remote desktop for substantially less repaint
   * traffic. Has no effect for SSH profiles.
   */
  rdp_aggressive_performance?: boolean;
  /**
   * `kind === "rustion"` only — ordered list of Rustion target ids
   * to try. Empty/unset = pick at random from the global pool of
   * healthy enabled targets. Tried in order; advances on transport/
   * 5xx failures, halts on auth (4xx) refusals. See
   * features/rustion-integration.md § Bastion selection.
   */
  bastions?: string[];
  /**
   * `kind === "rustion"` only — recording policy override. Strictest
   * wins under the policy ladder (always > input-redacted > off);
   * the resource's asset-group / type / global tier can still tighten
   * a per-profile `off` upward.
   */
  recording?: "always" | "off" | "input-redacted";
  /**
   * SSH only — the login class this profile is built for. When the
   * resource resolves to `brokered`, the editor forces `ssh-engine` and
   * disables the `secret` source. Optional; the effective class is
   * resolved server-side from the four-tier policy at connect time and
   * this field is only an editor hint. Ignored for RDP profiles.
   */
  login_class?: SshLoginClass;
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

export interface MachineBinding {
  machine_id: string;
  spiffe_id: string;
  environments: string[];
}

export interface MachineBindingList {
  machines: MachineBinding[];
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
  bound_machines: MachineBinding[];
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
  environments: string[];
}

// FerroGate machine auth
export interface FerroGateConfig {
  trust_domain: string;
  expected_audience: string;
  jwks_source: string;
  cmis_endpoint: string;
  cmis_srv: string;
  cmis_spki_pins: string[];
  static_jwks: string;
  accept_svid: boolean;
  clock_leeway_secs: number;
  default_token_ttl: number;
  cmis_tls_enable: boolean;
  cmis_same_host: boolean;
  jwks_refresh_secs: number;
  bootstrap_root_auto_approve: boolean;
  bootstrap_policies: string[];
  require_user_token: boolean;
  /**
   * Server-enforced: when true, EVERY authenticated request to this server
   * must present a FerroGate machine-bound token (or a root token). Clients
   * discover this via `ferrogateRequirement()` and cannot bypass it.
   */
  require_machine_identity: boolean;
  /**
   * MIA environment selector for this deployment: clients read
   * `mia-<env>.toml` when minting child tokens for this server. Advertised
   * via `ferrogateRequirement()`; empty = the default `mia.toml`.
   */
  mia_environment: string;
}

/**
 * The server's machine-identity requirement, from the unauthenticated
 * `auth/ferrogate/requirement` endpoint. The connect flow gates on this
 * (the server's answer), never on a client-side toggle.
 */
export interface FerroGateRequirement {
  require_machine_identity: boolean;
  expected_audience: string;
  trust_domain: string;
  /** MIA environment the client should dial (`mia-<env>.toml`); empty = default. */
  mia_environment: string;
}

export interface FerroGateMachine {
  id: string;
  spiffe_id: string;
  status: string;
  policies: string[];
  ttl_seconds: number;
  ek_cert_sha384: string;
  policy_id: string;
  parent_svid: string;
  first_seen_at: number;
  approved_at: number;
  approver: string;
  last_login_at: number;
  last_login_ip: string;
  reject_reason: string;
  comment: string;
}

// Result of a MIA self-bootstrap / machine-login attempt.
export type FerroGateEnrolment = "approved" | "pending" | "rejected" | "revoked";

export interface FerroGateLoginResult {
  spiffe_id: string;
  authenticated: boolean;
  // Classified enrolment outcome — lets the UI branch (proceed / show setup
  // dialog / show hard denial) without parsing free-text errors. Hard failures
  // (transport, token verification, rate limiting) reject the promise instead.
  enrolment: FerroGateEnrolment;
  // Server's reason for a non-approved outcome (empty when authenticated).
  message: string;
  client_token: string;
  policies: string[];
  lease_duration: number;
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

/** Grantee discriminator on shares. `entity` is the legacy default;
 *  `group_user` / `group_app` target an identity group and are gated
 *  by the caller having a policy with `metadata.group_shared_resources`
 *  set to `"true"`. */
export type ShareGranteeKind = "entity" | "group_user" | "group_app";

/** A share-pointer — what the `by-grantee` list returns; load the
 *  full record via `getShare` or equivalent if values are needed. */
export interface SharePointer {
  target_kind: string;
  target_path: string;
  /** Defaults to "entity" for legacy pointers persisted before group
   *  grantees existed. */
  grantee_kind?: ShareGranteeKind;
}

export interface ShareEntry {
  target_kind: string;
  target_path: string;
  /** Defaults to "entity" on shares persisted before grantee_kind
   *  existed. */
  grantee_kind?: ShareGranteeKind;
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
  /** Phase L8: managed-key UUID this issuer is backed by. The
   *  issuer's keypair lives in `pki/keys/<key_id>` (single source of
   *  truth); the GUI surfaces this so an operator can deep-link into
   *  the Keys tab and so refs / rotations stay traceable. Empty for
   *  pre-L8 records that haven't been re-read since the migration
   *  shim ran. */
  key_id?: string;
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
  /** Phase L3: promote a managed key to root issuer instead of
   *  generating fresh material. Algorithm must match key_type/key_bits. */
  key_ref?: string;
}

export interface PkiRootResult {
  certificate: string;
  issuer_id: string;
  issuer_name: string;
  expiration: number;
  /** Only populated in `exported` mode AND when `key_ref` was not used. */
  private_key?: string;
  private_key_type?: string;
  /** Phase L3: when `key_ref` was used, the bound managed key UUID. */
  key_id: string;
}

export interface PkiGenerateIntermediateRequest {
  mount: string;
  mode: "internal" | "exported";
  common_name: string;
  organization?: string;
  key_type?: string;
  key_bits?: number;
  /** Phase L3: back the pending intermediate with a managed key. */
  key_ref?: string;
}

export interface PkiIntermediateResult {
  csr: string;
  private_key?: string;
  private_key_type?: string;
  /** Phase L3: when `key_ref` was used, the bound managed key UUID. */
  key_id: string;
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

/** One certificate node in a parsed CA chain — shared by the pre-import
 *  preview and the post-import result. The tree is built by linking a
 *  node's `issuer` DN to another node's `subject` DN. */
export interface PkiChainNode {
  subject: string;
  issuer: string;
  common_name: string;
  issuer_common_name: string;
  serial: string;
  not_after: number;
  is_ca: boolean;
  self_signed: boolean;
}

export interface PkiChainPreview {
  nodes: PkiChainNode[];
  key_present: boolean;
  warnings: string[];
}

/** One imported (or skipped) cert from a `pki/config/ca` call. */
export interface PkiImportedCert {
  issuer_id: string;
  issuer_name: string;
  common_name: string;
  subject: string;
  issuer: string;
  serial: string;
  self_signed: boolean;
  has_key: boolean;
  keyless: boolean;
  skipped: boolean;
}

export interface PkiCaImportResult {
  issuer_id: string;
  issuer_name: string;
  imported_issuers: string[];
  imported_keys: string[];
  chain: PkiImportedCert[];
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
  /** Phase L2: opt-in to private-key reuse via `key_ref` on issue/sign. */
  allow_key_reuse: boolean;
  /** Phase L2: allow-list of managed keys this role may pin to. Empty +
   *  `allow_key_reuse=true` means any key on this mount is acceptable. */
  allowed_key_refs: string[];
  /** Phase L4: parent domains for CN / DNS SAN matching. Combined with
   *  `allow_subdomains` / `allow_bare_domains` / `allow_glob_domains`. */
  allowed_domains: string[];
  /** Phase L4: entries in `allowed_domains` may carry single-label `*` globs. */
  allow_glob_domains: boolean;
  /** Phase L4: per-role kill-switch for the ACME server endpoints. */
  acme_enabled: boolean;
}

export interface PkiIssueRequest {
  mount: string;
  role: string;
  common_name: string;
  alt_names?: string;
  ip_sans?: string;
  ttl?: string;
  issuer_ref?: string;
  /** Phase L2: pin issuance to a managed key. Requires `role.allow_key_reuse`. */
  key_ref?: string;
}

export interface PkiIssueResult {
  certificate: string;
  issuing_ca: string;
  private_key: string;
  private_key_type: string;
  serial_number: string;
  issuer_id: string;
  /** Phase L3: leaf-issuer → root chain. */
  ca_chain: string[];
  /** Phase L2: when `key_ref` was used, the resolved managed key UUID. */
  key_id: string;
}

export interface PkiSignCsrRequest {
  mount: string;
  role: string;
  csr: string;
  common_name?: string;
  alt_names?: string;
  ttl?: string;
  issuer_ref?: string;
  /** Phase L2: assert the CSR's SubjectPublicKeyInfo matches a managed key. */
  key_ref?: string;
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
  ca_chain: string[];
  key_id: string;
}

// ── Phase L1 — managed key store ──────────────────────────────────

export interface PkiManagedKey {
  key_id: string;
  name: string;
  key_type: string;
  key_bits: number;
  public_key: string;
  source: string;
  exported: boolean;
  created_at: number;
  issuer_ref_count: number;
  cert_ref_count: number;
}

export interface PkiGenerateKeyRequest {
  mount: string;
  /** `internal` (private not echoed) or `exported` (private returned once). */
  mode: "internal" | "exported";
  key_type: string;
  key_bits?: number;
  name?: string;
}

export interface PkiGenerateKeyResult {
  key_id: string;
  key_type: string;
  source: string;
  exported: boolean;
  /** Only populated in `exported` mode. */
  private_key?: string;
  public_key: string;
  name: string;
}

export interface PkiImportKeyRequest {
  mount: string;
  private_key: string;
  name?: string;
}

// ── Phase L3 — issuer chain ───────────────────────────────────────

export interface PkiIssuerChain {
  issuer_id: string;
  issuer_name: string;
  ca_chain: string[];
  certificate_bundle: string;
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
  /** True when indexed via `pki/certs/import` rather than issued by
   *  this engine. Carries no key, no issuer; CRL builder skips it. */
  is_orphaned?: boolean;
  /** Provenance label set at import time (e.g. `xca-import`). */
  source?: string;
  /** UUID of the issuer that signed this cert when the engine knows.
   *  Empty for orphan imports. */
  issuer_id?: string;
  /** Issuer DN as RFC 4514 text, parsed from the cert. Always
   *  populated. The Certificates tab uses this as the Emitter cell
   *  with an "owned" / "external" badge derived from `issuer_id`. */
  issuer_dn?: string;
  /** Subject Alternative Name buckets pulled from the cert. */
  san_dns?: string[];
  san_ip?: string[];
  san_email?: string[];
  san_uri?: string[];
  /** Decoded KU / EKU bits as textual labels (`digitalSignature`,
   *  `serverAuth`, …). Empty when the cert omits the extension. */
  key_usages?: string[];
  ext_key_usages?: string[];
}

export interface PkiImportCaPkcs12Request {
  mount: string;
  /** Base64-encoded PKCS#12 (.p12 / .pfx) container bytes. */
  pkcs12_b64: string;
  /** Container passphrase. Empty string is allowed for password-less files. */
  passphrase: string;
  issuer_name?: string;
}

export interface PkiImportCertRequest {
  mount: string;
  certificate: string;
  source?: string;
}

export interface PkiImportCertResult {
  serial_number: string;
  not_after: number;
  is_orphaned: boolean;
  source: string;
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

// ── Cert-Lifecycle module (Phases L5–L7) ─────────────────────────

export interface CertLifecycleMountInfo {
  path: string;
  mount_type: string;
}

export type CertLifecycleKind = "file" | "http-push";
export type CertLifecycleKeyPolicy = "rotate" | "reuse" | "agent-generates";

export interface CertLifecycleTarget {
  name: string;
  kind: CertLifecycleKind;
  /** For `file`: absolute directory path. For `http-push`: http(s) URL. */
  address: string;
  /** PKI mount the renewer dispatches issuance into. Default `pki`. */
  pki_mount: string;
  role_ref: string;
  common_name: string;
  alt_names: string[];
  ip_sans: string[];
  /** Optional duration string (e.g. `720h`). Empty = role default. */
  ttl: string;
  key_policy: CertLifecycleKeyPolicy;
  /** Required when `key_policy = "reuse"`. */
  key_ref: string;
  /** Lead time before NotAfter at which the L6 scheduler renews. */
  renew_before: string;
  created_at: number;
}

export interface CertLifecycleState {
  name: string;
  current_serial: string;
  current_not_after: number;
  last_renewal: number;
  last_attempt: number;
  last_error: string;
  next_attempt: number;
  failure_count: number;
}

export interface CertLifecycleRenewResult {
  name: string;
  serial_number: string;
  not_after: number;
  delivered_to: string;
  delivery_kind: string;
  delivery_note: string;
}

export interface CertLifecycleSchedulerConfig {
  enabled: boolean;
  tick_interval_seconds: number;
  /** Write-only: present in request bodies, never echoed by reads. */
  client_token: string;
  /** Read-side flag from the engine indicating whether a token is set. */
  client_token_set: boolean;
  base_backoff_seconds: number;
  max_backoff_seconds: number;
}
