// Typed wrappers for the Rustion bastion integration's Tauri commands.
// Phase 1 of features/rustion-integration.md: target registry, cached
// health view, master-cert configuration slot. Session-grant + dispatcher
// surfaces (Phases 2+) layer on top of these types.

import { invoke } from "@tauri-apps/api/core";

export type RustionHealthStatus = "up" | "degraded" | "down" | "unknown" | "";

export interface RustionTargetSummary {
  id: string;
  name: string;
  endpoint: string;
  fingerprint: string;
  description: string;
  tags: string[];
  enabled: boolean;
  default_recording_dir: string;
  created_at: string;
  updated_at: string;
  /** Base64 SPKI of the Ed25519 half. */
  public_key_ed25519: string;
  /** Base64 raw FIPS 204 ML-DSA-65 public key. */
  public_key_mldsa65: string;
  /** Base64 raw FIPS 203 ML-KEM-768 public key — used to encrypt
   *  session-grant envelopes to this Rustion instance. Empty for
   *  records enrolled before this field landed. */
  kem_public_key: string;
}

export interface RustionTargetHealth {
  id: string;
  name: string;
  endpoint: string;
  enabled: boolean;
  status: RustionHealthStatus;
  last_ok_at: string;
  last_error: string;
  latency_ms_p50: number;
  consecutive_failures: number;
  version: string;
  active_sessions: number;
  updated_at: string;
}

export interface RustionTargetProbeResult {
  id: string;
  name: string;
  status: RustionHealthStatus;
  last_error: string;
  latency_ms_p50: number;
  version: string;
  active_sessions: number;
  consecutive_failures: number;
  last_ok_at: string;
  updated_at: string;
}

export interface RustionMasterConfig {
  pki_mount: string;
  pki_role: string;
  issuer_ref: string;
  algorithm: string;
  default_ttl_secs: number;
  rotate_grace_secs: number;
  current_serial: string;
  current_not_after: string;
  updated_at: string;
  configured: boolean;
}

export interface RustionMasterPubkey {
  algorithm: string;
  ed25519_pem: string;
  mldsa65_pem: string;
  fingerprint: string;
  current_serial: string;
  current_not_after: string;
  issued: boolean;
}

export interface RustionTargetInput {
  name: string;
  endpoint: string;
  public_key_ed25519: string;
  public_key_mldsa65: string;
  kem_public_key: string;
  description: string;
  tags: string[];
  enabled: boolean;
  default_recording_dir: string;
}

export const rustionTargetList = () =>
  invoke<RustionTargetSummary[]>("rustion_target_list");

export const rustionTargetRead = (id: string) =>
  invoke<RustionTargetSummary>("rustion_target_read", { id });

/** Pass `id` to update an existing target; omit to create a new one. */
export const rustionTargetUpsert = (
  input: RustionTargetInput,
  id?: string,
) =>
  invoke<RustionTargetSummary>("rustion_target_upsert", {
    id: id ?? null,
    input,
  });

export const rustionTargetDelete = (id: string) =>
  invoke<void>("rustion_target_delete", { id });

export const rustionTargetHealthAll = () =>
  invoke<RustionTargetHealth[]>("rustion_target_health_all");

/** Pass `id` for a single-target test; omit to force a full sweep. */
export const rustionTargetProbe = (id?: string) =>
  invoke<RustionTargetProbeResult>("rustion_target_probe", { id: id ?? null });

export const rustionMasterRead = () =>
  invoke<RustionMasterConfig>("rustion_master_read");

export const rustionMasterWrite = (input: RustionMasterConfig) =>
  invoke<RustionMasterConfig>("rustion_master_write", { input });

export const rustionMasterPubkeyExport = () =>
  invoke<RustionMasterPubkey>("rustion_master_pubkey_export");

// ─── Session open ────────────────────────────────────────────────

export interface RustionSessionOpenRequest {
  target_host: string;
  target_port: number;
  /** "ssh" | "rdp" */
  target_protocol: string;
  target_hostkey_pin?: string;
  /** "ssh-key" | "ssh-password" | "rdp-password" | "rdp-cert" | ... */
  credential_kind: string;
  credential_username: string;
  /** Base64-encoded credential bytes. The GUI never sees the raw
   *  material — it's resolved on the host side and forwarded as a
   *  single string here. */
  credential_material_b64: string;
  ttl_secs: number;
  max_renewals: number;
  /** "always" | "off" | "input-redacted" */
  recording: string;
  /** Pinned ordered bastion-target ids. `null`/empty = global pool. */
  bastions?: string[];
  /** Phase 7.3 — policy resolver hints. The BV session-open handler
   *  looks these up in its policy store to walk the full type →
   *  asset-group → resource tier chain on top of the global policy. */
  resourceId?: string;
  resourceType?: string;
  assetGroupIds?: string[];
}

export interface RustionSessionOpenResult {
  session_id: string;
  host: string;
  port: number;
  ticket: string;
  expires_at: string;
  protocol: string;
  recording_id: string;
  bastion_id: string;
  bastion_name: string;
  /** "ordered-fallback" | "random-pool" */
  bastion_selection: string;
  /** IDs the dispatcher tried in order before this one accepted. */
  bastion_candidates_tried: string[];
  /** Correlation id BV stamped on the open envelope — required input
   *  for subsequent `rustionSessionRenew` / `rustionSessionKill`
   *  calls. Phase 5. */
  correlation_id: string;
}

export const rustionSessionOpen = (request: RustionSessionOpenRequest) =>
  invoke<RustionSessionOpenResult>("rustion_session_open", { request });

// ─── Session renew + kill (Phase 5) ──────────────────────────────

export interface RustionSessionRenewRequest {
  bastionId: string;
  sessionId: string;
  correlationId: string;
  extendSecs: number;
}

export interface RustionSessionRenewResult {
  sessionId: string;
  expiresAt: string;
  renewalsUsed: number;
  maxRenewals: number;
  bastionId: string;
}

export const rustionSessionRenew = (request: RustionSessionRenewRequest) =>
  invoke<RustionSessionRenewResult>("rustion_session_renew", { request });

export interface RustionSessionKillRequest {
  bastionId: string;
  sessionId: string;
  correlationId: string;
}

export interface RustionSessionKillResult {
  sessionId: string;
  terminatedAt: string;
  bastionId: string;
}

export const rustionSessionKill = (request: RustionSessionKillRequest) =>
  invoke<RustionSessionKillResult>("rustion_session_kill", { request });

// ─── Recordings (Phase 6.2 / 6.3) ────────────────────────────────

export interface RustionRecordingEntry {
  recordingId: string;
  sessionId: string;
  authority: string;
  format: string;
  sha256: string;
  sizeBytes: number;
  startedAt: string;
  finishedAt: string;
  targetHost: string;
  targetUser: string;
  correlationId: string;
  bastionId: string;
  receivedAt: string;
  /** "webhook" (delivered) or "pull" (fetched via the 24h fallback). */
  deliveryMode: string;
}

export const rustionRecordingsList = () =>
  invoke<string[]>("rustion_recordings_list");

export const rustionRecordingRead = (recordingId: string) =>
  invoke<RustionRecordingEntry>("rustion_recording_read", { recordingId });

export interface RustionRecordingPullRequest {
  bastionId: string;
  sessionId: string;
}

export const rustionRecordingPull = (request: RustionRecordingPullRequest) =>
  invoke<RustionRecordingEntry>("rustion_recording_pull", { request });

export interface RustionRecordingBlob {
  recordingId: string;
  format: string;
  sha256: string;
  /** Base64-encoded recording bytes. Decode via `atob` →
   *  Uint8Array before handing to the player. */
  bytesB64: string;
  sizeBytes: number;
}

export const rustionRecordingBlob = (recordingId: string) =>
  invoke<RustionRecordingBlob>("rustion_recording_blob", { recordingId });

// ─── Phase 7: policy + bastion groups ─────────────────────────────

export type Transport = "" | "direct" | "rustion-preferred" | "rustion-required";
export type Recording = "" | "always" | "input-redacted" | "off";
export type Selection = "ordered" | "random";

export interface RustionPolicyTier {
  transport: Transport;
  bastions: string[];
  bastionGroup: string;
  recording: Recording;
  lock: boolean;
}

export const rustionPolicyGlobalRead = () =>
  invoke<RustionPolicyTier>("rustion_policy_global_read");

export const rustionPolicyGlobalWrite = (input: RustionPolicyTier) =>
  invoke<void>("rustion_policy_global_write", { input });

export interface RustionBastionGroup {
  name: string;
  members: string[];
  selection: Selection;
  description: string;
  createdAt: string;
  updatedAt: string;
}

export interface RustionBastionGroupInput {
  name: string;
  members: string[];
  selection: Selection;
  description: string;
}

export const rustionBastionGroupList = () =>
  invoke<string[]>("rustion_bastion_group_list");

export const rustionBastionGroupRead = (name: string) =>
  invoke<RustionBastionGroup>("rustion_bastion_group_read", { name });

export const rustionBastionGroupCreate = (input: RustionBastionGroupInput) =>
  invoke<RustionBastionGroup>("rustion_bastion_group_create", { input });

export const rustionBastionGroupUpdate = (
  name: string,
  input: RustionBastionGroupInput,
) =>
  invoke<RustionBastionGroup>("rustion_bastion_group_update", { name, input });

export const rustionBastionGroupDelete = (name: string) =>
  invoke<void>("rustion_bastion_group_delete", { name });

export interface RustionTypePolicy {
  name: string;
  transport: Transport;
  bastions: string[];
  bastionGroup: string;
  recording: Recording;
  lock: boolean;
  updatedAt: string;
}

export const rustionPolicyTypeRead = (typeName: string) =>
  invoke<RustionTypePolicy>("rustion_policy_type_read", { typeName });

export const rustionPolicyTypeWrite = (
  typeName: string,
  input: RustionPolicyTier,
) => invoke<void>("rustion_policy_type_write", { typeName, input });

export const rustionPolicyTypeDelete = (typeName: string) =>
  invoke<void>("rustion_policy_type_delete", { typeName });

export interface RustionAssetGroupPolicy {
  priority: number;
  transport: Transport;
  bastions: string[];
  bastionGroup: string;
  recording: Recording;
  lock: boolean;
  updatedAt: string;
}

export interface RustionAssetGroupPolicyInput {
  priority: number;
  transport: Transport;
  bastions: string[];
  bastionGroup: string;
  recording: Recording;
  lock: boolean;
}

export const rustionPolicyAssetGroupRead = (assetGroupId: string) =>
  invoke<RustionAssetGroupPolicy>("rustion_policy_asset_group_read", {
    assetGroupId,
  });

export const rustionPolicyAssetGroupWrite = (
  assetGroupId: string,
  input: RustionAssetGroupPolicyInput,
) =>
  invoke<void>("rustion_policy_asset_group_write", { assetGroupId, input });

export const rustionPolicyResourceRead = (resourceId: string) =>
  invoke<RustionPolicyTier>("rustion_policy_resource_read", { resourceId });

export const rustionPolicyResourceWrite = (
  resourceId: string,
  input: RustionPolicyTier,
) =>
  invoke<void>("rustion_policy_resource_write", { resourceId, input });

export interface RustionForceRustionResult {
  currentTransport: string;
  currentLock: boolean;
  proposedTransport: string;
  proposedLock: boolean;
  applied: boolean;
  note: string;
}

export const rustionPolicyForceRustion = (confirm: boolean) =>
  invoke<RustionForceRustionResult>("rustion_policy_force_rustion", {
    confirm,
  });

// ─── Phase 8.1: telemetry ────────────────────────────────────────

export interface RustionTelemetrySession {
  sessionId: string;
  authority: string;
  protocol: string;
  targetHost: string;
  targetPort: number;
  targetUser: string;
  operatorVaultUser: string;
  operatorSrcIp: string;
  correlationId: string;
  openedAt: string;
  expiresAt: string;
  renewalsUsed: number;
  maxRenewals: number;
  killedAt: string | null;
}

export interface RustionTelemetryStats {
  active: number;
  total: number;
  totalDurationSecs: number;
  topTargets: Array<[string, number]>;
  topOperators: Array<[string, number]>;
}

export interface RustionTelemetryTarget {
  targetId: string;
  targetName: string;
  authority: string;
  lastPullAt: string | null;
  lastPullError: string | null;
  active: RustionTelemetrySession[];
  history: RustionTelemetrySession[];
  stats: RustionTelemetryStats;
}

export const rustionTelemetryList = () =>
  invoke<RustionTelemetryTarget[]>("rustion_telemetry_list");

export const rustionTelemetryPoll = () =>
  invoke<RustionTelemetryTarget[]>("rustion_telemetry_poll");
