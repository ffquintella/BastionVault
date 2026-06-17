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
  /** PEM-encoded leaf TLS cert pinned for outbound HTTPS to this
   *  Rustion. When non-empty, BV trusts only this cert as a root and
   *  skips hostname matching — lets the probe tolerate self-signed
   *  certs (lab / pre-prod) without weakening trust elsewhere. */
  tls_pinned_cert_pem: string;
  /** Convenience boolean mirror of `tls_pinned_cert_pem.length > 0`
   *  emitted by the server so list/health views can render a badge
   *  without loading the PEM body. */
  tls_pinned: boolean;
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
  /** Phase-2 ML-DSA-65 sibling role. Required for `master/issue` to
   *  succeed — the rustion engine mints the hybrid keypair by calling
   *  pki/issue/<pki_role> + pki/issue/<pki_role_pqc>. */
  pki_role_pqc: string;
  issuer_ref: string;
  algorithm: string;
  default_ttl_secs: number;
  rotate_grace_secs: number;
  current_serial: string;
  current_not_after: string;
  updated_at: string;
  configured: boolean;
}

export interface RustionMasterIssueResult {
  serial: string;
  not_after: string;
  algorithm: string;
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
  /** Optional PEM-encoded pinned TLS leaf cert. Empty = no pin /
   *  preserve existing on update. Pass the sentinel `"-"` on update
   *  to explicitly clear a previously-set pin. */
  tls_pinned_cert_pem?: string;
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

/** Mint the hybrid Ed25519 + ML-DSA-65 master keypair through the
 *  configured PKI engine. Mirrors `bvault rustion master issue`. */
export const rustionMasterIssue = () =>
  invoke<RustionMasterIssueResult>("rustion_master_issue");

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

// ─── Phase 9.2: attest + deenrol ────────────────────────────────

export interface RustionAttestOutcome {
  status: "ok" | "err" | string;
  bastionId: string;
  correlationId: string;
  attestedAt: string;
  expiresAt: string;
  error: string;
}

export interface RustionAttestResult {
  attempted: number;
  succeeded: number;
  failed: number;
  results: RustionAttestOutcome[];
}

/** Re-attest a single bastion (or all if bastionId is omitted). */
export const rustionAuthorityAttest = (bastionId?: string) =>
  invoke<RustionAttestResult>("rustion_authority_attest", { bastionId });

export interface RustionDeenrolResult {
  bastionId: string;
  correlationId: string;
  reason: string;
}

/** Send a deenrol envelope to a bastion before deleting the local target. */
export const rustionTargetDeenrol = (bastionId: string, reason?: string) =>
  invoke<RustionDeenrolResult>("rustion_target_deenrol", { bastionId, reason });

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

export interface RustionReconcileReport {
  found: number;
  imported: number;
  skippedExisting: number;
}

/** Actively reconcile the recordings index against a bastion's
 *  `/v1/recordings` list. Omit `bastionId` to sweep every enrolled
 *  bastion. Idempotent — only missing recordings are imported. */
export const rustionRecordingsReconcile = (bastionId?: string) =>
  invoke<RustionReconcileReport>("rustion_recordings_reconcile", {
    bastionId: bastionId ?? null,
  });

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

export interface RustionAuditEntry {
  sequence: number;
  timestamp: string;
  actor: string;
  sessionId: string | null;
  sourceAddr: string | null;
  event: unknown;
  hash: string;
  targetId: string;
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
  recentAudit: RustionAuditEntry[];
}

export const rustionRecordingReplayLog = (
  recordingId: string,
  sha256Mismatch: boolean,
) =>
  invoke<void>("rustion_recording_replay_log", {
    input: { recordingId, sha256Mismatch },
  });

// ─── Phase 9.1: deployment_id ───────────────────────────────────

export const rustionDeploymentIdRead = () =>
  invoke<string>("rustion_deployment_id_read");

/** Phase 8.3 — spawn a separate WebviewWindow for full-screen
 *  replay of one recording. Resolves once the window is open. */
export const rustionOpenReplayWindow = (recordingId: string) =>
  invoke<void>("rustion_open_replay_window", { recordingId });

export const rustionTelemetryList = () =>
  invoke<RustionTelemetryTarget[]>("rustion_telemetry_list");

export const rustionTelemetryPoll = () =>
  invoke<RustionTelemetryTarget[]>("rustion_telemetry_poll");

// ─── Phase 9.3: dispatcher preview ──────────────────────────────

export interface RustionDispatcherCandidate {
  id: string;
  name: string;
  /** up | degraded | down | unknown */
  status: RustionHealthStatus;
}

export interface RustionDispatcherDropped {
  id: string;
  name: string;
  /** disabled | not-registered | not-up:<status> */
  reason: string;
}

export interface RustionDispatcherPreview {
  /** ordered-fallback | random-pool | group */
  mode: string;
  /** group name when mode === "group", else "" */
  groupName: string;
  /** which policy tier supplied the bastion list */
  sourceTier: string;
  /** healthy candidates, in the order the next Connect would try them */
  candidates: RustionDispatcherCandidate[];
  /** targets the dispatcher skipped, with the reason */
  dropped: RustionDispatcherDropped[];
}

/** Preview the dispatcher's bastion candidate ordering for a resource,
 *  without opening a session. Drives the Connection tab's
 *  "Will try: A → B" line. */
export const rustionDispatcherPreview = (request: {
  resourceId?: string;
  resourceType?: string;
  assetGroupIds?: string[];
}) =>
  invoke<RustionDispatcherPreview>("rustion_dispatcher_preview", {
    request: {
      resourceId: request.resourceId ?? "",
      resourceType: request.resourceType ?? "",
      assetGroupIds: request.assetGroupIds ?? [],
    },
  });
