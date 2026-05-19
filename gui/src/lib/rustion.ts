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
}

export const rustionSessionOpen = (request: RustionSessionOpenRequest) =>
  invoke<RustionSessionOpenResult>("rustion_session_open", { request });
