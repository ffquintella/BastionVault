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
