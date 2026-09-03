// Typed wrappers for the Rustion bastion integration's Tauri commands.
// Phase 1 of features/rustion-integration.md: target registry, cached
// health view, master-cert configuration slot. Session-grant + dispatcher
// surfaces (Phases 2+) layer on top of these types.

import { invoke } from "@tauri-apps/api/core";

import { isRouteUnsupported } from "./error";

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
  /** Discovered OpenSSH host-key fingerprint of the bastion's SSH proxy
   *  (`SHA256:…`), pinned by the SSH dialler. Populated by listener
   *  discovery; empty when the bastion advertised none (pre-v2 Rustion
   *  or SSH proxy not co-located). */
  ssh_host_key_fingerprint?: string;
  /** Discovered SHA-256 of the bastion's RDP gateway TLS leaf cert
   *  (`sha256:…`), pinned by the RDP dialler. Empty when the bastion
   *  advertised none. */
  rdp_tls_pin_sha256?: string;
  /** ISO-8601 timestamp of the last successful `GET /v1/listeners`
   *  discovery pull, or empty before any pull. The pin fields above are
   *  only meaningful once this is set. */
  listeners_synced_at?: string;
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
  /** `X-Rustion-Authority` this deployment presents, and the name the
   *  bastion files the pinned pubkey under (`authorities/<name>.yaml`).
   *  Defaults to `bastion-vault`. Rustion verifies against exactly one
   *  record, looked up by this name, so two BV deployments sharing one
   *  bastion need distinct names. Empty on write = leave unchanged. */
  authority_name: string;
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
  /** The authority name this key must be approved under on the bastion. */
  authority_name: string;
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

/** Re-run `GET /v1/listeners` against the bastion and persist the
 *  discovered dial coordinates + transport pins on the target record.
 *  Discovery otherwise fires only once, best-effort, at enrolment — so
 *  a bastion upgraded to listener schema v2 (or one whose host key /
 *  RDP TLS cert rotated) keeps whatever was captured that day until
 *  this is called. */
export const rustionTargetRefreshListeners = (id: string) =>
  invoke<RustionTargetSummary>("rustion_target_refresh_listeners", { id });

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

/** Raw v1 open: the caller supplies its own resolved credential material.
 *
 *  Pass `resourceId` whenever there is a resource behind the session — the
 *  server authorizes the open against it (`connect`/`read`, ownership, or a
 *  share on `resources/secrets/<id>/`), which is what makes the endpoint
 *  usable by a non-admin. Omitting it asks for an *unbound* open to an
 *  arbitrary host, which has no object to authorize against and therefore
 *  requires `sudo` on `rustion/session/open` — root or `administrator` only. */
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

  // ─── Phase 8.6: keystroke-transcript summary ───────────────────
  // Counters and flags only. The transcript itself is behind
  // `rustionRecordingKeystrokes`, which the server gates with
  // recording *playback* and audits separately.
  /** `""` (no transcript index yet) | `indexed` | `not-enabled` |
   *  `digest-mismatch` | `failed`.
   *
   *  `""` and `not-enabled` are **different states** and the UI must
   *  not collapse them: the first means BastionVault has not looked
   *  yet, the second means the bastion had keystroke recording
   *  switched off for that session. Neither means nobody typed. */
  keystrokeState: string;
  /** The artifact header's `keystroke_metadata`. */
  keystrokeMetadata: boolean;
  /** A transcript with at least one non-redacted character exists. */
  keystrokeText: boolean;
  /** Non-redacted characters, i.e. what the search covers. */
  keystrokeChars: number;
  keystrokeRuns: number;
  keystrokeRedactedRuns: number;
  /** `exact` | `approximate` | `none` | `unknown`. Anything other
   *  than `exact` must be surfaced. */
  keystrokeDecoding: string;
  /** The bastion rebuilt the trailer after a crash — the session's
   *  final unclosed run is missing. */
  keystrokeRebuilt: boolean;
  keystrokeComplete: boolean;
  keystrokeIndexedAt: string;
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

/** One chunk of a recording artifact. `sha256` and `sizeBytes`
 *  describe the whole artifact and repeat on every chunk. */
export interface RustionRecordingChunk {
  recordingId: string;
  format: string;
  sha256: string;
  sizeBytes: number;
  chunkIndex: number;
  chunkCount: number;
  chunkSize: number;
  offset: number;
  chunkLen: number;
  eof: boolean;
  /** Base64 of this chunk only. */
  bytesB64: string;
}

export const rustionRecordingBlobChunk = (
  recordingId: string,
  chunkIndex: number,
) =>
  invoke<RustionRecordingChunk>("rustion_recording_blob_chunk", {
    recordingId,
    chunkIndex,
  });

/** Assembled recording artifact, plus the sidecar fields the player
 *  and the integrity check need. */
export interface RecordingBytes {
  recordingId: string;
  format: string;
  /** Whole-artifact digest, for the caller's integrity check. */
  sha256: string;
  bytes: Uint8Array;
}

/** Fetch a recording artifact of any size, one chunk at a time.
 *
 *  The single-shot `rustionRecordingBlob` puts the whole artifact in
 *  one response, which fails outright once that response exceeds the
 *  client's read limit — a 17.8 MB recording base64-expands past the
 *  10 MB default. This walks `blob/chunk/<n>` instead: the first chunk
 *  reports `sizeBytes` and `chunkCount`, the buffer is allocated once,
 *  and each chunk is decoded straight into place. Nothing here scales
 *  with recording size except the buffer the player was always going
 *  to need.
 *
 *  `onProgress(received, total)` is called after each chunk. `signal`
 *  aborts between chunks — a closed modal must not keep pulling
 *  megabytes.
 *
 *  Throws on a truncated or over-long transfer rather than handing back
 *  a partial artifact: a short read would surface as a corrupt
 *  recording, and playback failures must not be ambiguous about their
 *  cause. */
export async function fetchRecordingBytes(
  recordingId: string,
  opts: {
    onProgress?: (received: number, total: number) => void;
    signal?: AbortSignal;
  } = {},
): Promise<RecordingBytes> {
  const { onProgress, signal } = opts;
  let first: RustionRecordingChunk;
  try {
    first = await rustionRecordingBlobChunk(recordingId, 0);
  } catch (e) {
    // Version skew: a server that predates the chunk route. Fall back
    // to the single-shot read so replay keeps working against an
    // un-upgraded vault — small recordings play exactly as before, and
    // a large one still fails there with the response-size error,
    // which is the server upgrade this route exists to deliver.
    // Announced in the console rather than silently: the operator's
    // playback just took a different path than the one documented.
    if (!isRouteUnsupported(e)) throw e;
    console.warn(
      `recording ${recordingId}: server has no blob/chunk route; ` +
        "falling back to the single-response read (upgrade the server " +
        "to play recordings larger than its response limit)",
    );
    const whole = await rustionRecordingBlob(recordingId);
    const bin = atob(whole.bytesB64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    onProgress?.(bytes.length, bytes.length);
    return {
      recordingId: whole.recordingId || recordingId,
      format: whole.format,
      sha256: whole.sha256,
      bytes,
    };
  }
  const total = first.sizeBytes;
  const bytes = new Uint8Array(total);
  let received = 0;

  const place = (chunk: RustionRecordingChunk) => {
    const bin = atob(chunk.bytesB64);
    if (chunk.offset + bin.length > total) {
      throw new Error(
        `recording ${recordingId}: chunk ${chunk.chunkIndex} runs past the ` +
          `reported size (${chunk.offset} + ${bin.length} > ${total})`,
      );
    }
    for (let i = 0; i < bin.length; i++) {
      bytes[chunk.offset + i] = bin.charCodeAt(i);
    }
    received += bin.length;
    onProgress?.(received, total);
  };

  place(first);
  for (let i = 1; i < first.chunkCount; i++) {
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
    place(await rustionRecordingBlobChunk(recordingId, i));
  }

  if (received !== total) {
    throw new Error(
      `recording ${recordingId}: expected ${total} bytes, assembled ${received}`,
    );
  }
  return {
    recordingId: first.recordingId || recordingId,
    format: first.format,
    sha256: first.sha256,
    bytes,
  };
}

// ─── Keystroke transcripts + search (Phase 8.6) ───────────────────
//
// `.rdp-rec` version 4 carries a searchable keystroke transcript
// inside the artifact BastionVault already pulls — no new fetch path
// and no new integrity story, because the sidecar's `sha256` already
// covers it. Format spec: Rustion `docs/rdp-keystroke-metadata.md`.
//
// Three rules the UI has to honour, not just the API:
//   1. A redacted run is rendered as withheld with its rule and its
//      character count. Nothing reconstructs one.
//   2. `keystrokeState === ""` (not indexed) and `"not-enabled"`
//      (recording was off) are different, and neither is an empty
//      transcript.
//   3. `textDecoding !== "exact"`, `rebuilt`, and a
//      `text-record-scan` source each need a visible caveat.

/** One keystroke run. `text` is `null` exactly when `redacted`. */
export interface RustionKeystrokeRun {
  /** Elapsed ms of the run's first keystroke — the player's seek
   *  offset. */
  t: number;
  /** Duration in ms. `0` on a scanned transcript, which has none. */
  d: number;
  /** Character count. Retained on a redacted run so an auditor sees
   *  that N characters were withheld. */
  n: number;
  text: string | null;
  redacted: boolean;
  /** `known_secret` | `masked_field` | `deny_pattern` |
   *  `credential_pair` on a redacted run. */
  reason: string;
  /** The `field_epoch` correlation **hint**. A pass-through RDP proxy
   *  cannot see the remote UI's focus, so this groups runs visually —
   *  do not label it "field" and do not depend on it. */
  epoch: number;
  composed: boolean;
  approximate: boolean;
  truncated: boolean;
}

export interface RustionKeystrokeCensus {
  keysTotal: number;
  charsDecoded: number;
  unicodeEvents: number;
  namedKeys: number;
  composed: number;
  undecodableScancodes: number;
  redactedRuns: number;
  redactedChars: number;
  slowpathInputPdus: number;
  truncatedRuns: number;
}

export interface RustionKeystrokeTranscript {
  recordingId: string;
  sessionId: string;
  format: string;
  /** `not-indexed` | `indexed` | `not-enabled` | `digest-mismatch` |
   *  `failed`. */
  state: string;
  keystrokeMetadata: boolean;
  formatVersion: number;
  /** Bound on how far out of order a keystroke record may appear. */
  maxReorderMs: number;
  /** `trailer-footer` | `text-record-scan`. */
  source: string;
  /** False for a rebuilt trailer or a scanned fallback. */
  complete: boolean;
  trailerVersion: number;
  rebuilt: boolean;
  textDecoding: string;
  keyboardLayout: string;
  keyboardLayoutSource: string;
  runs: RustionKeystrokeRun[];
  census: RustionKeystrokeCensus;
  charsIndexed: number;
  indexedAt: string;
  warnings: string[];
  /** Server-supplied statement that upstream redaction is
   *  best-effort. Render it; never suppress it. */
  redactionDisclaimer: string;
}

/** Read one recording's keystroke transcript. Gated on the server
 *  with recording playback and audited as
 *  `recording.transcript.accessed` — a separate event from
 *  `recording.replayed`. */
export const rustionRecordingKeystrokes = (recordingId: string) =>
  invoke<RustionKeystrokeTranscript>("rustion_recording_keystrokes", {
    recordingId,
  });

export interface RustionKeystrokeIndexReport {
  recordingId: string;
  status: string;
  detail: string;
  runs: number;
  redactedRuns: number;
  charsIndexed: number;
  textDecoding: string;
  rebuilt: boolean;
  source: string;
  considered: number;
  indexed: number;
  notEnabled: number;
  unchanged: number;
  failed: number;
  remaining: number;
}

/** Build or refresh the transcript index. Omit `recordingId` to
 *  sweep the recordings that have none — each costs a full artifact
 *  fetch from its bastion, so the server caps the batch and reports
 *  what is left. */
export const rustionKeystrokesIndex = (
  recordingId?: string,
  force?: boolean,
) =>
  invoke<RustionKeystrokeIndexReport>("rustion_keystrokes_index", {
    recordingId: recordingId ?? null,
    force: force ?? null,
  });

export interface RustionKeystrokeHit {
  recordingId: string;
  sessionId: string;
  targetHost: string;
  targetUser: string;
  authority: string;
  bastionId: string;
  startedAt: string;
  runIndex: number;
  /** Seek offset into the recording, in ms. */
  tMs: number;
  dMs: number;
  n: number;
  epoch: number;
  excerpt: string;
  approximate: boolean;
  textDecoding: string;
  rebuilt: boolean;
  complete: boolean;
}

export interface RustionKeystrokeSearchReport {
  scanned: number;
  /** Recordings with no transcript index. A negative result does not
   *  speak for these, and the UI has to say so. */
  unindexed: number;
  truncated: boolean;
  hits: RustionKeystrokeHit[];
  redactionDisclaimer: string;
}

/** Search indexed transcripts for typed text.
 *
 *  The query travels in the request body over the Tauri IPC and then
 *  in a POST body — never a URL, a query string or a log line. The
 *  server matches per run over non-redacted text, so a hit cannot
 *  come from a withheld run. */
export const rustionKeystrokeSearch = (query: string, limit?: number) =>
  invoke<RustionKeystrokeSearchReport>("rustion_keystroke_search", {
    query,
    limit: limit ?? null,
  });

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

// ─── Phase 7.4: effective-policy resolver ────────────────────────

export interface RustionLockViolation {
  lockingTier: string;
  field: string;
  detail: string;
}

/** The resolver's verdict across all four tiers, with the tier each
 *  field came from. `transport` is what actually decides whether a
 *  Connect routes through a bastion — the per-resource tier alone
 *  doesn't, since a global / type / asset-group tier can supply it. */
export interface RustionEffectivePolicy {
  transport: Transport;
  transportSource: string;
  /** Bastion ids the resolver would pick, already expanded from
   *  `bastionGroup`. */
  bastions: string[];
  bastionGroup: string;
  bastionsSource: string;
  recording: Recording;
  recordingSource: string;
  lockedBy: string[];
  /** Set when a lower tier tried to weaken a locked higher tier;
   *  session/open would refuse with 403. */
  lockViolation: RustionLockViolation | null;
}

/** Resolve the effective Rustion policy for a resource without opening a
 *  session. Every authenticated principal can call this — the implicit
 *  `default` / `namespace-self` policies grant it — because a caller who
 *  can't see the transport tier can't tell a brokered resource from a
 *  direct-dial one, and the connect path has to know which it is. */
export const rustionPolicyEffective = (request: {
  resourceId?: string;
  resourceType?: string;
  assetGroupIds?: string[];
}) =>
  invoke<RustionEffectivePolicy>("rustion_policy_effective", {
    request: {
      resourceId: request.resourceId ?? "",
      resourceType: request.resourceType ?? "",
      assetGroupIds: request.assetGroupIds ?? [],
    },
  });

/** True when this verdict routes the session through a bastion — i.e. the
 *  credential is resolved server-side and never lands on the operator's
 *  machine. Mirrors `prefer_rustion` in
 *  `gui/src-tauri/src/commands/connect.rs`, which is the code that
 *  actually makes the routing decision at connect time. */
export function brokersThroughBastion(
  p: Pick<RustionEffectivePolicy, "transport" | "bastions"> | null,
): boolean {
  if (!p) return false;
  if (p.transport === "rustion-required") return true;
  return p.transport === "rustion-preferred" && p.bastions.length > 0;
}

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
/** Open the full-screen replay window.
 *
 *  `atMs` seeks the player to that offset — set it from a
 *  keystroke-search hit's `tMs`. Only the offset travels in the
 *  window URL; the query and the matched text never do. */
export const rustionOpenReplayWindow = (recordingId: string, atMs?: number) =>
  invoke<void>("rustion_open_replay_window", {
    recordingId,
    atMs: atMs ?? null,
  });

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
