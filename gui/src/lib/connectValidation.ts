/**
 * Connect-access validator for the resource list.
 *
 * The card-level Connect chip used to be gated on what the card projection
 * carries (`connect_profiles`) plus a batched `capabilities-self` probe. That
 * is enough to spot a resource with no profile at all, but not enough for the
 * case operators actually hit: a connect-only caller (no `read` on the
 * resource's secrets) looking at profiles that are launchable only when the
 * session is brokered through a bastion. Whether it *is* brokered is decided
 * by the effective transport across all four Rustion policy tiers, which the
 * card projection deliberately doesn't carry — so the chip stayed live and the
 * operator learned "you can't launch this" only after a click and a detour
 * through the Connection tab.
 *
 * This module resolves the same three inputs the launcher itself uses —
 * profiles, connect-only status, effective transport — for every card on
 * screen, in parallel, and answers one question per resource: *could one
 * click launch anything here?* `ResourcesPage` disables the chip when the
 * answer is a definite no.
 *
 * Three properties are deliberate:
 *
 * * **GUI gating only, never authorization.** A verdict decides whether a
 *   button is clickable. The click path (`connectResource`) still re-checks
 *   authoritatively before anything is dialled, and the server authorizes
 *   every session open regardless. A stale-permissive verdict therefore costs
 *   a click, not a boundary.
 * * **Fails open, never closed.** Anything that cannot be resolved — a
 *   capabilities probe that errored, a policy resolver that refused (403), a
 *   card built by a path that carries no profile hints — yields `allowed:
 *   true` with `indeterminate: true`. Failing closed would grey out Connect
 *   across a whole page on one transient error, which is the worse failure:
 *   it hides access the operator really has.
 * * **Cached with a long TTL, and force-refreshable.** Neither input changes
 *   often (a share being granted, a transport tier edited), and re-probing on
 *   every remount would make the list flash and generate exactly the request
 *   burst the read cache and the request gate exist to avoid. So verdicts are
 *   held for {@link CONNECT_VALIDATION_TTL_MS} and the app menu carries a
 *   "Revalidate Connectivity" item that drops them all — see
 *   {@link revalidateConnectAccess}.
 *
 * Cached verdicts are scoped to the authorization context (token + namespace)
 * and keyed by a fingerprint of the resource's profile hints, so a profile
 * edit invalidates its own verdict without waiting out the TTL.
 */

import { capabilitiesSelf } from "./api";
import { hasLaunchableProfile } from "./connectionProfiles";
import type { ConnectProfileHint } from "./types";
import { brokersThroughBastion, rustionPolicyEffective } from "./rustion";

/**
 * Verdict lifetime. Long on purpose: the inputs are policy-shaped, not
 * session-shaped, and the operator has an explicit revalidate in the app menu
 * for the moment they change one out of band.
 */
export const CONNECT_VALIDATION_TTL_MS = 10 * 60_000;

/** Most capability paths to put in one request. */
const CAPS_BATCH = 100;

/** Key separator — not a legal character in a resource name. */
const SEP = "\u0001";

export interface ConnectVerdict {
  /** False only when we can prove one click launches nothing. */
  allowed: boolean;
  /** Why not — rendered as the disabled chip's tooltip. */
  reason?: string;
  /** Caller can't read this resource's credentials. */
  connectOnly: boolean;
  /**
   * True when an input couldn't be resolved and `allowed` is therefore an
   * assumption rather than a finding. Callers must not present an
   * indeterminate verdict as a denial.
   */
  indeterminate: boolean;
}

/** What the validator needs to know about one card. */
export interface ConnectCandidate {
  name: string;
  /** Resource type — only `server` resources can be connected to. */
  type: string;
  /** False when the operator disabled Connect for this type. */
  connectEnabled: boolean;
  /**
   * The card's profile hints. `undefined` means "this card came from a path
   * that doesn't carry them" — not "no profiles" — so the verdict stays
   * indeterminate.
   */
  hints?: ConnectProfileHint[];
  /** Asset groups the resource belongs to — a transport-tier contributor. */
  assetGroupIds: string[];
}

const ALLOW_UNKNOWN: ConnectVerdict = {
  allowed: true,
  connectOnly: false,
  indeterminate: true,
};

interface CacheEntry {
  verdict: ConnectVerdict;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();
/** In-flight validations, so two mounts of the list share one probe. */
const inflight = new Map<string, Promise<ConnectVerdict>>();

let epoch = 0;
const listeners = new Set<() => void>();

/**
 * Cache key. Includes the authorization scope (so a different token or
 * namespace never reuses a verdict) and a fingerprint of the profile hints
 * (so editing a resource's profiles invalidates its verdict immediately).
 */
function cacheKey(scope: string, c: ConnectCandidate): string {
  return `${scope}${SEP}${c.name}${SEP}${fingerprint(c)}`;
}

function fingerprint(c: ConnectCandidate): string {
  if (c.hints === undefined) return "?";
  return c.hints
    .map(
      (h) =>
        `${h.protocol}:${h.kind ?? "direct"}:${h.credential_source.kind}:${
          h.credential_source.mode ?? ""
        }`,
    )
    .join("|");
}

/** Monotonic counter, bumped by {@link revalidateConnectAccess}. */
export function connectAccessEpoch(): number {
  return epoch;
}

/** Subscribe to forced revalidations. Returns the unsubscribe function. */
export function subscribeConnectAccess(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/**
 * Drop every cached verdict and notify subscribers, so whatever is on screen
 * re-probes. Wired to the app menu's "Revalidate Connectivity" item: the
 * operator has just been granted a share or changed a transport tier and
 * doesn't want to wait out the TTL.
 */
export function revalidateConnectAccess(): void {
  cache.clear();
  inflight.clear();
  epoch += 1;
  for (const fn of listeners) fn();
}

/**
 * Drop every verdict without notifying anyone. Called on logout, on a
 * namespace switch, and on connecting to a different vault — the cached
 * answers belong to a different authorization context.
 */
export function clearConnectAccessCache(): void {
  cache.clear();
  inflight.clear();
}

/**
 * Drop the verdicts for one resource. Called after its connection profiles
 * or transport policy are edited in the detail view.
 */
export function invalidateConnectAccess(name: string): void {
  const needle = `${SEP}${name}${SEP}`;
  for (const k of cache.keys()) {
    if (k.includes(needle)) cache.delete(k);
  }
  for (const k of inflight.keys()) {
    if (k.includes(needle)) inflight.delete(k);
  }
}

/** Test hook: cached verdict count. */
export function connectAccessCacheSizeForTests(): number {
  return cache.size;
}

/**
 * The request-free part of the verdict.
 *
 * Returns a verdict when the answer needs no server round trip, `null` when
 * it does. Kept separate so the card renders the obvious cases without
 * waiting for anything.
 */
export function staticVerdict(c: ConnectCandidate): ConnectVerdict | null {
  if (c.type !== "server" || !c.connectEnabled) {
    return {
      allowed: false,
      reason: "Connect isn't available for this resource.",
      connectOnly: false,
      indeterminate: false,
    };
  }
  if (c.hints === undefined) return ALLOW_UNKNOWN;
  if (c.hints.length === 0) {
    return {
      allowed: false,
      reason:
        "No connection profile on this resource yet — open it to add one.",
      connectOnly: false,
      indeterminate: false,
    };
  }
  return null;
}

/**
 * Validate a page of cards.
 *
 * One `capabilities-self` call covers every uncached candidate; the transport
 * resolution a connect-only caller needs then runs per resource, in parallel.
 * Resolves to a verdict for every candidate — cached ones included.
 */
export async function validateConnectAccess(
  candidates: ConnectCandidate[],
  scope: string,
): Promise<Record<string, ConnectVerdict>> {
  const out: Record<string, ConnectVerdict> = {};
  const pending: ConnectCandidate[] = [];

  for (const c of candidates) {
    const stat = staticVerdict(c);
    if (stat) {
      out[c.name] = stat;
      continue;
    }
    const hit = cache.get(cacheKey(scope, c));
    if (hit && hit.expiresAt > Date.now()) {
      out[c.name] = hit.verdict;
      continue;
    }
    pending.push(c);
  }
  if (pending.length === 0) return out;

  // Candidates already being validated by another mount are awaited rather
  // than re-probed, so only the genuinely fresh ones cost a capability path.
  const fresh = pending.filter((c) => !inflight.has(cacheKey(scope, c)));
  const connectOnlyByName = await probeConnectOnly(fresh.map((c) => c.name));

  const resolved = await Promise.all(
    pending.map((c) => {
      const key = cacheKey(scope, c);
      const running = inflight.get(key);
      if (running) return running.then((v) => [c.name, v] as const);
      const p = resolveVerdict(c, connectOnlyByName[c.name])
        .then((verdict) => {
          cache.set(key, {
            verdict,
            expiresAt: Date.now() + CONNECT_VALIDATION_TTL_MS,
          });
          return verdict;
        })
        .finally(() => {
          inflight.delete(key);
        });
      inflight.set(key, p);
      return p.then((v) => [c.name, v] as const);
    }),
  );
  for (const [name, verdict] of resolved) out[name] = verdict;
  return out;
}

/**
 * Connect-only status for a batch of names, in as few calls as the server
 * will take. `undefined` for a name means "couldn't tell" — the caller treats
 * that as "assume readable", which only ever leaves the chip live.
 */
async function probeConnectOnly(
  names: string[],
): Promise<Record<string, boolean | undefined>> {
  const map: Record<string, boolean | undefined> = {};
  if (names.length === 0) return map;
  for (let i = 0; i < names.length; i += CAPS_BATCH) {
    const chunk = names.slice(i, i + CAPS_BATCH);
    const paths = chunk.map((n) => `resources/secrets/${n}/`);
    const res = await capabilitiesSelf(paths).catch(() => null);
    chunk.forEach((n, j) => {
      if (!res) {
        map[n] = undefined;
        return;
      }
      const caps = res.paths[paths[j]] ?? [];
      map[n] = !(caps.includes("read") || caps.includes("root"));
    });
  }
  return map;
}

/**
 * The part of the verdict that needs the server: whether any of the
 * resource's profiles is launchable for this caller.
 *
 * A connect-only caller may launch only a profile whose session is brokered
 * through a bastion, so this asks the resolver for the effective transport. A
 * resolver that refuses or errors leaves the verdict indeterminate — never a
 * denial, because "unknown transport" is not "direct" (see
 * `hooks/useEffectivePolicy`).
 */
async function resolveVerdict(
  c: ConnectCandidate,
  connectOnlyProbe: boolean | undefined,
): Promise<ConnectVerdict> {
  const hints = c.hints ?? [];
  if (connectOnlyProbe !== true) {
    // Credential-readable caller (or an unresolved probe, which assumes as
    // much): launchability is decided by the profiles alone, with no
    // transport question to ask.
    const allowed = hasLaunchableProfile(hints, false);
    return {
      allowed,
      reason: allowed
        ? undefined
        : "None of this resource's profiles can be launched by this client yet.",
      connectOnly: false,
      indeterminate: connectOnlyProbe === undefined,
    };
  }
  let brokered: boolean | null = null;
  try {
    brokered = brokersThroughBastion(
      await rustionPolicyEffective({
        resourceId: c.name,
        resourceType: c.type,
        assetGroupIds: c.assetGroupIds,
      }),
    );
  } catch {
    brokered = null;
  }
  if (brokered === null) {
    // Transport unknown — don't claim the brokered profiles are unusable.
    return { allowed: true, connectOnly: true, indeterminate: true };
  }
  const allowed = hasLaunchableProfile(hints, true, brokered);
  return {
    allowed,
    reason: allowed
      ? undefined
      : "You can connect through a bastion only, and none of this resource's profiles is brokered.",
    connectOnly: true,
    indeterminate: false,
  };
}
