/**
 * Credential providers at Connect, GUI side (features/self-accounts.md §6,
 * T103 Phase 4).
 *
 * Pure helpers shared by the profile editor, the host-rendered account
 * picker and the launchers. Nothing here imports a store, a router or the
 * `ui` barrel: the picker is part of the session-only bundle
 * (`session.html`), whose import graph `sessionBundle.test.tsx` pins.
 *
 * Everything a provider plugin supplies (display name, labels, login names)
 * is untrusted. It reaches the webview only after the host checked it
 * (`commands/connect_provider.rs`), and it is only ever rendered as text —
 * never as markup, never in a URL, path or command.
 */

import type { ActiveSurfaceBundle, CredentialProviderInfo, ProviderCandidate, ProviderTarget } from "./api";
import { extractError } from "./error";
import type { SessionProtocol } from "./types";

const PROVIDER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** A provider (plugin) name as the host accepts it: ASCII letters, digits,
 *  `.`, `_`, `-`, starting with a letter or digit, no `..`. */
export function isProviderName(s: unknown): s is string {
  return typeof s === "string" && PROVIDER_NAME_RE.test(s) && !s.includes("..");
}

/** The providers that can serve a profile of `protocol`. */
export function providersForProtocol(
  list: CredentialProviderInfo[],
  protocol: SessionProtocol,
): CredentialProviderInfo[] {
  return list.filter((p) => isProviderName(p.name) && p.protocols.includes(protocol));
}

/** The credential-source `<select>` value of a provider. A prefix no other
 *  credential-source kind can start with. */
export const PROVIDER_OPTION_PREFIX = "provider:";

export function providerOptionValue(name: string): string {
  return `${PROVIDER_OPTION_PREFIX}${name}`;
}

/** The provider an option value names, or null when it names none. */
export function parseProviderOption(value: string): string | null {
  if (!value.startsWith(PROVIDER_OPTION_PREFIX)) return null;
  const name = value.slice(PROVIDER_OPTION_PREFIX.length);
  return isProviderName(name) ? name : null;
}

function endsWithAccount(displayName: string): boolean {
  return /account$/i.test(displayName.trim());
}

/** What the provider's accounts are called in a sentence: "self-accounts" for
 *  the "Self-account" provider, "<display name> accounts" otherwise. */
export function accountNoun(displayName: string): string {
  const d = displayName.trim();
  return endsWithAccount(d) ? `${d.toLowerCase()}s` : `${d} accounts`;
}

/** The empty state's link text: "Add a self-account" / "Add an account". */
export function addAccountLabel(displayName: string): string {
  const d = displayName.trim();
  return endsWithAccount(d) ? `Add a ${d.toLowerCase()}` : "Add an account";
}

const OS_LABELS: Record<string, string> = {
  linux: "Linux",
  windows: "Windows",
  macos: "macOS",
  bsd: "BSD",
  unix: "Unix",
};

/** A resource OS family for a sentence; unknown values are shown as given. */
export function osLabel(os: string | null | undefined): string {
  if (!os) return "";
  return OS_LABELS[os.toLowerCase()] ?? os;
}

/** The picker's header target: `host:port`, or the start origin (and how many
 *  more origins the login may fill). */
export function describeTarget(t: ProviderTarget): string {
  if (t.kind === "host") {
    const host = t.host.includes(":") ? `[${t.host}]` : t.host;
    return `${host}:${t.port}`;
  }
  const [first, ...rest] = t.origins;
  if (rest.length === 0) return first ?? "";
  return `${first} (+${rest.length} more origin${rest.length === 1 ? "" : "s"})`;
}

/** `DOMAIN\username`, or the username alone. */
export function loginLabel(c: Pick<ProviderCandidate, "username" | "domain">): string {
  return c.domain ? `${c.domain}\\${c.username}` : c.username;
}

/** "Never used", "Used just now", "Used 3 days ago", or the date. */
export function lastUsedLabel(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "Never used";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "Never used";
  const secs = Math.max(0, Math.round((now - t) / 1000));
  if (secs < 60) return "Used just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `Used ${mins} minute${mins === 1 ? "" : "s"} ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `Used ${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `Used ${days} day${days === 1 ? "" : "s"} ago`;
  return `Used on ${new Date(t).toISOString().slice(0, 10)}`;
}

/** The picker's first-use badge (features/self-accounts.md Phase 5). */
export function firstUseBadgeLabel(t: ProviderTarget): string {
  return t.kind === "host" ? "First use on this host" : "First use on this site";
}

/** The one-line caution under the list when the selected account has never
 *  been released for this target. A hint, never a protection: an unfamiliar
 *  target is where a hostile resource definition would harvest a credential,
 *  and only the account's own target binding stops that. */
export function firstUseHint(t: ProviderTarget): string {
  const where = t.kind === "host" ? "this host" : "this site";
  return `You have not used this account on ${where} before. Check that ${describeTarget(t)} is where you mean to sign in.`;
}

/**
 * The candidate the picker preselects: the one most recently used on this
 * same target (as the provider recorded it), else the only one, else none.
 * The list order is left as the provider sent it.
 */
export function preselectedCandidate(
  candidates: Pick<ProviderCandidate, "id" | "last_used_on_target">[],
): string | null {
  let best: { id: string; at: number } | null = null;
  for (const c of candidates) {
    const at = c.last_used_on_target ? Date.parse(c.last_used_on_target) : Number.NaN;
    if (Number.isNaN(at)) continue;
    if (best === null || at > best.at) best = { id: c.id, at };
  }
  if (best) return best.id;
  return candidates.length === 1 ? candidates[0].id : null;
}

/**
 * Operator text for the server's stable refusal codes on the provider path
 * (`<reason>: …`, `bv_kernel_api::provider::reason`). Unknown errors are
 * returned unchanged. The code is kept at the end so an administrator can
 * match the server's `connect.provider.*` audit line.
 */
const PROVIDER_REASONS: Record<string, (detail: string) => string> = {
  no_entity: () =>
    "Your login has no identity of its own, so it has no personal accounts. Sign in as a user (not with a root or bare token) to use this profile.",
  not_granted: () =>
    "The credential provider this profile uses is not approved on this server, or is disabled. Ask an administrator to approve it under Plugins.",
  unsupported_protocol: () => "The credential provider this profile uses does not support this protocol.",
  no_match: () =>
    "The account you picked does not match this resource and target. Connect again and pick another, or check the account's resource types and targets in your accounts list.",
  mfa_required: () =>
    "This account can only be released after connect-time MFA. Ask the resource's owner to tick “Require MFA re-validation” on this connection profile.",
  bad_request: (d) => `The credential provider refused the request: ${d}`,
  bad_provider_output: () =>
    "The credential provider returned an account this app cannot use; nothing was opened. Tell an administrator.",
  provider_error: () =>
    "The credential provider failed. Try again; if it keeps failing, tell an administrator.",
  invalid_profile: (d) => `This connection profile cannot use a credential provider: ${d}`,
  invalid_request: (d) => d,
  connect_denied: () => "You may not connect to this resource.",
  transport_policy: () =>
    "This resource's transport policy allows sessions only through a Rustion bastion, so your account is not released to this computer.",
  brokered_requires_ssh_engine: () =>
    "This resource is brokered: every SSH login to it is minted by the SSH engine, so a personal account cannot be used. Use an SSH-engine (or default-account) profile.",
};

const REASON_RE = new RegExp(`(?:^|[\\s:])(${Object.keys(PROVIDER_REASONS).join("|")}):\\s*([\\s\\S]*)$`);

/** The refusal code in an error, or null when it carries none. */
export function providerReason(e: unknown): string | null {
  const m = extractError(e).match(REASON_RE);
  return m ? m[1] : null;
}

export function describeProviderError(e: unknown): string {
  const msg = extractError(e);
  const m = msg.match(REASON_RE);
  if (!m) return msg;
  const [, code, detail] = m;
  return `${PROVIDER_REASONS[code](detail.trim())} (${code})`;
}

const SAFE_ROUTE_RE = /^\/plugin\/[A-Za-z0-9._-]+\/[A-Za-z0-9/_-]+$/;

/**
 * The provider plugin's own management page — the first of its surface's
 * menus (else pages) that is a registered page under `/plugin/<provider>/`.
 * Null when the provider registers no surface. The route comes from the
 * plugin's surface, like its sidebar menu does, and is only ever handed to
 * the in-app router.
 */
export function providerAccountsRoute(bundle: ActiveSurfaceBundle | null, provider: string): string | null {
  if (!bundle || !isProviderName(provider)) return null;
  const entry = bundle.entries.find((e) => e.plugin === provider);
  if (!entry) return null;
  const pages = entry.surface.pages ?? [];
  const registered = new Set(pages.map((p) => p.route));
  const prefix = `/plugin/${provider}/`;
  const candidates = [...(entry.surface.menus ?? []).map((m) => m.route), ...pages.map((p) => p.route)];
  return (
    candidates.find((r) => typeof r === "string" && r.startsWith(prefix) && SAFE_ROUTE_RE.test(r) && registered.has(r)) ??
    null
  );
}
