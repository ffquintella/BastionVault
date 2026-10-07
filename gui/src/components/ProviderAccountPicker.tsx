/**
 * The credential-provider account picker (features/self-accounts.md §6, T103
 * Phase 4).
 *
 * When a connection profile's credential source is `provider`, Connect asks
 * the host for the operator's accounts that match the resource, protocol and
 * target (`connect_provider_candidates`, metadata only) and shows them here.
 * The operator picks one; the launcher then runs the connect-time MFA gate
 * and opens the session with the picked `provider_account_id`
 * (`lib/connectFlow.ts`). Cancelling here costs no factor ceremony.
 *
 * This picker is **host-rendered** on purpose: a plugin-drawn picker inside
 * the Connect flow could imitate host chrome. It renders only metadata the
 * host checked (`commands/connect_provider.rs`), always as React text
 * children — never as markup, never in a URL — and truncates what is long.
 */

import { useEffect, useRef, useState } from "react";

import * as api from "../lib/api";
import {
  accountNoun,
  addAccountLabel,
  describeProviderError,
  describeTarget,
  firstUseBadgeLabel,
  firstUseHint,
  lastUsedLabel,
  loginLabel,
  osLabel,
  preselectedCandidate,
} from "../lib/credentialProviders";
import type { ConnectionProfile } from "../lib/types";
// Not the `./ui` barrel: this file is in the session-only bundle
// (session.html, T110) through the ⌘K palette and layout restore.
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Modal } from "./ui/Modal";

/** Resolves a provider to the handler that opens its account-management page,
 *  or null when it registers none (or this window cannot show it). */
export type ProviderAccountsLink = (provider: string) => (() => void) | null;

export type PendingProviderPick = {
  resourceName: string;
  profileName: string;
  data: api.ProviderCandidates;
  /** The picked account id, or null when the operator cancelled. */
  resolve: (accountId: string | null) => void;
};

export function ProviderAccountPicker({
  pending,
  accountsLink,
  now,
}: {
  pending: PendingProviderPick | null;
  accountsLink?: ProviderAccountsLink;
  /** Clock for the "last used" labels; tests pin it. */
  now?: number;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const listRef = useRef<HTMLUListElement>(null);

  // The account last used on this same target is preselected (the provider
  // remembers it, so it follows the operator across devices), else a single
  // candidate; otherwise the operator chooses.
  useEffect(() => {
    if (!pending) return;
    setSelected(preselectedCandidate(pending.data.candidates));
    const t = setTimeout(() => listRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [pending]);

  if (!pending) return null;

  const { data } = pending;
  const candidates = data.candidates;
  const cancel = () => pending.resolve(null);
  const connect = () => {
    if (selected !== null && candidates.some((c) => c.id === selected)) pending.resolve(selected);
  };
  // Arrow keys move the selection, Enter connects — as in the ⌘K palette.
  const onKeyDown = (e: React.KeyboardEvent<HTMLUListElement>) => {
    if (candidates.length === 0) return;
    const idx = candidates.findIndex((c) => c.id === selected);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelected(candidates[Math.min(candidates.length - 1, idx + 1)].id);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected(candidates[idx <= 0 ? 0 : idx - 1].id);
    } else if (e.key === "Enter") {
      e.preventDefault();
      connect();
    }
  };
  const openAccounts = accountsLink?.(data.provider) ?? null;
  const os = osLabel(data.os_type);
  const activeIndex = candidates.findIndex((c) => c.id === selected);
  const firstUseSelected = activeIndex >= 0 && candidates[activeIndex].first_use_on_target === true;

  return (
    <Modal
      open
      onClose={cancel}
      size="md"
      title="Choose an account"
      actions={
        <>
          <Button variant="ghost" onClick={cancel}>
            Cancel
          </Button>
          <Button onClick={connect} disabled={activeIndex < 0}>
            Connect
          </Button>
        </>
      }
    >
      <div className="space-y-3 min-w-0">
        <p className="text-sm min-w-0">
          <span className="text-[var(--color-text-muted)]">Connecting to </span>
          <strong className="font-mono break-all" data-testid="provider-picker-target">
            {describeTarget(data.target)}
          </strong>
        </p>
        <p className="text-xs text-[var(--color-text-muted)] truncate" title={`${data.display_name} · ${pending.profileName} on ${pending.resourceName}`}>
          {data.display_name} · {pending.profileName} on {pending.resourceName}
        </p>

        {candidates.length === 0 ? (
          <div role="status" className="rounded-md border border-[var(--color-border)] p-3 text-sm space-y-2 min-w-0">
            <p className="break-words">
              You have no {accountNoun(data.display_name)} for <code>{data.resource_type || "this resource type"}</code>
              {os ? ` (${os})` : ""} on this target.
            </p>
            {openAccounts && (
              <button
                type="button"
                className="text-sm text-[var(--color-primary)] underline"
                onClick={() => {
                  cancel();
                  openAccounts();
                }}
              >
                {addAccountLabel(data.display_name)}
              </button>
            )}
          </div>
        ) : (
          <ul
            ref={listRef}
            role="listbox"
            tabIndex={0}
            aria-label={`${data.display_name} accounts`}
            aria-activedescendant={activeIndex >= 0 ? `provider-account-${activeIndex}` : undefined}
            onKeyDown={onKeyDown}
            className="max-h-72 overflow-y-auto rounded-md border border-[var(--color-border)] divide-y divide-[var(--color-border)] outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
          >
            {candidates.map((c, i) => {
              const isSelected = c.id === selected;
              const login = loginLabel(c);
              return (
                <li
                  key={c.id}
                  id={`provider-account-${i}`}
                  role="option"
                  aria-selected={isSelected}
                  onClick={() => setSelected(c.id)}
                  onDoubleClick={() => pending.resolve(c.id)}
                  className={`px-3 py-2 cursor-pointer flex items-center gap-3 min-w-0 ${
                    isSelected ? "bg-[var(--color-surface-hover)]" : ""
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate" title={c.label}>
                      {c.label}
                    </div>
                    <div className="text-xs font-mono text-[var(--color-text-muted)] truncate" title={login}>
                      {login}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {c.first_use_on_target === true && (
                      <Badge variant="warning" label={firstUseBadgeLabel(data.target)} />
                    )}
                    <Badge label={c.secret_kind === "ssh-key" ? "Key" : "Password"} />
                    {c.has_totp && <Badge variant="info" label="TOTP" />}
                  </div>
                  <span className="text-xs text-[var(--color-text-muted)] shrink-0 w-32 text-right truncate">
                    {lastUsedLabel(c.last_used_at, now)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}

        {firstUseSelected && (
          <p className="text-xs text-[var(--color-warning)] break-words" data-testid="provider-first-use-hint">
            {firstUseHint(data.target)}
          </p>
        )}

        {data.hidden > 0 && (
          <p className="text-xs text-[var(--color-text-muted)]">
            {data.hidden} account{data.hidden === 1 ? " was" : "s were"} not shown: {data.hidden === 1 ? "its" : "their"}{" "}
            details contain characters this window does not display.
          </p>
        )}
      </div>
    </Modal>
  );
}

/**
 * The picker, packaged for a launcher component:
 *
 * ```tsx
 * const { pickProviderAccount, providerPicker } = useProviderAccountPicker(link);
 * const id = await pickProviderAccount(resourceName, profile); // null = cancelled
 * return <>{…}{providerPicker}</>;
 * ```
 *
 * The account list is fetched before the modal opens, so a refusal (an
 * unapproved provider, a login with no identity, …) surfaces as a thrown
 * error with operator text instead of an empty picker.
 */
export function useProviderAccountPicker(accountsLink?: ProviderAccountsLink) {
  const [pending, setPending] = useState<PendingProviderPick | null>(null);

  const pickProviderAccount = async (
    resourceName: string,
    profile: Pick<ConnectionProfile, "id" | "name">,
  ): Promise<string | null> => {
    let data: api.ProviderCandidates;
    try {
      data = await api.connectProviderCandidates(resourceName, profile.id);
    } catch (e) {
      throw new Error(describeProviderError(e));
    }
    return new Promise<string | null>((resolve) => {
      setPending({
        resourceName,
        profileName: profile.name,
        data,
        resolve: (accountId) => {
          setPending(null);
          resolve(accountId);
        },
      });
    });
  };

  return {
    pickProviderAccount,
    providerPicker: <ProviderAccountPicker pending={pending} accountsLink={accountsLink} />,
  };
}
