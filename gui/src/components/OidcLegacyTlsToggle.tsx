// The per-provider opt-in to the legacy TLS 1.2 CBC client (T551,
// features/legacy-tls-cbc.md). It can be switched on and off at any time;
// the vault refuses "on" when it was built without the client, and this
// control says so up front when the vault reports it.

export const LEGACY_TLS_NOT_BUILT_MARKER = "built without the legacy TLS 1.2 CBC client";

/** Whether a vault error is the "feature compiled out" refusal. */
export function isLegacyTlsUnavailableError(message: string | null | undefined): boolean {
  return !!message && message.includes(LEGACY_TLS_NOT_BUILT_MARKER);
}

export function OidcLegacyTlsToggle({
  checked,
  onChange,
  available,
  error,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  /** From the vault's config read: `false` = compiled out, `null` = not reported. */
  available: boolean | null | undefined;
  /** The last save error, if any. */
  error?: string | null;
}) {
  const unavailable = available === false || isLegacyTlsUnavailableError(error);
  // Turning it off is always allowed, so a stored "on" can be cleared even
  // from a build that cannot honour it.
  const disabled = unavailable && !checked;
  return (
    <div className="col-span-2 min-w-0 space-y-2" data-testid="oidc-legacy-tls">
      <label className="flex items-center gap-2 cursor-pointer select-none text-sm">
        <input
          type="checkbox"
          role="switch"
          aria-checked={checked}
          aria-describedby="oidc-legacy-tls-warning"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          className="accent-[var(--color-warning)]"
        />
        <span className="font-medium text-[var(--color-text)]">
          Use legacy TLS 1.2 (CBC) for this provider
        </span>
      </label>
      <p
        id="oidc-legacy-tls-warning"
        className={`text-xs min-w-0 break-words ${
          checked ? "text-[var(--color-warning)]" : "text-[var(--color-text-muted)]"
        }`}
      >
        Only for an IdP that cannot be upgraded and offers nothing but TLS 1.2
        with AES-CBC cipher suites. When on, the vault reaches this provider —
        discovery, signing keys and the token exchange of this mount only — with
        CBC + HMAC suites, which are weaker than the GCM / ChaCha20 suites every
        other connection uses. Each use is logged as a security warning. Turn it
        off once the IdP supports TLS 1.3 or GCM.
      </p>
      {unavailable && (
        <p
          role="alert"
          className="text-xs min-w-0 break-words rounded-lg border border-[var(--color-danger)] px-3 py-2 text-[var(--color-danger)]"
        >
          This vault was built without the legacy TLS client (build feature
          <code className="mx-1">oidc_legacy_tls</code>), so this option cannot be
          turned on here.
          {checked && " It is stored as on and every sign-in through this provider fails until you turn it off or use a vault built with the feature."}
        </p>
      )}
    </div>
  );
}
