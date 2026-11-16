import { useCallback, useState } from "react";
import { Button, MaskedValue, Modal, useToast } from "../ui";

/**
 * A secret the vault returns exactly once (an OIDC client secret, a RADIUS or
 * LDAP passcode, a shared secret just set). It lives only in the state of the
 * component that received it, and only until this modal closes.
 */
export interface OneTimeSecret {
  title: string;
  /** What the value is ("Client secret", "Passcode"). */
  label: string;
  value: string;
  /** Non-secret context shown under the value (login, bind DN, expiry). */
  details?: [string, string][];
  /** Why it cannot be read again and what to do with it now. */
  notice: string;
}

/** Holds one secret; `clear` drops the only reference the page keeps. */
export function useOneTimeSecret() {
  const [secret, setSecret] = useState<OneTimeSecret | null>(null);
  const show = useCallback((s: OneTimeSecret) => setSecret(s), []);
  const clear = useCallback(() => setSecret(null), []);
  return { secret, show, clear };
}

export function OneTimeSecretModal({ secret, onClose }: { secret: OneTimeSecret | null; onClose: () => void }) {
  const { toast } = useToast();
  if (!secret) return null;

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast("success", "Copied to clipboard");
    } catch {
      toast("error", "Could not copy to clipboard");
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={secret.title}
      size="md"
      actions={
        <>
          <Button variant="secondary" onClick={() => void copy(secret.value)}>
            Copy {secret.label.toLowerCase()}
          </Button>
          <Button onClick={onClose}>Done</Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="rounded-md border border-[var(--color-warning)] bg-[var(--color-warning)]/10 p-3 text-xs" role="alert">
          {secret.notice} It is cleared from this window when you close this dialog.
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="col-span-2 min-w-0">
            <div className="text-xs font-medium text-[var(--color-text-muted)] mb-1">{secret.label}</div>
            <div className="font-mono min-w-0" data-testid="one-time-secret-value">
              <MaskedValue value={secret.value} />
            </div>
          </div>
          {(secret.details ?? []).map(([k, v]) => (
            <div key={k} className="col-span-2 min-w-0">
              <div className="text-xs text-[var(--color-text-muted)]">{k}</div>
              <div className="font-mono text-xs truncate" title={v}>
                {v}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Modal>
  );
}
