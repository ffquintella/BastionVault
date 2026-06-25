import { useNavigate } from "react-router-dom";

interface QuickActionsProps {
  sealed: boolean | null;
  /** Open the seal-confirmation dialog. */
  onSeal: () => void;
  /** Open the unseal dialog. */
  onUnseal: () => void;
}

/** Action strip: the Seal/Unseal control (preserved from the old
 *  dashboard) plus deep-links into the most common workflows. */
export function QuickActions({ sealed, onSeal, onUnseal }: QuickActionsProps) {
  const navigate = useNavigate();
  const link =
    "px-3 py-1.5 rounded-lg text-sm border border-[var(--color-border)] bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)] transition-colors";

  return (
    <div className="flex flex-wrap gap-2">
      <button onClick={() => navigate("/secrets")} className={link}>
        Secrets
      </button>
      <button onClick={() => navigate("/pki")} className={link}>
        Issue certificate
      </button>
      <button onClick={() => navigate("/audit")} className={link}>
        Audit log
      </button>
      <button onClick={() => navigate("/policies")} className={link}>
        Policies
      </button>
      {sealed === true ? (
        <button
          onClick={onUnseal}
          className="ml-auto px-3 py-1.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-sm hover:bg-green-500/30 transition-colors"
        >
          Unseal Vault
        </button>
      ) : (
        <button
          onClick={onSeal}
          disabled={sealed === null}
          className="ml-auto px-3 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-sm hover:bg-red-500/30 disabled:opacity-50 transition-colors"
        >
          Seal Vault
        </button>
      )}
    </div>
  );
}
