import { useState } from "react";
import { Button, Input, Modal } from "./ui";
import * as api from "../lib/api";
import type {
  VaultMode,
  VaultStatus,
  NodeSealResult,
  RemoteProfile,
} from "../lib/types";
import { extractError } from "../lib/error";

interface UnsealModalProps {
  open: boolean;
  onClose: () => void;
  /** Called with the post-unseal status. The vault may still be sealed
   *  in remote t-of-n setups that need more shares — the caller decides
   *  whether to keep the dialog open. */
  onUnsealed: (status: VaultStatus) => void;
  mode: VaultMode;
  /** Explicit remote profile to unseal against, used by the Connect
   *  screen when the connection itself failed because every node is
   *  sealed (so no profile is stored in AppState). When set, the share
   *  is fanned out against this profile directly via
   *  `remote_unseal_profile` instead of the connected `unseal_vault`
   *  path. Implies remote mode. */
  profile?: RemoteProfile;
}

/**
 * Operator unseal dialog. Embedded vaults cache the unseal key on the
 * device, so the field is optional and an empty submit reuses the
 * stored key — a one-click unseal for the operator who set the machine
 * up. Remote vaults have no local cache, so the hex key is required;
 * the share is fanned out to every node of the connected cluster (seal
 * state is per-node), and the per-node outcome is shown below the field.
 */
export function UnsealModal({ open, onClose, onUnsealed, mode, profile }: UnsealModalProps) {
  const [key, setKey] = useState("");
  const [unsealing, setUnsealing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes] = useState<NodeSealResult[]>([]);
  // An explicit profile always means a remote, not-yet-connected cluster.
  const remote = mode === "Remote" || profile !== undefined;

  function reset() {
    setKey("");
    setError(null);
    setNodes([]);
    setUnsealing(false);
  }

  function handleClose() {
    if (unsealing) return;
    reset();
    onClose();
  }

  async function handleUnseal() {
    const trimmed = key.trim();
    if (remote && !trimmed) {
      setError("An unseal key is required to unseal a remote vault.");
      return;
    }
    setUnsealing(true);
    setError(null);
    try {
      const outcome = profile
        ? await api.remoteUnsealProfile(profile, trimmed)
        : await api.unsealVault(trimmed || undefined);
      setNodes(outcome.nodes);
      onUnsealed(outcome.status);
      if (!outcome.status.sealed) {
        setKey("");
        setError(null);
      } else {
        // Multi-share / multi-node progress: clear the field so the
        // operator can paste the next share without reselecting the old.
        setKey("");
        setError("Vault is still sealed — submit the next unseal key share.");
      }
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setUnsealing(false);
    }
  }

  const cluster = nodes.length > 1;

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Unseal vault"
      size="sm"
      actions={
        <>
          <Button variant="ghost" onClick={handleClose} disabled={unsealing}>
            Cancel
          </Button>
          <Button onClick={handleUnseal} loading={unsealing}>
            Unseal
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-[var(--color-text-muted)]">
          {remote
            ? "Paste an unseal key share to unlock the cluster's barrier. The share is sent to every node; multi-share setups need each share submitted in turn."
            : "Unlock the barrier so the vault can serve secrets again."}
        </p>
        <Input
          label={remote ? "Unseal key (hex)" : "Unseal key (hex) — optional"}
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder={remote ? "Paste your unseal key" : "Leave blank to use the key stored on this device"}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleUnseal();
          }}
          error={error ?? undefined}
          hint={
            remote
              ? undefined
              : "This device has the unseal key cached; leave the field blank to use it."
          }
        />

        {cluster && (
          <div className="space-y-1">
            <p className="text-xs font-medium text-[var(--color-text-muted)]">
              Cluster nodes ({nodes.filter((n) => n.error === null).length}/{nodes.length} reached)
            </p>
            <ul className="space-y-1">
              {nodes.map((n) => (
                <li
                  key={n.address}
                  className="flex items-center justify-between gap-2 text-xs rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1"
                >
                  <span className="min-w-0 truncate font-mono" title={n.address}>
                    {n.address}
                  </span>
                  <NodeStatus node={n} />
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Modal>
  );
}

function NodeStatus({ node }: { node: NodeSealResult }) {
  if (node.error) {
    return (
      <span className="shrink-0 text-red-400" title={node.error}>
        error
      </span>
    );
  }
  if (node.sealed === false) {
    return <span className="shrink-0 text-green-400">unsealed</span>;
  }
  // Still sealed — show Shamir progress when the node reported it.
  const progress =
    node.progress !== null && node.threshold !== null
      ? ` (${node.progress}/${node.threshold})`
      : "";
  return (
    <span className="shrink-0 text-amber-400">
      sealed{progress}
    </span>
  );
}
