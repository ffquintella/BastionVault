import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Input, Modal, SecretInput, useToast } from "./ui";

const MIN_PASSWORD_LEN = 16;
const DEFAULT_FILENAME_PREFIX = "bastionvault-backup";

type Mode = "export" | "restore" | null;

interface BackupModalProps {
  mode: Mode;
  onClose: () => void;
}

/**
 * Single modal that drives both Export and Restore from the File →
 * Backup menu. The mode is `null` while closed; the parent flips it
 * to `"export"` / `"restore"` when the operator clicks the menu
 * item, and back to `null` when the action completes or is
 * cancelled.
 *
 * Both flows enforce the same minimum password length (16 chars).
 * Confirm-password is required on Export; Restore only needs the
 * single password the file was created with.
 *
 * Root-policy gating is enforced inside the Tauri command
 * (`commands/backup.rs::require_root`) and that remains the security
 * boundary. `Layout` additionally hides the Backup menu items from
 * sessions whose policies lack `root`, so this modal is normally
 * unreachable for them: no auth backend can mint a root token, which
 * made the old "open it for everyone and let the toast explain"
 * behaviour a guaranteed dead end after typing a 16-char password
 * twice. Nothing here leaks that fact — the caller's own policy set
 * is already client-side state.
 */
export function BackupModal({ mode, onClose }: BackupModalProps) {
  const { toast } = useToast();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [restorePath, setRestorePath] = useState("");
  const [busy, setBusy] = useState(false);

  // Reset every time the modal opens / changes mode so an aborted
  // Export doesn't leak its password into a follow-up Restore.
  useEffect(() => {
    if (mode !== null) {
      setPassword("");
      setConfirm("");
      setRestorePath("");
      setBusy(false);
    }
  }, [mode]);

  const passwordOk = password.length >= MIN_PASSWORD_LEN;
  const confirmOk = mode !== "export" || password === confirm;
  const canSubmit = useMemo(() => {
    if (busy) return false;
    if (!passwordOk) return false;
    if (mode === "export") return confirmOk;
    if (mode === "restore") return restorePath.length > 0 && confirmOk;
    return false;
  }, [busy, passwordOk, confirmOk, mode, restorePath]);

  async function pickRestoreFile() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const picked = await open({
        title: "Select backup file to restore",
        multiple: false,
        directory: false,
        filters: [
          { name: "BastionVault Backup", extensions: ["bvbk", "bvbkp"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof picked === "string" && picked.length > 0) {
        setRestorePath(picked);
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleExport() {
    setBusy(true);
    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const ts = new Date()
        .toISOString()
        .replace(/[:.]/g, "-")
        .replace(/Z$/, "");
      const target = await save({
        title: "Save backup file",
        defaultPath: `${DEFAULT_FILENAME_PREFIX}-${ts}.bvbkp`,
        filters: [
          { name: "BastionVault Backup", extensions: ["bvbkp"] },
        ],
      });
      if (!target) {
        setBusy(false);
        return;
      }
      const entries = await invoke<number>("backup_export", {
        path: target,
        password,
      });
      toast(
        "success",
        `Backup written — ${entries} entries → ${target}`,
      );
      onClose();
    } catch (e: unknown) {
      toast("error", extractError(e));
      setBusy(false);
    }
  }

  async function handleRestore() {
    setBusy(true);
    try {
      const restored = await invoke<number>("backup_restore", {
        path: restorePath,
        password,
      });
      toast(
        "success",
        `Restore complete — ${restored} entries imported`,
      );
      onClose();
    } catch (e: unknown) {
      toast("error", extractError(e));
      setBusy(false);
    }
  }

  if (mode === null) return null;

  const title = mode === "export" ? "Export full backup" : "Restore from backup";
  const submitLabel = mode === "export" ? "Export…" : "Restore";
  const onSubmit = mode === "export" ? handleExport : handleRestore;

  return (
    <Modal
      open={mode !== null}
      onClose={() => {
        if (!busy) onClose();
      }}
      title={title}
      size="md"
      actions={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={!canSubmit}>
            {busy ? "Working…" : submitLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {mode === "export" ? (
          <p className="text-sm text-[var(--color-text-muted)]">
            Writes a password-encrypted snapshot of the entire vault to
            disk. Requires the <code>root</code> policy. Keep this file
            <strong> and</strong> the password somewhere safe — losing
            either makes the backup unusable.
          </p>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            Imports a password-encrypted backup file into the open
            vault. Requires the <code>root</code> policy. Existing
            entries with the same key will be overwritten.
          </p>
        )}

        {mode === "restore" && (
          <div className="flex items-end gap-2">
            <Input
              label="Backup file"
              value={restorePath}
              onChange={(e) => setRestorePath(e.target.value)}
              placeholder="Click Browse to pick a file"
              readOnly
            />
            <Button variant="secondary" onClick={pickRestoreFile} disabled={busy}>
              Browse…
            </Button>
          </div>
        )}

        <SecretInput
          label="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="At least 16 characters"
          autoFocus={mode === "export"}
          hint={
            password.length === 0
              ? `Minimum ${MIN_PASSWORD_LEN} characters.`
              : passwordOk
                ? `${password.length} characters — ok.`
                : `${password.length} / ${MIN_PASSWORD_LEN} characters.`
          }
        />

        {mode === "export" && (
          <SecretInput
            label="Confirm password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Type it again"
            hint={
              confirm.length === 0
                ? "Re-enter the password to catch typos."
                : confirmOk
                  ? "Matches — ok."
                  : "Doesn't match the password above."
            }
          />
        )}
      </div>
    </Modal>
  );
}

function extractError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object" && "message" in e) {
    const m = (e as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return JSON.stringify(e);
}
