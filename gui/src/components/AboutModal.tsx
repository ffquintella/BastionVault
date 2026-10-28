import { useEffect, useState } from "react";
import { Button, Modal } from "./ui";
import { getServerInfo, type ServerInfo } from "../lib/api";

interface AboutModalProps {
  open: boolean;
  onClose: () => void;
}

const REPO_URL = "https://github.com/ffquintella/BastionVault";

/**
 * Lightweight About dialog — name, version, repo link. Mirrors what
 * the native PredefinedMenuItem::about used to show before we
 * replaced the native menubar with the in-app hamburger menu.
 */
export function AboutModal({ open, onClose }: AboutModalProps) {
  // VITE_APP_VERSION is wired in vite.config.ts from package.json;
  // fall back gracefully so a missing inject doesn't render "undefined".
  const version =
    (import.meta.env?.VITE_APP_VERSION as string | undefined) ?? "dev";

  // Server facts are best-effort: the About dialog is also reachable from
  // the connect/login screens, where no backend is attached yet.
  const [server, setServer] = useState<ServerInfo | null>(null);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    getServerInfo()
      .then((info) => !cancelled && setServer(info?.version ? info : null))
      .catch(() => !cancelled && setServer(null));
    return () => {
      cancelled = true;
    };
  }, [open]);

  async function openRepo() {
    try {
      const { open: shellOpen } = await import("@tauri-apps/plugin-shell");
      await shellOpen(REPO_URL);
    } catch {
      /* ignore — the link below is also clickable */
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="About BastionVault"
      size="sm"
      actions={<Button onClick={onClose}>Close</Button>}
    >
      <div className="space-y-3 text-sm">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-md bg-[var(--color-primary)]/10 border border-[var(--color-border)] flex items-center justify-center">
            <span className="text-xl font-bold">BV</span>
          </div>
          <div>
            <div className="font-semibold text-base">BastionVault</div>
            <div className="text-[var(--color-text-muted)]">Version {version}</div>
          </div>
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
          <dt className="text-[var(--color-text-muted)]">Client version</dt>
          <dd className="font-mono min-w-0 truncate">{version}</dd>
          {server && (
            <>
              <dt className="text-[var(--color-text-muted)]">Server version</dt>
              <dd className="font-mono min-w-0 truncate">{server.version}</dd>
              <dt className="text-[var(--color-text-muted)]">Connection</dt>
              <dd className="min-w-0 truncate">
                {server.connection_kind === "embedded" ? "Embedded (this process)" : server.endpoint}
              </dd>
            </>
          )}
        </dl>
        <p className="text-[var(--color-text-muted)]">
          Identity-based secrets management with post-quantum cryptography.
        </p>
        <button
          type="button"
          onClick={openRepo}
          className="text-[var(--color-primary)] hover:underline break-all"
        >
          {REPO_URL}
        </button>
      </div>
    </Modal>
  );
}
