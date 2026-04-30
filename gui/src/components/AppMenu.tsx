import { useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useToast } from "./ui";

const REPO_URL = "https://github.com/ffquintella/BastionVault";

interface AppMenuProps {
  /**
   * Sign out — Layout owns the auth/router reset. Omit on unauth
   * routes (Connect / Login / Init) and the item is hidden.
   */
  onSignOut?: () => void;
  /** Backup → Export. Auth-gated; omit to hide. */
  onBackupExport?: () => void;
  /** Backup → Restore. Auth-gated; omit to hide. */
  onBackupRestore?: () => void;
  /** About modal. Always shown. */
  onAbout: () => void;
}

/**
 * Hamburger-button dropdown menu. Replaces the native OS menubar so
 * the app looks the same on Windows / macOS / Linux and the menu
 * lives where users of modern apps (Termius, VS Code, GitHub
 * Desktop, …) expect it: top-left corner, behind a hamburger icon.
 *
 * Items are grouped into sections separated by dividers — same
 * structure the previous native menu had:
 *   File: Backup ▸ (Export / Restore), Sign Out, Quit
 *   App:  Reload, Toggle Fullscreen
 *   About: About BastionVault, Open Repository
 */
export function AppMenu({
  onSignOut,
  onBackupExport,
  onBackupRestore,
  onAbout,
}: AppMenuProps) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [submenu, setSubmenu] = useState<"backup" | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close on click-outside / Escape.
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (
        rootRef.current &&
        !rootRef.current.contains(e.target as Node) &&
        !buttonRef.current?.contains(e.target as Node)
      ) {
        setOpen(false);
        setSubmenu(null);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        setSubmenu(null);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function pick(action: () => void) {
    setOpen(false);
    setSubmenu(null);
    action();
  }

  async function handleReload() {
    window.location.reload();
  }

  async function handleToggleFullscreen() {
    try {
      const w = getCurrentWindow();
      const isFs = await w.isFullscreen();
      await w.setFullscreen(!isFs);
    } catch (e) {
      toast("error", `Toggle fullscreen failed: ${String(e)}`);
    }
  }

  async function handleOpenRepo() {
    try {
      const { open: shellOpen } = await import("@tauri-apps/plugin-shell");
      await shellOpen(REPO_URL);
    } catch (e) {
      toast("error", `Open URL failed: ${String(e)}`);
    }
  }

  async function handleQuit() {
    try {
      // Closing the main window terminates the app — Tauri exits
      // when the last window closes. No need for a separate
      // process-exit plugin.
      await getCurrentWindow().close();
    } catch (e) {
      toast("error", `Quit failed: ${String(e)}`);
    }
  }

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-label="Open menu"
        aria-expanded={open}
        onClick={() => {
          setOpen((v) => !v);
          setSubmenu(null);
        }}
        className="flex items-center justify-center w-8 h-8 rounded-md hover:bg-[var(--color-surface-hover)] transition-colors text-[var(--color-text)]"
      >
        <svg
          className="w-5 h-5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <line x1="3" y1="6" x2="21" y2="6" />
          <line x1="3" y1="12" x2="21" y2="12" />
          <line x1="3" y1="18" x2="21" y2="18" />
        </svg>
      </button>

      {open && (
        <div
          ref={rootRef}
          role="menu"
          className="absolute top-full left-0 mt-1 z-50 min-w-56 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] shadow-xl py-1 text-sm"
        >
          {/* File section — auth-gated items only render when the
              caller supplied a handler. Unauth routes (Connect /
              Login / Init) get only the Application + About + Quit
              entries below. */}
          {(onBackupExport || onBackupRestore) && (
            <>
              <div
                role="menuitem"
                tabIndex={0}
                onMouseEnter={() => setSubmenu("backup")}
                onClick={() =>
                  setSubmenu(submenu === "backup" ? null : "backup")
                }
                className="flex items-center justify-between px-3 py-1.5 hover:bg-[var(--color-surface-hover)] cursor-pointer"
              >
                <span>Backup</span>
                <svg
                  className="w-3 h-3 text-[var(--color-text-muted)]"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </div>
              {submenu === "backup" && (
                <div
                  role="menu"
                  className="absolute top-1 left-full ml-1 min-w-44 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] shadow-xl py-1"
                >
                  {onBackupExport && (
                    <MenuButton
                      onClick={() => pick(onBackupExport)}
                      label="Export…"
                    />
                  )}
                  {onBackupRestore && (
                    <MenuButton
                      onClick={() => pick(onBackupRestore)}
                      label="Restore…"
                    />
                  )}
                </div>
              )}
            </>
          )}
          {onSignOut && (
            <MenuButton onClick={() => pick(onSignOut)} label="Sign Out" />
          )}
          {(onSignOut || onBackupExport || onBackupRestore) && <Divider />}

          {/* Application section */}
          <MenuButton
            onClick={() => pick(handleReload)}
            label="Reload"
            shortcut="Ctrl+R"
          />
          <MenuButton
            onClick={() => pick(handleToggleFullscreen)}
            label="Toggle Fullscreen"
            shortcut="F11"
          />
          <Divider />

          {/* About section */}
          <MenuButton onClick={() => pick(onAbout)} label="About BastionVault" />
          <MenuButton onClick={() => pick(handleOpenRepo)} label="Open GitHub Repository" />
          <Divider />

          <MenuButton
            onClick={() => pick(handleQuit)}
            label="Quit"
            shortcut="Ctrl+Q"
          />
        </div>
      )}
    </div>
  );
}

function MenuButton({
  onClick,
  label,
  shortcut,
}: {
  onClick: () => void;
  label: string;
  shortcut?: string;
}) {
  return (
    <button
      role="menuitem"
      type="button"
      onClick={onClick}
      className="w-full flex items-center justify-between px-3 py-1.5 hover:bg-[var(--color-surface-hover)] text-left"
    >
      <span>{label}</span>
      {shortcut && (
        <span className="text-xs text-[var(--color-text-muted)] ml-4">{shortcut}</span>
      )}
    </button>
  );
}

function Divider() {
  return <div className="border-t border-[var(--color-border)] my-1" />;
}
