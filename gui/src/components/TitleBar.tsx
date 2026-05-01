import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { AppMenu } from "./AppMenu";

interface TitleBarProps {
  /** Sign out — Layout owns the auth + router state. Omit on unauth routes. */
  onSignOut?: () => void;
  onBackupExport?: () => void;
  onBackupRestore?: () => void;
  onAbout: () => void;
  /** Optional override for the title text. Defaults to "BastionVault". */
  title?: string;
}

/**
 * Custom title bar replacing the OS chrome (we set
 * `decorations: false` on the window so this component is
 * responsible for drawing the title, the hamburger menu, and the
 * minimize / maximize / close buttons).
 *
 * The empty centre region is marked `data-tauri-drag-region` so
 * grabbing it drags the window. Buttons override that with their
 * own click handlers, which Tauri respects automatically.
 */
export function TitleBar({
  onSignOut,
  onBackupExport,
  onBackupRestore,
  onAbout,
  title = "BastionVault",
}: TitleBarProps) {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const w = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        setMaximized(await w.isMaximized());
        unlisten = await w.onResized(async () => {
          setMaximized(await w.isMaximized());
        });
      } catch {
        /* non-fatal — initial state read can race with window creation */
      }
    })();
    return () => {
      unlisten?.();
    };
  }, []);

  async function handleMinimize() {
    try {
      await getCurrentWindow().minimize();
    } catch {
      /* ignore */
    }
  }

  async function handleMaximizeToggle() {
    try {
      await getCurrentWindow().toggleMaximize();
    } catch {
      /* ignore */
    }
  }

  async function handleClose() {
    try {
      await getCurrentWindow().close();
    } catch {
      /* ignore */
    }
  }

  return (
    <div
      data-tauri-drag-region
      className="select-none flex items-center h-9 bg-[var(--color-surface)] border-b border-[var(--color-border)] pl-2 pr-0 shrink-0"
    >
      {/* Hamburger menu — its dropdown lives in a portal-like absolute
          inside AppMenu so it overflows the titlebar correctly. */}
      <div className="shrink-0">
        <AppMenu
          onSignOut={onSignOut}
          onBackupExport={onBackupExport}
          onBackupRestore={onBackupRestore}
          onAbout={onAbout}
        />
      </div>

      {/* Title — also a drag region so the user can grab next to the
          text to move the window. */}
      <div
        data-tauri-drag-region
        className="flex-1 flex items-center gap-2 px-3 text-xs text-[var(--color-text-muted)] truncate"
      >
        <span data-tauri-drag-region className="font-medium text-[var(--color-text)]">
          {title}
        </span>
      </div>

      {/* Window controls (minimize / maximize / close). Custom-drawn
          because `decorations: false` removed the OS-supplied ones.
          `self-stretch` so each button fills the full titlebar height —
          otherwise the hover highlight only covers the icon's bounding
          box and looks pinched compared to native chrome. */}
      <div className="flex self-stretch shrink-0">
        <button
          type="button"
          aria-label="Minimize"
          onClick={handleMinimize}
          className="w-11 flex items-center justify-center hover:bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
        >
          <svg className="w-3 h-3" viewBox="0 0 12 12" aria-hidden="true">
            <rect x="2" y="5.5" width="8" height="1" fill="currentColor" />
          </svg>
        </button>
        <button
          type="button"
          aria-label={maximized ? "Restore" : "Maximize"}
          onClick={handleMaximizeToggle}
          className="w-11 flex items-center justify-center hover:bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
        >
          {maximized ? (
            <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden="true">
              <rect x="2.5" y="3.5" width="6" height="6" />
              <path d="M4 3.5V2h6v6H8.5" />
            </svg>
          ) : (
            <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden="true">
              <rect x="2.5" y="2.5" width="7" height="7" />
            </svg>
          )}
        </button>
        <button
          type="button"
          aria-label="Close"
          onClick={handleClose}
          className="w-11 flex items-center justify-center hover:bg-[var(--color-danger)] hover:text-white text-[var(--color-text-muted)]"
        >
          <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden="true">
            <path d="M2 2 L10 10 M10 2 L2 10" />
          </svg>
        </button>
      </div>
    </div>
  );
}
