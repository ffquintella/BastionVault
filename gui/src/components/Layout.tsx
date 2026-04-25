import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import { StatusBadge } from "./StatusBadge";

// localStorage key for the persisted expanded/collapsed state of the
// Admin section in the sidebar. Default (no key set) is expanded so
// new sessions see admin links immediately.
const ADMIN_OPEN_KEY = "bv.nav.adminOpen";

type NavItem = { path: string; label: string };

const userNav: NavItem[] = [
  { path: "/dashboard", label: "Dashboard" },
  { path: "/resources", label: "Resources" },
  { path: "/secrets", label: "Secrets" },
  { path: "/files", label: "Files" },
  { path: "/sharing", label: "Sharing" },
];

// Features under Admin require elevated access. The menu is hidden when the
// current token carries none of the policies in `adminPolicies` below.
const adminNav: NavItem[] = [
  { path: "/users", label: "Users" },
  { path: "/approle", label: "AppRole" },
  { path: "/groups", label: "Identity Groups" },
  { path: "/asset-groups", label: "Asset Groups" },
  { path: "/policies", label: "Policies" },
  { path: "/mounts", label: "Mounts" },
  { path: "/audit", label: "Audit" },
  { path: "/settings", label: "Settings" },
];

const adminPolicies = new Set(["root", "admin"]);

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const status = useVaultStore((s) => s.status);
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const policies = useAuthStore((s) => s.policies);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const reset = useVaultStore((s) => s.reset);
  const isAdmin = policies.some((p) => adminPolicies.has(p));

  // Persist admin section open/closed across reloads. Auto-expand when
  // the active route is under the admin section so navigating directly
  // to an admin URL doesn't leave the user looking at a collapsed menu
  // that hides the selected item.
  const [adminOpen, setAdminOpen] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(ADMIN_OPEN_KEY);
      if (stored === "0") return false;
      return true;
    } catch {
      return true;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(ADMIN_OPEN_KEY, adminOpen ? "1" : "0");
    } catch {
      /* storage unavailable — fall back to in-memory state */
    }
  }, [adminOpen]);
  const activeInAdmin = adminNav.some((item) =>
    location.pathname.startsWith(item.path),
  );
  const effectiveAdminOpen = adminOpen || activeInAdmin;

  function handleSignOut() {
    clearAuth();
    reset();
    navigate("/connect");
  }

  /**
   * Jump to the vault chooser on the Connect page.
   *
   * Does NOT clear the auth store or the vault-mode store — those
   * are the "remembered session" for the current vault. The
   * ConnectPage chooser's `openProfile` path detects whether the
   * target equals the currently-open vault (no-op round-trip) or
   * a different one (disconnect → open → try `restoreSession` → skip
   * to /dashboard if the cached token is still valid).
   *
   * Earlier revisions cleared state here and then `navigate("/connect")`
   * — but the eager-clear triggered a route-guard redirect to
   * /login against the old URL before the navigate landed, so the
   * user ended up at the login screen for the same vault. Leaving
   * the state intact and letting ConnectPage + openProfile handle
   * the transition is both the correct UX and race-free.
   */
  function handleSwitchVault() {
    navigate("/connect?choose=1");
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-56 bg-[var(--color-surface)] border-r border-[var(--color-border)] flex flex-col">
        <div className="p-4 border-b border-[var(--color-border)]">
          <h1 className="text-lg font-bold">BastionVault</h1>
          <p className="text-xs text-[var(--color-text-muted)]">
            {mode === "Remote" && remoteProfile
              ? remoteProfile.name || remoteProfile.address
              : "Desktop"}
          </p>
        </div>

        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {userNav.map((item) => (
            <NavLink
              key={item.path}
              item={item}
              active={location.pathname.startsWith(item.path)}
            />
          ))}

          {isAdmin && (
            <div className="mt-4 pt-3 border-t border-[var(--color-border)]">
              <button
                type="button"
                onClick={() => setAdminOpen((v) => !v)}
                className="w-full flex items-center justify-between px-2 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] transition-colors"
                aria-expanded={effectiveAdminOpen}
                aria-controls="nav-admin-section"
              >
                <span className="flex items-center gap-1.5">
                  <svg
                    className="w-3 h-3 shrink-0"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                  Admin
                </span>
                <span
                  className={`transition-transform text-[14px] leading-none ${
                    effectiveAdminOpen ? "rotate-90" : ""
                  }`}
                  aria-hidden="true"
                >
                  ›
                </span>
              </button>
              {effectiveAdminOpen && (
                <div
                  id="nav-admin-section"
                  className="mt-1 ml-2 pl-2 border-l border-[var(--color-border)] space-y-0.5"
                >
                  {adminNav.map((item) => (
                    <NavLink
                      key={item.path}
                      item={item}
                      active={location.pathname.startsWith(item.path)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </nav>

        <div className="p-3 border-t border-[var(--color-border)] space-y-2">
          {/* Mode indicator + Switch-vault trigger. The mode dot is
              clickable so the operator can jump back to the vault
              chooser without going through Sign Out → re-land-on-
              Connect. Clicking the row reads as "I'm done with this
              vault, show me the others." */}
          <button
            type="button"
            onClick={handleSwitchVault}
            title="Switch vault"
            aria-label="Switch vault"
            className="w-full flex items-center justify-between gap-2 rounded-md px-1.5 py-1 text-left hover:bg-[var(--color-surface-hover)] transition-colors group"
          >
            <span className="flex items-center gap-1.5 min-w-0">
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  mode === "Remote" ? "bg-blue-400" : "bg-green-400"
                }`}
              />
              <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider truncate">
                {mode === "Remote"
                  ? remoteProfile?.name || "Remote"
                  : "Local"}
              </span>
            </span>
            <span
              className="text-[10px] text-[var(--color-text-muted)] opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
              aria-hidden
            >
              switch
            </span>
          </button>

          {status && (
            <StatusBadge
              status={status.sealed ? "error" : "ok"}
              label={status.sealed ? "Sealed" : "Unsealed"}
            />
          )}
          <button
            onClick={handleSignOut}
            className="w-full text-xs text-[var(--color-text-muted)] hover:text-[var(--color-danger)] transition-colors text-left px-1"
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}

function NavLink({ item, active }: { item: NavItem; active: boolean }) {
  return (
    <Link
      to={item.path}
      className={`block px-3 py-2 rounded-lg text-sm transition-colors ${
        active
          ? "bg-[var(--color-primary)] text-white"
          : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
      }`}
    >
      {item.label}
    </Link>
  );
}
