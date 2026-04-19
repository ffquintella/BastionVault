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
            <>
              <button
                type="button"
                onClick={() => setAdminOpen((v) => !v)}
                className="mt-3 mb-0.5 w-full flex items-center justify-between px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
                aria-expanded={effectiveAdminOpen}
                aria-controls="nav-admin-section"
              >
                <span>Admin</span>
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
                <div id="nav-admin-section" className="space-y-0.5">
                  {adminNav.map((item) => (
                    <NavLink
                      key={item.path}
                      item={item}
                      active={location.pathname.startsWith(item.path)}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </nav>

        <div className="p-3 border-t border-[var(--color-border)] space-y-2">
          {/* Mode indicator */}
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                mode === "Remote" ? "bg-blue-400" : "bg-green-400"
              }`}
            />
            <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">
              {mode === "Remote" ? "Remote" : "Local"}
            </span>
          </div>

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
