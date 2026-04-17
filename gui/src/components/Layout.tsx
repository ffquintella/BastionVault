import type { ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import { StatusBadge } from "./StatusBadge";

const navItems = [
  { path: "/dashboard", label: "Dashboard" },
  { path: "/resources", label: "Resources" },
  { path: "/secrets", label: "Secrets" },
  { path: "/users", label: "Users" },
  { path: "/approle", label: "AppRole" },
  { path: "/policies", label: "Policies" },
  { path: "/mounts", label: "Mounts" },
  { path: "/settings", label: "Settings" },
];

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const status = useVaultStore((s) => s.status);
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const reset = useVaultStore((s) => s.reset);

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
          {navItems.map((item) => {
            const active = location.pathname.startsWith(item.path);
            return (
              <Link
                key={item.path}
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
          })}
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
