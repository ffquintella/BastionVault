import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import { StatusBadge } from "./StatusBadge";
import { BackupModal } from "./BackupModal";
import { TitleBar } from "./TitleBar";
import { AboutModal } from "./AboutModal";
import * as api from "../lib/api";
import { PluginMenuSlot } from "./PluginMenuSlot";
import { usePluginSurfacesStore } from "../stores/pluginSurfacesStore";
import { useToast } from "./ui/Toast";

// localStorage key for the persisted expanded/collapsed state of the
// Admin section in the sidebar. Default (no key set) is expanded so
// new sessions see admin links immediately.
const ADMIN_OPEN_KEY = "bv.nav.adminOpen";

type NavItem = {
  path: string;
  label: string;
  /**
   * Policy names that grant access to this item. If unset (or empty)
   * the item is visible to every authenticated user. The token's
   * effective policy list is intersected with this set; a single
   * match is enough.
   */
  requires?: string[];
  /**
   * Logical mount-type that must be present on the vault for this
   * item to make sense. If set and no enabled mount has this
   * `logical_type`, the link is hidden. Use this for engine-driven
   * features (PKI, files, KV) so operators who haven't enabled the
   * corresponding mount don't see broken menu items.
   */
  requiresMountType?: string;
};

// Well-known full-admin policy names. Any of these grants the same
// nav as `root` — both the workspace engine links and the Admin
// section. Operators can assign one of these to delegate full GUI
// access without issuing a root token. See also `adminPolicies` below,
// which is kept in lockstep with this list.
const SUPER_ADMIN = ["root", "super-admin", "administrator", "admin"] as const;

// Workspace items — visible to every authenticated user, subject to
// `requires` and `requiresMountType` per item. PKI lives here (not
// under Admin) because regular users with `pki-user` need to issue
// certificates; gating is by policy, not by membership in the admin
// group.
const userNav: NavItem[] = [
  { path: "/dashboard", label: "Dashboard" },
  { path: "/resources", label: "Resources", requiresMountType: "resource" },
  { path: "/secrets", label: "Secrets", requiresMountType: "kv-v2" },
  { path: "/files", label: "Files", requiresMountType: "files" },
  { path: "/sharing", label: "Sharing" },
  {
    path: "/pki",
    label: "PKI",
    requires: [...SUPER_ADMIN, "pki-admin", "pki-user"],
    requiresMountType: "pki",
  },
  // SSH engine. Same gating shape as PKI: hidden when no `ssh/` mount
  // exists or when the token has no SSH-relevant policy. We don't ship
  // dedicated `ssh-admin` / `ssh-user` baseline policies yet — until
  // those land, the super-admin keywords gate the entry; operators who
  // already delegate via custom policies can override `requires` per
  // install.
  {
    path: "/ssh",
    label: "SSH",
    requires: [...SUPER_ADMIN],
    requiresMountType: "ssh",
  },
  // TOTP engine. Gated by the dedicated `totp-admin` / `totp-user`
  // baseline policies (registered server-side in `policy_store.rs`)
  // plus the conventional admin escalation paths. Same mount-type
  // gate as PKI / SSH — the link auto-hides when no `totp/` mount
  // exists, so an operator who hasn't mounted the engine doesn't see
  // a dead-end nav entry.
  {
    path: "/totp",
    label: "TOTP",
    requires: [...SUPER_ADMIN, "totp-admin", "totp-user"],
    requiresMountType: "totp",
  },
  // OpenLDAP / AD password-rotation engine. Same gating shape as
  // TOTP / PKI: hidden when no `openldap/` mount exists or when the
  // token has no LDAP-relevant policy.
  {
    path: "/ldap",
    label: "OpenLDAP / AD",
    requires: [...SUPER_ADMIN, "ldap-admin", "ldap-user"],
    requiresMountType: "openldap",
  },
  // Cert-Lifecycle module (Phases L5–L7). Surface alongside PKI when
  // the operator has mounted the engine. Same policy gate as PKI —
  // the lifecycle module is just a workflow layer over PKI issuance.
  {
    path: "/cert-lifecycle",
    label: "Cert Lifecycle",
    requires: [...SUPER_ADMIN, "pki-admin", "pki-user"],
    requiresMountType: "cert-lifecycle",
  },
];

// Admin features. The whole section collapses when none of the items
// pass their per-item visibility check, or when the token carries no
// admin policy at all.
const adminNav: NavItem[] = [
  { path: "/users", label: "Users" },
  { path: "/approle", label: "AppRole" },
  { path: "/groups", label: "Identity Groups" },
  { path: "/asset-groups", label: "Asset Groups" },
  { path: "/policies", label: "Policies" },
  { path: "/mounts", label: "Mounts" },
  { path: "/audit", label: "Audit" },
  { path: "/plugins", label: "Plugins" },
  { path: "/exchange", label: "Import / Export" },
  { path: "/settings", label: "Settings" },
];

// Policies that grant access to the Admin section as a whole. `root`,
// `super-admin`, `administrator`, and `admin` are well-known
// super-administrator policy-name keywords — any user assigned one of
// these sees every admin link. Operators who want to delegate just one
// admin sub-feature can grant the corresponding *-admin policy below
// without granting full admin. `pki-admin` does NOT belong here — PKI
// is a workspace feature now, not an admin one.
//
// Note: GUI visibility only. Actual API authorization is still enforced
// server-side by the policy's HCL path/capabilities rules.
const adminPolicies = new Set<string>([
  ...SUPER_ADMIN,
  "exchange-admin",
  "plugin-admin",
]);

// Match a NavItem's `requiresMountType` against the live mount table.
// Treat the kv family as interchangeable (kv ↔ kv-v2) so an operator
// running KV-v1 still sees the Secrets link.
function mountTypeMatches(required: string, available: Set<string>): boolean {
  if (available.has(required)) return true;
  if (required === "kv-v2" && available.has("kv")) return true;
  if (required === "kv" && available.has("kv-v2")) return true;
  return false;
}

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const status = useVaultStore((s) => s.status);
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const selectedNode = useVaultStore((s) => s.selectedNode);
  const policies = useAuthStore((s) => s.policies);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const reset = useVaultStore((s) => s.reset);
  const isAdmin = policies.some((p) => adminPolicies.has(p));
  const policySet = new Set(policies);

  // Plugin Extensibility v1: pull the active-surface bundle once
  // per authenticated session so plugin-contributed menus appear
  // alongside the static nav. Failures are non-fatal — if the
  // server has nothing to serve (no plugins, no surface support),
  // the store stays empty and the sidebar slots render nothing.
  const refreshPluginSurfaces = usePluginSurfacesStore((s) => s.refresh);
  const startWatchPluginSurfaces = usePluginSurfacesStore((s) => s.startWatch);
  const clearPluginSurfaces = usePluginSurfacesStore((s) => s.clear);
  useEffect(() => {
    if (!isAuthenticated) {
      clearPluginSurfaces();
      return;
    }
    void refreshPluginSurfaces().then(() => {
      // Phase 5: kick off the long-poll watcher so a server-side
      // activate / delete propagates without a manual reload. The
      // watcher is idempotent — repeated `startWatch` calls (e.g.
      // a re-render) do not stack loops.
      startWatchPluginSurfaces();
    });
  }, [
    isAuthenticated,
    refreshPluginSurfaces,
    startWatchPluginSurfaces,
    clearPluginSurfaces,
  ]);

  // Phase 5: surface a non-modal toast whenever the watcher picks up
  // a new plugin-surface version. The store flips `lastUpdate` to
  // `null` after we read it, so the toast fires once per change.
  const lastUpdate = usePluginSurfacesStore((s) => s.lastUpdate);
  const clearLastUpdate = usePluginSurfacesStore((s) => s.clearLastUpdate);
  const { toast } = useToast();
  useEffect(() => {
    if (!lastUpdate || lastUpdate.length === 0) return;
    const summary = lastUpdate
      .map(({ plugin, version }) => `${plugin} → ${version}`)
      .join(", ");
    toast(
      "info",
      `Plugin surface updated: ${summary}. Open a new page to see changes.`,
    );
    clearLastUpdate();
  }, [lastUpdate, clearLastUpdate, toast]);

  // Load the live mount-type set so per-item `requiresMountType`
  // gates work. We only ever need the set of types, not the full
  // mount records, so collapse to a Set on receive.
  const [mountTypes, setMountTypes] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (!isAuthenticated) {
      setMountTypes(new Set());
      return;
    }
    let cancelled = false;
    api
      .listMounts()
      .then((mounts) => {
        if (cancelled) return;
        setMountTypes(new Set(mounts.map((m) => m.mount_type)));
      })
      .catch(() => {
        // Non-fatal: a token without `sys/mounts` read access falls
        // back to "show everything that doesn't require a mount."
        // The route itself will still 403 if the user truly cannot
        // use it. Clearing the set means *only* mount-gated items
        // hide; items without a mount requirement remain visible.
        if (cancelled) return;
        // Permissive fallback: pretend all known engine types are
        // enabled so the user sees the links and gets a meaningful
        // error from the route handler instead of a silent hide.
        setMountTypes(
          new Set(["kv-v2", "kv", "resource", "files", "pki"]),
        );
      });
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  // Per-item visibility filter: passes both the policy gate and the
  // mount-type gate. An item with no `requires` is visible to all
  // authenticated users; an item with no `requiresMountType` is
  // unaffected by the mount table.
  function itemVisible(item: NavItem): boolean {
    if (item.requires && item.requires.length > 0) {
      const ok = item.requires.some((p) => policySet.has(p));
      if (!ok) return false;
    }
    if (item.requiresMountType) {
      if (!mountTypeMatches(item.requiresMountType, mountTypes)) return false;
    }
    return true;
  }

  const visibleUserNav = userNav.filter(itemVisible);
  const visibleAdminNav = adminNav.filter(itemVisible);

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

  // Backup modal mode + About modal flag are owned by Layout so the
  // hamburger menu (top-left of the sidebar) and any other future
  // trigger can drive them through the same state.
  const [backupMode, setBackupMode] = useState<"export" | "restore" | null>(
    null,
  );
  const [aboutOpen, setAboutOpen] = useState(false);

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

  const subtitle =
    mode === "Remote" && remoteProfile
      ? remoteProfile.name || remoteProfile.address
      : "Desktop";

  return (
    <div className="flex flex-col h-screen">
      {/* Custom title bar (replaces the OS chrome). Hamburger menu
          lives at the far left of it. */}
      <TitleBar
        onSignOut={handleSignOut}
        onBackupExport={() => setBackupMode("export")}
        onBackupRestore={() => setBackupMode("restore")}
        onAbout={() => setAboutOpen(true)}
        title={`BastionVault — ${subtitle}`}
      />

      <div className="flex flex-1 min-h-0">
      {/* Sidebar */}
      <aside className="w-56 bg-[var(--color-surface)] border-r border-[var(--color-border)] flex flex-col">
        <div className="p-4 border-b border-[var(--color-border)]">
          <h1 className="text-lg font-bold">BastionVault</h1>
          <p className="text-xs text-[var(--color-text-muted)]">{subtitle}</p>
        </div>

        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {visibleUserNav.map((item) => (
            <NavLink
              key={item.path}
              item={item}
              active={location.pathname.startsWith(item.path)}
            />
          ))}

          {/* Plugin Extensibility v1: dynamic menus contributed
              by registered plugins. `secrets` and `sharing` belong
              in the user nav; `admin` slots in below the static
              admin items. `settings` is reserved for the Settings
              sub-nav (Phase 6). */}
          <PluginMenuSlot section="secrets" />
          <PluginMenuSlot section="sharing" />

          {isAdmin && visibleAdminNav.length > 0 && (
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
                  {/* Plugin-contributed admin entries live next to
                      the static admin links. Filtered by `min_policy`
                      so non-admin users never see them. */}
                  <PluginMenuSlot section="admin" />
                  {visibleAdminNav.map((item) => (
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
            // Tooltip surfaces the discovered node when cluster
            // discovery picked one — operators sanity-check which
            // HA node they landed on without leaving the page.
            title={
              mode === "Remote" && selectedNode
                ? `Switch vault — connected via ${selectedNode.target}:${selectedNode.port} (${selectedNode.state}, ${selectedNode.rtt_ms} ms)`
                : "Switch vault"
            }
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

      {/* Backup modal — driven by the hamburger menu's Backup items */}
      <BackupModal mode={backupMode} onClose={() => setBackupMode(null)} />

      {/* About modal — driven by the hamburger menu's About entry */}
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} />
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
