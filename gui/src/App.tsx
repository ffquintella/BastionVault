import { Suspense, lazy, useEffect, type ComponentType } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router";
import { ConnectPage } from "./routes/ConnectPage";
import { fido2SubmitPin } from "./lib/api";
import { InitPage } from "./routes/InitPage";
import { LoginPage } from "./routes/LoginPage";
import { SurfaceRouter } from "./components/surface/SurfaceRouter";
import { useAuthStore } from "./stores/authStore";
import { useVaultStore } from "./stores/vaultStore";
import { ToastProvider } from "./components/ui";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConnectPalette } from "./components/ConnectPalette";
import { useProviderAccountsLink } from "./hooks/useCredentialProviders";
import { ServerInfoModal } from "./components/ServerInfoModal";
import { SessionMonitor } from "./components/SessionMonitor";
import { McpPromptHost } from "./components/McpPromptHost";

// Route pages are code-split: each becomes its own chunk, fetched on first
// visit, so the entry bundle holds only the connect/init/login flow and shell.
// Pages use named exports, hence the `.then` adapter around React.lazy.
function lazyPage<K extends string>(
  load: () => Promise<Record<K, ComponentType>>,
  name: K,
) {
  return lazy(() => load().then((m) => ({ default: m[name] })));
}

const DashboardPage = lazyPage(() => import("./routes/DashboardPage"), "DashboardPage");
const SecretsPage = lazyPage(() => import("./routes/SecretsPage"), "SecretsPage");
const ResourcesPage = lazyPage(() => import("./routes/ResourcesPage"), "ResourcesPage");
const PmpImportPage = lazyPage(() => import("./routes/PmpImportPage"), "PmpImportPage");
const FilesPage = lazyPage(() => import("./routes/FilesPage"), "FilesPage");
const UsersPage = lazyPage(() => import("./routes/UsersPage"), "UsersPage");
const AppRolePage = lazyPage(() => import("./routes/AppRolePage"), "AppRolePage");
const FerroGatePage = lazyPage(() => import("./routes/FerroGatePage"), "FerroGatePage");
const McpAppsPage = lazyPage(() => import("./routes/McpAppsPage"), "McpAppsPage");
const AiAssistantsPage = lazyPage(() => import("./routes/AiAssistantsPage"), "AiAssistantsPage");
const GroupsPage = lazyPage(() => import("./routes/GroupsPage"), "GroupsPage");
const AssetGroupsPage = lazyPage(() => import("./routes/AssetGroupsPage"), "AssetGroupsPage");
const SharingPage = lazyPage(() => import("./routes/SharingPage"), "SharingPage");
const AuditPage = lazyPage(() => import("./routes/AuditPage"), "AuditPage");
const RecordingsPage = lazyPage(() => import("./routes/RecordingsPage"), "RecordingsPage");
const RustionLiveSessionsPage = lazyPage(() => import("./routes/RustionLiveSessionsPage"), "RustionLiveSessionsPage");
const PoliciesPage = lazyPage(() => import("./routes/PoliciesPage"), "PoliciesPage");
const NamespacesPage = lazyPage(() => import("./routes/NamespacesPage"), "NamespacesPage");
const MountsPage = lazyPage(() => import("./routes/MountsPage"), "MountsPage");
const SettingsPage = lazyPage(() => import("./routes/SettingsPage"), "SettingsPage");
const ResourceTypesPage = lazyPage(() => import("./routes/ResourceTypesPage"), "ResourceTypesPage");
const ProfilePage = lazyPage(() => import("./routes/ProfilePage"), "ProfilePage");
const HsmStatusPage = lazyPage(() => import("./routes/HsmStatusPage"), "HsmStatusPage");
const ExchangePage = lazyPage(() => import("./routes/ExchangePage"), "ExchangePage");
const PkiPage = lazyPage(() => import("./routes/PkiPage"), "PkiPage");
const CertLifecyclePage = lazyPage(() => import("./routes/CertLifecyclePage"), "CertLifecyclePage");
const SshPage = lazyPage(() => import("./routes/SshPage"), "SshPage");
const TotpPage = lazyPage(() => import("./routes/TotpPage"), "TotpPage");
const LdapPage = lazyPage(() => import("./routes/LdapPage"), "LdapPage");
const PluginsPage = lazyPage(() => import("./routes/PluginsPage"), "PluginsPage");
const LeasesPage = lazyPage(() => import("./routes/LeasesPage"), "LeasesPage");
const NotificationsAdminPage = lazyPage(() => import("./routes/NotificationsAdminPage"), "NotificationsAdminPage");

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const bootstrapping = useAuthStore((s) => s.bootstrapping);
  // Hold the redirect while the boot-time `bootstrapAuth` call is in
  // flight. Otherwise a webview reload on a protected route flickers
  // through `/login` on its way back to itself — and worse, on slow
  // hosts the route guard wins the race and strands the user there.
  if (bootstrapping) return null;
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

/** The ⌘K palette, armed once the operator is authenticated. In this
 *  window its provider account picker can link to the provider's own page. */
function AuthedConnectPalette() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const accountsLink = useProviderAccountsLink();
  return <ConnectPalette armed={isAuthenticated} accountsLink={accountsLink} submitPin={fido2SubmitPin} />;
}

export default function App() {
  // Rehydrate auth from the Rust-side `AppState` on every mount. The
  // Rust client retains the access token across webview reloads — so
  // a tool-driven re-paint (e.g. MCP screenshot), Vite HMR, or any
  // other `location.reload()` no longer logs the operator out. See
  // `bootstrapAuth` in `stores/authStore.ts` for the contract.
  const bootstrapAuth = useAuthStore((s) => s.bootstrapAuth);
  // Same for the connection (mode / remote profile / selected node),
  // so a reload does not relabel a remote vault as "Local".
  const bootstrapConnection = useVaultStore((s) => s.bootstrapConnection);
  useEffect(() => {
    void bootstrapConnection();
    void bootstrapAuth();
  }, [bootstrapAuth, bootstrapConnection]);
  return (
    <ErrorBoundary>
      <ToastProvider>
        {/* Mounted once at the root so the Tauri window-menu
            "Server Info..." item can open it from anywhere — the
            modal listens for `open-server-info` and is otherwise
            hidden. Cheap to keep here unconditionally; no state
            until first activation. */}
        <ServerInfoModal />
        {/* Background session monitor — detects an expired/revoked
            token and bounces to /login. Mounted inside ToastProvider
            so it can surface the "session expired" toast. */}
        <SessionMonitor />
        {/* The AI-assistant server's pairing-consent and per-call
            confirmation dialogs (T131). Mounted once so a request can be
            answered from any page; renders nothing until one arrives. */}
        <McpPromptHost />
        <HashRouter>
          <Suspense fallback={null}>
          <Routes>
            <Route path="/" element={<Navigate to="/connect" replace />} />
            <Route path="/connect" element={<ConnectPage />} />
            <Route path="/init" element={<InitPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/dashboard"
              element={<ProtectedRoute><DashboardPage /></ProtectedRoute>}
            />
            <Route
              path="/resources/import-pmp"
              element={<ProtectedRoute><PmpImportPage /></ProtectedRoute>}
            />
            <Route
              path="/resources/*"
              element={<ProtectedRoute><ResourcesPage /></ProtectedRoute>}
            />
            <Route
              path="/secrets/*"
              element={<ProtectedRoute><SecretsPage /></ProtectedRoute>}
            />
            <Route
              path="/files"
              element={<ProtectedRoute><FilesPage /></ProtectedRoute>}
            />
            <Route
              path="/users"
              element={<ProtectedRoute><UsersPage /></ProtectedRoute>}
            />
            <Route
              path="/approle"
              element={<ProtectedRoute><AppRolePage /></ProtectedRoute>}
            />
            <Route
              path="/ferrogate"
              element={<ProtectedRoute><FerroGatePage /></ProtectedRoute>}
            />
            <Route
              path="/mcp-apps"
              element={<ProtectedRoute><McpAppsPage /></ProtectedRoute>}
            />
            <Route
              path="/ai-assistants"
              element={<ProtectedRoute><AiAssistantsPage /></ProtectedRoute>}
            />
            <Route
              path="/groups"
              element={<ProtectedRoute><GroupsPage /></ProtectedRoute>}
            />
            <Route
              path="/asset-groups"
              element={<ProtectedRoute><AssetGroupsPage /></ProtectedRoute>}
            />
            <Route
              path="/sharing"
              element={<ProtectedRoute><SharingPage /></ProtectedRoute>}
            />
            <Route
              path="/audit"
              element={<ProtectedRoute><AuditPage /></ProtectedRoute>}
            />
            <Route
              path="/recordings"
              element={<ProtectedRoute><RecordingsPage /></ProtectedRoute>}
            />
            <Route
              path="/rustion-sessions"
              element={<ProtectedRoute><RustionLiveSessionsPage /></ProtectedRoute>}
            />
            <Route
              path="/policies"
              element={<ProtectedRoute><PoliciesPage /></ProtectedRoute>}
            />
            <Route
              path="/mounts"
              element={<ProtectedRoute><MountsPage /></ProtectedRoute>}
            />
            <Route
              path="/leases"
              element={<ProtectedRoute><LeasesPage /></ProtectedRoute>}
            />
            <Route
              path="/namespaces"
              element={<ProtectedRoute><NamespacesPage /></ProtectedRoute>}
            />
            <Route
              path="/resource-types"
              element={<ProtectedRoute><ResourceTypesPage /></ProtectedRoute>}
            />
            <Route
              path="/settings"
              element={<ProtectedRoute><SettingsPage /></ProtectedRoute>}
            />
            {/* Self-service profile. Deliberately NOT under /settings —
                that page is server-level operator config; this one only
                ever touches the signed-in user's own account. */}
            <Route
              path="/profile"
              element={<ProtectedRoute><ProfilePage /></ProtectedRoute>}
            />
            <Route
              path="/hsm"
              element={<ProtectedRoute><HsmStatusPage /></ProtectedRoute>}
            />
            <Route
              path="/exchange"
              element={<ProtectedRoute><ExchangePage /></ProtectedRoute>}
            />
            <Route
              path="/plugins"
              element={<ProtectedRoute><PluginsPage /></ProtectedRoute>}
            />
            <Route
              path="/notifications"
              element={<ProtectedRoute><NotificationsAdminPage /></ProtectedRoute>}
            />
            {/* Plugin Extensibility v1: dynamic plugin pages.
                The splat pattern lets a plugin contribute multiple
                routes that share a `/plugin/<name>/` prefix. The
                SurfaceRouter looks the path up in the active-surface
                bundle and renders the matching components. */}
            <Route
              path="/plugin/:plugin/*"
              element={<ProtectedRoute><SurfaceRouter /></ProtectedRoute>}
            />
            <Route
              path="/pki"
              element={<ProtectedRoute><PkiPage /></ProtectedRoute>}
            />
            <Route
              path="/cert-lifecycle"
              element={<ProtectedRoute><CertLifecyclePage /></ProtectedRoute>}
            />
            <Route
              path="/ssh"
              element={<ProtectedRoute><SshPage /></ProtectedRoute>}
            />
            <Route
              path="/totp"
              element={<ProtectedRoute><TotpPage /></ProtectedRoute>}
            />
            <Route
              path="/ldap"
              element={<ProtectedRoute><LdapPage /></ProtectedRoute>}
            />
            {/*
              No session routes here. SSH / RDP session windows, the
              Session Workspace and recording replays load session.html
              (src/sessionApp/SessionApp.tsx), a separate bundle that
              mounts only those routes and holds no vault token
              (features/session-workspace.md, T110).
            */}
          </Routes>
          </Suspense>
          {/* Phase 7 — global ⌘K Connect palette. Sits above the
              router so the shortcut is armed everywhere post-auth. */}
          <AuthedConnectPalette />
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
