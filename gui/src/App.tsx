import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { ConnectPage } from "./routes/ConnectPage";
import { InitPage } from "./routes/InitPage";
import { LoginPage } from "./routes/LoginPage";
import { DashboardPage } from "./routes/DashboardPage";
import { SecretsPage } from "./routes/SecretsPage";
import { ResourcesPage } from "./routes/ResourcesPage";
import { FilesPage } from "./routes/FilesPage";
import { UsersPage } from "./routes/UsersPage";
import { AppRolePage } from "./routes/AppRolePage";
import { GroupsPage } from "./routes/GroupsPage";
import { AssetGroupsPage } from "./routes/AssetGroupsPage";
import { SharingPage } from "./routes/SharingPage";
import { AuditPage } from "./routes/AuditPage";
import { PoliciesPage } from "./routes/PoliciesPage";
import { MountsPage } from "./routes/MountsPage";
import { SettingsPage } from "./routes/SettingsPage";
import { ExchangePage } from "./routes/ExchangePage";
import { PkiPage } from "./routes/PkiPage";
import { CertLifecyclePage } from "./routes/CertLifecyclePage";
import { SshPage } from "./routes/SshPage";
import { TotpPage } from "./routes/TotpPage";
import { LdapPage } from "./routes/LdapPage";
import { PluginsPage } from "./routes/PluginsPage";
import { SessionSshWindow } from "./routes/SessionSshWindow";
import { SessionRdpWindow } from "./routes/SessionRdpWindow";
import { useAuthStore } from "./stores/authStore";
import { ToastProvider } from "./components/ui";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConnectPalette } from "./components/ConnectPalette";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <HashRouter>
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
              path="/policies"
              element={<ProtectedRoute><PoliciesPage /></ProtectedRoute>}
            />
            <Route
              path="/mounts"
              element={<ProtectedRoute><MountsPage /></ProtectedRoute>}
            />
            <Route
              path="/settings"
              element={<ProtectedRoute><SettingsPage /></ProtectedRoute>}
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
              Session windows are spawned by the Resource Connect
              flow into a fresh Tauri WebviewWindow. They claim
              their session via URL params; the host already
              authenticated the credential and registered the
              session before the window opens, so no auth gate.
            */}
            <Route path="/session/ssh" element={<SessionSshWindow />} />
            <Route path="/session/rdp" element={<SessionRdpWindow />} />
          </Routes>
          {/* Phase 7 — global ⌘K Connect palette. Sits above the
              router so the shortcut is armed everywhere post-auth. */}
          <ConnectPalette />
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
