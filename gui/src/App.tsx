import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { ConnectPage } from "./routes/ConnectPage";
import { InitPage } from "./routes/InitPage";
import { LoginPage } from "./routes/LoginPage";
import { DashboardPage } from "./routes/DashboardPage";
import { SecretsPage } from "./routes/SecretsPage";
import { ResourcesPage } from "./routes/ResourcesPage";
import { UsersPage } from "./routes/UsersPage";
import { AppRolePage } from "./routes/AppRolePage";
import { GroupsPage } from "./routes/GroupsPage";
import { AssetGroupsPage } from "./routes/AssetGroupsPage";
import { SharingPage } from "./routes/SharingPage";
import { AuditPage } from "./routes/AuditPage";
import { PoliciesPage } from "./routes/PoliciesPage";
import { MountsPage } from "./routes/MountsPage";
import { SettingsPage } from "./routes/SettingsPage";
import { useAuthStore } from "./stores/authStore";
import { ToastProvider } from "./components/ui";
import { ErrorBoundary } from "./components/ErrorBoundary";

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
          </Routes>
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
