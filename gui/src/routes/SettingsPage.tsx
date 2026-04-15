import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, useToast } from "../components/ui";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import * as api from "../lib/api";

export function SettingsPage() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const reset = useVaultStore((s) => s.reset);
  const [sealing, setSealing] = useState(false);

  async function handleSeal() {
    setSealing(true);
    try {
      await api.sealVault();
      toast("info", "Vault sealed");
    } catch (e: unknown) {
      toast("error", String(e));
    } finally {
      setSealing(false);
    }
  }

  function handleDisconnect() {
    api.disconnectRemote().catch(() => {});
    clearAuth();
    reset();
    navigate("/connect");
  }

  function handleSignOut() {
    clearAuth();
    reset();
    navigate("/connect");
  }

  return (
    <Layout>
      <div className="max-w-2xl space-y-6">
        <h1 className="text-2xl font-bold">Settings</h1>

        {/* Connection info */}
        <Card title="Connection">
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center">
              <span className="text-[var(--color-text-muted)]">Mode</span>
              <Badge
                label={mode === "Remote" ? "Remote" : "Local (Embedded)"}
                variant={mode === "Remote" ? "info" : "success"}
                dot
              />
            </div>
            {mode === "Remote" && remoteProfile && (
              <>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--color-text-muted)]">Server</span>
                  <span className="font-mono text-xs">{remoteProfile.address}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--color-text-muted)]">Profile</span>
                  <span>{remoteProfile.name}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--color-text-muted)]">TLS Verify</span>
                  <span>{remoteProfile.tls_skip_verify ? "Disabled" : "Enabled"}</span>
                </div>
              </>
            )}
            {mode === "Embedded" && (
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-muted)]">Data Location</span>
                <span className="font-mono text-xs">~/.bastion_vault_gui/data/</span>
              </div>
            )}
          </div>
        </Card>

        {/* About */}
        <Card title="About">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-[var(--color-text-muted)]">Application</span>
              <span>BastionVault Desktop</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--color-text-muted)]">GUI Version</span>
              <span className="font-mono">0.1.0</span>
            </div>
          </div>
        </Card>

        {/* Actions */}
        <Card title="Actions">
          <div className="space-y-3">
            {mode === "Embedded" && (
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Seal Vault</p>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    Lock the vault. Requires unseal to access again.
                  </p>
                </div>
                <Button variant="danger" size="sm" onClick={handleSeal} loading={sealing}>
                  Seal
                </Button>
              </div>
            )}
            {mode === "Remote" && (
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Disconnect</p>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    Disconnect from the remote server.
                  </p>
                </div>
                <Button variant="danger" size="sm" onClick={handleDisconnect}>
                  Disconnect
                </Button>
              </div>
            )}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Sign Out</p>
                <p className="text-xs text-[var(--color-text-muted)]">
                  Clear your session and return to the connection screen.
                </p>
              </div>
              <Button variant="secondary" size="sm" onClick={handleSignOut}>
                Sign Out
              </Button>
            </div>
          </div>
        </Card>
      </div>
    </Layout>
  );
}
