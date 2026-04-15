import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AuthLayout } from "../components/AuthLayout";
import { Button, Input, Modal, useToast } from "../components/ui";
import { useVaultStore } from "../stores/vaultStore";
import type { RemoteProfile } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

export function ConnectPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const forceChoose = searchParams.get("choose") === "1";
  const { toast } = useToast();
  const setMode = useVaultStore((s) => s.setMode);
  const setRemoteProfile = useVaultStore((s) => s.setRemoteProfile);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRemote, setShowRemote] = useState(false);

  // Remote form
  const [remoteAddr, setRemoteAddr] = useState("https://127.0.0.1:8200");
  const [remoteName, setRemoteName] = useState("My Server");
  const [tlsSkipVerify, setTlsSkipVerify] = useState(false);
  const [caCertPath, setCaCertPath] = useState("");
  const [connecting, setConnecting] = useState(false);

  useEffect(() => {
    checkSavedPreferences();
  }, []);

  async function checkSavedPreferences() {
    // If user explicitly wants the chooser (e.g. from "Switch vault"), skip auto-navigate
    if (forceChoose) {
      setLoading(false);
      // Pre-fill remote form from saved profile if available
      try {
        const prefs = await api.loadPreferences();
        if (prefs.remote_profile) {
          setRemoteAddr(prefs.remote_profile.address);
          setRemoteName(prefs.remote_profile.name);
          setTlsSkipVerify(prefs.remote_profile.tls_skip_verify);
          setCaCertPath(prefs.remote_profile.ca_cert_path ?? "");
        }
      } catch {
        // ignore
      }
      return;
    }

    try {
      const prefs = await api.loadPreferences();

      if (prefs.mode === "Embedded") {
        const initialized = await api.isVaultInitialized();
        if (initialized) {
          await api.openVault();
          setMode("Embedded");
          navigate("/login", { replace: true });
          return;
        }
        // Not initialized yet — show chooser
      } else if (prefs.mode === "Remote" && prefs.remote_profile) {
        // Try to reconnect with saved profile
        try {
          await api.connectRemote(prefs.remote_profile);
          setMode("Remote");
          setRemoteProfile(prefs.remote_profile);
          navigate("/login", { replace: true });
          return;
        } catch {
          // Remote server unavailable — fall through to show chooser
          // Pre-fill the remote form
          setRemoteAddr(prefs.remote_profile.address);
          setRemoteName(prefs.remote_profile.name);
          setTlsSkipVerify(prefs.remote_profile.tls_skip_verify);
          setCaCertPath(prefs.remote_profile.ca_cert_path ?? "");
        }
      }
    } catch {
      // No saved prefs or error loading — show chooser
    }

    setLoading(false);
  }

  async function handleEmbedded() {
    setLoading(true);
    setError(null);
    try {
      const initialized = await api.isVaultInitialized();
      if (!initialized) {
        navigate("/init");
      } else {
        await api.openVault();
        setMode("Embedded");
        await api.savePreferences("Embedded");
        navigate("/login");
      }
    } catch (e: unknown) {
      setError(extractError(e));
      setLoading(false);
    }
  }

  async function handleRemoteConnect() {
    setConnecting(true);
    setError(null);
    try {
      const profile: RemoteProfile = {
        name: remoteName,
        address: remoteAddr,
        tls_skip_verify: tlsSkipVerify,
        ca_cert_path: caCertPath || undefined,
      };

      await api.connectRemote(profile);
      setMode("Remote");
      setRemoteProfile(profile);
      await api.savePreferences("Remote", profile);
      setShowRemote(false);
      toast("success", `Connected to ${remoteAddr}`);
      navigate("/login");
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setConnecting(false);
    }
  }

  if (loading) {
    return (
      <AuthLayout title="BastionVault" subtitle="Identity-based secrets management">
        <div className="text-center text-[var(--color-text-muted)] py-8">
          <div className="inline-block w-6 h-6 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin mb-3" />
          <p>Connecting to vault...</p>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Get Started" subtitle="Identity-based secrets management">
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="space-y-3">
        <button
          onClick={handleEmbedded}
          className="w-full p-4 bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white rounded-lg text-left transition-colors"
        >
          <div className="font-medium">Local Vault</div>
          <div className="text-sm opacity-80 mt-0.5">
            Embedded vault stored on this device
          </div>
        </button>

        <button
          onClick={() => setShowRemote(true)}
          className="w-full p-4 bg-[var(--color-surface-hover)] hover:bg-[var(--color-border)] text-[var(--color-text)] rounded-lg text-left transition-colors"
        >
          <div className="font-medium">Connect to Server</div>
          <div className="text-sm text-[var(--color-text-muted)] mt-0.5">
            Remote BastionVault instance
          </div>
        </button>
      </div>

      {/* Remote connection modal */}
      <Modal
        open={showRemote}
        onClose={() => {
          setShowRemote(false);
          setError(null);
        }}
        title="Connect to Server"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowRemote(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleRemoteConnect}
              loading={connecting}
              disabled={!remoteAddr}
            >
              Connect
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}
          <Input
            label="Profile Name"
            value={remoteName}
            onChange={(e) => setRemoteName(e.target.value)}
            placeholder="Production Vault"
          />
          <Input
            label="Server Address"
            value={remoteAddr}
            onChange={(e) => setRemoteAddr(e.target.value)}
            placeholder="https://vault.example.com:8200"
            hint="Full URL including protocol and port"
          />
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={tlsSkipVerify}
              onChange={(e) => setTlsSkipVerify(e.target.checked)}
              className="rounded"
            />
            <span className="text-[var(--color-text-muted)]">
              Skip TLS certificate verification (insecure)
            </span>
          </label>
          <Input
            label="CA Certificate Path"
            value={caCertPath}
            onChange={(e) => setCaCertPath(e.target.value)}
            placeholder="/path/to/ca.pem"
            hint="Optional: path to PEM-encoded CA certificate"
          />
        </div>
      </Modal>
    </AuthLayout>
  );
}
