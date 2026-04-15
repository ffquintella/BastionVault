import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  Badge,
  ConfirmModal,
  EmptyState,
  useToast,
} from "../components/ui";
import { useWebAuthn } from "../hooks/useWebAuthn";
import { useVaultStore } from "../stores/vaultStore";
import type { Fido2Config, Fido2CredentialInfo } from "../lib/types";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

function deriveDefaults(mode: string, remoteAddress?: string) {
  if (mode === "Remote" && remoteAddress) {
    try {
      const url = new URL(remoteAddress);
      return {
        rpId: url.hostname,
        rpOrigin: `${url.protocol}//${url.host}`,
        rpName: "BastionVault",
      };
    } catch {
      // fall through to localhost defaults
    }
  }
  return {
    rpId: "localhost",
    rpOrigin: "https://localhost",
    rpName: "BastionVault",
  };
}

export function Fido2Page() {
  const { toast } = useToast();
  const { register } = useWebAuthn();
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const [config, setConfig] = useState<Fido2Config | null>(null);
  const [credInfo, setCredInfo] = useState<Fido2CredentialInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [fido2Status, setFido2Status] = useState<string | null>(null);
  const [showDelete, setShowDelete] = useState(false);
  const [editingConfig, setEditingConfig] = useState(false);

  // Config form
  const [rpId, setRpId] = useState("");
  const [rpOrigin, setRpOrigin] = useState("");
  const [rpName, setRpName] = useState("");

  // Username for operations
  const [username, setUsername] = useState("");

  useEffect(() => {
    loadData();
  }, []);

  // Listen for FIDO2 status events from native CTAP2 layer
  useEffect(() => {
    if (!registering) {
      setFido2Status(null);
      return;
    }
    const unlisten = listen<string>("fido2-status", (event) => {
      const status = event.payload;
      if (status === "insert-key") setFido2Status("Insert your security key...");
      else if (status === "tap-key") setFido2Status("Tap your security key now...");
      else if (status === "select-device") setFido2Status("Multiple devices found — please select one...");
      else if (status === "processing") setFido2Status("Processing...");
      else if (status === "complete") setFido2Status(null);
      else setFido2Status(status);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [registering]);

  async function loadData() {
    setLoading(true);

    try {
      // Ensure fido2 auth method is mounted (may not be if vault was
      // initialized before this feature, or in remote mode).
      try {
        const methods = await api.listAuthMethods();
        const mounted = methods.some((m) => m.mount_type === "fido2" || m.path === "fido2/");
        if (!mounted) {
          await api.enableAuthMethod("fido2/", "fido2", "FIDO2/WebAuthn authentication");
        }
      } catch {
        // fall through — mount might already exist or user lacks perms
      }

      let cfg = await api.fido2ConfigRead();

      // If no config exists, create one with sensible defaults
      if (!cfg) {
        const defaults = deriveDefaults(mode, remoteProfile?.address);
        try {
          await api.fido2ConfigWrite(defaults.rpId, defaults.rpOrigin, defaults.rpName);
          cfg = await api.fido2ConfigRead();
        } catch {
          // If auto-save fails, just pre-fill the form
        }
      }

      setConfig(cfg);
      if (cfg) {
        setRpId(cfg.rp_id);
        setRpOrigin(cfg.rp_origin);
        setRpName(cfg.rp_name);
      } else {
        // Pre-fill form with defaults even if save failed
        const defaults = deriveDefaults(mode, remoteProfile?.address);
        setRpId(defaults.rpId);
        setRpOrigin(defaults.rpOrigin);
        setRpName(defaults.rpName);
      }

      if (username) {
        const info = await api.fido2ListCredentials(username);
        setCredInfo(info);
      }
    } catch {
      // Config may not exist yet — pre-fill defaults
      const defaults = deriveDefaults(mode, remoteProfile?.address);
      setRpId(defaults.rpId);
      setRpOrigin(defaults.rpOrigin);
      setRpName(defaults.rpName);
    } finally {
      setLoading(false);
    }
  }

  async function loadCredentials() {
    if (!username) return;
    try {
      const info = await api.fido2ListCredentials(username);
      setCredInfo(info);
    } catch {
      setCredInfo(null);
    }
  }

  async function handleSaveConfig() {
    try {
      await api.fido2ConfigWrite(rpId, rpOrigin, rpName);
      toast("success", "FIDO2 configuration saved");
      setEditingConfig(false);
      const cfg = await api.fido2ConfigRead();
      setConfig(cfg);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRegister() {
    if (!username) {
      toast("error", "Enter a username first");
      return;
    }
    setRegistering(true);
    try {
      await register(username);
      toast("success", "Security key registered successfully");
      loadCredentials();
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setRegistering(false);
    }
  }

  async function handleDeleteCredentials() {
    if (!username) return;
    try {
      await api.fido2DeleteCredential(username);
      toast("success", "All credentials deleted");
      setShowDelete(false);
      setCredInfo(null);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <Layout>
      <div className="max-w-3xl space-y-6">
        <h1 className="text-2xl font-bold">FIDO2 / Security Keys</h1>

        {/* Configuration */}
        <Card
          title="Relying Party Configuration"
          actions={
            !editingConfig ? (
              <Button size="sm" variant="secondary" onClick={() => setEditingConfig(true)}>
                Edit
              </Button>
            ) : (
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" onClick={() => {
                  setEditingConfig(false);
                  // Revert form to saved config
                  if (config) {
                    setRpId(config.rp_id);
                    setRpOrigin(config.rp_origin);
                    setRpName(config.rp_name);
                  }
                }}>
                  Cancel
                </Button>
                <Button size="sm" onClick={handleSaveConfig}>
                  Save
                </Button>
              </div>
            )
          }
        >
          {loading ? (
            <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
          ) : editingConfig ? (
            <div className="space-y-3">
              <Input
                label="Relying Party ID"
                value={rpId}
                onChange={(e) => setRpId(e.target.value)}
                placeholder="example.com"
                hint="Domain name (e.g., example.com or localhost)"
              />
              <Input
                label="Origin"
                value={rpOrigin}
                onChange={(e) => setRpOrigin(e.target.value)}
                placeholder="https://example.com"
                hint="Full origin URL including protocol"
              />
              <Input
                label="Display Name"
                value={rpName}
                onChange={(e) => setRpName(e.target.value)}
                placeholder="BastionVault"
              />
            </div>
          ) : config ? (
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <span className="text-[var(--color-text-muted)] text-xs">RP ID</span>
                <p className="font-mono">{config.rp_id}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)] text-xs">Origin</span>
                <p className="font-mono">{config.rp_origin}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)] text-xs">Name</span>
                <p>{config.rp_name}</p>
              </div>
            </div>
          ) : (
            <EmptyState
              title="Not configured"
              description="Configure the FIDO2 relying party to enable security key authentication"
            />
          )}
        </Card>

        {/* User Credentials */}
        <Card title="Manage Credentials">
          <div className="space-y-4">
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <Input
                  label="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="alice"
                  hint="Enter the username to manage FIDO2 keys for"
                />
              </div>
              <Button
                size="md"
                variant="secondary"
                onClick={loadCredentials}
                disabled={!username}
              >
                Load
              </Button>
            </div>

            {credInfo ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4 text-sm p-3 bg-[var(--color-bg)] rounded-lg">
                  <div>
                    <span className="text-[var(--color-text-muted)] text-xs">Registered Keys</span>
                    <p className="text-lg font-bold">
                      {credInfo.registered_keys}
                      {credInfo.registered_keys > 0 && (
                        <span className="ml-2"><Badge label="Active" variant="success" dot /></span>
                      )}
                    </p>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)] text-xs">Policies</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {credInfo.policies.length > 0
                        ? credInfo.policies.map((p) => (
                            <Badge key={p} label={p} variant="info" />
                          ))
                        : <span className="text-[var(--color-text-muted)]">None</span>}
                    </div>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)] text-xs">Token TTL</span>
                    <p className="font-mono">
                      {credInfo.ttl > 0 ? `${credInfo.ttl}s` : "Default"}
                    </p>
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button
                    onClick={handleRegister}
                    loading={registering}
                    disabled={!config}
                  >
                    Register New Key
                  </Button>
                  {credInfo.registered_keys > 0 && (
                    <Button
                      variant="danger"
                      onClick={() => setShowDelete(true)}
                    >
                      Delete All Keys
                    </Button>
                  )}
                </div>
              </div>
            ) : username ? (
              <div className="space-y-3">
                <EmptyState
                  title="No credentials found"
                  description={`No FIDO2 keys registered for "${username}". Register a security key to get started.`}
                />
                <div className="flex justify-center">
                  <Button
                    onClick={handleRegister}
                    loading={registering}
                    disabled={!config}
                  >
                    Register Security Key
                  </Button>
                </div>
              </div>
            ) : null}
          </div>
        </Card>

        {registering && (
          <Card>
            <div className="flex items-center gap-3 text-sm">
              <span className="w-5 h-5 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin" />
              <span>{fido2Status || "Waiting for security key... Please insert and tap your key."}</span>
            </div>
          </Card>
        )}

        <ConfirmModal
          open={showDelete}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDeleteCredentials}
          title="Delete All FIDO2 Keys"
          message={`This will remove all registered security keys for "${username}". They will no longer be able to authenticate with FIDO2.`}
          confirmLabel="Delete All"
        />
      </div>
    </Layout>
  );
}
