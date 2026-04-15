import { useState, useEffect } from "react";
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
import type { Fido2Config, Fido2CredentialInfo } from "../lib/types";
import * as api from "../lib/api";

export function Fido2Page() {
  const { toast } = useToast();
  const { register } = useWebAuthn();
  const [config, setConfig] = useState<Fido2Config | null>(null);
  const [credInfo, setCredInfo] = useState<Fido2CredentialInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [editingConfig, setEditingConfig] = useState(false);

  // Config form
  const [rpId, setRpId] = useState("");
  const [rpOrigin, setRpOrigin] = useState("");
  const [rpName, setRpName] = useState("");

  // Username for operations (derived from token metadata or manual input)
  const [username, setUsername] = useState("");

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const cfg = await api.fido2ConfigRead();
      setConfig(cfg);
      if (cfg) {
        setRpId(cfg.rp_id);
        setRpOrigin(cfg.rp_origin);
        setRpName(cfg.rp_name);
      }

      // Try to load credential info for the current user
      if (username) {
        const info = await api.fido2ListCredentials(username);
        setCredInfo(info);
      }
    } catch {
      // Config may not exist yet
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
      toast("error", String(e));
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
      toast("error", String(e));
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
      toast("error", String(e));
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
                {config ? "Edit" : "Configure"}
              </Button>
            ) : (
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" onClick={() => setEditingConfig(false)}>
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
              <span>Waiting for security key... Please insert and tap your key.</span>
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
