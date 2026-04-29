import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, Input, Select, Modal, ConfirmModal, Tabs, useToast } from "../components/ui";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import { usePasswordPolicyStore } from "../stores/passwordPolicyStore";
import type {
  Fido2Config,
  ResourceTypeConfig,
  ResourceTypeDef,
  ResourceFieldDef,
  PasswordPolicy,
} from "../lib/types";
import type {
  SsoAdminProvider,
  SsoAdminInput,
  SsoCallbackHints,
} from "../lib/api";
import { DEFAULT_RESOURCE_TYPES, mergeTypeConfig } from "../lib/resourceTypes";
import { CloudStorageCard } from "../components/CloudStorageCard";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

function deriveDefaults(mode: string, remoteAddress?: string) {
  if (mode === "Remote" && remoteAddress) {
    try {
      const url = new URL(remoteAddress);
      return { rpId: url.hostname, rpOrigin: `${url.protocol}//${url.host}`, rpName: "BastionVault" };
    } catch { /* fall through */ }
  }
  return { rpId: "localhost", rpOrigin: "https://localhost", rpName: "BastionVault" };
}

export function SettingsPage() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const mode = useVaultStore((s) => s.mode);
  const remoteProfile = useVaultStore((s) => s.remoteProfile);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const reset = useVaultStore((s) => s.reset);
  const [sealing, setSealing] = useState(false);
  const [activeTab, setActiveTab] = useState<string>(() => {
    try { return localStorage.getItem("settings.activeTab") || "general"; } catch { return "general"; }
  });
  useEffect(() => {
    try { localStorage.setItem("settings.activeTab", activeTab); } catch { /* ignore */ }
  }, [activeTab]);
  const SETTINGS_TABS = [
    { id: "general",  label: "General" },
    { id: "security", label: "Security" },
    { id: "identity", label: "Identity" },
    { id: "resources", label: "Resources" },
    { id: "storage", label: "Storage" },
  ];
  // Effective data location for the currently-default Local profile.
  // Resolved at mount time so the Connection card reflects what
  // build_backend / is_initialized actually use, not a hardcoded
  // string. Empty until the lookup resolves.
  const [dataLocation, setDataLocation] = useState<string>("");

  // FIDO2 RP config
  const [fido2Config, setFido2Config] = useState<Fido2Config | null>(null);
  const [editingFido2, setEditingFido2] = useState(false);
  const [rpId, setRpId] = useState("");
  const [rpOrigin, setRpOrigin] = useState("");
  const [rpName, setRpName] = useState("");

  // Resource type config
  const [resTypes, setResTypes] = useState<ResourceTypeConfig>(DEFAULT_RESOURCE_TYPES);
  const [editType, setEditType] = useState<ResourceTypeDef | null>(null);
  const [deleteTypeId, setDeleteTypeId] = useState<string | null>(null);
  const [showAddType, setShowAddType] = useState(false);

  // SSO (Single Sign-On) admin: global toggle + provider list (each
  // provider is a mount + config + default role, managed as a unit).
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoLoaded, setSsoLoaded] = useState(false);
  const [ssoSaving, setSsoSaving] = useState(false);
  const [ssoProviders, setSsoProviders] = useState<SsoAdminProvider[]>([]);
  const [editingProvider, setEditingProvider] = useState<SsoAdminProvider | null>(null);
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [deletingMount, setDeletingMount] = useState<string | null>(null);

  // YubiKey failsafe — list of cards that can unlock the local
  // vault-keys file (the machine-level keystore, distinct from the
  // vault's own FIDO2 auth backend). See
  // `docs/docs/security-structure.md` § YubiKey failsafe.
  const [ykRegistered, setYkRegistered] = useState<
    import("../lib/api").RegisteredYubiKeyDto[]
  >([]);
  const [ykPlugged, setYkPlugged] = useState<
    import("../lib/api").YubiKeyDeviceInfo[]
  >([]);
  const [ykRegistering, setYkRegistering] = useState(false);
  const [ykSerialToRegister, setYkSerialToRegister] = useState<number | null>(
    null,
  );
  const [ykPin, setYkPin] = useState("");
  const [ykError, setYkError] = useState<string | null>(null);

  // Password policy
  const passwordPolicy = usePasswordPolicyStore((s) => s.policy);
  const loadPasswordPolicy = usePasswordPolicyStore((s) => s.load);
  const updatePasswordPolicy = usePasswordPolicyStore((s) => s.update);
  const [editingPolicy, setEditingPolicy] = useState(false);
  const [policyDraft, setPolicyDraft] = useState<PasswordPolicy>(passwordPolicy);
  const [savingPolicy, setSavingPolicy] = useState(false);

  useEffect(() => {
    loadFido2Config();
    loadResourceTypes();
    loadPasswordPolicy();
    loadSsoState();
    loadYubiKeyState();
    void loadDataLocation();
  }, [loadPasswordPolicy]);

  // Resolve the active Local profile's effective data dir for the
  // Connection card. Honours per-profile `data_dir` override and
  // falls back to the per-engine default — same logic the Rust side
  // uses in build_backend / is_initialized. Stays empty for Remote /
  // Cloud modes (the card's branches don't render this row).
  async function loadDataLocation() {
    try {
      const list = await api.listVaultProfiles();
      const active = list.vaults.find((v) => v.id === list.lastUsedId);
      if (!active || active.spec.kind !== "local") {
        setDataLocation("");
        return;
      }
      const custom =
        typeof active.spec.data_dir === "string" && active.spec.data_dir.trim()
          ? active.spec.data_dir
          : null;
      if (custom) {
        setDataLocation(custom);
        return;
      }
      const sk = (active.spec.storage_kind as "file" | "hiqlite") ?? "file";
      const fallback = await api.getDefaultLocalDataDir(sk);
      setDataLocation(fallback);
    } catch {
      setDataLocation("");
    }
  }

  async function loadYubiKeyState() {
    try {
      setYkRegistered(await api.yubikeyListRegistered());
    } catch {
      setYkRegistered([]);
    }
    try {
      setYkPlugged(await api.yubikeyListDevices());
    } catch {
      // PC/SC absent or empty — leave the "plugged in" list empty;
      // the UI surfaces the overall empty state instead of erroring.
      setYkPlugged([]);
    }
  }

  async function handleRegisterYubiKey() {
    if (!ykSerialToRegister) {
      setYkError("Pick a connected YubiKey to register.");
      return;
    }
    if (ykPin.trim().length < 4) {
      setYkError("PIV PIN is required (4+ digits).");
      return;
    }
    setYkRegistering(true);
    setYkError(null);
    try {
      await api.yubikeyRegister(ykSerialToRegister, ykPin);
      toast("success", `YubiKey ${ykSerialToRegister} registered`);
      setYkPin("");
      setYkSerialToRegister(null);
      await loadYubiKeyState();
    } catch (e: unknown) {
      setYkError(extractError(e));
    } finally {
      setYkRegistering(false);
    }
  }

  async function handleRemoveYubiKey(serial: number) {
    if (!confirm(`Remove YubiKey ${serial} as an unlock path?`)) return;
    try {
      await api.yubikeyRemove(serial);
      toast("success", `YubiKey ${serial} removed`);
      await loadYubiKeyState();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function loadSsoState() {
    try {
      const enabled = await api.getSsoSettings();
      setSsoEnabled(enabled);
    } catch {
      /* fall through — default to disabled */
    } finally {
      setSsoLoaded(true);
    }
    await reloadSsoProviders();
  }

  async function reloadSsoProviders() {
    try {
      const list = await api.ssoAdminList();
      setSsoProviders(list);
    } catch {
      setSsoProviders([]);
    }
  }

  async function handleToggleSso(next: boolean) {
    setSsoSaving(true);
    try {
      await api.setSsoSettings(next);
      setSsoEnabled(next);
      toast("success", next ? "SSO enabled" : "SSO disabled");
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSsoSaving(false);
    }
  }

  async function handleSaveProvider(input: SsoAdminInput, isEdit: boolean) {
    try {
      if (isEdit) {
        await api.ssoAdminUpdate(input);
      } else {
        await api.ssoAdminCreate(input);
      }
      toast(
        "success",
        isEdit ? "SSO provider updated" : "SSO provider created",
      );
      setEditingProvider(null);
      setShowAddProvider(false);
      await reloadSsoProviders();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDeleteProvider() {
    if (!deletingMount) return;
    try {
      await api.ssoAdminDelete(deletingMount);
      toast("success", "SSO provider removed");
      setDeletingMount(null);
      await reloadSsoProviders();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  // Keep the draft in sync with the store when not actively editing.
  useEffect(() => {
    if (!editingPolicy) setPolicyDraft(passwordPolicy);
  }, [passwordPolicy, editingPolicy]);

  async function handleSavePolicy() {
    setSavingPolicy(true);
    try {
      const normalized: PasswordPolicy = {
        ...policyDraft,
        min_length: Math.max(1, Math.min(512, Math.floor(policyDraft.min_length))),
      };
      await updatePasswordPolicy(normalized);
      toast("success", "Password policy saved");
      setEditingPolicy(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSavingPolicy(false);
    }
  }

  async function loadFido2Config() {
    const defaults = deriveDefaults(mode, remoteProfile?.address);
    try {
      let cfg = await api.fido2ConfigRead();
      if (!cfg) {
        try {
          await api.fido2ConfigWrite(defaults.rpId, defaults.rpOrigin, defaults.rpName);
          cfg = await api.fido2ConfigRead();
        } catch { /* fall through */ }
      }
      const effective = cfg ?? { rp_id: defaults.rpId, rp_origin: defaults.rpOrigin, rp_name: defaults.rpName };
      setFido2Config(effective);
      setRpId(effective.rp_id);
      setRpOrigin(effective.rp_origin);
      setRpName(effective.rp_name);
    } catch {
      const effective = { rp_id: defaults.rpId, rp_origin: defaults.rpOrigin, rp_name: defaults.rpName };
      setFido2Config(effective);
      setRpId(effective.rp_id);
      setRpOrigin(effective.rp_origin);
      setRpName(effective.rp_name);
    }
  }

  async function loadResourceTypes() {
    try {
      const saved = await api.resourceTypesRead();
      setResTypes(mergeTypeConfig(saved as ResourceTypeConfig | null));
    } catch {
      setResTypes(DEFAULT_RESOURCE_TYPES);
    }
  }

  async function saveResourceTypes(updated: ResourceTypeConfig) {
    try {
      await api.resourceTypesWrite(updated as unknown as Record<string, unknown>);
      setResTypes(updated);
      toast("success", "Resource types saved");
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function handleSaveType(typeDef: ResourceTypeDef) {
    const updated = { ...resTypes, [typeDef.id]: typeDef };
    saveResourceTypes(updated);
    setEditType(null);
    setShowAddType(false);
  }

  function handleDeleteType() {
    if (!deleteTypeId) return;
    const updated = { ...resTypes };
    delete updated[deleteTypeId];
    saveResourceTypes(updated);
    setDeleteTypeId(null);
  }

  function handleResetTypes() {
    saveResourceTypes(DEFAULT_RESOURCE_TYPES);
  }

  async function handleSaveFido2() {
    try {
      await api.fido2ConfigWrite(rpId, rpOrigin, rpName);
      toast("success", "FIDO2 configuration saved");
      setEditingFido2(false);
      const cfg = await api.fido2ConfigRead();
      setFido2Config(cfg ?? { rp_id: rpId, rp_origin: rpOrigin, rp_name: rpName });
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleSeal() {
    setSealing(true);
    try {
      await api.sealVault();
      toast("info", "Vault sealed");
    } catch (e: unknown) {
      toast("error", extractError(e));
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
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Settings</h1>

        <Tabs tabs={SETTINGS_TABS} active={activeTab} onChange={setActiveTab} />

        {activeTab === "general" && (<>
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
              <div className="flex justify-between items-center gap-3">
                <span className="text-[var(--color-text-muted)] shrink-0">
                  Data Location
                </span>
                <span
                  className="font-mono text-xs truncate min-w-0 text-right"
                  title={dataLocation || "(resolving…)"}
                >
                  {dataLocation || "(resolving…)"}
                </span>
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
        </>)}

        {activeTab === "security" && (<>
        {/* FIDO2 Configuration */}
        <Card
          title="FIDO2 / Security Keys"
          actions={
            !editingFido2 ? (
              <Button size="sm" variant="secondary" onClick={() => setEditingFido2(true)}>Edit</Button>
            ) : (
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" onClick={() => {
                  setEditingFido2(false);
                  if (fido2Config) { setRpId(fido2Config.rp_id); setRpOrigin(fido2Config.rp_origin); setRpName(fido2Config.rp_name); }
                }}>Cancel</Button>
                <Button size="sm" onClick={handleSaveFido2}>Save</Button>
              </div>
            )
          }
        >
          {editingFido2 ? (
            <div className="space-y-3">
              <Input label="Relying Party ID" value={rpId} onChange={(e) => setRpId(e.target.value)} placeholder="example.com" hint="Domain name (e.g., example.com or localhost)" />
              <Input label="Origin" value={rpOrigin} onChange={(e) => setRpOrigin(e.target.value)} placeholder="https://example.com" hint="Full origin URL including protocol" />
              <Input label="Display Name" value={rpName} onChange={(e) => setRpName(e.target.value)} placeholder="BastionVault" />
            </div>
          ) : fido2Config ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-muted)]">Relying Party ID</span>
                <span className="font-mono text-xs">{fido2Config.rp_id}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-muted)]">Origin</span>
                <span className="font-mono text-xs">{fido2Config.rp_origin}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-muted)]">Display Name</span>
                <span>{fido2Config.rp_name}</span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
          )}
        </Card>

        {/* YubiKey failsafe — additional / alternative unlock paths
            for the machine-level vault-keys file. Distinct from the
            vault's own FIDO2 auth backend (which authenticates USERS
            to the vault). This card adds HARDWARE KEYS that can
            unlock the local keystore so a spare YubiKey becomes a
            recovery path if the OS keychain is wiped or the primary
            card is lost. See docs/docs/security-structure.md. */}
        <Card title="YubiKey Failsafe">
          <div className="space-y-4">
            <p className="text-xs text-[var(--color-text-muted)]">
              Register one or more YubiKeys as additional unlock paths for
              this machine's vault-keys file. Each registered card becomes
              an independent unlock slot — any one is enough to open the
              file, so a spare key survives loss or damage of the primary.
              The OS keychain entry still works as the default unlock path.
            </p>

            {ykRegistered.length > 0 && (
              <div>
                <p className="text-xs font-medium text-[var(--color-text)] mb-1">
                  Registered
                </p>
                <div className="space-y-1">
                  {ykRegistered.map((y) => (
                    <div
                      key={y.serial}
                      className="flex items-center justify-between py-1.5 px-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm"
                    >
                      <div className="min-w-0 flex-1">
                        <span className="font-mono">#{y.serial}</span>
                        <span className="ml-2 text-xs text-[var(--color-text-muted)] font-mono truncate">
                          id {y.key_id.slice(0, 12)}…
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => handleRemoveYubiKey(y.serial)}
                      >
                        Remove
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <p className="text-xs font-medium text-[var(--color-text)] mb-1">
                Register a new YubiKey
              </p>
              {ykPlugged.length === 0 ? (
                <p className="text-xs text-[var(--color-text-muted)]">
                  No YubiKeys detected. Plug one in and click the button
                  below to refresh.
                </p>
              ) : (
                <div className="space-y-2">
                  <Select
                    label="Device"
                    value={
                      ykSerialToRegister !== null
                        ? String(ykSerialToRegister)
                        : ""
                    }
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      setYkSerialToRegister(Number.isFinite(n) ? n : null);
                    }}
                    options={[
                      { value: "", label: "— select a device —" },
                      ...ykPlugged.map((d) => ({
                        value: String(d.serial),
                        label: `#${d.serial}${
                          d.slot_occupied ? "" : " (slot 9a empty)"
                        }`,
                      })),
                    ]}
                  />
                  <Input
                    label="PIV PIN"
                    type="password"
                    value={ykPin}
                    onChange={(e) => setYkPin(e.target.value)}
                    placeholder="••••••"
                    hint="Default PIN on factory-reset cards is 123456. Never stored — cleared as soon as the registration completes."
                  />
                  {ykError && (
                    <p className="text-xs text-[var(--color-danger)]">
                      {ykError}
                    </p>
                  )}
                </div>
              )}
              <div className="flex gap-2 mt-2">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={loadYubiKeyState}
                  disabled={ykRegistering}
                >
                  Refresh
                </Button>
                <Button
                  size="sm"
                  onClick={handleRegisterYubiKey}
                  loading={ykRegistering}
                  disabled={
                    ykPlugged.length === 0 || ykSerialToRegister === null
                  }
                >
                  Register
                </Button>
              </div>
            </div>
          </div>
        </Card>
        </>)}

        {activeTab === "identity" && (<>
        {/* Single Sign-On (SSO) */}
        <Card
          title="Single Sign-On (SSO)"
          actions={
            <div className="flex items-center gap-3">
              <Button size="sm" onClick={() => setShowAddProvider(true)}>
                Add Provider
              </Button>
              {ssoLoaded && (
                <label className="flex items-center gap-2 cursor-pointer select-none text-sm">
                  <input
                    type="checkbox"
                    checked={ssoEnabled}
                    disabled={ssoSaving}
                    onChange={(e) => handleToggleSso(e.target.checked)}
                    className="accent-[var(--color-primary)] w-4 h-4"
                  />
                  <span className="text-[var(--color-text-muted)]">
                    {ssoEnabled ? "Enabled" : "Disabled"}
                  </span>
                </label>
              )}
            </div>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-[var(--color-text-muted)]">
              Configure identity providers users sign in through. Each
              provider is one OIDC auth mount with its own discovery URL,
              client credentials, allowed redirect URIs, and default role.
              Disable the top-right toggle to hide the SSO tab on the login
              screen without removing providers.
            </p>

            {ssoProviders.length === 0 ? (
              <p className="text-sm text-[var(--color-text-muted)] py-4 text-center">
                No providers configured yet. Click <span className="text-[var(--color-text)]">Add Provider</span> to set one up.
              </p>
            ) : (
              <div className="space-y-2">
                {ssoProviders.map((p) => (
                  <div
                    key={p.mount}
                    className="flex items-center justify-between py-2 border-b border-[var(--color-border)] last:border-0"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-[var(--color-text)] truncate">
                          {p.display_name || p.mount}
                        </span>
                        <Badge
                          label={p.kind.toUpperCase()}
                          variant="info"
                        />
                        {p.kind === "oidc" && !p.config.client_secret_set && (
                          <Badge label="PKCE" variant="neutral" />
                        )}
                        {p.kind === "saml" && !p.config.idp_cert_set && (
                          <Badge label="No cert" variant="warning" />
                        )}
                        {p.role === null && (
                          <Badge label="Missing role" variant="warning" />
                        )}
                      </div>
                      <div className="text-xs text-[var(--color-text-muted)] mt-0.5 flex gap-3 flex-wrap">
                        <span className="font-mono">mount: {p.mount}</span>
                        {p.kind === "oidc" && p.config.discovery_url && (
                          <span className="font-mono truncate max-w-md">
                            {p.config.discovery_url}
                          </span>
                        )}
                        {p.kind === "saml" &&
                          (p.config.idp_metadata_url ||
                            p.config.idp_sso_url) && (
                            <span className="font-mono truncate max-w-md">
                              {p.config.idp_metadata_url ||
                                p.config.idp_sso_url}
                            </span>
                          )}
                      </div>
                    </div>
                    <div className="flex gap-1 shrink-0 ml-3">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setEditingProvider(p)}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => setDeletingMount(p.mount)}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {ssoEnabled && ssoProviders.length === 0 && (
              <p className="text-xs text-[var(--color-warning)]">
                SSO is enabled but no providers are configured — the SSO
                login tab will stay hidden until at least one is added.
              </p>
            )}
            {!ssoEnabled && ssoProviders.length > 0 && (
              <p className="text-xs text-[var(--color-text-muted)]">
                SSO is currently disabled. Flip the toggle above to expose
                these providers on the login screen.
              </p>
            )}
          </div>
        </Card>
        </>)}

        {(editingProvider || showAddProvider) && (
          <SsoProviderModal
            provider={editingProvider}
            onSave={(input) =>
              handleSaveProvider(input, editingProvider !== null)
            }
            onClose={() => {
              setEditingProvider(null);
              setShowAddProvider(false);
            }}
          />
        )}

        <ConfirmModal
          open={deletingMount !== null}
          onClose={() => setDeletingMount(null)}
          onConfirm={handleDeleteProvider}
          title="Remove SSO Provider"
          message={`Disable and remove the \`${deletingMount}\` auth mount? Users currently signed in via this provider will keep their tokens until they expire.`}
          confirmLabel="Remove"
        />

        {activeTab === "security" && (<>
        {/* Password Policy */}
        <Card
          title="Password Policy"
          actions={
            !editingPolicy ? (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setPolicyDraft(passwordPolicy);
                  setEditingPolicy(true);
                }}
              >
                Edit
              </Button>
            ) : (
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setPolicyDraft(passwordPolicy);
                    setEditingPolicy(false);
                  }}
                  disabled={savingPolicy}
                >
                  Cancel
                </Button>
                <Button size="sm" onClick={handleSavePolicy} loading={savingPolicy}>
                  Save
                </Button>
              </div>
            )
          }
        >
          {editingPolicy ? (
            <div className="space-y-4">
              {/* Minimum length */}
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <label
                    htmlFor="policy-min-length"
                    className="font-medium text-[var(--color-text)]"
                  >
                    Minimum length
                  </label>
                  <span className="font-mono text-[var(--color-text-muted)]">
                    {policyDraft.min_length}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <input
                    id="policy-min-length"
                    type="range"
                    min={4}
                    max={128}
                    value={policyDraft.min_length}
                    onChange={(e) =>
                      setPolicyDraft({
                        ...policyDraft,
                        min_length: Number(e.target.value),
                      })
                    }
                    className="flex-1 accent-[var(--color-primary)]"
                  />
                  <input
                    type="number"
                    min={1}
                    max={512}
                    value={policyDraft.min_length}
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      if (Number.isFinite(n)) {
                        setPolicyDraft({
                          ...policyDraft,
                          min_length: Math.max(1, Math.min(512, Math.floor(n))),
                        });
                      }
                    }}
                    className="w-20 text-sm bg-[var(--color-bg)] border border-[var(--color-border)] rounded px-2 py-1"
                  />
                </div>
                <p className="text-xs text-[var(--color-text-muted)]">
                  The generator will never produce a password shorter than this.
                </p>
              </div>

              {/* Required character groups */}
              <div className="space-y-2">
                <label className="block text-sm font-medium text-[var(--color-text)]">
                  Required character groups
                </label>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <PolicyToggle
                    label="Lowercase (a-z)"
                    checked={policyDraft.require_lowercase}
                    onChange={(v) =>
                      setPolicyDraft({ ...policyDraft, require_lowercase: v })
                    }
                  />
                  <PolicyToggle
                    label="Uppercase (A-Z)"
                    checked={policyDraft.require_uppercase}
                    onChange={(v) =>
                      setPolicyDraft({ ...policyDraft, require_uppercase: v })
                    }
                  />
                  <PolicyToggle
                    label="Digits (0-9)"
                    checked={policyDraft.require_digits}
                    onChange={(v) =>
                      setPolicyDraft({ ...policyDraft, require_digits: v })
                    }
                  />
                  <PolicyToggle
                    label="Symbols (!@#...)"
                    checked={policyDraft.require_symbols}
                    onChange={(v) =>
                      setPolicyDraft({ ...policyDraft, require_symbols: v })
                    }
                  />
                </div>
                <p className="text-xs text-[var(--color-text-muted)]">
                  Groups toggled on here are always included by the generator --
                  the user cannot turn them off from the generator popover.
                </p>
                {!policyDraft.require_lowercase &&
                  !policyDraft.require_uppercase &&
                  !policyDraft.require_digits &&
                  !policyDraft.require_symbols && (
                    <p className="text-xs text-[var(--color-warning)]">
                      No character groups required. Users will be able to pick any
                      combination in the generator.
                    </p>
                  )}
              </div>
            </div>
          ) : (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-muted)]">Minimum length</span>
                <span className="font-mono">{passwordPolicy.min_length}</span>
              </div>
              <div>
                <div className="text-[var(--color-text-muted)] mb-1">
                  Required groups
                </div>
                <div className="flex flex-wrap gap-1">
                  {requiredGroupBadges(passwordPolicy).length === 0 ? (
                    <span className="text-[var(--color-text-muted)]">None</span>
                  ) : (
                    requiredGroupBadges(passwordPolicy).map((label) => (
                      <Badge key={label} label={label} variant="info" />
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </Card>
        </>)}

        {activeTab === "resources" && (<>
        {/* Resource Types */}
        <Card title="Resource Types" actions={
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={handleResetTypes}>Reset to Defaults</Button>
            <Button size="sm" onClick={() => setShowAddType(true)}>Add Type</Button>
          </div>
        }>
          <div className="space-y-2">
            {Object.values(resTypes).map((t) => (
              <div key={t.id} className="flex items-center justify-between py-2 border-b border-[var(--color-border)] last:border-0">
                <div className="flex items-center gap-2">
                  <Badge label={t.label} variant={t.color} />
                  <span className="text-xs text-[var(--color-text-muted)]">{t.fields.length} fields</span>
                </div>
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setEditType({ ...t, fields: t.fields.map(f => ({ ...f })) })}>Edit</Button>
                  <Button size="sm" variant="danger" onClick={() => setDeleteTypeId(t.id)}>Delete</Button>
                </div>
              </div>
            ))}
            {Object.keys(resTypes).length === 0 && (
              <p className="text-sm text-[var(--color-text-muted)]">No types configured. Add a type or reset to defaults.</p>
            )}
          </div>
        </Card>
        </>)}

        {/* Edit/Add Type Modal */}
        {(editType || showAddType) && (
          <TypeEditorModal
            typeDef={editType}
            onSave={handleSaveType}
            onClose={() => { setEditType(null); setShowAddType(false); }}
          />
        )}

        <ConfirmModal open={deleteTypeId !== null} onClose={() => setDeleteTypeId(null)}
          onConfirm={handleDeleteType} title="Delete Resource Type"
          message={`Delete the "${deleteTypeId}" resource type? Existing resources of this type will keep their data but won't have field definitions.`}
          confirmLabel="Delete" />

        {activeTab === "storage" && (<>
        {/* Cloud Storage Targets — OAuth connect flow. Phase 7 of
            features/cloud-storage-backend.md. */}
        <CloudStorageCard />
        </>)}

        {activeTab === "general" && (<>
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

            <div className="flex items-center justify-between pt-3 border-t border-[var(--color-border)]">
              <div className="pr-4">
                <p className="text-sm font-medium">Reset local key cache</p>
                <p className="text-xs text-[var(--color-text-muted)]">
                  Clears the encrypted vault-keys.enc file + its OS-keychain
                  seal. Vault data (local or cloud) is not touched — only
                  the cached unseal keys are. You'll re-enter each vault's
                  unseal key on next open. Use when "aead unwrap content
                  key" / "local keystore" errors appear on the chooser.
                </p>
              </div>
              <Button
                variant="danger"
                size="sm"
                onClick={async () => {
                  if (
                    !confirm(
                      "Clear the local key cache? You'll need to re-enter each vault's unseal key on next open. Vault data is NOT affected.",
                    )
                  )
                    return;
                  try {
                    await api.resetLocalKeystore();
                    toast("success", "Local key cache cleared");
                  } catch (e: unknown) {
                    toast("error", extractError(e));
                  }
                }}
              >
                Reset Cache
              </Button>
            </div>
          </div>
        </Card>
        </>)}
      </div>
    </Layout>
  );
}

// ── Password Policy helpers ────────────────────────────────────────

function PolicyToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-[var(--color-primary)]"
      />
      <span className="text-[var(--color-text-muted)]">{label}</span>
    </label>
  );
}

function requiredGroupBadges(p: PasswordPolicy): string[] {
  const out: string[] = [];
  if (p.require_lowercase) out.push("lowercase");
  if (p.require_uppercase) out.push("uppercase");
  if (p.require_digits) out.push("digits");
  if (p.require_symbols) out.push("symbols");
  return out;
}

// ── Type Editor Modal ──────────────────────────────────────────────

const COLOR_OPTIONS = [
  { value: "info", label: "Blue" },
  { value: "success", label: "Green" },
  { value: "warning", label: "Yellow" },
  { value: "error", label: "Red" },
  { value: "neutral", label: "Gray" },
];

const FIELD_TYPE_OPTIONS = [
  { value: "text", label: "Text" },
  { value: "number", label: "Number" },
  { value: "url", label: "URL" },
  { value: "ip", label: "IP Address" },
  { value: "fqdn", label: "FQDN" },
  { value: "select", label: "Select (enum)" },
];

/**
 * Parse the operator-typed `value=label, value=label` shorthand for
 * select-field options. Tolerates extra whitespace and trailing
 * commas; entries without an `=` use the same string for both
 * value and label so a quick `linux, windows, macos` works too.
 */
function parseSelectOptions(input: string): { value: string; label: string }[] {
  return input
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => {
      const eq = part.indexOf("=");
      if (eq < 0) return { value: part, label: part };
      const value = part.slice(0, eq).trim();
      const label = part.slice(eq + 1).trim();
      return { value, label: label || value };
    });
}

function TypeEditorModal({ typeDef, onSave, onClose }: {
  typeDef: ResourceTypeDef | null;
  onSave: (t: ResourceTypeDef) => void;
  onClose: () => void;
}) {
  const isNew = !typeDef;
  const [id, setId] = useState(typeDef?.id ?? "");
  const [label, setLabel] = useState(typeDef?.label ?? "");
  const [color, setColor] = useState<string>(typeDef?.color ?? "info");
  const [fields, setFields] = useState<ResourceFieldDef[]>(typeDef?.fields ?? []);

  function addField() {
    setFields([...fields, { key: "", label: "", type: "text", placeholder: "" }]);
  }

  function updateFieldDef(index: number, patch: Partial<ResourceFieldDef>) {
    setFields(fields.map((f, i) => i === index ? { ...f, ...patch } : f));
  }

  function removeField(index: number) {
    setFields(fields.filter((_, i) => i !== index));
  }

  function handleSave() {
    const resolvedId = isNew ? id.toLowerCase().replace(/[^a-z0-9_]/g, "_") : id;
    onSave({
      id: resolvedId,
      label: label || resolvedId,
      color: color as ResourceTypeDef["color"],
      fields: fields.filter((f) => f.key),
    });
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={isNew ? "Add Resource Type" : `Edit: ${label}`}
      size="lg"
      actions={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} disabled={isNew ? !id : false}>Save</Button>
      </>}
    >
      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-3">
          {isNew && (
            <Input label="Type ID" value={id} onChange={(e) => setId(e.target.value)}
              placeholder="my_device" hint="Lowercase, no spaces" />
          )}
          <Input label="Display Label" value={label} onChange={(e) => setLabel(e.target.value)}
            placeholder="My Device" />
          <Select label="Color" value={color} onChange={(e) => setColor(e.target.value)}
            options={COLOR_OPTIONS} />
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm font-medium text-[var(--color-text)]">Fields</label>
            <Button size="sm" variant="ghost" onClick={addField}>+ Add Field</Button>
          </div>
          <div className="space-y-2">
            {fields.map((f, i) => (
              <div key={i} className="space-y-1">
                <div className="flex gap-2 items-end">
                  <Input label={i === 0 ? "Key" : undefined} value={f.key}
                    onChange={(e) => updateFieldDef(i, { key: e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, "_") })}
                    placeholder="field_key" />
                  <Input label={i === 0 ? "Label" : undefined} value={f.label}
                    onChange={(e) => updateFieldDef(i, { label: e.target.value })}
                    placeholder="Field Label" />
                  <div className="w-28 shrink-0">
                    <Select label={i === 0 ? "Type" : undefined} value={f.type}
                      onChange={(e) => updateFieldDef(i, { type: e.target.value as ResourceFieldDef["type"] })}
                      options={FIELD_TYPE_OPTIONS} />
                  </div>
                  {f.type === "select" ? (
                    <Input
                      label={i === 0 ? "Options (value=label, comma-sep)" : undefined}
                      value={(f.options ?? []).map((o) => `${o.value}=${o.label}`).join(", ")}
                      onChange={(e) =>
                        updateFieldDef(i, {
                          options: parseSelectOptions(e.target.value),
                        })
                      }
                      placeholder="linux=Linux, windows=Windows"
                    />
                  ) : (
                    <Input label={i === 0 ? "Placeholder" : undefined} value={f.placeholder ?? ""}
                      onChange={(e) => updateFieldDef(i, { placeholder: e.target.value })}
                      placeholder="Hint text" />
                  )}
                  <button onClick={() => removeField(i)}
                    className="text-[var(--color-danger)] hover:text-red-400 text-lg pb-1 shrink-0">&times;</button>
                </div>
              </div>
            ))}
            {fields.length === 0 && (
              <p className="text-xs text-[var(--color-text-muted)]">No fields defined. Resources of this type will only have name, tags, and notes.</p>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
}

// ── SSO Provider Editor ────────────────────────────────────────────
//
// One modal for create + edit. The server side enforces the rules
// documented inline; this UI just validates the obvious misses
// up-front so the user doesn't round-trip to learn `policies` was
// required. `client_secret` field behavior is documented next to
// the input — blank on edit means "keep existing".

const COMMON_OIDC_SCOPES = ["openid", "profile", "email", "groups"];

function SsoProviderModal({
  provider,
  onSave,
  onClose,
}: {
  provider: SsoAdminProvider | null;
  onSave: (input: SsoAdminInput) => void;
  onClose: () => void;
}) {
  const isEdit = provider !== null;

  // `kind` is fixed-after-create: the mount-path maps to one auth
  // backend implementation, and we can't "convert" an OIDC mount to
  // SAML without tearing it down. On create the admin picks; on
  // edit the switcher is disabled.
  const [kind, setKind] = useState<"oidc" | "saml">(provider?.kind ?? "oidc");

  const [mount, setMount] = useState(provider?.mount ?? "oidc");
  const [displayName, setDisplayName] = useState(provider?.display_name ?? "");
  const [allowedRedirectUris, setAllowedRedirectUris] = useState(
    ((provider?.config.allowed_redirect_uris ?? []) as string[]).join("\n"),
  );
  const [defaultRole, setDefaultRole] = useState(provider?.default_role ?? "user");

  // OIDC-specific state (populated from provider.config when kind is OIDC).
  const oidcCfg =
    provider?.kind === "oidc" ? provider.config : undefined;
  const oidcRole = provider?.role?.kind === "oidc" ? provider.role : undefined;
  const [discoveryUrl, setDiscoveryUrl] = useState(oidcCfg?.discovery_url ?? "");
  const [clientId, setClientId] = useState(oidcCfg?.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [scopes, setScopes] = useState(
    (oidcCfg?.scopes ?? COMMON_OIDC_SCOPES.slice(0, 3)).join(", "),
  );
  const [userClaim, setUserClaim] = useState(
    oidcRole?.user_claim ?? "preferred_username",
  );
  const [groupsClaim, setGroupsClaim] = useState(oidcRole?.groups_claim ?? "");
  const [boundAudiences, setBoundAudiences] = useState(
    (oidcRole?.bound_audiences ?? []).join(", "),
  );
  const [boundClaimsJson, setBoundClaimsJson] = useState(
    oidcRole?.bound_claims_json ?? "",
  );

  // SAML-specific state.
  const samlCfg =
    provider?.kind === "saml" ? provider.config : undefined;
  const samlRole = provider?.role?.kind === "saml" ? provider.role : undefined;
  const [samlEntityId, setSamlEntityId] = useState(samlCfg?.entity_id ?? "");
  const [samlAcsUrl, setSamlAcsUrl] = useState(samlCfg?.acs_url ?? "");
  const [samlIdpSsoUrl, setSamlIdpSsoUrl] = useState(samlCfg?.idp_sso_url ?? "");
  const [samlIdpSloUrl, setSamlIdpSloUrl] = useState(samlCfg?.idp_slo_url ?? "");
  const [samlMetadataUrl, setSamlMetadataUrl] = useState(
    samlCfg?.idp_metadata_url ?? "",
  );
  const [samlMetadataXml, setSamlMetadataXml] = useState("");
  const [samlIdpCert, setSamlIdpCert] = useState("");
  const [samlBoundSubjects, setSamlBoundSubjects] = useState(
    (samlRole?.bound_subjects ?? []).join(", "),
  );
  const [samlBoundSubjectsType, setSamlBoundSubjectsType] = useState(
    samlRole?.bound_subjects_type ?? "",
  );
  const [samlBoundAttributesJson, setSamlBoundAttributesJson] = useState(
    samlRole?.bound_attributes_json ?? "",
  );
  const [samlAttributeMappingsJson, setSamlAttributeMappingsJson] = useState(
    samlRole?.attribute_mappings_json ?? "",
  );
  const [samlGroupsAttribute, setSamlGroupsAttribute] = useState(
    samlRole?.groups_attribute ?? "",
  );

  // Shared role fields.
  const [policies, setPolicies] = useState(
    (provider?.role?.policies ?? ["default"]).join(", "),
  );
  const [tokenTtlSecs, setTokenTtlSecs] = useState(
    String(provider?.role?.token_ttl_secs ?? 3600),
  );

  const [hints, setHints] = useState<SsoCallbackHints | null>(null);
  const [saving, setSaving] = useState(false);

  // If the admin flips kind on the Add form, reset the mount-path
  // suggestion so the default is sensible for the new kind.
  useEffect(() => {
    if (!isEdit) {
      setMount(kind === "oidc" ? "oidc" : "saml");
    }
  }, [kind, isEdit]);

  useEffect(() => {
    api
      .ssoAdminCallbackHints(mount.trim() || kind, kind)
      .then(setHints)
      .catch(() => setHints(null));
  }, [mount, kind]);

  function splitList(raw: string): string[] {
    return raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function handleCopy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* ignore; not fatal */
    }
  }

  async function handleSubmit() {
    const common = {
      mount: mount.trim(),
      display_name: displayName.trim(),
      default_role: defaultRole.trim(),
    };
    const ttl = Number.isFinite(Number(tokenTtlSecs))
      ? Math.max(0, Math.floor(Number(tokenTtlSecs)))
      : 0;

    // Build the discriminated-union payload as one atomic object
    // per kind so TS can correlate `kind`, `config.kind`, and
    // `role.kind` at the type level. Splitting them out into
    // separate variables and re-merging trips the union-narrowing.
    const input: SsoAdminInput =
      kind === "oidc"
        ? {
            ...common,
            kind: "oidc",
            config: {
              kind: "oidc",
              discovery_url: discoveryUrl.trim(),
              client_id: clientId.trim(),
              client_secret: clientSecret,
              scopes: splitList(scopes),
              allowed_redirect_uris: splitList(allowedRedirectUris),
            },
            role: {
              kind: "oidc",
              name: defaultRole.trim(),
              user_claim: userClaim.trim(),
              groups_claim: groupsClaim.trim(),
              bound_audiences: splitList(boundAudiences),
              bound_claims_json: boundClaimsJson.trim(),
              policies: splitList(policies),
              token_ttl_secs: ttl,
            },
          }
        : {
            ...common,
            kind: "saml",
            config: {
              kind: "saml",
              entity_id: samlEntityId.trim(),
              acs_url: samlAcsUrl.trim(),
              idp_sso_url: samlIdpSsoUrl.trim(),
              idp_slo_url: samlIdpSloUrl.trim(),
              idp_metadata_url: samlMetadataUrl.trim(),
              idp_metadata_xml: samlMetadataXml,
              idp_cert: samlIdpCert,
              allowed_redirect_uris: splitList(allowedRedirectUris),
            },
            role: {
              kind: "saml",
              name: defaultRole.trim(),
              bound_subjects: splitList(samlBoundSubjects),
              bound_subjects_type: samlBoundSubjectsType.trim(),
              bound_attributes_json: samlBoundAttributesJson.trim(),
              attribute_mappings_json: samlAttributeMappingsJson.trim(),
              groups_attribute: samlGroupsAttribute.trim(),
              policies: splitList(policies),
              token_ttl_secs: ttl,
            },
          };
    setSaving(true);
    try {
      await onSave(input);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? `Edit SSO Provider: ${provider!.display_name || provider!.mount}` : "Add SSO Provider"}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} loading={saving}>
            {isEdit ? "Save Changes" : "Create Provider"}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        {/* ─── Identification ─────────────────────────────────── */}
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            Identification
          </h3>
          {!isEdit && (
            <div>
              <label className="block text-sm font-medium text-[var(--color-text-muted)] mb-1">
                Protocol
              </label>
              <div className="flex gap-2">
                {(["oidc", "saml"] as const).map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setKind(k)}
                    className={`flex-1 py-2 px-3 rounded-lg border text-sm font-medium transition-colors ${
                      kind === k
                        ? "border-[var(--color-primary)] bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                        : "border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                    }`}
                  >
                    {k === "oidc" ? "OpenID Connect" : "SAML 2.0"}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-xs text-[var(--color-text-muted)]">
                {kind === "oidc"
                  ? "Use OIDC for modern IdPs (Okta OAuth, Google, Azure AD app registrations, Auth0)."
                  : "Use SAML 2.0 for legacy / enterprise IdPs (ADFS, Shibboleth, Okta SAML, Azure AD Enterprise Applications)."}
              </p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Display Name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Acme SSO"
              hint="Shown on the 'Sign in with …' button."
            />
            <Input
              label="Mount Path"
              value={mount}
              onChange={(e) =>
                setMount(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ""))
              }
              placeholder={kind === "oidc" ? "oidc" : "saml"}
              disabled={isEdit}
              hint={
                isEdit
                  ? "Mount path is fixed after creation."
                  : "Vault auth-mount path. Lowercase, alphanumeric, - or _."
              }
            />
          </div>
        </section>

        {/* ─── OIDC provider ──────────────────────────────────── */}
        {kind === "oidc" && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            OIDC Provider
          </h3>
          <Input
            label="Discovery URL"
            value={discoveryUrl}
            onChange={(e) => setDiscoveryUrl(e.target.value)}
            placeholder="https://login.example.com"
            hint="The IdP issuer URL. The vault appends /.well-known/openid-configuration."
          />
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Client ID"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder="1234abcd-..."
            />
            <Input
              label="Client Secret"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder={
                isEdit && oidcCfg?.client_secret_set
                  ? "••••••• (leave blank to keep)"
                  : "(leave blank for PKCE-only)"
              }
              hint={
                isEdit && oidcCfg?.client_secret_set
                  ? "Blank leaves the stored secret unchanged."
                  : "Omit for public/PKCE clients. Never surfaced on read."
              }
            />
          </div>
          <Input
            label="Scopes"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            placeholder="openid, profile, email"
            hint={`Comma-separated. Common: ${COMMON_OIDC_SCOPES.join(", ")}.`}
          />
        </section>
        )}

        {/* ─── SAML provider ──────────────────────────────────── */}
        {kind === "saml" && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            SAML 2.0 Provider
          </h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            SAML identifies the Service Provider (this vault) by its
            entity ID and the Assertion Consumer Service (ACS) URL.
            Configure one IdP metadata source — either a metadata URL,
            inline metadata XML, or an SSO URL + signing certificate
            pair for air-gapped setups.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="SP Entity ID"
              value={samlEntityId}
              onChange={(e) => setSamlEntityId(e.target.value)}
              placeholder="https://vault.example.com/saml"
              hint="Identifies this SP on Issuer + Audience. Register it with your IdP."
            />
            <Input
              label="ACS URL"
              value={samlAcsUrl}
              onChange={(e) => setSamlAcsUrl(e.target.value)}
              placeholder="https://vault.example.com/v1/auth/saml/callback"
              hint="Where the IdP POSTs the signed SAML Response."
            />
          </div>
          <Input
            label="IdP Metadata URL"
            value={samlMetadataUrl}
            onChange={(e) => setSamlMetadataUrl(e.target.value)}
            placeholder="https://idp.example.com/metadata"
            hint="Preferred. Lets the IdP rotate certs without re-configuring the vault."
          />
          <label className="block text-sm text-[var(--color-text-muted)]">
            <span className="block mb-1">
              Inline IdP Metadata XML {samlCfg?.idp_metadata_xml_set && (
                <span className="text-[var(--color-text)]">(set — blank to keep)</span>
              )}
            </span>
            <textarea
              value={samlMetadataXml}
              onChange={(e) => setSamlMetadataXml(e.target.value)}
              placeholder="<EntityDescriptor>…</EntityDescriptor>"
              rows={3}
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
            />
            <span className="text-xs">
              Alternative to a metadata URL for air-gapped / offline IdPs.
              Redacted on read.
            </span>
          </label>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="IdP SSO URL"
              value={samlIdpSsoUrl}
              onChange={(e) => setSamlIdpSsoUrl(e.target.value)}
              placeholder="https://idp.example.com/sso"
              hint="Only needed if you skip metadata. Paired with IdP Cert below."
            />
            <Input
              label="IdP Logout URL"
              value={samlIdpSloUrl}
              onChange={(e) => setSamlIdpSloUrl(e.target.value)}
              placeholder="https://idp.example.com/slo"
              hint="Optional. Single-logout endpoint."
            />
          </div>
          <label className="block text-sm text-[var(--color-text-muted)]">
            <span className="block mb-1">
              IdP Signing Certificate (PEM) {samlCfg?.idp_cert_set && (
                <span className="text-[var(--color-text)]">(set — blank to keep)</span>
              )}
            </span>
            <textarea
              value={samlIdpCert}
              onChange={(e) => setSamlIdpCert(e.target.value)}
              placeholder={"-----BEGIN CERTIFICATE-----\nMIIC…\n-----END CERTIFICATE-----"}
              rows={4}
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
            />
            <span className="text-xs">
              Used to verify the RSA-SHA256 / RSA-SHA1 signature on incoming
              assertions. Redacted on read.
            </span>
          </label>
        </section>
        )}

        {/* ─── Redirect URIs ──────────────────────────────────── */}
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            Allowed Redirect URIs
          </h3>
          {hints && (
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] space-y-2">
              <div className="flex items-center gap-2 text-xs">
                <Badge
                  label={hints.mode === "embedded" ? "Desktop" : "Remote"}
                  variant="info"
                />
                <span className="text-[var(--color-text-muted)]">
                  Register this with your IdP:
                </span>
              </div>
              {hints.suggested.map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <code className="flex-1 text-xs font-mono bg-[var(--color-surface)] px-2 py-1 rounded border border-[var(--color-border)] truncate">
                    {s}
                  </code>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleCopy(s)}
                  >
                    Copy
                  </Button>
                </div>
              ))}
              {hints.notes.map((n, i) => (
                <p key={i} className="text-xs text-[var(--color-text-muted)]">
                  {n}
                </p>
              ))}
            </div>
          )}
          <label className="block text-sm text-[var(--color-text-muted)]">
            <span className="block mb-1">
              Redirect URIs the vault will accept on callback
            </span>
            <textarea
              value={allowedRedirectUris}
              onChange={(e) => setAllowedRedirectUris(e.target.value)}
              placeholder="http://127.0.0.1/callback&#10;https://vault.example.com/v1/auth/oidc/callback"
              rows={3}
              className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
            />
            <span className="text-xs">
              One per line or comma-separated. Leave blank to accept any URI
              (development only).
            </span>
          </label>
        </section>

        {/* ─── Default role ───────────────────────────────────── */}
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            Default Role
          </h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            {kind === "oidc"
              ? "Users sign in through this role. It names the vault policies to attach and which claim identifies the user."
              : "Users sign in through this role. It names the vault policies to attach and which SAML attributes / subjects are accepted."}
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Role Name"
              value={defaultRole}
              onChange={(e) =>
                setDefaultRole(e.target.value.replace(/[^a-zA-Z0-9_-]/g, ""))
              }
              placeholder="user"
            />
            <Input
              label="Token TTL (seconds)"
              type="number"
              value={tokenTtlSecs}
              onChange={(e) => setTokenTtlSecs(e.target.value)}
              placeholder="3600"
              hint="0 = token store default."
            />
          </div>

          {kind === "oidc" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label="User Claim"
                  value={userClaim}
                  onChange={(e) => setUserClaim(e.target.value)}
                  placeholder="preferred_username"
                  hint="Claim used as the principal's display name."
                />
                <Input
                  label="Groups Claim"
                  value={groupsClaim}
                  onChange={(e) => setGroupsClaim(e.target.value)}
                  placeholder="groups"
                  hint="Optional. Claim carrying the user's groups list."
                />
              </div>
              <Input
                label="Bound Audiences"
                value={boundAudiences}
                onChange={(e) => setBoundAudiences(e.target.value)}
                placeholder="my-client-id"
                hint="Comma-separated. If set, the ID token's aud must match one."
              />
              <label className="block text-sm text-[var(--color-text-muted)]">
                <span className="block mb-1">Bound Claims (JSON)</span>
                <textarea
                  value={boundClaimsJson}
                  onChange={(e) => setBoundClaimsJson(e.target.value)}
                  placeholder='{"hd":["example.com"]}'
                  rows={2}
                  className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
                />
                <span className="text-xs">
                  Optional JSON object of claim → allowed-values. Login is
                  denied if any listed claim is missing or doesn't match.
                </span>
              </label>
            </>
          )}

          {kind === "saml" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label="Groups Attribute"
                  value={samlGroupsAttribute}
                  onChange={(e) => setSamlGroupsAttribute(e.target.value)}
                  placeholder="groups"
                  hint="Optional. SAML attribute carrying the user's groups."
                />
                <Input
                  label="Bound Subjects Type"
                  value={samlBoundSubjectsType}
                  onChange={(e) => setSamlBoundSubjectsType(e.target.value)}
                  placeholder="emailAddress"
                  hint="Optional. Required NameID Format (e.g. `emailAddress`, `persistent`)."
                />
              </div>
              <Input
                label="Bound Subjects"
                value={samlBoundSubjects}
                onChange={(e) => setSamlBoundSubjects(e.target.value)}
                placeholder="alice@example.com, bob@example.com"
                hint="Optional comma-separated NameID allow-list. Empty = any subject."
              />
              <label className="block text-sm text-[var(--color-text-muted)]">
                <span className="block mb-1">Bound Attributes (JSON)</span>
                <textarea
                  value={samlBoundAttributesJson}
                  onChange={(e) => setSamlBoundAttributesJson(e.target.value)}
                  placeholder='{"department":["engineering","sre"]}'
                  rows={2}
                  className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
                />
                <span className="text-xs">
                  Optional JSON object of SAML attribute → allowed-values.
                  Login is denied if any listed attribute is missing or
                  doesn't match.
                </span>
              </label>
              <label className="block text-sm text-[var(--color-text-muted)]">
                <span className="block mb-1">Attribute Mappings (JSON)</span>
                <textarea
                  value={samlAttributeMappingsJson}
                  onChange={(e) => setSamlAttributeMappingsJson(e.target.value)}
                  placeholder='{"email":"email","displayName":"name"}'
                  rows={2}
                  className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-[var(--color-primary)]"
                />
                <span className="text-xs">
                  Optional JSON object of SAML attribute → vault-metadata
                  key. Renames attributes before they land on the vault token.
                </span>
              </label>
            </>
          )}

          <Input
            label="Policies"
            value={policies}
            onChange={(e) => setPolicies(e.target.value)}
            placeholder="default, readonly"
            hint="Comma-separated. At least one is required."
          />
        </section>
      </div>
    </Modal>
  );
}
