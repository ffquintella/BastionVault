import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, Input, Select, Modal, ConfirmModal, useToast } from "../components/ui";
import { useVaultStore } from "../stores/vaultStore";
import { useAuthStore } from "../stores/authStore";
import type { Fido2Config, ResourceTypeConfig, ResourceTypeDef, ResourceFieldDef } from "../lib/types";
import { DEFAULT_RESOURCE_TYPES, mergeTypeConfig } from "../lib/resourceTypes";
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

  useEffect(() => {
    loadFido2Config();
    loadResourceTypes();
  }, []);

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
];

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
              <div key={i} className="flex gap-2 items-end">
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
                <Input label={i === 0 ? "Placeholder" : undefined} value={f.placeholder ?? ""}
                  onChange={(e) => updateFieldDef(i, { placeholder: e.target.value })}
                  placeholder="Hint text" />
                <button onClick={() => removeField(i)}
                  className="text-[var(--color-danger)] hover:text-red-400 text-lg pb-1 shrink-0">&times;</button>
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
