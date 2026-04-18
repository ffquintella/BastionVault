import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Button, Card, Badge, Input, Select, Modal, ConfirmModal, useToast } from "../components/ui";
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
  }, [loadPasswordPolicy]);

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
