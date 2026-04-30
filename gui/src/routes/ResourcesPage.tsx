import { useState, useEffect } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Card,
  Input,
  MaskedValue,
  Select,
  Textarea,
  Badge,
  Breadcrumb,
  Tabs,
  Table,
  Modal,
  ConfirmModal,
  EmptyState,
  EntityLabel,
  EntityPicker,
  GroupsSection,
  SecretPairsEditor,
  SecretHistoryPanel,
  ResourceHistoryPanel,
  pairsFromData,
  dataFromPairs,
  type SecretPair,
  type SecretHistoryVersion,
  useToast,
} from "../components/ui";
import type {
  ResourceMetadata,
  ResourceTypeConfig,
  ResourceTypeDef,
  ResourceFieldDef,
  ResourceHistoryEntry,
  ShareEntry,
  OwnerInfo,
  FileMeta,
  ConnectionProfile,
  CredentialSource,
  SessionProtocol,
  RecentSession,
} from "../lib/types";
import { DEFAULT_RESOURCE_TYPES, mergeTypeConfig, getTypeDef, inferOsType } from "../lib/resourceTypes";
import {
  blankProfile,
  defaultPort,
  detectSecretShape,
  protocolForOsType,
  readProfiles,
  validateProfile,
} from "../lib/connectionProfiles";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { useAuthStore } from "../stores/authStore";
import { useAssetGroupMap } from "../hooks/useAssetGroupMap";

function parseTags(tags: unknown): string[] {
  if (Array.isArray(tags)) return tags.filter(Boolean);
  if (typeof tags === "string" && tags) return tags.split(",").map((t) => t.trim()).filter(Boolean);
  return [];
}

export function ResourcesPage() {
  const { toast } = useToast();
  const [, setResources] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [resourceInfo, setResourceInfo] = useState<ResourceMetadata | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<
    "info" | "secrets" | "files" | "connection" | "sharing" | "history"
  >("info");
  const [filterType, setFilterType] = useState("");
  const [filterGroup, setFilterGroup] = useState("");
  const [search, setSearch] = useState("");
  const [allMeta, setAllMeta] = useState<ResourceMetadata[]>([]);
  const [typeConfig, setTypeConfig] = useState<ResourceTypeConfig>(DEFAULT_RESOURCE_TYPES);
  const assetGroups = useAssetGroupMap();

  useEffect(() => {
    loadTypeConfig();
    loadResources();
  }, []);

  async function loadTypeConfig() {
    try {
      const saved = await api.resourceTypesRead();
      setTypeConfig(mergeTypeConfig(saved as ResourceTypeConfig | null));
    } catch {
      setTypeConfig(DEFAULT_RESOURCE_TYPES);
    }
  }

  async function loadResources() {
    setLoading(true);
    try {
      const result = await api.listResources();
      setResources(result.resources);
      const metas = await Promise.all(
        result.resources.map((name) => api.readResource(name).catch(() => null)),
      );
      setAllMeta(metas.filter((m): m is ResourceMetadata => m !== null));
    } catch {
      setResources([]);
      setAllMeta([]);
    } finally {
      setLoading(false);
    }
  }

  async function selectResource(name: string) {
    try {
      const info = await api.readResource(name);
      setSelected(name);
      setResourceInfo(info);
      setDetailTab("info");
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteResource(deleteTarget);
      toast("success", `Resource ${deleteTarget} deleted`);
      if (selected === deleteTarget) { setSelected(null); setResourceInfo(null); }
      setDeleteTarget(null);
      loadResources();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  const filteredMeta = allMeta.filter((m) => {
    if (filterType && m.type !== filterType) return false;
    if (filterGroup) {
      const groups = assetGroups.map.byResource[String(m.name)] || [];
      if (!groups.includes(filterGroup)) return false;
    }
    if (search) {
      const q = search.toLowerCase();
      const name = String(m.name || "").toLowerCase();
      const hostname = String(m.hostname || "").toLowerCase();
      const ip = String(m.ip_address || "");
      const tags = String(m.tags || "").toLowerCase();
      return name.includes(q) || hostname.includes(q) || ip.includes(q) || tags.includes(q);
    }
    return true;
  });

  // All group names referenced by the currently loaded resources —
  // used to populate the filter dropdown so operators only see groups
  // they can actually filter by.
  const groupOptionsSet = new Set<string>();
  for (const m of allMeta) {
    for (const g of assetGroups.map.byResource[String(m.name)] || []) {
      groupOptionsSet.add(g);
    }
  }
  const groupOptions = Array.from(groupOptionsSet).sort();

  const typeOptions = Object.values(typeConfig).map((t) => ({ value: t.id, label: t.label }));
  const filterOptions = [{ value: "", label: "All types" }, ...typeOptions];

  // ── Detail view ──────────────────────────────────────────────────
  if (selected && resourceInfo) {
    const typeDef = getTypeDef(typeConfig, String(resourceInfo.type || ""));
    return (
      <Layout>
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <button onClick={() => { setSelected(null); setResourceInfo(null); }}
              className="text-[var(--color-text-muted)] hover:text-[var(--color-text)]">&larr; Back</button>
            <h1 className="text-2xl font-bold">{String(resourceInfo.name)}</h1>
            <Badge label={typeDef.label} variant={typeDef.color} />
          </div>

          <Card>
            <Tabs
              tabs={[
                { id: "info", label: "Info" },
                { id: "secrets", label: "Secrets" },
                { id: "files", label: "Files" },
                // Connection tab is server-only — the Connect button
                // dispatches on os_type, which only exists on the
                // server resource type. Also hidden when the
                // operator disabled Connect for this type via
                // Settings (Phase 7 per-type policy).
                ...(String(resourceInfo.type || "") === "server" &&
                typeDef.connect?.enabled !== false
                  ? [{ id: "connection", label: "Connection" }]
                  : []),
                { id: "sharing", label: "Sharing" },
                { id: "history", label: "History" },
              ]}
              active={detailTab}
              onChange={(t) =>
                setDetailTab(
                  t as "info" | "secrets" | "files" | "connection" | "sharing" | "history",
                )
              }
            />
          </Card>

          {detailTab === "info" && (
            <ResourceInfoCard
              resource={resourceInfo}
              typeDef={typeDef}
              onUpdate={() => selectResource(selected)}
              onDelete={() => setDeleteTarget(selected)}
              toast={toast}
            />
          )}

          {detailTab === "secrets" && (
            <ResourceSecretsPanel resourceName={String(resourceInfo.name)} toast={toast} />
          )}

          {detailTab === "files" && (
            <ResourceFilesPanel resourceName={String(resourceInfo.name)} toast={toast} />
          )}

          {detailTab === "connection" && (
            <ConnectionProfilesPanel
              resource={resourceInfo}
              onUpdated={() => selectResource(selected)}
              toast={toast}
            />
          )}

          {detailTab === "sharing" && (
            <ResourceSharingCard resourceName={String(resourceInfo.name)} toast={toast} />
          )}

          {detailTab === "history" && (
            <ResourceMetadataHistoryCard resourceName={String(resourceInfo.name)} toast={toast} />
          )}

          <ConfirmModal open={deleteTarget !== null} onClose={() => setDeleteTarget(null)}
            onConfirm={handleDelete} title="Delete Resource"
            message={`Delete "${deleteTarget}" and all its secrets? This cannot be undone.`}
            confirmLabel="Delete" />
        </div>
      </Layout>
    );
  }

  // ── List view ────────────────────────────────────────────────────
  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Resources</h1>
          <Button size="sm" onClick={() => setShowCreate(true)}>Add Resource</Button>
        </div>

        {/* Breadcrumb-style path indicator. Shows the active filter as
            a drill-down path ("All resources / <group>") so the user
            always knows where in the group hierarchy they are. The
            "All resources" segment clears the filter. */}
        <Breadcrumb
          segments={
            filterGroup
              ? [
                  { label: "All resources", onClick: () => setFilterGroup("") },
                  { label: filterGroup },
                ]
              : [{ label: "All resources" }]
          }
        />

        <div className="flex gap-3">
          <Input placeholder="Search by name, hostname" value={search}
            onChange={(e) => setSearch(e.target.value)} />
          <Select value={filterType} onChange={(e) => setFilterType(e.target.value)}
            options={filterOptions} />
        </div>

        <GroupsSection
          groups={groupOptions.map((name) => ({
            name,
            count: allMeta.filter((m) =>
              (assetGroups.map.byResource[String(m.name)] || []).includes(name),
            ).length,
          }))}
          selected={filterGroup || null}
          onSelect={(name) => setFilterGroup(name ?? "")}
          itemKindPlural="resources"
        />

        {loading ? (
          <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
        ) : filteredMeta.length === 0 ? (
          <EmptyState title="No resources"
            description="Add your first resource to start organizing secrets by infrastructure"
            action={<Button size="sm" onClick={() => setShowCreate(true)}>Add Resource</Button>} />
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredMeta.map((meta) => {
              const td = getTypeDef(typeConfig, String(meta.type));
              const groups = assetGroups.map.byResource[String(meta.name)] || [];
              const quickProfile = pickQuickLaunchProfile(meta, td);
              return (
                <button key={String(meta.name)} onClick={() => selectResource(String(meta.name))}
                  className="p-4 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl text-left hover:border-[var(--color-primary)] transition-colors">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-medium truncate flex-1 min-w-0">{String(meta.name)}</span>
                    <Badge label={td.label} variant={td.color} />
                    {quickProfile && (
                      <ConnectQuickButton
                        resource={meta}
                        profile={quickProfile}
                        toast={toast}
                      />
                    )}
                  </div>
                  {meta.hostname ? <p className="text-xs text-[var(--color-text-muted)] truncate">{String(meta.hostname)}{meta.ip_address ? ` (${String(meta.ip_address)})` : ""}</p> : null}
                  {groups.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {groups.map((g) => (
                        <span
                          key={g}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            setFilterGroup((cur) => (cur === g ? "" : g));
                          }}
                          className="px-1.5 py-0.5 bg-[var(--color-primary)] text-white rounded text-[10px] cursor-pointer hover:opacity-80"
                          title={`Filter by group "${g}"`}
                        >
                          {g}
                        </span>
                      ))}
                    </div>
                  )}
                  {parseTags(meta.tags).length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {parseTags(meta.tags).slice(0, 4).map((t) => (
                        <span key={t} className="px-1.5 py-0.5 bg-[var(--color-bg)] rounded text-[10px] text-[var(--color-text-muted)]">{t}</span>
                      ))}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        )}

        <CreateResourceModal open={showCreate} onClose={() => setShowCreate(false)}
          typeConfig={typeConfig}
          onCreated={() => { setShowCreate(false); loadResources(); }}
          toast={toast} />

        <ConfirmModal open={deleteTarget !== null} onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete} title="Delete Resource"
          message={`Delete "${deleteTarget}" and all its secrets?`} confirmLabel="Delete" />
      </div>
    </Layout>
  );
}

// ── Resource Info Card ─────────────────────────────────────────────

function ResourceInfoCard({ resource, typeDef, onUpdate, onDelete, toast }: {
  resource: ResourceMetadata;
  typeDef: ResourceTypeDef;
  onUpdate: () => void;
  onDelete: () => void;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Record<string, unknown>>({ ...resource });

  function updateField(key: string, value: unknown) {
    setForm((prev) => {
      const next = { ...prev, [key]: value };
      // Same migration heuristic as the create modal — when editing
      // a server resource that pre-dates the os_type field, typing
      // into the free-form `os` field auto-fills os_type if the
      // operator hasn't already picked one.
      if (
        String(prev["type"] ?? "") === "server" &&
        key === "os" &&
        typeof value === "string" &&
        !String(prev["os_type"] ?? "").trim()
      ) {
        const inferred = inferOsType(value);
        if (inferred) next["os_type"] = inferred;
      }
      return next;
    });
  }

  async function handleSave() {
    try {
      await api.writeResource(String(resource.name), form as ResourceMetadata);
      toast("success", "Resource updated");
      setEditing(false);
      onUpdate();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  if (!editing) {
    return (
      <Card actions={
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={() => { setForm({ ...resource }); setEditing(true); }}>Edit</Button>
          <Button size="sm" variant="danger" onClick={onDelete}>Delete</Button>
        </div>
      }>
        <div className="grid grid-cols-2 gap-4 text-sm">
          {typeDef.fields.map((f) => (
            <div key={f.key}>
              <span className="text-[var(--color-text-muted)] text-xs">{f.label}</span>
              <p className="font-mono text-sm">{String(resource[f.key] ?? "-")}</p>
            </div>
          ))}
          <div className="col-span-2">
            <span className="text-[var(--color-text-muted)] text-xs">Tags</span>
            <div className="flex flex-wrap gap-1 mt-1">
              {parseTags(resource.tags).length > 0
                ? parseTags(resource.tags).map((t) => <Badge key={t} label={t} variant="neutral" />)
                : <span className="text-[var(--color-text-muted)]">-</span>}
            </div>
          </div>
          {resource.notes && (
            <div className="col-span-2">
              <span className="text-[var(--color-text-muted)] text-xs">Notes</span>
              <p className="whitespace-pre-wrap text-sm">{String(resource.notes)}</p>
            </div>
          )}
          <div>
            <span className="text-[var(--color-text-muted)] text-xs">Created</span>
            <p className="text-xs">{resource.created_at ? new Date(String(resource.created_at)).toLocaleString() : "-"}</p>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)] text-xs">Updated</span>
            <p className="text-xs">{resource.updated_at ? new Date(String(resource.updated_at)).toLocaleString() : "-"}</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card actions={
      <div className="flex gap-2">
        <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
        <Button size="sm" onClick={handleSave}>Save</Button>
      </div>
    }>
      <DynamicFieldsForm fields={typeDef.fields} values={form} onChange={updateField} showErrors />
      <div className="mt-3 space-y-3">
        <Input label="Tags" value={String(form.tags ?? "")} onChange={(e) => updateField("tags", e.target.value)}
          placeholder="production, web" hint="Comma-separated" />
        <Textarea label="Notes" value={String(form.notes ?? "")} onChange={(e) => updateField("notes", e.target.value)} />
      </div>
    </Card>
  );
}

// ── Validation ─────────────────────────────────────────────────────

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const FQDN_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$/;

function validateField(type: string, value: string): string | null {
  if (!value) return null; // empty is OK (not required)
  switch (type) {
    case "ip":
      if (!IPV4_RE.test(value) && !IPV6_RE.test(value))
        return "Invalid IP address (IPv4 or IPv6)";
      return null;
    case "fqdn":
      if (!FQDN_RE.test(value) || value.length > 253)
        return "Invalid hostname (FQDN)";
      return null;
    case "url":
      try { new URL(value); return null; }
      catch { return "Invalid URL"; }
    default:
      return null;
  }
}

// ── Dynamic Fields Form ────────────────────────────────────────────

function DynamicFieldsForm({ fields, values, onChange, showErrors }: {
  fields: ResourceFieldDef[];
  values: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
  showErrors?: boolean;
}) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {fields.map((f) => {
        const val = String(values[f.key] ?? "");
        const error = showErrors ? validateField(f.type, val) : null;
        return (
          <div key={f.key}>
            {f.type === "select" ? (
              <Select
                label={f.label}
                value={val}
                onChange={(e) => onChange(f.key, e.target.value)}
                options={f.options ?? []}
              />
            ) : (
              <Input
                label={f.label}
                type={f.type === "number" ? "number" : "text"}
                value={val}
                onChange={(e) => onChange(f.key, f.type === "number" ? (parseInt(e.target.value) || 0) : e.target.value)}
                placeholder={f.placeholder}
                hint={f.type === "ip" ? "IPv4 or IPv6" : f.type === "fqdn" ? "Fully qualified domain name" : undefined}
              />
            )}
            {error && <p className="text-xs text-[var(--color-danger)] mt-0.5">{error}</p>}
          </div>
        );
      })}
    </div>
  );
}

/** Check if all validated fields pass. */
function hasValidationErrors(fields: ResourceFieldDef[], values: Record<string, unknown>): boolean {
  return fields.some((f) => validateField(f.type, String(values[f.key] ?? "")) !== null);
}

// ── Create Resource Modal ──────────────────────────────────────────

function CreateResourceModal({ open, onClose, typeConfig, onCreated, toast }: {
  open: boolean;
  onClose: () => void;
  typeConfig: ResourceTypeConfig;
  onCreated: () => void;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [name, setName] = useState("");
  const [typeId, setTypeId] = useState(Object.keys(typeConfig)[0] || "server");
  const [customType, setCustomType] = useState("");
  const [fields, setFields] = useState<Record<string, unknown>>({});
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");

  const typeOptions = [
    ...Object.values(typeConfig).map((t) => ({ value: t.id, label: t.label })),
    { value: "_custom", label: "Custom..." },
  ];
  const typeDef = typeId === "_custom" ? null : getTypeDef(typeConfig, typeId);

  function updateField(key: string, value: unknown) {
    setFields((prev) => {
      const next = { ...prev, [key]: value };
      // Migration heuristic: when the operator types into the
      // free-form `os` field on a server resource and `os_type`
      // is still unset, infer it. Operator can override via the
      // dropdown; we never overwrite a user-set value.
      if (
        typeId === "server" &&
        key === "os" &&
        typeof value === "string" &&
        !String(prev["os_type"] ?? "").trim()
      ) {
        const inferred = inferOsType(value);
        if (inferred) next["os_type"] = inferred;
      }
      return next;
    });
  }

  async function handleCreate() {
    if (!name) return;
    const resolvedType = typeId === "_custom" ? customType : typeId;
    const meta: ResourceMetadata = {
      name,
      type: resolvedType,
      tags,
      notes,
      created_at: "",
      updated_at: "",
      ...fields,
    };
    try {
      await api.writeResource(name, meta);
      toast("success", `Resource ${name} created`);
      setName(""); setTypeId(Object.keys(typeConfig)[0] || "server");
      setCustomType(""); setFields({}); setTags(""); setNotes("");
      onCreated();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Add Resource" size="lg"
      actions={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={handleCreate} disabled={!name || (typeId === "_custom" && !customType) || (typeDef ? hasValidationErrors(typeDef.fields, fields) : false)}>Create</Button>
      </>}>
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="web-server-01" />
          <div className="space-y-1">
            <Select label="Type" value={typeId} onChange={(e) => { setTypeId(e.target.value); setFields({}); }} options={typeOptions} />
            {typeId === "_custom" && (
              <Input placeholder="Custom type name" value={customType} onChange={(e) => setCustomType(e.target.value)} />
            )}
          </div>
        </div>
        {typeDef && <DynamicFieldsForm fields={typeDef.fields} values={fields} onChange={updateField} showErrors />}
        <Input label="Tags" value={tags} onChange={(e) => setTags(e.target.value)}
          placeholder="production, web, linux" hint="Comma-separated" />
        <Textarea label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)}
          placeholder="Additional information..." />
      </div>
    </Modal>
  );
}

// ── Connection Profiles (Phase 2 — Secret source) ─────────────────

/**
 * Lists every ConnectionProfile on the resource, lets the operator
 * add / edit / delete them. Profiles persist as a key inside the
 * resource's flexible metadata bag — no backend schema change.
 *
 * Phase 2 ships the **Secret** credential source (a credential-shaped
 * resource secret with username + password / private_key). The
 * other three sources (LDAP, SSH-engine, PKI) are stubbed in the
 * editor and surface a "ships in Phase N" hint until those phases
 * land.
 */
function ConnectionProfilesPanel({
  resource,
  onUpdated,
  toast,
}: {
  resource: ResourceMetadata;
  onUpdated: () => void;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const profiles = readProfiles(resource as Record<string, unknown>);
  const osType = String(resource["os_type"] ?? "");
  const osTypeProtocol = protocolForOsType(osType);
  const [editTarget, setEditTarget] = useState<ConnectionProfile | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<ConnectionProfile | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);

  // What ships today by (protocol, source) combo:
  //   - SSH+Secret: Phase 3
  //   - RDP+Secret: Phase 4 (Standard Security; no NLA)
  //   - SSH+LDAP / RDP+LDAP: Phase 5 (operator / static / library)
  //   - SSH+PKI: Phase 6 (issued cert's private_key as a russh
  //     publickey credential)
  //   - RDP+PKI: pending CredSSP smartcard wiring
  //   - SSH-engine: pending
  const launchableProfiles = profiles.filter((p) => {
    if (p.protocol !== "ssh" && p.protocol !== "rdp") return false;
    switch (p.credential_source.kind) {
      case "secret":
      case "ldap":
      case "pki":
        // SSH+PKI: russh publickey via the PKI-issued key.
        // RDP+PKI: CredSSP smartcard via sspi-rs's PIV emulator.
        return true;
      case "ssh-engine":
        return false;
    }
  });

  // LDAP operator-bind mode requires a credential prompt before
  // the open call. We surface it as a tiny inline modal; on
  // submit it forwards the typed user/password through the open
  // request's `operator_credential` field.
  const [operatorPrompt, setOperatorPrompt] = useState<ConnectionProfile | null>(null);

  async function handleConnect(profile: ConnectionProfile) {
    if (
      profile.credential_source.kind === "ldap" &&
      profile.credential_source.bind_mode === "operator"
    ) {
      setOperatorPrompt(profile);
      return;
    }
    await runConnect(profile, undefined);
  }

  async function runConnect(
    profile: ConnectionProfile,
    operatorCredential: { username: string; password: string } | undefined,
  ) {
    setConnecting(profile.id);
    try {
      if (profile.protocol === "ssh") {
        await api.sessionOpenSsh({
          resource_name: String(resource.name),
          profile_id: profile.id,
          operator_credential: operatorCredential,
        });
      } else {
        await api.sessionOpenRdp({
          resource_name: String(resource.name),
          profile_id: profile.id,
          operator_credential: operatorCredential,
        });
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setConnecting(null);
    }
  }

  async function persist(next: ConnectionProfile[]) {
    try {
      const updated: ResourceMetadata = {
        ...(resource as ResourceMetadata),
        connection_profiles: next as unknown as ResourceMetadata["connection_profiles"],
      };
      await api.writeResource(String(resource.name), updated);
      onUpdated();
      toast("success", "Connection profiles saved");
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleSaveProfile(p: ConnectionProfile) {
    const idx = profiles.findIndex((x) => x.id === p.id);
    const next = idx >= 0 ? [...profiles] : [...profiles, p];
    if (idx >= 0) next[idx] = p;
    await persist(next);
    setEditTarget(null);
    setCreating(false);
  }

  async function handleDeleteProfile(p: ConnectionProfile) {
    const next = profiles.filter((x) => x.id !== p.id);
    await persist(next);
    setConfirmDelete(null);
  }

  return (
    <Card>
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-lg font-medium">Connection profiles</h2>
            <p className="text-xs text-[var(--color-text-muted)]">
              Bind a (protocol, target, credential) combination so the
              Connect button can launch a session in one click.
            </p>
          </div>
          <Button onClick={() => setCreating(true)}>+ Add profile</Button>
        </div>

        {!osType && (
          <div className="rounded border border-yellow-700 bg-yellow-950/40 text-yellow-200 px-3 py-2 text-sm">
            Set <strong>OS Type</strong> on this resource (Info tab) so
            the Connect button knows which protocol to dispatch.
          </div>
        )}
        {osType && !osTypeProtocol && (
          <div className="rounded border border-yellow-700 bg-yellow-950/40 text-yellow-200 px-3 py-2 text-sm">
            <code>os_type = {osType}</code> — Connect is disabled for
            this OS type. Profiles can still be saved for future use.
          </div>
        )}

        {profiles.length === 0 && (
          <p className="text-sm text-[var(--color-text-muted)]">
            No profiles configured yet.
          </p>
        )}

        <div className="space-y-2">
          {profiles.map((p) => (
            <div
              key={p.id}
              className="flex items-start justify-between gap-3 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <strong className="truncate">{p.name}</strong>
                  <Badge label={p.protocol.toUpperCase()} />
                </div>
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs text-[var(--color-text-muted)] mt-1">
                  <dt>target</dt>
                  <dd className="font-mono break-all">
                    {p.target_host || (resource["hostname"] as string) || (resource["ip_address"] as string) || "—"}
                    :
                    {p.target_port ?? defaultPort(p.protocol)}
                  </dd>
                  <dt>user</dt>
                  <dd className="font-mono">{p.username || "(default)"}</dd>
                  <dt>cred</dt>
                  <dd className="font-mono">{describeCredentialSource(p.credential_source)}</dd>
                </dl>
              </div>
              <div className="flex flex-col gap-1 shrink-0">
                {launchableProfiles.some((lp) => lp.id === p.id) ? (
                  <Button
                    size="sm"
                    onClick={() => handleConnect(p)}
                    disabled={connecting !== null}
                    title={
                      p.credential_source.kind === "pki" && p.protocol === "rdp"
                        ? "PKI + RDP: vault-issued cert wraps as a synthetic PIV smartcard for CredSSP / NLA negotiation."
                        : p.credential_source.kind === "pki"
                          ? "PKI + SSH: fresh leaf cert issued per session; SSH uses the private_key as a russh credential."
                          : p.protocol === "rdp"
                            ? "RDP: Standard Security with password, or NLA / CredSSP smartcard with PKI."
                            : undefined
                    }
                  >
                    {connecting === p.id ? "Connecting…" : "Connect"}
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    disabled
                    title="Connect for this combination ships in a later phase"
                  >
                    Connect
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => setEditTarget(p)}>
                  Edit
                </Button>
                <Button size="sm" variant="danger" onClick={() => setConfirmDelete(p)}>
                  Delete
                </Button>
              </div>
            </div>
          ))}
        </div>

        {launchableProfiles.length === 0 && profiles.length > 0 && (
          <p className="text-xs text-[var(--color-text-muted)]">
            Connect launches today for SSH+Secret and RDP+Secret
            profiles. LDAP / SSH-engine / PKI credential sources
            land in Phases 5–6.
          </p>
        )}

        <RecentSessionsList resource={resource} />

        <p className="text-xs text-[var(--color-text-muted)]">
          Connect launches an in-app session window for SSH × {"{"}
          Secret, LDAP, PKI{"}"} (xterm.js + russh) and RDP × {"{"}
          Secret, LDAP, PKI{"}"} (canvas + ironrdp). RDP+PKI
          negotiates CredSSP smartcard auth via sspi-rs's PIV
          emulator using the vault-issued cert + key. The SSH
          secret-engine source remains pending its own follow-up.
        </p>
      </div>

      {(creating || editTarget) && (
        <ConnectionProfileEditor
          open
          resource={resource}
          existing={editTarget}
          onClose={() => {
            setCreating(false);
            setEditTarget(null);
          }}
          onSave={handleSaveProfile}
          toast={toast}
        />
      )}

      <ConfirmModal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && handleDeleteProfile(confirmDelete)}
        title="Delete connection profile"
        message={`Delete profile "${confirmDelete?.name}"? Resource secrets and the resource itself stay intact.`}
        variant="danger"
      />

      {operatorPrompt && (
        <OperatorBindPrompt
          profile={operatorPrompt}
          onCancel={() => setOperatorPrompt(null)}
          onSubmit={async (oc) => {
            const p = operatorPrompt;
            setOperatorPrompt(null);
            await runConnect(p, oc);
          }}
        />
      )}
    </Card>
  );
}

/**
 * Inline modal for the LDAP operator-bind credential source. The
 * operator types user + password; we forward both to the host's
 * session-open command. Credentials never persist anywhere — the
 * modal closes on submit and the typed password lives only as
 * long as the request to the host.
 */
function OperatorBindPrompt({
  profile,
  onCancel,
  onSubmit,
}: {
  profile: ConnectionProfile;
  onCancel: () => void;
  onSubmit: (oc: { username: string; password: string }) => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    if (!username || !password || submitting) return;
    setSubmitting(true);
    try {
      await onSubmit({ username, password });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      open
      onClose={onCancel}
      title={`LDAP credentials · ${profile.name}`}
      size="sm"
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!username || !password || submitting}>
            {submitting ? "Connecting…" : "Connect"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-[var(--color-text-muted)]">
          Enter the LDAP / Active Directory credentials to bind with
          for this session. Accepts plain <code>user</code>,{" "}
          <code>DOMAIN\\user</code>, or <code>user@realm</code> — the
          host parses the domain part for the RDP CredSSP slot.
          Credentials are not persisted on this profile.
        </p>
        <Input
          label="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="DOMAIN\\alice"
          autoFocus
        />
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
    </Modal>
  );
}

/**
 * Last 10 sessions on this resource. Persisted in the resource's
 * `recent_sessions` field by the host's `record_recent_session`
 * helper after every successful `session_open_*`. Read-only here
 * — the operator's primary use case is "connect to the same one
 * again" via the profile button list above.
 */
function RecentSessionsList({ resource }: { resource: ResourceMetadata }) {
  const raw = (resource as Record<string, unknown>)["recent_sessions"];
  if (!Array.isArray(raw) || raw.length === 0) {
    return null;
  }
  const entries: RecentSession[] = (raw as unknown[])
    .filter(
      (e): e is RecentSession =>
        typeof e === "object" &&
        e !== null &&
        typeof (e as RecentSession).ts === "string" &&
        typeof (e as RecentSession).profile_name === "string",
    );
  if (entries.length === 0) return null;
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-[var(--color-text-muted)] select-none">
        Recently connected ({entries.length})
      </summary>
      <ul className="mt-2 space-y-1">
        {entries.map((e, i) => (
          <li
            key={`${e.ts}-${i}`}
            className="flex items-center gap-2 text-[var(--color-text-muted)]"
          >
            <span className="font-mono">{e.ts.replace("T", " ").replace("Z", "")}</span>
            <Badge label={e.protocol.toUpperCase()} />
            <span>via</span>
            <strong className="text-[var(--color-text)]">{e.profile_name}</strong>
            <span>by</span>
            <span className="font-mono">{e.actor}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

/**
 * Find the profile we'd launch for a one-click "Connect" without
 * any operator prompt. Returns null if none qualifies — used by
 * the inline card-level quick-connect button + the ⌘K palette.
 *
 * Eligibility (mirrors `ConnectionProfilesPanel.launchableProfiles`
 * + the palette's filter, minus LDAP operator-bind which would
 * need a credential prompt the card can't surface inline):
 *   - resource type's Connect policy not disabled
 *   - resource has a usable os_type → protocol mapping
 *   - profile.protocol matches that protocol
 *   - credential_source kind is one we launch today
 *     (Secret / LDAP non-operator-bind / PKI)
 */
function pickQuickLaunchProfile(
  resource: ResourceMetadata,
  typeDef: ResourceTypeDef,
): ConnectionProfile | null {
  if (typeDef.connect?.enabled === false) return null;
  const protocol = protocolForOsType(String(resource["os_type"] ?? ""));
  if (!protocol) return null;
  const profiles = readProfiles(resource as Record<string, unknown>);
  for (const p of profiles) {
    if (p.protocol !== protocol) continue;
    const k = p.credential_source.kind;
    if (k === "ssh-engine") continue;
    if (
      k === "ldap" &&
      "bind_mode" in p.credential_source &&
      p.credential_source.bind_mode === "operator"
    ) {
      // Operator-bind needs a typed credential — handled by the
      // Connection tab's inline modal, not the card-level button.
      continue;
    }
    return p;
  }
  return null;
}

/**
 * Tiny one-click Connect button rendered on the resource list
 * card. Visible only when `pickQuickLaunchProfile` finds an
 * eligible profile. Click stops propagation so it doesn't also
 * fire the card's `selectResource` navigation. The host enforces
 * the actual permission check; on rejection we surface the error
 * via toast and stay on the list page.
 */
function ConnectQuickButton({
  resource,
  profile,
  toast,
}: {
  resource: ResourceMetadata;
  profile: ConnectionProfile;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  async function handleClick(ev: React.MouseEvent<HTMLButtonElement>) {
    ev.stopPropagation();
    if (busy) return;
    setBusy(true);
    try {
      const req = {
        resource_name: String(resource.name),
        profile_id: profile.id,
        operator_credential: undefined,
      };
      if (profile.protocol === "ssh") {
        await api.sessionOpenSsh(req);
      } else {
        await api.sessionOpenRdp(req);
      }
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={busy}
      title={`Connect (${profile.protocol.toUpperCase()} · ${profile.name})`}
      aria-label="Connect"
      className="shrink-0 inline-flex items-center justify-center w-7 h-7 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-text-muted)] hover:text-[var(--color-primary)] hover:border-[var(--color-primary)] disabled:opacity-50 transition-colors"
    >
      {/* Inline SVG — terminal-prompt glyph for SSH, monitor for RDP.
          Stays crisp at the 14px size and avoids pulling an icon font. */}
      {profile.protocol === "ssh" ? (
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="2" y="4" width="20" height="14" rx="2" ry="2" />
          <line x1="8" y1="21" x2="16" y2="21" />
          <line x1="12" y1="17" x2="12" y2="21" />
        </svg>
      )}
    </button>
  );
}

function describeCredentialSource(c: CredentialSource): string {
  switch (c.kind) {
    case "secret":
      return c.secret_id ? `secret • ${c.secret_id}` : "secret • (not set)";
    case "ldap":
      return `ldap • ${c.ldap_mount} (${c.bind_mode})`;
    case "ssh-engine":
      return `ssh-engine • ${c.ssh_mount}role=${c.ssh_role} (${c.mode})`;
    case "pki":
      return `pki • ${c.pki_mount} role=${c.pki_role}`;
  }
}

/**
 * Profile editor modal. Phase 2 implements the **Secret** source
 * fully; the other three sources show a stub panel pointing at the
 * spec until their phases ship.
 */
function ConnectionProfileEditor({
  open,
  resource,
  existing,
  onClose,
  onSave,
  toast,
}: {
  open: boolean;
  resource: ResourceMetadata;
  existing: ConnectionProfile | null;
  onClose: () => void;
  onSave: (p: ConnectionProfile) => Promise<void>;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const osType = String(resource["os_type"] ?? "");
  const fallbackProtocol = protocolForOsType(osType) ?? "ssh";
  const [profile, setProfile] = useState<ConnectionProfile>(
    existing ?? blankProfile(osType),
  );
  const [secretCandidates, setSecretCandidates] = useState<Array<{
    value: string;
    label: string;
  }>>([]);
  const [loadingSecrets, setLoadingSecrets] = useState(false);

  // Reload the candidate list of credential-shaped resource secrets
  // every time the editor opens. We don't try to filter to "only
  // credential-shaped" client-side — the read+detect would require
  // a fetch per secret. Instead the dropdown lists every secret;
  // the operator picks one and the runtime path validates the
  // shape on the actual connect.
  useEffect(() => {
    if (!open) return;
    let cancel = false;
    setLoadingSecrets(true);
    (async () => {
      try {
        const out = await api.listResourceSecrets(String(resource.name));
        if (cancel) return;
        const cands = (out.keys ?? []).map((k) => ({ value: k, label: k }));
        setSecretCandidates(cands);
      } catch (e: unknown) {
        if (!cancel) toast("error", extractError(e));
      } finally {
        if (!cancel) setLoadingSecrets(false);
      }
    })();
    return () => {
      cancel = true;
    };
  }, [open, resource.name, toast]);

  function update<K extends keyof ConnectionProfile>(k: K, v: ConnectionProfile[K]) {
    setProfile((p) => ({ ...p, [k]: v }));
  }

  function updateCredentialSource(s: CredentialSource) {
    setProfile((p) => ({ ...p, credential_source: s }));
  }

  function handleCredKindChange(kind: CredentialSource["kind"]) {
    switch (kind) {
      case "secret":
        updateCredentialSource({ kind: "secret", secret_id: "" });
        break;
      case "ldap":
        updateCredentialSource({
          kind: "ldap",
          ldap_mount: "",
          bind_mode: "operator",
        });
        break;
      case "ssh-engine":
        updateCredentialSource({
          kind: "ssh-engine",
          ssh_mount: "",
          ssh_role: "",
          mode: "ca",
        });
        break;
      case "pki":
        updateCredentialSource({
          kind: "pki",
          pki_mount: "",
          pki_role: "",
        });
        break;
    }
  }

  const validationError = validateProfile(profile);
  const canSave = validationError === null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={existing ? `Edit profile · ${existing.name}` : "Add connection profile"}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!canSave} onClick={() => onSave(profile)}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Profile name"
            value={profile.name}
            onChange={(e) => update("name", e.target.value)}
            placeholder="Default"
          />
          <Select
            label="Protocol"
            value={profile.protocol}
            onChange={(e) =>
              update("protocol", e.target.value as SessionProtocol)
            }
            options={[
              { value: "ssh", label: "SSH" },
              { value: "rdp", label: "RDP" },
            ]}
          />
        </div>
        {osType && profile.protocol !== fallbackProtocol && (
          <p className="text-xs text-[var(--color-text-muted)]">
            os_type = {osType} normally maps to{" "}
            {fallbackProtocol.toUpperCase()}.
          </p>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Target host (override)"
            value={profile.target_host ?? ""}
            onChange={(e) =>
              update("target_host", e.target.value || undefined)
            }
            placeholder={
              (resource["hostname"] as string) ||
              (resource["ip_address"] as string) ||
              "from resource"
            }
          />
          <Input
            label="Target port (override)"
            type="number"
            value={profile.target_port?.toString() ?? ""}
            onChange={(e) => {
              const n = parseInt(e.target.value, 10);
              update(
                "target_port",
                Number.isFinite(n) && n > 0 ? n : undefined,
              );
            }}
            placeholder={defaultPort(profile.protocol).toString()}
          />
        </div>

        <Input
          label="Username"
          value={profile.username ?? ""}
          onChange={(e) => update("username", e.target.value || undefined)}
          placeholder={
            profile.protocol === "rdp" ? "Administrator" : "root"
          }
          hint={
            profile.credential_source.kind === "secret"
              ? "Optional — used only as a fallback if the chosen secret has no `username` field. When the secret carries a username it wins."
              : profile.credential_source.kind === "ldap"
                ? "Ignored for LDAP — the credential source supplies the username (operator-typed, static-role, or checked-out account)."
                : "Used as the SSH/RDP login user. PKI client certs don't carry the OS user, so this field is required."
          }
        />

        <hr className="border-[var(--color-border)]" />

        <Select
          label="Credential source"
          value={profile.credential_source.kind}
          onChange={(e) =>
            handleCredKindChange(e.target.value as CredentialSource["kind"])
          }
          options={[
            { value: "secret", label: "Resource secret" },
            { value: "ldap", label: "LDAP / Active Directory" },
            { value: "ssh-engine", label: "SSH secret engine (later phase)" },
            { value: "pki", label: "PKI client cert (SSH publickey / RDP CredSSP smartcard)" },
          ]}
        />

        {profile.credential_source.kind === "secret" ? (
          <div className="space-y-2">
            <Select
              label="Resource secret"
              value={profile.credential_source.secret_id}
              onChange={(e) =>
                updateCredentialSource({
                  kind: "secret",
                  secret_id: e.target.value,
                })
              }
              options={[
                { value: "", label: loadingSecrets ? "Loading…" : "(pick a secret)" },
                ...secretCandidates,
              ]}
            />
            <p className="text-xs text-[var(--color-text-muted)]">
              Pick a credential-shaped secret (<code>username</code> +{" "}
              <code>password</code> and/or <code>private_key</code>). Plain
              key/value secrets work too — extra fields are ignored at
              connect time.
            </p>
            {profile.credential_source.secret_id ? (
              <CredentialSecretInspector
                resourceName={String(resource.name)}
                secretId={profile.credential_source.secret_id}
              />
            ) : null}
          </div>
        ) : profile.credential_source.kind === "ldap" ? (
          <LdapCredentialEditor
            cs={profile.credential_source}
            onChange={updateCredentialSource}
          />
        ) : profile.credential_source.kind === "pki" ? (
          <PkiCredentialEditor
            cs={profile.credential_source}
            onChange={updateCredentialSource}
            protocol={profile.protocol}
          />
        ) : (
          <CredentialSourceStub
            kind={profile.credential_source.kind}
          />
        )}

        {validationError && (
          <p className="text-xs text-[var(--color-danger)]">{validationError}</p>
        )}

        <hr className="border-[var(--color-border)]" />

        <Input
          label="Host-key pin (optional)"
          value={profile.host_key_pin ?? ""}
          onChange={(e) =>
            update("host_key_pin", e.target.value || undefined)
          }
          placeholder={
            profile.protocol === "ssh"
              ? "SHA256:abc123…"
              : "RDP cert thumbprint"
          }
          hint="Leave empty for TOFU on first connect. The session window will surface the observed fingerprint so you can pin it on the next save."
        />
      </div>
    </Modal>
  );
}

/**
 * Inspector that reads the chosen secret and reports whether it
 * looks credential-shaped. Surfaces a friendly "this secret looks
 * like a credential" / "this secret doesn't look like a credential"
 * line so the operator gets immediate feedback before saving.
 */
function CredentialSecretInspector({
  resourceName,
  secretId,
}: {
  resourceName: string;
  secretId: string;
}) {
  const [shape, setShape] = useState<"loading" | "credential" | "kv" | "error">(
    "loading",
  );
  const [detail, setDetail] = useState<string>("");

  useEffect(() => {
    let cancel = false;
    setShape("loading");
    (async () => {
      try {
        const out = await api.readResourceSecret(resourceName, secretId);
        if (cancel) return;
        const s = detectSecretShape(
          (out.data ?? {}) as Record<string, unknown>,
        );
        if (s.kind === "credential") {
          setShape("credential");
          setDetail(
            `username = ${s.username || "(empty)"}; ` +
              [
                s.has_password ? "password" : null,
                s.has_private_key ? "private_key" : null,
              ]
                .filter((x) => x !== null)
                .join(" + "),
          );
        } else {
          setShape("kv");
          setDetail(
            s.keys.length
              ? `keys: ${s.keys.join(", ")}`
              : "(no keys)",
          );
        }
      } catch (e: unknown) {
        if (!cancel) {
          setShape("error");
          setDetail(extractError(e));
        }
      }
    })();
    return () => {
      cancel = true;
    };
  }, [resourceName, secretId]);

  if (shape === "loading") {
    return <p className="text-xs text-[var(--color-text-muted)]">Inspecting secret…</p>;
  }
  if (shape === "error") {
    return (
      <p className="text-xs text-[var(--color-danger)]">
        Couldn't read the secret: {detail}
      </p>
    );
  }
  if (shape === "credential") {
    return (
      <div className="rounded border border-green-700 bg-green-950/40 px-3 py-2 text-xs text-green-200">
        Credential-shaped. <span className="font-mono">{detail}</span>
      </div>
    );
  }
  return (
    <div className="rounded border border-yellow-700 bg-yellow-950/40 px-3 py-2 text-xs text-yellow-200">
      Generic key/value secret — Connect will look for{" "}
      <code>username</code> + <code>password</code> /{" "}
      <code>private_key</code> at runtime. {detail}
    </div>
  );
}

/**
 * Editor for LDAP credential sources. Three sub-modes:
 *   - operator: operator types user+password into a small prompt
 *     at connect time. Profile only stores the mount path.
 *   - static_role: profile points at an LDAP static-role; host
 *     pulls username + password from `ldap/static-cred/<role>` at
 *     connect time.
 *   - library_set: profile points at an LDAP library set; host
 *     calls `library/<set>/check-out` and registers a session-
 *     close hook that runs `library/<set>/check-in`.
 */
function LdapCredentialEditor({
  cs,
  onChange,
}: {
  cs: Extract<CredentialSource, { kind: "ldap" }>;
  onChange: (s: CredentialSource) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="LDAP mount path"
          value={cs.ldap_mount}
          onChange={(e) =>
            onChange({ ...cs, ldap_mount: e.target.value })
          }
          placeholder="openldap/"
          hint="Mount path of the OpenLDAP / AD secret engine on this vault (e.g. `openldap/`)."
        />
        <Select
          label="Bind mode"
          value={cs.bind_mode}
          onChange={(e) =>
            onChange({
              ...cs,
              bind_mode: e.target.value as
                | "operator"
                | "static_role"
                | "library_set",
            })
          }
          options={[
            { value: "operator", label: "Operator-supplied (prompt at connect)" },
            { value: "static_role", label: "Vault-managed (static role)" },
            { value: "library_set", label: "Vault-managed (library check-out)" },
          ]}
        />
      </div>
      {cs.bind_mode === "static_role" && (
        <Input
          label="Static role name"
          value={cs.static_role ?? ""}
          onChange={(e) =>
            onChange({ ...cs, static_role: e.target.value || undefined })
          }
          placeholder="db-admin"
          hint="Name of the LDAP static role configured on the bound mount. Connect reads `<mount>/static-cred/<role>` at session-open time."
        />
      )}
      {cs.bind_mode === "library_set" && (
        <Input
          label="Library set name"
          value={cs.library_set ?? ""}
          onChange={(e) =>
            onChange({ ...cs, library_set: e.target.value || undefined })
          }
          placeholder="db-admins"
          hint="Name of the LDAP library set on the bound mount. Connect calls `library/<set>/check-out`; session close runs the matching `check-in`."
        />
      )}
      {cs.bind_mode === "operator" && (
        <p className="text-xs text-[var(--color-text-muted)]">
          The session window will prompt for username + password
          before opening. Credentials are passed straight to the
          SSH/RDP transport — never persisted on this resource.
        </p>
      )}
    </div>
  );
}

/**
 * Editor for the PKI credential source. Issues a fresh client
 * cert from the bound PKI mount at connect time. SSH uses the
 * issued private_key directly; RDP requires the CredSSP smartcard
 * wiring which is still pending — we surface a banner so the
 * operator can pre-stage the profile but not be surprised at
 * connect time.
 */
function PkiCredentialEditor({
  cs,
  onChange,
  protocol,
}: {
  cs: Extract<CredentialSource, { kind: "pki" }>;
  onChange: (s: CredentialSource) => void;
  protocol: SessionProtocol;
}) {
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="PKI mount path"
          value={cs.pki_mount}
          onChange={(e) =>
            onChange({ ...cs, pki_mount: e.target.value })
          }
          placeholder="pki/"
          hint="Mount path of the PKI engine on this vault (e.g. `pki/`). Connect issues a fresh leaf cert per session via `<mount>/issue/<role>`."
        />
        <Input
          label="PKI role"
          value={cs.pki_role}
          onChange={(e) =>
            onChange({ ...cs, pki_role: e.target.value })
          }
          placeholder="server-auth"
          hint="Role configured on the bound PKI mount. Role TTL caps the per-session cert lifetime."
        />
      </div>
      <Input
        label="Cert TTL (seconds, optional)"
        type="number"
        value={cs.cert_ttl_secs?.toString() ?? ""}
        onChange={(e) => {
          const n = parseInt(e.target.value, 10);
          onChange({
            ...cs,
            cert_ttl_secs: Number.isFinite(n) && n > 0 ? n : undefined,
          });
        }}
        placeholder="(role default)"
        hint="Optional override; clamped to the role's max_ttl by the engine."
      />
      {protocol === "rdp" && (
        <p className="text-xs text-[var(--color-text-muted)]">
          RDP wraps the issued cert as a synthetic PIV smartcard
          via sspi-rs's emulated scard backend, then negotiates
          CredSSP / NLA. The Windows server must have the cert's
          issuing CA enrolled (typically via AD smartcard logon
          policy). The PKI role's <code>max_ttl</code> caps how
          long the per-session cert is valid.
        </p>
      )}
      {protocol === "ssh" && (
        <p className="text-xs text-[var(--color-text-muted)]">
          SSH uses the issued <code>private_key</code> directly.
          The cert is delivered alongside (operators using
          x509-cert-auth servers like Tectia drop it on the host;
          everyone else relies on the public key being in
          <code> authorized_keys</code>). Operators get the
          short-lived-cert lifecycle benefit either way.
        </p>
      )}
    </div>
  );
}

function CredentialSourceStub({ kind }: { kind: CredentialSource["kind"] }) {
  const labels: Record<CredentialSource["kind"], string> = {
    secret: "",
    ldap: "",
    "ssh-engine": "SSH secret engine — vault-issued cert/OTP/PQC, ships in a later phase",
    pki: "",
  };
  return (
    <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-xs text-[var(--color-text-muted)]">
      {labels[kind]}. The profile editor remembers your selection so
      you can pre-stage a profile, but Connect will refuse to
      launch until the implementation lands. See{" "}
      <code>features/resource-connect.md</code>.
    </div>
  );
}

// ── Resource Metadata History ──────────────────────────────────────

function ResourceMetadataHistoryCard({
  resourceName,
  toast,
}: {
  resourceName: string;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [entries, setEntries] = useState<ResourceHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const result = await api.listResourceHistory(resourceName);
        if (!cancelled) setEntries(result.entries);
      } catch (e: unknown) {
        if (!cancelled) {
          toast("error", extractError(e));
          setEntries([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [resourceName, toast]);

  return (
    <Card title="Change history">
      <p className="text-xs text-[var(--color-text-muted)] mb-3">
        Records who made each change and which metadata fields were modified.
        Before/after values are not retained here -- use the Secrets tab for
        per-secret version history with values.
      </p>
      <ResourceHistoryPanel entries={entries} loading={loading} />
    </Card>
  );
}

// ── Resource Secrets Panel ─────────────────────────────────────────

function ResourceSecretsPanel({ resourceName, toast }: {
  resourceName: string;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [secretData, setSecretData] = useState<Record<string, unknown>>({});
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [createPairs, setCreatePairs] = useState<SecretPair[]>([{ key: "", value: "" }]);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // In-place edit of the currently-selected secret.
  const [editingSecret, setEditingSecret] = useState(false);
  const [editPairs, setEditPairs] = useState<SecretPair[]>([]);
  const [savingEdit, setSavingEdit] = useState(false);

  // Version history panel for the selected secret.
  const [showHistory, setShowHistory] = useState(false);
  const [versions, setVersions] = useState<SecretHistoryVersion[]>([]);
  const [loadingVersions, setLoadingVersions] = useState(false);

  useEffect(() => {
    loadSecrets();
  }, [resourceName]);

  async function loadSecrets() {
    setLoading(true);
    try {
      const result = await api.listResourceSecrets(resourceName);
      setKeys(result.keys);
    } catch {
      setKeys([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectKey(key: string) {
    try {
      const result = await api.readResourceSecret(resourceName, key);
      setSelectedKey(key);
      setSecretData(result.data);
      setEditingSecret(false);
      setShowHistory(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function openHistory() {
    if (!selectedKey) return;
    setShowHistory(true);
    setLoadingVersions(true);
    try {
      const result = await api.listResourceSecretVersions(resourceName, selectedKey);
      setVersions(result.versions);
    } catch (e: unknown) {
      toast("error", extractError(e));
      setVersions([]);
    } finally {
      setLoadingVersions(false);
    }
  }

  async function loadSecretVersion(version: number) {
    if (!selectedKey) throw new Error("No secret selected");
    const result = await api.readResourceSecretVersion(resourceName, selectedKey, version);
    return result.data;
  }

  async function handleRestoreSecretVersion(
    version: number,
    data: Record<string, unknown>,
  ) {
    if (!selectedKey) return;
    const stringData: Record<string, string> = {};
    for (const [k, v] of Object.entries(data)) stringData[k] = String(v ?? "");
    try {
      await api.writeResourceSecret(resourceName, selectedKey, stringData);
      toast("success", `Restored "${selectedKey}" from version ${version}`);
      const refreshed = await api.readResourceSecret(resourceName, selectedKey);
      setSecretData(refreshed.data);
      await openHistory();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleCreate() {
    if (!newKey) return;
    try {
      await api.writeResourceSecret(resourceName, newKey, dataFromPairs(createPairs));
      toast("success", `Secret "${newKey}" created`);
      setShowCreate(false);
      setNewKey("");
      setCreatePairs([{ key: "", value: "" }]);
      loadSecrets();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.deleteResourceSecret(resourceName, deleteTarget);
      toast("success", `Secret "${deleteTarget}" deleted`);
      if (selectedKey === deleteTarget) {
        setSelectedKey(null);
        setSecretData({});
        setEditingSecret(false);
      }
      setDeleteTarget(null);
      loadSecrets();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function startEdit() {
    setEditPairs(pairsFromData(secretData));
    setEditingSecret(true);
  }

  async function handleSaveEdit() {
    if (!selectedKey) return;
    const data = dataFromPairs(editPairs);
    if (Object.keys(data).length === 0) {
      toast("error", "At least one key-value pair is required.");
      return;
    }
    setSavingEdit(true);
    try {
      await api.writeResourceSecret(resourceName, selectedKey, data);
      toast("success", `Secret "${selectedKey}" updated`);
      const refreshed = await api.readResourceSecret(resourceName, selectedKey);
      setSecretData(refreshed.data);
      setEditingSecret(false);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSavingEdit(false);
    }
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-[var(--color-text-muted)]">Secrets</h2>
        <Button size="sm" onClick={() => setShowCreate(true)}>Add Secret</Button>
      </div>

      {loading ? (
        <Card>
          <p className="text-sm text-[var(--color-text-muted)]">Loading...</p>
        </Card>
      ) : keys.length === 0 ? (
        <Card>
          <EmptyState
            title="No secrets"
            description="Add credentials, API keys, or other secrets for this resource."
          />
        </Card>
      ) : (
        <div className="flex gap-4">
          {/* Key list */}
          <Card className="w-72 shrink-0" title="Keys">
            <div className="space-y-0.5 -mx-1">
              {keys.map((key) => (
                <div
                  key={key}
                  className={`group flex items-center justify-between gap-2 rounded px-3 py-1.5 transition-colors ${
                    selectedKey === key
                      ? "bg-[var(--color-primary)] text-white"
                      : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => handleSelectKey(key)}
                    className="flex-1 text-left text-sm font-mono truncate"
                  >
                    {key}
                  </button>
                  <button
                    type="button"
                    onClick={() => setDeleteTarget(key)}
                    aria-label={`Delete ${key}`}
                    className={`text-xs shrink-0 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity ${
                      selectedKey === key
                        ? "text-white/80 hover:text-white"
                        : "text-[var(--color-danger)] hover:underline"
                    }`}
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </Card>

          {/* Secret detail */}
          <Card className="flex-1" title={selectedKey ? `Secret: ${selectedKey}` : "Select a secret"}>
            {selectedKey ? (
              showHistory ? (
                <SecretHistoryPanel
                  versions={versions}
                  loading={loadingVersions}
                  loadVersion={loadSecretVersion}
                  onRestore={handleRestoreSecretVersion}
                  onClose={() => setShowHistory(false)}
                />
              ) : editingSecret ? (
                <div className="space-y-3">
                  <SecretPairsEditor pairs={editPairs} onChange={setEditPairs} />
                  <div className="flex gap-2 pt-2">
                    <Button
                      size="sm"
                      onClick={handleSaveEdit}
                      loading={savingEdit}
                      disabled={savingEdit}
                    >
                      Save
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setEditingSecret(false)}
                      disabled={savingEdit}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  {Object.keys(secretData).length === 0 ? (
                    <p className="text-sm text-[var(--color-text-muted)]">Empty secret.</p>
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-[var(--color-text-muted)] text-left">
                          <th className="pb-2 font-medium">Key</th>
                          <th className="pb-2 font-medium">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(secretData).map(([k, v]) => (
                          <tr key={k} className="border-t border-[var(--color-border)]">
                            <td className="py-2 font-mono text-[var(--color-primary)]">{k}</td>
                            <td className="py-2 font-mono">
                              <MaskedValue value={String(v)} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" onClick={startEdit}>Edit</Button>
                    <Button size="sm" variant="secondary" onClick={openHistory}>
                      History
                    </Button>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => setDeleteTarget(selectedKey)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              )
            ) : (
              <EmptyState
                title="No secret selected"
                description="Select a key from the list to view its contents"
              />
            )}
          </Card>
        </div>
      )}

      {/* Create secret modal */}
      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="Add Secret"
        size="md"
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={!newKey}>Create</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Input
            label="Key Name"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="ssh_key, api_token, password"
          />
          <SecretPairsEditor pairs={createPairs} onChange={setCreatePairs} />
        </div>
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete Secret"
        message={`Delete secret "${deleteTarget}"? This cannot be undone.`}
        confirmLabel="Delete"
      />
    </>
  );
}

// ── Resource Files Panel ───────────────────────────────────────────
//
// Lists files whose `resource` field names this resource. Filtering
// is done client-side over `listFiles` + `readFileMeta` — the same
// enumeration FilesPage already uses — because the file module does
// not yet expose a `by-resource` reverse index. For deployments with
// many files this is O(n), which we accept today; a server-side
// index is a reasonable future optimization if it becomes a hot path.

function ResourceFilesPanel({
  resourceName,
  toast,
}: {
  resourceName: string;
  toast: (kind: "success" | "error" | "info", msg: string) => void;
}) {
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loading, setLoading] = useState(true);

  function fmtBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const list = await api.listFiles();
        const matched: FileMeta[] = [];
        for (const id of list.ids) {
          try {
            const m = await api.readFileMeta(id);
            if (m.resource === resourceName) matched.push(m);
          } catch {
            /* skip individual read failures */
          }
        }
        matched.sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
        if (!cancelled) setFiles(matched);
      } catch (e) {
        if (!cancelled) toast("error", extractError(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [resourceName, toast]);

  async function download(m: FileMeta) {
    try {
      const c = await api.readFileContent(m.id);
      const binary = atob(c.content_base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes.buffer], {
        type: c.mime_type || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = m.name || m.id;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      toast("error", extractError(e));
    }
  }

  return (
    <Card>
      <div className="mb-3 text-sm text-[var(--color-text-muted)]">
        Files whose <span className="font-mono">resource</span> field is{" "}
        <span className="font-mono">{resourceName}</span>. Manage them on the
        Files page.
      </div>
      {loading ? (
        <div className="text-sm text-[var(--color-text-muted)]">Loading…</div>
      ) : files.length === 0 ? (
        <EmptyState
          title="No files"
          description="Upload a file on the Files page and set its Resource field to this resource's name."
        />
      ) : (
        <Table<FileMeta>
          columns={[
            {
              key: "name",
              header: "Name",
              render: (m) =>
                m.name ? m.name : <span className="opacity-60">{m.id}</span>,
            },
            {
              key: "mime_type",
              header: "Type",
              render: (m) => m.mime_type || "—",
            },
            {
              key: "size_bytes",
              header: "Size",
              render: (m) => fmtBytes(m.size_bytes),
            },
            {
              key: "updated_at",
              header: "Updated",
              render: (m) =>
                m.updated_at ? new Date(m.updated_at).toLocaleString() : "—",
            },
            {
              key: "actions",
              header: "",
              render: (m) => (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => download(m)}
                >
                  Download
                </Button>
              ),
            },
          ]}
          data={files}
          rowKey={(m) => m.id}
          emptyMessage=""
        />
      )}
    </Card>
  );
}

// ── Resource Sharing Card ──────────────────────────────────────────
//
// Displays the resource's owner record plus every active share and
// offers Grant / Revoke controls. When the caller's token carries an
// admin policy, also offers a Transfer-ownership form.
function ResourceSharingCard({
  resourceName,
  toast,
}: {
  resourceName: string;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  const [owner, setOwner] = useState<OwnerInfo | null>(null);
  const [shares, setShares] = useState<ShareEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const policies = useAuthStore((s) => s.policies);
  const entityId = useAuthStore((s) => s.entityId);
  const isAdmin = policies.some((p) => p === "root" || p === "admin");
  const isOwner =
    owner?.owned === true && owner.entity_id === entityId && entityId !== "";

  // Grant modal state
  const [showGrant, setShowGrant] = useState(false);
  const [grantee, setGrantee] = useState("");
  const [caps, setCaps] = useState<string[]>(["read"]);
  const [expires, setExpires] = useState("");

  // Transfer modal state
  const [showTransfer, setShowTransfer] = useState(false);
  const [newOwner, setNewOwner] = useState("");

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resourceName]);

  async function load() {
    setLoading(true);
    try {
      const [o, s] = await Promise.all([
        api.getResourceOwner(resourceName).catch(() => null),
        api.listSharesForTarget("resource", resourceName).catch(() => [] as ShareEntry[]),
      ]);
      setOwner(o);
      setShares(s);
    } finally {
      setLoading(false);
    }
  }

  async function handleGrant() {
    try {
      await api.putShare("resource", resourceName, grantee.trim(), caps, expires.trim());
      toast("success", "Share granted");
      setShowGrant(false);
      setGrantee("");
      setCaps(["read"]);
      setExpires("");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke(share: ShareEntry) {
    try {
      await api.deleteShare("resource", share.target_path, share.grantee_entity_id);
      toast("success", "Share revoked");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleTransfer() {
    try {
      await api.transferResourceOwner(resourceName, newOwner.trim());
      toast("success", "Ownership transferred");
      setShowTransfer(false);
      setNewOwner("");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function toggleCap(c: string) {
    setCaps((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]));
  }

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">Loading sharing info...</p>
      </Card>
    );
  }

  const canGrant = isOwner || isAdmin;

  return (
    <>
      <Card
        title="Owner"
        actions={
          isAdmin ? (
            <Button size="sm" variant="secondary" onClick={() => setShowTransfer(true)}>
              Transfer
            </Button>
          ) : null
        }
      >
        {owner?.owned ? (
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-[var(--color-text-muted)] text-xs">owner</span>
              <EntityLabel
                entityId={owner.entity_id}
                callerEntityId={entityId}
              />
              {owner.entity_id === entityId && entityId !== "" && (
                <Badge label="You" variant="success" />
              )}
            </div>
            {owner.created_at && (
              <div className="flex items-center gap-2">
                <span className="text-[var(--color-text-muted)] text-xs">since</span>
                <span className="text-xs">{new Date(owner.created_at).toLocaleString()}</span>
              </div>
            )}
          </div>
        ) : (
          <EmptyState
            title="Unowned"
            description="No entity has claimed this resource yet. The next write by an authenticated caller will capture ownership."
          />
        )}
      </Card>

      <Card
        title="Shares"
        actions={
          canGrant ? (
            <Button size="sm" onClick={() => setShowGrant(true)}>
              Grant access
            </Button>
          ) : null
        }
      >
        {shares.length === 0 ? (
          <EmptyState
            title="No shares"
            description={
              canGrant
                ? "Nobody else has access through an explicit share yet."
                : "Only the owner or an admin can grant new shares on this resource."
            }
          />
        ) : (
          <Table
            columns={[
              {
                key: "grantee",
                header: "Grantee",
                render: (s: ShareEntry) => (
                  <EntityLabel entityId={s.grantee_entity_id} />
                ),
              },
              {
                key: "caps",
                header: "Capabilities",
                render: (s: ShareEntry) => (
                  <div className="flex flex-wrap gap-1">
                    {s.capabilities.map((c) => (
                      <Badge key={c} label={c} variant="info" />
                    ))}
                  </div>
                ),
              },
              {
                key: "granted_at",
                header: "Granted",
                render: (s: ShareEntry) => (
                  <span className="text-xs text-[var(--color-text-muted)]">
                    {s.granted_at ? new Date(s.granted_at).toLocaleString() : "-"}
                  </span>
                ),
              },
              {
                key: "expires",
                header: "Expires",
                render: (s: ShareEntry) =>
                  s.expires_at ? (
                    <span
                      className={`text-xs ${s.expired ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}
                    >
                      {s.expires_at}
                      {s.expired && " (expired)"}
                    </span>
                  ) : (
                    <span className="text-xs text-[var(--color-text-muted)]">never</span>
                  ),
              },
              {
                key: "revoke",
                header: "",
                className: "text-right w-24",
                render: (s: ShareEntry) =>
                  canGrant ? (
                    <Button variant="danger" size="sm" onClick={() => handleRevoke(s)}>
                      Revoke
                    </Button>
                  ) : null,
              },
            ]}
            data={shares}
            rowKey={(s: ShareEntry) => s.grantee_entity_id}
          />
        )}
      </Card>

      <Modal
        open={showGrant}
        onClose={() => setShowGrant(false)}
        title={`Grant access to ${resourceName}`}
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowGrant(false)}>
              Cancel
            </Button>
            <Button onClick={handleGrant} disabled={!grantee.trim() || caps.length === 0}>
              Grant
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <EntityPicker
            label="Grantee"
            value={grantee}
            onChange={(id) => setGrantee(id)}
            placeholder="Search by login or paste entity_id"
            hint="Type part of a username, mount, or UUID."
          />
          <div>
            <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
              Capabilities
            </label>
            <div className="flex flex-wrap gap-2">
              {(["read", "list", "update", "delete", "create"] as const).map((c) => {
                const selected = caps.includes(c);
                return (
                  <button
                    key={c}
                    type="button"
                    onClick={() => toggleCap(c)}
                    className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                      selected
                        ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                        : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                    }`}
                  >
                    {c}
                  </button>
                );
              })}
            </div>
          </div>
          <Input
            label="Expires at (optional)"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            placeholder="2026-12-31T23:59:59Z"
            hint="RFC3339 timestamp. Leave empty for no expiry."
          />
        </div>
      </Modal>

      <Modal
        open={showTransfer}
        onClose={() => setShowTransfer(false)}
        title={`Transfer ownership of ${resourceName}`}
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowTransfer(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleTransfer} disabled={!newOwner.trim()}>
              Transfer
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            Overwrite the owner record for this resource. Admin-only. The new entity
            will pass the <code>scopes = ["owner"]</code> check on every subsequent
            request; the previous owner loses owner-scoped access unless a share is
            also created for them.
          </p>
          <Input
            label="New owner entity_id"
            value={newOwner}
            onChange={(e) => setNewOwner(e.target.value)}
            placeholder="Target entity UUID"
          />
        </div>
      </Modal>
    </>
  );
}

