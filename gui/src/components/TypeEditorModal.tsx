import { useState } from "react";
import { Button, Input, Select, Modal, ResourceTypeIcon, RESOURCE_TYPE_ICON_CATALOG } from "./ui";
import type { ConnectProtocol, ResourceTypeDef, ResourceFieldDef } from "../lib/types";
import {
  WEB_EXPOSURE_CAPS,
  connectProtocols,
  heuristicChoice,
  webExposureChoice,
  withWebPolicy,
  type HeuristicChoice,
  type WebExposureChoice,
} from "../lib/resourceTypes";

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

export function TypeEditorModal({ typeDef, onSave, onClose }: {
  typeDef: ResourceTypeDef | null;
  onSave: (t: ResourceTypeDef) => void;
  onClose: () => void;
}) {
  const isNew = !typeDef;
  const [id, setId] = useState(typeDef?.id ?? "");
  const [label, setLabel] = useState(typeDef?.label ?? "");
  const [color, setColor] = useState<string>(typeDef?.color ?? "info");
  const [icon, setIcon] = useState<string>(typeDef?.icon ?? "");
  const [fields, setFields] = useState<ResourceFieldDef[]>(typeDef?.fields ?? []);
  // Phase 7 — per-type Resource-Connect policy. Persisted on the
  // type record's `connect` block; missing record == enabled.
  const [connectEnabled, setConnectEnabled] = useState<boolean>(
    typeDef?.connect?.enabled ?? true,
  );
  // Which Connect protocols the type offers (T96). Seeded from the
  // effective list with the enabled toggle ignored, so unticking "enabled"
  // and ticking it again doesn't lose the selection.
  const [protocols, setProtocols] = useState<ConnectProtocol[]>(() =>
    typeDef
      ? connectProtocols({ ...typeDef, connect: { ...typeDef.connect, enabled: true } })
      : [],
  );

  // Web exposure policy (T96 §6). The server denies a credential-releasing
  // web login unless the resource's *saved* type sets a cap, so this is where
  // an administrator opts a type in. Unset keeps today's deny.
  const [webExposure, setWebExposure] = useState<WebExposureChoice>(() =>
    webExposureChoice(typeDef?.connect),
  );
  const [webHeuristic, setWebHeuristic] = useState<HeuristicChoice>(() =>
    heuristicChoice(typeDef?.connect),
  );

  function toggleProtocol(p: ConnectProtocol, on: boolean) {
    setProtocols((cur) =>
      (["ssh", "sftp", "rdp", "web"] as const).filter((x) => (x === p ? on : cur.includes(x))),
    );
  }

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
    // Only emit what differs from the default — keeps the persisted shape
    // minimal so a round-trip through save → load doesn't bloat existing
    // type records that never opted in. `protocols` is written when the
    // record already carried it or the selection differs from what an
    // absent key means for this id (SSH+RDP for `server`, nothing else).
    const { enabled: _enabled, protocols: savedProtocols, ...rest } = typeDef?.connect ?? {};
    void _enabled;
    const legacyDefault = connectProtocols({ id: resolvedId, label: "", color: "neutral", fields: [] });
    const sameAsLegacy =
      legacyDefault.length === protocols.length && legacyDefault.every((p) => protocols.includes(p));
    const connect: NonNullable<ResourceTypeDef["connect"]> = withWebPolicy(
      {
        ...rest,
        ...(connectEnabled ? {} : { enabled: false }),
        ...(savedProtocols !== undefined || !sameAsLegacy ? { protocols } : {}),
      },
      webExposure,
      webHeuristic,
    );
    onSave({
      id: resolvedId,
      label: label || resolvedId,
      color: color as ResourceTypeDef["color"],
      ...(icon ? { icon } : {}),
      fields: fields.filter((f) => f.key),
      ...(Object.keys(connect).length > 0 ? { connect } : {}),
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
          <div className="flex items-end gap-2">
            <Select
              label="Icon"
              value={icon}
              onChange={(e) => setIcon(e.target.value)}
              options={[
                { value: "", label: "(none — show label)" },
                ...RESOURCE_TYPE_ICON_CATALOG.map((c) => ({ value: c.value, label: c.label })),
              ]}
            />
            <ResourceTypeIcon
              typeDef={{
                id: id || "preview",
                label: label || "Preview",
                color: color as ResourceTypeDef["color"],
                icon: icon || undefined,
                fields: [],
              }}
              size={20}
            />
          </div>
        </div>

        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={connectEnabled}
              onChange={(e) => setConnectEnabled(e.target.checked)}
            />
            <span>
              <strong>Resource Connect enabled</strong> for this type
            </span>
          </label>
          <p className="text-xs text-[var(--color-text-muted)] mt-1 pl-6">
            When unchecked, the Connect button + the Connection tab
            are hidden for every resource of this type. Useful for
            regulated environments that ship the metadata layer but
            force operators through an existing PAM tool.
          </p>
          <div className="mt-2 pl-6 flex flex-wrap gap-4 text-sm">
            {(["ssh", "sftp", "rdp", "web"] as const).map((p) => (
              <label key={p} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  disabled={!connectEnabled}
                  checked={protocols.includes(p)}
                  onChange={(e) => toggleProtocol(p, e.target.checked)}
                />
                <span>{p === "web" ? "Web" : p.toUpperCase()}</span>
              </label>
            ))}
          </div>
          <p className="text-xs text-[var(--color-text-muted)] mt-1 pl-6">
            Protocols resources of this type can be connected with. SSH and
            RDP pick the protocol from the resource&rsquo;s <code>os_type</code>{" "}
            field, which only the Server type carries by default. Web opens
            the application in an isolated in-app window.
          </p>
          {protocols.includes("web") && (
            <div className="mt-3 pl-6 grid grid-cols-2 gap-3" data-testid="web-policy">
              <div className="min-w-0">
                <Select
                  label="Web exposure cap"
                  disabled={!connectEnabled}
                  value={webExposure}
                  onChange={(e) => setWebExposure(e.target.value as WebExposureChoice)}
                  options={[
                    { value: "", label: "(not set \u2014 form logins denied)" },
                    ...(webExposure === "keep"
                      ? [{ value: "keep", label: "(saved value not recognised \u2014 kept; the server refuses it)" }]
                      : []),
                    ...WEB_EXPOSURE_CAPS.map((c) => ({
                      value: c,
                      label: c === "dom" ? "dom \u2014 form logins allowed" : c,
                    })),
                  ]}
                />
              </div>
              <div className="min-w-0">
                <Select
                  label="Allow heuristic fill"
                  disabled={!connectEnabled}
                  value={webHeuristic}
                  onChange={(e) => setWebHeuristic(e.target.value as HeuristicChoice)}
                  options={[
                    { value: "", label: "(not set \u2014 heuristics denied)" },
                    ...(webHeuristic === "keep"
                      ? [{ value: "keep", label: "(saved value not recognised \u2014 kept; the server refuses it)" }]
                      : []),
                    { value: "true", label: "Allowed" },
                    { value: "false", label: "Forbidden (beats a resource that allows it)" },
                  ]}
                />
              </div>
              <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
                Web credential release is <strong>off by default</strong>: the server injects a username
                or password into a web page only for a resource whose type is saved with a cap of{" "}
                <code>dom</code> here. Opening a site without signing in (open mode) works under any
                setting. A resource can lower this cap for itself but never raise it. Heuristic fill finds
                the login fields automatically and can pick the wrong one, so it stays off unless you
                allow it. The server enforces both; the profile editor only warns.
              </p>
            </div>
          )}
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
