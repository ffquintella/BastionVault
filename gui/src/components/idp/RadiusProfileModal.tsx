import { useState } from "react";
import { Button, Input, Modal, Select } from "../ui";
import { environmentOptions } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

const ATTRIBUTES = [
  { value: "fortinet-group-name", label: "Fortinet-Group-Name" },
  { value: "fortinet-vdom-name", label: "Fortinet-Vdom-Name" },
  { value: "fortinet-access-profile", label: "Fortinet-Access-Profile" },
  { value: "cisco-avpair", label: "Cisco-AVPair" },
  { value: "vsa", label: "Other vendor-specific (VSA)" },
];

type Attr = { attribute: string; value: string; vendor_id: string; vendor_type: string };

function fromProfile(p: idp.IdpRadiusProfile | null): Record<string, Attr[]> {
  const out: Record<string, Attr[]> = {};
  for (const [role, attrs] of Object.entries(p?.roles ?? {})) {
    out[role] = attrs.map((a) => ({
      attribute: a.attribute,
      value: a.value,
      vendor_id: a.attribute === "vsa" ? String(a.vendor_id ?? "") : "",
      vendor_type: a.attribute === "vsa" ? String(a.vendor_type ?? "") : "",
    }));
  }
  return out;
}

/** The vendor attributes an Access-Accept carries, per environment role. */
export function RadiusProfileModal({
  profile,
  directory,
  onClose,
  onSaved,
}: {
  profile: idp.IdpRadiusProfile | null;
  directory: IdpDirectory;
  onClose: () => void;
  onSaved: (p: idp.IdpRadiusProfile) => void;
}) {
  const creating = profile === null;
  const [name, setName] = useState(profile?.name ?? "");
  const [environment, setEnvironment] = useState(profile?.environment ?? "");
  const [description, setDescription] = useState(profile?.description ?? "");
  const [roles, setRoles] = useState<Record<string, Attr[]>>(fromProfile(profile));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const envRoles = directory.environments.find((e) => e.name === environment)?.info.roles ?? [];

  const update = (role: string, fn: (attrs: Attr[]) => Attr[]) =>
    setRoles((prev) => ({ ...prev, [role]: fn(prev[role] ?? []) }));

  async function save() {
    setError(null);
    const body: Record<string, unknown> = { description: description.trim() };
    if (creating) body.environment = environment;
    const out: Record<string, unknown[]> = {};
    for (const [role, attrs] of Object.entries(roles)) {
      const filled = attrs.filter((a) => a.value.trim() !== "");
      if (filled.length === 0) continue;
      out[role] = filled.map((a) =>
        a.attribute === "vsa"
          ? { attribute: "vsa", vendor_id: Number(a.vendor_id), vendor_type: Number(a.vendor_type), value: a.value }
          : { attribute: a.attribute, value: a.value },
      );
    }
    body.roles = out;
    setBusy(true);
    try {
      onSaved((await idp.idpWrite<idp.IdpRadiusProfile>("radius_profile", creating ? name.trim() : profile.name, body)).data);
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={creating ? "New attribute profile" : `Profile ${profile.name}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => void save()} loading={busy}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 sm:col-span-1">
          <Input label="Name" value={name} disabled={!creating} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select
            label="Environment"
            value={environment}
            disabled={!creating}
            onChange={(e) => setEnvironment(e.target.value)}
            options={environmentOptions(creating ? directory.activeEnvironments : [environment])}
          />
        </div>
        <div className="col-span-2">
          <Input label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {envRoles.map((role) => (
          <div key={role} className="col-span-2 space-y-2 rounded-md border border-[var(--color-border)] p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{role}</span>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => update(role, (a) => [...a, { attribute: "fortinet-group-name", value: "", vendor_id: "", vendor_type: "" }])}
              >
                Add attribute
              </Button>
            </div>
            {(roles[role] ?? []).map((a, i) => (
              <div key={i} className="grid grid-cols-2 gap-3">
                <Select
                  aria-label={`${role} attribute ${i + 1}`}
                  value={a.attribute}
                  onChange={(e) => update(role, (all) => all.map((x, j) => (j === i ? { ...x, attribute: e.target.value } : x)))}
                  options={ATTRIBUTES}
                />
                <div className="flex min-w-0 gap-2">
                  <div className="min-w-0 flex-1">
                    <Input
                      aria-label={`${role} value ${i + 1}`}
                      value={a.value}
                      onChange={(e) => update(role, (all) => all.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))}
                    />
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => update(role, (all) => all.filter((_, j) => j !== i))}>
                    Remove
                  </Button>
                </div>
                {a.attribute === "vsa" && (
                  <>
                    <Input
                      aria-label={`${role} vendor id ${i + 1}`}
                      placeholder="vendor id"
                      inputMode="numeric"
                      value={a.vendor_id}
                      onChange={(e) => update(role, (all) => all.map((x, j) => (j === i ? { ...x, vendor_id: e.target.value } : x)))}
                    />
                    <Input
                      aria-label={`${role} vendor type ${i + 1}`}
                      placeholder="vendor type"
                      inputMode="numeric"
                      value={a.vendor_type}
                      onChange={(e) => update(role, (all) => all.map((x, j) => (j === i ? { ...x, vendor_type: e.target.value } : x)))}
                    />
                  </>
                )}
              </div>
            ))}
          </div>
        ))}
        {environment && envRoles.length === 0 && (
          <p className="col-span-2 text-xs text-[var(--color-text-muted)]">This environment defines no roles.</p>
        )}
        {error && (
          <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
