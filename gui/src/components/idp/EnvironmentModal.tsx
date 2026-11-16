import { useState } from "react";
import { Button, Input, Modal, Select } from "../ui";
import { useNamespaceStore } from "../../stores/namespaceStore";
import * as idp from "../../lib/idp";

type RoleRow = { role: string; policies: string };

function toRows(roles: Record<string, string[]> | undefined): RoleRow[] {
  const rows = Object.entries(roles ?? {}).map(([role, policies]) => ({ role, policies: policies.join(", ") }));
  return rows.length > 0 ? rows : [{ role: "", policies: "" }];
}

/**
 * Create an environment (bound for life to one namespace) or edit its role
 * map and description. A role maps to ACL policy names in that namespace;
 * each write replaces the whole map.
 */
export function EnvironmentModal({
  environment,
  onClose,
  onSaved,
}: {
  environment: idp.IdpEnvironment | null;
  onClose: () => void;
  onSaved: (env: idp.IdpEnvironment) => void;
}) {
  const creating = environment === null;
  const namespaces = useNamespaceStore((s) => s.namespaces);
  const [name, setName] = useState(environment?.name ?? "");
  const [namespace, setNamespace] = useState(environment?.namespace ?? "");
  const [description, setDescription] = useState(environment?.description ?? "");
  const [rows, setRows] = useState<RoleRow[]>(toRows(environment?.roles));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const nsOptions = Array.from(new Set(["", ...namespaces])).map((n) => ({ value: n, label: n === "" ? "(root)" : n }));

  function setRow(i: number, patch: Partial<RoleRow>) {
    setRows((prev) => prev.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  async function save() {
    setError(null);
    const roles: Record<string, string[]> = {};
    for (const r of rows) {
      if (!r.role.trim()) continue;
      roles[r.role.trim()] = idp.splitList(r.policies);
    }
    const body: Record<string, unknown> = { roles, description: description.trim() };
    if (creating) body.namespace = namespace;
    const target = creating ? name.trim() : environment.name;
    if (!target) {
      setError("A name is required");
      return;
    }
    setBusy(true);
    try {
      onSaved((await idp.idpWrite<idp.IdpEnvironment>("environment", target, body)).data);
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
      title={creating ? "New environment" : `Environment ${environment.name}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => void save()} loading={busy}>
            {creating ? "Create" : "Save"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 sm:col-span-1">
          <Input
            label="Name"
            value={name}
            disabled={!creating}
            onChange={(e) => setName(e.target.value)}
            hint={creating ? "Lower case; a retired name is never reused." : undefined}
          />
        </div>
        <div className="col-span-2 sm:col-span-1">
          {creating ? (
            <Select
              label="Namespace"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              options={nsOptions}
            />
          ) : (
            <Input label="Namespace (bound for life)" value={environment.namespace || "(root)"} disabled />
          )}
        </div>
        <div className="col-span-2">
          <Input label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div className="col-span-2 space-y-2">
          <div className="text-sm font-medium text-[var(--color-text-muted)]">Roles → policies in that namespace</div>
          {rows.map((r, i) => (
            <div key={i} className="grid grid-cols-2 gap-3">
              <Input aria-label={`Role ${i + 1}`} placeholder="role (e.g. sysadmin)" value={r.role} onChange={(e) => setRow(i, { role: e.target.value })} />
              <div className="flex min-w-0 gap-2">
                <div className="min-w-0 flex-1">
                  <Input
                    aria-label={`Policies for role ${i + 1}`}
                    placeholder="policy-a, policy-b"
                    value={r.policies}
                    onChange={(e) => setRow(i, { policies: e.target.value })}
                  />
                </div>
                <Button size="sm" variant="ghost" onClick={() => setRows((prev) => prev.filter((_, j) => j !== i))}>
                  Remove
                </Button>
              </div>
            </div>
          ))}
          <Button size="sm" variant="secondary" onClick={() => setRows((prev) => [...prev, { role: "", policies: "" }])}>
            Add role
          </Button>
          <p className="text-xs text-[var(--color-text-muted)]">
            root, response-wrapping and control-group are refused. Whether a policy exists is not checked.
          </p>
        </div>
        {error && (
          <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
