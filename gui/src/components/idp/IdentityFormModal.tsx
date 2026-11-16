import { useEffect, useState } from "react";
import { Button, EntityPicker, Input, Modal, Select } from "../ui";
import * as idp from "../../lib/idp";

function parseGids(raw: string): number[] {
  return idp.splitList(raw).map((s) => {
    const n = Number(s);
    if (!Number.isInteger(n) || n <= 0) throw new Error(`"${s}" is not a group id`);
    return n;
  });
}

/**
 * Allocate a workforce identity, or edit the two mutable fields of one
 * (display name, supplementary gids). Login, uid and primary gid are shown
 * read-only when editing: they are immutable for life.
 */
export function IdentityFormModal({
  mode,
  identity,
  onClose,
  onSaved,
}: {
  mode: "allocate" | "edit";
  identity?: idp.IdpIdentity | null;
  onClose: () => void;
  onSaved: (rec: idp.IdpIdentity) => void;
}) {
  const [entityId, setEntityId] = useState("");
  const [login, setLogin] = useState("");
  const [displayName, setDisplayName] = useState(identity?.display_name ?? "");
  const [gids, setGids] = useState((identity?.gids ?? []).join(", "));
  const [source, setSource] = useState<"vault" | "imported">("vault");
  const [uid, setUid] = useState("");
  const [primaryGid, setPrimaryGid] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDisplayName(identity?.display_name ?? "");
    setGids((identity?.gids ?? []).join(", "));
  }, [identity]);

  async function save() {
    setError(null);
    let body: Record<string, unknown>;
    try {
      body = { display_name: displayName.trim(), gids: parseGids(gids) };
      if (mode === "allocate") {
        body.login = login.trim();
        if (!entityId.trim()) throw new Error("Pick the entity this identity belongs to");
        if (!body.login) throw new Error("A login is required");
        if (source === "imported") {
          const u = Number(uid);
          if (!Number.isInteger(u)) throw new Error("An imported identity needs its uid");
          body.uid_source = "imported";
          body.uid = u;
          if (primaryGid.trim()) body.primary_gid = Number(primaryGid);
        }
        if (!body.display_name) delete body.display_name;
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    const target = mode === "allocate" ? entityId.trim() : identity?.entity_id ?? "";
    setBusy(true);
    try {
      const resp = await idp.idpWrite<idp.IdpIdentity>("identity", target, body);
      onSaved(resp.data);
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
      title={mode === "allocate" ? "Allocate workforce identity" : `Edit ${identity?.login ?? "identity"}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => void save()} loading={busy}>
            {mode === "allocate" ? "Allocate" : "Save"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        {mode === "allocate" ? (
          <>
            <div className="col-span-2">
              <EntityPicker
                label="Entity"
                value={entityId}
                onChange={(id) => setEntityId(id)}
                hint="The identity-store entity this person signs in as. It must exist."
              />
            </div>
            <div className="col-span-2 sm:col-span-1">
              <Input
                label="Login"
                value={login}
                onChange={(e) => setLogin(e.target.value)}
                hint="Lower case, at most 32 characters. Immutable and never reused."
              />
            </div>
            <div className="col-span-2 sm:col-span-1">
              <Select
                label="uid source"
                value={source}
                onChange={(e) => setSource(e.target.value as "vault" | "imported")}
                options={[
                  { value: "vault", label: "Allocate from the range" },
                  { value: "imported", label: "Import an existing uid" },
                ]}
              />
            </div>
            {source === "imported" && (
              <>
                <div className="col-span-2 sm:col-span-1">
                  <Input label="uid" value={uid} inputMode="numeric" onChange={(e) => setUid(e.target.value)} />
                </div>
                <div className="col-span-2 sm:col-span-1">
                  <Input
                    label="Primary gid"
                    value={primaryGid}
                    inputMode="numeric"
                    onChange={(e) => setPrimaryGid(e.target.value)}
                    hint="Defaults to the uid."
                  />
                </div>
              </>
            )}
          </>
        ) : (
          <div className="col-span-2 grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
            {[
              ["Login", identity?.login ?? ""],
              ["uid", String(identity?.uid ?? "")],
              ["Primary gid", String(identity?.primary_gid ?? "")],
            ].map(([k, v]) => (
              <div key={k} className="min-w-0" title="Immutable: changing it would break file ownership and audit trails">
                <div className="text-xs text-[var(--color-text-muted)]">{k} (immutable)</div>
                <div className="font-mono truncate">{v}</div>
              </div>
            ))}
          </div>
        )}
        <div className="col-span-2">
          <Input label="Display name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </div>
        <div className="col-span-2">
          <Input
            label="Supplementary gids"
            value={gids}
            onChange={(e) => setGids(e.target.value)}
            hint="Comma-separated. Another identity's primary group is refused."
          />
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
