import { useEffect, useState } from "react";
import { Button, Card, ConfirmModal, ResourceTypeIcon, useToast } from "./ui";
import { TypeEditorModal } from "./TypeEditorModal";
import type { ResourceTypeConfig, ResourceTypeDef } from "../lib/types";
import { DEFAULT_RESOURCE_TYPES, parseTypeConfig, serializeTypeConfig } from "../lib/resourceTypes";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

/**
 * The resource type editor for the active namespace's resource mount.
 *
 * Every namespace has its own `resources/config/types`. One that has saved
 * none is governed by the root namespace's (the server's fallback), so the
 * card starts from what the server actually enforces and says where it came
 * from. Saving writes this namespace's own configuration, which from then on
 * replaces the root's here — wholesale, not per type.
 */
export function ResourceTypesCard({ inNamespace }: { inNamespace: boolean }) {
  const { toast } = useToast();
  const [resTypes, setResTypes] = useState<ResourceTypeConfig>(DEFAULT_RESOURCE_TYPES);
  // Builtin type ids the operator deleted (tombstones in the saved config).
  const [removedBuiltins, setRemovedBuiltins] = useState<string[]>([]);
  const [source, setSource] = useState<api.TypeConfigSource | "error" | null>(null);
  const [editType, setEditType] = useState<ResourceTypeDef | null>(null);
  const [deleteTypeId, setDeleteTypeId] = useState<string | null>(null);
  const [showAddType, setShowAddType] = useState(false);

  useEffect(() => {
    void load();
  }, []);

  async function load() {
    try {
      const effective = await api.resourceTypesReadEffective();
      const parsed = parseTypeConfig(effective.types);
      setResTypes(parsed.types);
      setRemovedBuiltins(parsed.removedBuiltins);
      setSource(effective.source);
    } catch (e: unknown) {
      setResTypes(DEFAULT_RESOURCE_TYPES);
      setRemovedBuiltins([]);
      setSource("error");
      toast("error", extractError(e));
    }
  }

  // Every write carries the tombstones (deleted builtins), so the additive
  // merge never brings a deleted builtin back. See `serializeTypeConfig`.
  async function save(updated: ResourceTypeConfig, removed: string[]) {
    try {
      await api.resourceTypesWrite(serializeTypeConfig(updated, removed));
      setResTypes(updated);
      setRemovedBuiltins(removed);
      setSource("mount");
      toast("success", "Resource types saved");
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function handleSaveType(typeDef: ResourceTypeDef) {
    const updated = { ...resTypes, [typeDef.id]: typeDef };
    // Re-adding a deleted builtin's id lifts its tombstone.
    void save(updated, removedBuiltins.filter((id) => id !== typeDef.id));
    setEditType(null);
    setShowAddType(false);
  }

  function handleDeleteType() {
    if (!deleteTypeId) return;
    const updated = { ...resTypes };
    delete updated[deleteTypeId];
    const removed =
      deleteTypeId in DEFAULT_RESOURCE_TYPES && !removedBuiltins.includes(deleteTypeId)
        ? [...removedBuiltins, deleteTypeId]
        : removedBuiltins;
    void save(updated, removed);
    setDeleteTypeId(null);
  }

  return (
    <>
      <Card
        title="Resource Types"
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => void save(DEFAULT_RESOURCE_TYPES, [])}>
              Reset to Defaults
            </Button>
            <Button size="sm" onClick={() => setShowAddType(true)}>Add Type</Button>
          </div>
        }
      >
        <TypeConfigSourceNotice source={source} inNamespace={inNamespace} />
        <div className="space-y-2">
          {Object.values(resTypes).map((t) => (
            <div
              key={t.id}
              className="flex items-center justify-between py-2 border-b border-[var(--color-border)] last:border-0"
            >
              <div className="flex items-center gap-2 min-w-0">
                <ResourceTypeIcon typeDef={t} withLabel />
                <span className="text-xs text-[var(--color-text-muted)]">{t.fields.length} fields</span>
              </div>
              <div className="flex gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditType({ ...t, fields: t.fields.map((f) => ({ ...f })) })}
                >
                  Edit
                </Button>
                <Button size="sm" variant="danger" onClick={() => setDeleteTypeId(t.id)}>Delete</Button>
              </div>
            </div>
          ))}
          {Object.keys(resTypes).length === 0 && (
            <p className="text-sm text-[var(--color-text-muted)]">
              No types configured. Add a type or reset to defaults.
            </p>
          )}
        </div>
      </Card>

      {(editType || showAddType) && (
        <TypeEditorModal
          typeDef={editType}
          onSave={handleSaveType}
          onClose={() => {
            setEditType(null);
            setShowAddType(false);
          }}
        />
      )}

      <ConfirmModal
        open={deleteTypeId !== null}
        onClose={() => setDeleteTypeId(null)}
        onConfirm={handleDeleteType}
        title="Delete Resource Type"
        message={`Delete the "${deleteTypeId}" resource type? Existing resources of this type will keep their data but won't have field definitions.`}
        confirmLabel="Delete"
      />
    </>
  );
}

/** Where the types shown come from — the shown values are only enforced
 *  once they are saved somewhere the server reads. */
function TypeConfigSourceNotice({
  source,
  inNamespace,
}: {
  source: api.TypeConfigSource | "error" | null;
  inNamespace: boolean;
}) {
  if (source === null || source === "mount") return null;
  const text =
    source === "root" ? (
      <>
        This namespace has not saved its own resource types, so the <strong>root namespace&rsquo;s</strong> saved
        types apply here (shown below). Saving creates this namespace&rsquo;s own configuration, which then
        replaces the root&rsquo;s for this namespace entirely.
      </>
    ) : source === "none" ? (
      <>
        No resource types are saved{inNamespace ? " in this namespace or the root namespace" : ""}: the list below
        is the built-in defaults, which the server does not enforce. Until you save, web credential release (form
        and HTTP-auth logins) is denied for every type.
      </>
    ) : (
      <>Could not read the saved resource types; the list below is the built-in defaults.</>
    );
  return (
    <p
      className="mb-3 text-xs text-[var(--color-text-muted)] border border-[var(--color-border)] rounded px-3 py-2"
      data-testid={`type-config-source-${source}`}
    >
      {text}
    </p>
  );
}
