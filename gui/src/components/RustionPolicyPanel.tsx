// Settings → Rustion Policy panel — Phase 7.
//
// Surfaces:
//   - Global policy editor (root-gated: API enforces).
//   - Bastion Groups CRUD.
//   - "Force all Connect through Rustion" migration action with a
//     dry-run diff preview.
//
// Per-resource-type / per-asset-group / per-resource overrides live
// on their respective pages (Resource Types, Asset Groups, Resource
// Connection tab) — Phase 7.3 wires those.

import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  Input,
  Modal,
  Select,
  Textarea,
  useToast,
} from "./ui";
import { RustionPolicyTierEditor } from "./RustionPolicyTierEditor";
import { extractError } from "../lib/error";
import {
  rustionBastionGroupCreate,
  rustionBastionGroupDelete,
  rustionBastionGroupList,
  rustionBastionGroupRead,
  rustionBastionGroupUpdate,
  rustionPolicyForceRustion,
  rustionPolicyGlobalRead,
  rustionPolicyGlobalWrite,
  type RustionBastionGroup,
  type RustionPolicyTier,
} from "../lib/rustion";

export function RustionPolicyPanel() {
  return (
    <div className="space-y-4">
      <GlobalPolicyCard />
      <BastionGroupsCard />
      <ResourceTypePolicyCard />
      <ForceRustionCard />
    </div>
  );
}

// ─── Global policy editor ───────────────────────────────────────────

function GlobalPolicyCard() {
  const toast = useToast();
  const [policy, setPolicy] = useState<RustionPolicyTier | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [bastionList, setBastionList] = useState("");

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const p = await rustionPolicyGlobalRead();
      setPolicy(p);
      setBastionList(p.bastions.join(", "));
    } catch (e) {
      toast.toast("error", `Failed to load global policy: ${extractError(e)}`);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleSave = async () => {
    if (!policy) return;
    setSaving(true);
    try {
      const input: RustionPolicyTier = {
        ...policy,
        bastions: bastionList
          .split(",")
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      };
      await rustionPolicyGlobalWrite(input);
      toast.toast("success", "Global Rustion policy saved");
      await reload();
    } catch (e) {
      toast.toast("error", `Save failed: ${extractError(e)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="Global Rustion policy">
      {loading || !policy ? (
        <div className="py-4 text-sm text-[var(--color-text-muted)]">
          Loading…
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-[var(--color-text-muted)]">
            Deployment-wide defaults. Root-gated by the API. Lock prevents
            lower tiers (resource type / asset group / resource) from
            weakening these settings.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Transport"
              value={policy.transport}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  transport: e.target.value as RustionPolicyTier["transport"],
                })
              }
              options={[
                { value: "", label: "(unset — fall through)" },
                { value: "direct", label: "direct" },
                { value: "rustion-preferred", label: "rustion-preferred" },
                { value: "rustion-required", label: "rustion-required" },
              ]}
            />
            <Select
              label="Recording"
              value={policy.recording}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  recording: e.target.value as RustionPolicyTier["recording"],
                })
              }
              options={[
                { value: "", label: "(unset — fall through)" },
                { value: "always", label: "always" },
                { value: "input-redacted", label: "input-redacted" },
                { value: "off", label: "off" },
              ]}
            />
            <Input
              label="Bastion group"
              value={policy.bastionGroup}
              onChange={(e) =>
                setPolicy({ ...policy, bastionGroup: e.target.value })
              }
              placeholder="(unset)"
            />
            <Input
              label="Pinned bastions (comma-separated)"
              value={bastionList}
              onChange={(e) => setBastionList(e.target.value)}
              placeholder="rt_abc…, rt_def…"
            />
            <div className="col-span-2">
              <label className="inline-flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={policy.lock}
                  onChange={(e) =>
                    setPolicy({ ...policy, lock: e.target.checked })
                  }
                />
                <span>
                  Lock — lower tiers cannot weaken these settings.{" "}
                  {policy.lock && (
                    <Badge variant="warning" label="locked" />
                  )}
                </span>
              </label>
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={handleSave} loading={saving} variant="primary">
              Save global policy
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

// ─── Bastion groups CRUD ────────────────────────────────────────────

function BastionGroupsCard() {
  const toast = useToast();
  const [names, setNames] = useState<string[]>([]);
  const [groups, setGroups] = useState<RustionBastionGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<RustionBastionGroup | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const ids = await rustionBastionGroupList();
      setNames(ids);
      const rows = await Promise.all(
        ids.map((n) => rustionBastionGroupRead(n).catch(() => null)),
      );
      setGroups(rows.filter((g): g is RustionBastionGroup => g !== null));
    } catch (e) {
      toast.toast("error", `Failed to load bastion groups: ${extractError(e)}`);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleDelete = async () => {
    if (!deleting) return;
    try {
      await rustionBastionGroupDelete(deleting);
      toast.toast("success", `Deleted bastion group ${deleting}`);
      setDeleting(null);
      await reload();
    } catch (e) {
      toast.toast("error", `Delete failed: ${extractError(e)}`);
    }
  };

  return (
    <Card title={`Bastion groups (${names.length})`}>
      <div className="flex justify-end mb-3">
        <Button variant="primary" onClick={() => setCreating(true)}>
          Create group
        </Button>
      </div>
      {loading ? (
        <div className="py-4 text-sm text-[var(--color-text-muted)]">
          Loading…
        </div>
      ) : groups.length === 0 ? (
        <EmptyState
          title="No bastion groups yet"
          description="Bastion groups are named pools of Rustion targets that the policy resolver can pin per resource, asset group, type, or globally."
        />
      ) : (
        <div className="space-y-2">
          {groups.map((g) => (
            <div
              key={g.name}
              className="flex items-center justify-between gap-3 p-3 border border-[var(--color-border)] rounded"
            >
              <div className="min-w-0">
                <div className="font-mono text-sm">{g.name}</div>
                <div className="text-xs text-[var(--color-text-muted)]">
                  {g.members.length} member{g.members.length === 1 ? "" : "s"} ·{" "}
                  <span className="font-mono">{g.selection}</span>
                  {g.description && (
                    <span className="ml-2 truncate">— {g.description}</span>
                  )}
                </div>
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => setEditing(g)}>
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  onClick={() => setDeleting(g.name)}
                >
                  Delete
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
      {creating && (
        <BastionGroupEditor
          mode="create"
          initial={null}
          onClose={() => setCreating(false)}
          onSaved={async () => {
            setCreating(false);
            await reload();
          }}
        />
      )}
      {editing && (
        <BastionGroupEditor
          mode="edit"
          initial={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await reload();
          }}
        />
      )}
      {deleting && (
        <ConfirmModal
          open
          title={`Delete bastion group ${deleting}?`}
          message="Resources or asset groups currently pinning this group will fall through to the next-defined tier or the global pool."
          confirmLabel="Delete"
          variant="danger"
          onClose={() => setDeleting(null)}
          onConfirm={handleDelete}
        />
      )}
    </Card>
  );
}

function BastionGroupEditor({
  mode,
  initial,
  onClose,
  onSaved,
}: {
  mode: "create" | "edit";
  initial: RustionBastionGroup | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const toast = useToast();
  const [name, setName] = useState(initial?.name ?? "");
  const [members, setMembers] = useState((initial?.members ?? []).join(", "));
  const [selection, setSelection] = useState(initial?.selection ?? "ordered");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    if (!name) {
      toast.toast("error", "Name is required");
      return;
    }
    setSaving(true);
    try {
      const input = {
        name,
        members: members
          .split(",")
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
        selection: selection as "ordered" | "random",
        description,
      };
      if (mode === "create") {
        await rustionBastionGroupCreate(input);
        toast.toast("success", `Created bastion group ${name}`);
      } else {
        await rustionBastionGroupUpdate(name, input);
        toast.toast("success", `Updated bastion group ${name}`);
      }
      await onSaved();
    } catch (e) {
      toast.toast("error", `${mode === "create" ? "Create" : "Update"} failed: ${extractError(e)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={mode === "create" ? "Create bastion group" : `Edit ${name}`}
      size="md"
    >
      <div className="space-y-3">
        <Input
          label="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="eu-west, prod-jump, …"
          disabled={mode === "edit"}
        />
        <Textarea
          label="Members (comma-separated bastion ids)"
          value={members}
          onChange={(e) => setMembers(e.target.value)}
          rows={3}
          placeholder="rt_abc…, rt_def…"
        />
        <Select
          label="Selection"
          value={selection}
          onChange={(e) => setSelection(e.target.value as "ordered" | "random")}
          options={[
            { value: "ordered", label: "ordered (pinned-fallback)" },
            { value: "random", label: "random (round-robin)" },
          ]}
        />
        <Input
          label="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose} variant="secondary">
            Cancel
          </Button>
          <Button onClick={handleSave} loading={saving} variant="primary">
            {mode === "create" ? "Create" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ─── Resource Type policy subpanel ──────────────────────────────────

function ResourceTypePolicyCard() {
  const toast = useToast();
  const [typeName, setTypeName] = useState("");
  const [committed, setCommitted] = useState<string | null>(null);

  const handleLoad = () => {
    const t = typeName.trim();
    if (!t) {
      toast.toast("error", "Enter a resource type name");
      return;
    }
    setCommitted(t);
  };

  return (
    <Card title="Resource type policy">
      <div className="space-y-3">
        <p className="text-sm text-[var(--color-text-muted)]">
          Per-resource-type policy. Admin-gated on the API. Enter a type
          name (the same identifier resources use as their{" "}
          <code>type_name</code>) to load + edit its policy.
        </p>
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <Input
              label="Resource type"
              value={typeName}
              onChange={(e) => setTypeName(e.target.value)}
              placeholder="ssh-host, mysql, rdp-host, …"
            />
          </div>
          <Button variant="primary" onClick={handleLoad}>
            Load
          </Button>
        </div>
        {committed && (
          <RustionPolicyTierEditor
            key={committed}
            tier="type"
            id={committed}
          />
        )}
      </div>
    </Card>
  );
}

// ─── Force-all-through-Rustion migration action ─────────────────────

function ForceRustionCard() {
  const toast = useToast();
  const [preview, setPreview] = useState<{
    current_transport: string;
    proposed_transport: string;
    current_lock: boolean;
    proposed_lock: boolean;
  } | null>(null);
  const [applying, setApplying] = useState(false);

  const handlePreview = async () => {
    try {
      const p = await rustionPolicyForceRustion(false);
      setPreview({
        current_transport: p.currentTransport,
        proposed_transport: p.proposedTransport,
        current_lock: p.currentLock,
        proposed_lock: p.proposedLock,
      });
    } catch (e) {
      toast.toast("error", `Preview failed: ${extractError(e)}`);
    }
  };

  const handleApply = async () => {
    setApplying(true);
    try {
      await rustionPolicyForceRustion(true);
      toast.toast(
        "success",
        "Forced all Connect through Rustion (locked at global tier).",
      );
      setPreview(null);
    } catch (e) {
      toast.toast("error", `Apply failed: ${extractError(e)}`);
    } finally {
      setApplying(false);
    }
  };

  return (
    <Card title="Force all Connect through Rustion">
      <div className="space-y-3">
        <p className="text-sm text-[var(--color-text-muted)]">
          Flips the global policy to <code>transport = rustion-required</code> +{" "}
          <code>lock = true</code>. After this, the per-tier overrides
          (resource type / asset group / resource) can still pin a specific
          bastion group, but cannot drop back to <code>direct</code>.
          Root-only.
        </p>
        {!preview ? (
          <Button onClick={handlePreview} variant="secondary">
            Preview change
          </Button>
        ) : (
          <ConfirmModal
            open
            title="Force all Connect through Rustion?"
            message={`Current transport: ${preview.current_transport} (locked=${preview.current_lock}). Proposed: ${preview.proposed_transport} (locked=${preview.proposed_lock}). Sessions configured with transport=direct at any tier will start returning 403 lock_violation until they raise their setting.`}
            confirmLabel="Apply"
            variant="danger"
            onClose={() => setPreview(null)}
            onConfirm={handleApply}
            loading={applying}
          />
        )}
      </div>
    </Card>
  );
}
