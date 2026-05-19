// Phase 7.3 — Reusable editor for one tier of Rustion transport-and-bastion
// policy. Drops into the Asset Groups detail card, the Resource Types
// subpanel, and the Resource Connection tab.
//
// Tier behaviours:
//   - "type":         lock=true allowed (admin-only on the API side)
//   - "asset-group":  lock=true allowed + priority slider visible
//   - "resource":     lock toggle hidden (API refuses lock=true)
//
// All four tiers ship the same five knobs (transport / bastions /
// bastion_group / recording / lock) plus per-AG `priority`. The
// component manages its own load/save state via the typed wrappers in
// gui/src/lib/rustion.ts.

import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, Input, Select, useToast } from "./ui";
import { extractError } from "../lib/error";
import {
  rustionPolicyAssetGroupRead,
  rustionPolicyAssetGroupWrite,
  rustionPolicyResourceRead,
  rustionPolicyResourceWrite,
  rustionPolicyTypeDelete,
  rustionPolicyTypeRead,
  rustionPolicyTypeWrite,
  type Recording,
  type RustionPolicyTier,
  type Transport,
} from "../lib/rustion";

export type PolicyTierKind = "type" | "asset-group" | "resource";

interface Props {
  tier: PolicyTierKind;
  /** type_name for "type", asset_group_id for "asset-group",
   *  resource_id for "resource". */
  id: string;
  /** Optional callback after a successful save. */
  onSaved?: () => void;
}

export function RustionPolicyTierEditor({ tier, id, onSaved }: Props) {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [exists, setExists] = useState(false);
  const [transport, setTransport] = useState<Transport>("");
  const [bastionsList, setBastionsList] = useState("");
  const [bastionGroup, setBastionGroup] = useState("");
  const [recording, setRecording] = useState<Recording>("");
  const [lock, setLock] = useState(false);
  const [priority, setPriority] = useState(0);
  const [saving, setSaving] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      if (tier === "type") {
        try {
          const p = await rustionPolicyTypeRead(id);
          setExists(true);
          setTransport(p.transport as Transport);
          setBastionsList(p.bastions.join(", "));
          setBastionGroup(p.bastionGroup);
          setRecording(p.recording as Recording);
          setLock(p.lock);
        } catch {
          // 404 → not configured yet; clear-state form.
          setExists(false);
          setTransport("");
          setBastionsList("");
          setBastionGroup("");
          setRecording("");
          setLock(false);
        }
      } else if (tier === "asset-group") {
        try {
          const p = await rustionPolicyAssetGroupRead(id);
          setExists(true);
          setTransport(p.transport as Transport);
          setBastionsList(p.bastions.join(", "));
          setBastionGroup(p.bastionGroup);
          setRecording(p.recording as Recording);
          setLock(p.lock);
          setPriority(p.priority);
        } catch {
          setExists(false);
          setTransport("");
          setBastionsList("");
          setBastionGroup("");
          setRecording("");
          setLock(false);
          setPriority(0);
        }
      } else {
        try {
          const p = await rustionPolicyResourceRead(id);
          setExists(true);
          setTransport(p.transport as Transport);
          setBastionsList(p.bastions.join(", "));
          setBastionGroup(p.bastionGroup);
          setRecording(p.recording as Recording);
          setLock(false);
        } catch {
          setExists(false);
          setTransport("");
          setBastionsList("");
          setBastionGroup("");
          setRecording("");
          setLock(false);
        }
      }
    } finally {
      setLoading(false);
    }
  }, [tier, id]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleSave = async () => {
    if (!id) {
      toast.toast("error", "Missing tier id");
      return;
    }
    setSaving(true);
    try {
      const bastions = bastionsList
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const tierInput: RustionPolicyTier = {
        transport,
        bastions,
        bastionGroup,
        recording,
        lock: tier === "resource" ? false : lock,
      };
      if (tier === "type") {
        await rustionPolicyTypeWrite(id, tierInput);
      } else if (tier === "asset-group") {
        await rustionPolicyAssetGroupWrite(id, {
          priority,
          ...tierInput,
        });
      } else {
        await rustionPolicyResourceWrite(id, tierInput);
      }
      toast.toast("success", `${tierLabel(tier)} policy saved`);
      await reload();
      onSaved?.();
    } catch (e) {
      toast.toast(
        "error",
        `Save failed: ${extractError(e)}`,
      );
    } finally {
      setSaving(false);
    }
  };

  const handleClear = async () => {
    if (tier !== "type") {
      // For asset-group and resource we just write an empty tier to
      // effectively reset (no Delete endpoint on those, by design —
      // empty fields fall through to the next tier).
      setTransport("");
      setBastionsList("");
      setBastionGroup("");
      setRecording("");
      setLock(false);
      return;
    }
    setSaving(true);
    try {
      await rustionPolicyTypeDelete(id);
      toast.toast("success", "Type policy cleared");
      await reload();
      onSaved?.();
    } catch (e) {
      toast.toast("error", `Clear failed: ${extractError(e)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card
      title={`Rustion policy (${tierLabel(tier)})`}
      actions={
        exists ? <Badge variant="info" label="configured" /> : <Badge variant="neutral" label="not configured" />
      }
    >
      {loading ? (
        <div className="py-3 text-sm text-[var(--color-text-muted)]">Loading…</div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-[var(--color-text-muted)]">
            {tierDescription(tier)}
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Transport"
              value={transport}
              onChange={(e) => setTransport(e.target.value as Transport)}
              options={[
                { value: "", label: "(unset — fall through)" },
                { value: "direct", label: "direct" },
                { value: "rustion-preferred", label: "rustion-preferred" },
                { value: "rustion-required", label: "rustion-required" },
              ]}
            />
            <Select
              label="Recording"
              value={recording}
              onChange={(e) => setRecording(e.target.value as Recording)}
              options={[
                { value: "", label: "(unset — fall through)" },
                { value: "always", label: "always" },
                { value: "input-redacted", label: "input-redacted" },
                { value: "off", label: "off" },
              ]}
            />
            <Input
              label="Bastion group"
              value={bastionGroup}
              onChange={(e) => setBastionGroup(e.target.value)}
              placeholder="(unset)"
            />
            <Input
              label="Pinned bastions"
              value={bastionsList}
              onChange={(e) => setBastionsList(e.target.value)}
              placeholder="rt_…, rt_…"
            />
            {tier === "asset-group" && (
              <div className="col-span-2">
                <Input
                  label={`Priority (higher wins: ${priority})`}
                  type="number"
                  value={String(priority)}
                  onChange={(e) =>
                    setPriority(parseInt(e.target.value || "0", 10) || 0)
                  }
                />
              </div>
            )}
            {tier !== "resource" && (
              <div className="col-span-2">
                <label className="inline-flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={lock}
                    onChange={(e) => setLock(e.target.checked)}
                  />
                  <span>
                    Lock — lower tiers cannot weaken these settings.{" "}
                    {lock && <Badge variant="warning" label="locked" />}
                  </span>
                </label>
              </div>
            )}
            {tier === "resource" && (
              <div className="col-span-2 text-xs text-[var(--color-text-muted)]">
                Per-resource overrides may not lock; only higher tiers may.
                Lower tiers locked by an upstream policy will refuse a
                write that weakens them (403 lock_violation).
              </div>
            )}
          </div>
          <div className="flex justify-end gap-2">
            {exists && (
              <Button onClick={handleClear} variant="secondary" loading={saving}>
                {tier === "type" ? "Delete tier" : "Clear fields"}
              </Button>
            )}
            <Button onClick={handleSave} loading={saving} variant="primary">
              Save
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

function tierLabel(t: PolicyTierKind): string {
  switch (t) {
    case "type":
      return "type";
    case "asset-group":
      return "asset group";
    case "resource":
      return "resource";
  }
}

function tierDescription(t: PolicyTierKind): string {
  switch (t) {
    case "type":
      return "Per-resource-type policy. Admin-gated. Defaults applied to every resource of this type unless a lower tier overrides.";
    case "asset-group":
      return "Per-asset-group policy. Admin or group-owner gated. Higher priority asset groups win when a resource belongs to multiple groups.";
    case "resource":
      return "Per-resource override. Gated to the resource owner. Cannot weaken a lock from a higher tier.";
  }
}
