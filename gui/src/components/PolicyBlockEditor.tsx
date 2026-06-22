import { useEffect, useRef, useState } from "react";
import { Button, Card, Input, Badge, CollapsibleSection } from "./ui";
import {
  parsePolicyHcl,
  serializePolicyModel,
  CAPABILITIES,
  type PolicyModel,
  type PolicyBlock,
} from "../lib/policyHcl";

interface Props {
  /** Current policy HCL (the source of truth). */
  value: string;
  /** Emit serialized HCL whenever a block is edited. */
  onChange: (hcl: string) => void;
  /**
   * Called when the incoming HCL fails to parse into blocks, so the parent
   * can keep the operator on the source tab (per the spec's round-trip
   * rule). Passed the error message, or null once parsing succeeds.
   */
  onParseError?: (message: string | null) => void;
}

// The CRUD set is offered as the default chip group; the rest are
// advanced. `root` is a policy-level concept, surfaced disabled.
const PRIMARY_CAPS = ["create", "read", "update", "delete", "list"] as const;
const ADVANCED_CAPS = ["patch", "sudo", "connect"] as const;

function emptyBlock(): PolicyBlock {
  return { path: "", capabilities: ["read"] };
}

/** Classify a path's wildcard usage for the inline lint badge. */
function globLint(path: string): { variant: "error" | "warning" | "info" | "neutral"; label: string } {
  if (path.includes("+*")) return { variant: "error", label: "invalid +*" };
  if (path === "*" || path === "") return { variant: "warning", label: "matches everything" };
  if (path.endsWith("*")) return { variant: "info", label: "prefix" };
  if (path === "+" || path.includes("/+") || path.startsWith("+/")) return { variant: "info", label: "segment +" };
  return { variant: "neutral", label: "exact" };
}

function csvToArray(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * Visual, block-based ACL policy editor. Each `path "..." { ... }` rule is
 * a card with capability toggles and collapsible dynamic blocks. Round-trips
 * losslessly to and from HCL: it parses the incoming `value` into a block
 * model and serializes back to HCL on every edit. HCL remains the source of
 * truth — see `features/policy-builder-validator.md`.
 */
export function PolicyBlockEditor({ value, onChange, onParseError }: Props) {
  const [model, setModel] = useState<PolicyModel>({ blocks: [] });
  const [parseError, setParseError] = useState<string | null>(null);
  // The last HCL we emitted, so an external edit (source tab) is
  // distinguishable from our own round-trip and we don't fight the parent.
  const lastSerialized = useRef<string>("");

  useEffect(() => {
    if (value === lastSerialized.current) return;
    const r = parsePolicyHcl(value);
    if (r.ok) {
      setModel(r.model);
      setParseError(null);
      onParseError?.(null);
    } else {
      const msg = r.errors[0]?.message ?? "could not parse policy";
      setParseError(msg);
      onParseError?.(msg);
    }
  }, [value, onParseError]);

  function commit(next: PolicyModel) {
    setModel(next);
    const hcl = serializePolicyModel(next);
    lastSerialized.current = hcl;
    setParseError(null);
    onParseError?.(null);
    onChange(hcl);
  }

  function updateBlock(i: number, patch: Partial<PolicyBlock>) {
    const blocks = model.blocks.map((b, idx) => (idx === i ? { ...b, ...patch } : b));
    commit({ ...model, blocks });
  }

  function toggleCap(i: number, cap: string) {
    const b = model.blocks[i];
    const has = b.capabilities.includes(cap);
    let caps: string[];
    if (cap === "deny") {
      // deny is mutually exclusive with everything else.
      caps = has ? [] : ["deny"];
    } else {
      caps = has ? b.capabilities.filter((c) => c !== cap) : [...b.capabilities.filter((c) => c !== "deny"), cap];
    }
    updateBlock(i, { capabilities: caps });
  }

  function move(i: number, dir: -1 | 1) {
    const j = i + dir;
    if (j < 0 || j >= model.blocks.length) return;
    const blocks = [...model.blocks];
    [blocks[i], blocks[j]] = [blocks[j], blocks[i]];
    commit({ ...model, blocks });
  }

  function addBlock() {
    commit({ ...model, blocks: [...model.blocks, emptyBlock()] });
  }

  function removeBlock(i: number) {
    commit({ ...model, blocks: model.blocks.filter((_, idx) => idx !== i) });
  }

  if (parseError) {
    return (
      <Card>
        <div className="rounded border border-[var(--color-danger)] bg-red-500/10 p-3 text-sm">
          <p className="font-medium text-red-400">This policy can&apos;t be shown in the visual builder.</p>
          <p className="mt-1 text-[var(--color-text-muted)]">{parseError}</p>
          <p className="mt-2 text-[var(--color-text-muted)]">
            Switch to the <span className="font-medium">HCL source</span> tab to fix the syntax — your content is
            preserved.
          </p>
        </div>
      </Card>
    );
  }

  const preview = serializePolicyModel(model);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--color-text-muted)]">
          {model.blocks.length} rule{model.blocks.length === 1 ? "" : "s"}
        </p>
        <Button size="sm" variant="secondary" onClick={addBlock}>
          + Add rule
        </Button>
      </div>

      {model.blocks.length === 0 && (
        <Card>
          <p className="text-sm text-[var(--color-text-muted)]">
            No rules yet. Add a rule to grant capabilities on a path.
          </p>
        </Card>
      )}

      {model.blocks.map((b, i) => {
        const lint = globLint(b.path);
        const denied = b.capabilities.includes("deny");
        return (
          <Card key={i}>
            <div className="space-y-3">
              {/* Path + reorder/remove */}
              <div className="flex items-end gap-2">
                <div className="min-w-0 flex-1">
                  <Input
                    label="Path"
                    value={b.path}
                    onChange={(e) => updateBlock(i, { path: e.target.value })}
                    placeholder='secret/data/team/*'
                  />
                </div>
                <Badge variant={lint.variant} label={lint.label} />
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" onClick={() => move(i, -1)} disabled={i === 0} title="Move up">
                    ↑
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => move(i, 1)}
                    disabled={i === model.blocks.length - 1}
                    title="Move down"
                  >
                    ↓
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => removeBlock(i)} title="Remove rule">
                    ✕
                  </Button>
                </div>
              </div>

              {/* Capability chips */}
              <div className="flex flex-wrap gap-1.5">
                <CapChip label="deny" active={denied} danger onClick={() => toggleCap(i, "deny")} />
                {PRIMARY_CAPS.map((c) => (
                  <CapChip
                    key={c}
                    label={c}
                    active={b.capabilities.includes(c)}
                    muted={denied}
                    onClick={() => toggleCap(i, c)}
                  />
                ))}
                {ADVANCED_CAPS.map((c) => (
                  <CapChip
                    key={c}
                    label={c}
                    active={b.capabilities.includes(c)}
                    muted={denied}
                    warn={c === "sudo"}
                    onClick={() => toggleCap(i, c)}
                  />
                ))}
                <CapChip label="root" active={b.capabilities.includes("root")} disabled />
              </div>
              {denied && (
                <p className="text-xs text-[var(--color-text-muted)]">
                  deny overrides every other capability and always wins on merge.
                </p>
              )}
              {b.capabilities.includes("connect") && (
                <p className="text-xs text-[var(--color-text-muted)]">
                  connect grants brokered session access without exposing the stored credential.
                </p>
              )}

              {/* Advanced / dynamic blocks */}
              <CollapsibleSection title="Advanced">
                <div className="grid grid-cols-2 gap-3">
                  <Input
                    label="min_wrapping_ttl"
                    value={b.minWrappingTtl ?? ""}
                    onChange={(e) => updateBlock(i, { minWrappingTtl: e.target.value || undefined })}
                    placeholder="e.g. 1h"
                  />
                  <Input
                    label="max_wrapping_ttl"
                    value={b.maxWrappingTtl ?? ""}
                    onChange={(e) => updateBlock(i, { maxWrappingTtl: e.target.value || undefined })}
                    placeholder="e.g. 24h"
                  />
                  <div className="col-span-2">
                    <Input
                      label="required_parameters (comma-separated)"
                      value={(b.requiredParameters ?? []).join(", ")}
                      onChange={(e) =>
                        updateBlock(i, { requiredParameters: csvToArray(e.target.value) })
                      }
                      placeholder="env, region"
                    />
                  </div>
                  <div className="col-span-2">
                    <Input
                      label="groups — asset-group filter (comma-separated)"
                      value={(b.groups ?? []).join(", ")}
                      onChange={(e) => updateBlock(i, { groups: csvToArray(e.target.value) })}
                      placeholder="sre, dba"
                    />
                  </div>
                  <div className="col-span-2">
                    <Input
                      label="scopes — ownership filter (comma-separated: owner, shared)"
                      value={(b.scopes ?? []).join(", ")}
                      onChange={(e) => updateBlock(i, { scopes: csvToArray(e.target.value) })}
                      placeholder="owner, shared"
                    />
                  </div>
                </div>
                <p className="mt-2 text-xs text-[var(--color-text-muted)]">
                  Allowed/denied parameter maps are preserved on round-trip but edited from the HCL source tab.
                </p>
              </CollapsibleSection>
            </div>
          </Card>
        );
      })}

      <CollapsibleSection title="HCL preview">
        <pre className="overflow-x-auto rounded bg-[var(--color-bg)] p-3 text-xs text-[var(--color-text-muted)]">
          {preview || "# (empty)"}
        </pre>
      </CollapsibleSection>
    </div>
  );
}

function CapChip({
  label,
  active,
  onClick,
  danger,
  warn,
  muted,
  disabled,
}: {
  label: string;
  active: boolean;
  onClick?: () => void;
  danger?: boolean;
  warn?: boolean;
  muted?: boolean;
  disabled?: boolean;
}) {
  const base = "rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors";
  let style: string;
  if (disabled) {
    style = "border-[var(--color-border)] text-[var(--color-text-muted)] opacity-50 cursor-not-allowed";
  } else if (active && danger) {
    style = "bg-red-500/20 text-red-400 border-red-500/40";
  } else if (active && warn) {
    style = "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
  } else if (active) {
    style = "bg-[var(--color-primary)] text-white border-transparent";
  } else {
    style = "border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]";
  }
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`${base} ${style} ${muted && !active ? "opacity-40" : ""}`}
      title={
        warn
          ? "sudo is root-equivalent on the matched path"
          : label === "root"
            ? "root is a policy-level concept, not a per-path grant"
            : undefined
      }
    >
      {label}
    </button>
  );
}

export const _internal = { CAPABILITIES };
