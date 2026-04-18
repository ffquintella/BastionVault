import { Button } from "./Button";
import { Input } from "./Input";
import { SecretInput } from "./SecretInput";

export interface SecretPair {
  key: string;
  value: string;
}

interface SecretPairsEditorProps {
  pairs: SecretPair[];
  onChange: (pairs: SecretPair[]) => void;
  /** Optional label rendered above the rows. */
  label?: string;
  /** Minimum row count to always display (default 1). */
  minRows?: number;
}

/**
 * Reusable key-value editor for KV secrets and resource secrets. Each row
 * has a plain `Input` for the key and a `SecretInput` (with built-in
 * password generator) for the value. Used by both the create modals and
 * the in-place edit flows on SecretsPage and ResourcesPage.
 */
export function SecretPairsEditor({
  pairs,
  onChange,
  label = "Key-Value Pairs",
  minRows = 1,
}: SecretPairsEditorProps) {
  function updateAt(i: number, next: SecretPair) {
    const updated = [...pairs];
    updated[i] = next;
    onChange(updated);
  }

  function removeAt(i: number) {
    onChange(pairs.filter((_, j) => j !== i));
  }

  function addRow() {
    onChange([...pairs, { key: "", value: "" }]);
  }

  return (
    <div className="space-y-2">
      {label && (
        <label className="block text-sm font-medium text-[var(--color-text-muted)]">
          {label}
        </label>
      )}
      {pairs.map((pair, i) => (
        <div key={i} className="flex gap-2">
          <Input
            placeholder="key"
            value={pair.key}
            onChange={(e) => updateAt(i, { ...pair, key: e.target.value })}
          />
          <SecretInput
            placeholder="value"
            value={pair.value}
            onChange={(e) => updateAt(i, { ...pair, value: e.target.value })}
            showGenerator
            onGenerate={(v) => updateAt(i, { ...pair, value: v })}
            className="flex-1"
          />
          {pairs.length > minRows && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => removeAt(i)}
              aria-label="Remove pair"
            >
              &times;
            </Button>
          )}
        </div>
      ))}
      <Button variant="ghost" size="sm" onClick={addRow}>
        + Add pair
      </Button>
    </div>
  );
}

/** Convert a `Record<string, unknown>` (as returned from the vault) into
 *  an editable list of pairs. Empty objects yield one blank row so the
 *  editor always has something to display. */
export function pairsFromData(data: Record<string, unknown>): SecretPair[] {
  const entries = Object.entries(data);
  if (entries.length === 0) return [{ key: "", value: "" }];
  return entries.map(([key, value]) => ({ key, value: String(value ?? "") }));
}

/** Convert a list of pairs into a `Record<string, string>` suitable for
 *  posting back to the vault. Empty keys are dropped. */
export function dataFromPairs(pairs: SecretPair[]): Record<string, string> {
  const data: Record<string, string> = {};
  for (const pair of pairs) {
    if (pair.key) data[pair.key] = pair.value;
  }
  return data;
}
