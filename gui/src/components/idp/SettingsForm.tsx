import { useEffect, useMemo, useState } from "react";
import { Button, Input, Textarea } from "../ui";
import { extractError } from "../../lib/error";

/**
 * One field of a provider settings document. `secret_pem` is write-only: it
 * starts empty, is never filled from a read, renders masked, and is sent only
 * when something was typed (`setFlag` names the read's "a key is set" field).
 */
export type FieldSpec =
  | { key: string; label: string; kind: "text" | "duration" | "number"; hint?: string; full?: boolean; placeholder?: string }
  | { key: string; label: string; kind: "bool"; hint?: string }
  | { key: string; label: string; kind: "pem"; hint?: string }
  | { key: string; label: string; kind: "secret_pem"; setFlag: string; hint?: string };

type Values = Record<string, string | boolean>;

function initial(fields: FieldSpec[], current: Record<string, unknown> | null): Values {
  const out: Values = {};
  for (const f of fields) {
    const v = current?.[f.key];
    if (f.kind === "bool") out[f.key] = v === true;
    else if (f.kind === "secret_pem") out[f.key] = "";
    else out[f.key] = v === null || v === undefined ? "" : String(v);
  }
  return out;
}

/**
 * The write body: only fields that differ from the last read (an emptied
 * text field is sent as "" because the engine reads that as "clear"), and a
 * write-only field only when typed. Throws on a non-numeric number.
 */
export function buildSettingsBody(
  fields: FieldSpec[],
  current: Record<string, unknown> | null,
  values: Values,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const f of fields) {
    const v = values[f.key];
    if (f.kind === "bool") {
      if (v !== (current?.[f.key] === true)) body[f.key] = v;
      continue;
    }
    const text = typeof v === "string" ? v : "";
    if (f.kind === "secret_pem") {
      if (text.trim() !== "") body[f.key] = text;
      continue;
    }
    const before = current?.[f.key];
    if (text === (before === null || before === undefined ? "" : String(before))) continue;
    if (f.kind === "number") {
      if (text.trim() === "") continue;
      const n = Number(text.trim());
      if (!Number.isInteger(n) || n < 0) throw new Error(`${f.label} must be a whole number`);
      body[f.key] = n;
    } else {
      body[f.key] = text;
    }
  }
  return body;
}

export function SettingsForm({
  fields,
  current,
  onSave,
  saveLabel = "Save settings",
}: {
  fields: FieldSpec[];
  current: Record<string, unknown> | null;
  onSave: (body: Record<string, unknown>) => Promise<void>;
  saveLabel?: string;
}) {
  const [values, setValues] = useState<Values>(() => initial(fields, current));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A fresh read replaces the form, and with it any typed write-only value.
  useEffect(() => {
    setValues(initial(fields, current));
  }, [fields, current]);

  const pending = useMemo(() => {
    try {
      return Object.keys(buildSettingsBody(fields, current, values)).length;
    } catch {
      return 1;
    }
  }, [fields, current, values]);

  async function save() {
    setError(null);
    let body: Record<string, unknown>;
    try {
      body = buildSettingsBody(fields, current, values);
    } catch (e) {
      setError(extractError(e));
      return;
    }
    setBusy(true);
    try {
      await onSave(body);
    } catch (e) {
      setError(extractError(e));
    } finally {
      setBusy(false);
    }
  }

  const set = (key: string, v: string | boolean) => setValues((prev) => ({ ...prev, [key]: v }));

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        {fields.map((f) => {
          if (f.kind === "bool") {
            return (
              <label key={f.key} className="col-span-2 sm:col-span-1 flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={values[f.key] === true}
                  onChange={(e) => set(f.key, e.target.checked)}
                />
                <span className="min-w-0">
                  <span className="block">{f.label}</span>
                  {f.hint && <span className="block text-xs text-[var(--color-text-muted)]">{f.hint}</span>}
                </span>
              </label>
            );
          }
          if (f.kind === "pem" || f.kind === "secret_pem") {
            const secret = f.kind === "secret_pem";
            const isSet = secret && current?.[f.setFlag] === true;
            return (
              <div key={f.key} className="col-span-2 space-y-1">
                <Textarea
                  label={f.label}
                  value={String(values[f.key] ?? "")}
                  onChange={(e) => set(f.key, e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  data-write-only={secret ? "true" : undefined}
                  className={secret ? "min-h-[80px] [-webkit-text-security:disc]" : "min-h-[80px]"}
                  placeholder={secret ? (isSet ? "A key is set. Paste a new one to replace it." : "Not set") : ""}
                />
                {(f.hint || secret) && (
                  <p className="text-xs text-[var(--color-text-muted)]">
                    {secret ? "Write-only: never read back. " : ""}
                    {f.hint}
                  </p>
                )}
              </div>
            );
          }
          return (
            <div key={f.key} className={f.full ? "col-span-2" : "col-span-2 sm:col-span-1"}>
              <Input
                label={f.label}
                value={String(values[f.key] ?? "")}
                onChange={(e) => set(f.key, e.target.value)}
                hint={f.hint}
                placeholder={f.placeholder}
                inputMode={f.kind === "number" ? "numeric" : undefined}
              />
            </div>
          );
        })}
      </div>
      {error && (
        <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
          {error}
        </p>
      )}
      <div className="flex justify-end">
        <Button onClick={() => void save()} loading={busy} disabled={pending === 0}>
          {saveLabel}
        </Button>
      </div>
    </div>
  );
}
