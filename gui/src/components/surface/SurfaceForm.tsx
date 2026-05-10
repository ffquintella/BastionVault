import { useMemo, useState } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";
import { Button, Input, SecretInput, Textarea } from "../ui";

/**
 * Schema-driven form. Honours a small subset of JSON Schema 2020-12
 * — enough for the v1 plugin surfaces:
 *
 *   * `type: "object"` with `properties`, `required`
 *   * per-property `type: "string" | "integer" | "number" | "boolean"`
 *   * per-property `format: "password"` → `<SecretInput>`
 *   * per-property `format: "textarea"` → `<Textarea>`
 *   * per-property `enum: [...]` → `<Select>`
 *   * per-property `title`, `description`, `default`
 *
 * Anything outside that subset falls through to a plain `<Input>`.
 * The renderer is deliberately conservative: a plugin author who
 * needs richer form behaviour ships a `hook` alongside the schema.
 *
 * Form-hook integration is wired in Phase 4. For now, the `hook`
 * field is read off the spec and surfaced through `console.warn`
 * if present so plugin authors notice the missing wiring early.
 */
type Schema = {
  type?: string;
  properties?: Record<string, PropSchema>;
  required?: string[];
};

type PropSchema = {
  type?: string;
  title?: string;
  description?: string;
  format?: string;
  enum?: string[];
  default?: unknown;
};

export function SurfaceForm({
  spec,
  mount,
  onSubmitted,
}: {
  spec: api.SurfaceForm;
  mount: string;
  onSubmitted?: (resp: Record<string, unknown> | null) => void;
}) {
  const schema = (spec.schema as Schema) ?? {};
  const properties = schema.properties ?? {};
  const required = new Set(schema.required ?? []);

  const initial = useMemo(() => {
    const out: Record<string, unknown> = {};
    for (const [k, prop] of Object.entries(properties)) {
      if (prop.default !== undefined) out[k] = prop.default;
    }
    return out;
  }, [properties]);

  const [values, setValues] = useState<Record<string, unknown>>(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (spec.hook && !globalHookWarned) {
    // Only warn once per page load — repeated submits would otherwise
    // spam the console.
    globalHookWarned = true;
    // eslint-disable-next-line no-console
    console.warn(
      `SurfaceForm: form hook "${spec.hook}" is declared but Phase 4 wiring isn't shipped yet — submitting raw form values.`,
    );
  }

  function setField(field: string, v: unknown) {
    setValues((prev) => ({ ...prev, [field]: v }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      // Build `{<field>}` path substitutions from string fields,
      // mirroring the SurfaceTable row-action behaviour.
      const params: Record<string, string> = {};
      for (const [k, v] of Object.entries(values)) {
        if (typeof v === "string") params[k] = v;
      }
      const resp = await api.pluginSurfaceDispatch(
        spec.submit.binding.op,
        spec.submit.binding.path,
        mount,
        params,
        values as Record<string, unknown>,
      );
      onSubmitted?.(resp ?? null);
    } catch (e) {
      setErr(extractError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {spec.title && (
        <h3 className="text-base font-semibold">{spec.title}</h3>
      )}
      {Object.entries(properties).map(([name, prop]) => (
        <FieldRenderer
          key={name}
          name={name}
          prop={prop}
          value={values[name]}
          required={required.has(name)}
          onChange={(v) => setField(name, v)}
        />
      ))}
      {err && <p className="text-sm text-[var(--color-danger)]">{err}</p>}
      <div className="flex justify-end">
        <Button type="submit" disabled={busy}>
          {busy ? "Submitting…" : spec.submit.label}
        </Button>
      </div>
    </form>
  );
}

let globalHookWarned = false;

function FieldRenderer({
  name,
  prop,
  value,
  required,
  onChange,
}: {
  name: string;
  prop: PropSchema;
  value: unknown;
  required: boolean;
  onChange: (v: unknown) => void;
}) {
  const label = prop.title ?? name;
  const hint = prop.description;
  const fieldId = `surface-form-${name}`;

  if (prop.enum && prop.enum.length > 0) {
    return (
      <div className="space-y-1">
        <label
          htmlFor={fieldId}
          className="block text-sm font-medium text-[var(--color-text-muted)]"
        >
          {label}
        </label>
        <select
          id={fieldId}
          required={required}
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(e.target.value)}
          className="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)]"
        >
          <option value="" disabled>
            Select…
          </option>
          {prop.enum.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        {hint && (
          <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>
        )}
      </div>
    );
  }

  if (prop.type === "boolean") {
    return (
      <label
        htmlFor={fieldId}
        className="flex items-center gap-2 text-sm text-[var(--color-text)]"
      >
        <input
          id={fieldId}
          type="checkbox"
          checked={value === true}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span>{label}</span>
      </label>
    );
  }

  if (prop.format === "password") {
    return (
      <SecretInput
        id={fieldId}
        label={label}
        hint={hint}
        required={required}
        value={typeof value === "string" ? value : ""}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }

  if (prop.format === "textarea") {
    return (
      <div className="space-y-1">
        <Textarea
          id={fieldId}
          label={label}
          required={required}
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(e.target.value)}
        />
        {hint && (
          <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>
        )}
      </div>
    );
  }

  if (prop.type === "integer" || prop.type === "number") {
    return (
      <Input
        id={fieldId}
        label={label}
        hint={hint}
        required={required}
        type="number"
        value={typeof value === "number" ? value : value === undefined ? "" : String(value)}
        onChange={(e) => {
          const n = e.target.value === "" ? undefined : Number(e.target.value);
          onChange(n);
        }}
      />
    );
  }

  return (
    <Input
      id={fieldId}
      label={label}
      hint={hint}
      required={required}
      value={typeof value === "string" ? value : ""}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}
