import { useMemo, useState } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";
import { Button, Input, SecretInput, Textarea } from "../ui";
import { usePluginSurfacesStore } from "../../stores/pluginSurfacesStore";

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
  entry,
  onSubmitted,
}: {
  spec: api.SurfaceForm;
  /** The owning plugin's active-surface entry. Carries the mount the
   *  binding's `{mount}` placeholder resolves to, plus the assets
   *  table the form-hook reference is looked up in. */
  entry: api.ActiveSurfaceEntry;
  onSubmitted?: (resp: Record<string, unknown> | null) => void;
}) {
  const mount = entry.mount;
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
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const refreshSurfaces = usePluginSurfacesStore((s) => s.refresh);

  function setField(field: string, v: unknown) {
    setValues((prev) => ({ ...prev, [field]: v }));
    setFieldErrors((prev) => {
      if (!(field in prev)) return prev;
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }

  /**
   * Resolve a `<asset>#<export>` hook reference against the owning
   * plugin's declared `client_assets[]`. Returns `null` when the
   * asset isn't declared (forces submit to skip the hook quietly
   * rather than block on a malformed surface).
   */
  function resolveHook(
    hook: string,
  ): { sha256: string; export: string } | null {
    const idx = hook.indexOf("#");
    if (idx <= 0 || idx === hook.length - 1) return null;
    const asset = hook.slice(0, idx);
    const exp = hook.slice(idx + 1);
    const assetEntry = entry.assets.find(([name]) => name === asset);
    if (!assetEntry) return null;
    return { sha256: assetEntry[1], export: exp };
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setFieldErrors({});
    try {
      // Phase 4: optional WASM form-hook validation. The hook
      // receives the form values as JSON and returns
      // `{ ok: bool, errors: { field: msg } }`. Server-side ACLs
      // remain authoritative — a hostile form bypassing the hook
      // (DOM tampering) still gets caught downstream.
      let payload = values;
      if (spec.hook) {
        const ref = resolveHook(spec.hook);
        if (ref) {
          try {
            const out = await api.pluginSurfaceHook(
              entry.plugin,
              entry.version,
              ref.sha256,
              ref.export,
              JSON.stringify(payload),
            );
            const parsed = JSON.parse(out) as {
              ok?: boolean;
              errors?: Record<string, string>;
              values?: Record<string, unknown>;
            };
            if (parsed.ok === false) {
              setFieldErrors(parsed.errors ?? {});
              setErr(
                Object.values(parsed.errors ?? {}).join("; ") ||
                  "Form rejected by plugin validator.",
              );
              return;
            }
            // A hook may rewrite the payload (`pre_submit` style) by
            // returning a `values` object — honour it when present.
            if (parsed.values && typeof parsed.values === "object") {
              payload = parsed.values;
            }
          } catch (hookErr) {
            // A failing hook (compile error, fuel exhaustion,
            // missing export) is not the operator's fault; log and
            // fall through to the unrewritten submit. The user-
            // facing error pipeline still surfaces the message so
            // plugin authors see it during dev.
            // eslint-disable-next-line no-console
            console.warn(`SurfaceForm hook ${spec.hook} failed:`, hookErr);
          }
        }
      }

      // Build `{<field>}` path substitutions from string fields,
      // mirroring the SurfaceTable row-action behaviour.
      const params: Record<string, string> = {};
      for (const [k, v] of Object.entries(payload)) {
        if (typeof v === "string") params[k] = v;
      }
      const resp = await api.pluginSurfaceDispatch(
        spec.submit.binding.op,
        spec.submit.binding.path,
        mount,
        params,
        payload as Record<string, unknown>,
      );
      onSubmitted?.(resp ?? null);
      // The server may have flipped a flag the surface depends on
      // (for example, a "first-time setup" wizard that the menu
      // hides afterwards). Cheap to ask; bundle ETag short-circuits
      // when nothing changed.
      void refreshSurfaces();
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
          error={fieldErrors[name]}
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

function FieldRenderer({
  name,
  prop,
  value,
  required,
  error,
  onChange,
}: {
  name: string;
  prop: PropSchema;
  value: unknown;
  required: boolean;
  /** Per-field error message returned by a `validate` hook. */
  error?: string;
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
          className={`w-full bg-[var(--color-bg)] border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40 focus:border-[var(--color-primary)] ${
            error
              ? "border-[var(--color-danger)]"
              : "border-[var(--color-border)]"
          }`}
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
        {error && (
          <p className="text-xs text-[var(--color-danger)]">{error}</p>
        )}
        {!error && hint && (
          <p className="text-xs text-[var(--color-text-muted)]">{hint}</p>
        )}
      </div>
    );
  }

  if (prop.type === "boolean") {
    return (
      <div>
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
        {error && (
          <p className="text-xs text-[var(--color-danger)] mt-1">{error}</p>
        )}
      </div>
    );
  }

  if (prop.format === "password") {
    return (
      <SecretInput
        id={fieldId}
        label={label}
        hint={hint}
        error={error}
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
        {error && (
          <p className="text-xs text-[var(--color-danger)]">{error}</p>
        )}
        {!error && hint && (
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
        error={error}
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
      error={error}
      required={required}
      value={typeof value === "string" ? value : ""}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}
