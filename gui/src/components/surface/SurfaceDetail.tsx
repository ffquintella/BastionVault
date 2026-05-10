import { useEffect, useState } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";

/**
 * Read-only key/value view for a single record. Issues `binding.op
 * = "read"` and renders one row per `fields[]` entry. Fields with
 * `live: true` re-issue the read on a 5-second cadence while the
 * page is mounted — useful for things like a TOTP code that
 * advances on its own.
 */
export function SurfaceDetail({
  spec,
  mount,
}: {
  spec: api.SurfaceDetail;
  mount: string;
}) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | undefined;

    async function load() {
      try {
        const resp = await api.pluginSurfaceDispatch(
          spec.binding.op,
          spec.binding.path,
          mount,
        );
        if (!cancelled) setData(resp ?? null);
      } catch (e) {
        if (!cancelled) setErr(extractError(e));
      }
    }

    void load();
    if (spec.fields.some((f) => f.live)) {
      timer = setInterval(load, 5000);
    }
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [spec.binding.op, spec.binding.path, spec.fields, mount]);

  if (err) {
    return <div className="text-sm text-[var(--color-danger)] p-4">{err}</div>;
  }
  if (!data) {
    return (
      <div className="text-sm text-[var(--color-text-muted)] p-4">Loading…</div>
    );
  }

  return (
    <dl className="grid grid-cols-[max-content,1fr] gap-x-4 gap-y-2 p-2 text-sm">
      {spec.fields.map((f) => {
        const v = data[f.field];
        return (
          <div key={f.field} className="contents">
            <dt className="text-[var(--color-text-muted)]">{f.label}</dt>
            <dd className="font-mono break-all">
              {v == null
                ? "—"
                : typeof v === "string"
                ? v
                : JSON.stringify(v)}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
