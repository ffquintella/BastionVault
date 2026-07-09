import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";

/**
 * Read-only key/value view for a single record. Issues `binding.op
 * = "read"` and renders one row per `fields[]` entry. Fields with
 * `live: true` re-issue the read on a 5-second cadence while the
 * page is mounted — useful for things like a TOTP code that
 * advances on its own.
 *
 * Extensibility v2 (Phase 3): when `spec.subscribe` is set and the
 * component is rendered inside a plugin window (`windowHandle`
 * present), it instead consumes `plugin-window-data-<handle>` events
 * pushed by the plugin's app module via `bvx.window_emit` — no polling.
 */
export function SurfaceDetail({
  spec,
  mount,
  windowHandle,
}: {
  spec: api.SurfaceDetail;
  mount: string;
  windowHandle?: string | null;
}) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const subscribed = !!spec.subscribe && windowHandle != null;

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

    // Load once for the initial paint regardless of mode.
    void load();

    if (subscribed) {
      // Push mode: the app module drives updates via window_emit.
      const unlisten = listen<Record<string, unknown>>(
        `plugin-window-data-${windowHandle}`,
        (ev) => {
          if (!cancelled) setData(ev.payload ?? null);
        },
      );
      return () => {
        cancelled = true;
        void unlisten.then((u) => u());
      };
    }

    if (spec.fields.some((f) => f.live)) {
      timer = setInterval(load, 5000);
    }
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [spec.binding.op, spec.binding.path, spec.fields, mount, subscribed, windowHandle]);

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
