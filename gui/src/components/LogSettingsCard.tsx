/** Settings → General → Logging: the log level and where the file is. */

import { useEffect, useState } from "react";

import { Card, Select, useToast } from "./ui";
import { getLogSettings, setLogLevel, type LogSettings } from "../lib/api";
import { extractError } from "../lib/error";

const HINTS: Record<string, string> = {
  off: "Nothing is logged.",
  error: "Failures only.",
  warn: "Failures and warnings.",
  info: "Normal operation (default).",
  debug: "Detailed; use when diagnosing a problem.",
  trace: "Very verbose; may be slow and large.",
};

export function LogSettingsCard() {
  const { toast } = useToast();
  const [settings, setSettings] = useState<LogSettings | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const loaded = await getLogSettings();
        if (live) setSettings(loaded);
      } catch (e) {
        if (live) setLoadError(extractError(e));
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  async function change(level: string) {
    setSaving(true);
    try {
      setSettings(await setLogLevel(level));
      toast("success", `Log level set to ${level}.`);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card title="Logging">
      {loadError ? (
        <p className="text-sm text-[var(--color-danger)] break-words">{loadError}</p>
      ) : !settings ? (
        <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
      ) : (
        <div className="space-y-3 min-w-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Select
              label="Log level"
              value={settings.level}
              disabled={saving || settings.env_override}
              onChange={(e) => void change(e.target.value)}
              options={settings.levels.map((l) => ({ value: l, label: l }))}
            />
          </div>
          <p className="text-sm text-[var(--color-text-muted)]">{HINTS[settings.level] ?? ""}</p>
          {settings.env_override && (
            <p className="text-sm text-[var(--color-warning)]">
              The RUST_LOG environment variable is set, so it decides the level; this setting has no effect until
              the app is started without it.
            </p>
          )}
          <div className="text-sm min-w-0">
            <p className="text-[var(--color-text-muted)]">Log file</p>
            {settings.path ? (
              <p className="font-mono text-xs truncate" title={settings.path}>
                {settings.path}
              </p>
            ) : (
              <p className="text-xs text-[var(--color-text-muted)]">
                Not written (BVAULT_GUI_LOG=off, or the folder could not be opened); logs go to stderr only.
              </p>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}
