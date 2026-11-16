import { useCallback, useEffect, useState } from "react";
import { Button, Card, Modal, useToast } from "../ui";
import { SettingsForm, type FieldSpec } from "./SettingsForm";
import * as idp from "../../lib/idp";

const RANGE_FIELDS: FieldSpec[] = [
  { key: "uid_min", label: "Lowest uid", kind: "number" },
  { key: "uid_max", label: "Highest uid", kind: "number" },
  { key: "gid_min", label: "Lowest primary gid", kind: "number" },
  { key: "gid_max", label: "Highest primary gid", kind: "number" },
];

/** The allocator's ranges and counters. Ids are allocated upward only. */
export function IdpRangesCard() {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<idp.IdpCoreConfig | null>(null);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setCfg((await idp.idpReadSettings<idp.IdpCoreConfig>("core")).data);
      setError(null);
    } catch (e) {
      setError(idp.describeIdpError(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(body: Record<string, unknown>) {
    const resp = await idp.idpWriteSettings<idp.IdpCoreConfig>("core", body);
    setCfg(resp.data);
    setEditing(false);
    toast("success", "Allocation ranges saved");
  }

  const stat = (label: string, value: string) => (
    <div className="min-w-0">
      <div className="text-xs text-[var(--color-text-muted)]">{label}</div>
      <div className="font-mono text-sm truncate">{value}</div>
    </div>
  );

  return (
    <Card
      title="uid / gid allocation"
      actions={
        <Button size="sm" variant="secondary" onClick={() => setEditing(true)} disabled={!cfg}>
          Edit ranges
        </Button>
      }
    >
      {error && (
        <p className="text-sm text-[var(--color-danger)]" role="alert">
          {error}
        </p>
      )}
      {cfg && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {stat("uid range", `${cfg.uid_min}–${cfg.uid_max}`)}
          {stat("uid high-water", String(cfg.uid_high_water ?? "—"))}
          {stat("uids used / retired", `${cfg.uid_used} / ${cfg.uid_retired}`)}
          {stat("gid range", `${cfg.gid_min}–${cfg.gid_max}`)}
          {stat("gid high-water", String(cfg.gid_high_water ?? "—"))}
          {stat("gids used / retired", `${cfg.gid_used} / ${cfg.gid_retired}`)}
        </div>
      )}
      {editing && (
        <Modal open onClose={() => setEditing(false)} title="Allocation ranges" size="md">
          <div className="space-y-3">
            <p className="text-xs text-[var(--color-text-muted)]">
              Allocation never goes at or below the high-water mark, so a range moved below it is exhausted rather
              than reused. Retired ids are never handed out again.
            </p>
            <SettingsForm fields={RANGE_FIELDS} current={cfg as unknown as Record<string, unknown>} onSave={save} saveLabel="Save ranges" />
          </div>
        </Modal>
      )}
    </Card>
  );
}
