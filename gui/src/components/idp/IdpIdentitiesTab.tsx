import { useMemo, useState } from "react";
import { Button, Card, EntityLabel, Select, Table, useToast } from "../ui";
import { IdpRangesCard } from "./IdpRangesCard";
import { IdentityFormModal } from "./IdentityFormModal";
import { IdentityStateModal, type StateChange } from "./IdentityStateModal";
import { StateBadge } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

type Row = IdpDirectory["identities"][number];

export function IdpIdentitiesTab({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [filter, setFilter] = useState<"all" | idp.IdpIdentityState>("all");
  const [allocating, setAllocating] = useState(false);
  const [editing, setEditing] = useState<idp.IdpIdentity | null>(null);
  const [change, setChange] = useState<StateChange | null>(null);

  const rows = useMemo(
    () => directory.identities.filter((r) => filter === "all" || r.info.state === filter),
    [directory.identities, filter],
  );

  async function openEdit(row: Row) {
    try {
      setEditing((await idp.idpRead<idp.IdpIdentity>("identity", row.entity_id)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  function stateDone(resp: idp.IdpResponse<idp.IdpIdentity>) {
    const rec = resp.data;
    const revoked = rec.revoked_certificates ?? 0;
    const feed = rec.deny_feed_version !== undefined ? `; deny feed v${rec.deny_feed_version}` : "";
    toast("success", `${rec.login} is now ${rec.state} (${revoked} certificate(s) revoked${feed})`);
    for (const w of resp.warnings) toast("info", w);
    setChange(null);
    void directory.reload();
  }

  const ask = (row: Row, to: idp.IdpIdentityState) =>
    setChange({ entity_id: row.entity_id, login: row.info.login, uid: row.info.uid, to });

  return (
    <div className="space-y-4">
      <IdpRangesCard />
      <Card
        title={`Workforce identities (${directory.identities.length})`}
        actions={
          <>
            <Select
              aria-label="Filter by state"
              value={filter}
              onChange={(e) => setFilter(e.target.value as typeof filter)}
              options={[
                { value: "all", label: "All states" },
                { value: "active", label: "Active" },
                { value: "disabled", label: "Disabled" },
                { value: "removed", label: "Removed" },
              ]}
            />
            <Button size="sm" onClick={() => setAllocating(true)}>
              Allocate identity
            </Button>
          </>
        }
      >
        <Table<Row>
          tableClassName="table-fixed"
          data={rows}
          rowKey={(r) => r.entity_id}
          emptyMessage="No workforce identities yet"
          columns={[
            {
              key: "login",
              header: "Login",
              className: "w-1/5",
              render: (r) => (
                <div className="min-w-0 truncate font-medium" title={r.info.login}>
                  {r.info.login}
                </div>
              ),
            },
            {
              key: "uid",
              header: "uid / gid",
              className: "w-1/6",
              render: (r) => (
                <span className="font-mono text-xs" title="Immutable for life and never reused, even after removal">
                  {r.info.uid} / {r.info.primary_gid}
                </span>
              ),
            },
            { key: "state", header: "State", className: "w-1/6", render: (r) => <StateBadge state={r.info.state} /> },
            {
              key: "entity",
              header: "Entity",
              render: (r) => (
                <div className="min-w-0 truncate">
                  <EntityLabel entityId={r.entity_id} />
                </div>
              ),
            },
            {
              key: "actions",
              header: "",
              className: "w-64",
              render: (r) => (
                <div className="flex flex-wrap justify-end gap-2">
                  {r.info.state !== "removed" && (
                    <Button size="sm" variant="ghost" onClick={() => void openEdit(r)}>
                      Edit
                    </Button>
                  )}
                  {r.info.state === "active" && (
                    <Button size="sm" variant="danger" onClick={() => ask(r, "disabled")}>
                      Disable
                    </Button>
                  )}
                  {r.info.state === "disabled" && (
                    <>
                      <Button size="sm" variant="secondary" onClick={() => ask(r, "active")}>
                        Reinstate
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => ask(r, "removed")}>
                        Remove
                      </Button>
                    </>
                  )}
                </div>
              ),
            },
          ]}
        />
        <p className="mt-3 text-xs text-[var(--color-text-muted)]">
          An identity is disabled before it can be removed. Removal is permanent: the uid, primary gid and login are
          never reused.
        </p>
      </Card>

      {allocating && (
        <IdentityFormModal
          mode="allocate"
          onClose={() => setAllocating(false)}
          onSaved={(rec) => {
            toast("success", `Allocated ${rec.login} (uid ${rec.uid}, gid ${rec.primary_gid})`);
            setAllocating(false);
            void directory.reload();
          }}
        />
      )}
      {editing && (
        <IdentityFormModal
          mode="edit"
          identity={editing}
          onClose={() => setEditing(null)}
          onSaved={(rec) => {
            toast("success", `Saved ${rec.login}`);
            setEditing(null);
            void directory.reload();
          }}
        />
      )}
      <IdentityStateModal change={change} onClose={() => setChange(null)} onDone={stateDone} />
    </div>
  );
}
