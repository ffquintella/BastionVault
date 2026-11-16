import { useState } from "react";
import { Badge, Button, Card, ConfirmModal, Table, useToast } from "../ui";
import { EnvironmentModal } from "./EnvironmentModal";
import { StateBadge } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

type Row = IdpDirectory["environments"][number];

export function IdpEnvironmentsCard({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [editing, setEditing] = useState<idp.IdpEnvironment | null | undefined>(undefined);
  const [retiring, setRetiring] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function openEdit(name: string) {
    try {
      setEditing((await idp.idpRead<idp.IdpEnvironment>("environment", name)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function retire() {
    if (!retiring) return;
    setBusy(true);
    try {
      await idp.idpDelete("environment", retiring);
      toast("success", `Environment ${retiring} retired`);
      setRetiring(null);
      await directory.reload();
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title={`Environments (${directory.environments.length})`}
      actions={
        <Button size="sm" onClick={() => setEditing(null)}>
          New environment
        </Button>
      }
    >
      <Table<Row>
        tableClassName="table-fixed"
        data={directory.environments}
        rowKey={(r) => r.name}
        emptyMessage="No environments yet: create one per namespace that people enter."
        columns={[
          {
            key: "name",
            header: "Environment",
            className: "w-1/5",
            render: (r) => (
              <div className="truncate font-medium" title={r.name}>
                {r.name}
              </div>
            ),
          },
          {
            key: "ns",
            header: "Namespace",
            className: "w-1/5",
            render: (r) => (
              <div className="truncate font-mono text-xs" title={r.info.namespace || "(root)"}>
                {r.info.namespace || "(root)"}
              </div>
            ),
          },
          { key: "state", header: "State", className: "w-28", render: (r) => <StateBadge state={r.info.state} /> },
          {
            key: "roles",
            header: "Roles",
            render: (r) => (
              <div className="flex min-w-0 flex-wrap gap-1">
                {r.info.roles.map((role) => (
                  <Badge key={role} variant="info" label={role} />
                ))}
              </div>
            ),
          },
          {
            key: "actions",
            header: "",
            className: "w-48",
            render: (r) =>
              r.info.state === "active" ? (
                <div className="flex justify-end gap-2">
                  <Button size="sm" variant="ghost" onClick={() => void openEdit(r.name)}>
                    Edit roles
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => setRetiring(r.name)}>
                    Retire
                  </Button>
                </div>
              ) : null,
          },
        ]}
      />
      {editing !== undefined && (
        <EnvironmentModal
          environment={editing}
          onClose={() => setEditing(undefined)}
          onSaved={(env) => {
            toast("success", `Environment ${env.name} saved`);
            setEditing(undefined);
            void directory.reload();
          }}
        />
      )}
      <ConfirmModal
        open={retiring !== null}
        onClose={() => setRetiring(null)}
        onConfirm={() => void retire()}
        loading={busy}
        title={`Retire environment ${retiring ?? ""}`}
        message={
          `Retiring "${retiring ?? ""}" is permanent: the name is never reused, the issue gate refuses every ` +
          "credential for it at once, and the RADIUS, OIDC, SAML and LDAP clients bound to it stop being served. " +
          "Its entitlements are kept but never honoured again."
        }
        confirmLabel="Retire permanently"
        confirmPhrase={retiring ?? ""}
      />
    </Card>
  );
}
