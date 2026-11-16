import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, ConfirmModal, Table, useToast } from "../ui";
import { RadiusClientModal } from "./RadiusClientModal";
import { RadiusProfileModal } from "./RadiusProfileModal";
import { OneTimeSecretModal, useOneTimeSecret } from "./OneTimeSecretModal";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

type ClientRow = { name: string; info: idp.IdpRadiusClientInfo };
type ProfileRow = { name: string; environment: string; roles: string[] };

async function listRows<I>(kind: idp.IdpKind) {
  const list = await idp.idpList<I>(kind);
  return list.keys.map((name) => ({ name, info: list.key_info[name] })).filter((r) => r.info !== undefined);
}

export function RadiusClientsCard({ directory, profiles }: { directory: IdpDirectory; profiles: ProfileRow[] }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<ClientRow[]>([]);
  const [editing, setEditing] = useState<idp.IdpRadiusClient | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const secret = useOneTimeSecret();

  const load = useCallback(async () => {
    try {
      setRows(await listRows<idp.IdpRadiusClientInfo>("radius_client"));
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function openEdit(name: string) {
    try {
      setEditing((await idp.idpRead<idp.IdpRadiusClient>("radius_client", name)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await idp.idpDelete("radius_client", deleting);
      toast("success", `NAS ${deleting} removed`);
      setDeleting(null);
      await load();
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="NAS clients" actions={<Button size="sm" onClick={() => setEditing(null)}>Register NAS</Button>}>
      <Table<ClientRow>
        tableClassName="table-fixed"
        data={rows}
        rowKey={(r) => r.name}
        emptyMessage="No NAS registered"
        columns={[
          { key: "name", header: "NAS", className: "w-1/4", render: (r) => <div className="truncate font-medium" title={r.name}>{r.name}</div> },
          {
            key: "transport",
            header: "Transport",
            className: "w-36",
            render: (r) =>
              r.info.transport === "udp" ? <Badge variant="warning" label="UDP (MD5 secret)" /> : <Badge variant="success" label="RadSec" />,
          },
          { key: "env", header: "Environment / profile", render: (r) => <div className="truncate text-xs" title={`${r.info.environment} / ${r.info.profile}`}>{r.info.environment} / {r.info.profile}</div> },
          {
            key: "actions",
            header: "",
            className: "w-40",
            render: (r) => (
              <div className="flex justify-end gap-2">
                <Button size="sm" variant="ghost" onClick={() => void openEdit(r.name)}>Edit</Button>
                <Button size="sm" variant="danger" onClick={() => setDeleting(r.name)}>Remove</Button>
              </div>
            ),
          },
        ]}
      />
      {editing !== undefined && (
        <RadiusClientModal
          client={editing}
          environments={directory.activeEnvironments}
          profiles={profiles}
          onClose={() => setEditing(undefined)}
          onSaved={(resp, sentSecret) => {
            setEditing(undefined);
            toast("success", `NAS ${resp.data.name} saved`);
            for (const w of resp.warnings) toast("info", w);
            if (sentSecret) {
              secret.show({
                title: `Shared secret for ${resp.data.name}`,
                label: "Shared secret",
                value: sentSecret,
                details: [["NAS address", resp.data.address ?? ""]],
                notice: "Configure it on the NAS now: the vault never returns it.",
              });
            }
            void load();
          }}
        />
      )}
      <ConfirmModal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => void remove()}
        loading={busy}
        title={`Remove NAS ${deleting ?? ""}`}
        message={`Remove "${deleting ?? ""}"? The device's next Access-Request is dropped as from an unknown NAS, so nobody can log in through it until it is registered again.`}
        confirmLabel="Remove"
      />
      <OneTimeSecretModal secret={secret.secret} onClose={secret.clear} />
    </Card>
  );
}

export function RadiusProfilesCard({
  directory,
  rows,
  reload,
}: {
  directory: IdpDirectory;
  rows: ProfileRow[];
  reload: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [editing, setEditing] = useState<idp.IdpRadiusProfile | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function openEdit(name: string) {
    try {
      setEditing((await idp.idpRead<idp.IdpRadiusProfile>("radius_profile", name)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await idp.idpDelete("radius_profile", deleting);
      toast("success", `Profile ${deleting} removed`);
      setDeleting(null);
      await reload();
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Attribute profiles" actions={<Button size="sm" onClick={() => setEditing(null)}>New profile</Button>}>
      <Table<ProfileRow>
        tableClassName="table-fixed"
        data={rows}
        rowKey={(r) => r.name}
        emptyMessage="No attribute profile yet: a NAS needs one."
        columns={[
          { key: "name", header: "Profile", className: "w-1/4", render: (r) => <div className="truncate font-medium" title={r.name}>{r.name}</div> },
          { key: "env", header: "Environment", className: "w-1/4", render: (r) => <div className="truncate">{r.environment}</div> },
          { key: "roles", header: "Roles", render: (r) => <div className="flex flex-wrap gap-1">{r.roles.map((x) => <Badge key={x} variant="info" label={x} />)}</div> },
          {
            key: "actions",
            header: "",
            className: "w-40",
            render: (r) => (
              <div className="flex justify-end gap-2">
                <Button size="sm" variant="ghost" onClick={() => void openEdit(r.name)}>Edit</Button>
                <Button size="sm" variant="danger" onClick={() => setDeleting(r.name)}>Remove</Button>
              </div>
            ),
          },
        ]}
      />
      {editing !== undefined && (
        <RadiusProfileModal
          profile={editing}
          directory={directory}
          onClose={() => setEditing(undefined)}
          onSaved={(p) => {
            toast("success", `Profile ${p.name} saved`);
            setEditing(undefined);
            void reload();
          }}
        />
      )}
      <ConfirmModal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => void remove()}
        loading={busy}
        title={`Remove profile ${deleting ?? ""}`}
        message={`Remove "${deleting ?? ""}"? The vault refuses while a NAS still uses it.`}
        confirmLabel="Remove"
      />
    </Card>
  );
}

export async function loadRadiusProfiles(): Promise<ProfileRow[]> {
  const rows = await listRows<{ environment: string; roles: string[] }>("radius_profile");
  return rows.map((r) => ({ name: r.name, environment: r.info.environment, roles: r.info.roles }));
}
