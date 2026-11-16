import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, ConfirmModal, Input, Modal, Select, Table, useToast } from "../ui";
import { SettingsForm, type FieldSpec } from "./SettingsForm";
import { ListenerLine, Snippet, TransportWarning, Warnings, environmentOptions } from "./IdpShared";
import { PasscodeCard } from "./PasscodeCard";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

const LDAP_FIELDS: FieldSpec[] = [
  { key: "enabled", label: "Run the listeners", kind: "bool" },
  { key: "allow_unspecified_bind", label: "Allow 0.0.0.0 / :: listen addresses", kind: "bool", hint: "Off by default: bind an explicit interface." },
  { key: "plaintext_enabled", label: "Serve plain clients in cleartext", kind: "bool", hint: "Directory data and bind passcodes cross the network unencrypted: trusted segments only." },
  { key: "ldaps_listen", label: "LDAPS listen (IP:port)", kind: "text", placeholder: "10.0.0.5:636", hint: "Empty clears it." },
  { key: "ldap_listen", label: "Cleartext/StartTLS listen (IP:port)", kind: "text", placeholder: "10.0.0.5:389", hint: "Empty clears it." },
  { key: "base_dn", label: "Base DN", kind: "text" },
  { key: "home_directory_base", label: "homeDirectory prefix", kind: "text" },
  { key: "login_shell", label: "loginShell", kind: "text" },
  { key: "size_limit", label: "Entries per search", kind: "number" },
  { key: "time_limit", label: "Search time limit", kind: "duration" },
  { key: "rate_limit_per_minute", label: "Operations per source per minute", kind: "number" },
  { key: "passcode_default_ttl", label: "Passcode default lifetime", kind: "duration" },
  { key: "passcode_max_ttl", label: "Passcode longest lifetime", kind: "duration", hint: "At most 15m." },
  { key: "tls_cert_pem", label: "Server certificate chain (PEM)", kind: "pem" },
  { key: "tls_key_pem", label: "Server private key (PEM)", kind: "secret_pem", setFlag: "tls_key_set" },
  { key: "client_ca_pem", label: "Client CA (PEM)", kind: "pem", hint: "Every client certificate must chain to it and be pinned on a client." },
];

type Row = { name: string; info: idp.IdpLdapClientInfo };

function sssdSnippet(cfg: idp.IdpLdapConfig | null) {
  const base = cfg?.base_dn || "dc=bastionvault";
  return [
    "# /etc/sssd/sssd.conf (domain section), one environment per client record",
    `ldap_uri = ldaps://${cfg?.ldaps_listen || "<ldaps_listen>"}`,
    `ldap_search_base = ${base}`,
    "ldap_schema = rfc2307",
    "ldap_tls_cert = /etc/sssd/client.crt   # pinned on this host's client record",
    "ldap_tls_key = /etc/sssd/client.key",
    "cache_credentials = false              # required: a cached passcode would outlive the live check",
  ].join("\n");
}

function ClientModal({ client, environments, onClose, onSaved }: { client: idp.IdpLdapClient | null; environments: string[]; onClose: () => void; onSaved: (resp: idp.IdpResponse<idp.IdpLdapClient>) => void }) {
  const creating = client === null;
  const [name, setName] = useState(client?.name ?? "");
  const [transport, setTransport] = useState<"tls" | "plain">(client?.transport ?? "tls");
  const [environment, setEnvironment] = useState(client?.environment ?? "");
  const [pin, setPin] = useState(client?.cert_sha256 ?? "");
  const [address, setAddress] = useState(client?.address ?? "");
  const [description, setDescription] = useState(client?.description ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setError(null);
    const body: Record<string, unknown> = { description: description.trim() };
    if (creating) {
      body.transport = transport;
      body.environment = environment;
    }
    if (transport === "tls") body.cert_sha256 = pin.trim().toLowerCase();
    else body.address = address.trim();
    setBusy(true);
    try {
      onSaved(await idp.idpWrite<idp.IdpLdapClient>("ldap_client", creating ? name.trim() : client.name, body));
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={creating ? "Register a directory client" : `Directory client ${client.name}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={() => void save()} loading={busy}>{creating ? "Register" : "Save"}</Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        {transport === "plain" && (
          <div className="col-span-2">
            <TransportWarning title="Cleartext LDAP client">
              A plain client is recognised by its source address and served without TLS: directory data and bind
              passcodes cross the network unencrypted. Trusted segments only.
            </TransportWarning>
          </div>
        )}
        <div className="col-span-2 sm:col-span-1">
          <Input label="Name" value={name} disabled={!creating} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select
            label="Transport"
            value={transport}
            disabled={!creating}
            onChange={(e) => setTransport(e.target.value as "tls" | "plain")}
            options={[
              { value: "tls", label: "TLS (pinned certificate)" },
              { value: "plain", label: "Plain (source address, cleartext)" },
            ]}
          />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select label="Environment" value={environment} disabled={!creating} onChange={(e) => setEnvironment(e.target.value)} options={environmentOptions(creating ? environments : [environment])} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          {transport === "tls" ? (
            <Input label="Client certificate SHA-256 (hex, DER)" value={pin} onChange={(e) => setPin(e.target.value)} className="font-mono" />
          ) : (
            <Input label="Client source address" value={address} onChange={(e) => setAddress(e.target.value)} />
          )}
        </div>
        <div className="col-span-2">
          <Input label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {error && <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">{error}</p>}
      </div>
    </Modal>
  );
}

export function IdpLdapPanel({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<idp.IdpLdapConfig | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [rows, setRows] = useState<Row[]>([]);
  const [editing, setEditing] = useState<idp.IdpLdapClient | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [c, list] = await Promise.all([idp.idpReadSettings<idp.IdpLdapConfig>("ldap"), idp.idpList<idp.IdpLdapClientInfo>("ldap_client")]);
      setCfg(c.data);
      setRows(list.keys.map((name) => ({ name, info: list.key_info[name] })).filter((r) => r.info !== undefined));
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(body: Record<string, unknown>) {
    const resp = await idp.idpWriteSettings<idp.IdpLdapConfig>("ldap", body);
    setCfg(resp.data);
    setWarnings(resp.warnings);
    toast("success", "LDAP directory settings saved");
  }

  async function openEdit(name: string) {
    try {
      setEditing((await idp.idpRead<idp.IdpLdapClient>("ldap_client", name)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await idp.idpDelete("ldap_client", deleting);
      toast("success", `Directory client ${deleting} removed`);
      setDeleting(null);
      await load();
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      {cfg?.plaintext_enabled && (
        <TransportWarning title="Cleartext LDAP is enabled">
          Plain clients are served without TLS: directory data and bind passcodes cross the network unencrypted. Keep
          it on a trusted segment, and prefer LDAPS or StartTLS.
        </TransportWarning>
      )}
      <Card title="LDAP directory (read-only)" actions={<Badge variant={cfg?.enabled ? "success" : "neutral"} label={cfg?.enabled ? "enabled" : "disabled"} />}>
        <div className="space-y-3">
          <ListenerLine status={cfg?.listening} names={[["ldaps", "LDAPS"], ["ldap", "LDAP/StartTLS"]]} />
          <Warnings warnings={warnings} />
          <SettingsForm fields={LDAP_FIELDS} current={cfg as unknown as Record<string, unknown>} onSave={save} />
        </div>
      </Card>
      <Card title="Directory clients" actions={<Button size="sm" onClick={() => setEditing(null)}>Register client</Button>}>
        <Table<Row>
          tableClassName="table-fixed"
          data={rows}
          rowKey={(r) => r.name}
          emptyMessage="No directory client registered"
          columns={[
            { key: "name", header: "Client", className: "w-1/4", render: (r) => <div className="truncate font-medium" title={r.name}>{r.name}</div> },
            { key: "transport", header: "Transport", className: "w-40", render: (r) => (r.info.transport === "plain" ? <Badge variant="warning" label="plain (cleartext)" /> : <Badge variant="success" label="TLS" />) },
            { key: "env", header: "Environment", render: (r) => <div className="truncate">{r.info.environment}</div> },
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
      </Card>
      <Card title="Host configuration">
        <Snippet title="sssd.conf" text={sssdSnippet(cfg)} />
      </Card>
      <PasscodeCard provider="ldap" environments={directory.activeEnvironments} />
      {editing !== undefined && (
        <ClientModal
          client={editing}
          environments={directory.activeEnvironments}
          onClose={() => setEditing(undefined)}
          onSaved={(resp) => {
            setEditing(undefined);
            toast("success", `Directory client ${resp.data.name} saved`);
            for (const w of resp.warnings) toast("info", w);
            void load();
          }}
        />
      )}
      <ConfirmModal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => void remove()}
        loading={busy}
        title={`Remove directory client ${deleting ?? ""}`}
        message={`Remove "${deleting ?? ""}"? Its next operation is refused as from an unknown client; hosts using it stop resolving users.`}
        confirmLabel="Remove"
      />
    </div>
  );
}
