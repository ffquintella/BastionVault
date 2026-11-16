import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, ConfirmModal, Input, Modal, Select, Table, Textarea, useToast } from "../ui";
import { SettingsForm, type FieldSpec } from "./SettingsForm";
import { KeyRingCard } from "./KeyRingCard";
import { CopyValue, environmentOptions } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

const SAML_FIELDS: FieldSpec[] = [
  { key: "enabled", label: "Issue assertions", kind: "bool" },
  { key: "entity_id", label: "IdP entity ID", kind: "text", full: true, hint: "Absolute URI; the Issuer of every response." },
  { key: "sso_url", label: "SSO page", kind: "text", full: true, hint: "Browser-facing https page that relays to v2/idp/saml/sso." },
  { key: "assertion_ttl", label: "Assertion lifetime", kind: "duration", hint: "1m–10m, default 5m." },
  { key: "request_max_age", label: "Oldest AuthnRequest", kind: "duration", hint: "1m–15m, default 5m." },
];

type Row = { name: string; info: idp.IdpSamlSpInfo };

function SpModal({ sp, environments, onClose, onSaved }: { sp: idp.IdpSamlSp | null; environments: string[]; onClose: () => void; onSaved: (sp: idp.IdpSamlSp) => void }) {
  const creating = sp === null;
  const [name, setName] = useState(sp?.name ?? "");
  const [entityId, setEntityId] = useState(sp?.entity_id ?? "");
  const [environment, setEnvironment] = useState(sp?.environment ?? "");
  const [acs, setAcs] = useState((sp?.acs_urls ?? []).join("\n"));
  const [idpInitiated, setIdpInitiated] = useState(sp?.allow_idp_initiated ?? false);
  const [description, setDescription] = useState(sp?.description ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setError(null);
    const body: Record<string, unknown> = { acs_urls: idp.splitList(acs), allow_idp_initiated: idpInitiated, description: description.trim() };
    if (creating) {
      body.entity_id = entityId.trim();
      body.environment = environment;
    }
    setBusy(true);
    try {
      onSaved((await idp.idpWrite<idp.IdpSamlSp>("saml_sp", creating ? name.trim() : sp.name, body)).data);
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
      title={creating ? "Register a service provider" : `Service provider ${sp.name}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={() => void save()} loading={busy}>{creating ? "Register" : "Save"}</Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 sm:col-span-1">
          <Input label="Name" value={name} disabled={!creating} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Select label="Environment" value={environment} disabled={!creating} onChange={(e) => setEnvironment(e.target.value)} options={environmentOptions(creating ? environments : [environment])} />
        </div>
        <div className="col-span-2">
          <Input label="SP entity ID (AuthnRequest Issuer)" value={entityId} disabled={!creating} onChange={(e) => setEntityId(e.target.value)} />
        </div>
        <div className="col-span-2">
          <Textarea label="ACS URLs (one per line, https; the first is the default)" value={acs} onChange={(e) => setAcs(e.target.value)} className="min-h-[80px]" />
        </div>
        <label className="col-span-2 flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" checked={idpInitiated} onChange={(e) => setIdpInitiated(e.target.checked)} />
          <span>Allow IdP-initiated (unsolicited) responses</span>
        </label>
        <div className="col-span-2">
          <Input label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {error && <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">{error}</p>}
      </div>
    </Modal>
  );
}

export function IdpSamlPanel({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<idp.IdpSamlConfig | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [editing, setEditing] = useState<idp.IdpSamlSp | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [c, list] = await Promise.all([idp.idpReadSettings<idp.IdpSamlConfig>("saml"), idp.idpList<idp.IdpSamlSpInfo>("saml_sp")]);
      setCfg(c.data);
      setRows(list.keys.map((name) => ({ name, info: list.key_info[name] })).filter((r) => r.info !== undefined));
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function copyMetadata() {
    try {
      const md = (await idp.idpReadSamlMetadata()).data;
      await navigator.clipboard.writeText(md.metadata);
      toast("success", "IdP metadata XML copied");
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function openEdit(name: string) {
    try {
      setEditing((await idp.idpRead<idp.IdpSamlSp>("saml_sp", name)).data);
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await idp.idpDelete("saml_sp", deleting);
      toast("success", `Service provider ${deleting} removed`);
      setDeleting(null);
      await load();
    } catch (e) {
      toast("error", idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  async function save(body: Record<string, unknown>) {
    setCfg((await idp.idpWriteSettings<idp.IdpSamlConfig>("saml", body)).data);
    toast("success", "SAML IdP settings saved");
  }

  return (
    <div className="space-y-4">
      <Card
        title="SAML 2.0 identity provider"
        actions={
          <>
            <Badge variant={cfg?.enabled ? "success" : "neutral"} label={cfg?.enabled ? "enabled" : "disabled"} />
            <Button size="sm" variant="secondary" onClick={() => void copyMetadata()} disabled={!cfg?.entity_id}>
              Copy metadata XML
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {cfg?.entity_id && <CopyValue label="entity id" value={cfg.entity_id} />}
          <SettingsForm fields={SAML_FIELDS} current={cfg as unknown as Record<string, unknown>} onSave={save} />
        </div>
      </Card>
      <KeyRingCard ring="saml" />
      <Card title="Service providers" actions={<Button size="sm" onClick={() => setEditing(null)}>Register SP</Button>}>
        <Table<Row>
          tableClassName="table-fixed"
          data={rows}
          rowKey={(r) => r.name}
          emptyMessage="No service provider registered"
          columns={[
            { key: "name", header: "Name", className: "w-1/5", render: (r) => <div className="truncate font-medium" title={r.name}>{r.name}</div> },
            { key: "entity", header: "Entity ID", render: (r) => <div className="truncate font-mono text-xs" title={r.info.entity_id}>{r.info.entity_id}</div> },
            { key: "env", header: "Environment", className: "w-1/6", render: (r) => <div className="truncate">{r.info.environment}</div> },
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
      {editing !== undefined && (
        <SpModal
          sp={editing}
          environments={directory.activeEnvironments}
          onClose={() => setEditing(undefined)}
          onSaved={(sp) => {
            setEditing(undefined);
            toast("success", `Service provider ${sp.name} saved`);
            void load();
          }}
        />
      )}
      <ConfirmModal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => void remove()}
        loading={busy}
        title={`Remove service provider ${deleting ?? ""}`}
        message={`Remove "${deleting ?? ""}"? Its AuthnRequests are refused from now on; nobody can sign in to it through the vault.`}
        confirmLabel="Remove"
      />
    </div>
  );
}
