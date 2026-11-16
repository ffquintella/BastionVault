import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, Input, Modal, Select, Table, Textarea, useToast } from "../ui";
import { SettingsForm, type FieldSpec } from "./SettingsForm";
import { DenyFeedKeyCard } from "./DenyFeedKeyCard";
import { CopyValue, Snippet, environmentOptions } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import { useAuthStore } from "../../stores/authStore";
import * as idp from "../../lib/idp";

const SSH_FIELDS: FieldSpec[] = [
  { key: "mount", label: "SSH engine mount", kind: "text", hint: "Resolved in each environment's namespace (default ssh)." },
  { key: "role", label: "CA role", kind: "text", hint: "Must allow any principal and the four bastionvault extensions." },
  { key: "default_ttl", label: "Default lifetime", kind: "duration", hint: "Seconds or e.g. 30m." },
  { key: "max_ttl", label: "Largest lifetime", kind: "duration", hint: "At most 8h; a larger request is refused." },
];

function hostSnippet(environment: string) {
  const env = environment || "<environment>";
  return [
    `# /etc/ssh/sshd_config on a host of environment ${env}`,
    "TrustedUserCAKeys /etc/ssh/bv_user_ca.pub      # that environment's SSH CA",
    "RevokedKeys /etc/ssh/bv_revoked.krl             # base64 -d of v2/idp/ssh/krl .data.krl",
    `AuthorizedPrincipalsCommand /usr/local/sbin/bv-idp-host principals --key /etc/bv-idp/feed-key.json --state-dir /var/lib/bv-idp --environment ${env} %u %s %i`,
    "AuthorizedPrincipalsCommandUser bv-idp",
  ].join("\n");
}

function SignCard({ environments }: { environments: string[] }) {
  const isRootToken = useAuthStore((s) => s.policies.includes("root"));
  const [environment, setEnvironment] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [ttl, setTtl] = useState("");
  const [roles, setRoles] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cert, setCert] = useState<idp.IdpSshCertificate | null>(null);

  async function sign() {
    setError(null);
    setBusy(true);
    try {
      setCert((await idp.idpSshSign(environment, publicKey.trim(), ttl, idp.splitList(roles))).data);
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Sign my SSH key">
      <div className="grid grid-cols-2 gap-3">
        <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
          Signs your own public key into a certificate whose principal is your login, for an environment you are
          entitled to. Never paste a private key here.
        </p>
        {isRootToken && (
          <p className="col-span-2 text-xs text-[var(--color-warning)]" role="note">
            You are signed in with a root token, which is bound to no identity: the vault will refuse this.
          </p>
        )}
        <div className="col-span-2 sm:col-span-1">
          <Select label="Environment" value={environment} onChange={(e) => setEnvironment(e.target.value)} options={environmentOptions(environments)} />
        </div>
        <div className="col-span-2 sm:col-span-1">
          <Input label="Lifetime (optional)" placeholder="default" value={ttl} onChange={(e) => setTtl(e.target.value)} />
        </div>
        <div className="col-span-2">
          <Textarea
            label="Public key"
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder="ssh-ed25519 AAAA… user@host"
            className="min-h-[60px]"
          />
        </div>
        <div className="col-span-2">
          <Input label="Roles (optional)" placeholder="all entitled roles" value={roles} onChange={(e) => setRoles(e.target.value)} />
        </div>
        {error && (
          <p className="col-span-2 text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        )}
        <div className="col-span-2 flex justify-end">
          <Button onClick={() => void sign()} loading={busy} disabled={!environment || !publicKey.trim()}>
            Sign
          </Button>
        </div>
      </div>
      {cert && (
        <Modal open onClose={() => setCert(null)} title={`Certificate for ${cert.login} in ${cert.environment}`} size="lg">
          <div className="space-y-3">
            <Textarea label="Signed certificate (save as <key>-cert.pub)" readOnly value={cert.signed_key} className="min-h-[100px]" />
            <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
              <CopyValue label="serial" value={cert.serial_number} />
              <CopyValue label="key id" value={cert.key_id} />
            </div>
            <p className="text-xs text-[var(--color-text-muted)]">
              uid {cert.uid}, gid {cert.gid}, roles {cert.roles.join(", ") || "—"}; valid {idp.formatTime(cert.valid_after)}{" "}
              to {idp.formatTime(cert.valid_before)}.
            </p>
          </div>
        </Modal>
      )}
    </Card>
  );
}

export function IdpSshPanel({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<idp.IdpSshConfig | null>(null);
  const [snippetEnv, setSnippetEnv] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setCfg((await idp.idpReadSettings<idp.IdpSshConfig>("ssh")).data);
      setError(null);
    } catch (e) {
      setError(idp.describeIdpError(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(body: Record<string, unknown>) {
    const resp = await idp.idpWriteSettings<idp.IdpSshConfig>("ssh", body);
    setCfg(resp.data);
    toast("success", "SSH provider settings saved");
  }

  const envs = directory.environments.filter((e) => e.info.state === "active");

  return (
    <div className="space-y-4">
      <Card
        title="SSH identity certificates"
        actions={
          <>
            <Badge variant={cfg?.enabled ? "success" : "neutral"} label={cfg?.enabled ? "enabled" : "off until saved"} />
            {cfg && !cfg.enabled && (
              <Button size="sm" onClick={() => void save({}).catch((e) => toast("error", idp.describeIdpError(e)))}>
                Enable with defaults
              </Button>
            )}
          </>
        }
      >
        {error && (
          <p className="mb-2 text-sm text-[var(--color-danger)]" role="alert">
            {error}
          </p>
        )}
        <SettingsForm fields={SSH_FIELDS} current={cfg as unknown as Record<string, unknown>} onSave={save} />
      </Card>
      <Card title="Where each environment signs">
        <Table<(typeof envs)[number]>
          tableClassName="table-fixed"
          data={envs}
          rowKey={(e) => e.name}
          emptyMessage="No active environment"
          columns={[
            { key: "env", header: "Environment", className: "w-1/4", render: (e) => <div className="truncate">{e.name}</div> },
            {
              key: "target",
              header: "Signer (in the environment's namespace)",
              render: (e) => (
                <div className="truncate font-mono text-xs" title={`${e.info.namespace || "(root)"}: ${cfg?.mount ?? "ssh"}/sign/${cfg?.role ?? "idp"}`}>
                  {e.info.namespace || "(root)"}: {cfg?.mount ?? "ssh"}/sign/{cfg?.role ?? "idp"}
                </div>
              ),
            },
            {
              key: "status",
              header: "Issue",
              className: "w-32",
              render: () => <Badge variant={cfg?.enabled ? "success" : "neutral"} label={cfg?.enabled ? "configured" : "off"} />,
            },
          ]}
        />
        <p className="mt-2 text-xs text-[var(--color-text-muted)]">
          The page does not probe each namespace's SSH engine; a missing mount or role shows up as a sign error.
        </p>
      </Card>
      <Card title="Linux host setup">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 sm:col-span-1">
              <Select label="Environment" value={snippetEnv} onChange={(e) => setSnippetEnv(e.target.value)} options={environmentOptions(directory.activeEnvironments, "<environment>")} />
            </div>
          </div>
          <Snippet title="sshd_config" text={hostSnippet(snippetEnv)} />
          <p className="text-xs text-[var(--color-text-muted)]">
            Plus a timer that fetches v2/idp/ssh/krl and v2/idp/deny-feed with a read-only token and runs bv-idp-host
            install-feed.
          </p>
        </div>
      </Card>
      <DenyFeedKeyCard />
      <SignCard environments={directory.activeEnvironments} />
    </div>
  );
}
