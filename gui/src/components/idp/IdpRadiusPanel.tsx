import { useCallback, useEffect, useState } from "react";
import { Badge, Card, useToast } from "../ui";
import { SettingsForm, type FieldSpec } from "./SettingsForm";
import { ListenerLine, Snippet, TransportWarning, Warnings } from "./IdpShared";
import { PasscodeCard } from "./PasscodeCard";
import { RadiusClientsCard, RadiusProfilesCard, loadRadiusProfiles } from "./RadiusCards";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

const RADIUS_FIELDS: FieldSpec[] = [
  { key: "enabled", label: "Run the listeners", kind: "bool" },
  { key: "allow_unspecified_bind", label: "Allow 0.0.0.0 / :: listen addresses", kind: "bool", hint: "Off by default: bind an explicit interface." },
  { key: "radsec_listen", label: "RadSec listen (IP:port)", kind: "text", placeholder: "10.0.0.5:2083", hint: "Empty clears it." },
  { key: "rate_limit_per_minute", label: "Requests per source per minute", kind: "number" },
  { key: "udp_enabled", label: "Allow classic UDP RADIUS", kind: "bool", hint: "MD5-based shared secret: trusted segments only." },
  { key: "udp_listen", label: "UDP listen (IP:port)", kind: "text", placeholder: "10.0.0.5:1812", hint: "Needs UDP allowed." },
  { key: "passcode_default_ttl", label: "Passcode default lifetime", kind: "duration", hint: "Seconds or e.g. 2m." },
  { key: "passcode_max_ttl", label: "Passcode longest lifetime", kind: "duration", hint: "At most 15m." },
  { key: "tls_cert_pem", label: "RadSec server certificate chain (PEM)", kind: "pem" },
  { key: "tls_key_pem", label: "RadSec server private key (PEM)", kind: "secret_pem", setFlag: "tls_key_set" },
  { key: "client_ca_pem", label: "NAS client CA (PEM)", kind: "pem", hint: "Every NAS certificate must chain to it and be pinned on a client." },
];

function nasSnippet(cfg: idp.IdpRadiusConfig | null) {
  return [
    "# Settings for a NAS (FortiGate or other) using BastionVault as its RADIUS server",
    `RadSec (TCP/TLS, RFC 6614): ${cfg?.radsec_listen || "<radsec_listen>"}, shared secret "radsec", client certificate pinned on its NAS record`,
    cfg?.udp_enabled ? `UDP (trusted segment only): ${cfg.udp_listen || "<udp_listen>"}, the NAS's own shared secret` : "UDP: not enabled",
    "Authentication: PAP; User-Name = the person's login, User-Password = a one-time passcode",
    "Message-Authenticator: required on every request",
    "Login prompt: must accept a 32-character password",
  ].join("\n");
}

export function IdpRadiusPanel({ directory }: { directory: IdpDirectory }) {
  const { toast } = useToast();
  const [cfg, setCfg] = useState<idp.IdpRadiusConfig | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [profiles, setProfiles] = useState<Awaited<ReturnType<typeof loadRadiusProfiles>>>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, p] = await Promise.all([idp.idpReadSettings<idp.IdpRadiusConfig>("radius"), loadRadiusProfiles()]);
      setCfg(c.data);
      setProfiles(p);
      setError(null);
    } catch (e) {
      setError(idp.describeIdpError(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(body: Record<string, unknown>) {
    const resp = await idp.idpWriteSettings<idp.IdpRadiusConfig>("radius", body);
    setCfg(resp.data);
    setWarnings(resp.warnings);
    toast("success", "RADIUS settings saved");
  }

  return (
    <div className="space-y-4">
      {cfg?.udp_enabled && (
        <TransportWarning title="Classic UDP RADIUS is enabled">
          UDP RADIUS protects the password only with an MD5 construction keyed by the shared secret. Keep it on a
          trusted segment, and prefer RadSec for every device that supports it.
        </TransportWarning>
      )}
      <Card title="RADIUS server" actions={<Badge variant={cfg?.enabled ? "success" : "neutral"} label={cfg?.enabled ? "enabled" : "disabled"} />}>
        <div className="space-y-3">
          {error && (
            <p className="text-sm text-[var(--color-danger)]" role="alert">
              {error}
            </p>
          )}
          <ListenerLine status={cfg?.listening} names={[["radsec", "RadSec"], ["udp", "UDP"]]} />
          <Warnings warnings={warnings} />
          <SettingsForm fields={RADIUS_FIELDS} current={cfg as unknown as Record<string, unknown>} onSave={save} />
        </div>
      </Card>
      <RadiusProfilesCard directory={directory} rows={profiles} reload={load} />
      <RadiusClientsCard directory={directory} profiles={profiles} />
      <Card title="NAS configuration">
        <Snippet title="NAS settings" text={nasSnippet(cfg)} />
      </Card>
      <PasscodeCard provider="radius" environments={directory.activeEnvironments} />
    </div>
  );
}
