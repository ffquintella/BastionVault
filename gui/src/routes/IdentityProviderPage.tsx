import { useCallback, useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { Button, Card, EmptyState, Tabs, useToast } from "../components/ui";
import { IdpIdentitiesTab } from "../components/idp/IdpIdentitiesTab";
import { IdpEntitlementsTab } from "../components/idp/IdpEntitlementsTab";
import { IdpProvidersTab } from "../components/idp/IdpProvidersTab";
import { IdpRevocationsTab } from "../components/idp/IdpRevocationsTab";
import type { IdpDirectory } from "../components/idp/directory";
import * as idp from "../lib/idp";
import { extractError } from "../lib/error";
import { useNamespaceStore } from "../stores/namespaceStore";

type Probe = { kind: "loading" } | { kind: "missing" } | { kind: "error"; message: string } | { kind: "ready" };

const TABS = [
  { id: "identities", label: "Identities" },
  { id: "entitlements", label: "Entitlements" },
  { id: "providers", label: "Providers" },
  { id: "revocations", label: "Revocations" },
];

const EMPTY: IdpDirectory = { identities: [], environments: [], activeEnvironments: [], reload: async () => {} };

/**
 * Identity Provider admin page (T52 Phase 7). The engine is root-namespace
 * only and not mounted by default, so the page first probes `v2/idp/config`
 * and offers to mount it rather than erroring.
 */
export function IdentityProviderPage() {
  const { toast } = useToast();
  const activeNamespace = useNamespaceStore((s) => s.active);
  const isRoot = activeNamespace === "";
  const [probe, setProbe] = useState<Probe>({ kind: "loading" });
  const [tab, setTab] = useState("identities");
  const [enabling, setEnabling] = useState(false);
  const [directory, setDirectory] = useState<IdpDirectory>(EMPTY);

  const loadDirectory = useCallback(async () => {
    const [ids, envs] = await Promise.all([
      idp.idpList<idp.IdpIdentityInfo>("identity"),
      idp.idpList<idp.IdpEnvironmentInfo>("environment"),
    ]);
    const identities = ids.keys
      .map((entity_id) => ({ entity_id, info: ids.key_info[entity_id] }))
      .filter((i) => i.info !== undefined)
      .sort((a, b) => a.info.login.localeCompare(b.info.login));
    const environments = envs.keys
      .map((name) => ({ name, info: envs.key_info[name] }))
      .filter((e) => e.info !== undefined)
      .sort((a, b) => a.name.localeCompare(b.name));
    setDirectory({
      identities,
      environments,
      activeEnvironments: environments.filter((e) => e.info.state === "active").map((e) => e.name),
      reload: loadDirectory,
    });
  }, []);

  const load = useCallback(async () => {
    setProbe({ kind: "loading" });
    try {
      await idp.idpReadSettings<idp.IdpCoreConfig>("core");
    } catch (e) {
      setProbe(idp.isIdpNotMounted(e) ? { kind: "missing" } : { kind: "error", message: extractError(e) });
      return;
    }
    try {
      await loadDirectory();
      setProbe({ kind: "ready" });
    } catch (e) {
      setProbe({ kind: "error", message: extractError(e) });
    }
  }, [loadDirectory]);

  useEffect(() => {
    // Outside root every request would be refused; say so instead.
    if (!isRoot) return;
    void load();
  }, [isRoot, load]);

  async function enable() {
    setEnabling(true);
    try {
      await idp.idpEnableMount();
      toast("success", "Identity provider enabled at idp/");
      await load();
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setEnabling(false);
    }
  }

  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold">Identity Provider</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              Workforce identities with a stable uid, environment entitlements, and the SSH, RADIUS, SAML, OIDC and
              LDAP providers that assert them downstream.
            </p>
          </div>
          {isRoot && probe.kind !== "missing" && (
            <Button variant="secondary" size="sm" onClick={() => void load()} disabled={probe.kind === "loading"}>
              Refresh
            </Button>
          )}
        </div>

        {!isRoot ? (
          <Card>
            <EmptyState
              title="The identity provider is managed at the root namespace"
              description={`Its identities and uid space are deployment-wide. Switch to the root namespace to administer it (currently in "${activeNamespace}").`}
            />
          </Card>
        ) : probe.kind === "loading" ? (
          <Card>
            <p className="text-sm text-[var(--color-text-muted)]">Loading…</p>
          </Card>
        ) : probe.kind === "missing" ? (
          <Card>
            <EmptyState
              title="Identity provider not enabled"
              description="The idp engine is not mounted. Enabling it mounts idp/ in the root namespace (sys/mounts/idp, type idp); nothing listens or issues until each provider is configured."
              action={
                <Button onClick={() => void enable()} loading={enabling}>
                  Enable identity provider
                </Button>
              }
            />
          </Card>
        ) : probe.kind === "error" ? (
          <Card>
            <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
              {probe.message}
            </p>
          </Card>
        ) : (
          <>
            <Tabs tabs={TABS} active={tab} onChange={setTab} />
            {tab === "identities" && <IdpIdentitiesTab directory={directory} />}
            {tab === "entitlements" && <IdpEntitlementsTab directory={directory} />}
            {tab === "providers" && <IdpProvidersTab directory={directory} />}
            {tab === "revocations" && <IdpRevocationsTab directory={directory} />}
          </>
        )}
      </div>
    </Layout>
  );
}
