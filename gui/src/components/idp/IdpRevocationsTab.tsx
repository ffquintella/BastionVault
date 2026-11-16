import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, EntityLabel, Table } from "../ui";
import { DenyFeedKeyCard } from "./DenyFeedKeyCard";
import { CopyValue, Snippet, StateBadge } from "./IdpShared";
import type { IdpDirectory } from "./directory";
import * as idp from "../../lib/idp";

type Revoked = idp.IdpDenyFeedPayload["identities"][number];

/**
 * What the targets are told to block: the deny feed (identities that are not
 * active, revoked certificate serials) and the KRL built from the same view.
 * The feed is decoded here for display only; hosts verify its signature
 * against the pinned key before trusting it.
 */
export function IdpRevocationsTab({ directory }: { directory: IdpDirectory }) {
  const [feed, setFeed] = useState<idp.IdpDenyFeed | null>(null);
  const [payload, setPayload] = useState<idp.IdpDenyFeedPayload | null>(null);
  const [krl, setKrl] = useState<idp.IdpKrl | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [f, k] = await Promise.all([idp.idpReadDenyFeed(), idp.idpReadKrl()]);
      setFeed(f.data);
      setPayload(idp.decodeDenyFeed(f.data.feed));
      setKrl(k.data);
    } catch (e) {
      setError(idp.describeIdpError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const notActive = directory.identities.filter((i) => i.info.state !== "active");

  return (
    <div className="space-y-4">
      {error && (
        <Card>
          <p className="text-sm text-[var(--color-danger)] break-words" role="alert">
            {error}
          </p>
        </Card>
      )}
      <Card
        title="Deny feed"
        actions={
          <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
            Refetch
          </Button>
        }
      >
        {feed && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 text-sm">
              <div>
                <div className="text-xs text-[var(--color-text-muted)]">Feed version</div>
                <div className="font-mono" data-testid="deny-feed-version">{feed.feed_version}</div>
              </div>
              <div>
                <div className="text-xs text-[var(--color-text-muted)]">Generated</div>
                <div>{idp.formatTime(payload?.generated_at ?? null)}</div>
              </div>
              <div>
                <div className="text-xs text-[var(--color-text-muted)]">Identities blocked</div>
                <div>{payload?.identities.length ?? "?"}</div>
              </div>
              <div>
                <div className="text-xs text-[var(--color-text-muted)]">Certificates revoked</div>
                <div>{payload?.revoked_serials.length ?? "?"}</div>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
              <CopyValue label="signed by" value={feed.key_id} />
              <CopyValue label="algorithm" value={feed.algorithm} />
            </div>
            <p className="text-xs text-[var(--color-text-muted)]">
              Decoded for display, not verified here. Hosts run bv-idp-host install-feed, which checks the composite
              signature and refuses a version below the one installed.
            </p>
            <Table<Revoked>
              tableClassName="table-fixed"
              data={payload?.identities ?? []}
              rowKey={(r) => r.entity_id}
              emptyMessage="No identity is blocked"
              columns={[
                { key: "login", header: "Login", className: "w-1/5", render: (r) => <div className="truncate font-medium" title={r.login}>{r.login}</div> },
                { key: "uid", header: "uid", className: "w-24", render: (r) => <span className="font-mono text-xs">{r.uid}</span> },
                { key: "state", header: "State", className: "w-28", render: (r) => <StateBadge state={r.state} /> },
                { key: "since", header: "Since", className: "w-48", render: (r) => <span className="text-xs">{idp.formatTime(r.since)}</span> },
                { key: "entity", header: "Entity", render: (r) => <div className="min-w-0 truncate"><EntityLabel entityId={r.entity_id} /></div> },
              ]}
            />
          </div>
        )}
        {feed && !payload && (
          <p className="text-sm text-[var(--color-warning)]" role="alert">
            The feed payload could not be decoded for display.
          </p>
        )}
      </Card>
      <Card title="SSH key revocation list (KRL)">
        {krl && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <Badge variant="info" label={`KRL v${krl.krl_version}`} />
              <span className="text-xs text-[var(--color-text-muted)]">generated {idp.formatTime(krl.generated_at)}</span>
              <span className="text-xs text-[var(--color-text-muted)]">{krl.revoked_serials.length} serial(s)</span>
            </div>
            <CopyValue label="krl (base64)" value={krl.krl} />
            <p className="text-xs text-[var(--color-text-muted)]">
              Install with base64 -d into the file sshd's RevokedKeys names. The KRL version equals the deny feed
              version it was built with.
            </p>
            {krl.revoked_serials.length > 0 && <Snippet title="Revoked certificate serials" text={krl.revoked_serials.join("\n")} />}
          </div>
        )}
      </Card>
      <Card title={`Lifecycle: identities not active (${notActive.length})`}>
        <Table<IdpDirectory["identities"][number]>
          tableClassName="table-fixed"
          data={notActive}
          rowKey={(r) => r.entity_id}
          emptyMessage="Every identity is active"
          columns={[
            { key: "login", header: "Login", className: "w-1/4", render: (r) => <div className="truncate" title={r.info.login}>{r.info.login}</div> },
            { key: "uid", header: "uid", className: "w-24", render: (r) => <span className="font-mono text-xs">{r.info.uid}</span> },
            { key: "state", header: "State", render: (r) => <StateBadge state={r.info.state} /> },
          ]}
        />
        <p className="mt-2 text-xs text-[var(--color-text-muted)]">
          Leaving active revokes the identity's outstanding certificates and advances the feed; removed identities stay
          listed, and their uid and login are never reused.
        </p>
      </Card>
      <DenyFeedKeyCard />
    </div>
  );
}
