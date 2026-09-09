import { useEffect, useState, type ReactNode } from "react";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  EntityLabel,
  EntityPicker,
  GroupNamePicker,
  Input,
  Modal,
  Select,
  Table,
} from "./ui";
import type {
  OwnerInfo,
  ShareEntry,
  ShareGranteeKind,
  ShareTargetKind,
} from "../lib/types";
import { isAdminUser } from "../lib/access";
import { useAuthStore } from "../stores/authStore";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

/**
 * The three ownership calls a shareable object has to provide. Point
 * them straight at the `api` helpers — `read`/`transfer`/`claim` are
 * called with the object's API-side target key, nothing else.
 *
 * `claim` is optional and carries meaning: a kind that has a dedicated
 * claim endpoint (KV) offers Claim-ownership to *any* caller, because
 * the server decides whether the path is still unowned. A kind without
 * one (resources, files) can only claim by riding the admin transfer
 * endpoint, so the control is admin-only. Do not add a `claim` that is
 * really a transfer-to-self — leave it out and the component derives
 * that shape itself.
 *
 * `read` is optional for the one kind that has no owner endpoint at
 * all: an asset group carries `owner_entity_id` on the record the
 * parent page already loaded, and supplies it through `ownerOverride`.
 */
export interface OwnerAdapter {
  read?: (target: string) => Promise<OwnerInfo>;
  transfer: (target: string, newOwnerEntityId: string) => Promise<void>;
  claim?: (target: string) => Promise<void>;
}

const GRANTEE_KIND_LABELS: Record<ShareGranteeKind, string> = {
  entity: "User (entity)",
  group_user: "User identity group",
  group_app: "Application group (AppID)",
};

export interface ObjectSharingCardProps {
  /** Share kind the ACL evaluator keys on. */
  kind: ShareTargetKind;
  /**
   * API-side target key. Not necessarily what the user sees: files are
   * keyed by their server-assigned UUID, KV secrets by the canonical
   * mount-relative path.
   */
  target: string;
  /** Display label for the modal titles. Defaults to `target`. */
  label?: string;
  /** Prose noun — "resource", "file", "KV path". */
  noun: string;
  owner: OwnerAdapter;
  /**
   * Owner record supplied by the call site instead of being fetched
   * through `owner.read`. Asset groups take this path: their owner is a
   * field on the `AssetGroupInfo` the detail page already holds, so a
   * second lookup would only be a chance to disagree with the header.
   * `null` means "loaded, and unowned". Pair it with `onOwnerChange`,
   * which is the only way this card can refresh a value it does not own.
   */
  ownerOverride?: OwnerInfo | null;
  /**
   * Fired after a successful transfer or claim. Required when
   * `ownerOverride` is used — the card reloads the shares itself, but
   * the owner value belongs to the caller and only the caller can
   * refetch it.
   */
  onOwnerChange?: () => void;
  /** Grantable capabilities, in the order they are offered. */
  capabilities: readonly string[];
  /** Explanatory copy under the capability chips, when a kind needs it. */
  capabilityHint?: ReactNode;
  /**
   * Grantee kinds offered on grant, in the order they are listed. A
   * single-entry list (the default) hides the selector entirely.
   *
   * This gates only what the *grant* form can create. Revoke and the
   * grantee column always honour the `grantee_kind` on the record, so a
   * group share created through the API or CLI on a kind that does not
   * offer them here still renders and revokes correctly.
   */
  granteeKinds?: readonly ShareGranteeKind[];
  /**
   * Replaces the derived unowned copy. Needed by kinds whose ownership
   * is *not* captured by the next authenticated write — an asset group
   * takes its owner on create and never again.
   */
  unownedDescription?: string;
  toast: (type: "success" | "error" | "info", msg: string) => void;
  /**
   * Which policies see the admin ownership controls. Defaults to the
   * delegated-admin set the sidebar and dashboard use; KV and asset
   * groups pass a narrower literal `root`/`admin` check to keep their
   * long-standing behavior. GUI gating only — the API authorizes every
   * request.
   */
  isAdminPolicy?: (policies: readonly string[]) => boolean;
  /**
   * Widget for the transfer target. `"text"` is a free-text entity_id
   * field; `"entity-picker"` searches the directory by login.
   */
  transferInput?: "text" | "entity-picker";
  /**
   * Lets a detail header's Share button drive this card: opens the
   * Grant modal, or explains why the caller can't grant, so the
   * permission model lives in one place. `onGrantHandled` fires once so
   * the request isn't replayed the next time the tab is opened.
   */
  openGrant?: boolean;
  onGrantHandled?: () => void;
}

function unownedDescription(
  noun: string,
  canClaim: boolean,
  isAdmin: boolean,
): string {
  const head = `No entity has claimed this ${noun} yet.`;
  if (canClaim && isAdmin) {
    return `${head} Claim it for yourself, assign an owner, or let the next authenticated write capture it.`;
  }
  if (canClaim) {
    return `${head} Claim it for yourself, or wait for the next authenticated write.`;
  }
  return `${head} The next write by an authenticated caller will capture ownership.`;
}

/** Grantee cell: an entity resolves to a login, a group renders as its
 *  literal name behind a kind badge — there is no directory lookup for
 *  a group name and it is already human-readable. */
function GranteeCell({ share }: { share: ShareEntry }) {
  const gk = share.grantee_kind ?? "entity";
  if (gk === "entity") {
    return <EntityLabel entityId={share.grantee_entity_id} />;
  }
  return (
    <div className="flex items-center gap-2 min-w-0">
      <Badge
        label={gk === "group_user" ? "user group" : "app group"}
        variant="warning"
      />
      <span className="font-mono text-xs truncate">
        {share.grantee_entity_id}
      </span>
    </div>
  );
}

/**
 * Owner card + shares table + grant/revoke + admin transfer for one
 * shareable object, of any `ShareTargetKind`.
 *
 * This is the single implementation behind `ResourceSharingCard`
 * (resources), `FileSharingCard` (file resources), the KV sharing panel
 * in SecretsPage and `AssetGroupSharingCard`. The kinds differ only in
 * their target key, their owner endpoints, their capability set and
 * which grantee kinds they offer — all of which arrive as props — so
 * share semantics change in one place.
 *
 * It renders the body only: the page wrapper (a detail tab, a modal)
 * belongs to the call site.
 */
export function ObjectSharingCard({
  kind,
  target,
  label,
  noun,
  owner: ownerApi,
  ownerOverride,
  onOwnerChange,
  capabilities,
  capabilityHint,
  granteeKinds = ["entity"],
  unownedDescription: unownedDescriptionOverride,
  toast,
  isAdminPolicy = isAdminUser,
  transferInput = "text",
  openGrant = false,
  onGrantHandled,
}: ObjectSharingCardProps) {
  const title = label || target;

  const [fetchedOwner, setFetchedOwner] = useState<OwnerInfo | null>(null);
  const [shares, setShares] = useState<ShareEntry[]>([]);
  const [loading, setLoading] = useState(true);

  // The call site's value wins whenever it supplies one; `null` from it
  // is a real answer ("unowned"), not "not supplied".
  const owner = ownerOverride !== undefined ? ownerOverride : fetchedOwner;

  const policies = useAuthStore((s) => s.policies);
  const entityId = useAuthStore((s) => s.entityId);
  const isAdmin = isAdminPolicy(policies);
  const isOwner =
    owner?.owned === true && owner.entity_id === entityId && entityId !== "";
  const canGrant = isOwner || isAdmin;
  // A dedicated claim endpoint is open to everyone (the server rejects
  // an already-owned target); a transfer-to-self is admin-only.
  const canClaim = !owner?.owned && (ownerApi.claim !== undefined || isAdmin);

  const [showGrant, setShowGrant] = useState(false);
  const [granteeKind, setGranteeKind] = useState<ShareGranteeKind>(
    granteeKinds[0] ?? "entity",
  );
  const [grantee, setGrantee] = useState("");
  const [caps, setCaps] = useState<string[]>(["read"]);
  const [expires, setExpires] = useState("");

  const [showTransfer, setShowTransfer] = useState(false);
  const [newOwner, setNewOwner] = useState("");

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, target]);

  // Waits for the owner lookup so an object the caller owns doesn't get
  // a spurious "not allowed".
  useEffect(() => {
    if (!openGrant || loading) return;
    if (canGrant) {
      setShowGrant(true);
    } else {
      toast("error", `Only the owner or an admin can share this ${noun}.`);
    }
    onGrantHandled?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openGrant, loading]);

  async function load() {
    setLoading(true);
    try {
      const [o, s] = await Promise.all([
        ownerApi.read
          ? ownerApi.read(target).catch(() => null)
          : Promise.resolve(null),
        api.listSharesForTarget(kind, target).catch(() => [] as ShareEntry[]),
      ]);
      setFetchedOwner(o);
      setShares(s);
    } finally {
      setLoading(false);
    }
  }

  function resetGrantForm() {
    setGranteeKind(granteeKinds[0] ?? "entity");
    setGrantee("");
    setCaps(["read"]);
    setExpires("");
  }

  async function handleGrant() {
    try {
      await api.putShare(
        kind,
        target,
        grantee.trim(),
        caps,
        expires.trim(),
        granteeKind,
      );
      toast("success", "Share granted");
      setShowGrant(false);
      resetGrantForm();
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleRevoke(s: ShareEntry) {
    try {
      // The record's own kind, not the form default: a group share made
      // through the API or CLI is a different key and revoking it as an
      // `entity` would miss it silently.
      await api.deleteShare(
        kind,
        s.target_path,
        s.grantee_entity_id,
        s.grantee_kind ?? "entity",
      );
      toast("success", "Share revoked");
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  async function handleTransfer() {
    try {
      await ownerApi.transfer(target, newOwner.trim());
      toast("success", "Ownership transferred");
      setShowTransfer(false);
      setNewOwner("");
      onOwnerChange?.();
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  // Claim = point the owner record at the caller's own entity.
  async function handleClaim() {
    try {
      if (ownerApi.claim) {
        await ownerApi.claim(target);
      } else {
        if (!entityId) {
          toast(
            "error",
            "Your token has no entity_id — use Assign owner to name one explicitly.",
          );
          return;
        }
        await ownerApi.transfer(target, entityId);
      }
      toast("success", "Ownership claimed");
      onOwnerChange?.();
      load();
    } catch (e: unknown) {
      toast("error", extractError(e));
    }
  }

  function toggleCap(c: string) {
    setCaps((prev) =>
      prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c],
    );
  }

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-[var(--color-text-muted)]">
          Loading sharing info...
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card
        title="Owner"
        actions={
          canClaim || isAdmin ? (
            <>
              {canClaim && (
                <Button size="sm" variant="secondary" onClick={handleClaim}>
                  Claim ownership
                </Button>
              )}
              {isAdmin && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowTransfer(true)}
                >
                  {owner?.owned ? "Transfer" : "Assign owner"}
                </Button>
              )}
            </>
          ) : null
        }
      >
        {owner?.owned ? (
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-[var(--color-text-muted)] text-xs">
                owner
              </span>
              <EntityLabel
                entityId={owner.entity_id}
                callerEntityId={entityId}
              />
              {isOwner && <Badge label="You" variant="success" />}
            </div>
            {owner.created_at && (
              <div className="flex items-center gap-2">
                <span className="text-[var(--color-text-muted)] text-xs">
                  since
                </span>
                <span className="text-xs">
                  {new Date(owner.created_at).toLocaleString()}
                </span>
              </div>
            )}
          </div>
        ) : (
          <EmptyState
            title="Unowned"
            description={
              unownedDescriptionOverride ??
              unownedDescription(noun, canClaim, isAdmin)
            }
          />
        )}
      </Card>

      <Card
        title="Shares"
        actions={
          canGrant ? (
            <Button size="sm" onClick={() => setShowGrant(true)}>
              Grant access
            </Button>
          ) : null
        }
      >
        {shares.length === 0 ? (
          <EmptyState
            title="No shares"
            description={
              canGrant
                ? "Nobody else has access through an explicit share yet."
                : `Only the owner or an admin can grant new shares on this ${noun}.`
            }
          />
        ) : (
          <Table
            columns={[
              {
                key: "grantee",
                header: "Grantee",
                render: (s: ShareEntry) => <GranteeCell share={s} />,
              },
              {
                key: "caps",
                header: "Capabilities",
                render: (s: ShareEntry) => (
                  <div className="flex flex-wrap gap-1">
                    {s.capabilities.map((c) => (
                      <Badge key={c} label={c} variant="info" />
                    ))}
                  </div>
                ),
              },
              {
                key: "granted_at",
                header: "Granted",
                render: (s: ShareEntry) => (
                  <span className="text-xs text-[var(--color-text-muted)]">
                    {s.granted_at
                      ? new Date(s.granted_at).toLocaleString()
                      : "-"}
                  </span>
                ),
              },
              {
                key: "expires",
                header: "Expires",
                render: (s: ShareEntry) =>
                  s.expires_at ? (
                    <span
                      className={`text-xs ${s.expired ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}
                    >
                      {s.expires_at}
                      {s.expired && " (expired)"}
                    </span>
                  ) : (
                    <span className="text-xs text-[var(--color-text-muted)]">
                      never
                    </span>
                  ),
              },
              {
                key: "revoke",
                header: "",
                className: "text-right w-24",
                render: (s: ShareEntry) =>
                  canGrant ? (
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => handleRevoke(s)}
                    >
                      Revoke
                    </Button>
                  ) : null,
              },
            ]}
            data={shares}
            // An entity and a group can hold the same literal id, so the
            // kind is part of the key.
            rowKey={(s: ShareEntry) =>
              `${s.grantee_kind ?? "entity"}:${s.grantee_entity_id}`
            }
          />
        )}
      </Card>

      <Modal
        open={showGrant}
        onClose={() => setShowGrant(false)}
        title={`Grant access to ${title}`}
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowGrant(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleGrant}
              disabled={!grantee.trim() || caps.length === 0}
            >
              Grant
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {granteeKinds.length > 1 && (
            <div>
              <Select
                label="Grantee kind"
                value={granteeKind}
                onChange={(e) => {
                  setGranteeKind(e.target.value as ShareGranteeKind);
                  setGrantee("");
                }}
                options={granteeKinds.map((k) => ({
                  value: k,
                  label: GRANTEE_KIND_LABELS[k],
                }))}
              />
              {granteeKind !== "entity" && (
                <p className="text-xs text-[var(--color-text-muted)] mt-1">
                  Group shares only resolve to access for members with a policy
                  that carries{" "}
                  <code className="font-mono">
                    metadata.group_shared_resources = "true"
                  </code>
                  .
                </p>
              )}
            </div>
          )}
          {granteeKind === "entity" ? (
            <EntityPicker
              label="Grantee"
              value={grantee}
              onChange={(id) => setGrantee(id)}
              placeholder="Search by login or paste entity_id"
              hint="Type part of a username, mount, or UUID."
            />
          ) : (
            <GroupNamePicker
              kind={granteeKind === "group_user" ? "user" : "app"}
              value={grantee}
              onChange={setGrantee}
              label={
                granteeKind === "group_user"
                  ? "User group name"
                  : "App group name"
              }
              placeholder={
                granteeKind === "group_user" ? "engineering" : "ci-bots"
              }
              hint="Pick from existing groups (Admin → Identity Groups) or type a name."
            />
          )}
          <div>
            <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1">
              Capabilities
            </label>
            <div className="flex flex-wrap gap-2">
              {capabilities.map((c) => {
                const selected = caps.includes(c);
                return (
                  <button
                    key={c}
                    type="button"
                    onClick={() => toggleCap(c)}
                    className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                      selected
                        ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                        : "bg-[var(--color-bg)] border-[var(--color-border)] text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)]"
                    }`}
                  >
                    {c}
                  </button>
                );
              })}
            </div>
            {capabilityHint && (
              <p className="text-xs text-[var(--color-text-muted)] mt-1.5">
                {capabilityHint}
              </p>
            )}
          </div>
          <Input
            label="Expires at (optional)"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            placeholder="2026-12-31T23:59:59Z"
            hint="RFC3339 timestamp. Leave empty for no expiry."
          />
        </div>
      </Modal>

      <Modal
        open={showTransfer}
        onClose={() => setShowTransfer(false)}
        title={
          owner?.owned
            ? `Transfer ownership of ${title}`
            : `Assign an owner for ${title}`
        }
        actions={
          <>
            <Button variant="ghost" onClick={() => setShowTransfer(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleTransfer}
              disabled={!newOwner.trim()}
            >
              Transfer
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            Overwrite the owner record for this {noun}. Admin-only. The new
            entity will pass the <code>scopes = ["owner"]</code> check on every
            subsequent request; the previous owner loses owner-scoped access
            unless a share is also created for them.
          </p>
          {transferInput === "entity-picker" ? (
            <EntityPicker
              label="New owner"
              value={newOwner}
              onChange={(id) => setNewOwner(id)}
              placeholder="Search by login or paste entity_id"
            />
          ) : (
            <Input
              label="New owner entity_id"
              value={newOwner}
              onChange={(e) => setNewOwner(e.target.value)}
              placeholder="Target entity UUID"
            />
          )}
        </div>
      </Modal>
    </div>
  );
}
