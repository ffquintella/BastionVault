import { useEffect } from "react";
import { useEntityDirectoryStore } from "../../stores/entityDirectoryStore";

interface EntityLabelProps {
  /** Raw `entity_id` to humanize. */
  entityId: string;
  /** When true, render a `You` marker next to the label if the id is the caller's. */
  callerEntityId?: string;
  /** Extra className for the wrapping span. */
  className?: string;
  /** When `true`, show the raw UUID even when a login is known.
   *  Useful in admin-debug contexts where identity transparency matters. */
  showUuid?: boolean;
}

/**
 * Render an `entity_id` as its human login (e.g. `felipe @ userpass/`)
 * when the entity-directory cache knows who it is, falling back to
 * the raw UUID otherwise. The full UUID always appears as a browser
 * `title` tooltip so operators can still copy it when needed.
 *
 * Triggers a one-time directory load on mount; subsequent `<EntityLabel>`
 * instances reuse the cached map from `entityDirectoryStore`.
 */
export function EntityLabel({
  entityId,
  callerEntityId,
  className,
  showUuid,
}: EntityLabelProps) {
  const ensureLoaded = useEntityDirectoryStore((s) => s.ensureLoaded);
  const lookup = useEntityDirectoryStore((s) => s.lookup);
  // Subscribe to loaded so re-renders happen once the cache fills.
  useEntityDirectoryStore((s) => s.loaded);

  useEffect(() => {
    ensureLoaded();
  }, [ensureLoaded]);

  if (!entityId) {
    return (
      <span className={className ?? "text-xs text-[var(--color-text-muted)] italic"}>
        (none)
      </span>
    );
  }

  const alias = lookup(entityId);
  const isSelf = callerEntityId !== undefined && callerEntityId === entityId;

  if (!alias) {
    // Unknown entity — show the raw UUID (mono, truncated), tooltip
    // carries the full form.
    return (
      <span
        className={className ?? "font-mono text-xs truncate"}
        title={entityId}
      >
        {entityId}
        {isSelf && (
          <span className="ml-1 text-[10px] text-[var(--color-text-muted)]">(you)</span>
        )}
      </span>
    );
  }

  return (
    <span
      className={className ?? "text-xs truncate"}
      title={`entity_id: ${entityId}`}
    >
      <span className="font-medium">{alias.name}</span>
      <span className="text-[var(--color-text-muted)]"> @ {alias.mount}</span>
      {isSelf && (
        <span className="ml-1 text-[10px] text-[var(--color-text-muted)]">(you)</span>
      )}
      {showUuid && (
        <span className="ml-2 font-mono text-[10px] text-[var(--color-text-muted)]">
          {entityId}
        </span>
      )}
    </span>
  );
}
