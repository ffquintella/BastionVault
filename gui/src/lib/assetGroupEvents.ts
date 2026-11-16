// In-app signal that this client changed asset groups. Raised by the `lib/api`
// wrappers once a group write / delete / owner transfer settles, so no caller
// has to remember; `lib/assetGroupCache` drops its entries and tells open pages.
// Dependency-free on purpose: `lib/api` imports this module.

/** DOM event dispatched on `window` alongside the module listeners. */
export const ASSET_GROUPS_CHANGED_EVENT = "bv:asset-groups-changed";

type Listener = () => void;

const listeners = new Set<Listener>();

/** Tell every listener (and `window`) that asset groups changed. */
export function emitAssetGroupsChanged(): void {
  for (const listener of [...listeners]) {
    try {
      listener();
    } catch {
      /* one listener's failure must not stop the others */
    }
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(ASSET_GROUPS_CHANGED_EVENT));
  }
}

/** Run `listener` on every change; returns the unsubscribe function. */
export function onAssetGroupsChanged(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
