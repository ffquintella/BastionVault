/**
 * Opening the ⌘K Connect palette from elsewhere in the same window
 * (T38 Phase 3): the Session Workspace's new-tab and split chords open it
 * with the placement the chosen session should get. A DOM event in this
 * window only — nothing crosses to another webview.
 */

import type { SessionPlacement } from "./api";

export const CONNECT_PALETTE_OPEN_EVENT = "bv:connect-palette-open";

export interface ConnectPaletteOpenDetail {
  placement?: SessionPlacement;
}

export function openConnectPalette(placement?: SessionPlacement): void {
  window.dispatchEvent(
    new CustomEvent<ConnectPaletteOpenDetail>(CONNECT_PALETTE_OPEN_EVENT, { detail: { placement } }),
  );
}
