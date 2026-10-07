// Phase 8.3 — full-screen replay in a separate Tauri WebviewWindow.
// Spawned from the Recordings page via `rustionOpenReplayWindow`.
//
// A one-pane wrapper (T38 Phase 1): reads the recording id and seek
// offset from the URL query (HashRouter), owns the window title and what
// Close means, and renders [[ReplayPane]]. No Layout chrome — this window
// is meant for operators to scrub a recording without the main app's
// sidebar in the way. A replay holds no live session, so it sends no
// heartbeat.

import { useEffect } from "react";
import { useSearchParams } from "react-router";

import { ReplayPane } from "../components/session/ReplayPane";

export function SessionReplayWindow() {
  const [params] = useSearchParams();
  const recordingId = params.get("recording") ?? "";
  // Phase 8.6 — `?at=<ms>` seeks the player, set from a
  // keystroke-search hit. A numeric offset and nothing else: the
  // query and the matched text never travel in a URL.
  const seekMs = Number.parseInt(params.get("at") ?? "", 10);
  const initialSeekMs = Number.isFinite(seekMs) && seekMs > 0 ? seekMs : undefined;

  useEffect(() => {
    document.title = `BastionVault — Replay ${recordingId}`;
  }, [recordingId]);

  return (
    <ReplayPane
      recordingId={recordingId}
      initialSeekMs={initialSeekMs}
      onClose={() => window.close()}
      fillViewport
    />
  );
}
