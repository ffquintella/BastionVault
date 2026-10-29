/**
 * A SQL browser session's own window (`sql-<token>`, features/sql-browser.md
 * §10, T125). URL params: `token` (what every `sql_*` command names) and
 * `label`. The host refuses each command unless this window holds the
 * session; the vault and the plugin decide every statement.
 */

import { useCallback, useState } from "react";
import { useSearchParams } from "react-router";

import { sessionWindowClose, sqlSessionClose } from "../lib/api";
import { describeSqlError } from "../lib/sqlWorkspace";
import { useSessionHeartbeat } from "../lib/sessionHeartbeat";
import { useWindowCloseGuard } from "../lib/sessionWindowClose";
import { WindowCloseConfirm } from "../components/session/CloseConfirm";
import type { SessionPaneStatus } from "../components/session/SessionPaneHeader";
import { SqlPane } from "../components/sql/SqlPane";

export function SessionSqlWindow() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const label = params.get("label") ?? "sql session";
  const [state, setState] = useState<SessionPaneStatus>("connecting");
  const [notice, setNotice] = useState("");

  const live = token !== "" && state !== "closed";
  useSessionHeartbeat(token !== "");
  const closeGuard = useWindowCloseGuard(() => (live ? [label] : []), token !== "");

  const disconnect = useCallback(async () => {
    try {
      await sqlSessionClose(token);
      setState("closed");
      await sessionWindowClose();
    } catch (e) {
      setNotice(describeSqlError(e));
    }
  }, [token]);

  if (!token) {
    return <div className="p-6 text-sm text-[var(--color-text-muted)]">This window has no SQL session.</div>;
  }
  return (
    <div className="flex h-screen min-w-0 flex-col bg-[var(--color-bg)] text-[var(--color-text)]">
      {notice && (
        <div role="alert" className="px-2 py-1 text-xs text-red-300">
          {notice}
        </div>
      )}
      <div className="min-h-0 flex-1">
        <SqlPane token={token} label={label} onStatusChange={setState} onDisconnect={() => void disconnect()} />
      </div>
      <WindowCloseConfirm guard={closeGuard} labels={live ? [label] : []} />
    </div>
  );
}
