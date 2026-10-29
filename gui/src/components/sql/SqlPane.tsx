import { lazy, Suspense } from "react";
import type { ComponentProps } from "react";

// D3 (features/sql-browser.md, Phase 0): the workspace loads on demand, so
// the session bundle's first chunk is unchanged for people who never open it.
const SqlWorkspace = lazy(() => import("./SqlWorkspace"));

/** The SQL workspace, lazily loaded: a `sql-<token>` window or a pane. */
export function SqlPane(props: ComponentProps<typeof SqlWorkspace>) {
  return (
    <Suspense fallback={<div className="p-3 text-xs text-[var(--color-text-muted)]">Loading the SQL workspace…</div>}>
      <SqlWorkspace {...props} />
    </Suspense>
  );
}
