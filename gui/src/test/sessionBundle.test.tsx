/**
 * The session-only bundle, `session.html` (features/session-workspace.md,
 * T110).
 *
 * Session windows — a session's own window, the Session Workspace, a
 * recording replay — load `src/sessionApp/main.tsx` instead of the vault UI.
 * This suite pins three properties of that bundle:
 *
 *   1. its route table is the four session routes and nothing else;
 *   2. its import graph reaches no vault page, no auth store (and so never
 *      the vault token), no `ui` barrel and no shell / dialog plugin;
 *   3. the commands each window's routes can call are exactly the command
 *      set the host grants that window (`src-tauri/permissions/
 *      window-sets.json`). A command the bundle needs but the window is not
 *      granted would fail at run time; one granted but never called is a
 *      wider boundary than the window needs. The Rust side
 *      (`window_acl_tests`) pins which capability gets which set.
 *
 * The import graph is read statically from the sources, so the check covers
 * code paths no test renders.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { WEB_CHROME_COMMANDS } from "../lib/webChrome";
import { SESSION_ROUTES, SessionRoutes } from "../sessionApp/SessionApp";

vi.mock("@xterm/xterm", () => ({ Terminal: class {} }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class {} }));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

const SOURCES = import.meta.glob<string>("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
});
const WINDOW_SETS_JSON = Object.values(
  import.meta.glob<string>("/src-tauri/permissions/window-sets.json", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
)[0];

// ── Static import graph ─────────────────────────────────────────────────

/** Modules that wrap one command per export. Only the exports a file
 *  imports count as reachable — the rest of the wrapper is not called. */
const WRAPPERS = new Set(["/src/lib/api.ts", "/src/lib/rustion.ts", "/src/lib/sshBroker.ts"]);

const IMPORT_RE =
  /(?:^|[\s;])(import|export)\s+(type\s+)?([\s\S]*?)\s*from\s*["']([^"']+)["']|(?:^|[\s;])import\s*["']([^"']+)["']|\bimport\(\s*["']([^"']+)["']\s*\)/g;
const INVOKE_RE = /\binvoke\s*(?:<[\s\S]*?>)?\s*\(\s*["'`]([A-Za-z0-9_:|]+)["'`]/g;

function normalise(parts: string[]): string {
  const out: string[] = [];
  for (const p of parts) {
    if (p === "" || p === ".") continue;
    if (p === "..") out.pop();
    else out.push(p);
  }
  return "/" + out.join("/");
}

function resolve(from: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  const dir = from.split("/").slice(0, -1);
  const base = normalise([...dir, ...spec.split("/")]);
  for (const candidate of [base, `${base}.ts`, `${base}.tsx`, `${base}/index.ts`, `${base}/index.tsx`]) {
    if (candidate in SOURCES) return candidate;
  }
  if (/\.(css|json|svg|png)$/.test(spec)) return null;
  throw new Error(`cannot resolve ${spec} from ${from}`);
}

interface Graph {
  files: Set<string>;
  bare: Set<string>;
  commands: Set<string>;
}

function walk(entries: string[]): Graph {
  const files = new Set<string>();
  const bare = new Set<string>();
  const used = new Map<string, Set<string>>();
  const commands = new Set<string>();

  const visit = (file: string) => {
    if (files.has(file)) return;
    files.add(file);
    const text = SOURCES[file];
    if (text === undefined) throw new Error(`no source for ${file}`);
    if (!WRAPPERS.has(file)) for (const m of text.matchAll(INVOKE_RE)) commands.add(m[1]);
    for (const m of text.matchAll(IMPORT_RE)) {
      const typeOnly = Boolean(m[2]);
      const clause = m[3] ?? "";
      const spec = m[4] ?? m[5] ?? m[6];
      if (typeOnly) continue;
      const target = resolve(file, spec);
      if (target === null) {
        if (!spec.startsWith(".")) bare.add(spec);
        continue;
      }
      if (WRAPPERS.has(target)) {
        const names = used.get(target) ?? new Set<string>();
        used.set(target, names);
        const ns = clause.match(/\*\s+as\s+(\w+)/);
        if (ns) for (const u of text.matchAll(new RegExp(`\\b${ns[1]}\\.(\\w+)`, "g"))) names.add(u[1]);
        const named = clause.match(/\{([\s\S]*)\}/);
        if (named) {
          for (const part of named[1].split(",")) {
            const p = part.trim();
            if (p && !p.startsWith("type ")) names.add(p.split(/\s+as\s+/)[0].trim());
          }
        }
      }
      visit(target);
    }
  };
  entries.forEach(visit);

  // Wrapper exports: the invoke literals of each export a reachable file
  // uses, and of the exports those reference.
  for (const [wrapper, names] of used) {
    const chunks = new Map<string, string>();
    for (const chunk of SOURCES[wrapper].split(/\n(?=export )/)) {
      const m = chunk.match(/^export\s+(?:const|async function|function)\s+(\w+)/);
      if (m) chunks.set(m[1], chunk);
    }
    const queue = [...names];
    const done = new Set<string>();
    while (queue.length > 0) {
      const name = queue.pop()!;
      if (done.has(name)) continue;
      done.add(name);
      const body = chunks.get(name);
      if (body === undefined) continue; // a type, interface or constant
      for (const m of body.matchAll(INVOKE_RE)) commands.add(m[1]);
      const rest = body.slice(body.indexOf(name) + name.length);
      for (const other of chunks.keys()) {
        if (other !== name && new RegExp(`\\b${other}\\b`).test(rest)) queue.push(other);
      }
    }
  }
  return { files, bare, commands };
}

// ── The host's command sets ─────────────────────────────────────────────

const WINDOW_SETS: Map<string, string[]> = new Map(
  (JSON.parse(WINDOW_SETS_JSON) as { set: { identifier: string; permissions: string[] }[] }).set.map((s) => [
    s.identifier,
    s.permissions,
  ]),
);

/** The app commands a set grants, nested sets expanded. */
function granted(setId: string): Set<string> {
  const out = new Set<string>();
  const perms = WINDOW_SETS.get(setId);
  if (!perms) throw new Error(`no set ${setId} in window-sets.json`);
  for (const p of perms) {
    if (p.startsWith("allow-")) out.add(p.slice("allow-".length).replace(/-/g, "_"));
    else granted(p).forEach((c) => out.add(c));
  }
  return out;
}

const sorted = (s: Iterable<string>) => [...s].sort();

const ENTRY = "/src/sessionApp/main.tsx";
const SESSION_ROUTE_MODULES = [
  "/src/routes/SessionRdpWindow.tsx",
  "/src/routes/SessionReplayWindow.tsx",
  "/src/routes/SessionSshWindow.tsx",
  "/src/routes/SessionWorkspaceWindow.tsx",
];

// ── Tests ───────────────────────────────────────────────────────────────

describe("session.html route table", () => {
  it("mounts the four session routes and nothing else", () => {
    expect(sorted(SESSION_ROUTES.map((r) => r.path))).toEqual(
      sorted(["/session/ssh", "/session/rdp", "/workspace", "/session-replay"]),
    );
  });

  it.each(["/", "/connect", "/login", "/dashboard", "/secrets", "/resources", "/settings", "/policies", "/plugin/x/y"])(
    "renders no vault page at %s",
    (path) => {
      render(
        <MemoryRouter initialEntries={[path]}>
          <SessionRoutes />
        </MemoryRouter>,
      );
      expect(screen.getByText("This window shows sessions only.")).toBeInTheDocument();
    },
  );

  it("is the only place the session routes are mounted", () => {
    const app = SOURCES["/src/App.tsx"];
    expect(app).not.toMatch(/path="\/(session|workspace)/);
    expect(app).not.toMatch(/Session(Ssh|Rdp|Replay|Workspace)Window/);
  });
});

describe("session.html import graph", () => {
  const graph = walk([ENTRY]);

  it("reaches no vault page, auth store, ui barrel or app shell", () => {
    const routes = sorted([...graph.files].filter((f) => f.startsWith("/src/routes/")));
    expect(routes).toEqual(SESSION_ROUTE_MODULES);
    for (const banned of [
      "/src/App.tsx",
      "/src/main.tsx",
      "/src/stores/authStore.ts",
      "/src/stores/namespaceStore.ts",
      "/src/components/ui/index.ts",
      "/src/components/Layout.tsx",
      "/src/components/SessionMonitor.tsx",
      "/src/lib/changeWatcher.ts",
    ]) {
      expect(graph.files.has(banned), banned).toBe(false);
    }
  });

  it("never asks for the vault token or a login", () => {
    for (const command of ["get_current_token", "login_token", "remote_login_token", "token_status"]) {
      expect(graph.commands.has(command), command).toBe(false);
    }
  });

  it("uses no shell or dialog plugin", () => {
    expect([...graph.bare].filter((s) => s.startsWith("@tauri-apps/plugin-"))).toEqual([]);
  });

  it("can call nothing outside the session windows' command sets", () => {
    const allSets = new Set([
      ...granted("session-window"),
      ...granted("session-workspace"),
      ...granted("session-replay"),
    ]);
    expect(sorted([...graph.commands].filter((c) => !allSets.has(c)))).toEqual([]);
  });
});

describe("each session window's command set is exactly what its routes call", () => {
  it("own SSH / RDP windows: session-window", () => {
    const ssh = walk(["/src/routes/SessionSshWindow.tsx"]).commands;
    const rdp = walk(["/src/routes/SessionRdpWindow.tsx"]).commands;
    expect(sorted(new Set([...ssh, ...rdp]))).toEqual(sorted(granted("session-window")));
  });

  it("the Session Workspace (with its ⌘K palette): session-workspace", () => {
    const used = walk(["/src/routes/SessionWorkspaceWindow.tsx", "/src/components/ConnectPalette.tsx"]).commands;
    expect(sorted(used)).toEqual(sorted(granted("session-workspace")));
  });

  it("a recording replay: session-replay", () => {
    const used = walk(["/src/routes/SessionReplayWindow.tsx"]).commands;
    expect(sorted(used)).toEqual(sorted(granted("session-replay")));
  });

  it("the web session toolbar: web-chrome-toolbar", () => {
    // The toolbar (web-chrome.html) invokes through a passed-in function,
    // naming its commands in one table; it calls nothing else.
    const used = walk(["/src/webChrome/main.ts"]).commands;
    expect(sorted(used)).toEqual([]);
    expect(sorted(Object.values(WEB_CHROME_COMMANDS))).toEqual(sorted(granted("web-chrome-toolbar")));
  });
});
