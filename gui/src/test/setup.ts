import "@testing-library/jest-dom/vitest";
import { beforeEach, vi } from "vitest";
import { clearCache } from "../lib/cache";

// The read cache is module-global by design — one vault session per process.
// Under vitest that makes it shared state between tests in a file: a page
// rendered in one test would serve the next test the listing it cached.
// Reset it before every test so no individual test has to remember to.
//
// Only `lib/cache` is imported here, deliberately. It has no dependencies;
// `lib/changeWatcher` pulls in `lib/api` and therefore
// `@tauri-apps/api/core`, and importing that from the setup file binds it
// before a test file's own `vi.mock` of that module can take effect — which
// breaks every suite that mocks `invoke` itself. The watcher's own test
// resets it directly, and a component's subscription dies with its unmount.
//
// The block body is deliberate: an arrow returning a value here would be
// taken as a cleanup hook.
beforeEach(() => {
  clearCache();
});

// Mock Tauri invoke API globally so tests don't need a running Tauri backend.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("invoke not mocked for this call")),
}));

// Tauri event API — components (e.g. Layout's `plugin-menus-updated`
// listener) subscribe via `listen()`. Outside a Tauri shell the real
// impl reaches for an IPC bridge that isn't there, so hand back a stub
// whose `listen` resolves to a no-op unlisten. Individual tests that
// assert on events still override this with their own `vi.mock`.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
  emit: vi.fn().mockResolvedValue(undefined),
}));

// Tauri window API — pages that mount the custom TitleBar pull
// `getCurrentWindow()` from this module. Vitest doesn't run inside
// a Tauri shell, so we hand back a stub whose methods resolve to
// inert defaults; the components only consume them in effects.
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    isFullscreen: async () => false,
    setFullscreen: async () => undefined,
    isMaximized: async () => false,
    toggleMaximize: async () => undefined,
    minimize: async () => undefined,
    close: async () => undefined,
    onResized: async () => () => undefined,
  }),
}));
