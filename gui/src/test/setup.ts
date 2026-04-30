import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// Mock Tauri invoke API globally so tests don't need a running Tauri backend.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("invoke not mocked for this call")),
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
