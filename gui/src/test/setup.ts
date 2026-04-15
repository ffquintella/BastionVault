import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// Mock Tauri invoke API globally so tests don't need a running Tauri backend.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("invoke not mocked for this call")),
}));
