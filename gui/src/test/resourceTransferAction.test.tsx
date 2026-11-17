/**
 * The Info tab's "Copy / Move to namespace" button (T496/T501): always
 * offered when another namespace exists, with a hint for a read-only viewer
 * that a move needs delete rights on the source.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
}));

function mockVault() {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "resource_types_read_effective":
        return Promise.resolve({ source: "none", types: null });
      case "list_asset_groups":
      case "asset_groups_for_resource":
        return Promise.resolve({ groups: [] });
      case "search_resources":
        return Promise.resolve({ items: [{ name: "web01", type: "server", hostname: "web01.example.net" }], total: 1, has_more: false });
      case "read_resource":
        return Promise.resolve({ name: "web01", type: "server", hostname: "web01.example.net" });
      case "list_shares_for_target":
      case "list_entity_aliases":
        return Promise.resolve([]);
      case "list_resource_secrets":
        return Promise.resolve({ keys: [] });
      case "get_resource_owner":
        return Promise.resolve({ owned: false });
      case "capabilities_self":
        return Promise.resolve({ paths: {} });
      default:
        return Promise.resolve(null);
    }
  });
}

async function openInfo() {
  const { ResourcesPage } = await import("../routes/ResourcesPage");
  render(
    <MemoryRouter>
      <ToastProvider>
        <ResourcesPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await userEvent.click(await screen.findByText("web01"));
  return screen.findByRole("button", { name: "Copy / Move to namespace" });
}

beforeEach(() => {
  mockInvoke.mockReset();
  mockVault();
  useNamespaceStore.setState({ namespaces: ["", "team-a"], active: "", loaded: true });
});

describe("Info tab Copy / Move to namespace", () => {
  it("tells a read-only viewer that moving needs delete rights, without disabling Copy", async () => {
    useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["resource-user"], entityId: "entity-1" });
    const button = await openInfo();
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit" })).toBeDisabled());
    expect(button).toBeEnabled();
    expect(button.getAttribute("title")).toMatch(/moving .*delete/i);
  });

  it("adds no hint for a viewer who can write", async () => {
    useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "entity-1" });
    const button = await openInfo();
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit" })).toBeEnabled());
    expect(button).toBeEnabled();
    expect(button).not.toHaveAttribute("title");
  });

  it("is disabled with a reason when no other namespace is available", async () => {
    useNamespaceStore.setState({ namespaces: [""], active: "", loaded: true });
    useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "entity-1" });
    const button = await openInfo();
    expect(button).toBeDisabled();
    expect(button.getAttribute("title")).toMatch(/No other namespace/);
  });
});
