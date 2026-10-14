import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { ResourceTypesCard } from "../components/ResourceTypesCard";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const rootWebsite = {
  website: { id: "website", label: "Root Website", color: "success", fields: [], connect: { web_exposure_max: "dom" } },
};

function mockEffective(effective: unknown) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "resource_types_read_effective") return Promise.resolve(effective);
    if (cmd === "resource_types_write") return Promise.resolve();
    // Unrelated environment calls (e.g. listeners) resolve empty.
    return Promise.resolve(null);
  });
}

function renderCard(inNamespace: boolean) {
  return render(
    <ToastProvider>
      <ResourceTypesCard inNamespace={inNamespace} />
    </ToastProvider>,
  );
}

describe("ResourceTypesCard", () => {
  beforeEach(() => mockInvoke.mockReset());

  it("shows a namespace inheriting the root's saved types, and saving makes them the namespace's own", async () => {
    mockEffective({ source: "root", types: rootWebsite });
    renderCard(true);
    expect(await screen.findByTestId("type-config-source-root")).toBeInTheDocument();
    // The root's saved definition is what is shown, not the builtin.
    expect(screen.getByText("Root Website")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Reset to Defaults" }));
    await waitFor(() =>
      expect(mockInvoke.mock.calls.some(([cmd]) => cmd === "resource_types_write")).toBe(true),
    );
    await waitFor(() => expect(screen.queryByTestId("type-config-source-root")).not.toBeInTheDocument());
  });

  it("warns that unsaved builtins are not enforced", async () => {
    mockEffective({ source: "none", types: null });
    renderCard(true);
    const notice = await screen.findByTestId("type-config-source-none");
    expect(notice.textContent).toMatch(/not enforce/);
    expect(notice.textContent).toMatch(/root namespace/);
  });

  it("shows no notice when the mount has its own saved types", async () => {
    mockEffective({ source: "mount", types: rootWebsite });
    renderCard(false);
    expect(await screen.findByText("Root Website")).toBeInTheDocument();
    expect(screen.queryByTestId(/type-config-source-/)).not.toBeInTheDocument();
  });
});
