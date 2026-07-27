import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { ExchangePage } from "../routes/ExchangePage";

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
// Isolate the page from the Layout chrome (nav/store effects).
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/exchange"]}>
      <ToastProvider>
        <ExchangePage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

/** The download path uses object URLs, which jsdom does not implement. */
function stubObjectUrls() {
  Object.defineProperty(URL, "createObjectURL", {
    writable: true,
    value: vi.fn(() => "blob:stub"),
  });
  Object.defineProperty(URL, "revokeObjectURL", { writable: true, value: vi.fn() });
}

describe("Exchange full-vault export", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    stubObjectUrls();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "exchange_export") {
        return Promise.resolve({ file_b64: "aGk=", size_bytes: 2, format: "bvx" });
      }
      // Root session with one child namespace, so the all-namespaces option
      // is offered. Individual tests override this for a child session.
      if (cmd === "get_active_namespace") return Promise.resolve("");
      if (cmd === "list_namespaces") {
        return Promise.resolve({ namespaces: ["engineering"] });
      }
      // Schedules tab and any incidental lookups.
      return Promise.resolve([]);
    });
  });

  it("sends scopeKind=full with no selectors, after confirmation", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.selectOptions(await screen.findByLabelText("What to export"), "full");
    expect(screen.getByLabelText("What to export")).toHaveValue("full");

    // The per-scope picker is replaced by the full-export warning.
    expect(screen.queryByText("+ Add scope")).not.toBeInTheDocument();
    expect(
      screen.getByText(/Full export — the vault's entire data plane/),
    ).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^Password/), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Export full vault & download" }));

    // First click only opens the confirm dialog — nothing exported yet.
    expect(mockInvoke).not.toHaveBeenCalledWith("exchange_export", expect.anything());
    await user.click(screen.getByRole("button", { name: "Export everything" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "exchange_export",
        expect.objectContaining({
          include: [],
          scopeKind: "full",
          format: "bvx",
          password: "correct-horse-battery",
          allowPlaintext: false,
        }),
      ),
    );
  });

  it("forces the encrypted .bvx format for full exports", async () => {
    const user = userEvent.setup();
    renderPage();

    // Plaintext JSON is selectable for a selective export…
    const formatSelect = screen.getByLabelText("Format") as HTMLSelectElement;
    await user.selectOptions(formatSelect, "json");
    expect(formatSelect.value).toBe("json");

    // …but switching to a full export snaps back to .bvx and locks the choice.
    await user.selectOptions(screen.getByLabelText("What to export"), "full");
    expect(formatSelect.value).toBe("bvx");
    expect(formatSelect.disabled).toBe(true);
    expect(formatSelect.querySelectorAll("option")).toHaveLength(1);
  });

  it("keeps selective exports on scopeKind=selective", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText(/^Password/), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Export & download" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "exchange_export",
        expect.objectContaining({
          scopeKind: "selective",
          include: [{ type: "kv_path", mount: "secret/", path: "" }],
        }),
      ),
    );
  });

  it("offers an all-namespaces export at the root namespace and sends it", async () => {
    const user = userEvent.setup();
    renderPage();

    const scopeSelect = await screen.findByLabelText("What to export");
    await waitFor(() =>
      expect(screen.getByRole("option", { name: /all namespaces/i })).toBeInTheDocument(),
    );

    await user.selectOptions(scopeSelect, "all_namespaces");
    expect(
      screen.getByText(/All-namespaces export — every tenant's data plane/),
    ).toBeInTheDocument();
    // The namespaces actually in scope are named, so the operator can see
    // what the file will hold before producing it.
    expect(screen.getByText(/root \+ engineering/)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^Password/), "correct-horse-battery");
    await user.click(
      screen.getByRole("button", { name: "Export all namespaces & download" }),
    );
    expect(mockInvoke).not.toHaveBeenCalledWith("exchange_export", expect.anything());
    await user.click(screen.getByRole("button", { name: "Export everything" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "exchange_export",
        expect.objectContaining({
          include: [],
          scopeKind: "all_namespaces",
          format: "bvx",
        }),
      ),
    );
  });

  it("hides the all-namespaces option inside a child namespace", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_active_namespace") return Promise.resolve("engineering");
      if (cmd === "exchange_export") {
        return Promise.resolve({ file_b64: "aGk=", size_bytes: 2, format: "bvx" });
      }
      return Promise.resolve([]);
    });
    renderPage();

    const scopeSelect = (await screen.findByLabelText(
      "What to export",
    )) as HTMLSelectElement;
    // Give the namespace lookup a chance to resolve before asserting absence.
    await waitFor(() => expect(scopeSelect.querySelectorAll("option")).toHaveLength(2));
    expect(
      screen.queryByRole("option", { name: /all namespaces/i }),
    ).not.toBeInTheDocument();
  });
});
