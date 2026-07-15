import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { DosProtectionPanel } from "../components/DosProtectionPanel";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const CONFIG = {
  enabled: true,
  window_secs: 10,
  max_requests: 200,
  auth_max_requests: 20,
  ban_secs: 300,
  refresh_secs: 30,
};

function stats(overrides: Record<string, unknown> = {}) {
  return {
    config: CONFIG,
    tracked: [
      { ip: "203.0.113.7", requests: 5, auth_requests: 1, window_secs: 10 },
    ],
    bans: [
      { ip: "198.51.100.9", kind: "manual", reason: "operator block", expires_in_secs: 250, until_unix: 1 },
    ],
    ...overrides,
  };
}

function renderPanel() {
  return render(
    <ToastProvider>
      <DosProtectionPanel />
    </ToastProvider>,
  );
}

describe("DosProtectionPanel", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "get_dos_config":
          return Promise.resolve(CONFIG);
        case "get_dos_stats":
          return Promise.resolve(stats());
        case "ban_ip":
          return Promise.resolve({ banned: true });
        case "unban_ip":
          return Promise.resolve({ unbanned: true });
        case "set_dos_config":
          return Promise.resolve(CONFIG);
        default:
          return Promise.resolve(null);
      }
    });
  });

  it("renders tracked IPs and active bans", async () => {
    renderPanel();
    await waitFor(() => expect(screen.getByText("203.0.113.7")).toBeInTheDocument());
    expect(screen.getByText("198.51.100.9")).toBeInTheDocument();
    // The manual ban shows an Unban action.
    expect(screen.getByRole("button", { name: "Unban" })).toBeInTheDocument();
  });

  it("unbans an IP via the confirm dialog", async () => {
    const user = userEvent.setup();
    renderPanel();
    await waitFor(() => expect(screen.getByText("198.51.100.9")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Unban" }));
    // Confirm dialog → confirm.
    const dialog = await screen.findByText(/Remove the ban on 198\.51\.100\.9/);
    expect(dialog).toBeInTheDocument();
    const confirmBtn = screen.getAllByRole("button", { name: "Unban" }).pop()!;
    await user.click(confirmBtn);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("unban_ip", { ip: "198.51.100.9" }),
    );
  });

  it("bans a tracked IP through the modal", async () => {
    const user = userEvent.setup();
    renderPanel();
    await waitFor(() => expect(screen.getByText("203.0.113.7")).toBeInTheDocument());

    // The tracked (unbanned) IP row has a Ban button.
    await user.click(screen.getByRole("button", { name: "Ban" }));
    // Modal opens with the IP prefilled; submit.
    const modalBanBtn = screen.getAllByRole("button", { name: "Ban" }).pop()!;
    await user.click(modalBanBtn);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "ban_ip",
        expect.objectContaining({ ip: "203.0.113.7" }),
      ),
    );
  });

  it("saves edited thresholds", async () => {
    const user = userEvent.setup();
    renderPanel();
    await waitFor(() => expect(screen.getByText("Abuse-Protection Thresholds")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Edit" }));
    const maxReq = screen.getByLabelText("Max requests / window");
    await user.clear(maxReq);
    await user.type(maxReq, "50");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "set_dos_config",
        expect.objectContaining({ config: expect.objectContaining({ max_requests: 50 }) }),
      ),
    );
  });
});
