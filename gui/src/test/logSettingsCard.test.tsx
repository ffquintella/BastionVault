import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { LogSettingsCard } from "../components/LogSettingsCard";
import { ToastProvider } from "../components/ui";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

const LEVELS = ["off", "error", "warn", "info", "debug", "trace"];
const settings = (over = {}) => ({
  level: "info",
  levels: LEVELS,
  path: "/home/u/Library/Logs/com.bastionvault.gui/bastion-vault-gui.log",
  env_override: false,
  ...over,
});

function renderCard() {
  return render(
    <ToastProvider>
      <LogSettingsCard />
    </ToastProvider>,
  );
}

describe("LogSettingsCard", () => {
  beforeEach(() => invoke.mockReset());

  it("shows the saved level and the log file", async () => {
    invoke.mockResolvedValue(settings());
    renderCard();
    expect(await screen.findByLabelText("Log level")).toHaveValue("info");
    expect(screen.getByText(/bastion-vault-gui\.log/)).toBeInTheDocument();
  });

  it("sends the chosen level and shows what the backend answered", async () => {
    invoke.mockImplementation(async (cmd: string, args?: { level: string }) =>
      cmd === "set_log_level" ? settings({ level: args?.level }) : settings(),
    );
    renderCard();
    await userEvent.selectOptions(await screen.findByLabelText("Log level"), "debug");
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("set_log_level", { level: "debug" }));
    await waitFor(() => expect(screen.getByLabelText("Log level")).toHaveValue("debug"));
  });

  it("disables the control and says why when RUST_LOG decides", async () => {
    invoke.mockResolvedValue(settings({ env_override: true }));
    renderCard();
    expect(await screen.findByLabelText("Log level")).toBeDisabled();
    expect(screen.getByText(/RUST_LOG environment variable/)).toBeInTheDocument();
  });

  it("says so when no file is written", async () => {
    invoke.mockResolvedValue(settings({ path: null }));
    renderCard();
    expect(await screen.findByText(/stderr only/)).toBeInTheDocument();
  });
});
