/**
 * Leases page (T62, features/dynamic-secrets.md Phase 5): revoke-failed
 * listing, confirmed force-clear, 403 messages, renew only when renewable.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { LeasesPage } from "../routes/LeasesPage";
import { useLeaseStore } from "../stores/leaseStore";

const FAILED = {
  lease_id: "database/creds/ro/0f3c",
  path: "database/creds/ro",
  issue_time: "2026-10-26T09:00:00Z",
  expire_time: "2020-01-01T00:00:00Z",
  attempts: 3,
  max_attempts: 6,
  exhausted: false,
  first_failed_at: "2026-10-26T10:00:01Z",
  last_failed_at: "2026-10-26T10:01:00Z",
  next_attempt_at: new Date(Date.now() + 40_000).toISOString(),
  last_error: "connection refused",
  origin: "expiry",
};

function setup(overrides: Record<string, (args?: unknown) => Promise<unknown>> = {}) {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "leases_list_revoke_failed":
        return Promise.resolve([FAILED]);
      case "leases_renew":
        return Promise.resolve({ lease_id: "a", lease_duration: 600, renewable: true });
      default:
        return Promise.resolve(null);
    }
  });
}

function renderPage() {
  return render(
    <MemoryRouter>
      <LeasesPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockInvoke.mockReset();
  useLeaseStore.getState().clear();
});

describe("LeasesPage", () => {
  it("lists revoke-failed leases with attempts, last error and next retry", async () => {
    setup();
    renderPage();
    expect(await screen.findByText("database/creds/ro/0f3c")).toBeInTheDocument();
    expect(screen.getByText("3 / 6")).toBeInTheDocument();
    expect(screen.getByText("connection refused")).toBeInTheDocument();
    expect(screen.getByText(/^in \d+s$/)).toBeInTheDocument();
    expect(screen.getByText("expired")).toBeInTheDocument();
    expect(mockInvoke).toHaveBeenCalledWith("leases_list_revoke_failed", undefined);
  });

  it("explains the sudo requirement when the listing is refused", async () => {
    setup({ leases_list_revoke_failed: () => Promise.reject({ message: "HTTP 403: permission denied" }) });
    renderPage();
    expect(await screen.findByTestId("revoke-failed-error")).toHaveTextContent(/needs sudo/);
  });

  it("force-clears only after the operator confirms the manual cleanup", async () => {
    setup();
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Force-clear" }));
    expect(screen.getByText(/WITHOUT revoking its credential/)).toBeInTheDocument();
    const dialogButtons = screen.getAllByRole("button", { name: "Force-clear" });
    const confirm = dialogButtons[dialogButtons.length - 1];
    expect(confirm).toBeDisabled();
    await userEvent.type(screen.getByPlaceholderText("force-clear"), "force-clear");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("leases_force_clear_revoke_failed", {
        leaseId: "database/creds/ro/0f3c",
      }),
    );
  });

  it("shows which capability a refused force-clear needed", async () => {
    setup({
      leases_force_clear_revoke_failed: () => Promise.reject({ message: "HTTP 403: permission denied" }),
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Force-clear" }));
    await userEvent.type(screen.getByPlaceholderText("force-clear"), "force-clear");
    const buttons = screen.getAllByRole("button", { name: "Force-clear" });
    await userEvent.click(buttons[buttons.length - 1]);
    const alerts = await screen.findAllByText(/Force-clear was refused/);
    expect(alerts[0]).toHaveTextContent("`delete` with `sudo`");
  });

  it("offers renew only for renewable leases and warns it may be refused", async () => {
    setup({ leases_list_revoke_failed: () => Promise.resolve([]) });
    const now = Date.now();
    useLeaseStore.getState().record({
      lease_id: "db/creds/ro/renewable", mount: "db/", role: "ro", since: now,
      lease_duration: 3600, renewable: true, shared: false,
    });
    useLeaseStore.getState().record({
      lease_id: "db/creds/ro/fixed", mount: "db/", role: "ro", since: now,
      lease_duration: 3600, renewable: false, shared: false,
    });
    renderPage();
    const fixedRow = (await screen.findByText("db/creds/ro/fixed")).closest("tr")!;
    expect(within(fixedRow).getByRole("button", { name: "Renew" })).toBeDisabled();
    const renewableRow = screen.getByText("db/creds/ro/renewable").closest("tr")!;
    const renew = within(renewableRow).getByRole("button", { name: "Renew" });
    expect(renew).toBeEnabled();
    expect(screen.getAllByText(/Renew may be refused/).length).toBeGreaterThan(0);
    await userEvent.click(renew);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("leases_renew", {
        leaseId: "db/creds/ro/renewable",
        increment: null,
      }),
    );
  });

  it("revokes an issued lease after confirmation and forgets it", async () => {
    setup({ leases_list_revoke_failed: () => Promise.resolve([]) });
    useLeaseStore.getState().record({
      lease_id: "db/creds/ro/gone", mount: "db/", role: "ro", since: Date.now(),
      lease_duration: 60, renewable: false, shared: true,
    });
    renderPage();
    const row = (await screen.findByText("db/creds/ro/gone")).closest("tr")!;
    expect(within(row).getByText("shared")).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Revoke" }));
    const buttons = screen.getAllByRole("button", { name: "Revoke" });
    await userEvent.click(buttons[buttons.length - 1]);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("leases_revoke", { leaseId: "db/creds/ro/gone" }),
    );
    await waitFor(() => expect(screen.queryByText("db/creds/ro/gone")).not.toBeInTheDocument());
  });
});
