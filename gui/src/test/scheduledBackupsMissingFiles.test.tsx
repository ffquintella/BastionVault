/**
 * The Backups modal's empty state.
 *
 * The runner writes backup files to a directory on the *vault host*, and the
 * listing is a plain directory scan. When that directory is not on persistent
 * storage — the classic case being a path inside a container's ephemeral
 * writable layer, which is discarded on every recreate — the schedule survives
 * (it lives barrier-encrypted in the vault) but its files do not, and every
 * write succeeded at the time so nothing is logged as an error. The modal must
 * therefore distinguish "no run has produced a file yet" from "runs succeeded
 * and the files are gone", instead of showing the same benign empty state for
 * both.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { ExchangePage } from "../routes/ExchangePage";
import type { RunRecord, Schedule } from "../lib/api";

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
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const SCHEDULE: Schedule = {
  id: "0942a14b-588b-4d08-9c03-13630a970994",
  name: "daily",
  cron: "0 0 3 * * *",
  format: "bvx",
  scope: { kind: "full", include: [] },
  destination: { kind: "local_path", path: "/backups" },
  password_ref: { kind: "literal", password: "correct-horse-battery" },
  allow_plaintext: false,
  comment: null,
  created_at: "2026-07-20T12:00:00Z",
  updated_at: "2026-07-20T12:00:00Z",
  enabled: true,
};

const SUCCESSFUL_RUN: RunRecord = {
  schedule_id: SCHEDULE.id,
  run_at: "2026-07-27T17:35:48Z",
  status: "success",
  bytes_written: 44032,
  destination: SCHEDULE.destination,
  error: null,
};

/** Mount the page and open the Backups modal for the single schedule. */
async function openBackupsModal(runs: RunRecord[]) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "scheduled_exports_list") return Promise.resolve({ schedules: [SCHEDULE] });
    // The directory scan comes back empty: the files are not there.
    if (cmd === "scheduled_exports_backups_list") {
      return Promise.resolve({ dir: "/backups", files: [] });
    }
    if (cmd === "scheduled_exports_runs") return Promise.resolve({ runs });
    if (cmd === "get_active_namespace") return Promise.resolve("");
    if (cmd === "list_namespaces") return Promise.resolve({ namespaces: [] });
    return Promise.resolve([]);
  });

  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/exchange"]}>
      <ToastProvider>
        <ExchangePage />
      </ToastProvider>
    </MemoryRouter>,
  );

  await user.click(screen.getByRole("button", { name: "Scheduled backups" }));
  await user.click(await screen.findByRole("button", { name: "Backups" }));
  return user;
}

describe("Scheduled backups — missing backup files", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
  });

  it("warns when successful runs are on record but the directory is empty", async () => {
    await openBackupsModal([SUCCESSFUL_RUN]);

    expect(
      await screen.findByText(/1 successful run on record, but this directory is empty/),
    ).toBeInTheDocument();
    // The cause is named, because nothing in the logs points at it.
    expect(screen.getByText(/ephemeral writable layer/)).toBeInTheDocument();
    expect(screen.getByText("/var/lib/bvault/backups")).toBeInTheDocument();
    expect(screen.queryByText(/No backup files found/)).not.toBeInTheDocument();
  });

  it("keeps the benign empty state when no run has produced a file yet", async () => {
    await openBackupsModal([]);

    expect(await screen.findByText(/No backup files found/)).toBeInTheDocument();
    expect(screen.queryByText(/directory is empty/)).not.toBeInTheDocument();
  });

  it("does not warn when only failed runs are on record", async () => {
    await openBackupsModal([
      { ...SUCCESSFUL_RUN, status: "failed", bytes_written: 0, error: "boom" },
    ]);

    expect(await screen.findByText(/No backup files found/)).toBeInTheDocument();
    expect(screen.queryByText(/directory is empty/)).not.toBeInTheDocument();
  });
  it("shows which node holds a backup and still offers to restore it", async () => {
    // The nightly run was claimed by node 2, so node 1 has the catalog record
    // but not the bytes. The server fetches them on restore, so the row must
    // stay actionable — only the location is different.
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "scheduled_exports_list") return Promise.resolve({ schedules: [SCHEDULE] });
      if (cmd === "scheduled_exports_backups_list") {
        return Promise.resolve({
          dir: "/backups",
          files: [
            {
              name: "sched-20260727T163407Z.bvx",
              size_bytes: 43917,
              modified: "2026-07-27T16:34:07Z",
              format: "bvx",
              node_id: 2,
              node_name: "segdc1vhm0004",
              api_addr: "https://segdc1vhm0004.fgv.br:5200",
              local: false,
              present: true,
            },
            {
              name: "sched-20260727T173548Z.bvx",
              size_bytes: 43917,
              modified: "2026-07-27T17:35:48Z",
              format: "bvx",
              node_id: 1,
              node_name: "segdc1vhm0003",
              local: true,
              present: true,
            },
          ],
        });
      }
      if (cmd === "scheduled_exports_runs") return Promise.resolve({ runs: [SUCCESSFUL_RUN] });
      if (cmd === "get_active_namespace") return Promise.resolve("");
      if (cmd === "list_namespaces") return Promise.resolve({ namespaces: [] });
      return Promise.resolve([]);
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/exchange"]}>
        <ToastProvider>
          <ExchangePage />
        </ToastProvider>
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: "Scheduled backups" }));
    await user.click(await screen.findByRole("button", { name: "Backups" }));

    // Both nodes' backups appear, each labelled with where it lives.
    expect(await screen.findByText("segdc1vhm0004 (node 2)")).toBeInTheDocument();
    expect(screen.getByText("this node")).toBeInTheDocument();
    expect(screen.getByText(/fetched on restore/)).toBeInTheDocument();

    // A peer-held file is restorable from here — nothing is disabled.
    const restoreButtons = screen.getAllByRole("button", { name: "Restore" });
    expect(restoreButtons).toHaveLength(2);
    restoreButtons.forEach((b) => expect(b).not.toBeDisabled());
  });

  it("blocks restore for a catalogued file that has gone missing", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "scheduled_exports_list") return Promise.resolve({ schedules: [SCHEDULE] });
      if (cmd === "scheduled_exports_backups_list") {
        return Promise.resolve({
          dir: "/backups",
          files: [
            {
              name: "sched-20260727T163407Z.bvx",
              size_bytes: 43917,
              modified: "2026-07-27T16:34:07Z",
              format: "bvx",
              node_id: 1,
              node_name: "segdc1vhm0003",
              local: false,
              present: false,
            },
          ],
        });
      }
      if (cmd === "scheduled_exports_runs") return Promise.resolve({ runs: [SUCCESSFUL_RUN] });
      if (cmd === "get_active_namespace") return Promise.resolve("");
      if (cmd === "list_namespaces") return Promise.resolve({ namespaces: [] });
      return Promise.resolve([]);
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/exchange"]}>
        <ToastProvider>
          <ExchangePage />
        </ToastProvider>
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: "Scheduled backups" }));
    await user.click(await screen.findByRole("button", { name: "Backups" }));

    expect(await screen.findByText(/file missing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restore" })).toBeDisabled();
  });
});
