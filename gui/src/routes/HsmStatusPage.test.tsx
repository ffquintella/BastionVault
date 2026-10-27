/**
 * HSM / Seal page (features/hsm-pool-ha.md, "API, CLI and GUI"): the pool
 * sections render from the phase 6 status fields and stay absent for the
 * per-node topology. The page is read-only; ceremonies stay CLI-only.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { HsmStatusPage } from "./HsmStatusPage";

const BASE = {
  type: "hsm",
  auto_unseal: true,
  backend: "mock",
  node_id: "node-a",
  sealed: false,
  initialized: true,
  cluster_uuid: "11111111-2222-3333-4444-555555555555",
  epoch: 3,
};

const POOL = {
  ...BASE,
  topology: "pool",
  seal_record_version: 2,
  min_wrap_copies: 2,
  under_replicated_sets: 1,
  kek_under_replicated: false,
  members: [
    {
      name: "hsm-1",
      hsm_id: "hsm-id-1",
      serial: "1000001",
      state: "active",
      up: true,
      faulted: false,
      prefer: true,
      holds_kek_copy: true,
      last_error: null,
      latency_ms: 42,
      pending_revocations: [],
    },
    {
      name: "hsm-2",
      hsm_id: "hsm-id-2",
      serial: "1000002",
      state: "faulted",
      up: false,
      faulted: true,
      prefer: false,
      holds_kek_copy: false,
      last_error: "device unreachable: connection timed out",
      pending_revocations: ["node-b"],
    },
  ],
  pending_revocations: [{ member: "hsm-2", node: "node-b" }],
  repair: {
    repair_rate: 5,
    interval_secs: 300,
    last_run: {
      started_at: 1_790_000_000,
      finished_at: 1_790_000_010,
      sets_scanned: 42,
      copies_added: 3,
      copies_removed: 1,
      recovery_copies_added: 2,
      under_replicated: 1,
      failures: ["hsm-2: wrap copy failed"],
      ready_to_promote: ["hsm-3"],
      promoted: [],
      revocations_pending: ["hsm-2"],
      auditors_installed: ["hsm-1"],
      custody_scanned: true,
    },
  },
  device_audit: {
    mode: "drain",
    interval_secs: 5,
    members: [
      {
        name: "hsm-1",
        hsm_id: "hsm-id-1",
        enrolled: true,
        last_index: 128,
        last_drain_at: 1_790_000_100,
        drained_by: "node-a",
        entries_drained: 77,
        gaps: 1,
        last_error: null,
      },
      {
        name: "hsm-2",
        hsm_id: "hsm-id-2",
        enrolled: false,
        last_index: null,
        last_drain_at: null,
        entries_drained: 0,
        gaps: 0,
        last_error: null,
      },
      {
        name: "hsm-3",
        hsm_id: "hsm-id-3",
        enrolled: null,
        entries_drained: 0,
        gaps: 0,
        last_error: null,
      },
    ],
  },
  recovery_configured: true,
  recovery_fingerprint: "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
  recovery_threshold: 3,
  recovery_shares: 5,
  kek_recovery_copy: true,
  recovery_progress: 2,
};

const PER_NODE = { ...BASE, topology: "per-node", recovery: "none" };

function renderPage() {
  return render(
    <MemoryRouter>
      <HsmStatusPage />
    </MemoryRouter>,
  );
}

function serve(status: unknown) {
  mockInvoke.mockImplementation((cmd: string) =>
    cmd === "hsm_status" ? Promise.resolve(status) : Promise.resolve(null),
  );
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("HsmStatusPage pool topology", () => {
  beforeEach(() => serve(POOL));

  it("shows the under-replicated warning banner", async () => {
    renderPage();
    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent("1 wrapped set is under-replicated");
    expect(banner.className).toContain("yellow");
  });

  it("renders the members table with the down member's error", async () => {
    renderPage();
    await screen.findByText("Pool Members");
    const table = within(screen.getByRole("table"));
    expect(table.getByText("hsm-1")).toBeInTheDocument();
    expect(table.getByText("faulted")).toBeInTheDocument();
    expect(table.getByText("Down")).toBeInTheDocument();
    expect(table.getByText("1 pending")).toBeInTheDocument();
    expect(table.getByText("42 ms")).toBeInTheDocument();
    const err = table.getByText("device unreachable: connection timed out");
    expect(err).toHaveAttribute("title", "device unreachable: connection timed out");
    expect(err.className).toContain("truncate");
  });

  it("lists the pending revocation with the treated-as-down warning", async () => {
    renderPage();
    await screen.findByText("Pending Revocations", { selector: "h3" });
    expect(screen.getByText("node-b", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText(/treats these members as down until the revocation is applied/)).toBeInTheDocument();
  });

  it("renders the repair card with its failure", async () => {
    renderPage();
    await screen.findByText("Repair", { selector: "h3" });
    expect(screen.getByText("Sets Scanned")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("hsm-2: wrap copy failed")).toBeInTheDocument();
    expect(screen.getByText("Auditor Keys Installed")).toBeInTheDocument();
  });

  it("highlights device-audit gaps and says how to install a missing auditor key", async () => {
    renderPage();
    await screen.findByText("Device Audit", { selector: "h3" });
    const gap = screen.getByText("1 gap");
    expect(gap.className).toContain("yellow");
    expect(screen.getByText("No auditor key")).toBeInTheDocument();
    expect(screen.getByText("bvault operator hsm repair --run --admin hsm-2")).toBeInTheDocument();
    expect(screen.getByText("Not drained yet")).toBeInTheDocument();
    expect(screen.getByText("Drained By")).toBeInTheDocument();
  });

  it("renders the recovery card with threshold and ceremony progress", async () => {
    renderPage();
    await screen.findByText("Recovery", { selector: "h3" });
    expect(screen.getByText("3 of 5 shares")).toBeInTheDocument();
    expect(screen.getByText("Present")).toBeInTheDocument();
    expect(screen.getByText(/In progress \(2 shares held\)/)).toBeInTheDocument();
    expect(screen.getByText(POOL.recovery_fingerprint)).toHaveAttribute(
      "title",
      POOL.recovery_fingerprint,
    );
  });

  it("does not crash when the pool fields are missing", async () => {
    serve({ ...BASE, topology: "pool" });
    renderPage();
    await screen.findByText("Pool Members");
    expect(screen.getByText("No pool members reported")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("HsmStatusPage pool redundancy", () => {
  const CLEAN = { ...BASE, topology: "pool", under_replicated_sets: 0, members: [] };
  const WARNING =
    "pool of one device: losing that device loses the vault until the second device is added";

  it("shows no banner when redundancy is full", async () => {
    serve({ ...CLEAN, redundancy: "full", members_active: 2, members_expected: 2, redundancy_warning: null });
    renderPage();
    await screen.findByText("Pool Replication");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Full")).toBeInTheDocument();
    expect(screen.getByText("2 of 2")).toBeInTheDocument();
  });

  it("shows a warning banner with the text and counts when redundancy is none", async () => {
    serve({ ...CLEAN, redundancy: "none", members_active: 1, members_expected: 2, redundancy_warning: WARNING });
    renderPage();
    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent(WARNING);
    expect(banner).toHaveTextContent("Active members: 1 of 2");
    expect(banner.className).toContain("yellow");
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    expect(screen.getByText("None")).toBeInTheDocument();
  });

  it("renders without a banner or a crash when the fields are absent (older server)", async () => {
    serve({ ...CLEAN });
    renderPage();
    await screen.findByText("Pool Replication");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("Redundancy")).not.toBeInTheDocument();
    expect(screen.queryByText("Active Members")).not.toBeInTheDocument();
  });
});

describe("HsmStatusPage per-node topology", () => {
  it("keeps the existing cards and renders no pool sections", async () => {
    serve(PER_NODE);
    renderPage();
    await waitFor(() => expect(screen.getByText("Cluster Key Custody")).toBeInTheDocument());
    expect(screen.getByText("HSM Device")).toBeInTheDocument();
    expect(screen.queryByText("Pool Members")).not.toBeInTheDocument();
    expect(screen.queryByText("Pool Replication")).not.toBeInTheDocument();
    expect(screen.queryByText("Device Audit")).not.toBeInTheDocument();
    expect(screen.queryByText("Repair")).not.toBeInTheDocument();
    expect(screen.queryByText("Recovery")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
