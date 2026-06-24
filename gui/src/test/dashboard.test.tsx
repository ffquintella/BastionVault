import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { bucketByHour } from "../components/dashboard/SessionActivityChart";
import { KpiTile } from "../components/dashboard/KpiTile";
import { AttentionPanel } from "../components/dashboard/AttentionPanel";
import { isAdminUser } from "../lib/access";
import type { RustionTargetHealth } from "../lib/rustion";

// Mock the Tauri invoke API at the module level (same pattern as
// pages.test.tsx) so UserDashboard's `list_shares_for_me` call resolves.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const wrap = (ui: React.ReactNode) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe("bucketByHour", () => {
  const now = Date.parse("2026-06-18T12:00:00Z");

  it("returns 24 buckets", () => {
    expect(bucketByHour([], now)).toHaveLength(24);
  });

  it("ignores events outside the 24h window", () => {
    const events = [
      { ts: "2026-06-17T11:00:00Z" }, // 25h ago — out
      { ts: "2026-06-19T00:00:00Z" }, // future — out
    ];
    expect(bucketByHour(events, now).reduce((a, b) => a + b, 0)).toBe(0);
  });

  it("places the most recent event in the last bucket", () => {
    const buckets = bucketByHour([{ ts: "2026-06-18T11:30:00Z" }], now);
    expect(buckets[23]).toBe(1);
    expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
  });

  it("tallies multiple events in the same hour", () => {
    const events = [
      { ts: "2026-06-18T11:10:00Z" },
      { ts: "2026-06-18T11:50:00Z" },
    ];
    expect(bucketByHour(events, now)[23]).toBe(2);
  });

  it("ignores malformed timestamps", () => {
    expect(bucketByHour([{ ts: "not-a-date" }], now).reduce((a, b) => a + b, 0)).toBe(0);
  });
});

describe("KpiTile", () => {
  it("renders an em-dash and hint when value is null", () => {
    wrap(<KpiTile label="Live sessions" value={null} unavailableHint="no bastion" />);
    expect(screen.getByText("—")).toBeTruthy();
    expect(screen.getByText("no bastion")).toBeTruthy();
  });

  it("renders the value and sub-line when present", () => {
    wrap(<KpiTile label="Policies" value={14} sub="2 new" />);
    expect(screen.getByText("14")).toBeTruthy();
    expect(screen.getByText("2 new")).toBeTruthy();
  });
});

describe("AttentionPanel", () => {
  const h = (status: RustionTargetHealth["status"]): RustionTargetHealth => ({
    id: "t1",
    name: "t1",
    endpoint: "",
    enabled: true,
    status,
    last_ok_at: "",
    last_error: "",
    latency_ms_p50: 0,
    consecutive_failures: 0,
    version: "",
    active_sessions: 0,
    updated_at: "",
  });

  it("shows all-clear when nothing is wrong", () => {
    wrap(<AttentionPanel sealed={false} health={[h("up")]} />);
    expect(screen.getByText(/All clear/i)).toBeTruthy();
  });

  it("flags a sealed vault", () => {
    wrap(<AttentionPanel sealed={true} health={null} />);
    expect(screen.getByText(/Vault is sealed/i)).toBeTruthy();
  });

  it("flags down and degraded bastions", () => {
    wrap(<AttentionPanel sealed={false} health={[h("down"), h("degraded")]} />);
    expect(screen.getByText(/1 bastion down/i)).toBeTruthy();
    expect(screen.getByText(/1 bastion degraded/i)).toBeTruthy();
  });

  it("flags audit-write failures and failed logins from the stats aggregator", () => {
    wrap(
      <AttentionPanel
        sealed={false}
        health={[h("up")]}
        auditWriteFailures={2}
        failedLogins1h={5}
      />,
    );
    expect(screen.getByText(/2 audit-write failures/i)).toBeTruthy();
    expect(screen.getByText(/5 failed logins/i)).toBeTruthy();
  });

  it("stays all-clear when stats counters are zero", () => {
    wrap(
      <AttentionPanel sealed={false} health={[h("up")]} auditWriteFailures={0} failedLogins1h={0} />,
    );
    expect(screen.getByText(/All clear/i)).toBeTruthy();
  });
});

describe("isAdminUser", () => {
  it("treats a plain default user as non-admin", () => {
    expect(isAdminUser(["default"])).toBe(false);
    expect(isAdminUser([])).toBe(false);
    expect(isAdminUser(["pki-user", "default"])).toBe(false);
  });

  it("recognizes super-admin keywords and delegated admin policies", () => {
    for (const p of ["root", "admin", "administrator", "super-admin"]) {
      expect(isAdminUser([p])).toBe(true);
    }
    expect(isAdminUser(["exchange-admin"])).toBe(true);
    expect(isAdminUser(["plugin-admin"])).toBe(true);
    expect(isAdminUser(["default", "admin"])).toBe(true);
  });
});

describe("UserDashboard (cropped non-admin view)", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("renders the shares scoped to the user with working Open links", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_shares_for_me") {
        return Promise.resolve({
          entity_id: "entity-felipe2",
          group_shared_resources: false,
          entries: [
            { target_kind: "resource", target_path: "apldc1vds0045.fgv.br", grantee_kind: "entity" },
            { target_kind: "kv-secret", target_path: "team/db", grantee_kind: "entity" },
          ],
        });
      }
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });

    const { UserDashboard } = await import("../components/dashboard/UserDashboard");
    wrap(<UserDashboard />);

    await waitFor(() =>
      expect(screen.getByText("apldc1vds0045.fgv.br")).toBeInTheDocument(),
    );
    expect(screen.getByText("team/db")).toBeInTheDocument();

    const hrefs = screen
      .getAllByRole("link", { name: "Open" })
      .map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("/resources/apldc1vds0045.fgv.br");
    expect(hrefs).toContain("/secrets/team/db");

    // Cropped view: none of the operator-only KPIs appear.
    expect(screen.queryByText("Secret engines")).not.toBeInTheDocument();
    expect(screen.queryByText("Identities")).not.toBeInTheDocument();
    expect(screen.queryByText("Seal Vault")).not.toBeInTheDocument();
    // "Shared with me" shows as both the KPI tile label and the card header.
    expect(screen.getAllByText("Shared with me").length).toBeGreaterThan(0);
  });

  it("shows an empty state when nothing is shared", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_shares_for_me") {
        return Promise.resolve({ entity_id: "x", group_shared_resources: false, entries: [] });
      }
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });

    const { UserDashboard } = await import("../components/dashboard/UserDashboard");
    wrap(<UserDashboard />);

    await waitFor(() =>
      expect(
        screen.getByText("Nothing has been shared with you yet."),
      ).toBeInTheDocument(),
    );
  });
});
