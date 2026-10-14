import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { SessionActivityChart, formatUpdatedAgo } from "../components/dashboard/SessionActivityChart";
import { RecentAuditCard } from "../components/dashboard/RecentAuditCard";
import { KpiTile } from "../components/dashboard/KpiTile";
import { AttentionPanel } from "../components/dashboard/AttentionPanel";
import { isAdminUser } from "../lib/access";
import type { RustionTargetHealth } from "../lib/rustion";
import { useAuthStore } from "../stores/authStore";

// Mock the Tauri invoke API at the module level (same pattern as
// pages.test.tsx) so UserDashboard's `list_shares_for_me` call resolves.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

// The Dashboard page test renders the page body only; the app shell is not
// under test here.
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const wrap = (ui: React.ReactNode) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe("formatUpdatedAgo", () => {
  const now = Date.parse("2026-06-18T12:00:00Z");

  it("labels the age of the precomputed statistics", () => {
    expect(formatUpdatedAgo("2026-06-18T11:59:30Z", now)).toBe("updated just now");
    expect(formatUpdatedAgo("2026-06-18T11:53:00Z", now)).toBe("updated 7 min ago");
    expect(formatUpdatedAgo("2026-06-18T09:00:00+00:00", now)).toBe("updated 3 h ago");
    expect(formatUpdatedAgo("2026-06-16T12:00:00Z", now)).toBe("updated 2 d ago");
  });

  it("returns null for a missing or malformed timestamp", () => {
    expect(formatUpdatedAgo(null, now)).toBeNull();
    expect(formatUpdatedAgo("", now)).toBeNull();
    expect(formatUpdatedAgo("not-a-date", now)).toBeNull();
  });
});

describe("SessionActivityChart", () => {
  const now = Date.parse("2026-06-18T12:00:00Z");
  const buckets = Array.from({ length: 24 }, (_, i) => (i === 23 ? 5 : i === 0 ? 1 : 0));

  it("draws the server's hourly buckets and their freshness", () => {
    wrap(<SessionActivityChart buckets={buckets} computedAt="2026-06-18T11:57:00Z" nowMs={now} />);
    expect(screen.getByRole("img", { name: "6 audit events over the last 24 hours" })).toBeInTheDocument();
    expect(screen.getByText(/peak 5 · updated 3 min ago/)).toBeInTheDocument();
  });

  it("says the statistics are being computed while pending", () => {
    wrap(<SessionActivityChart buckets={null} pending nowMs={now} />);
    expect(screen.getByText(/Statistics are being computed/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("distinguishes unavailable from an idle day", () => {
    const { unmount } = wrap(<SessionActivityChart buckets={null} nowMs={now} />);
    expect(screen.getByText("Activity unavailable")).toBeInTheDocument();
    unmount();
    wrap(<SessionActivityChart buckets={new Array(24).fill(0)} computedAt="2026-06-18T11:59:00Z" nowMs={now} />);
    expect(screen.getByText("No activity in the last 24 hours")).toBeInTheDocument();
  });
});

describe("RecentAuditCard", () => {
  it("shows the pending state instead of an empty list", () => {
    wrap(<RecentAuditCard events={[]} pending nowMs={Date.now()} />);
    expect(screen.getByText(/Statistics are being computed/)).toBeInTheDocument();
    expect(screen.queryByText("No recent activity.")).not.toBeInTheDocument();
  });
});

describe("DashboardPage (admin) — consolidated summary", () => {
  const nowIso = new Date(Date.now() - 4 * 60_000).toISOString();
  const readySummary = {
    version: "1",
    namespace: "",
    seal: { sealed: false, initialized: true },
    counts: { secret_mounts: 3, auth_mounts: 2, policies: 7, entities: 11 },
    audit_24h_total: 4242,
    audit_24h_denied: 0,
    audit_24h_write_failures: 0,
    failed_logins_1h: 0,
    audit_stats: {
      state: "ready",
      reason: null,
      computed_at: nowIso,
      stale: false,
      partial: false,
      failed_sources: [],
      histogram_24h: Array.from({ length: 24 }, (_, i) => (i === 23 ? 4242 : 0)),
      recent: [
        {
          ts: nowIso,
          user: "alice",
          op: "read",
          category: "access",
          target: "secret/data/from-the-summary",
          changed_fields: [],
          summary: "",
        },
      ],
    },
  };

  function mockCommands(summary: unknown) {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "get_vault_status":
          return Promise.resolve({ initialized: true, sealed: false, has_vault: true });
        case "dashboard_summary":
          return Promise.resolve(summary);
        case "get_server_info":
          return Promise.resolve({
            connection_kind: "embedded",
            endpoint: "",
            version: "0.0.0",
            started_at: "",
            uptime_seconds: 1,
            initialized: true,
            sealed: false,
            storage_type: "file",
          });
        case "rustion_telemetry_list":
        case "rustion_target_health_all":
          return Promise.resolve([]);
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
  }

  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ principal: "root", entityId: "", policies: ["root"] });
  });

  it("renders counts, histogram and recent activity from the summary alone", async () => {
    mockCommands(readySummary);
    const { DashboardPage } = await import("../routes/DashboardPage");
    wrap(<DashboardPage />);

    await waitFor(() => expect(screen.getByText("4242")).toBeInTheDocument());
    expect(screen.getByText("secret/data/from-the-summary")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "4242 audit events over the last 24 hours" })).toBeInTheDocument();
    expect(screen.getAllByText(/updated 4 min ago/).length).toBeGreaterThan(0);

    const commands = mockInvoke.mock.calls.map((c) => c[0]);
    expect(commands).toContain("dashboard_summary");
    expect(commands).not.toContain("list_audit_events");
  });

  it("shows the pending state when the statistics are not computed yet", async () => {
    mockCommands({
      ...readySummary,
      audit_24h_total: null,
      audit_24h_denied: null,
      audit_24h_write_failures: null,
      failed_logins_1h: null,
      audit_stats: {
        state: "pending",
        reason: "not_computed",
        computed_at: null,
        stale: false,
        partial: false,
        failed_sources: [],
        histogram_24h: null,
        recent: null,
      },
    });
    const { DashboardPage } = await import("../routes/DashboardPage");
    wrap(<DashboardPage />);

    await waitFor(() => expect(screen.getByText("computing…")).toBeInTheDocument());
    expect(screen.getAllByText(/Statistics are being computed/).length).toBe(2);
    expect(mockInvoke.mock.calls.map((c) => c[0])).not.toContain("list_audit_events");
  });

  it("marks partial statistics and names the unreadable sources", async () => {
    mockCommands({
      ...readySummary,
      audit_stats: { ...readySummary.audit_stats, partial: true, failed_sources: ["access", "denial"] },
    });
    const { DashboardPage } = await import("../routes/DashboardPage");
    wrap(<DashboardPage />);

    await waitFor(() => expect(screen.getByText("4242")).toBeInTheDocument());
    const markers = screen.getAllByText("partial");
    expect(markers.length).toBeGreaterThan(0);
    expect(screen.getByTitle("Partial: could not read access, denial")).toBeInTheDocument();
  });

  it("shows counts but no rows or chart when the server withholds the audit detail", async () => {
    mockCommands({
      ...readySummary,
      audit_stats: { ...readySummary.audit_stats, histogram_24h: null, recent: null },
    });
    const { DashboardPage } = await import("../routes/DashboardPage");
    wrap(<DashboardPage />);

    await waitFor(() => expect(screen.getByText("4242")).toBeInTheDocument());
    expect(screen.getByText("Activity unavailable")).toBeInTheDocument();
    expect(screen.getByText("Recent activity unavailable.")).toBeInTheDocument();
    expect(screen.queryByText("secret/data/from-the-summary")).not.toBeInTheDocument();
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
