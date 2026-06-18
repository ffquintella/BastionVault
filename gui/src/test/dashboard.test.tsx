import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { bucketByHour } from "../components/dashboard/SessionActivityChart";
import { KpiTile } from "../components/dashboard/KpiTile";
import { AttentionPanel } from "../components/dashboard/AttentionPanel";
import type { RustionTargetHealth } from "../lib/rustion";

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
});
