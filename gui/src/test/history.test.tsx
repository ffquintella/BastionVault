import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  SecretHistoryPanel,
  type SecretHistoryVersion,
} from "../components/ui/SecretHistoryPanel";
import {
  operationVariant,
  formatTimestamp,
} from "../components/ui/SecretHistoryPanel";
import { ResourceHistoryPanel } from "../components/ui/ResourceHistoryPanel";
import { generatePassword, checkPasswordPolicy } from "../lib/password";

// ── Pure util tests ────────────────────────────────────────────────

describe("operationVariant", () => {
  it("maps known ops to their badge variants", () => {
    expect(operationVariant("create")).toBe("success");
    expect(operationVariant("update")).toBe("info");
    expect(operationVariant("restore")).toBe("info");
    expect(operationVariant("delete")).toBe("error");
  });
  it("falls back to neutral for unknown ops", () => {
    expect(operationVariant("")).toBe("neutral");
    expect(operationVariant("weird")).toBe("neutral");
  });
});

describe("formatTimestamp", () => {
  it("returns 'unknown time' for empty input", () => {
    expect(formatTimestamp("")).toBe("unknown time");
  });
  it("returns the raw value when not a valid date", () => {
    expect(formatTimestamp("not-a-date")).toBe("not-a-date");
  });
  it("formats valid ISO8601 timestamps", () => {
    const s = formatTimestamp("2030-01-02T03:04:05Z");
    // Exact string depends on locale, but it must differ from the raw input.
    expect(s).not.toBe("2030-01-02T03:04:05Z");
    expect(s.length).toBeGreaterThan(0);
  });
});

// ── SecretHistoryPanel ─────────────────────────────────────────────

const SAMPLE_VERSIONS: SecretHistoryVersion[] = [
  { version: 3, created_time: "2030-01-03T00:00:00Z", username: "alice", operation: "update" },
  { version: 2, created_time: "2030-01-02T00:00:00Z", username: "bob", operation: "update" },
  { version: 1, created_time: "2030-01-01T00:00:00Z", username: "alice", operation: "create" },
];

describe("SecretHistoryPanel", () => {
  it("renders a timeline row for each version with user + operation", () => {
    render(
      <SecretHistoryPanel
        versions={SAMPLE_VERSIONS}
        loadVersion={vi.fn()}
      />,
    );
    expect(screen.getByText("v3")).toBeInTheDocument();
    expect(screen.getByText("v2")).toBeInTheDocument();
    expect(screen.getByText("v1")).toBeInTheDocument();
    // Two "update" badges and one "create" badge.
    expect(screen.getAllByText("update")).toHaveLength(2);
    expect(screen.getByText("create")).toBeInTheDocument();
    expect(screen.getAllByText(/by alice/)).toHaveLength(2);
    expect(screen.getByText(/by bob/)).toBeInTheDocument();
  });

  it("shows an empty state when there are no versions", () => {
    render(<SecretHistoryPanel versions={[]} loadVersion={vi.fn()} />);
    expect(screen.getByText("No history")).toBeInTheDocument();
  });

  it("shows a loading indicator while loading", () => {
    render(
      <SecretHistoryPanel versions={[]} loading loadVersion={vi.fn()} />,
    );
    expect(screen.getByText(/loading history/i)).toBeInTheDocument();
  });

  it("loads and displays a version's data when a row is clicked", async () => {
    const loadVersion = vi.fn().mockResolvedValue({
      password: "Sup4rS4cret",
      username: "admin",
    });
    const user = userEvent.setup();
    render(
      <SecretHistoryPanel
        versions={SAMPLE_VERSIONS}
        loadVersion={loadVersion}
      />,
    );
    await user.click(screen.getByText("v2"));
    await waitFor(() => expect(loadVersion).toHaveBeenCalledWith(2));
    // Both keys rendered as table cells.
    await waitFor(() => {
      expect(screen.getByText("password")).toBeInTheDocument();
      expect(screen.getByText("username")).toBeInTheDocument();
    });
    // "Back" returns to the timeline.
    await user.click(screen.getByText(/back/i));
    expect(screen.getByText("v3")).toBeInTheDocument();
  });

  it("calls onRestore when the Restore button is clicked", async () => {
    const loadVersion = vi.fn().mockResolvedValue({ password: "old" });
    const onRestore = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(
      <SecretHistoryPanel
        versions={SAMPLE_VERSIONS}
        loadVersion={loadVersion}
        onRestore={onRestore}
      />,
    );
    await user.click(screen.getByText("v1"));
    await waitFor(() => screen.getByText(/restore this version/i));
    await user.click(screen.getByText(/restore this version/i));
    await waitFor(() =>
      expect(onRestore).toHaveBeenCalledWith(1, { password: "old" }),
    );
  });

  it("hides the Restore button for destroyed versions", async () => {
    const loadVersion = vi.fn().mockResolvedValue({ k: "v" });
    const user = userEvent.setup();
    render(
      <SecretHistoryPanel
        versions={[{ ...SAMPLE_VERSIONS[0], destroyed: true }]}
        loadVersion={loadVersion}
        onRestore={vi.fn()}
      />,
    );
    await user.click(screen.getByText("v3"));
    await waitFor(() => expect(loadVersion).toHaveBeenCalled());
    expect(screen.queryByText(/restore this version/i)).not.toBeInTheDocument();
  });
});

// ── ResourceHistoryPanel ───────────────────────────────────────────

describe("ResourceHistoryPanel", () => {
  it("renders an entry per change with user, op, and field chips", () => {
    render(
      <ResourceHistoryPanel
        entries={[
          {
            ts: "2030-01-03T00:00:00Z",
            user: "alice",
            op: "update",
            changed_fields: ["hostname", "tags"],
          },
          {
            ts: "2030-01-01T00:00:00Z",
            user: "root",
            op: "create",
            changed_fields: [],
          },
        ]}
      />,
    );
    expect(screen.getByText("update")).toBeInTheDocument();
    expect(screen.getByText("create")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("hostname")).toBeInTheDocument();
    expect(screen.getByText("tags")).toBeInTheDocument();
  });

  it("shows an empty state with no entries", () => {
    render(<ResourceHistoryPanel entries={[]} />);
    expect(screen.getByText("No history")).toBeInTheDocument();
  });

  it("notes when an update had no tracked field-level changes", () => {
    render(
      <ResourceHistoryPanel
        entries={[{ ts: "2030-01-01T00:00:00Z", user: "x", op: "update", changed_fields: [] }]}
      />,
    );
    expect(screen.getByText(/no field-level changes/i)).toBeInTheDocument();
  });
});

// ── Password generator + policy (regression) ───────────────────────

describe("generatePassword", () => {
  it("returns empty string when no groups are selected", () => {
    expect(
      generatePassword({
        length: 16,
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
      }),
    ).toBe("");
  });

  it("respects length and guarantees at least one char from each group", () => {
    const pw = generatePassword({
      length: 20,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
    });
    expect(pw).toHaveLength(20);
    expect(pw).toMatch(/[a-z]/);
    expect(pw).toMatch(/[A-Z]/);
    expect(pw).toMatch(/[0-9]/);
    expect(pw).toMatch(/[^A-Za-z0-9]/);
  });

  it("excludes ambiguous characters when asked", () => {
    for (let i = 0; i < 20; i++) {
      const pw = generatePassword({
        length: 32,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        excludeAmbiguous: true,
      });
      expect(pw).not.toMatch(/[0O1lI|`'"]/);
    }
  });
});

describe("checkPasswordPolicy", () => {
  const policy = {
    min_length: 12,
    require_lowercase: true,
    require_uppercase: true,
    require_digits: true,
    require_symbols: false,
  };

  it("accepts a compliant password", () => {
    expect(checkPasswordPolicy("Abcdefg12345", policy).ok).toBe(true);
  });

  it("reports every missing criterion", () => {
    const r = checkPasswordPolicy("abc", policy);
    expect(r.ok).toBe(false);
    expect(r.failures).toContain("at least 12 characters");
    expect(r.failures).toContain("an uppercase letter");
    expect(r.failures).toContain("a digit");
  });

  it("reports symbol requirement only when enabled", () => {
    const strict = { ...policy, require_symbols: true };
    expect(checkPasswordPolicy("Abcdefg12345", strict).failures).toContain(
      "a symbol",
    );
  });
});
