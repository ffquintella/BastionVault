/**
 * "Generate credential" modal (T62, features/dynamic-secrets.md Phase 5): the
 * credential is shown once, copied on request, dropped on close and on lease
 * expiry, flagged on a cache hit, and never logged or stored.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { DynamicCredsModal } from "../components/DynamicCredsModal";
import { useLeaseStore } from "../stores/leaseStore";

const PASSWORD = "Zq3-unique-dynamic-password-9Xw";
const USERNAME = "v-root-readonly-1761480000-0a1b2c3d";

function creds(overrides: Record<string, unknown> = {}) {
  return {
    data: { username: USERNAME, password: PASSWORD },
    lease_id: "database/creds/readonly/0f3c",
    lease_duration: 3600,
    renewable: true,
    cache_hit: false,
    warnings: [],
    ...overrides,
  };
}

/** Opens the modal, and can reopen it after Close, like the Secrets page. */
function Host() {
  const [open, setOpen] = useState(true);
  return open ? (
    <DynamicCredsModal mount="database/" role="readonly" onClose={() => setOpen(false)} />
  ) : (
    <button onClick={() => setOpen(true)}>reopen</button>
  );
}

const consoleSpies: ReturnType<typeof vi.spyOn>[] = [];

beforeEach(() => {
  mockInvoke.mockReset();
  useLeaseStore.getState().clear();
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    consoleSpies.push(vi.spyOn(console, method));
  }
});

afterEach(() => {
  consoleSpies.splice(0).forEach((s) => s.mockRestore());
  vi.unstubAllGlobals();
});

describe("DynamicCredsModal", () => {
  it("warns before generating and shows the credential once it is generated", async () => {
    mockInvoke.mockResolvedValue(creds());
    render(<Host />);
    expect(screen.getByText(/The credential is shown once/)).toBeInTheDocument();
    expect(screen.queryByText(PASSWORD)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    expect(await screen.findByText(PASSWORD)).toBeInTheDocument();
    expect(screen.getByText(USERNAME)).toBeInTheDocument();
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke).toHaveBeenCalledWith("dynamic_generate_creds", { mount: "database/", role: "readonly" });
    expect(screen.getByTestId("dynamic-creds-countdown")).toHaveTextContent(/Expires in (1h 00m|59m \d\ds)/);
    expect(screen.queryByRole("button", { name: "Generate credential" })).not.toBeInTheDocument();
  });

  it("copies the password to the clipboard", async () => {
    mockInvoke.mockResolvedValue(creds());
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    render(<Host />);
    await user.click(screen.getByRole("button", { name: "Generate credential" }));
    await screen.findByText(PASSWORD);
    const copyButtons = screen.getAllByRole("button", { name: "Copy value to clipboard" });
    await user.click(copyButtons[1]);
    expect(writeText).toHaveBeenCalledWith(PASSWORD);
  });

  it("drops the credential on close: reopening shows nothing until a new generate", async () => {
    mockInvoke.mockResolvedValue(creds());
    render(<Host />);
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    await screen.findByText(PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByText(PASSWORD)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "reopen" }));
    expect(screen.queryByText(PASSWORD)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate credential" })).toBeInTheDocument();
    expect(mockInvoke).toHaveBeenCalledTimes(1);
  });

  it("drops the credential when its lease runs out", async () => {
    mockInvoke.mockResolvedValue(creds({ lease_duration: 1 }));
    render(<Host />);
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    await screen.findByText(PASSWORD);
    await waitFor(() => expect(screen.queryByText(PASSWORD)).not.toBeInTheDocument(), { timeout: 3000 });
    expect(screen.getByRole("status")).toHaveTextContent(/lease ended/);
  });

  it("flags a cache hit as a shared lease", async () => {
    mockInvoke.mockResolvedValue(
      creds({ cache_hit: true, lease_duration: 900, warnings: ["served from the credential cache"] }),
    );
    render(<Host />);
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    expect(await screen.findByText("Served from the credential cache")).toBeInTheDocument();
    expect(screen.getByText("shared lease")).toBeInTheDocument();
    expect(useLeaseStore.getState().issued[0]).toMatchObject({
      lease_id: "database/creds/readonly/0f3c",
      shared: true,
    });
  });

  it("never logs or stores the credential, and records only lease metadata", async () => {
    // Recording storages, installed whatever the runtime's own Web Storage is.
    const writes: string[] = [];
    const recorder = () => ({
      length: 0,
      key: () => null,
      getItem: () => null,
      setItem: (k: string, v: string) => void writes.push(`${k}=${v}`),
      removeItem: () => undefined,
      clear: () => undefined,
    });
    vi.stubGlobal("localStorage", recorder());
    vi.stubGlobal("sessionStorage", recorder());
    mockInvoke.mockResolvedValue(creds({ data: { username: USERNAME, password: PASSWORD, extra: "x" } }));
    render(<Host />);
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    await screen.findByText(PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Close" }));

    for (const spy of consoleSpies) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call.map(String))).not.toContain(PASSWORD);
      }
    }
    for (const write of writes) expect(write).not.toContain(PASSWORD);
    const stored = JSON.stringify(useLeaseStore.getState().issued);
    expect(stored).toContain("database/creds/readonly/0f3c");
    expect(stored).not.toContain(PASSWORD);
    expect(stored).not.toContain(USERNAME);
  });

  it("shows the host's refusal and no credential", async () => {
    mockInvoke.mockRejectedValue({ message: "HTTP 507: lease quota reached" });
    render(<Host />);
    await userEvent.click(screen.getByRole("button", { name: "Generate credential" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("lease quota reached");
    expect(useLeaseStore.getState().issued).toHaveLength(0);
  });
});
