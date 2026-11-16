/**
 * One-time secrets (T52 Phase 7): shown once in a dedicated modal with an
 * explicit copy action, dropped from React state on close, never rendered
 * again, never written to web storage or the console.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../ui/Toast";
import { useAuthStore } from "../../stores/authStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { OneTimeSecretModal, useOneTimeSecret } from "./OneTimeSecretModal";
import { PasscodeCard } from "./PasscodeCard";

const SECRET = "0123456789abcdef0123456789abcdef";

function Harness() {
  const s = useOneTimeSecret();
  return (
    <ToastProvider>
      <button onClick={() => s.show({ title: "Client secret", label: "Client secret", value: SECRET, notice: "Store it now." })}>
        reveal
      </button>
      <span data-testid="held">{s.secret ? "held" : "empty"}</span>
      <OneTimeSecretModal secret={s.secret} onClose={s.clear} />
    </ToastProvider>
  );
}

let setItem: ReturnType<typeof vi.spyOn>;
let consoleSpies: ReturnType<typeof vi.spyOn>[];

beforeEach(() => {
  mockInvoke.mockReset();
  setItem = vi.spyOn(Storage.prototype, "setItem");
  consoleSpies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
    vi.spyOn(console, m).mockImplementation(() => {}),
  );
});

afterEach(() => {
  setItem.mockRestore();
  consoleSpies.forEach((s) => s.mockRestore());
});

function assertNeverLeaked() {
  for (const call of setItem.mock.calls) expect(JSON.stringify(call)).not.toContain(SECRET);
  for (const spy of consoleSpies) for (const call of spy.mock.calls) expect(JSON.stringify(call)).not.toContain(SECRET);
}

describe("OneTimeSecretModal", () => {
  it("shows the secret once and clears it from state when closed", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    render(<Harness />);

    expect(screen.queryByText(SECRET)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "reveal" }));
    expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(SECRET);
    expect(screen.getByText(/cleared from this window/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /copy client secret/i }));
    expect(writeText).toHaveBeenCalledWith(SECRET);

    await user.click(screen.getByRole("button", { name: /^done$/i }));
    expect(screen.queryByText(SECRET)).not.toBeInTheDocument();
    expect(screen.getByTestId("held")).toHaveTextContent("empty");
    expect(document.body.innerHTML).not.toContain(SECRET);
    assertNeverLeaked();
  });

  it("a minted passcode is shown once, then gone; a re-render does not bring it back", async () => {
    const user = userEvent.setup();
    useAuthStore.setState({ policies: ["default"] });
    mockInvoke.mockResolvedValue({
      data: { passcode: SECRET, login: "alice", environment: "prod", roles: ["netadmin"], expires_at: "2027-01-01T00:00:00Z", ttl: 120 },
      warnings: [],
    });
    const { rerender } = render(
      <ToastProvider>
        <PasscodeCard provider="radius" environments={["prod"]} />
      </ToastProvider>,
    );
    await user.selectOptions(screen.getByLabelText("Environment"), "prod");
    await user.click(screen.getByRole("button", { name: /mint passcode/i }));

    await waitFor(() => expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(SECRET));
    expect(mockInvoke).toHaveBeenCalledWith("idp_radius_passcode", { environment: "prod", ttl: null, roles: null });
    await user.click(screen.getByRole("button", { name: /^done$/i }));
    expect(document.body.innerHTML).not.toContain(SECRET);

    rerender(
      <ToastProvider>
        <PasscodeCard provider="radius" environments={["prod"]} />
      </ToastProvider>,
    );
    expect(document.body.innerHTML).not.toContain(SECRET);
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    assertNeverLeaked();
  });

  it("a root-token refusal is explained, not worked around", async () => {
    const user = userEvent.setup();
    useAuthStore.setState({ policies: ["root"] });
    mockInvoke.mockRejectedValue({
      message: "HTTP 403: LDAP passcodes are self-service and the calling token is not bound to an entity",
    });
    render(
      <ToastProvider>
        <PasscodeCard provider="ldap" environments={["prod"]} />
      </ToastProvider>,
    );
    expect(screen.getByRole("note")).toHaveTextContent(/root token/i);
    await user.selectOptions(screen.getByLabelText("Environment"), "prod");
    await user.click(screen.getByRole("button", { name: /mint passcode/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/not bound to an entity \(the root token never is\)/));
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("one-time-secret-value")).not.toBeInTheDocument();
  });
});
