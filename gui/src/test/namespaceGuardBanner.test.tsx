/**
 * The read-only banner has to *repair* the state it reports, not send the
 * operator back to the login page.
 *
 * A token is bound to the namespace it logged into; it reaches another one
 * through the principal's allowed-namespace entry
 * (`sys/identity/ns-assignment/…`), which the server resolves live on every
 * request. So the fix for "read-only here" is to write that entry — signing in
 * again binds to whatever namespace the new login names and leaves the missing
 * entry exactly as missing.
 *
 * These cover the three states the banner has to get right: operable (render
 * nothing), inoperable with an identifiable principal (name it and offer the
 * grant), and inoperable with a token that stamps no principal (explain only —
 * no assignment could be matched to such a token, so a grant button would be a
 * lie).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { NamespaceGuardBanner } from "../components/NamespaceGuardBanner";
import * as api from "../lib/api";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

vi.mock("../lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/api")>()),
  capabilitiesSelf: vi.fn(),
  sessionPrincipal: vi.fn(),
  getNsAssignment: vi.fn(),
  setNsAssignment: vi.fn(),
}));

const mocked = api as unknown as {
  capabilitiesSelf: ReturnType<typeof vi.fn>;
  sessionPrincipal: ReturnType<typeof vi.fn>;
  getNsAssignment: ReturnType<typeof vi.fn>;
  setNsAssignment: ReturnType<typeof vi.fn>;
};

function renderBanner() {
  return render(
    <ToastProvider>
      <NamespaceGuardBanner />
    </ToastProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("NamespaceGuardBanner", () => {
  it("renders nothing when the token can operate in the active namespace", async () => {
    mocked.capabilitiesSelf.mockResolvedValue({
      paths: {},
      namespace_operable: true,
      token_namespace: "",
      active_namespace: "",
    });

    renderBanner();

    await waitFor(() => expect(mocked.capabilitiesSelf).toHaveBeenCalled());
    // `ToastProvider` renders its own (empty) portal container, so assert on
    // the banner's own landmark rather than on the whole tree.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // No principal round-trip when there is nothing to explain.
    expect(mocked.sessionPrincipal).not.toHaveBeenCalled();
  });

  it("names the principal and the missing entry, and grants it in place", async () => {
    mocked.capabilitiesSelf.mockResolvedValue({
      paths: {},
      namespace_operable: false,
      token_namespace: "",
      active_namespace: "dti/esi",
    });
    mocked.sessionPrincipal.mockResolvedValue({
      mount: "userpass/",
      name: "felipe",
      known: true,
    });
    // The principal already holds one namespace — the grant must widen, not
    // replace: writing just `["dti/esi"]` would silently revoke `dti`.
    mocked.getNsAssignment.mockResolvedValue({ namespaces: ["dti"] });
    mocked.setNsAssignment.mockResolvedValue(undefined);

    const reload = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, reload },
    });

    const user = userEvent.setup();
    renderBanner();

    const grant = await screen.findByRole("button", {
      name: /grant access to dti\/esi/i,
    });
    expect(screen.getByRole("alert")).toHaveTextContent("userpass/felipe");
    expect(screen.getByRole("alert")).toHaveTextContent(
      /no allowed-namespace entry covering/i,
    );
    // The old text sent the operator back to the login page, which does not
    // fix a missing assignment.
    expect(screen.getByRole("alert")).not.toHaveTextContent(/sign in directly/i);

    await user.click(grant);

    await waitFor(() =>
      expect(mocked.setNsAssignment).toHaveBeenCalledWith("userpass/", "felipe", [
        "dti",
        "dti/esi",
      ]),
    );
    await waitFor(() => expect(reload).toHaveBeenCalled());
  });

  it("explains without offering a grant when the token stamps no principal", async () => {
    mocked.capabilitiesSelf.mockResolvedValue({
      paths: {},
      namespace_operable: false,
      token_namespace: "",
      active_namespace: "dti/esi",
    });
    mocked.sessionPrincipal.mockResolvedValue({
      mount: "",
      name: "",
      known: false,
    });

    renderBanner();

    const alert = await screen.findByRole("alert");
    await waitFor(() => expect(mocked.sessionPrincipal).toHaveBeenCalled());
    expect(alert).toHaveTextContent(/cannot be matched to an allowed-namespace/i);
    expect(
      screen.queryByRole("button", { name: /grant access/i }),
    ).not.toBeInTheDocument();
  });
});
