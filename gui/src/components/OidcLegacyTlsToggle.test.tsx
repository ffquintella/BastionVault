import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { OidcLegacyTlsToggle, isLegacyTlsUnavailableError } from "./OidcLegacyTlsToggle";

const REFUSAL =
  "oidc: `oidc_discovery_legacy_tls` is true, but this vault was built without the legacy TLS 1.2 CBC client " +
  "(cargo feature `oidc_legacy_tls`); rebuild with it or set `oidc_discovery_legacy_tls` to false";

describe("OidcLegacyTlsToggle", () => {
  it("renders off with its warning and no error state", () => {
    render(<OidcLegacyTlsToggle checked={false} onChange={() => undefined} available={true} />);
    const toggle = screen.getByRole("switch", { name: /legacy TLS 1\.2 \(CBC\)/i });
    expect(toggle).not.toBeChecked();
    expect(toggle).toBeEnabled();
    expect(screen.getByText(/weaker than the GCM \/ ChaCha20 suites/i)).toBeInTheDocument();
    expect(screen.getByText(/this mount only/i)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reports on and off", async () => {
    const onChange = vi.fn();
    const { rerender } = render(<OidcLegacyTlsToggle checked={false} onChange={onChange} available={true} />);
    await userEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenLastCalledWith(true);
    rerender(<OidcLegacyTlsToggle checked={true} onChange={onChange} available={true} />);
    expect(screen.getByRole("switch")).toBeChecked();
    await userEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenLastCalledWith(false);
  });

  it("shows a distinct error and refuses to turn on when the vault lacks the feature", () => {
    render(<OidcLegacyTlsToggle checked={false} onChange={() => undefined} available={false} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/built without the legacy TLS client/i);
    expect(screen.getByRole("switch")).toBeDisabled();
  });

  it("still lets a stored 'on' be turned off when the vault lacks the feature", async () => {
    const onChange = vi.fn();
    render(<OidcLegacyTlsToggle checked={true} onChange={onChange} available={false} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/every sign-in through this provider fails/i);
    await userEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenLastCalledWith(false);
  });

  it("recognises the vault's refusal of a save", () => {
    expect(isLegacyTlsUnavailableError(REFUSAL)).toBe(true);
    expect(isLegacyTlsUnavailableError("oidc: `oidc_discovery_url` is required")).toBe(false);
    expect(isLegacyTlsUnavailableError(null)).toBe(false);
    render(<OidcLegacyTlsToggle checked={true} onChange={() => undefined} available={null} error={REFUSAL} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
