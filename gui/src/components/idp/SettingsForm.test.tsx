/**
 * Provider settings (T52 Phase 7): only changed fields are written, and a
 * write-only TLS key is never filled from a read and is sent only when typed.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsForm, buildSettingsBody, type FieldSpec } from "./SettingsForm";

const FIELDS: FieldSpec[] = [
  { key: "enabled", label: "Run the listeners", kind: "bool" },
  { key: "radsec_listen", label: "RadSec listen", kind: "text" },
  { key: "rate_limit_per_minute", label: "Rate", kind: "number" },
  { key: "tls_key_pem", label: "Private key", kind: "secret_pem", setFlag: "tls_key_set" },
];

const READ = { enabled: false, radsec_listen: "10.0.0.5:2083", rate_limit_per_minute: 120, tls_key_set: true };

describe("buildSettingsBody", () => {
  it("sends nothing when nothing changed, even with a key set on the server", () => {
    expect(buildSettingsBody(FIELDS, READ, { enabled: false, radsec_listen: "10.0.0.5:2083", rate_limit_per_minute: "120", tls_key_pem: "" })).toEqual({});
  });

  it("sends changed fields, an emptied address as a clear, and a typed key", () => {
    expect(
      buildSettingsBody(FIELDS, READ, { enabled: true, radsec_listen: "", rate_limit_per_minute: "60", tls_key_pem: "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----" }),
    ).toEqual({ enabled: true, radsec_listen: "", rate_limit_per_minute: 60, tls_key_pem: "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----" });
  });

  it("refuses a non-numeric number", () => {
    expect(() => buildSettingsBody(FIELDS, READ, { enabled: false, radsec_listen: "10.0.0.5:2083", rate_limit_per_minute: "fast", tls_key_pem: "" })).toThrow(/whole number/);
  });
});

describe("SettingsForm", () => {
  it("never echoes the write-only key and clears it after a save", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    const { rerender } = render(<SettingsForm fields={FIELDS} current={READ} onSave={onSave} />);

    const key = screen.getByLabelText("Private key") as HTMLTextAreaElement;
    expect(key.value).toBe("");
    expect(key).toHaveAttribute("data-write-only", "true");
    expect(key).toHaveAttribute("autocomplete", "off");
    expect(key.className).toContain("-webkit-text-security");
    expect(screen.getByRole("button", { name: /save settings/i })).toBeDisabled();

    await user.type(key, "PEMKEY");
    await user.click(screen.getByRole("button", { name: /save settings/i }));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith({ tls_key_pem: "PEMKEY" }));

    // The page re-reads after a save; the new read resets the field.
    rerender(<SettingsForm fields={FIELDS} current={{ ...READ, updated_at: "now" }} onSave={onSave} />);
    expect((screen.getByLabelText("Private key") as HTMLTextAreaElement).value).toBe("");
    expect(document.body.innerHTML).not.toContain("PEMKEY");
  });
});
