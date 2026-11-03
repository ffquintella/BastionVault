import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SecretPairsEditor, isMultilineSecret } from "../components/ui/SecretPairsEditor";

describe("SecretPairsEditor multiline values", () => {
  it("flags PEM-like keys and values containing newlines", () => {
    expect(isMultilineSecret({ key: "private_key", value: "" })).toBe(true);
    expect(isMultilineSecret({ key: "x", value: "a\nb" })).toBe(true);
    expect(isMultilineSecret({ key: "password", value: "hunter2" })).toBe(false);
  });

  it("preserves newlines typed into a private_key row", () => {
    const onChange = vi.fn();
    render(<SecretPairsEditor pairs={[{ key: "private_key", value: "" }]} onChange={onChange} />);
    const ta = screen.getByPlaceholderText(/multi-line/i);
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    fireEvent.change(ta, { target: { value: pem } });
    expect(onChange).toHaveBeenCalledWith([{ key: "private_key", value: pem }]);
  });
});
