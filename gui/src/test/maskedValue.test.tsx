import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MaskedValue } from "../components/ui/MaskedValue";
import { ToastProvider } from "../components/ui/Toast";

function renderValue(value: string) {
  return render(
    <ToastProvider>
      <MaskedValue value={value} />
    </ToastProvider>,
  );
}

describe("MaskedValue", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });

  it("starts blurred and unblurs on the show toggle", async () => {
    const user = userEvent.setup();
    renderValue("s3cr3t");
    const text = screen.getByText("s3cr3t");
    expect(text.className).toContain("blur-sm");
    await user.click(screen.getByRole("button", { name: /show value/i }));
    expect(screen.getByText("s3cr3t").className).not.toContain("blur-sm");
    // The toggle flips to "Hide value" once revealed.
    expect(
      screen.getByRole("button", { name: /hide value/i }),
    ).toBeInTheDocument();
  });

  it("copies the exact value without revealing it first", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(navigator.clipboard, "writeText");
    renderValue("p@ss word/with:specials");
    await user.click(screen.getByRole("button", { name: /copy value/i }));
    expect(spy).toHaveBeenCalledWith("p@ss word/with:specials");
    // Still masked — copying is not a reveal.
    expect(screen.getByText("p@ss word/with:specials").className).toContain(
      "blur-sm",
    );
  });

  it("confirms the copy on the button title", async () => {
    const user = userEvent.setup();
    renderValue("abc123");
    const copyButton = screen.getByRole("button", { name: /copy value/i });
    await user.click(copyButton);
    expect(copyButton.title).toMatch(/copied/i);
  });

  it("toasts when the clipboard is unavailable", async () => {
    // `userEvent.setup()` installs its own clipboard stub, so the failing mock
    // has to be planted after setup to survive.
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
      configurable: true,
    });
    renderValue("abc123");
    await user.click(screen.getByRole("button", { name: /copy value/i }));
    expect(
      await screen.findByText(/could not copy to clipboard/i),
    ).toBeInTheDocument();
  });
});
