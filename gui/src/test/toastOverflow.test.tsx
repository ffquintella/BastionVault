import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider, useToast } from "../components/ui/Toast";

/// The shape that broke: an ironrdp connector failure carries a cargo
/// checkout path and a docs.rs URL verbatim. Both are single tokens with
/// no break opportunity, so a shrink-to-fit toast grew to their
/// min-content width and spilled off the right edge of the window.
const LONG_ERROR =
  "rdp: connect_finalize: [read frame by hint @ " +
  "/Users/felipe/.cargo/git/checkouts/ironrdp-4e0c3b4d251f13bf/b49b313/crates/ironrdp-connector/src/lib.rs:416] " +
  "custom error, caused by: peer closed connection without sending TLS close_notify: " +
  "https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof";

function Trigger() {
  const { toast } = useToast();
  return (
    <button onClick={() => toast("error", LONG_ERROR)}>boom</button>
  );
}

async function showToast() {
  const user = userEvent.setup();
  render(
    <ToastProvider>
      <Trigger />
    </ToastProvider>,
  );
  await user.click(screen.getByRole("button", { name: "boom" }));
  return screen.getByText(LONG_ERROR);
}

describe("Toast overflow", () => {
  it("renders the whole message, untruncated", async () => {
    const message = await showToast();
    expect(message.textContent).toBe(LONG_ERROR);
  });

  it("lets unbreakable tokens wrap instead of overflowing", async () => {
    const message = await showToast();
    // `min-w-0` defeats the flex item's `min-width: auto`, `break-words`
    // gives the long path and URL a break opportunity. Without both, the
    // row is as wide as its longest token.
    expect(message.className).toContain("min-w-0");
    expect(message.className).toContain("break-words");
  });

  it("pins the stack width rather than shrinking to fit its content", async () => {
    const message = await showToast();
    const stack = message.closest("div")?.parentElement;
    expect(stack?.className).toContain("w-[min(24rem,calc(100vw-2rem))]");
    // A bare max-width does not stop a min-content-sized flex row.
    expect(stack?.className).not.toMatch(/\bmax-w-sm\b/);
  });
});
