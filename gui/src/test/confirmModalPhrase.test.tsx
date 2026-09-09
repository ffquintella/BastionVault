import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmModal } from "../components/ui/Modal";

describe("ConfirmModal typed confirmation", () => {
  it("keeps the warning and locks confirm until the phrase matches exactly", async () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmModal
        open
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Unmount PKI engine"
        message="This permanently destroys every issuer, key, role, and stored certificate under this mount."
        confirmPhrase="pki-fgv-ssl-ca"
        confirmPhraseLabel='Type the mount path "pki-fgv-ssl-ca" to confirm'
        confirmLabel="Unmount"
      />,
    );

    // The destructive warning is still shown above the field.
    expect(screen.getByText(/permanently destroys every issuer/)).toBeTruthy();

    const button = screen.getByRole("button", { name: "Unmount" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);

    const field = screen.getByLabelText('Type the mount path "pki-fgv-ssl-ca" to confirm');

    // A near-miss must not unlock the action.
    await userEvent.type(field, "pki-fgv-ssl-c");
    expect(button.disabled).toBe(true);
    await userEvent.click(button);
    expect(onConfirm).not.toHaveBeenCalled();

    await userEvent.type(field, "a");
    expect(button.disabled).toBe(false);
    await userEvent.click(button);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("clears the field between confirmations so a stale match cannot unlock the next target", async () => {
    const onConfirm = vi.fn();
    const { rerender } = render(
      <ConfirmModal
        open
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Unmount PKI engine"
        message="destroys everything"
        confirmPhrase="pki-a"
        confirmLabel="Unmount"
      />,
    );

    await userEvent.type(screen.getByLabelText(/pki-a/), "pki-a");
    expect((screen.getByRole("button", { name: "Unmount" }) as HTMLButtonElement).disabled).toBe(
      false,
    );

    // Dialog closes, then reopens on a different mount.
    rerender(
      <ConfirmModal
        open={false}
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Unmount PKI engine"
        message="destroys everything"
        confirmPhrase="pki-b"
        confirmLabel="Unmount"
      />,
    );
    rerender(
      <ConfirmModal
        open
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Unmount PKI engine"
        message="destroys everything"
        confirmPhrase="pki-b"
        confirmLabel="Unmount"
      />,
    );

    expect((screen.getByLabelText(/pki-b/) as HTMLInputElement).value).toBe("");
    expect((screen.getByRole("button", { name: "Unmount" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it("leaves confirm available when no phrase is required", async () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmModal
        open
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Delete role"
        message="Delete this role?"
        confirmLabel="Delete"
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
