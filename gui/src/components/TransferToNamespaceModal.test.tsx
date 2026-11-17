import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { TransferToNamespaceModal } from "./TransferToNamespaceModal";
import { useNamespaceStore } from "../stores/namespaceStore";

const PLAN_NO_SHARES = {
  transferred: { secrets: 2, versions: 5, history: 4, shares: 0 },
  warnings: [
    {
      code: "policies-not-carried",
      subject: "team-a/resources/db1",
      message: "policies that name the source path are not rewritten",
    },
  ],
  dry_run: true,
  destination: { namespace: "team-b", mount: "resources", path: "db1" },
};

const PLAN_WITH_SHARES = {
  transferred: { secrets: 2, versions: 5, history: 4, shares: 1 },
  warnings: [
    {
      code: "grantee-not-in-destination",
      subject: "entity-aaa-111",
      message: "the grantee does not live in the destination namespace (read, connect)",
    },
    {
      code: "cannot-grant",
      subject: "ops-group",
      message: "the destination refused the grant",
    },
    ...PLAN_NO_SHARES.warnings,
  ],
  dry_run: true,
  destination: { namespace: "team-b", mount: "resources", path: "db1" },
};

function realOf(plan: typeof PLAN_NO_SHARES) {
  return { ...plan, dry_run: false };
}

function dryRunOf(call: unknown[]): unknown {
  return (call[1] as { dryRun: boolean }).dryRun;
}

function setup(props: Partial<React.ComponentProps<typeof TransferToNamespaceModal>> = {}) {
  const onClose = vi.fn();
  const onTransferred = vi.fn();
  render(
    <TransferToNamespaceModal
      kind="resource"
      namespace="team-a"
      mount="resources"
      path="db1"
      onClose={onClose}
      onTransferred={onTransferred}
      {...props}
    />,
  );
  return { onClose, onTransferred };
}

async function chooseDestination(ns = "team-b") {
  await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), ns);
}

describe("TransferToNamespaceModal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useNamespaceStore.setState({ namespaces: ["", "team-a", "team-b"], active: "team-a", loaded: true });
  });

  it("shows_dropped_share_warnings_before_confirm", async () => {
    mockInvoke.mockImplementation(async (_cmd: string, args: { dryRun: boolean }) =>
      args.dryRun ? PLAN_WITH_SHARES : realOf(PLAN_WITH_SHARES),
    );
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));

    await screen.findByText(/Some or all shares will be dropped/);
    // Every warning, with its code, subject and message, before anything is written.
    expect(screen.getByText("grantee-not-in-destination")).toBeInTheDocument();
    expect(screen.getByText("entity-aaa-111")).toBeInTheDocument();
    expect(screen.getByText(/does not live in the destination namespace/)).toBeInTheDocument();
    expect(screen.getByText("cannot-grant")).toBeInTheDocument();
    expect(screen.getByText("ops-group")).toBeInTheDocument();
    expect(screen.getByText("policies-not-carried")).toBeInTheDocument();
    // Counts from the plan.
    expect(screen.getByTestId("count-secrets")).toHaveTextContent("2");
    expect(screen.getByTestId("count-versions")).toHaveTextContent("5");
    expect(screen.getByTestId("count-history")).toHaveTextContent("4");
    expect(screen.getByTestId("count-shares")).toHaveTextContent("1");
    // Nothing real has run yet.
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(dryRunOf(mockInvoke.mock.calls[0])).toBe(true);

    await userEvent.click(screen.getByRole("button", { name: "Copy now" }));
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledTimes(2));
    expect(dryRunOf(mockInvoke.mock.calls[1])).toBe(false);
    await screen.findByText(/Transfer complete/);
  });

  it("move_requires_explicit_confirm", async () => {
    mockInvoke.mockImplementation(async (_cmd: string, args: { dryRun: boolean }) =>
      args.dryRun ? PLAN_NO_SHARES : realOf(PLAN_NO_SHARES),
    );
    const { onTransferred } = setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await userEvent.click(screen.getByRole("button", { name: "Check" }));

    const run = await screen.findByRole("button", { name: "Move now" });
    expect(run).toBeDisabled();
    await userEvent.click(run);
    expect(mockInvoke).toHaveBeenCalledTimes(1);

    await userEvent.click(screen.getByRole("checkbox", { name: /source will be deleted/i }));
    expect(run).toBeEnabled();
    await userEvent.click(run);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledTimes(2));
    expect((mockInvoke.mock.calls[1][1] as { op: string }).op).toBe("move");
    expect(dryRunOf(mockInvoke.mock.calls[1])).toBe(false);
    await waitFor(() => expect(onTransferred).toHaveBeenCalledTimes(1));
    expect(onTransferred.mock.calls[0][1]).toBe("move");
  });

  it("copy_does_not_require_delete_confirm", async () => {
    mockInvoke.mockResolvedValue(PLAN_NO_SHARES);
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));

    const run = await screen.findByRole("button", { name: "Copy now" });
    expect(run).toBeEnabled();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.queryByText(/source will be deleted/i)).not.toBeInTheDocument();
  });

  it("overwrite_shows_non_atomic_warning", async () => {
    setup();
    expect(screen.queryByText(/not atomic/i)).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    const note = screen.getByText(/not atomic/i);
    expect(note).toHaveTextContent(/deletes the destination/i);
  });

  it("dry_run_is_always_first_and_writes_nothing", async () => {
    mockInvoke.mockResolvedValue(PLAN_NO_SHARES);
    setup();
    await chooseDestination();
    // No way to run for real before a check.
    expect(screen.queryByRole("button", { name: "Copy now" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await screen.findByRole("button", { name: "Copy now" });

    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke.mock.calls[0][0]).toBe("transfer_object");
    expect(dryRunOf(mockInvoke.mock.calls[0])).toBe(true);

    // Changing anything invalidates the checked plan: back to Check.
    await userEvent.clear(screen.getByLabelText("Destination path"));
    await userEvent.type(screen.getByLabelText("Destination path"), "db2");
    expect(screen.queryByRole("button", { name: "Copy now" })).not.toBeInTheDocument();
  });

  it("errors_show_the_server_message", async () => {
    mockInvoke.mockRejectedValueOnce({ message: "permission denied: the caller may not read resources/db1" });
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("permission denied: the caller may not read resources/db1");

    // A JSON body is reduced to the server's own message.
    mockInvoke.mockRejectedValueOnce({ message: '{"errors":["a secret already exists at db1"]}' });
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("a secret already exists at db1"));
    expect(screen.getByRole("alert")).not.toHaveTextContent("{");
  });

  it("defaults_destination_to_same_mount_and_path", () => {
    setup();
    expect(screen.getByLabelText("Destination mount")).toHaveValue("resources");
    expect(screen.getByLabelText("Destination path")).toHaveValue("db1");
    // The list is the real namespace list, root named; the source namespace is
    // not preselected as the destination.
    const select = screen.getByLabelText("Destination namespace") as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(["", "team-a", "team-b"]);
    expect(select.value).not.toBe("team-a");
    expect(screen.getByRole("option", { name: "root" })).toBeInTheDocument();
  });

  it("warnings_without_shares_show_no_drop_banner", async () => {
    mockInvoke.mockResolvedValue(PLAN_NO_SHARES);
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await screen.findByText("policies-not-carried");
    expect(screen.queryByText(/Some or all shares/)).not.toBeInTheDocument();
  });

  it("sends_the_documented_request_shape", async () => {
    mockInvoke.mockResolvedValue(PLAN_NO_SHARES);
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await screen.findByRole("button", { name: "Copy now" });
    expect(mockInvoke).toHaveBeenCalledWith("transfer_object", {
      op: "copy",
      kind: "resource",
      source: { namespace: "team-a", mount: "resources", path: "db1" },
      destination: { namespace: "team-b", mount: "resources", path: "db1" },
      onConflict: "refuse",
      dryRun: true,
    });
  });

  it("refuses_an_identical_destination_without_calling", async () => {
    setup();
    await chooseDestination("team-a");
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
    expect(screen.getByText(/same as the source/i)).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
  });
});
