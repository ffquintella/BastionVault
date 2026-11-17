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
    expect(note).toHaveTextContent(/tries the import first/i);
    expect(note).toHaveTextContent(/if the name is taken it deletes the destination and imports again/i);
    expect(note).not.toHaveTextContent(/deletes the destination item first/i);
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

  // ── T501: polish ─────────────────────────────────────────────────

  function answerWithPlan(plan = PLAN_NO_SHARES) {
    mockInvoke.mockImplementation(async (_cmd: string, args: { dryRun: boolean }) =>
      args.dryRun ? plan : realOf(plan as typeof PLAN_NO_SHARES),
    );
  }

  async function check() {
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
  }

  const OVERWRITE_ACK = /destination is deleted if the name is taken/i;

  it("overwrite_run_requires_acknowledgement", async () => {
    answerWithPlan();
    const { onTransferred } = setup();
    await chooseDestination();
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    await check();

    const run = await screen.findByRole("button", { name: "Copy now" });
    expect(run).toBeDisabled();
    await userEvent.click(run);
    expect(mockInvoke).toHaveBeenCalledTimes(1);

    await userEvent.click(screen.getByRole("checkbox", { name: OVERWRITE_ACK }));
    expect(run).toBeEnabled();
    await userEvent.click(run);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledTimes(2));
    const sent = mockInvoke.mock.calls[1][1] as { onConflict: string; dryRun: boolean };
    expect(sent.onConflict).toBe("overwrite");
    expect(sent.dryRun).toBe(false);
    await waitFor(() => expect(onTransferred).toHaveBeenCalledTimes(1));
  });

  it("overwrite_and_move_each_need_their_own_acknowledgement", async () => {
    answerWithPlan();
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    await check();
    const run = await screen.findByRole("button", { name: "Move now" });
    await userEvent.click(screen.getByRole("checkbox", { name: /source will be deleted/i }));
    expect(run).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox", { name: OVERWRITE_ACK }));
    expect(run).toBeEnabled();
  });

  it("refuse_and_rename_need_no_overwrite_acknowledgement", async () => {
    answerWithPlan();
    setup();
    await chooseDestination();
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "rename");
    await check();
    expect(await screen.findByRole("button", { name: "Copy now" })).toBeEnabled();
    expect(screen.queryByRole("checkbox", { name: OVERWRITE_ACK })).not.toBeInTheDocument();
  });

  it("overwrite_note_stays_visible_in_the_checked_phase", async () => {
    answerWithPlan();
    setup();
    await chooseDestination();
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    await check();
    await screen.findByRole("button", { name: "Copy now" });
    expect(screen.getByText(/Overwrite tries the import first/)).toBeInTheDocument();
  });

  // Each edit of the request makes a checked plan stale.
  const EDITS: [string, () => Promise<void>][] = [
    ["destination namespace", () => userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "")],
    ["destination mount", () => userEvent.type(screen.getByLabelText("Destination mount"), "2")],
    ["destination path", () => userEvent.type(screen.getByLabelText("Destination path"), "2")],
    ["on_conflict", () => userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "rename")],
  ];

  it.each(EDITS)("a changed %s hides the run button and clears the acknowledgements", async (_name, edit) => {
    answerWithPlan();
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    await check();
    await screen.findByRole("button", { name: "Move now" });
    await userEvent.click(screen.getByRole("checkbox", { name: /source will be deleted/i }));
    await userEvent.click(screen.getByRole("checkbox", { name: OVERWRITE_ACK }));
    expect(screen.getByRole("button", { name: "Move now" })).toBeEnabled();

    await edit();
    expect(screen.queryByRole("button", { name: "Move now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();

    // Back to a Move + overwrite request and a new check: both start unticked.
    await userEvent.selectOptions(screen.getByLabelText("If the destination exists"), "overwrite");
    await check();
    const run = await screen.findByRole("button", { name: "Move now" });
    expect(run).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /source will be deleted/i })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: OVERWRITE_ACK })).not.toBeChecked();
  });

  it("switching the operation away and back hides the run button and clears the move acknowledgement", async () => {
    answerWithPlan();
    setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await check();
    await screen.findByRole("button", { name: "Move now" });
    await userEvent.click(screen.getByRole("checkbox", { name: /source will be deleted/i }));
    expect(screen.getByRole("button", { name: "Move now" })).toBeEnabled();

    await userEvent.click(screen.getByRole("radio", { name: "Copy" }));
    expect(screen.queryByRole("button", { name: "Copy now" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    expect(screen.queryByRole("button", { name: "Move now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();

    await check();
    const run = await screen.findByRole("button", { name: "Move now" });
    expect(run).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /source will be deleted/i })).not.toBeChecked();
    expect(mockInvoke).toHaveBeenCalledTimes(2);
  });

  it("a failed real run returns to the form and needs a new check", async () => {
    mockInvoke
      .mockResolvedValueOnce(PLAN_NO_SHARES)
      .mockRejectedValueOnce({ message: "the destination refused the import" })
      .mockResolvedValueOnce(PLAN_NO_SHARES);
    const { onTransferred } = setup();
    await chooseDestination();
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await check();
    await screen.findByRole("button", { name: "Move now" });
    await userEvent.click(screen.getByRole("checkbox", { name: /source will be deleted/i }));
    await userEvent.click(screen.getByRole("button", { name: "Move now" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("the destination refused the import");
    expect(onTransferred).not.toHaveBeenCalled();
    // Back on the form: no run button, the stale plan is gone.
    expect(screen.queryByRole("button", { name: "Move now" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Check result/)).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeEnabled();
    expect(mockInvoke).toHaveBeenCalledTimes(2);

    await check();
    const run = await screen.findByRole("button", { name: "Move now" });
    expect(run).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /source will be deleted/i })).not.toBeChecked();
    expect(dryRunOf(mockInvoke.mock.calls[2])).toBe(true);
  });

  it("uses_a_fixed_title_that_does_not_embed_the_path", () => {
    const long = "a-very-long-resource-name-".repeat(8);
    setup({ path: long });
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(/^Copy or move to another namespace$/);
    // The From line is the one place the path shows.
    expect(screen.getAllByText(new RegExp(long)).length).toBe(1);
  });

  it("compares_resource_names_without_case_to_match_the_server", async () => {
    setup({ path: "DB1" });
    await chooseDestination("team-a");
    const path = screen.getByLabelText("Destination path");
    await userEvent.clear(path);
    await userEvent.type(path, "  db1 ");
    expect(screen.getByText(/same as the source/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
    await userEvent.clear(path);
    await userEvent.type(path, "db2");
    expect(screen.queryByText(/same as the source/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeEnabled();
  });

  it("compares_kv_secret_names_with_case", async () => {
    setup({ kind: "kv-secret", mount: "secret", path: "Db1" });
    await chooseDestination("team-a");
    const path = screen.getByLabelText("Destination path");
    await userEvent.clear(path);
    await userEvent.type(path, "db1");
    expect(screen.queryByText(/same as the source/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeEnabled();
    await userEvent.clear(path);
    await userEvent.type(path, "Db1");
    expect(screen.getByText(/same as the source/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
  });

  it("a future share code still raises the drop banner and is listed", async () => {
    mockInvoke.mockResolvedValue({
      ...PLAN_NO_SHARES,
      warnings: [{ code: "grantee-foo", subject: "entity-zzz", message: "a code this client has never seen" }],
    });
    setup();
    await chooseDestination();
    await check();
    await screen.findByText(/Some or all shares will be dropped/);
    expect(screen.getByText("grantee-foo")).toBeInTheDocument();
    expect(screen.getByText("entity-zzz")).toBeInTheDocument();
  });

  it("group_and_file_warnings_do_not_raise_the_share_banner", async () => {
    mockInvoke.mockResolvedValue({
      ...PLAN_NO_SHARES,
      warnings: [
        { code: "group-membership-dropped", subject: "ops", message: "no group of that name" },
        { code: "files-not-transferred", subject: "db1", message: "2 files stay" },
      ],
    });
    setup();
    await chooseDestination();
    await check();
    await screen.findByText("group-membership-dropped");
    expect(screen.getByText("files-not-transferred")).toBeInTheDocument();
    expect(screen.queryByText(/Some or all shares/)).not.toBeInTheDocument();
  });

  it("lists_the_kv_specific_warnings", async () => {
    mockInvoke.mockResolvedValue({
      ...PLAN_NO_SHARES,
      warnings: [
        { code: "deleted-version-not-recoverable", subject: "secret/x v2", message: "arrives destroyed" },
        { code: "kv-environment-overrides-normalized", subject: "secret/x", message: "an override equal to its base is dropped" },
      ],
    });
    setup({ kind: "kv-secret", mount: "secret", path: "x" });
    await chooseDestination();
    await check();
    await screen.findByText("deleted-version-not-recoverable");
    expect(screen.getByText("kv-environment-overrides-normalized")).toBeInTheDocument();
    expect(screen.queryByText(/Some or all shares/)).not.toBeInTheDocument();
    expect((mockInvoke.mock.calls[0][1] as { kind: string }).kind).toBe("kv-secret");
  });
});
