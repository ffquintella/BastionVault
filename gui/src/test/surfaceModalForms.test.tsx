/**
 * Plugin surface schema v2: modal forms opened by a table action (with a
 * "choose the kind" step) and by an Edit row action (prefilled from the
 * row's `read`, secrets never prefilled and never sent empty).
 */
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { SurfaceRouter } from "../components/surface/SurfaceRouter";
import { KEEP_SECRET_HINT, prefillValues } from "../components/surface/SurfaceForm";
import type { ActiveSurfaceBundle, SurfaceComponent } from "../lib/api";
import { usePluginSurfacesStore } from "../stores/pluginSurfacesStore";

const PROTOCOLS = { type: "array", title: "Protocols", items: { enum: ["ssh", "rdp", "web"] } };

const components: SurfaceComponent[] = [
  {
    kind: "table",
    id: "accounts",
    binding: { op: "list", path: "{mount}/v2/accounts" },
    columns: [
      { field: "label", label: "Label" },
      { field: "secret_kind", label: "Kind" },
    ],
    actions: [
      { label: "Add account", prompt: "What kind of account?", forms: ["add-password", "add-ssh-key"] },
    ],
    row_actions: [
      {
        label: "Edit",
        binding: { op: "read", path: "{mount}/v2/accounts/{id}" },
        open_form: {
          select_by: "secret_kind",
          forms_by_value: { password: "edit-password", "ssh-key": "edit-ssh-key" },
        },
      },
      {
        label: "Delete",
        binding: { op: "delete", path: "{mount}/v2/accounts/{id}" },
        confirm: true,
      },
    ],
    empty_text: "You have no accounts yet.",
  },
  {
    kind: "form",
    id: "add-password",
    title: "Password account",
    presentation: "modal",
    schema: {
      type: "object",
      required: ["label", "password"],
      properties: {
        label: { type: "string", title: "Label" },
        password: { type: "string", title: "Password", format: "password" },
        secret_kind: { type: "string", title: "Kind", enum: ["password"], default: "password" },
      },
    },
    submit: { label: "Add account", binding: { op: "write", path: "{mount}/v2/accounts" } },
  },
  {
    kind: "form",
    id: "add-ssh-key",
    title: "SSH-key account",
    presentation: "modal",
    schema: {
      type: "object",
      required: ["label", "private_key"],
      properties: {
        label: { type: "string", title: "Label" },
        private_key: { type: "string", title: "Private key", format: "secret-textarea" },
      },
    },
    submit: { label: "Add key account", binding: { op: "write", path: "{mount}/v2/accounts" } },
  },
  {
    kind: "form",
    id: "edit-password",
    title: "Edit password account",
    presentation: "modal",
    schema: {
      type: "object",
      required: ["label", "password"],
      properties: {
        label: { type: "string", title: "Label" },
        password: { type: "string", title: "Password", format: "password" },
        totp_seed: { type: "string", title: "TOTP seed", format: "password" },
        protocols: PROTOCOLS,
        targets: { type: "string", title: "Targets", format: "textarea" },
      },
    },
    submit: { label: "Save changes", binding: { op: "write", path: "{mount}/v2/accounts/{id}" } },
  },
  {
    kind: "form",
    id: "edit-ssh-key",
    title: "Edit SSH-key account",
    presentation: "modal",
    schema: {
      type: "object",
      required: ["label"],
      properties: {
        label: { type: "string", title: "Label" },
        private_key: { type: "string", title: "Private key", format: "secret-textarea" },
      },
    },
    submit: { label: "Save changes", binding: { op: "write", path: "{mount}/v2/accounts/{id}" } },
  },
] as SurfaceComponent[];

function bundleWith(schemaVersion: number): ActiveSurfaceBundle {
  return {
    etag: "surface-etag",
    entries: [
      {
        plugin: "self-accounts",
        version: "0.1.2",
        mount: "self-accounts/",
        assets: [],
        surface: {
          schema_version: schemaVersion,
          title: "Self-accounts",
          pages: [{ route: "/plugin/self-accounts/accounts", title: "My accounts", components }],
        },
      },
    ],
  };
}

type Args = {
  op: string;
  path: string;
  params: Record<string, string>;
  body: Record<string, unknown> | null;
};

let accounts: Record<string, unknown>[] = [];
let records: Record<string, Record<string, unknown>> = {};
let writeReply: () => Promise<unknown> = () => Promise.resolve({ data: { id: "acct-new" } });

function dispatched(op: string): Args[] {
  return mockInvoke.mock.calls
    .filter(([command]) => command === "plugin_surface_dispatch")
    .map(([, payload]) => (payload as { args: Args }).args)
    .filter((a) => a.op === op);
}

beforeEach(() => {
  accounts = [];
  records = {};
  writeReply = () => Promise.resolve({ data: { id: "acct-new" } });
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((command: string, payload?: unknown) => {
    if (command === "plugin_surface_dispatch") {
      const { op, params } = (payload as { args: Args }).args;
      if (op === "list") return Promise.resolve({ data: { entries: accounts.map((a) => ({ ...a })) } });
      if (op === "read") return Promise.resolve({ data: records[params.id] ?? null });
      if (op === "write") return writeReply();
      return Promise.resolve({ data: null });
    }
    if (command === "plugin_surfaces_refresh") return Promise.resolve({ bundle: bundleWith(2) });
    return Promise.resolve({});
  });
  usePluginSurfacesStore.setState({ bundle: bundleWith(2), loading: false, error: null });
});

afterEach(() => {
  usePluginSurfacesStore.getState().clear();
});

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/plugin/self-accounts/accounts?pluginWindow=modal-test"]}>
      <SurfaceRouter />
    </MemoryRouter>,
  );
}

/** Fill the create form's required fields (jsdom enforces `required`). */
function fillPasswordForm() {
  fireEvent.change(screen.getByLabelText("Label"), { target: { value: "Corp admin" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2" } });
}

describe("surface schema v2 — Add account", () => {
  it("keeps modal forms off the page and opens them through a kind chooser", async () => {
    renderPage();
    expect(await screen.findByText("You have no accounts yet.")).toBeInTheDocument();
    // No form is rendered inline any more.
    expect(screen.queryByLabelText("Label")).toBeNull();
    expect(screen.queryByText("Password account")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    expect(screen.getByText("What kind of account?")).toBeInTheDocument();
    expect(screen.queryByLabelText("Label")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "SSH-key account" }));

    // The SSH-key form, not the password one.
    expect(screen.getByLabelText("Private key")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).toBeNull();

    // Back to the chooser, then the password form.
    fireEvent.click(screen.getByRole("button", { name: /Choose another kind/ }));
    fireEvent.click(screen.getByRole("button", { name: "Password account" }));
    expect(screen.getByLabelText("Password")).toHaveAttribute("required");
  });

  it("submits the chosen form, closes the modal and re-lists the table", async () => {
    renderPage();
    await screen.findByText("You have no accounts yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    fireEvent.click(screen.getByRole("button", { name: "Password account" }));
    fireEvent.change(screen.getByLabelText("Label"), { target: { value: "Corp admin" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2" } });

    accounts = [{ id: "acct-new", label: "Corp admin", secret_kind: "password" }];
    const form = screen.getByLabelText("Label").closest("form")!;
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Add account" }));
    });

    expect(await screen.findByText("Corp admin")).toBeInTheDocument();
    const [write] = dispatched("write");
    expect(write.path).toBe("{mount}/v2/accounts");
    expect(write.body).toEqual({ label: "Corp admin", password: "hunter2", secret_kind: "password" });
    expect(screen.queryByLabelText("Password")).toBeNull();
    await waitFor(() => expect(dispatched("list")).toHaveLength(2));
  });

  it("shows an API error in the modal and keeps it open", async () => {
    writeReply = () => Promise.reject("label is required");
    renderPage();
    await screen.findByText("You have no accounts yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    fireEvent.click(screen.getByRole("button", { name: "Password account" }));
    fillPasswordForm();
    const form = screen.getByLabelText("Label").closest("form")!;
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Add account" }));
    });
    expect(await within(form).findByText(/label is required/)).toBeInTheDocument();
    expect(screen.getByLabelText("Label")).toBeInTheDocument();
  });

  it("shows the plugin's warnings after a save instead of closing", async () => {
    writeReply = () =>
      Promise.resolve({ data: { id: "acct-new" }, warnings: ["this account is never offered for web"] });
    renderPage();
    await screen.findByText("You have no accounts yet.");
    fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    fireEvent.click(screen.getByRole("button", { name: "Password account" }));
    fillPasswordForm();
    const form = screen.getByLabelText("Label").closest("form")!;
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Add account" }));
    });
    expect(await screen.findByText("this account is never offered for web")).toBeInTheDocument();
    await waitFor(() => expect(dispatched("list")).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByText("this account is never offered for web")).toBeNull();
  });
});

describe("surface schema v2 — Edit", () => {
  beforeEach(() => {
    accounts = [
      { id: "acct-pw", label: "Domain admin", secret_kind: "password" },
      { id: "acct-key", label: "Deploy key", secret_kind: "ssh-key" },
    ];
    records = {
      "acct-pw": {
        id: "acct-pw",
        label: "Domain admin",
        secret_kind: "password",
        has_secret: true,
        protocols: ["rdp", "web"],
        targets: ["*.corp.example.com", "10.20.0.0/16"],
        // A plugin must never return these; if one does, they stay out.
        password: "LEAKED-PASSWORD",
        totp_seed: "LEAKED-SEED",
      },
      "acct-key": { id: "acct-key", label: "Deploy key", secret_kind: "ssh-key", has_secret: true },
    };
  });

  function editButtons() {
    return screen.getAllByRole("button", { name: "Edit" });
  }

  it("opens the form for the row's kind, prefilled, with empty optional secrets", async () => {
    renderPage();
    await screen.findByText("Domain admin");
    await act(async () => {
      fireEvent.click(editButtons()[0]);
    });

    const [read] = dispatched("read");
    expect(read.path).toBe("{mount}/v2/accounts/{id}");
    expect(read.params.id).toBe("acct-pw");

    expect(await screen.findByDisplayValue("Domain admin")).toBeInTheDocument();
    expect(screen.getByText("Edit password account")).toBeInTheDocument();
    expect(screen.getByLabelText("Targets")).toHaveValue("*.corp.example.com\n10.20.0.0/16");
    expect(screen.getByLabelText("rdp")).toBeChecked();
    expect(screen.getByLabelText("ssh")).not.toBeChecked();

    const password = screen.getByLabelText("Password");
    expect(password).toHaveValue("");
    expect(password).not.toHaveAttribute("required");
    expect(screen.getByLabelText("TOTP seed")).toHaveValue("");
    expect(screen.getAllByText(KEEP_SECRET_HINT)).toHaveLength(2);
    expect(document.body.innerHTML).not.toContain("LEAKED");
    // The kind cannot be changed here: the edit form has no kind field.
    expect(screen.queryByLabelText("Kind")).toBeNull();
  });

  it("writes to the row's id and leaves an empty secret out of the request", async () => {
    renderPage();
    await screen.findByText("Domain admin");
    await act(async () => {
      fireEvent.click(editButtons()[0]);
    });
    const label = await screen.findByDisplayValue("Domain admin");
    fireEvent.change(label, { target: { value: "Domain admin (old)" } });
    const form = label.closest("form")!;
    await act(async () => {
      fireEvent.click(within(form).getByRole("button", { name: "Save changes" }));
    });

    await waitFor(() => expect(dispatched("write")).toHaveLength(1));
    const [write] = dispatched("write");
    expect(write.path).toBe("{mount}/v2/accounts/{id}");
    expect(write.params.id).toBe("acct-pw");
    expect(write.body).toEqual({
      label: "Domain admin (old)",
      protocols: ["rdp", "web"],
      targets: "*.corp.example.com\n10.20.0.0/16",
    });
    expect(write.body).not.toHaveProperty("password");
    expect(write.body).not.toHaveProperty("totp_seed");
    // Closed and re-listed.
    await waitFor(() => expect(screen.queryByText("Edit password account")).toBeNull());
    await waitFor(() => expect(dispatched("list")).toHaveLength(2));
  });

  it("sends a secret the user typed, and a form value cannot retarget the write", async () => {
    renderPage();
    await screen.findByText("Domain admin");
    await act(async () => {
      fireEvent.click(editButtons()[0]);
    });
    const label = await screen.findByDisplayValue("Domain admin");
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "new-pw" } });
    await act(async () => {
      fireEvent.click(within(label.closest("form")!).getByRole("button", { name: "Save changes" }));
    });
    await waitFor(() => expect(dispatched("write")).toHaveLength(1));
    expect(dispatched("write")[0].body).toMatchObject({ password: "new-pw" });
    expect(dispatched("write")[0].params.id).toBe("acct-pw");
  });

  it("opens the SSH-key edit form for an ssh-key row", async () => {
    renderPage();
    await screen.findByText("Deploy key");
    await act(async () => {
      fireEvent.click(editButtons()[1]);
    });
    expect(await screen.findByText("Edit SSH-key account")).toBeInTheDocument();
    const key = screen.getByLabelText("Private key");
    expect(key).toHaveValue("");
    expect(key).not.toHaveAttribute("required");
    expect(screen.queryByLabelText("Password")).toBeNull();
  });

  it("refuses a row whose kind has no form instead of guessing one", async () => {
    accounts = [{ id: "acct-x", label: "Odd one", secret_kind: "token" }];
    renderPage();
    await screen.findByText("Odd one");
    fireEvent.click(editButtons()[0]);
    expect(await screen.findByText('No form for secret_kind "token".')).toBeInTheDocument();
    expect(dispatched("read")).toHaveLength(0);
  });

  it("shows a failed read in the modal", async () => {
    mockInvoke.mockImplementation((command: string, payload?: unknown) => {
      if (command === "plugin_surface_dispatch") {
        const { op } = (payload as { args: Args }).args;
        if (op === "list") return Promise.resolve({ data: { entries: accounts } });
        if (op === "read") return Promise.reject("permission denied");
      }
      return Promise.resolve({});
    });
    renderPage();
    await screen.findByText("Domain admin");
    await act(async () => {
      fireEvent.click(editButtons()[0]);
    });
    expect(await screen.findByText(/permission denied/)).toBeInTheDocument();
    expect(dispatched("write")).toHaveLength(0);
  });
});

describe("surface schema fence", () => {
  it("does not render a page from a surface newer than this GUI", async () => {
    usePluginSurfacesStore.setState({ bundle: bundleWith(3) });
    renderPage();
    expect(await screen.findByText("Update BastionVault to open this page")).toBeInTheDocument();
    expect(dispatched("list")).toHaveLength(0);
  });
});

describe("prefillValues", () => {
  it("takes only the form's own fields, in shapes they can show, never secrets", () => {
    const schema = {
      type: "object",
      properties: {
        label: { type: "string" },
        targets: { type: "string", format: "textarea" },
        domains: { type: "string" },
        protocols: { type: "array" },
        count: { type: "integer" },
        enabled: { type: "boolean" },
        password: { type: "string", format: "password" },
        private_key: { type: "string", format: "secret-textarea" },
      },
    };
    expect(
      prefillValues(schema, {
        label: "A",
        targets: ["a", "b"],
        domains: ["x", "y"],
        protocols: "ssh",
        count: "3",
        enabled: true,
        password: "p",
        private_key: "k",
        unrelated: "u",
      }),
    ).toEqual({ label: "A", targets: "a\nb", domains: "x, y", enabled: true });
  });
});
