/**
 * The SQL profile editor on a database resource's Connection tab
 * (features/sql-browser.md §5, §10) and the type editor's `sql` switch.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SqlProfilesCard } from "../components/SqlProfilesCard";
import { TypeEditorModal } from "../components/TypeEditorModal";
import { useAuthStore } from "../stores/authStore";
import { DEFAULT_RESOURCE_TYPES } from "../lib/resourceTypes";
import type { ResourceMetadata, ResourceTypeDef } from "../lib/types";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const SSH_PROFILE = {
  id: "p_ssh",
  name: "SSH",
  protocol: "ssh",
  is_default: true,
  credential_source: { kind: "secret", secret_id: "k" },
};
const FUTURE_PROFILE = {
  id: "p_future",
  name: "Later",
  protocol: "future",
  credential_source: { kind: "x" },
  extra: { a: 1 },
};
const STORED_SQL = {
  id: "p_ro",
  name: "Read-only (svc_ro)",
  protocol: "sql",
  sql: { catalog: "app", tls: { mode: "verify-full" }, ceiling: ["sql_select"], require_mfa: false },
  credential_source: { kind: "secret", secret_id: "svc_ro" },
};

const DATABASE = DEFAULT_RESOURCE_TYPES["database"] as ResourceTypeDef;

function resource(over: Record<string, unknown> = {}): ResourceMetadata {
  return {
    name: "netrisk-db",
    type: "database",
    tags: "",
    notes: "",
    created_at: "",
    updated_at: "",
    engine: "postgresql",
    hostname: "db1.example.net",
    connection_profiles: [SSH_PROFILE, STORED_SQL, FUTURE_PROFILE],
    ...over,
  } as ResourceMetadata;
}

function bridge(over: Record<string, (args?: unknown) => unknown> = {}) {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    if (over[cmd]) return over[cmd](args);
    if (cmd === "list_resource_secrets") return Promise.resolve({ keys: ["svc_ro", "svc_rw"] });
    if (cmd === "resource_sql_privileges") {
      return Promise.resolve({ resource: "netrisk-db", server: ["sql_select"], resource_wide: ["sql_select", "sql_update"] });
    }
    if (cmd === "write_resource") return Promise.resolve(null);
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

function mount(
  res: ResourceMetadata = resource(),
  typeDef: ResourceTypeDef = DATABASE,
  props: Partial<React.ComponentProps<typeof SqlProfilesCard>> = {},
) {
  const toast = vi.fn();
  const onUpdated = vi.fn();
  render(<SqlProfilesCard resource={res} typeDef={typeDef} onUpdated={onUpdated} toast={toast} {...props} />);
  return { toast, onUpdated };
}

const written = () => {
  const calls = mockInvoke.mock.calls.filter(([c]) => c === "write_resource");
  const call = calls[calls.length - 1];
  expect(call).toBeDefined();
  return (call![1] as { name: string; metadata: Record<string, unknown> }).metadata;
};

beforeEach(() => {
  mockInvoke.mockReset();
  bridge();
  useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "e1" });
});

describe("the profile list", () => {
  it("lists the resource's sql profiles and nothing else", () => {
    mount();
    const card = screen.getByTestId("sql-profiles-card");
    expect(within(card).getByText("Read-only (svc_ro)")).toBeInTheDocument();
    expect(within(card).queryByText("SSH")).not.toBeInTheDocument();
    expect(within(card).queryByText("Later")).not.toBeInTheDocument();
    expect(within(card).getAllByText("sql_select").length).toBeGreaterThan(0);
    expect(card).toHaveTextContent("login from secret svc_ro");
  });

  it("flags a stored profile the server would refuse, with the reason", () => {
    mount(resource({ connection_profiles: [{ ...STORED_SQL, sql: { ceiling: ["sql_select"], require_mfa: "yes" } }] }));
    expect(screen.getByText("invalid")).toBeInTheDocument();
    expect(screen.getByText(/require_mfa/)).toBeInTheDocument();
  });

  it("shows the caller's own effective SQL privileges", async () => {
    mount();
    const chips = await screen.findByTestId("sql-my-privileges");
    expect(chips).toHaveTextContent("sql_select");
    expect(chips).toHaveTextContent("sql_update");
    expect(mockInvoke).toHaveBeenCalledWith("resource_sql_privileges", { resource: "netrisk-db", objects: undefined });
  });
});

describe("adding a profile", () => {
  async function openEditor(res = resource()) {
    const user = userEvent.setup();
    const m = mount(res);
    await user.click(screen.getByRole("button", { name: /add sql profile/i }));
    return { user, ...m };
  }

  it("writes exactly the shape the backend accepts, beside the profiles it must not touch", async () => {
    const { user, onUpdated } = await openEditor();
    const name = screen.getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "Writer");
    await user.type(screen.getByLabelText("Database"), "app");
    await user.click(screen.getByRole("button", { name: "Read/write" }));
    await user.click(screen.getByLabelText(/require mfa/i));
    await user.type(screen.getByLabelText("Secret"), "svc_rw");
    await user.click(screen.getByRole("button", { name: /save profile/i }));

    await waitFor(() => expect(onUpdated).toHaveBeenCalled());
    const meta = written();
    const profiles = meta["connection_profiles"] as Record<string, unknown>[];
    expect(profiles).toHaveLength(4);
    // The launcher's profile and the newer client's profile are kept untouched.
    expect(profiles.find((p) => p["id"] === "p_ssh")).toEqual(SSH_PROFILE);
    expect(profiles.find((p) => p["id"] === "p_future")).toEqual(FUTURE_PROFILE);
    expect(profiles.find((p) => p["id"] === "p_ro")).toEqual(STORED_SQL);
    const added = profiles.find((p) => p["name"] === "Writer")!;
    expect(added).toMatchObject({
      protocol: "sql",
      sql: {
        catalog: "app",
        tls: { mode: "verify-full" },
        ceiling: ["sql_select", "sql_insert", "sql_update", "sql_delete"],
        require_mfa: true,
      },
      credential_source: { kind: "secret", secret_id: "svc_rw" },
    });
    expect(Object.keys(added).sort()).toEqual(["credential_source", "id", "name", "protocol", "sql"]);
    // The rest of the record is written back as it was.
    expect(meta["engine"]).toBe("postgresql");
    expect(meta["hostname"]).toBe("db1.example.net");
  });

  it("does not let a bad value reach the server: the errors show and Save stays disabled", async () => {
    const { user } = await openEditor();
    await user.type(screen.getByLabelText("Secret"), "svc_rw");
    expect(screen.getByRole("button", { name: /save profile/i })).toBeEnabled();
    await user.type(screen.getByLabelText("Host (optional)"), "db1/x");
    await user.type(screen.getByLabelText("Port (optional)"), "70000");
    const errors = screen.getByTestId("sql-profile-errors");
    expect(errors).toHaveTextContent(/Host must be a host name/);
    expect(errors).toHaveTextContent(/Port must be an integer/);
    expect(screen.getByRole("button", { name: /save profile/i })).toBeDisabled();
  });

  it("needs a secret and a non-empty ceiling", async () => {
    const { user } = await openEditor();
    expect(screen.getByRole("button", { name: /save profile/i })).toBeDisabled();
    await user.type(screen.getByLabelText("Secret"), "svc_rw");
    const group = screen.getByRole("group", { name: "Ceiling" });
    await user.click(within(group).getByRole("button", { name: "sql_select" }));
    expect(screen.getByTestId("sql-profile-errors")).toHaveTextContent(/at least one capability/);
    expect(screen.getByRole("button", { name: /save profile/i })).toBeDisabled();
  });

  it("offers a named instance only for SQL Server", async () => {
    await openEditor(resource({ engine: "postgresql" }));
    expect(screen.queryByLabelText(/named instance/i)).not.toBeInTheDocument();
  });

  it("offers it for SQL Server, and labels the catalog as the service on Oracle", async () => {
    mockInvoke.mockReset();
    bridge();
    const { unmount } = render(
      <SqlProfilesCard resource={resource({ engine: "mssql" })} typeDef={DATABASE} onUpdated={() => {}} toast={() => {}} />,
    );
    await userEvent.click(screen.getByRole("button", { name: /add sql profile/i }));
    expect(screen.getByLabelText(/named instance/i)).toBeInTheDocument();
    unmount();
    render(
      <SqlProfilesCard resource={resource({ engine: "oracle" })} typeDef={DATABASE} onUpdated={() => {}} toast={() => {}} />,
    );
    await userEvent.click(screen.getByRole("button", { name: /add sql profile/i }));
    expect(screen.getByLabelText("Service name")).toBeInTheDocument();
  });

  it("shows the endpoint the secret's sql_endpoint must name, and follows the host and port", async () => {
    const { user } = await openEditor();
    const hint = screen.getByTestId("sql-endpoint-hint");
    expect(hint).toHaveTextContent("sql_endpoint");
    expect(hint).toHaveTextContent("db1.example.net:5432");
    await user.type(screen.getByLabelText("Host (optional)"), "DB2.example.net");
    await user.type(screen.getByLabelText("Port (optional)"), "6432");
    expect(screen.getByTestId("sql-endpoint-hint")).toHaveTextContent("db2.example.net:6432");
  });

  it("does not let dynamic credentials be chosen: they are for later", async () => {
    const { user } = await openEditor();
    await user.selectOptions(screen.getByLabelText("Credential source"), "dynamic");
    // Still a stored secret: the secret field is still there.
    expect(screen.getByLabelText("Secret")).toBeInTheDocument();
    expect(screen.getByText(/not available yet/)).toBeInTheDocument();
  });

  it("explains step-up as enforced per action", async () => {
    await openEditor();
    expect(screen.getByText(/fresh MFA step-up bound to that action/)).toBeInTheDocument();
    expect(screen.queryByText(/not enforced/)).not.toBeInTheDocument();
  });
});

describe("editing and deleting", () => {
  it("edits one sql profile in place and leaves every other entry byte for byte", async () => {
    const user = userEvent.setup();
    const { onUpdated } = mount();
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.queryByText(/The server refuses this stored profile/)).not.toBeInTheDocument();
    const name = screen.getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "Renamed");
    await user.click(screen.getByRole("button", { name: /save profile/i }));
    await waitFor(() => expect(onUpdated).toHaveBeenCalled());
    const profiles = written()["connection_profiles"] as Record<string, unknown>[];
    expect(profiles).toHaveLength(3);
    expect(profiles.find((p) => p["id"] === "p_ro")).toMatchObject({ id: "p_ro", name: "Renamed", protocol: "sql" });
    expect(profiles.find((p) => p["id"] === "p_future")).toEqual(FUTURE_PROFILE);
    expect(profiles.find((p) => p["id"] === "p_ssh")).toEqual(SSH_PROFILE);
  });

  it("repairs a profile the server refuses by saving it in the accepted shape", async () => {
    const user = userEvent.setup();
    mount(
      resource({
        connection_profiles: [
          { ...STORED_SQL, target: { host: "db1", user: "x" }, sql: { ceiling: ["sql_select"], require_mfa: "yes" } },
        ],
      }),
    );
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByText(/The server refuses this stored profile/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /save profile/i }));
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("write_resource", expect.anything()));
    const [p] = written()["connection_profiles"] as Record<string, any>[];
    expect(p.target).toEqual({ host: "db1" });
    expect(p.sql.require_mfa).toBe(true);
  });

  it("deletes only the chosen sql profile", async () => {
    const user = userEvent.setup();
    const { onUpdated } = mount();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = screen.getByText(/Delete the SQL profile/).closest("div")!;
    await user.click(within(dialog.parentElement!.parentElement!).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(onUpdated).toHaveBeenCalled());
    const ids = (written()["connection_profiles"] as { id: string }[]).map((p) => p.id);
    expect(ids.sort()).toEqual(["p_future", "p_ssh"]);
  });
});

describe("enforcement (spec §5.2)", () => {
  it("defaults to database-first and says what a read-only grant then needs", () => {
    mount();
    expect(screen.getByLabelText("Enforcement")).toHaveValue("database-first");
    expect(screen.getByText(/ceiling is exactly/)).toBeInTheDocument();
    expect(screen.queryByTestId("classifier-only-note")).not.toBeInTheDocument();
  });

  it("states the downgrade plainly for classifier-only, and saves it", async () => {
    const user = userEvent.setup();
    const { onUpdated } = mount();
    await user.selectOptions(screen.getByLabelText("Enforcement"), "classifier-only");
    expect(screen.getByTestId("classifier-only-note")).toHaveTextContent(
      "SQL grants on this database are enforced by BastionVault only; the database login can do more.",
    );
    expect(screen.getByTestId("classifier-only-note")).toHaveTextContent("db_enforced: false");
    await user.click(screen.getByRole("button", { name: /save enforcement/i }));
    await waitFor(() => expect(onUpdated).toHaveBeenCalled());
    const meta = written();
    expect(meta["sql"]).toEqual({ enforcement: "classifier-only" });
    // The record's profiles go back as they were.
    expect(meta["connection_profiles"]).toEqual([SSH_PROFILE, STORED_SQL, FUTURE_PROFILE]);
  });

  it("reads a saved classifier-only", () => {
    mount(resource({ sql: { enforcement: "classifier-only" } }));
    expect(screen.getByLabelText("Enforcement")).toHaveValue("classifier-only");
    expect(screen.getByTestId("classifier-only-note")).toBeInTheDocument();
  });

  it("reports a block the server refuses", () => {
    mount(resource({ sql: { enforcement: "none" } }));
    expect(screen.getByRole("alert")).toHaveTextContent(/enforcement/);
  });
});

describe("the type must offer sql", () => {
  const withProtocols = (protocols: unknown): ResourceTypeDef => ({ ...DATABASE, connect: { protocols } as never });

  it("is on for the built-in type, and for a saved list that names sql", () => {
    mount(resource(), DATABASE);
    expect(screen.getByRole("button", { name: /add sql profile/i })).toBeEnabled();
    expect(screen.queryByText(/lists its Connect protocols without/)).not.toBeInTheDocument();
    document.body.innerHTML = "";
    mount(resource(), withProtocols(["ssh", "sql"]));
    expect(screen.getByRole("button", { name: /add sql profile/i })).toBeEnabled();
  });

  it("says it is off for a saved list without sql, and offers to add it", () => {
    mount(resource(), withProtocols(["ssh"]));
    expect(screen.getByRole("button", { name: /add sql profile/i })).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent(/without `sql`/);
    expect(screen.getByRole("button", { name: /add sql to the database type/i })).toBeInTheDocument();
  });

  it("adds sql to the saved list, touching nothing else in the configuration", async () => {
    const user = userEvent.setup();
    const saved = {
      database: { id: "database", label: "Database", color: "error", fields: [], connect: { protocols: ["ssh"], default_ports: { ssh: 22 } } },
      server: { id: "server", label: "Server", color: "info", fields: [] },
    };
    bridge({
      resource_types_read_effective: () => Promise.resolve({ source: "mount", types: saved }),
      resource_types_write: () => Promise.resolve(null),
    });
    const onTypeUpdated = vi.fn();
    mount(resource(), withProtocols(["ssh"]), { onTypeUpdated });
    await user.click(screen.getByRole("button", { name: /add sql to the database type/i }));
    await waitFor(() => expect(onTypeUpdated).toHaveBeenCalled());
    const call = mockInvoke.mock.calls.find(([c]) => c === "resource_types_write")!;
    const types = (call[1] as { types: Record<string, any> }).types;
    expect(types.database.connect).toEqual({ protocols: ["ssh", "sql"], default_ports: { ssh: 22 } });
    expect(types.server).toEqual(saved.server);
  });

  it("does not fork the configuration from a namespace that inherits the root's", async () => {
    const user = userEvent.setup();
    bridge({ resource_types_read_effective: () => Promise.resolve({ source: "root", types: {} }) });
    mount(resource(), withProtocols(["ssh"]));
    await user.click(screen.getByRole("button", { name: /add sql to the database type/i }));
    expect(await screen.findByText(/inherits the root namespace/)).toBeInTheDocument();
    expect(mockInvoke.mock.calls.some(([c]) => c === "resource_types_write")).toBe(false);
  });

  it("says connect is disabled for the type, without an offer to change it here", () => {
    mount(resource(), { ...DATABASE, connect: { enabled: false } });
    expect(screen.getByRole("alert")).toHaveTextContent(/Connect is disabled for the Database type/);
    expect(screen.queryByRole("button", { name: /add sql to the database type/i })).not.toBeInTheDocument();
  });
});

describe("the engine", () => {
  it("must be one the SQL browser supports", () => {
    mount(resource({ engine: "mongodb" }));
    expect(screen.getByRole("button", { name: /add sql profile/i })).toBeDisabled();
    expect(screen.getByText(/Set this resource/)).toHaveTextContent(/PostgreSQL, MySQL, MariaDB, Microsoft SQL Server, Oracle Database/);
  });
});

describe("the type editor's sql switch (a saved list must not lose sql)", () => {
  function editor(typeDef: ResourceTypeDef | null) {
    const onSave = vi.fn();
    render(<TypeEditorModal typeDef={typeDef} onSave={onSave} onClose={() => {}} />);
    return onSave;
  }
  const db = (connect?: unknown): ResourceTypeDef => ({ ...DATABASE, ...(connect ? { connect: connect as never } : { connect: undefined }) });
  const saveBtn = () => screen.getByRole("button", { name: /^save$/i });

  it("offers the SQL checkbox on the database type only", () => {
    editor(db());
    expect(screen.getByRole("checkbox", { name: "SQL" })).toBeChecked();
    document.body.innerHTML = "";
    editor(DEFAULT_RESOURCE_TYPES["server"] as ResourceTypeDef);
    expect(screen.queryByRole("checkbox", { name: "SQL" })).not.toBeInTheDocument();
  });

  it("saves an unchanged database type with no connect block at all", async () => {
    const onSave = editor(db());
    await userEvent.click(saveBtn());
    expect(onSave.mock.calls[0][0].connect).toBeUndefined();
  });

  it("keeps sql when another protocol is ticked on a type that never saved a list", async () => {
    const onSave = editor(db());
    await userEvent.click(screen.getByRole("checkbox", { name: "SSH" }));
    await userEvent.click(saveBtn());
    expect(onSave.mock.calls[0][0].connect.protocols).toEqual(["ssh", "sql"]);
  });

  it("keeps sql on a saved list that names it, through an unrelated edit", async () => {
    const onSave = editor(db({ protocols: ["sql"] }));
    expect(screen.getByRole("checkbox", { name: "SQL" })).toBeChecked();
    await userEvent.click(saveBtn());
    expect(onSave.mock.calls[0][0].connect.protocols).toEqual(["sql"]);
  });

  it("shows sql off for a saved list without it, and writes it once ticked", async () => {
    const onSave = editor(db({ protocols: ["ssh"] }));
    expect(screen.getByRole("checkbox", { name: "SQL" })).not.toBeChecked();
    await userEvent.click(screen.getByRole("checkbox", { name: "SQL" }));
    await userEvent.click(saveBtn());
    expect(onSave.mock.calls[0][0].connect.protocols).toEqual(["ssh", "sql"]);
  });

  it("writes a list without sql when it is unticked on the database type", async () => {
    const onSave = editor(db());
    await userEvent.click(screen.getByRole("checkbox", { name: "SQL" }));
    await userEvent.click(saveBtn());
    expect(onSave.mock.calls[0][0].connect.protocols).toEqual([]);
  });
});
