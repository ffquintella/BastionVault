/**
 * Policy builder and validator: the eleven sql_* capabilities
 * (features/sql-browser.md §3.2, §9.1, §13).
 */
import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { PolicyBlockEditor } from "../components/PolicyBlockEditor";
import { PolicyValidatorPanel } from "../components/PolicyValidatorPanel";
import { PolicySqlGateNotice } from "../components/PolicySqlGateNotice";
import { ALL_CAPABILITIES, CAPABILITIES, lintPolicyModel, parsePolicyHcl } from "../lib/policyHcl";
import { SQL_CAPABILITIES } from "../lib/sqlPrivileges";

function lint(hcl: string, ns = "") {
  const parsed = parsePolicyHcl(hcl);
  expect(parsed.ok).toBe(true);
  return lintPolicyModel(parsed.model, ns);
}

const sqlOnly = (hcl: string, ns = "") => lint(hcl, ns).filter((f) => f.code !== undefined);

// A block body: an arrow returning the mock would be taken as a cleanup hook.
beforeEach(() => {
  mockInvoke.mockReset();
});

describe("capability sets", () => {
  it("keeps the ten generic capabilities and adds the eleven SQL ones to the accepted set", () => {
    expect(CAPABILITIES).toHaveLength(10);
    expect(ALL_CAPABILITIES).toHaveLength(21);
    for (const c of SQL_CAPABILITIES) expect(ALL_CAPABILITIES).toContain(c);
  });

  it("no longer reports a sql_* capability as unknown, and still reports a made-up one", () => {
    const msgs = lint(`
      path "resources/resources/db/sql/*" { capabilities = ["sql_select", "sql_bogus"] }
    `).map((f) => f.message);
    expect(msgs.some((m) => m.includes('unknown capability "sql_bogus"'))).toBe(true);
    expect(msgs.some((m) => m.includes('unknown capability "sql_select"'))).toBe(false);
  });
});

describe("lint: SQL rules", () => {
  it("accepts the spec's examples without a SQL finding", () => {
    const hcl = `
      path "resources/resources/netrisk-db/sql/*" { capabilities = ["sql_select"] }
      path "resources/resources/netrisk-db/sql/objects/def/netrisk/*" {
        capabilities = ["sql_select", "sql_update", "sql_delete"]
      }
      path "resources/resources/+/sql/*" {
        capabilities = ["sql_select", "sql_insert", "sql_script", "sql_export"]
        groups = ["prod-databases"]
      }
      path "resources/resources/pci-db/sql/*" { capabilities = ["deny"] }
    `;
    expect(sqlOnly(hcl)).toEqual([]);
  });

  it("refuses a SQL capability beside parameter constraints, as the server does", () => {
    for (const body of [
      `allowed_parameters = { "x" = ["1"] }`,
      `denied_parameters = { "x" = ["1"] }`,
      `required_parameters = ["env"]`,
    ]) {
      const f = sqlOnly(`path "resources/resources/db/sql/*" { capabilities = ["sql_select"]\n ${body} }`);
      expect(f.map((x) => x.code)).toContain("sql-parameters");
      expect(f.find((x) => x.code === "sql-parameters")!.severity).toBe("error");
      expect(f.find((x) => x.code === "sql-parameters")!.message).toMatch(/allowed_parameters, denied_parameters or required_parameters/);
    }
  });

  it("does not flag parameters on a rule without a SQL capability", () => {
    expect(sqlOnly(`path "resources/resources/db" { capabilities = ["read"]\n required_parameters = ["env"] }`)).toEqual([]);
  });

  it("warns when the path can never carry a SQL check", () => {
    const f = sqlOnly(`path "secret/data/team/*" { capabilities = ["sql_select"] }`);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ code: "sql-path", severity: "warning" });
    expect(f[0].message).toMatch(/sql\/server/);
  });

  it("warns that an object-scoped policy with no sql/server grant cannot open a session", () => {
    const f = sqlOnly(
      `path "resources/resources/db/sql/objects/def/netrisk/*" { capabilities = ["sql_select", "sql_update"] }`,
    );
    expect(f).toHaveLength(1);
    expect(f[0].code).toBe("sql-no-server");
    expect(f[0].message).toMatch(/resources\/resources\/db\/sql\/server/);
    expect(f[0].message).toMatch(/SELECT now\(\)/);
  });

  it("is satisfied by a resource-wide rule or an explicit server rule on the same resource", () => {
    const objectRule = `path "resources/resources/db/sql/objects/def/netrisk/*" { capabilities = ["sql_update"] }`;
    expect(sqlOnly(`${objectRule}\npath "resources/resources/db/sql/*" { capabilities = ["sql_select"] }`)).toEqual([]);
    expect(sqlOnly(`${objectRule}\npath "resources/resources/db/sql/server" { capabilities = ["sql_select"] }`)).toEqual([]);
  });

  it("is not satisfied by a server grant on another resource", () => {
    const f = sqlOnly(`
      path "resources/resources/db-a/sql/objects/def/s/*" { capabilities = ["sql_update"] }
      path "resources/resources/db-b/sql/*" { capabilities = ["sql_select"] }
    `);
    expect(f.map((x) => x.code)).toEqual(["sql-no-server"]);
  });

  it("is not satisfied by a deny", () => {
    const f = sqlOnly(`
      path "resources/resources/db/sql/objects/def/s/*" { capabilities = ["sql_update"] }
      path "resources/resources/db/sql/*" { capabilities = ["deny"] }
    `);
    expect(f.map((x) => x.code)).toEqual(["sql-no-server"]);
  });

  it("treats a wildcard resource as satisfied by any rule that covers the server path", () => {
    expect(
      sqlOnly(`
        path "resources/resources/+/sql/objects/def/s/*" { capabilities = ["sql_update"] }
        path "resources/resources/+/sql/server" { capabilities = ["sql_select"] }
      `),
    ).toEqual([]);
  });

  it("expects the namespace prefix inside a namespace, without a second finding for a bare rule", () => {
    expect(sqlOnly(`path "dti/resources/resources/db/sql/*" { capabilities = ["sql_select"] }`, "dti")).toEqual([]);
    const bare = lint(`path "resources/resources/db/sql/*" { capabilities = ["sql_select"] }`, "dti");
    expect(bare.filter((f) => f.message.includes("unreachable"))).toHaveLength(1);
    expect(bare.filter((f) => f.code)).toEqual([]);
  });
});

describe("PolicyBlockEditor: SQL chips", () => {
  const RESOURCE = `path "resources/resources/db/sql/*" {\n  capabilities = ["sql_select"]\n}\n`;
  const SECRET = `path "secret/data/team/*" {\n  capabilities = ["read"]\n}\n`;

  it("shows the eleven chips on a resource path", () => {
    render(<PolicyBlockEditor value={RESOURCE} onChange={() => {}} />);
    const group = screen.getByTestId("sql-capabilities");
    for (const c of SQL_CAPABILITIES) expect(within(group).getByRole("button", { name: c })).toBeInTheDocument();
    expect(within(group).getByRole("button", { name: "sql_select" })).toHaveClass("bg-[var(--color-primary)]");
    expect(within(group).getByRole("button", { name: "sql_drop" })).not.toHaveClass("bg-[var(--color-primary)]");
  });

  it("does not show them on a non-resource path", () => {
    render(<PolicyBlockEditor value={SECRET} onChange={() => {}} />);
    expect(screen.queryByTestId("sql-capabilities")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "sql_select" })).not.toBeInTheDocument();
  });

  it("keeps showing them on a rule that already names one, wherever its path points", () => {
    render(
      <PolicyBlockEditor value={`path "secret/data/x" {\n capabilities = ["sql_select"]\n}\n`} onChange={() => {}} />,
    );
    expect(screen.getByTestId("sql-capabilities")).toBeInTheDocument();
  });

  it("writes a toggled chip into the HCL, and removing the last one writes none", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<PolicyBlockEditor value={RESOURCE} onChange={onChange} />);
    await user.click(screen.getByRole("button", { name: "sql_update" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.stringContaining('capabilities = ["sql_select", "sql_update"]'));
    await user.click(screen.getByRole("button", { name: "sql_select" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.stringContaining('capabilities = ["sql_update"]'));
  });

  it("offers the chips once the path is typed as a resource path", async () => {
    const user = userEvent.setup();
    const Harness = () => {
      const [v, setV] = React.useState(`path "" {\n capabilities = ["read"]\n}\n`);
      return <PolicyBlockEditor value={v} onChange={setV} />;
    };
    render(<Harness />);
    expect(screen.queryByTestId("sql-capabilities")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Path"), "resources/resources/db/sql/*");
    expect(await screen.findByTestId("sql-capabilities")).toBeInTheDocument();
  });

  it("says SQL capabilities cannot be combined with parameter constraints and hides the env restriction", () => {
    const hcl = `path "resources/resources/db/sql/*" {\n capabilities = ["sql_select"]\n required_parameters = ["env"]\n}\n`;
    render(<PolicyBlockEditor value={hcl} onChange={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/cannot be combined with allowed_parameters/);
    expect(screen.queryByLabelText(/Restrict to environments/)).not.toBeInTheDocument();
  });

  it("warns inline about an object-scoped rule with no server grant", () => {
    const hcl = `path "resources/resources/db/sql/objects/def/s/*" {\n capabilities = ["sql_update"]\n}\n`;
    render(<PolicyBlockEditor value={hcl} onChange={() => {}} />);
    expect(screen.getByRole("note")).toHaveTextContent(/object-scoped SQL grant without a grant on/);
  });
});


describe("PolicyValidatorPanel: SQL checks", () => {
  const HCL = `path "resources/resources/db/sql/*" {\n capabilities = ["sql_select"]\n}\n`;

  function panel(cases: { path: string; capability: string }[]) {
    return render(
      <PolicyValidatorPanel
        name="analysts"
        hcl={HCL}
        savedCases={cases.map((c) => ({ ...c, expect: "allow" as const }))}
        onSavedCasesChange={() => {}}
        toast={() => {}}
      />,
    );
  }

  it("explains an object check against its synthetic path", () => {
    panel([{ path: "resources/resources/db/sql/objects/def/netrisk/users", capability: "sql_update" }]);
    const note = screen.getByTestId("sql-check-note");
    expect(note).toHaveTextContent("def.netrisk.users");
    expect(note).toHaveTextContent("…/sql/server");
  });

  it("explains a server check and warns about a path outside the SQL namespace", () => {
    panel([
      { path: "resources/resources/db/sql/server", capability: "sql_select" },
      { path: "secret/data/x", capability: "sql_select" },
    ]);
    const notes = screen.getAllByTestId("sql-check-note");
    expect(notes[0]).toHaveTextContent(/Server-level check of sql_select/);
    expect(notes[1]).toHaveTextContent(/no other path ever carries a SQL check/);
  });

  it("adds nothing for an ordinary capability", () => {
    panel([{ path: "secret/data/x", capability: "read" }]);
    expect(screen.queryByTestId("sql-check-note")).not.toBeInTheDocument();
  });

  it("offers the SQL capabilities in the case's capability list", () => {
    panel([{ path: "resources/resources/db/sql/server", capability: "sql_select" }]);
    const select = screen.getAllByRole("combobox")[0];
    const options = within(select).getAllByRole("option").map((o) => o.getAttribute("value"));
    for (const c of SQL_CAPABILITIES) expect(options).toContain(c);
  });

  it("shows the lint findings of a SQL rule in the Validation card", () => {
    render(
      <PolicyValidatorPanel
        name="x"
        hcl={`path "secret/data/x" {\n capabilities = ["sql_select"]\n}\n`}
        savedCases={[]}
        onSavedCasesChange={() => {}}
        toast={() => {}}
      />,
    );
    expect(screen.getByText(/can never be checked on this path/)).toBeInTheDocument();
  });
});

describe("PolicySqlGateNotice: the 409 from the write gate", () => {
  const CLOSED = {
    sql_capabilities_writable: false,
    reason: "node 3: no version record: it runs a build older than the SQL write gate",
    nodes: [
      { node: "1", member: true, policy_schema: 2, host_abi_minor: 4, qualifies: true, problem: null },
      { node: "3", member: true, policy_schema: null, host_abi_minor: null, qualifies: false, problem: "no version record" },
    ],
  };
  const SQL_HCL = `path "resources/resources/db/sql/*" {\n capabilities = ["sql_select"]\n}\n`;

  it("explains the closed gate and names the blocking node", async () => {
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "policy_schema_status" ? Promise.resolve(CLOSED) : Promise.reject(new Error(`unmocked ${cmd}`)),
    );
    render(<PolicySqlGateNotice hcl={SQL_HCL} />);
    const notice = await screen.findByTestId("sql-gate-notice");
    expect(notice).toHaveTextContent(/SQL privileges cannot be saved yet/);
    expect(notice).toHaveTextContent("node 3: no version record");
    expect(notice).not.toHaveTextContent("node 1:");
  });

  it("does not ask, or show anything, for a policy without SQL capabilities", async () => {
    mockInvoke.mockResolvedValue(CLOSED);
    render(<PolicySqlGateNotice hcl={`path "secret/*" {\n capabilities = ["read"]\n}\n`} />);
    await Promise.resolve();
    expect(mockInvoke).not.toHaveBeenCalled();
    expect(screen.queryByTestId("sql-gate-notice")).not.toBeInTheDocument();
  });

  it("shows nothing once the gate is open", async () => {
    mockInvoke.mockResolvedValue({ sql_capabilities_writable: true, latched: true });
    render(<PolicySqlGateNotice hcl={SQL_HCL} />);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("policy_schema_status", undefined));
    expect(screen.queryByTestId("sql-gate-notice")).not.toBeInTheDocument();
  });

  it("stays silent when the status cannot be read; the save reports the refusal itself", async () => {
    mockInvoke.mockRejectedValue(new Error("403"));
    render(<PolicySqlGateNotice hcl={SQL_HCL} />);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalled());
    expect(screen.queryByTestId("sql-gate-notice")).not.toBeInTheDocument();
  });
});
