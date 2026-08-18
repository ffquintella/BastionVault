import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { EntityPicker } from "../components/ui/EntityPicker";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

/** Root's alias plus a same-named one local to `dti/esi` — the shape the
 *  backend returns for a listing made from inside a namespace. */
const ALIASES = [
  {
    mount: "userpass/",
    name: "felipe2",
    entity_id: "aaaa1111-2222-3333-4444-555566667777",
    namespace: "dti/esi",
  },
  {
    mount: "userpass/",
    name: "felipe2",
    entity_id: "fb832647-1499-6347-ecc2-dde54572a2de",
    namespace: "",
  },
];

function Harness({ onPick }: { onPick: (id: string) => void }) {
  const [value, setValue] = useState("");
  return (
    <EntityPicker
      value={value}
      onChange={(id) => {
        setValue(id);
        onPick(id);
      }}
      placeholder="Search by login or paste entity_id"
    />
  );
}

describe("EntityPicker across namespaces", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_entity_aliases") return Promise.resolve(ALIASES);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
  });

  it("lists root's aliases alongside the namespace's own, tagged apart", async () => {
    const user = userEvent.setup();
    render(<Harness onPick={vi.fn()} />);

    await user.click(screen.getByPlaceholderText(/paste entity_id/i));
    await waitFor(() =>
      expect(screen.getAllByText("felipe2")).toHaveLength(2),
    );

    // The namespace-local one carries its namespace; root's carries no tag,
    // so the two entity_ids are distinguishable before picking either.
    expect(screen.getByText("dti/esi")).toBeInTheDocument();
    expect(
      screen.getByText("fb832647-1499-6347-ecc2-dde54572a2de"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("aaaa1111-2222-3333-4444-555566667777"),
    ).toBeInTheDocument();
  });

  it("resolves a root login typed from inside a namespace", async () => {
    const user = userEvent.setup();
    const onPick = vi.fn();
    render(<Harness onPick={onPick} />);

    const input = screen.getByPlaceholderText(/paste entity_id/i);
    await user.click(input);
    await user.type(input, "felipe2");
    await waitFor(() => expect(screen.getAllByText("felipe2")).toHaveLength(2));

    // Rows render in listing order: the namespace's own first, then root's.
    const rows = screen.getAllByRole("button");
    await user.click(rows[1]);

    expect(onPick).toHaveBeenCalledWith("fb832647-1499-6347-ecc2-dde54572a2de");
    // Once picked, the field says which namespace the entity came from.
    expect(input).toHaveValue("felipe2 @ userpass/");
  });

  it("filters by namespace text", async () => {
    const user = userEvent.setup();
    render(<Harness onPick={vi.fn()} />);
    const input = screen.getByPlaceholderText(/paste entity_id/i);
    await user.click(input);
    await user.type(input, "dti/esi");
    await waitFor(() => expect(screen.getAllByText("felipe2")).toHaveLength(1));
    expect(
      screen.getByText("aaaa1111-2222-3333-4444-555566667777"),
    ).toBeInTheDocument();
  });
});
