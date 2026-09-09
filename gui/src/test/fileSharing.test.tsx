import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// Tauri bridge stub. The sharing card reads the owner record and the
// share list on mount and writes through put_share / delete_share /
// transfer_file_owner.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
}));
// The Files page is wrapped in the app chrome, which fans out a dozen
// unrelated background calls. Only the page body is under test here.
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const FILE_ID = "018f3b2a-abcd-1234-5678-000000000001";
const GRANTEE_ID = "22222222-2222-2222-2222-222222222222";

const noopToast = () => {};

function meta(over: Record<string, unknown> = {}) {
  return {
    id: FILE_ID,
    name: "fgv_certificates_internos.xdb",
    resource: "",
    mime_type: "",
    size_bytes: 2222222,
    sha256: "",
    tags: [],
    notes: "",
    created_at: "2026-08-26T17:09:22Z",
    updated_at: "2026-08-26T17:09:22Z",
    ...over,
  };
}

async function renderCard() {
  const { FileSharingCard } = await import("../components/FileSharingCard");
  const view = render(
    <ToastProvider>
      <FileSharingCard
        fileId={FILE_ID}
        fileName="fgv_certificates_internos.xdb"
        toast={noopToast}
      />
    </ToastProvider>,
  );
  await waitFor(() =>
    expect(screen.queryByText(/loading sharing info/i)).not.toBeInTheDocument(),
  );
  return view;
}

describe("FileSharingCard", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_file_owner")
        return Promise.resolve({
          target_kind: "file",
          target: FILE_ID,
          entity_id: "entity-1",
          owned: true,
          created_at: "",
        });
      if (cmd === "list_shares_for_target") return Promise.resolve([]);
      if (cmd === "put_share") return Promise.resolve({});
      if (cmd === "delete_share") return Promise.resolve(null);
      if (cmd === "transfer_file_owner") return Promise.resolve(null);
      if (cmd === "list_entity_aliases") return Promise.resolve([]);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["default"],
      entityId: "entity-1",
    });
  });

  it("looks up owner and shares against the file kind, keyed by id", async () => {
    await renderCard();
    expect(mockInvoke).toHaveBeenCalledWith("get_file_owner", { id: FILE_ID });
    expect(mockInvoke).toHaveBeenCalledWith("list_shares_for_target", {
      kind: "file",
      targetPath: FILE_ID,
    });
  });

  it("grants a share on the file id, not its display name", async () => {
    const user = userEvent.setup();
    await renderCard();
    await user.click(screen.getByRole("button", { name: /grant access/i }));
    // EntityPicker only propagates free text when it parses as a UUID —
    // otherwise it waits for a directory selection.
    await user.type(
      screen.getByPlaceholderText(/paste entity_id/i),
      GRANTEE_ID,
    );
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("put_share", {
        kind: "file",
        targetPath: FILE_ID,
        grantee: GRANTEE_ID,
        granteeKind: "entity",
        capabilities: ["read"],
        expiresAt: "",
      }),
    );
  });

  it("revokes an existing share through the file kind", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_file_owner")
        return Promise.resolve({ owned: true, entity_id: "entity-1" });
      if (cmd === "list_shares_for_target")
        return Promise.resolve([
          {
            target_kind: "file",
            target_path: FILE_ID,
            grantee_entity_id: "entity-2",
            granted_by_entity_id: "entity-1",
            capabilities: ["read"],
            granted_at: "",
            expires_at: "",
            expired: false,
          },
        ]);
      if (cmd === "delete_share") return Promise.resolve(null);
      if (cmd === "list_entity_aliases") return Promise.resolve([]);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const user = userEvent.setup();
    await renderCard();
    await user.click(screen.getByRole("button", { name: /revoke/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("delete_share", {
        kind: "file",
        targetPath: FILE_ID,
        grantee: "entity-2",
        granteeKind: "entity",
      }),
    );
  });

  it("hides the grant control from a caller who neither owns nor administers", async () => {
    useAuthStore.setState({ policies: ["default"], entityId: "someone-else" });
    await renderCard();
    expect(
      screen.queryByRole("button", { name: /grant access/i }),
    ).not.toBeInTheDocument();
  });
});

describe("FilesPage sharing entry point", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  function mountList() {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_files") return Promise.resolve({ ids: [FILE_ID] });
      if (cmd === "read_file_meta") return Promise.resolve(meta());
      if (cmd === "get_file_owner")
        return Promise.resolve({ owned: true, entity_id: "entity-1" });
      if (cmd === "list_shares_for_target") return Promise.resolve([]);
      if (cmd === "list_entity_aliases") return Promise.resolve([]);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
  }

  it("offers a Share action per file that opens the sharing tab", async () => {
    mountList();
    const user = userEvent.setup();
    const { FilesPage } = await import("../routes/FilesPage");
    render(
      <ToastProvider>
        <FilesPage />
      </ToastProvider>,
    );
    await screen.findByText("fgv_certificates_internos.xdb");
    await user.click(screen.getByRole("button", { name: /^share$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("get_file_owner", {
        id: FILE_ID,
      }),
    );
  });

  it("falls back to the caller's share pointers when listing is denied", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_files")
        return Promise.reject(new Error("permission denied"));
      if (cmd === "list_shares_for_me")
        return Promise.resolve({
          entity_id: "entity-1",
          group_shared_resources: false,
          entries: [
            { target_kind: "resource", target_path: "server-01" },
            { target_kind: "file", target_path: FILE_ID },
          ],
        });
      if (cmd === "read_file_meta") return Promise.resolve(meta());
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const { FilesPage } = await import("../routes/FilesPage");
    render(
      <ToastProvider>
        <FilesPage />
      </ToastProvider>,
    );
    await screen.findByText("fgv_certificates_internos.xdb");
    expect(screen.getByText(/shared with me/i)).toBeInTheDocument();
    // Only the file pointer is resolved — the resource pointer is not a
    // file and must not be read through the files API.
    expect(mockInvoke).toHaveBeenCalledWith("read_file_meta", { id: FILE_ID });
    expect(mockInvoke).not.toHaveBeenCalledWith("read_file_meta", {
      id: "server-01",
    });
  });
});
