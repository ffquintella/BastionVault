/**
 * The pages that used to read one record per listed object now load pages
 * from the `<list>-info` endpoints instead.
 *
 * Each test pins the same two properties: the page walks cursor pages and
 * never falls back to the per-object read, and against a server that predates
 * the endpoint it *does* fall back rather than breaking. Both matter — the
 * first is the fix for the abuse-guard ban, the second is what keeps a newer
 * desktop app usable against an older vault.
 *
 * See `features/client-request-efficiency.md`.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import {
  pollNowForTests,
  stopChangeWatcher,
} from "../lib/changeWatcher";
import { UsersPage } from "../routes/UsersPage";
import { NamespacesPage } from "../routes/NamespacesPage";
import { CertLifecyclePage } from "../routes/CertLifecyclePage";

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: () => Promise.resolve(null),
  open: () => Promise.resolve(null),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

/** The error shape `isRouteUnsupported` recognises as version skew. */
const ROUTE_UNSUPPORTED = {
  message: "HTTP 404: Logical backend path not supported.",
};

function renderPage(page: React.ReactNode) {
  useAuthStore.setState({ token: "root-token", isAuthenticated: true });
  useNamespaceStore.setState({ active: "" });
  render(
    <MemoryRouter>
      <ToastProvider>{page}</ToastProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockInvoke.mockReset();
  stopChangeWatcher();
});

// ── UserPass users: 1 + 2N became one page ──────────────────────────

describe("Users page", () => {
  function userRecord(i: number) {
    return {
      username: `user-${String(i).padStart(3, "0")}`,
      policies: ["default"],
      disabled: false,
      locked: i === 0,
      failed_login_count: 0,
      totp_mfa_enabled: i === 1,
      totp_mount: "",
      totp_key: "",
      email: "",
      phone: "",
      registered_keys: i === 2 ? 3 : 0,
      fido2_enabled: i === 2,
    };
  }

  it("pages users-info and never reads a user or its keys individually", async () => {
    const all = Array.from({ length: 7 }, (_, i) => userRecord(i));
    const cursors: Array<string | null> = [];
    mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
      switch (cmd) {
        case "list_auth_methods":
          return Promise.resolve([{ path: "userpass/", mount_type: "userpass" }]);
        case "list_policies":
          return Promise.resolve({ policies: ["default"] });
        case "list_namespaces":
        case "list_namespaces_info":
          return Promise.resolve({ namespaces: [], details: {} });
        case "get_lockout_config":
          return Promise.resolve({ enabled: false });
        case "get_mfa_config":
          return Promise.resolve({ enabled: false });
        case "get_password_policy":
          // The create-user form embeds PasswordGenerator, which reads the
          // policy eagerly and would otherwise fault on a null.
          return Promise.resolve({
            min_length: 16,
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_symbol: false,
          });
        case "list_users_info": {
          const after = (args?.after as string | null) ?? null;
          cursors.push(after);
          const start = after
            ? all.findIndex((r) => r.username === after) + 1
            : 0;
          const limit = (args?.limit as number) ?? 100;
          const records = all.slice(start, start + limit);
          const consumed = start + records.length;
          return Promise.resolve({
            records,
            total: all.length,
            next: consumed < all.length ? records[records.length - 1].username : "",
          });
        }
        case "get_user":
        case "fido2_list_credentials":
          throw new Error("must not read a user or its FIDO2 keys per row");
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<UsersPage />);

    expect(await screen.findByText("user-000")).toBeInTheDocument();
    await waitFor(() => expect(cursors.length).toBeGreaterThanOrEqual(1));
    // 7 users at the 500-per-request page size is a single call.
    expect(cursors).toEqual([null]);
    expect(await screen.findByText("user-006")).toBeInTheDocument();
  });

  it("falls back to the per-user reads on a server without the route", async () => {
    let perUserReads = 0;
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_auth_methods":
          return Promise.resolve([{ path: "userpass/", mount_type: "userpass" }]);
        case "list_policies":
          return Promise.resolve({ policies: ["default"] });
        case "list_namespaces":
        case "list_namespaces_info":
          return Promise.resolve({ namespaces: [], details: {} });
        case "get_lockout_config":
        case "get_mfa_config":
          return Promise.resolve({ enabled: false });
        case "get_password_policy":
          // The create-user form embeds PasswordGenerator, which reads the
          // policy eagerly and would otherwise fault on a null.
          return Promise.resolve({
            min_length: 16,
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_symbol: false,
          });
        case "list_users_info":
          return Promise.reject(ROUTE_UNSUPPORTED);
        case "list_users":
          return Promise.resolve({ users: ["alice", "bob"] });
        case "get_user":
          perUserReads += 1;
          return Promise.resolve({
            username: "alice",
            policies: [],
            disabled: false,
            locked: false,
            failed_login_count: 0,
            totp_mfa_enabled: false,
            totp_mount: "",
            totp_key: "",
            email: "",
            phone: "",
          });
        case "fido2_list_credentials":
          return Promise.resolve(null);
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<UsersPage />);
    expect(await screen.findByText("alice")).toBeInTheDocument();
    await waitFor(() => expect(perUserReads).toBe(2));
  });
});

// ── Namespaces: one request per tree level ──────────────────────────

describe("Namespaces page", () => {
  function nsInfo(path: string) {
    return {
      uuid: `uuid-${path}`,
      path,
      parent_uuid: "root-uuid",
      created_at: "2026-01-01T00:00:00Z",
      child_visible_default: false,
      quotas: {
        max_storage_bytes: 0,
        max_leases: 0,
        request_rate: 0,
        max_mounts: 5,
        max_entities: 0,
        max_child_namespaces: 0,
      },
    };
  }

  it("uses the tree endpoint and never reads a namespace per path", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_namespaces_info":
          return Promise.resolve({
            namespaces: ["tenant-a", "tenant-b"],
            details: {
              "tenant-a": nsInfo("tenant-a"),
              "tenant-b": nsInfo("tenant-b"),
            },
          });
        case "read_namespace":
          // The root config is read separately — it is not a child and is
          // reached through the self-config route with an empty path.
          return Promise.resolve(nsInfo(""));
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<NamespacesPage />);
    expect(await screen.findByText("tenant-a")).toBeInTheDocument();
    expect(await screen.findByText("tenant-b")).toBeInTheDocument();

    // `read_namespace` may only have been called for the root ("").
    const perPathReads = mockInvoke.mock.calls.filter(
      (c) => c[0] === "read_namespace" && (c[1] as { path?: string })?.path !== "",
    );
    expect(perPathReads).toEqual([]);
  });

  it("falls back to the per-path reads on a server without the route", async () => {
    const readPaths: string[] = [];
    mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
      switch (cmd) {
        case "list_namespaces_info":
          return Promise.reject(ROUTE_UNSUPPORTED);
        case "list_namespaces":
          return Promise.resolve({ namespaces: ["legacy-a"] });
        case "read_namespace":
          readPaths.push((args?.path as string) ?? "");
          return Promise.resolve(nsInfo((args?.path as string) ?? ""));
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<NamespacesPage />);
    expect(await screen.findByText("legacy-a")).toBeInTheDocument();
    await waitFor(() => expect(readPaths).toContain("legacy-a"));
  });
});

// ── Certificate lifecycle: the 1 + 2N page ──────────────────────────

describe("Certificate lifecycle page", () => {
  function targetRow(name: string) {
    return {
      target: {
        name,
        kind: "file",
        address: "/tmp",
        pki_mount: "pki",
        role_ref: "web",
        common_name: `${name}.example.com`,
        alt_names: [],
        ip_sans: [],
        ttl: "",
        key_policy: "rotate",
        key_ref: "",
        renew_before: "168h",
        created_at: 1_700_000_000,
      },
      state: {
        name,
        current_serial: "",
        current_not_after: 0,
        last_renewal: 0,
        last_attempt: 0,
        last_error: "",
        next_attempt: 0,
        failure_count: 0,
      },
    };
  }

  function baseHandler(cmd: string) {
    switch (cmd) {
      case "cert_lifecycle_list_mounts":
        return Promise.resolve([
          { path: "cert-lifecycle/", mount_type: "cert-lifecycle" },
        ]);
      case "cert_lifecycle_list_deliverers":
        return Promise.resolve([]);
      case "cert_lifecycle_read_scheduler_config":
        return Promise.resolve({ enabled: false });
      case "pki_list_mounts":
        return Promise.resolve([]);
      default:
        return undefined;
    }
  }

  it("pages targets-info and never reads a target or its state individually", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      const base = baseHandler(cmd);
      if (base) return base;
      switch (cmd) {
        case "cert_lifecycle_list_targets_info":
          return Promise.resolve({
            records: [targetRow("web-a"), targetRow("web-b")],
            total: 2,
            next: "",
          });
        case "cert_lifecycle_read_target":
        case "cert_lifecycle_read_state":
          throw new Error("must not read a target or its state per row");
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<CertLifecyclePage />);
    expect(await screen.findByText("web-a")).toBeInTheDocument();
    expect(await screen.findByText("web-b")).toBeInTheDocument();
  });

  it("falls back to the paired per-target reads on a server without the route", async () => {
    let targetReads = 0;
    let stateReads = 0;
    mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
      const base = baseHandler(cmd);
      if (base) return base;
      switch (cmd) {
        case "cert_lifecycle_list_targets_info":
          return Promise.reject(ROUTE_UNSUPPORTED);
        case "cert_lifecycle_list_targets":
          return Promise.resolve(["legacy-a"]);
        case "cert_lifecycle_read_target":
          targetReads += 1;
          return Promise.resolve(targetRow((args?.name as string) ?? "").target);
        case "cert_lifecycle_read_state":
          stateReads += 1;
          return Promise.resolve(targetRow((args?.name as string) ?? "").state);
        default:
          return Promise.resolve(null);
      }
    });

    renderPage(<CertLifecyclePage />);
    expect(await screen.findByText("legacy-a")).toBeInTheDocument();
    await waitFor(() => {
      expect(targetReads).toBe(1);
      expect(stateReads).toBe(1);
    });
  });
});

// ── Change-watcher subscriptions ────────────────────────────────────

describe("page change-watcher subscriptions", () => {
  /**
   * Every page must subscribe to the mount the *server* keys epochs by, not
   * the one the GUI happens to carry. This fails silently when wrong — the
   * watcher asks about a mount that never moves and simply never invalidates
   * — so it is asserted rather than assumed.
   */
  async function mountsAskedAbout(page: React.ReactNode, settle: () => Promise<void>) {
    renderPage(page);
    await settle();
    await pollNowForTests();
    const call = mockInvoke.mock.calls.find((c) => c[0] === "cache_version");
    return (call?.[1] as { topics: string[] } | undefined)?.topics ?? [];
  }

  it("the Users page watches the full `auth/<mount>/`, not the bare mount", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_auth_methods":
          return Promise.resolve([{ path: "userpass/", mount_type: "userpass" }]);
        case "list_policies":
          return Promise.resolve({ policies: [] });
        case "list_namespaces":
        case "list_namespaces_info":
          return Promise.resolve({ namespaces: [], details: {} });
        case "get_lockout_config":
        case "get_mfa_config":
          return Promise.resolve({ enabled: false });
        case "get_password_policy":
          return Promise.resolve({ min_length: 16 });
        case "list_users_info":
          return Promise.resolve({ records: [], total: 0, next: "" });
        case "cache_version":
          return Promise.resolve({ version: 1, topics: {}, coarse: false });
        default:
          return Promise.resolve(null);
      }
    });

    const mounts = await mountsAskedAbout(<UsersPage />, async () => {
      await waitFor(() =>
        expect(
          mockInvoke.mock.calls.some((c) => c[0] === "list_users_info"),
        ).toBe(true),
      );
    });
    expect(mounts).toEqual(["auth/userpass/"]);
  });

  it("the Namespaces page watches `sys/`, where namespace records live", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_namespaces_info":
          return Promise.resolve({ namespaces: [], details: {} });
        case "read_namespace":
          return Promise.resolve(null);
        case "cache_version":
          return Promise.resolve({ version: 1, topics: {}, coarse: false });
        default:
          return Promise.resolve(null);
      }
    });

    const mounts = await mountsAskedAbout(<NamespacesPage />, async () => {
      await waitFor(() =>
        expect(
          mockInvoke.mock.calls.some((c) => c[0] === "list_namespaces_info"),
        ).toBe(true),
      );
    });
    expect(mounts).toEqual(["sys/"]);
  });
});
