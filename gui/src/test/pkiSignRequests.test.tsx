/**
 * Inbound sign-request queue — import a foreign CSR, dry-run it, then
 * approve or refuse it. Covers the parts an operator can get wrong: a
 * refusal with no reason, and approving without reading the verdict.
 *
 * See features/pki-inbound-sign-requests.md.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import { PkiPage } from "../routes/PkiPage";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const CSR_PEM =
  "-----BEGIN CERTIFICATE REQUEST-----\nMIIBase64Body\n-----END CERTIFICATE REQUEST-----\n";

const PENDING = {
  request_id: "req-uuid-1",
  status: "pending",
  subject_dn: "CN=leaf.example.com",
  common_name: "leaf.example.com",
  dns_sans: ["leaf.example.com", "leaf-alt.example.com"],
  ip_sans: [],
  key_description: "ec-p256",
  spki_sha256: "a".repeat(64),
  requester: "ops@example.com",
  notes: "TICKET-42",
  suggested_role: "open",
  created_at: 1_700_000_000,
  imported_by: "felipe",
  decided_at: 0,
  decided_by: "",
  reject_reason: "",
  sign_mode: "",
  role: "",
  serial_number: "",
  issuer_id: "",
  csr: CSR_PEM,
  certificate: "",
};

const VERDICTS = [
  {
    mode: "verbatim",
    role: "",
    allowed: true,
    reason: "",
    hints: [],
    common_name: "leaf.example.com",
    dns_sans: ["leaf-alt.example.com"],
    ip_sans: [],
    upn_sans: [],
    ad_sid: "",
    ttl_seconds: 2_592_000,
    ttl_clamped: false,
    not_after: 1_702_592_000,
    issuer_id: "iss-1",
    issuer_name: "root",
    issuer_not_after: 1_800_000_000,
    key_description: "ec-p256",
    key_id: "",
    warnings: [
      "verbatim mode bypasses role policy: the subject and SANs are taken from the CSR with no allowed_domains / allow_ip_sans check",
    ],
  },
  {
    mode: "role",
    role: "open",
    allowed: true,
    reason: "",
    hints: [],
    common_name: "leaf.example.com",
    dns_sans: ["leaf-alt.example.com"],
    ip_sans: [],
    upn_sans: [],
    ad_sid: "",
    ttl_seconds: 86_400,
    ttl_clamped: false,
    not_after: 1_700_086_400,
    issuer_id: "iss-1",
    issuer_name: "root",
    issuer_not_after: 1_800_000_000,
    key_description: "ec-p256",
    key_id: "",
    warnings: [],
  },
  {
    mode: "role",
    role: "locked",
    allowed: false,
    reason: "PKI data is invalid.",
    hints: [
      "common name `leaf.example.com` is not permitted by role `locked` (allow_any_name=false, allow_subdomains=true, allow_bare_domains=false, allowed_domains=[\"allowed.example.com\"])",
    ],
    common_name: "",
    dns_sans: [],
    ip_sans: [],
    upn_sans: [],
    ad_sid: "",
    ttl_seconds: 0,
    ttl_clamped: false,
    not_after: 0,
    issuer_id: "",
    issuer_name: "",
    issuer_not_after: 0,
    key_description: "",
    key_id: "",
    warnings: [],
  },
];

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

/** `requests` is what `pki_sign_request_list`/`_read` serve. */
function installMocks(requests: Array<typeof PENDING> = []) {
  mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [] });
      case "pki_list_roles":
        return Promise.resolve(["open", "locked"]);
      case "pki_sign_request_list":
        return Promise.resolve(requests.map((r) => r.request_id));
      case "pki_sign_request_read": {
        const id = args?.requestId as string;
        return Promise.resolve(requests.find((r) => r.request_id === id) ?? null);
      }
      case "pki_sign_request_import":
        return Promise.resolve(PENDING);
      case "pki_sign_request_preflight":
        return Promise.resolve({ request: PENDING, verdicts: VERDICTS });
      case "pki_sign_request_approve":
        return Promise.resolve({
          request: {
            ...PENDING,
            status: "signed",
            sign_mode: "role",
            role: "open",
            serial_number: "1a2b3c4d5e6f7890",
            issuer_id: "iss-1",
            decided_at: 1_700_000_100,
            decided_by: "felipe",
            certificate: "-----BEGIN CERTIFICATE-----\nMIIleaf\n-----END CERTIFICATE-----",
          },
          certificate: "-----BEGIN CERTIFICATE-----\nMIIleaf\n-----END CERTIFICATE-----",
          issuing_ca: "-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----",
          ca_chain: ["-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----"],
          ttl_seconds: 43_200,
          not_after: 1_700_043_200,
          warnings: [],
          key_id: "",
        });
      case "pki_sign_request_reject":
        return Promise.resolve({
          ...PENDING,
          status: "rejected",
          reject_reason: "requester unverified",
          decided_at: 1_700_000_100,
          decided_by: "felipe",
        });
      default:
        return Promise.resolve(null);
    }
  });
}

async function openTab(user: ReturnType<typeof userEvent.setup>) {
  renderPage();
  await user.click(await screen.findByRole("button", { name: "Sign Requests" }));
}

describe("PKI inbound sign requests", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("imports a pasted CSR and opens it for review", async () => {
    installMocks();
    const user = userEvent.setup();
    await openTab(user);

    await user.type(screen.getByLabelText("CSR (PEM)"), CSR_PEM);
    await user.type(screen.getByLabelText("Requester"), "ops@example.com");
    await user.click(screen.getByRole("button", { name: "Import CSR" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_sign_request_import");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        request: expect.objectContaining({
          mount: "pki",
          csr: expect.stringContaining("BEGIN CERTIFICATE REQUEST"),
          requester: "ops@example.com",
        }),
      });
    });

    // The imported request opens for review, showing what the CSR asks
    // for rather than just the base64.
    expect(await screen.findByText("CN=leaf.example.com")).toBeTruthy();
    expect(screen.getByText("ec-p256")).toBeTruthy();
  });

  it("refuses to import nothing", async () => {
    installMocks();
    const user = userEvent.setup();
    await openTab(user);

    await user.click(screen.getByRole("button", { name: "Import CSR" }));
    expect(await screen.findByText(/Paste a CSR/)).toBeTruthy();
    expect(mockInvoke.mock.calls.some((c) => c[0] === "pki_sign_request_import")).toBe(
      false,
    );
  });

  it("dry-runs every role and shows why one refuses", async () => {
    installMocks([PENDING]);
    const user = userEvent.setup();
    await openTab(user);

    await user.click(await screen.findByRole("button", { name: "Review" }));
    await user.click(await screen.findByRole("button", { name: "Check every role" }));

    // One verdict per mode/role, verbatim flagged as policy-bypassing.
    expect(await screen.findByText("Dry run")).toBeTruthy();
    expect(screen.getAllByText("would sign").length).toBe(2);
    expect(screen.getByText("refused")).toBeTruthy();
    expect(screen.getByText(/bypasses role policy/)).toBeTruthy();
    // The refusal names the value that failed policy, not just a code.
    expect(
      screen.getByText(/common name `leaf.example.com` is not permitted by role `locked`/),
    ).toBeTruthy();

    // Preflight must not have issued anything.
    expect(mockInvoke.mock.calls.some((c) => c[0] === "pki_sign_request_approve")).toBe(
      false,
    );
  });

  it("approves under a role and records the serial", async () => {
    installMocks([PENDING]);
    const user = userEvent.setup();
    await openTab(user);

    await user.click(await screen.findByRole("button", { name: "Review" }));
    // The suggested role is pre-selected, so approving takes one click.
    await user.click(await screen.findByRole("button", { name: "Approve & sign" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_sign_request_approve");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        request: expect.objectContaining({
          mount: "pki",
          request_id: "req-uuid-1",
          mode: "role",
          role: "open",
        }),
      });
    });

    expect(await screen.findByText("1a2b3c4d5e6f7890")).toBeTruthy();
    expect(screen.getByText("role: open")).toBeTruthy();
  });

  it("will not reject without a reason, and records one when given", async () => {
    installMocks([PENDING]);
    const user = userEvent.setup();
    await openTab(user);

    await user.click(await screen.findByRole("button", { name: "Review" }));
    await user.click(await screen.findByRole("button", { name: "Reject" }));
    expect(await screen.findByText(/A reason is required/)).toBeTruthy();
    expect(mockInvoke.mock.calls.some((c) => c[0] === "pki_sign_request_reject")).toBe(
      false,
    );

    await user.type(screen.getByLabelText("Reason"), "requester unverified");
    await user.click(screen.getByRole("button", { name: "Reject" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_sign_request_reject");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        request: { mount: "pki", request_id: "req-uuid-1", reason: "requester unverified" },
      });
    });
    // The decision panel replaces the decide form, reason on the record.
    expect(await screen.findByText("requester unverified")).toBeTruthy();
  });

  it("switches to verbatim from the dry run and warns about the bypass", async () => {
    installMocks([PENDING]);
    const user = userEvent.setup();
    await openTab(user);

    await user.click(await screen.findByRole("button", { name: "Review" }));
    await user.click(await screen.findByRole("button", { name: "Check every role" }));

    const verbatimRow = (await screen.findByText("verbatim")).closest("tr") as HTMLElement;
    await user.click(within(verbatimRow).getByRole("button", { name: "Use" }));

    expect(
      await screen.findByText(/taken from the CSR with no\s+allowed_domains or IP-SAN check/),
    ).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Approve & sign" }));
    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_sign_request_approve");
      expect(call).toBeTruthy();
      expect((call![1] as { request: { mode: string } }).request.mode).toBe("verbatim");
    });
  });
});
